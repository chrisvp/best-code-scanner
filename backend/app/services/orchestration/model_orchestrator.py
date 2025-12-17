import asyncio
import httpx
import time
import json
import re
from typing import List, Dict, Optional, Any, Callable, AsyncIterator
from app.models.scanner_models import ModelConfig, ScanErrorLog
from app.services.llm_logger import llm_logger
from app.services.token_utils import calculate_max_tokens, is_max_tokens_error, calculate_retry_max_tokens
from app.core.config import settings
from app.services.orchestration.queue_manager import queue_manager


async def _parse_sse_stream(response: httpx.Response) -> AsyncIterator[dict]:
    """Parse Server-Sent Events stream from vLLM/OpenAI API.

    Yields parsed JSON objects from 'data:' lines.
    Handles multi-line chunks and the [DONE] marker.
    """
    buffer = ""
    async for chunk in response.aiter_text():
        buffer += chunk
        # Process complete lines
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            line = line.strip()
            if line.startswith("data:"):
                data_str = line[5:].strip()
                if data_str == "[DONE]":
                    return
                if data_str:
                    try:
                        yield json.loads(data_str)
                    except json.JSONDecodeError:
                        continue


async def _stream_chat_completion(
    client: httpx.AsyncClient,
    url: str,
    payload: dict,
    api_key: str,
) -> dict:
    """Make a streaming chat completion request and accumulate the response.

    Returns the same format as non-streaming: dict with content, usage, etc.
    Streaming keeps the connection alive as long as tokens flow.
    """
    payload = {**payload, "stream": True, "stream_options": {"include_usage": True}}

    content_chunks = []
    thinking_chunks = []
    usage = {"prompt_tokens": 0, "completion_tokens": 0}
    model_name = payload.get("model", "unknown")
    tool_calls = []
    tool_call_buffer = {}  # id -> {name, arguments}

    async with client.stream(
        "POST",
        url,
        json=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
    ) as response:
        if response.status_code >= 400:
            # Read error body
            error_text = await response.aread()
            try:
                error_body = json.loads(error_text)
                error_detail = error_body.get("error", {})
                if isinstance(error_detail, dict):
                    error_message = error_detail.get("message", str(error_body))
                else:
                    error_message = str(error_detail) or str(error_body)
            except Exception:
                error_message = error_text.decode()[:500] if isinstance(error_text, bytes) else str(error_text)[:500]

            return {
                "content": "",
                "tool_calls": [],
                "usage": usage,
                "error": f"HTTP {response.status_code}: {error_message}",
                "status_code": response.status_code
            }

        async for chunk_data in _parse_sse_stream(response):
            choices = chunk_data.get("choices", [])
            if choices:
                delta = choices[0].get("delta", {})

                # Accumulate content
                if "content" in delta and delta["content"]:
                    content_chunks.append(delta["content"])

                # Handle reasoning/thinking content
                if "thinking" in delta and delta["thinking"]:
                    thinking_chunks.append(delta["thinking"])
                if "reasoning_content" in delta and delta["reasoning_content"]:
                    thinking_chunks.append(delta["reasoning_content"])

                # Handle tool calls (streamed in pieces)
                if "tool_calls" in delta:
                    for tc in delta["tool_calls"]:
                        tc_idx = tc.get("index", 0)
                        if tc_idx not in tool_call_buffer:
                            tool_call_buffer[tc_idx] = {
                                "id": tc.get("id", ""),
                                "type": "function",
                                "function": {"name": "", "arguments": ""}
                            }
                        if tc.get("id"):
                            tool_call_buffer[tc_idx]["id"] = tc["id"]
                        if "function" in tc:
                            if tc["function"].get("name"):
                                tool_call_buffer[tc_idx]["function"]["name"] = tc["function"]["name"]
                            if tc["function"].get("arguments"):
                                tool_call_buffer[tc_idx]["function"]["arguments"] += tc["function"]["arguments"]

            # Extract usage from final chunk
            if "usage" in chunk_data and chunk_data["usage"]:
                usage = {
                    "prompt_tokens": chunk_data["usage"].get("prompt_tokens", 0),
                    "completion_tokens": chunk_data["usage"].get("completion_tokens", 0)
                }

    # Assemble final content
    content = "".join(content_chunks)
    thinking = "".join(thinking_chunks)
    if thinking:
        content = f"<thinking>{thinking}</thinking>\n{content}"

    # Convert tool call buffer to list
    if tool_call_buffer:
        tool_calls = [tool_call_buffer[i] for i in sorted(tool_call_buffer.keys())]

    return {
        "content": content,
        "tool_calls": tool_calls,
        "usage": usage,
        "model": model_name
    }


class ModelPool:
    """Manages concurrent access to a single model with batching support.

    Also provides static methods for simple one-off LLM calls that don't require
    a full orchestrator setup (simple_chat_completion, simple_chat_completion_with_tools).
    """

    # ============================================================
    # Static methods for simple one-off calls (no orchestrator needed)
    # ============================================================

    @staticmethod
    async def simple_call(
        prompt: str,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.1,
        output_mode: str = "markers",
        json_schema: Optional[str] = None,
        _retry_max_tokens: Optional[int] = None,
    ) -> str:
        """
        Single prompt call using STREAMING to avoid timeout issues.

        A convenience static method for simple LLM calls (chat, cleanup, etc.)
        that don't need batching or queue management. Uses SSE streaming to
        keep connection alive during long inference.

        Args:
            prompt: The prompt text to send
            model: Model to use (defaults to settings.LLM_MODEL)
            base_url: API base URL (defaults to settings.LLM_BASE_URL)
            api_key: API key (defaults to settings.LLM_API_KEY)
            max_tokens: Maximum tokens in response (default 4096)
            temperature: Sampling temperature (default 0.1)
            output_mode: Response format mode:
                - "markers": Default, no special formatting
                - "json": Use response_format: {"type": "json_object"}
                - "guided_json": Use vLLM guided_json with schema
            json_schema: JSON schema string for guided_json mode
            _retry_max_tokens: Internal override for retry on token errors

        Returns:
            The response content string, or empty string on error
        """
        effective_base_url = base_url or settings.LLM_BASE_URL
        effective_api_key = api_key or settings.LLM_API_KEY
        model_name = model or settings.LLM_MODEL
        effective_max_tokens = _retry_max_tokens if _retry_max_tokens is not None else max_tokens

        if not effective_base_url:
            return ""

        # Build URL
        base = effective_base_url.rstrip('/')
        if base.endswith('/v1'):
            url = f"{base}/chat/completions"
        else:
            url = f"{base}/v1/chat/completions"

        # Build request payload
        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": effective_max_tokens,
            "temperature": temperature,
        }

        # Apply output mode formatting
        if output_mode == "json":
            payload["response_format"] = {"type": "json_object"}
        elif output_mode == "guided_json" and json_schema:
            try:
                schema = json.loads(json_schema) if isinstance(json_schema, str) else json_schema
                payload["guided_json"] = schema
            except json.JSONDecodeError:
                payload["response_format"] = {"type": "json_object"}

        verify_ssl = getattr(settings, 'LLM_VERIFY_SSL', False)

        # Streaming timeout config:
        # - read: Time to wait for FIRST chunk (model processing prompt) - this is the long wait
        # - Once streaming starts, chunks flow fast so between-chunk timeout is implicit
        stream_timeout = httpx.Timeout(connect=60.0, read=3600.0, write=60.0, pool=60.0)

        try:
            async with httpx.AsyncClient(verify=verify_ssl, timeout=stream_timeout) as client:
                result = await _stream_chat_completion(client, url, payload, effective_api_key)

                # Check for errors
                if "error" in result:
                    error_message = result["error"]

                    # Check if this is a max_tokens error we can retry
                    if _retry_max_tokens is None and is_max_tokens_error(error_message):
                        new_max_tokens = calculate_retry_max_tokens(error_message)
                        if new_max_tokens and new_max_tokens > 100:
                            print(f"[simple_call RETRY] {model_name} max_tokens error, retrying with {new_max_tokens}")
                            return await ModelPool.simple_call(
                                prompt=prompt,
                                model=model,
                                base_url=base_url,
                                api_key=api_key,
                                max_tokens=max_tokens,
                                temperature=temperature,
                                output_mode=output_mode,
                                json_schema=json_schema,
                                _retry_max_tokens=new_max_tokens
                            )

                    print(f"[simple_call ERROR] {model_name}: {error_message}")
                    return ""

                return result.get("content", "")

        except Exception as e:
            print(f"[simple_call ERROR] {model_name}: {type(e).__name__}: {e}")
            return ""

    @staticmethod
    async def simple_chat_completion(
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.1,
        output_mode: str = "markers",
        json_schema: Optional[str] = None,
        _retry_max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Chat completion using STREAMING to avoid timeout issues.

        A convenience static method for chat-style LLM calls that need
        multi-turn conversation support. Uses SSE streaming to keep
        connection alive during long inference.

        Args:
            messages: List of message dicts with 'role' and 'content' keys
            model: Model to use (defaults to settings.LLM_MODEL)
            base_url: API base URL (defaults to settings.LLM_BASE_URL)
            api_key: API key (defaults to settings.LLM_API_KEY)
            max_tokens: Maximum tokens in response (default 4096)
            temperature: Sampling temperature (default 0.1)
            output_mode: Response format mode:
                - "markers": Default, no special formatting
                - "json": Use response_format: {"type": "json_object"}
                - "guided_json": Use vLLM guided_json with schema
            json_schema: JSON schema string for guided_json mode
            _retry_max_tokens: Internal override for retry on token errors

        Returns:
            Dict with keys:
                - content: Response text
                - model: Model name used
                - usage: Token usage dict (prompt_tokens, completion_tokens)
                - error: Error message if failed (optional)
        """
        effective_base_url = base_url or settings.LLM_BASE_URL
        effective_api_key = api_key or settings.LLM_API_KEY
        model_name = model or settings.LLM_MODEL
        effective_max_tokens = _retry_max_tokens if _retry_max_tokens is not None else max_tokens

        if not effective_base_url:
            return {
                "content": "",
                "model": model_name,
                "usage": {"prompt_tokens": 0, "completion_tokens": 0},
                "error": "No base_url configured"
            }

        # Build URL
        base = effective_base_url.rstrip('/')
        if base.endswith('/v1'):
            url = f"{base}/chat/completions"
        else:
            url = f"{base}/v1/chat/completions"

        # Build request payload
        payload = {
            "model": model_name,
            "messages": messages,
            "max_tokens": effective_max_tokens,
            "temperature": temperature,
        }

        # Apply output mode formatting
        if output_mode == "json":
            payload["response_format"] = {"type": "json_object"}
        elif output_mode == "guided_json" and json_schema:
            try:
                schema = json.loads(json_schema) if isinstance(json_schema, str) else json_schema
                payload["guided_json"] = schema
            except json.JSONDecodeError:
                payload["response_format"] = {"type": "json_object"}

        verify_ssl = getattr(settings, 'LLM_VERIFY_SSL', False)

        # Streaming timeout config:
        # - read: Time to wait for FIRST chunk (model processing prompt) - this is the long wait
        # - Once streaming starts, chunks flow fast so between-chunk timeout is implicit
        stream_timeout = httpx.Timeout(connect=60.0, read=3600.0, write=60.0, pool=60.0)

        try:
            async with httpx.AsyncClient(verify=verify_ssl, timeout=stream_timeout) as client:
                result = await _stream_chat_completion(client, url, payload, effective_api_key)

                # Check for errors
                if "error" in result:
                    error_message = result["error"]

                    # Check if this is a max_tokens error we can retry
                    if _retry_max_tokens is None and is_max_tokens_error(error_message):
                        new_max_tokens = calculate_retry_max_tokens(error_message)
                        if new_max_tokens and new_max_tokens > 100:
                            print(f"[simple_chat_completion RETRY] {model_name} max_tokens error, retrying with {new_max_tokens}")
                            return await ModelPool.simple_chat_completion(
                                messages=messages,
                                model=model,
                                base_url=base_url,
                                api_key=api_key,
                                max_tokens=max_tokens,
                                temperature=temperature,
                                output_mode=output_mode,
                                json_schema=json_schema,
                                _retry_max_tokens=new_max_tokens
                            )

                    print(f"[simple_chat_completion ERROR] {model_name}: {error_message}")
                    return {
                        "content": "",
                        "model": model_name,
                        "usage": {"prompt_tokens": 0, "completion_tokens": 0},
                        "error": error_message
                    }

                return {
                    "content": result.get("content", ""),
                    "model": model_name,
                    "usage": result.get("usage", {"prompt_tokens": 0, "completion_tokens": 0})
                }

        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            print(f"[simple_chat_completion ERROR] {model_name}: {error_msg}")
            return {
                "content": "",
                "model": model_name,
                "usage": {"prompt_tokens": 0, "completion_tokens": 0},
                "error": error_msg
            }

    @staticmethod
    async def simple_chat_with_tools(
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.1,
        tool_choice: str = "auto",
        _retry_max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Chat completion with tool/function calling using STREAMING.

        A convenience static method for LLM calls that use native tool calling.
        Uses SSE streaming to keep connection alive during long inference.

        Args:
            messages: List of message dicts (can include tool results)
            tools: List of tool definitions in OpenAI format
            model: Model to use (defaults to settings.LLM_MODEL)
            base_url: API base URL (defaults to settings.LLM_BASE_URL)
            api_key: API key (defaults to settings.LLM_API_KEY)
            max_tokens: Maximum tokens in response (default 4096)
            temperature: Sampling temperature (default 0.1)
            tool_choice: Tool choice mode ("auto", "none", or specific tool)
            _retry_max_tokens: Internal override for retry on token errors

        Returns:
            Dict with keys:
                - content: Text response (may be empty if tool calls present)
                - tool_calls: List of tool call objects
                - model: Model name used
                - usage: Token usage dict (prompt_tokens, completion_tokens)
                - error: Error message if failed (optional)
        """
        effective_base_url = base_url or settings.LLM_BASE_URL
        effective_api_key = api_key or settings.LLM_API_KEY
        model_name = model or settings.LLM_MODEL
        effective_max_tokens = _retry_max_tokens if _retry_max_tokens is not None else max_tokens

        if not effective_base_url:
            return {
                "content": "",
                "tool_calls": [],
                "model": model_name,
                "usage": {"prompt_tokens": 0, "completion_tokens": 0},
                "error": "No base_url configured"
            }

        # Build URL
        base = effective_base_url.rstrip('/')
        if base.endswith('/v1'):
            url = f"{base}/chat/completions"
        else:
            url = f"{base}/v1/chat/completions"

        # Build request payload
        payload = {
            "model": model_name,
            "messages": messages,
            "max_tokens": effective_max_tokens,
            "temperature": temperature,
            "tools": tools,
            "tool_choice": tool_choice
        }

        verify_ssl = getattr(settings, 'LLM_VERIFY_SSL', False)

        # Streaming timeout config:
        # - read: Time to wait for FIRST chunk (model processing prompt) - this is the long wait
        # - Once streaming starts, chunks flow fast so between-chunk timeout is implicit
        stream_timeout = httpx.Timeout(connect=60.0, read=3600.0, write=60.0, pool=60.0)

        try:
            async with httpx.AsyncClient(verify=verify_ssl, timeout=stream_timeout) as client:
                result = await _stream_chat_completion(client, url, payload, effective_api_key)

                # Check for errors
                if "error" in result:
                    error_message = result["error"]

                    # Check if this is a max_tokens error we can retry
                    if _retry_max_tokens is None and is_max_tokens_error(error_message):
                        new_max_tokens = calculate_retry_max_tokens(error_message)
                        if new_max_tokens and new_max_tokens > 100:
                            print(f"[simple_chat_with_tools RETRY] {model_name} max_tokens error, retrying with {new_max_tokens}")
                            return await ModelPool.simple_chat_with_tools(
                                messages=messages,
                                tools=tools,
                                model=model,
                                base_url=base_url,
                                api_key=api_key,
                                max_tokens=max_tokens,
                                temperature=temperature,
                                tool_choice=tool_choice,
                                _retry_max_tokens=new_max_tokens
                            )

                    print(f"[simple_chat_with_tools ERROR] {model_name}: {error_message}")
                    return {
                        "content": "",
                        "tool_calls": [],
                        "model": model_name,
                        "usage": {"prompt_tokens": 0, "completion_tokens": 0},
                        "error": error_message
                    }

                return {
                    "content": result.get("content", "") or "",
                    "tool_calls": result.get("tool_calls", []),
                    "model": model_name,
                    "usage": result.get("usage", {"prompt_tokens": 0, "completion_tokens": 0})
                }

        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            print(f"[simple_chat_with_tools ERROR] {model_name}: {error_msg}")
            return {
                "content": "",
                "tool_calls": [],
                "model": model_name,
                "usage": {"prompt_tokens": 0, "completion_tokens": 0},
                "error": error_msg
            }

    # ============================================================
    # Instance methods for orchestrated calls
    # ============================================================

    def __init__(self, config: ModelConfig, error_callback: Optional[Callable] = None):
        self.config = config
        # Use global queue manager's semaphore for this model (enforces limits across all pools)
        model_queue = queue_manager._get_or_create_queue(config.name, config.max_concurrent)
        self.semaphore = model_queue.semaphore
        self.batch_queue: asyncio.Queue = asyncio.Queue()
        self.batch_size = config.max_concurrent  # Match batch size to model's concurrency limit
        self.batch_timeout = 0.5  # Seconds to wait for batch to fill
        self._batch_task: Optional[asyncio.Task] = None
        self._running = False
        # Logging context (set by caller before making calls)
        self._log_context: Dict[str, Any] = {}
        # Error tracking
        self._consecutive_failures = 0
        self._error_callback = error_callback  # Called on error with (model_name, error_type, error_msg)

    async def start(self):
        """Start the batch processor"""
        self._running = True
        self._batch_task = asyncio.create_task(self._batch_processor())

    async def stop(self):
        """Stop the batch processor"""
        self._running = False
        if self._batch_task:
            self._batch_task.cancel()
            try:
                await self._batch_task
            except asyncio.CancelledError:
                pass

    async def call(self, prompt: str) -> str:
        """Single prompt call - gets batched automatically"""
        future: asyncio.Future = asyncio.Future()
        await self.batch_queue.put((prompt, future))
        return await future

    async def call_batch(
        self,
        prompts: List[str],
        log_context: Optional[Dict[str, Any]] = None,
        output_mode: str = "markers",
        json_schema: Optional[str] = None
    ) -> List[str]:
        """Direct batch call - bypasses queue

        Args:
            prompts: List of prompts to send
            log_context: Optional context for logging
            output_mode: Response format mode:
                - "markers": Default, no special formatting
                - "json": Use response_format: {"type": "json_object"}
                - "guided_json": Use vLLM guided_json with schema
            json_schema: JSON schema string for guided_json mode
        """
        if log_context:
            self._log_context = log_context
        return await self._send_batch(prompts, output_mode=output_mode, json_schema=json_schema)

    async def call_with_tools(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        tool_choice: str = "auto",
        retry_max_tokens: int = None
    ) -> Dict[str, Any]:
        """Call the model with native tool calling support.

        Args:
            messages: OpenAI-format messages list
            tools: List of tool definitions in OpenAI format
            tool_choice: Tool choice mode ("auto", "none", or specific tool)
            retry_max_tokens: Override max_tokens for retry (internal use)

        Returns:
            Dict with 'content' (text response) and 'tool_calls' (list of tool calls)
        """
        base_url = self.config.base_url or settings.LLM_BASE_URL
        api_key = self.config.api_key or settings.LLM_API_KEY

        if not base_url:
            return {"content": "", "tool_calls": [], "error": f"Model '{self.config.name}' has no base_url configured"}

        base = base_url.rstrip('/')
        if base.endswith('/v1'):
            url = f"{base}/chat/completions"
        else:
            url = f"{base}/v1/chat/completions"

        # Calculate effective max_tokens
        total_content = "".join(m.get("content", "") or "" for m in messages)
        if retry_max_tokens is not None:
            effective_max_tokens = retry_max_tokens
        else:
            max_context = getattr(self.config, 'max_context_length', 0) or 0
            effective_max_tokens = calculate_max_tokens(
                prompt=total_content,
                requested_max_tokens=self.config.max_tokens or 4096,
                max_context_length=max_context
            )

        payload = {
            "model": self.config.name,
            "messages": messages,
            "max_tokens": effective_max_tokens,
            "temperature": 0.1,
            "tools": tools,
            "tool_choice": tool_choice
        }

        # Dynamic timeout: base 300s + 1s per 200 chars, max 3600s (1 hour)
        total_chars = len(total_content)
        dynamic_timeout = min(3600.0, 300.0 + (total_chars / 200))

        async with self.semaphore:
            async with httpx.AsyncClient(verify=False, timeout=dynamic_timeout) as client:
                response = await client.post(
                    url,
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json"
                    },
                    json=payload
                )

                # Check for max_tokens error and retry
                if response.status_code >= 400:
                    try:
                        error_body = response.json()
                        error_detail = error_body.get("error", {})
                        if isinstance(error_detail, dict):
                            error_message = error_detail.get("message", str(error_body))
                        else:
                            error_message = str(error_detail) or str(error_body)
                    except Exception:
                        error_message = response.text[:500]

                    if retry_max_tokens is None and is_max_tokens_error(error_message):
                        new_max_tokens = calculate_retry_max_tokens(error_message)
                        if new_max_tokens and new_max_tokens > 100:
                            print(f"[LLM RETRY] {self.config.name} tool call max_tokens error, retrying with {new_max_tokens}")
                            return await self.call_with_tools(messages, tools, tool_choice, retry_max_tokens=new_max_tokens)

                    response.raise_for_status()

                data = response.json()

        choice = data.get("choices", [{}])[0]
        message = choice.get("message", {})

        return {
            "content": message.get("content", ""),
            "tool_calls": message.get("tool_calls", [])
        }

    def set_log_context(self, **kwargs):
        """Set logging context for subsequent calls (scan_id, phase, analyzer_name, etc.)"""
        self._log_context.update(kwargs)

    async def _batch_processor(self):
        """Collects prompts and sends in batches"""
        while self._running:
            batch = []
            futures = []

            try:
                # Wait for first item
                try:
                    prompt, future = await asyncio.wait_for(
                        self.batch_queue.get(),
                        timeout=1.0
                    )
                    batch.append(prompt)
                    futures.append(future)
                except asyncio.TimeoutError:
                    continue

                # Collect more items up to batch_size or timeout
                deadline = asyncio.get_event_loop().time() + self.batch_timeout
                while len(batch) < self.batch_size:
                    timeout = deadline - asyncio.get_event_loop().time()
                    if timeout <= 0:
                        break
                    try:
                        prompt, future = await asyncio.wait_for(
                            self.batch_queue.get(),
                            timeout=timeout
                        )
                        batch.append(prompt)
                        futures.append(future)
                    except asyncio.TimeoutError:
                        break

                # Send batch
                try:
                    results = await self._send_batch(batch)

                    # Resolve futures
                    for future, result in zip(futures, results):
                        if not future.done():
                            future.set_result(result)
                except Exception as e:
                    # Fail all futures in batch
                    for future in futures:
                        if not future.done():
                            future.set_exception(e)

            except asyncio.CancelledError:
                # Cancel any pending futures
                for future in futures:
                    if not future.done():
                        future.cancel()
                raise

    async def _send_batch(
        self,
        prompts: List[str],
        output_mode: str = "markers",
        json_schema: Optional[str] = None
    ) -> List[str]:
        """Send batch to vLLM using STREAMING chat completions.

        Uses Server-Sent Events (SSE) streaming to keep connections alive
        as long as tokens are flowing. This eliminates timeout issues for
        long-running inference requests.

        Args:
            prompts: List of prompts to send
            output_mode: Response format mode (markers, json, guided_json)
            json_schema: JSON schema string for guided_json mode
        """
        results = []
        log_context = self._log_context.copy()

        # Log pending requests BEFORE sending
        pending_log_ids = []
        for prompt in prompts:
            log_id = llm_logger.log_pending(
                model_name=self.config.name,
                phase=log_context.get('phase', 'unknown'),
                request_prompt=prompt,
                scan_id=log_context.get('scan_id'),
                mr_review_id=log_context.get('mr_review_id'),
                analyzer_name=log_context.get('analyzer_name'),
                file_path=log_context.get('file_path'),
                chunk_id=log_context.get('chunk_id'),
            )
            pending_log_ids.append(log_id)

        # Streaming timeout config:
        # - read: Time to wait for FIRST chunk (model processing prompt) - this is the long wait
        # - Once streaming starts, chunks flow fast so between-chunk timeout is implicit
        stream_timeout = httpx.Timeout(
            connect=60.0,      # 60s to establish connection
            read=3600.0,       # 1hr for first chunk (model thinking time)
            write=60.0,        # 60s to send request
            pool=60.0          # 60s to get connection from pool
        )

        async with httpx.AsyncClient(timeout=stream_timeout, verify=False) as client:
            # Rate-limited concurrent requests with streaming
            async def send_one_streaming(prompt: str, idx: int, retry_max_tokens: int = None) -> tuple:
                """Returns (response_content, prompt, duration_ms, tokens_in, tokens_out, error, log_id)

                Uses streaming to keep connection alive during long inference.
                """
                log_id = pending_log_ids[idx] if idx < len(pending_log_ids) else None

                # Log before acquiring semaphore
                semaphore_wait_start = time.time()
                semaphore_value = getattr(self.semaphore, '_value', 'unknown')
                print(f"[SEMAPHORE] Waiting for semaphore - model={self.config.name}, task_idx={idx}, semaphore_value={semaphore_value}, log_id={log_id}")

                async with self.semaphore:
                    # Log after acquiring semaphore
                    time_waited = (time.time() - semaphore_wait_start) * 1000  # in milliseconds
                    print(f"[SEMAPHORE] Acquired semaphore - model={self.config.name}, task_idx={idx}, log_id={log_id}, time_waited={time_waited:.2f}ms")

                    start_time = time.time()
                    tokens_in = None
                    tokens_out = None

                    try:
                        # Fall back to default settings if model config is missing values
                        base_url = self.config.base_url or settings.LLM_BASE_URL
                        api_key = self.config.api_key or settings.LLM_API_KEY

                        if not base_url:
                            duration_ms = (time.time() - start_time) * 1000
                            return ("", prompt, duration_ms, None, None, f"Model '{self.config.name}' has no base_url configured and no default set", log_id)

                        base = base_url.rstrip('/')
                        if base.endswith('/v1'):
                            url = f"{base}/chat/completions"
                        else:
                            url = f"{base}/v1/chat/completions"

                        # Calculate dynamic max_tokens based on context limits
                        if retry_max_tokens is not None:
                            effective_max_tokens = retry_max_tokens
                        else:
                            max_context = getattr(self.config, 'max_context_length', 0) or 0
                            effective_max_tokens = calculate_max_tokens(
                                prompt=prompt,
                                requested_max_tokens=self.config.max_tokens,
                                max_context_length=max_context
                            )

                        request_payload = {
                            "model": self.config.name,
                            "messages": [{"role": "user", "content": prompt}],
                            "max_tokens": effective_max_tokens,
                            "temperature": 0.1
                        }

                        # Apply output mode formatting
                        if output_mode == "json":
                            request_payload["response_format"] = {"type": "json_object"}
                        elif output_mode == "guided_json" and json_schema:
                            try:
                                schema = json.loads(json_schema) if isinstance(json_schema, str) else json_schema
                                request_payload["guided_json"] = schema
                            except json.JSONDecodeError:
                                # Invalid schema - fall back to regular json mode
                                request_payload["response_format"] = {"type": "json_object"}

                        # Mark as running now that HTTP request is about to start
                        if log_id:
                            llm_logger.set_running(log_id)

                        # HTTP request starting
                        http_start_time = time.time()
                        print(f"[HTTP START] model={self.config.name}, log_id={log_id}, url={url}")

                        # Use streaming to avoid timeout issues
                        result = await _stream_chat_completion(client, url, request_payload, api_key)

                        # HTTP request completed
                        http_duration_ms = (time.time() - http_start_time) * 1000
                        print(f"[HTTP COMPLETE] model={self.config.name}, log_id={log_id}, duration={http_duration_ms:.2f}ms")

                        # Check for errors
                        if "error" in result:
                            error_message = result["error"]
                            status_code = result.get("status_code", 0)

                            # Check if this is a max_tokens error that we can retry
                            if retry_max_tokens is None and is_max_tokens_error(error_message):
                                new_max_tokens = calculate_retry_max_tokens(error_message)
                                if new_max_tokens and new_max_tokens > 100:
                                    print(f"[LLM RETRY] {self.config.name} max_tokens error, retrying with {new_max_tokens}")
                                    return await send_one_streaming(prompt, idx, retry_max_tokens=new_max_tokens)

                            prompt_len = len(prompt)
                            print(f"[LLM ERROR] {self.config.name} returned error: {error_message}")
                            print(f"[LLM ERROR] Prompt length: {prompt_len} chars, max_tokens: {effective_max_tokens}")
                            if prompt_len > 1000:
                                print(f"[LLM ERROR] Prompt preview: {prompt[:500]}...{prompt[-200:]}")

                            duration_ms = (time.time() - start_time) * 1000
                            return ("", prompt, duration_ms, None, None, error_message, log_id)

                        # Extract content and usage from streaming result
                        content = result.get("content", "")
                        usage = result.get("usage", {})
                        tokens_in = usage.get("prompt_tokens")
                        tokens_out = usage.get("completion_tokens")

                        duration_ms = (time.time() - start_time) * 1000
                        return (content, prompt, duration_ms, tokens_in, tokens_out, None, log_id)

                    except Exception as e:
                        import traceback
                        error_msg = f"{type(e).__name__}: {e}"
                        print(f"Request failed for {self.config.name}: {error_msg}")
                        traceback.print_exc()
                        duration_ms = (time.time() - start_time) * 1000
                        return ("", prompt, duration_ms, None, None, error_msg, log_id)
                    finally:
                        # Log when releasing semaphore
                        print(f"[SEMAPHORE] Released semaphore - model={self.config.name}, task_idx={idx}, log_id={log_id}")

            tasks = [send_one_streaming(prompt, i) for i, prompt in enumerate(prompts)]
            batch_results = await asyncio.gather(*tasks)

            # Count errors in this batch
            batch_errors = sum(1 for _, _, _, _, _, error, _ in batch_results if error)
            batch_successes = len(batch_results) - batch_errors

            # Update consecutive failure tracking
            if batch_errors == len(batch_results):
                # All failed - increment consecutive failures
                self._consecutive_failures += batch_errors
            elif batch_successes > 0:
                # At least one success - reset counter
                self._consecutive_failures = 0

            # Update log entries with responses
            for content, prompt, duration_ms, tokens_in, tokens_out, error, log_id in batch_results:
                results.append(content)

                # Update the pending log entry with the response
                if log_id:
                    llm_logger.log_response(
                        log_id=log_id,
                        raw_response=content,
                        parse_success=error is None,
                        parse_error=error,
                        tokens_in=tokens_in,
                        tokens_out=tokens_out,
                        duration_ms=duration_ms,
                        status="failed" if error else "completed",
                    )

                # Call error callback if there's an error
                if error and self._error_callback:
                    error_type = "connection_error" if "ConnectError" in error else "model_error"
                    self._error_callback(
                        self.config.name,
                        error_type,
                        error,
                        log_context.get('scan_id'),
                        log_context.get('phase', 'unknown'),
                        log_context.get('file_path'),
                        self._consecutive_failures
                    )

        return results


class ModelOrchestrator:
    """Manages all model pools"""

    # Auto-pause after this many consecutive failures across all models
    FAILURE_THRESHOLD = 10

    def __init__(self, db, profile_id: int = None, scan_id: int = None):
        self.db = db
        self.profile_id = profile_id
        self.scan_id = scan_id
        self.pools: Dict[str, ModelPool] = {}
        self._profile_analyzer_model_ids: set = set()  # Model IDs from profile analyzers
        self._profile_verifier_model_ids: set = set()  # Model IDs from profile verifiers
        self._total_consecutive_failures = 0
        self._should_pause = False

    def _on_model_error(self, model_name: str, error_type: str, error_msg: str,
                        scan_id: int, phase: str, file_path: str, consecutive_failures: int):
        """Called when a model encounters an error"""
        # Log to database
        if scan_id:
            try:
                error_log = ScanErrorLog(
                    scan_id=scan_id,
                    phase=phase,
                    error_type=error_type,
                    error_message=error_msg[:1000],  # Truncate long messages
                    model_name=model_name,
                    file_path=file_path,
                    retry_count=0
                )
                self.db.add(error_log)
                self.db.commit()
            except Exception as e:
                print(f"[ModelOrchestrator] Failed to log error: {e}")

        # Update total consecutive failures
        self._total_consecutive_failures = max(
            self._total_consecutive_failures,
            consecutive_failures
        )

        # Check if we should auto-pause
        if self._total_consecutive_failures >= self.FAILURE_THRESHOLD:
            self._should_pause = True
            if scan_id:
                from app.models.models import Scan
                try:
                    scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan and scan.status == "running":
                        scan.status = "paused"
                        scan.logs = (scan.logs or "") + f"\n[Auto-paused] {self._total_consecutive_failures} consecutive LLM failures detected\n"
                        self.db.commit()
                        print(f"[Scan {scan_id}] Auto-paused after {self._total_consecutive_failures} consecutive failures")
                except Exception as e:
                    print(f"[ModelOrchestrator] Failed to pause scan: {e}")

    def reset_failure_count(self):
        """Reset the failure counter (call after successful operations)"""
        self._total_consecutive_failures = 0
        self._should_pause = False

    @property
    def should_pause(self) -> bool:
        """Check if scan should be paused due to errors"""
        return self._should_pause

    async def initialize(self):
        """Load model configs and create pools"""
        from app.models.scanner_models import ProfileVerifier, ProfileAnalyzer

        configs = self.db.query(ModelConfig).all()

        # If profile_id is specified, get the analyzer and verifier model IDs from that profile
        if self.profile_id:
            # Load analyzer models from profile
            profile_analyzers = self.db.query(ProfileAnalyzer).filter(
                ProfileAnalyzer.profile_id == self.profile_id,
                ProfileAnalyzer.enabled == True,
                ProfileAnalyzer.role == 'analyzer'
            ).all()
            self._profile_analyzer_model_ids = {pa.model_id for pa in profile_analyzers}
            print(f"[ModelOrchestrator] Profile {self.profile_id} has {len(self._profile_analyzer_model_ids)} analyzer models")

            # Load verifier models from profile
            profile_verifiers = self.db.query(ProfileVerifier).filter(
                ProfileVerifier.profile_id == self.profile_id,
                ProfileVerifier.enabled == True
            ).all()
            self._profile_verifier_model_ids = {pv.model_id for pv in profile_verifiers}
            print(f"[ModelOrchestrator] Profile {self.profile_id} has {len(self._profile_verifier_model_ids)} verifier models")

        for config in configs:
            # Detach config from session to avoid refresh errors when accessed later
            self.db.expunge(config)
            pool = ModelPool(config, error_callback=self._on_model_error)
            await pool.start()
            self.pools[config.name] = pool

    async def shutdown(self):
        """Stop all pools"""
        for pool in self.pools.values():
            await pool.stop()

    def get_analyzers(self) -> List[ModelPool]:
        """Get analyzer model pools.

        If profile_id specified, uses profile's analyzers.
        Otherwise returns all available models (no is_analyzer filtering).
        """
        if self._profile_analyzer_model_ids:
            return [p for p in self.pools.values() if p.config.id in self._profile_analyzer_model_ids]
        # Fallback: return all models
        return list(self.pools.values())

    def get_verifiers(self) -> List[ModelPool]:
        """Get all verifier model pools.

        If a profile_id was specified, return only models from that profile's verifiers.
        Otherwise, fall back to models with is_verifier=True.
        """
        if self._profile_verifier_model_ids:
            # Use profile-specific verifiers
            return [p for p in self.pools.values() if p.config.id in self._profile_verifier_model_ids]
        # Fall back to global is_verifier flag
        return [p for p in self.pools.values() if p.config.is_verifier]

    def get_pool(self, name: str) -> Optional[ModelPool]:
        """Get a specific model pool by name"""
        return self.pools.get(name)

    def get_primary_analyzer(self) -> Optional[ModelPool]:
        """Get the first available analyzer"""
        analyzers = self.get_analyzers()
        return analyzers[0] if analyzers else None

    def get_primary_verifier(self) -> Optional[ModelPool]:
        """Get the first available verifier"""
        verifiers = self.get_verifiers()
        return verifiers[0] if verifiers else None
