import asyncio
import httpx
import time
from typing import List, Dict, Optional, Any
from app.models.scanner_models import ModelConfig
from app.services.llm_logger import llm_logger


class ModelPool:
    """Manages concurrent access to a single model with batching support"""

    def __init__(self, config: ModelConfig):
        self.config = config
        self.semaphore = asyncio.Semaphore(config.max_concurrent)  # Default 2
        self.batch_queue: asyncio.Queue = asyncio.Queue()
        self.batch_size = 10
        self.batch_timeout = 0.5  # Seconds to wait for batch to fill
        self._batch_task: Optional[asyncio.Task] = None
        self._running = False
        # Logging context (set by caller before making calls)
        self._log_context: Dict[str, Any] = {}

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

    async def call_batch(self, prompts: List[str], log_context: Optional[Dict[str, Any]] = None) -> List[str]:
        """Direct batch call - bypasses queue"""
        if log_context:
            self._log_context = log_context
        return await self._send_batch(prompts)

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

    async def _send_batch(self, prompts: List[str]) -> List[str]:
        """Send batch to vLLM using chat completions"""
        results = []
        log_context = self._log_context.copy()

        async with httpx.AsyncClient(timeout=600.0, verify=False) as client:
            # Rate-limited concurrent requests
            async def send_one(prompt: str, idx: int) -> tuple:
                """Returns (response_content, prompt, duration_ms, tokens_in, tokens_out, error)"""
                async with self.semaphore:
                    start_time = time.time()
                    tokens_in = None
                    tokens_out = None
                    error = None

                    try:
                        base = self.config.base_url.rstrip('/')
                        if base.endswith('/v1'):
                            url = f"{base}/chat/completions"
                        else:
                            url = f"{base}/v1/chat/completions"

                        request_payload = {
                            "model": self.config.name,
                            "messages": [{"role": "user", "content": prompt}],
                            "max_tokens": self.config.max_tokens,
                            "temperature": 0.1
                        }

                        response = await client.post(
                            url,
                            json=request_payload,
                            headers={"Authorization": f"Bearer {self.config.api_key}"}
                        )

                        # Check for errors and get detailed error message
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

                            prompt_len = len(prompt)
                            print(f"[LLM ERROR] {self.config.name} returned {response.status_code}: {error_message}")
                            print(f"[LLM ERROR] Prompt length: {prompt_len} chars, max_tokens: {self.config.max_tokens}")
                            if prompt_len > 1000:
                                print(f"[LLM ERROR] Prompt preview: {prompt[:500]}...{prompt[-200:]}")

                            duration_ms = (time.time() - start_time) * 1000
                            return ("", prompt, duration_ms, None, None, f"HTTP {response.status_code}: {error_message}")

                        data = response.json()

                        # Extract token usage if available
                        usage = data.get("usage", {})
                        tokens_in = usage.get("prompt_tokens")
                        tokens_out = usage.get("completion_tokens")

                        choices = data.get("choices", [])
                        if choices:
                            message = choices[0].get("message", {})
                            content = message.get("content", "")

                            # Handle reasoning models that return thinking in separate field
                            # API returns this format when model name contains "thinking" or "reasoning"
                            thinking = message.get("thinking", "")
                            reasoning_content = message.get("reasoning_content", "")

                            # Use whichever field is present
                            reasoning = thinking or reasoning_content
                            if reasoning:
                                # Wrap reasoning in tags for parser consistency
                                content = f"<thinking>{reasoning}</thinking>\n{content}"

                            duration_ms = (time.time() - start_time) * 1000
                            return (content, prompt, duration_ms, tokens_in, tokens_out, None)

                        duration_ms = (time.time() - start_time) * 1000
                        return ("", prompt, duration_ms, tokens_in, tokens_out, None)

                    except Exception as e:
                        import traceback
                        error_msg = f"{type(e).__name__}: {e}"
                        print(f"Request failed for {self.config.name}: {error_msg}")
                        traceback.print_exc()
                        duration_ms = (time.time() - start_time) * 1000
                        return ("", prompt, duration_ms, tokens_in, tokens_out, error_msg)

            tasks = [send_one(prompt, i) for i, prompt in enumerate(prompts)]
            batch_results = await asyncio.gather(*tasks)

            # Log all results
            for content, prompt, duration_ms, tokens_in, tokens_out, error in batch_results:
                results.append(content)

                # Log this request/response
                llm_logger.log(
                    model_name=self.config.name,
                    phase=log_context.get('phase', 'unknown'),
                    request_prompt=prompt,
                    raw_response=content,
                    scan_id=log_context.get('scan_id'),
                    mr_review_id=log_context.get('mr_review_id'),
                    analyzer_name=log_context.get('analyzer_name'),
                    file_path=log_context.get('file_path'),
                    chunk_id=log_context.get('chunk_id'),
                    parse_success=error is None,
                    parse_error=error,
                    tokens_in=tokens_in,
                    tokens_out=tokens_out,
                    duration_ms=duration_ms,
                )

        return results


class ModelOrchestrator:
    """Manages all model pools"""

    def __init__(self, db):
        self.db = db
        self.pools: Dict[str, ModelPool] = {}

    async def initialize(self):
        """Load model configs and create pools"""
        configs = self.db.query(ModelConfig).all()

        for config in configs:
            pool = ModelPool(config)
            await pool.start()
            self.pools[config.name] = pool

    async def shutdown(self):
        """Stop all pools"""
        for pool in self.pools.values():
            await pool.stop()

    def get_analyzers(self) -> List[ModelPool]:
        """Get all analyzer model pools"""
        return [p for p in self.pools.values() if p.config.is_analyzer]

    def get_verifiers(self) -> List[ModelPool]:
        """Get all verifier model pools"""
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
