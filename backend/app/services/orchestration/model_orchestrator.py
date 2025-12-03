import asyncio
import httpx
import time
from typing import List, Dict, Optional, Any, Callable
from app.models.scanner_models import ModelConfig, ScanErrorLog
from app.services.llm_logger import llm_logger
from app.core.config import settings


class ModelPool:
    """Manages concurrent access to a single model with batching support"""

    def __init__(self, config: ModelConfig, error_callback: Optional[Callable] = None):
        self.config = config
        self.semaphore = asyncio.Semaphore(config.max_concurrent)  # Default 2
        self.batch_queue: asyncio.Queue = asyncio.Queue()
        self.batch_size = 10
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
                        # Fall back to default settings if model config is missing values
                        base_url = self.config.base_url or settings.LLM_BASE_URL
                        api_key = self.config.api_key or settings.LLM_API_KEY

                        if not base_url:
                            duration_ms = (time.time() - start_time) * 1000
                            return ("", prompt, duration_ms, None, None, f"Model '{self.config.name}' has no base_url configured and no default set")

                        base = base_url.rstrip('/')
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
                            headers={"Authorization": f"Bearer {api_key}"}
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

            # Count errors in this batch
            batch_errors = sum(1 for _, _, _, _, _, error in batch_results if error)
            batch_successes = len(batch_results) - batch_errors

            # Update consecutive failure tracking
            if batch_errors == len(batch_results):
                # All failed - increment consecutive failures
                self._consecutive_failures += batch_errors
            elif batch_successes > 0:
                # At least one success - reset counter
                self._consecutive_failures = 0

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
        from app.models.scanner_models import ProfileVerifier

        configs = self.db.query(ModelConfig).all()

        # If profile_id is specified, get the verifier model IDs from that profile
        if self.profile_id:
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
        """Get all analyzer model pools"""
        return [p for p in self.pools.values() if p.config.is_analyzer]

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
