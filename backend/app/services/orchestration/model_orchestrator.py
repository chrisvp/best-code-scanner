import asyncio
import httpx
from typing import List, Dict, Optional
from app.models.scanner_models import ModelConfig


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

    async def call_batch(self, prompts: List[str]) -> List[str]:
        """Direct batch call - bypasses queue"""
        async with self.semaphore:
            return await self._send_batch(prompts)

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
                    async with self.semaphore:
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
        async with httpx.AsyncClient(timeout=120.0, verify=False) as client:
            # Rate-limited concurrent requests
            async def send_one(prompt: str) -> str:
                async with self.semaphore:
                    try:
                        response = await client.post(
                            f"{self.config.base_url}/v1/chat/completions",
                            json={
                                "model": self.config.name,
                                "messages": [{"role": "user", "content": prompt}],
                                "max_tokens": self.config.max_tokens,
                                "temperature": 0.1
                            },
                            headers={"Authorization": f"Bearer {self.config.api_key}"}
                        )
                        response.raise_for_status()
                        data = response.json()
                        choices = data.get("choices", [])
                        if choices:
                            return choices[0].get("message", {}).get("content", "")
                        return ""
                    except Exception as e:
                        print(f"Request failed: {e}")
                        return ""

            tasks = [send_one(prompt) for prompt in prompts]
            return await asyncio.gather(*tasks)


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
