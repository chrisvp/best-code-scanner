# Implement Pipeline Coordinator and Orchestration

Create the model orchestrator with vLLM batching and the pipeline coordinator.

## Task

Implement the core orchestration and pipeline coordination.

## Files to Create

### 1. backend/app/services/orchestration/__init__.py

### 2. backend/app/services/orchestration/cache.py

```python
class AnalysisCache:
    def __init__(self, max_ast_cache=10000, max_analysis_cache=50000):
        self.ast_cache = {}
        self.analysis_cache = {}
        self.symbol_cache = {}

    def get_ast(self, file_path: str, mtime: float) -> Optional[ParsedFile]
    def set_ast(self, file_path: str, mtime: float, parsed: ParsedFile)

    def get_analysis(self, content_hash: str) -> Optional[List[DraftFinding]]
    def set_analysis(self, content_hash: str, findings: List[DraftFinding])

    @staticmethod
    def hash_content(content: str) -> str:
        return hashlib.md5(content.encode()).hexdigest()
```

### 3. backend/app/services/orchestration/model_orchestrator.py

#### ModelPool class
```python
class ModelPool:
    def __init__(self, config: ModelConfig):
        self.config = config
        self.semaphore = asyncio.Semaphore(config.max_concurrent)  # Default 2
        self.batch_queue = asyncio.Queue()
        self.batch_size = 10
        self.batch_timeout = 0.5
        self._batch_task = None

    async def start(self):
        self._batch_task = asyncio.create_task(self._batch_processor())

    async def stop(self):
        if self._batch_task:
            self._batch_task.cancel()

    async def call(self, prompt: str) -> str:
        # Single prompt - gets batched
        future = asyncio.Future()
        await self.batch_queue.put((prompt, future))
        return await future

    async def call_batch(self, prompts: List[str]) -> List[str]:
        # Direct batch call
        async with self.semaphore:
            return await self._send_batch(prompts)

    async def _batch_processor(self):
        # Collect prompts up to batch_size or timeout
        # Send batch
        # Resolve futures

    async def _send_batch(self, prompts: List[str]) -> List[str]:
        # POST to vLLM with list of prompts
        # Return list of completions
```

#### ModelOrchestrator class
```python
class ModelOrchestrator:
    def __init__(self, db):
        self.db = db
        self.pools: Dict[str, ModelPool] = {}

    async def initialize(self):
        configs = self.db.query(ModelConfig).all()
        for config in configs:
            pool = ModelPool(config)
            await pool.start()
            self.pools[config.name] = pool

    async def shutdown(self):
        for pool in self.pools.values():
            await pool.stop()

    def get_analyzers(self) -> List[ModelPool]
    def get_verifiers(self) -> List[ModelPool]
    def get_pool(self, name: str) -> ModelPool
```

### 4. backend/app/services/orchestration/pipeline.py

```python
class ScanPipeline:
    def __init__(self, scan_id: int, config: ScanConfig, db):
        self.scan_id = scan_id
        self.config = config
        self.db = db
        self.model_orchestrator = None
        self.cache = AnalysisCache()
        self.code_indexer = None

    async def run(self):
        # Initialize model orchestrator
        # Build code index
        # Run three phases in parallel
        # Cleanup

    async def _run_scanner_phase(self):
        # Get batches of pending chunks
        # Mark as scanning
        # Call scanner.scan_batch()
        # Save draft findings
        # Mark chunks as scanned

    async def _run_verifier_phase(self):
        # Get batches of pending drafts (priority order)
        # Mark as verifying
        # Call verifier.verify_batch()
        # Save verified findings or mark rejected

    async def _run_enricher_phase(self):
        # Get batches of pending verified findings
        # Mark as enriching
        # Call enricher.enrich_batch()
        # Save final findings
```

### 5. backend/app/services/orchestration/checkpoint.py

```python
class ScanCheckpoint:
    def __init__(self, scan_id: int, db):
        self.scan_id = scan_id
        self.db = db

    def save(self):
        # State is in DB via statuses
        pass

    def recover(self):
        # Reset "scanning"/"verifying"/"enriching" back to "pending"
        self.db.query(ScanFileChunk).filter(
            ScanFileChunk.scan_file_id.in_(
                self.db.query(ScanFile.id).filter(ScanFile.scan_id == self.scan_id)
            ),
            ScanFileChunk.status.in_(["scanning"])
        ).update({"status": "pending"}, synchronize_session=False)

        # Similar for DraftFinding, VerifiedFinding
        self.db.commit()
```

## vLLM Batch API

```python
async def _send_batch(self, prompts: List[str]) -> List[str]:
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            f"{self.config.base_url}/v1/completions",
            json={
                "model": self.config.name,
                "prompt": prompts,  # List of prompts
                "max_tokens": self.config.max_tokens,
                "temperature": 0.1
            },
            headers={"Authorization": f"Bearer {self.config.api_key}"}
        )
        response.raise_for_status()
        data = response.json()
        return [choice["text"] for choice in data["choices"]]
```

## Batch Processor Logic

```python
async def _batch_processor(self):
    while True:
        batch = []
        futures = []

        # Wait for first item
        prompt, future = await self.batch_queue.get()
        batch.append(prompt)
        futures.append(future)

        # Collect more up to batch_size or timeout
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

        # Send and resolve
        try:
            async with self.semaphore:
                results = await self._send_batch(batch)
            for future, result in zip(futures, results):
                future.set_result(result)
        except Exception as e:
            for future in futures:
                if not future.done():
                    future.set_exception(e)
```

## Pipeline Phase Coordination

Each phase runs as separate async task, communicating via database:
- Scanner writes DraftFinding with status="pending"
- Verifier reads pending drafts, writes VerifiedFinding
- Enricher reads pending verified, writes Finding

Use `with_for_update(skip_locked=True)` to allow parallel workers.
