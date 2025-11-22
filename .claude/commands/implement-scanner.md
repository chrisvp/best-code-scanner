# Implement Security Scanner Refactoring

You are implementing the security scanner refactoring as defined in IMPLEMENTATION_PLAN.md.

## Your Task

Implement all phases of the scanner refactoring. Work through each phase sequentially, ensuring each component is complete before moving to the next.

## Implementation Order

### Phase 1: Database Models
Create `backend/app/models/scanner_models.py` with all models:
- ModelConfig (max_concurrent default=2)
- ScanConfig
- ScanFile
- ScanFileChunk
- Symbol
- SymbolReference
- ImportRelation
- DraftFinding
- VerifiedFinding

Update `backend/app/models/models.py` to extend Finding model with new fields.

### Phase 2: Model Orchestrator
Create `backend/app/services/orchestration/model_orchestrator.py`:
- ModelPool class with vLLM batching support
- Semaphore-based concurrency control (default 2 per model)
- Batch queue with configurable batch_size and timeout
- ModelOrchestrator to manage all pools

Create `backend/app/services/orchestration/cache.py`:
- AnalysisCache with AST cache, analysis cache, symbol cache
- LRU eviction
- Content hashing

Create `backend/app/services/orchestration/__init__.py`

### Phase 3: Code Intelligence
Create `backend/app/services/intelligence/ast_parser.py`:
- ASTParser with tree-sitter for Python, C, C++
- ParsedFile class with extraction methods
- FunctionDef, ClassDef, ImportDef, CallSite dataclasses

Create `backend/app/services/intelligence/code_indexer.py`:
- CodeIndexer to build full codebase index
- Symbol extraction and storage
- Import resolution
- Incremental indexing support

Create `backend/app/services/intelligence/context_retriever.py`:
- ContextRetriever to fetch relevant context
- Definition lookup
- Caller/callee resolution
- Context string building for LLM

Create `backend/app/services/intelligence/__init__.py`

### Phase 4: Pipeline Components
Create `backend/app/services/analysis/static_detector.py`:
- StaticPatternDetector with DEFINITE_VULNS and SAFE_PATTERNS
- Fast regex-based detection for obvious vulnerabilities
- Returns (findings, needs_llm) tuple

Create `backend/app/services/analysis/parsers.py`:
- DraftParser for lightweight format
- VerificationParser for verify/reject format
- EnrichmentParser for full report format

Create `backend/app/services/analysis/draft_scanner.py`:
- DraftScanner with batching support
- Cache checking, static detection, LLM fallback
- Batch multiple chunks per LLM call

Create `backend/app/services/analysis/verifier.py`:
- FindingVerifier with context retrieval
- Priority-based processing
- Severity adjustment support

Create `backend/app/services/analysis/enricher.py`:
- FindingEnricher for full reports
- Batch enrichment

Create `backend/app/services/analysis/file_chunker.py`:
- FileChunker using tree-sitter
- Semantic chunking by functions/classes
- Preamble (imports) included with each chunk
- Fallback to simple chunking

Create `backend/app/services/analysis/__init__.py`

### Phase 5: Pipeline Coordinator
Create `backend/app/services/orchestration/pipeline.py`:
- ScanPipeline coordinating all phases
- Parallel workers for scanner, verifier, enricher
- Batch processing at each phase
- Progress tracking
- Checkpoint/resume support

Create `backend/app/services/orchestration/checkpoint.py`:
- ScanCheckpoint for pause/resume
- State recovery

### Phase 6: API Integration
Update `backend/app/api/endpoints.py`:
- New /scan/start with config options
- /scan/{id}/progress endpoint
- /scan/{id}/pause and /scan/{id}/resume
- Wire up the new pipeline

Update `backend/requirements.txt`:
- Add tree-sitter-cpp

## Key Requirements

1. **Concurrency**: Default 2 per model, configurable via ModelConfig.max_concurrent
2. **Batching**: Use vLLM batch API (list of prompts)
3. **Formats**: Use custom text formats, not JSON (see IMPLEMENTATION_PLAN.md)
4. **Context**: Always retrieve and provide code context for verification
5. **Static Detection**: Skip LLM for obvious patterns
6. **Caching**: Cache by content hash to avoid redundant analysis

## Testing

After implementation, verify:
1. Models can be created and queried
2. AST parser works for Python/C/C++
3. Static detector catches obvious vulns
4. Pipeline runs end-to-end
5. Batching works correctly

## Output

After completing each phase, report what was implemented and any issues encountered.
