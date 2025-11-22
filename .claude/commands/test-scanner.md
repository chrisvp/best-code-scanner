# Test Security Scanner

Run comprehensive tests on the security scanner implementation.

## Test Strategy

### 1. Unit Tests

Create `backend/tests/test_scanner/` directory with:

#### test_models.py
- Test all new models can be created
- Test relationships work correctly
- Test default values (max_concurrent=2)

#### test_ast_parser.py
- Test Python parsing (functions, classes, imports, calls)
- Test C parsing (functions, includes, calls)
- Test C++ parsing
- Test error handling for invalid files

#### test_static_detector.py
- Test definite vulnerability detection (gets, eval+request, etc.)
- Test safe pattern recognition
- Test needs_llm flag logic

#### test_parsers.py
- Test DraftParser with valid/invalid input
- Test VerificationParser for verified/rejected
- Test EnrichmentParser for full findings
- Test edge cases (empty, malformed)

#### test_file_chunker.py
- Test small file (single chunk)
- Test large file (multiple chunks)
- Test preamble inclusion
- Test fallback chunking

#### test_cache.py
- Test AST cache hit/miss
- Test analysis cache
- Test LRU eviction

#### test_context_retriever.py
- Test definition lookup
- Test caller resolution
- Test context string building

### 2. Integration Tests

#### test_pipeline.py
- Test full pipeline with mock LLM
- Test scanner → verifier → enricher flow
- Test batching behavior
- Test pause/resume

#### test_code_indexer.py
- Test full index build
- Test incremental update
- Test symbol resolution
- Test import resolution

### 3. End-to-End Tests

#### test_e2e.py
- Create test vulnerable files
- Run full scan
- Verify findings are correct
- Test different analysis modes

## Test Fixtures

Create `backend/tests/fixtures/`:
- `vulnerable_python.py` - Python with known vulns (eval, pickle, etc.)
- `vulnerable_c.c` - C with known vulns (gets, strcpy, sprintf)
- `safe_python.py` - Safe Python code
- `safe_c.c` - Safe C code
- `large_file.py` - File that requires chunking

## Mock LLM

Create `backend/tests/mocks/mock_llm.py`:
- MockModelPool that returns predefined responses
- Configurable responses per prompt pattern
- Track batch calls for verification

## Running Tests

```bash
cd backend
pytest tests/test_scanner/ -v
pytest tests/test_scanner/test_e2e.py -v --slow
```

## Expected Results

1. All unit tests pass
2. Integration tests demonstrate correct flow
3. E2E tests find expected vulnerabilities
4. No false positives on safe code
5. Batching reduces LLM calls
6. Caching prevents duplicate analysis
