# Build Complete Security Scanner

Implement the entire security scanner refactoring from start to finish.

## Overview

This command implements the complete scanner as defined in IMPLEMENTATION_PLAN.md.
Execute each phase in order. Do not skip phases.

## Execution Order

### Step 1: Create Directory Structure
```bash
mkdir -p backend/app/services/orchestration
mkdir -p backend/app/services/intelligence
mkdir -p backend/app/services/analysis
```

### Step 2: Implement Database Models
Follow: /implement-models

Create `backend/app/models/scanner_models.py` with all models.
Key: ModelConfig.max_concurrent defaults to 2.

### Step 3: Implement Orchestration Layer
Follow: /implement-pipeline

Create:
- backend/app/services/orchestration/__init__.py
- backend/app/services/orchestration/cache.py
- backend/app/services/orchestration/model_orchestrator.py
- backend/app/services/orchestration/pipeline.py
- backend/app/services/orchestration/checkpoint.py

Key: vLLM batching sends list of prompts.

### Step 4: Implement Code Intelligence
Follow: /implement-intelligence

Create:
- backend/app/services/intelligence/__init__.py
- backend/app/services/intelligence/ast_parser.py
- backend/app/services/intelligence/code_indexer.py
- backend/app/services/intelligence/context_retriever.py

Key: Tree-sitter for Python, C, C++.

### Step 5: Implement Analysis Components
Follow: /implement-analysis

Create:
- backend/app/services/analysis/__init__.py
- backend/app/services/analysis/static_detector.py
- backend/app/services/analysis/parsers.py
- backend/app/services/analysis/draft_scanner.py
- backend/app/services/analysis/verifier.py
- backend/app/services/analysis/enricher.py
- backend/app/services/analysis/file_chunker.py

Key: Use custom text format, not JSON.

### Step 6: Implement API Integration
Follow: /implement-api

Update:
- backend/app/api/endpoints.py
- backend/requirements.txt

Add new endpoints for progress, pause/resume, model config.

### Step 7: Update Existing Models
Modify `backend/app/models/models.py`:
- Add verified_id, vulnerability_details, proof_of_concept, etc. to Finding

### Step 8: Create Tests
Follow: /test-scanner

Create test directory and files.

## Critical Requirements

1. **Concurrency Default**: ModelConfig.max_concurrent = 2
2. **vLLM Batching**: Send prompts as list to /v1/completions
3. **Custom Format**: Use *FIELD: value format, not JSON
4. **Context Retrieval**: Always fetch definitions/callers for verification
5. **Static Detection**: Skip LLM for obvious patterns like gets(), eval(request.*)
6. **Caching**: Cache by content hash

## File Summary

After completion, you should have created:

```
backend/
├── app/
│   ├── models/
│   │   ├── models.py (modified)
│   │   └── scanner_models.py (new)
│   ├── services/
│   │   ├── orchestration/
│   │   │   ├── __init__.py
│   │   │   ├── cache.py
│   │   │   ├── checkpoint.py
│   │   │   ├── model_orchestrator.py
│   │   │   └── pipeline.py
│   │   ├── intelligence/
│   │   │   ├── __init__.py
│   │   │   ├── ast_parser.py
│   │   │   ├── code_indexer.py
│   │   │   └── context_retriever.py
│   │   └── analysis/
│   │       ├── __init__.py
│   │       ├── draft_scanner.py
│   │       ├── enricher.py
│   │       ├── file_chunker.py
│   │       ├── parsers.py
│   │       ├── static_detector.py
│   │       └── verifier.py
│   └── api/
│       └── endpoints.py (modified)
├── requirements.txt (modified)
└── tests/
    └── test_scanner/ (new)
```

## Validation

After implementation:

1. Run `python -c "from app.models.scanner_models import *"` - no errors
2. Run `python -c "from app.services.orchestration import *"` - no errors
3. Run `python -c "from app.services.intelligence import *"` - no errors
4. Run `python -c "from app.services.analysis import *"` - no errors
5. Start server: `uvicorn main:app --reload`
6. Create model via API
7. Start test scan
8. Check progress endpoint

## Notes

- Read IMPLEMENTATION_PLAN.md for full architecture details
- Reference individual /implement-* commands for detailed specs
- Run /test-scanner after implementation to verify
