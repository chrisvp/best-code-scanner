# Security Scanner Refactoring - Implementation Plan

## Overview

Refactoring the security scanner into a high-performance, context-aware vulnerability detection system with:
- Three-phase pipeline: Draft Scanning → Verification → Enrichment
- Full code intelligence via tree-sitter
- vLLM batch inference support
- Configurable concurrency (default: 2 per model)
- Static pattern detection for speed
- Pause/resume capability

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      CodeIndex                               │
│  Symbol tables, cross-references, call graph                │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────┐     ┌─────────┴────┐     ┌─────────────┐
│   Scanner   │ ──▶ │   Verifier   │ ──▶ │  Enricher   │
│             │     │              │     │             │
│ Draft       │     │ Validate     │     │ Full Report │
│ Findings    │     │ w/ Context   │     │ + Fix       │
└─────────────┘     └──────────────┘     └─────────────┘
```

## vLLM Batching

Send multiple prompts per request for maximum throughput:

```python
POST /v1/completions
{
    "model": "llama3.3-70b",
    "prompt": ["prompt1", "prompt2", "prompt3", ...],
    "max_tokens": 2000
}
```

## Configuration

### Model Configuration
- `max_concurrent`: Requests per model (default: 2)
- `votes`: Voting weight for consensus
- `is_analyzer` / `is_verifier`: Role assignment
- Custom prompt templates per model

### Scan Configuration
- `analysis_mode`: "primary_verifiers" or "multi_consensus"
- `scope`: "full" or "incremental"
- `scanner_concurrency`: Parallel scanner workers
- `verifier_concurrency`: Parallel verifier workers
- `enricher_concurrency`: Parallel enricher workers

## Pipeline Phases

### Phase 1: Draft Scanning (Fast)

Lightweight format for quick flagging:

```
*DRAFT: Short title
*TYPE: vulnerability type
*SEVERITY: High/Medium/Low
*LINE: 45
*SNIPPET: os.system(cmd)
*REASON: User input passed to shell command
*END_DRAFT
```

Process:
1. Check cache for identical code
2. Run static pattern detection (instant)
3. If interesting patterns found, send to LLM
4. Batch multiple chunks per LLM call

### Phase 2: Verification (Context-Aware)

Validates drafts with code intelligence:

```
*VERIFIED: Command Injection in execute_task
*CONFIDENCE: 92
*ATTACK_VECTOR: User controls task_id which selects command from DB
*DATA_FLOW: request.form['task_id'] → get_task() → task.command → os.system()
*END_VERIFIED
```

Or:

```
*REJECTED: Potential SQL injection in query
*REASON: Query uses parameterized statements
*END_REJECTED
```

Process:
1. Retrieve context (definitions, callers, data flow)
2. Priority queue (Critical first)
3. Batch verification calls
4. Can adjust severity based on context

### Phase 3: Enrichment (Detailed Report)

Full report for verified findings only:

```
*FINDING: Command Injection via User-Controlled Task Execution
*CATEGORY: CWE-78 OS Command Injection
*SEVERITY: Critical
*CVSS: 9.8
*IMPACTED_CODE: ...
*VULNERABILITY_DETAILS: ...
*PROOF_OF_CONCEPT: ...
*CORRECTED_CODE: ...
*REMEDIATION_STEPS: ...
*REFERENCES: ...
*END_FINDING
```

## Code Intelligence

### Capabilities
- **Symbol Resolution**: Find definition of any symbol
- **Import Resolution**: Follow imports to source files
- **Call Graph**: Who calls what, reverse lookup
- **Context Retrieval**: Fetch relevant code for LLM

### Tree-sitter Integration
- Python, C, C++ parsers
- Extract functions, classes, imports, calls
- Build full codebase index

## Speed Optimizations

### Static Pattern Detection
Auto-detect without LLM:
- `gets()` → Buffer Overflow (Critical)
- `eval(request.*)` → Code Injection (Critical)
- `strcpy(*, argv)` → Buffer Overflow (High)

### Caching
- AST cache (parsed files)
- Analysis cache (content hash → findings)
- Symbol cache (lookups)

### Risk-Based Prioritization
- High risk: auth, login, password, exec, sql
- Low risk: tests, docs, vendor, generated

### Incremental Indexing
Only re-index changed files on subsequent scans.

## Database Schema

### New Models
- `ModelConfig`: LLM configuration with concurrency settings
- `ScanConfig`: Per-scan configuration
- `ScanFile`: File-level tracking with hash
- `ScanFileChunk`: Chunk-level tracking
- `Symbol`: Indexed code symbols
- `SymbolReference`: Cross-references
- `ImportRelation`: Import mappings
- `DraftFinding`: Initial findings
- `VerifiedFinding`: Validated findings
- `Finding`: Final enriched reports (extended)

## File Structure

```
backend/
├── app/
│   ├── models/
│   │   ├── models.py              # Existing (Scan, Finding)
│   │   └── scanner_models.py      # New models
│   ├── services/
│   │   ├── orchestration/
│   │   │   ├── model_orchestrator.py
│   │   │   ├── pipeline.py
│   │   │   ├── cache.py
│   │   │   └── checkpoint.py
│   │   ├── intelligence/
│   │   │   ├── ast_parser.py
│   │   │   ├── code_indexer.py
│   │   │   └── context_retriever.py
│   │   ├── analysis/
│   │   │   ├── static_detector.py
│   │   │   ├── draft_scanner.py
│   │   │   ├── verifier.py
│   │   │   ├── enricher.py
│   │   │   ├── file_chunker.py
│   │   │   └── parsers.py
│   │   └── ingestion.py
│   └── api/
│       └── endpoints.py
└── requirements.txt
```

## Implementation Timeline

| Week | Phase | Deliverable |
|------|-------|-------------|
| 1 | Phase 1 | Database models, migrations |
| 1 | Phase 2 | ModelOrchestrator with vLLM batching |
| 2 | Phase 3 | AST parser, Code indexer |
| 2 | Phase 6 | File chunker |
| 3 | Phase 4 | Static detector, Scanner, Verifier, Enricher |
| 4 | Phase 5 | Pipeline coordinator |
| 4 | Phase 7 | API integration |
| 5 | Testing | End-to-end testing, optimization |

## Configuration Defaults

```python
# Model defaults
max_concurrent = 2  # Per model
max_tokens = 4096
votes = 1

# Pipeline defaults
scanner_concurrency = 20  # Workers
verifier_concurrency = 10
enricher_concurrency = 5

# Batching
batch_size_scan = 10
batch_size_verify = 5
batch_size_enrich = 3
batch_timeout = 0.5  # seconds

# Chunking
max_chunk_tokens = 3000

# Context
max_context_tokens = 4000
```

## API Endpoints

### Start Scan
```
POST /scan/start
- target_url: Git URL or archive path
- analysis_mode: "primary_verifiers" | "multi_consensus"
- scope: "full" | "incremental"
```

### Get Progress
```
GET /scan/{scan_id}/progress
Returns: chunks, drafts, verified, findings counts
```

### Pause/Resume
```
POST /scan/{scan_id}/pause
POST /scan/{scan_id}/resume
```

## Future Enhancements

- GitLab API integration for continuous monitoring
- PoC validation (on-demand exploit generation)
- Distributed scanning across multiple workers
- Model performance metrics and accuracy tracking
- User feedback loop for false positive learning
