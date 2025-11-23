# Agentic Firmware Security Scanner - Architecture & Design

## Overview

An LLM-powered security vulnerability scanner that analyzes code repositories using multi-model voting and a three-phase pipeline to identify, verify, and enrich security findings. Designed for firmware and embedded systems code (C, C++, Python).

## Tech Stack

- **Backend**: FastAPI (Python 3.11+)
- **Database**: SQLite with SQLAlchemy ORM
- **LLM Integration**: AsyncOpenAI client (vLLM-compatible)
- **Code Intelligence**: tree-sitter for AST parsing
- **Frontend**: HTMX + Jinja2 templates
- **Inference**: vLLM batch inference for high throughput

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        API Layer                            │
│                   (FastAPI endpoints)                       │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│                   Scan Pipeline                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                   │
│  │ Scanner  │→ │ Verifier │→ │ Enricher │                   │
│  │ (Draft)  │  │ (Verify) │  │ (Report) │                   │
│  └──────────┘  └──────────┘  └──────────┘                   │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│              Model Orchestrator                             │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐               │
│  │ Model Pool │ │ Model Pool │ │ Model Pool │               │
│  │ (mistral)  │ │ (llama)    │ │ (gpt-oss)  │               │
│  └────────────┘ └────────────┘ └────────────┘               │
└─────────────────────────────────────────────────────────────┘
```

## Three-Phase Pipeline

### Phase 1: Draft Scanning

**Purpose**: Fast initial scan to identify potential vulnerabilities

**Process**:
1. Code is chunked into segments (configurable `chunk_size`, default 3000 tokens)
2. Each chunk is sent to analyzer models
3. Multi-model mode: All analyzers scan each chunk, findings are deduplicated
4. Single-model mode: Primary analyzer only
5. Findings are stored as `DraftFinding` with initial vote counts

**Output Format** (lightweight JSON):
```json
{
  "findings": [
    {
      "title": "Buffer Overflow",
      "type": "CWE-120",
      "severity": "High",
      "line": 42,
      "snippet": "strcpy(buffer, input);",
      "reason": "No bounds checking on input"
    }
  ]
}
```

**Deduplication**: Drafts with same `file + line + type` are merged, votes combined

### Phase 2: Verification

**Purpose**: Context-aware validation to filter false positives

**Process**:
1. Drafts with sufficient votes are prioritized by severity
2. Each draft gets full context via Code Intelligence:
   - Function definitions
   - Import statements
   - Call graph relationships
3. Multiple verifier models vote: `VERIFY`, `WEAKNESS`, or `REJECT`
4. Majority vote determines outcome
5. Verified findings get `VerifiedFinding` record with confidence scores

**Voting Logic**:
- `VERIFY`: Exploitable vulnerability
- `WEAKNESS`: Code smell but not exploitable
- `REJECT`: False positive

### Phase 3: Enrichment

**Purpose**: Generate comprehensive security reports for verified findings

**Process**:
1. Only verified findings are enriched
2. Primary analyzer generates full report with:
   - Detailed vulnerability explanation
   - CVSS score calculation
   - Attack vectors and data flow
   - Proof of concept
   - Corrected code
   - Remediation steps
   - References

**Output**: Full `Finding` record for display in UI

## Configuration Options

### Scan Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `multi_model_scan` | true | Use all analyzers for initial scan |
| `batch_size` | 10 | Chunks processed per batch |
| `chunk_size` | 3000 | Max tokens per code chunk |
| `min_votes_to_verify` | 1 | Minimum votes to proceed to verification |
| `deduplicate_drafts` | true | Merge duplicate findings |

### Model Configuration

Each model can be configured with:
- `name`: Model identifier
- `base_url`: vLLM endpoint
- `api_key`: Authentication
- `is_analyzer`: Can scan for vulnerabilities
- `is_verifier`: Can vote on findings
- `concurrency`: Parallel requests (default 2)

### Recommended Models

- **gpt-oss-120b**: Best for large context windows, high accuracy
- **llama3.3-70b-instruct**: Good balance of speed and accuracy
- **mistral-small**: Fast, good for initial screening

## Code Intelligence

Tree-sitter powered AST analysis provides:

- **Function extraction**: Definitions, parameters, return types
- **Import resolution**: Dependencies and includes
- **Call graph**: Function relationships
- **Context retrieval**: Surrounding code for verification

Supports: C, C++, Python

## Performance Optimizations

### Implemented

1. **vLLM Batch Inference**: Send multiple prompts per request
2. **Parallel Phases**: Scanner, verifier, enricher run concurrently
3. **Priority Queuing**: High-severity findings processed first
4. **Deduplication**: Reduce redundant LLM calls
5. **Risk-based Chunking**: High-risk files (network, crypto) prioritized

### Results

- Scan time: 42 min → 13.6 min (67% faster)
- LLM calls: 637 → 125 (80% reduction)

## Metrics & Benchmarking

### Tracked Metrics

**Per-scan (`ScanMetrics`)**:
- Total chunks
- Avg/min/max tokens per chunk
- Chunk size setting

**Per-model (`LLMCallMetric`)**:
- Call count
- Total time (ms)
- Tokens submitted (estimated)
- Phase (scanner/verifier/enricher)

### Query Metrics

```bash
python scripts/scan_metrics.py [scan_id]
```

Output:
```
SCAN METRICS - Scan #1
Target: https://github.com/user/repo
Config:
  - Multi-model scan: True
  - Chunk size: 3000

ACTUAL METRICS:
SCANNER:
  mistral-small: 12 calls, 45.2s, 48,000 tokens
  llama3.3-70b: 12 calls, 52.1s, 48,000 tokens
```

## Current Tuning Status

### What's Working

- Multi-model voting reduces false positives significantly
- Deduplication effectively merges duplicate findings
- Priority-based processing handles large repos efficiently
- Timing metrics identify bottlenecks

### Areas for Tuning

1. **Chunk Size Optimization**
   - Test larger chunks (6000-8000 tokens) with gpt-oss-120b
   - Compare accuracy vs. speed tradeoffs

2. **Model Selection**
   - Benchmark gpt-oss-120b vs. llama3.3-70b for accuracy
   - Evaluate smaller models for draft scanning

3. **Prompt Templates**
   - Scanner prompts in `backend/app/prompts/`
   - Tune for specific vulnerability classes
   - Add few-shot examples for edge cases

4. **Vote Thresholds**
   - Test `min_votes_to_verify` = 2 or 3 for higher confidence
   - Adjust for precision vs. recall

### Test Samples

`test_samples/vulnerable_cpp/` contains 4 files with 40+ intentional CWE patterns:
- `sample_01.cpp`: Buffer overflows (CWE-120, 121, 122, etc.)
- `sample_02.cpp`: Memory issues (CWE-415, 416, 401, etc.)
- `sample_03.cpp`: Injection (CWE-78, 88, 426, etc.)
- `sample_04.cpp`: Integer issues (CWE-190, 191, 681, etc.)

Use these to benchmark scanner accuracy before scanning production repos.

## Database Schema

### Core Tables

- `scans`: Scan status, target, logs
- `scan_config`: Per-scan configuration
- `scan_files`: Discovered files with risk levels
- `scan_file_chunks`: Code chunks for analysis

### Finding Pipeline

- `draft_findings`: Initial scan results
- `verified_findings`: Verified vulnerabilities
- `findings`: Final enriched reports

### Metrics

- `llm_call_metrics`: Per-model timing and token counts
- `scan_metrics`: Scan-level chunk statistics
- `model_configs`: Registered LLM models

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scan/start` | POST | Start new scan |
| `/scan/{id}/progress` | GET | Get scan progress |
| `/scan/{id}/findings` | GET | Get findings |
| `/models` | GET/POST | Manage models |
| `/config` | GET/POST | Runtime configuration |

## Next Steps

1. **Accuracy Benchmarking**: Run test samples with different model configs
2. **Prompt Optimization**: Tune scanner prompts for specific CWE classes
3. **Chunk Size Testing**: Evaluate larger chunks with long-context models
4. **Production Hardening**: Add rate limiting, auth, logging

## Usage

### Start Server

```bash
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Configure Models

```bash
curl -X POST http://localhost:8000/models \
  -F "name=gpt-oss-120b" \
  -F "base_url=https://your-vllm:5000" \
  -F "api_key=test" \
  -F "is_analyzer=true" \
  -F "is_verifier=true"
```

### Run Scan

```bash
curl -X POST http://localhost:8000/scan/start \
  -F "target_url=https://github.com/user/repo" \
  -F "chunk_size=3000" \
  -F "multi_model_scan=true"
```

### Query Metrics

```bash
python scripts/scan_metrics.py
```

## References

- [vLLM Documentation](https://vllm.readthedocs.io/)
- [tree-sitter](https://tree-sitter.github.io/)
- [CWE Database](https://cwe.mitre.org/)
