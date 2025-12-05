# Code Scanner - Codebase Audit Findings

**Date**: 2025-12-05
**Purpose**: Identify technical debt, orphaned code, and architectural issues before implementing streaming LLM support.

---

## Executive Summary

The audit found **4 major areas** needing attention:

1. **LLM calls are NOT fully centralized** - 4 places bypass the main orchestrator
2. **Significant orphaned code** - Legacy scanning engine, unused services, dead config
3. **Database schema issues** - Missing cascades left 20k+ orphaned records
4. **Code quality issues** - Duplicate endpoints, hardcoded paths, silent exception swallowing

---

## 1. LLM Call Sites Analysis

### Current Architecture

There are **two** LLM access patterns that should ideally be **one**:

| Component | Location | Pattern |
|-----------|----------|---------|
| `LLMProvider` | `services/llm_provider.py` | AsyncOpenAI client wrapper |
| `ModelOrchestrator/ModelPool` | `services/orchestration/model_orchestrator.py` | Raw httpx with batching, semaphores |

### Properly Centralized Calls (GOOD)

| File | Lines | Method | Notes |
|------|-------|--------|-------|
| `api/endpoints.py` | 782, 1794, 4797 | `llm_provider.chat_completion()` | Chat, cleanup, test prompt |
| `api/endpoints.py` | 2366 | `model_pool.call()` | Scan chat |
| `services/mr_reviewer_service.py` | 296, 361, 500, 627 | `llm_provider.chat_completion()` | MR review |
| `services/fix_generator.py` | 230, 365 | `llm_provider.chat_completion()` | Fix generation |
| `services/analysis/draft_scanner.py` | 232, 578, 711 | `pool.call_batch()` | Draft scanning |
| `services/analysis/verifier.py` | 216 | `pool.call_batch()` | Verification |
| `services/analysis/enricher.py` | 241, 273, 346 | `model_pool.call_batch()` | Enrichment |
| `services/analysis/findings_analyzer.py` | 114 | `model_pool.call_batch()` | Analysis |
| `services/intelligence/agent_runtime.py` | 234, 242 | `model_pool.call_batch()` | Agent |

### NON-CENTRALIZED Calls (PROBLEMS)

| File | Lines | Issue |
|------|-------|-------|
| **`services/intelligence/agent_runtime.py`** | 284-291 | **Duplicate httpx implementation** for native tool calling - bypasses ModelPool entirely |
| **`services/fix_generator.py`** | 336 | Uses `llm_provider.get_client()` directly for tool calling - bypasses `chat_completion()` abstraction |
| **`services/analysis/response_cleaner.py`** | 157 | Uses `llm_provider.get_client()` directly - missing max_tokens retry logic |
| **`services/scan_engine.py`** | 147, 232 | Legacy code using `llm_provider.get_client()` with different timeout handling |

### Recommendation

Before adding streaming, consolidate to ONE path:
1. Extend `ModelPool._send_batch()` to support streaming and tool calling
2. Route all LLM calls through `ModelPool` (deprecate `LLMProvider` or make it a thin wrapper)
3. This ensures streaming, retries, logging, and timeouts are consistent everywhere

---

## 2. Orphaned / Dead Code

### ORPHANED FILES

| File | Path | Status | Action |
|------|------|--------|--------|
| **report_service.py** | `services/report_service.py` | Imports `xhtml2pdf` (not installed), never used | DELETE or implement |
| **scan_engine.py** | `services/scan_engine.py` | Legacy scanner, superseded by `pipeline.py` | DEPRECATE/DELETE |
| **code_navigator.py** | `services/code_navigator.py` | Only used by dead `scan_engine.py` | DELETE with scan_engine |

### UNUSED DATABASE COLUMNS

| Model | Column | Location | Issue |
|-------|--------|----------|-------|
| `ScanConfig.scope` | `scope = Column(String)` | `scanner_models.py:53` | "full" vs "incremental" logic never implemented |
| `Settings.DB_PASSWORD` | `DB_PASSWORD: str` | `config.py:11` | SQLCipher support planned but never done |
| `ModelConfig.analysis_prompt_template` | Line 39-40 | `scanner_models.py` | Superseded by `ProfileAnalyzer.prompt_template` |
| `ModelConfig.verification_prompt_template` | Line 40 | `scanner_models.py` | Superseded by `ProfileVerifier.prompt_template` |
| `Scan.consensus_enabled` | Line 39 | `models.py` | Only used in legacy `scan_engine.py` |

### UNUSED CONFIG VALUES

| Config | Location | Issue |
|--------|----------|-------|
| `LLM_VERIFICATION_MODELS` | `config.py` | Only used by dead `scan_engine.py` |
| `LLM_MODEL` | `config.py` | Only used by dead `scan_engine.py` |

### TODO/FIXME Comments (Incomplete Work)

| File | Line | Comment |
|------|------|---------|
| `endpoints.py` | 1859 | `# TODO: Implement report generation` |
| `endpoints.py` | 1865 | `# TODO: Implement PDF report generation` |
| `ingestion.py` | 55 | `# TODO: Token handling` |
| `ingestion.py` | 83 | `# TODO: Add ISO support via libarchive or 7z` |
| `ast_parser.py` | 384 | `bases=[],  # TODO: extract base classes` |
| `code_indexer.py` | 57 | `# TODO: Compare with previous scan's file hashes` |

### TEMP/TEST FILES IN BACKEND ROOT (Should Move/Delete)

| File | Purpose | Action |
|------|---------|--------|
| `test_llm.py` | Quick test (has broken import) | DELETE or fix and move to tests/ |
| `test_ast_parsing.py` | AST test script | Move to tests/ |
| `simulate_benchmarks.py` | Benchmark simulation | Move to scripts/ or delete |
| `check_models.py` | Debug script | DELETE |
| `check_models_file.py` | Debug script | DELETE |
| `update_prompts.py` | Migration script | Move to migrations/ |
| `scan_report.py` | Unknown purpose | Investigate |

---

## 3. Database Schema Issues

### ORPHANED DATA (Missing CASCADE Deletes)

**Critical**: Deleting scans leaves behind massive orphaned data:

| Table | Orphaned Records | Issue |
|-------|------------------|-------|
| `symbols` | **12,594** | Parent scan deleted |
| `import_relations` | **6,645** | Parent scan deleted |
| `draft_findings` | **1,038** | Parent scan deleted |
| `scan_files` | **268** | Parent scan deleted |
| `llm_call_metrics` | 40 | Parent scan deleted |
| `verified_findings` | 18 | Parent draft deleted |
| `llm_request_logs` | 13 | Parent scan deleted |

**Root Cause**: All FKs use `NO ACTION` (SQLite default)

**Fix**: Add `ON DELETE CASCADE` or implement app-level cascade

### DUPLICATE/LEGACY INDEXES

The `agent_sessions` table has duplicate indexes from table rename:
```
ix_agent_verification_sessions_scan_id    (old)
idx_avs_scan_id                           (duplicate)
ix_agent_verification_sessions_finding_id (old)
idx_avs_finding_id                        (duplicate)
etc.
```

### ORPHANED/DEAD TABLES

| Table | Rows | Status |
|-------|------|--------|
| `symbol_references` | **0** | Model exists, code exists, never populated |
| `webhook_configs` | 0 | Feature not deployed |
| `webhook_delivery_logs` | 0 | Depends on webhooks |

### SCHEMA INCONSISTENCIES

1. **Missing FK constraint**: `repo_watchers.github_repo_id` and `mr_reviews.github_repo_id` - Model has FK, database doesn't
2. **Redundant FK path**: `findings` has both `draft_id` and `verified_id` creating two paths to same draft
3. **Redundant columns in `repo_watchers`**: Both FK references AND inline credential fields

---

## 4. Code Quality Issues

### CRITICAL: Duplicate FastAPI Endpoints

```python
# endpoints.py - TWO definitions of same route
@router.get("/scan/{scan_id}")        # Line X
@router.get("/scan/{scan_id}")        # Line Y - SHADOWS first!
```

### CRITICAL: Hardcoded Developer Paths

```python
# Various files
"/home/chris/..."                     # Will break on deployment
"/mnt/c/Users/acrvp/..."             # WSL-specific path
```

### HIGH: Silent Exception Swallowing

Multiple places catch exceptions and continue silently:
```python
except Exception:
    pass  # Error lost forever
```

### HIGH: Inconsistent LLM Timeout Handling

| Location | Timeout Pattern |
|----------|----------------|
| `model_orchestrator.py` | Dynamic formula: `min(3600, 300 + (len/200))` |
| `scan_engine.py` | Fixed 120s with `asyncio.wait_for` |
| `llm_provider.py` | No explicit timeout |

### MEDIUM: Functions Doing Too Much

`endpoints.py` is 5000+ lines with functions handling multiple concerns (validation, business logic, DB, response formatting all in one function).

### MEDIUM: Duplicate Code Patterns

LLM response parsing logic duplicated across:
- `parsers.py`
- `response_cleaner.py`
- `draft_scanner.py`
- `verifier.py`

---

## 5. Recommended Cleanup Plan

### Phase 1: Critical Fixes (Before Streaming)

1. **Consolidate LLM calls to ModelPool**
   - Add tool calling support to `ModelPool._send_batch()`
   - Route `agent_runtime.py`, `fix_generator.py`, `response_cleaner.py` through it
   - Then add streaming to the single implementation

2. **Remove dead code**
   - Delete `scan_engine.py`, `code_navigator.py`, `report_service.py`
   - Delete temp files from backend root
   - Remove unused config values

3. **Fix duplicate endpoints**
   - Search for duplicate route definitions
   - Remove shadowed implementations

### Phase 2: Database Cleanup

1. **Clean orphaned data**
   ```sql
   DELETE FROM symbols WHERE scan_id NOT IN (SELECT id FROM scans);
   DELETE FROM import_relations WHERE scan_id NOT IN (SELECT id FROM scans);
   -- etc.
   ```

2. **Add CASCADE deletes** to SQLAlchemy models

3. **Remove duplicate indexes** from `agent_sessions`

### Phase 3: Refactoring

1. Split `endpoints.py` into multiple routers
2. Consolidate parsing logic into single parser module
3. Standardize error handling patterns
4. Remove hardcoded paths, use config

---

## 6. Files to Review Together

These files warrant manual review for the cleanup:

- `/backend/app/services/scan_engine.py` - Legacy, confirm safe to delete
- `/backend/app/services/code_navigator.py` - Used only by above
- `/backend/app/services/report_service.py` - PDF feature never implemented
- `/backend/app/services/intelligence/agent_runtime.py:284-291` - Duplicate LLM logic
- `/backend/app/api/endpoints.py` - 5000+ lines, needs splitting
