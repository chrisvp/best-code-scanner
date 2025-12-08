# Codebase Audit Report (December 6, 2025)

**Status**: Critical cleanup required.
**Context**: Project appears "vinecoded" (iterative/rapid dev), resulting in technical debt, orphaned data, and inconsistent patterns.

## 1. Critical Findings

### 1.1 Database Integrity
*   **Orphaned Records**: The database (`/tmp/scans.db`) contains significant orphaned data due to missing CASCADE delete constraints.
    *   **3,360** orphaned `symbols` records.
    *   **524** orphaned `draft_findings` records.
    *   This bloats the DB and causes query anomalies.
*   **Recommendation**: Run a cleanup SQL script immediately and update SQLAlchemy models to include `cascade="all, delete-orphan"`.

### 1.2 LLM Stability & Timeouts
*   **Recent Failure**: An `agent_fix` job hung and auto-expired after 20 minutes (Log ID 1874).
*   **Root Cause**: Inconsistent timeout handling.
    *   `ModelPool.simple_call` uses robust SSE streaming.
    *   `ModelPool.call_with_tools` uses a custom `dynamic_timeout` (up to 3600s) and *waits* for the full response instead of streaming. If the model hangs or is slow, the client hangs until timeout.
*   **Recommendation**: Refactor `call_with_tools` to use the same streaming logic as `simple_call` to keep connections alive and fail fast on actual disconnects.

### 1.3 Code Duplication & Dead Code
*   **Duplicate Endpoints**: `backend/app/api/endpoints.py` contains shadowed routes (e.g., `@router.get("/scan/{scan_id}")` appears multiple times or shadows another route).
*   **Dead Files**: `backend/app/services/scan_engine.py` (Legacy Scanner) is still present but superseded by the new pipeline.
*   **Recommendation**: Delete `scan_engine.py`, `code_navigator.py`, and `report_service.py`.

## 2. Recent Fixes (Applied)
*   **Hardcoded Paths**: Found and fixed hardcoded paths in `backend/app/api/endpoints.py` that pointed to `/mnt/c/Users/...`. It now dynamically detects the project root.

## 3. Action Plan
1.  **Database**: Execute cleanup SQL.
2.  **Refactor**: Consolidate LLM calls in `agent_runtime.py` to use `ModelPool`'s streaming methods.
3.  **Cleanup**: Delete identified dead files.
4.  **Verify**: Run `pytest` to ensure no regressions.

## 4. System Status
*   **Server**: Running (PID 207) on port 8000.
*   **Database**: Accessible (`/tmp/scans.db`).
