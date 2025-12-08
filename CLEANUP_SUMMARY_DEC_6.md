# Cleanup Summary (December 6, 2025)

## 1. Dead Code Removed
*   Deleted `backend/app/services/scan_engine.py` (Legacy)
*   Deleted `backend/app/services/code_navigator.py` (Legacy)
*   Deleted `backend/app/services/report_service.py` (Legacy/Unused)

## 2. Database Cleaned
*   Removed **3360** orphaned symbols
*   Removed **524** orphaned draft findings
*   Removed **1820** orphaned import relations
*   Removed **927** orphaned LLM logs

## 3. Agent Stability Fixes
*   Refactored `AgentRuntime._call_llm_with_tools` to use `ModelPool.simple_chat_with_tools`.
*   Refactored `AgentRuntime._call_llm` to use `ModelPool.simple_call`.
*   **Benefit:** This enforces consistent SSE streaming timeouts across all agent operations, preventing the 20-minute hang issue seen in log ID 1874.

## 4. Bug Fixes
*   Resolved duplicated endpoint `@router.get("/scan/{scan_id}")` in `backend/app/api/endpoints.py` (it was shadowing another route).
*   Fixed hardcoded paths in `endpoints.py` to support any project location.

## Status
All identified critical items from the audit are resolved. The system is cleaner, faster, and more stable.
