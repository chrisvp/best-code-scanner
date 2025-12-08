# Davy Code Scanner - Project Context

## Project Overview
**Davy Code Scanner** is an LLM-powered security vulnerability scanner designed to analyze code repositories (Git or ZIP) for security flaws. It employs a **multi-model voting system** and a **three-phase pipeline** to minimize false positives and provide high-quality security reports.

**Key Features:**
*   **Three-Phase Pipeline:** Discovery (Draft) -> Verification (Voting) -> Enrichment (Reporting).
*   **Multi-Model Voting:** Findings require consensus from multiple LLMs to be verified.
*   **Code Intelligence:** Uses `tree-sitter` for AST parsing to provide context to LLMs.
*   **Tech Stack:** FastAPI (Backend), SQLite (DB), HTMX + Jinja2 (Frontend), vLLM (Inference).

## Architecture
The application follows a modular architecture centered around a scanning pipeline:

1.  **API Layer:** FastAPI endpoints (`backend/app/api`) serve the UI and manage scan requests.
2.  **Orchestrator:** Manages the scan lifecycle, distributing work to models.
3.  **Pipeline Phases:**
    *   **Phase 1 (Discovery):** Fast scanning using lightweight models or static rules (Regex) to identify potential issues.
    *   **Phase 2 (Verification):** Deep analysis where multiple "verifier" models vote on the validity of findings using expanded code context.
    *   **Phase 3 (Enrichment):** Verified findings are enriched with CVSS scores, remediation steps, and PoCs.

## Directory Structure
*   `backend/` - Core application logic.
    *   `main.py` - FastAPI application entry point.
    *   `start.py` - Helper script to kill existing processes and start the server.
    *   `app/`
        *   `api/` - HTTP endpoints.
        *   `core/` - Configuration and database setup.
        *   `models/` - SQLAlchemy database models and Pydantic schemas.
        *   `services/` - Business logic (scanning, verification, LLM interaction).
        *   `templates/` - Jinja2 HTML templates.
        *   `static/` - CSS/JS assets.
*   `test_samples/` - Vulnerable code samples for testing scanner accuracy.
*   `tests/` - Pytest suite.

## Development & Usage

### 1. Environment Setup
The project uses a Python virtual environment.
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Running the Server
The easiest way to start the server (reloading enabled):
```bash
cd backend
python start.py
```
*   **URL:** `http://localhost:8000`
*   **Database:** `/tmp/scans.db` (SQLite)

### 3. Running Tests
```bash
cd backend
pytest
```

### 4. Configuration
*   **Models:** Configured via the UI (`/models`) or database. Models have roles (`is_analyzer`, `is_verifier`).
*   **Scan Profiles:** Define which analyzers run and file filters.
*   **Static Rules:** Regex patterns for instant detection defined in `backend/app/services/analysis/static_rules.py` (or similar).

## Key Concepts for Development
*   **Draft Findings:** Initial, unverified potential vulnerabilities.
*   **Verified Findings:** Findings that have passed the voting threshold.
*   **LLM Integration:** All LLM calls go through `ModelPool` in `backend/app/services/orchestration/model_orchestrator.py`.
*   **Streaming:** The application relies heavily on SSE (Server-Sent Events) for real-time scan progress updates.

## Common Tasks
*   **Adding a new Model:** Register it in the `model_configs` table or via the UI.
*   **Improving Accuracy:** Tune prompt templates in `backend/app/services/analysis/` or adjust voting thresholds.
*   **New Vulnerability Checks:** Add regex patterns to the static rules engine or improved few-shot examples to the LLM prompts.
