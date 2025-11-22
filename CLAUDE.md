# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Agentic Firmware Security Scanner - A FastAPI-based web application that uses LLMs to analyze code for security vulnerabilities. Supports scanning Git repositories or uploaded archives (.zip/.tar.gz) containing Python, C, and C++ code.

## Commands

### Run the server
```bash
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Run tests
```bash
cd backend
pytest tests/
```

### Run a single test
```bash
cd backend
pytest tests/test_api.py::test_health_check -v
```

### Install dependencies
```bash
cd backend
pip install -r requirements.txt
```

## Architecture

### Core Flow
1. **Ingestion** (`app/services/ingestion.py`): Clones Git repos or extracts archives into `sandbox/` directory
2. **Code Navigation** (`app/services/code_navigator.py`): Uses tree-sitter to parse files and extract imports/functions for context
3. **Scan Engine** (`app/services/scan_engine.py`): Orchestrates the scan workflow - walks files, sends to LLM for analysis, stores findings
4. **LLM Provider** (`app/services/llm_provider.py`): AsyncOpenAI client wrapper that connects to configurable LLM endpoint

### Key Components
- **Scan**: Database model tracking scan status (queued/running/completed/failed) and logs
- **Finding**: Security vulnerability with file_path, line_number, severity, description, snippet, remediation
- **Consensus Mode**: Optional verification step that uses additional LLMs to validate findings as true/false positives

### Web Interface
- HTMX-based dashboard with Jinja2 templates in `app/templates/`
- Endpoints in `app/api/endpoints.py` serve both UI and API
- Runtime LLM configuration via `/config` endpoint

### Configuration
Settings in `app/core/config.py` - configurable via `.env` file:
- `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`: Primary analysis model
- `LLM_VERIFICATION_MODELS`: List of models for consensus verification
- `DATABASE_URL`: SQLite database path (default: `./scans.db`)

### File Support
Analyzes: `.py`, `.c`, `.cpp` files
Tree-sitter parsers initialized for C and Python

## Slash Commands for Implementation

Use these commands to implement the refactored scanner architecture:

- `/build-all` - Implement entire scanner from scratch (master command)
- `/implement-models` - Create database models (Phase 1)
- `/implement-pipeline` - Create orchestration layer with vLLM batching (Phase 2)
- `/implement-intelligence` - Create code intelligence system (Phase 3)
- `/implement-analysis` - Create analysis components (Phase 4-6)
- `/implement-api` - Update API endpoints (Phase 7)
- `/test-scanner` - Create and run tests

## Refactored Architecture (In Progress)

See `IMPLEMENTATION_PLAN.md` for full details.

### Three-Phase Pipeline
1. **Draft Scanning**: Fast LLM scan, lightweight format
2. **Verification**: Context-aware validation with code intelligence
3. **Enrichment**: Full reports for verified findings only

### Key Features
- vLLM batch inference (list of prompts per request)
- Configurable concurrency per model (default: 2)
- Tree-sitter code intelligence for context retrieval
- Static pattern detection for obvious vulnerabilities
- Pause/resume with checkpoint recovery

### New Service Structure
```
backend/app/services/
├── orchestration/    # Pipeline, model pools, caching
├── intelligence/     # AST parser, indexer, context
└── analysis/         # Scanner, verifier, enricher
```
