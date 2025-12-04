# CLAUDE.md

Guidance for Claude Code when working with this repository.

## Project Overview

**Davy Code Scanner** - An LLM-powered security vulnerability scanner that analyzes code repositories using multi-model voting and a three-phase pipeline. Supports scanning Git repositories or uploaded archives containing Python, C, and C++ code.

## Quick Start

```bash
# Start the server
cd backend && source venv/bin/activate
python start.py
# Or manually: uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Run tests
cd backend && pytest tests/

# Install dependencies
cd backend && pip install -r requirements.txt
```

**Server URL**: http://localhost:8000
**Database**: `/tmp/scans.db` (SQLite)

## Tech Stack

- **Backend**: FastAPI (Python 3.11+)
- **Database**: SQLite with SQLAlchemy ORM
- **LLM Integration**: AsyncOpenAI client (vLLM-compatible)
- **Code Intelligence**: tree-sitter for AST parsing
- **Frontend**: HTMX + Jinja2 templates + Tailwind CSS
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
│         (vLLM batch inference, multi-model)                 │
└─────────────────────────────────────────────────────────────┘
```

### Three-Phase Pipeline

1. **Draft Scanning**: Fast initial scan using lightweight marker format
2. **Verification**: Context-aware validation with code intelligence and multi-model voting
3. **Enrichment**: Full security reports with CVSS, PoC, and remediation for verified findings

### Service Structure

```
backend/app/
├── api/endpoints.py         # FastAPI routes (UI + API)
├── core/config.py           # Settings (env vars)
├── models/
│   ├── models.py            # Scan, Finding models
│   └── scanner_models.py    # Pipeline models (Draft, Verified, etc.)
├── services/
│   ├── orchestration/
│   │   ├── pipeline.py      # Main scan orchestrator
│   │   ├── model_orchestrator.py  # LLM pool management
│   │   └── cache.py         # Response caching
│   ├── intelligence/
│   │   ├── ast_parser.py    # Tree-sitter parsing
│   │   └── context_retriever.py   # Code context for verification
│   └── analysis/
│       ├── draft_scanner.py # Phase 1: Initial scanning
│       ├── verifier.py      # Phase 2: Verification
│       ├── enricher.py      # Phase 3: Report generation
│       └── parsers.py       # LLM response parsing
└── templates/               # Jinja2 + HTMX UI
```

## Database Schema

### Core Tables

| Table | Purpose |
|-------|---------|
| `scans` | Scan metadata and status |
| `scan_files` | Files discovered in scan |
| `scan_file_chunks` | Code chunks for analysis |
| `draft_findings` | Initial vulnerability candidates |
| `verified_findings` | Confirmed vulnerabilities |
| `findings` | Final enriched reports |
| `model_configs` | LLM model configurations |
| `scan_profiles` | Reusable scan configurations |
| `profile_analyzers` | Analyzer configs per profile |
| `static_rules` | Regex-based detection patterns |

## Configuration

### Scan Profiles

Profiles define how scans run with multiple analyzers:
- Each analyzer has: model, chunk_size, prompt_template, file_filter
- Analyzers run in order (run_order)
- Profiles can be enabled/disabled

### Model Roles

| Role | Description |
|------|-------------|
| `is_analyzer` | Can scan for vulnerabilities |
| `is_verifier` | Can vote on findings |
| `is_cleanup` | Reformats malformed responses |
| `is_chat` | Default for chat interface |

### Environment Variables

```
LLM_BASE_URL=https://192.168.33.158:5000/v1
LLM_API_KEY=your-api-key
LLM_VERIFY_SSL=false
DATABASE_URL=sqlite:////tmp/scans.db
MAX_CONCURRENT_REQUESTS=5
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard UI |
| `/config` | GET | Settings page |
| `/scan/start` | POST | Start new scan |
| `/scan/{id}/progress` | GET | Get scan progress |
| `/scan/{id}/findings` | GET | Get findings |
| `/models` | GET/POST | Manage models |
| `/profiles` | GET/POST | Manage scan profiles |
| `/profiles/{id}/analyzers` | POST | Add analyzer to profile |
| `/rules` | GET/POST | Manage static rules |
| `/chat` | POST | Chat with AI about findings |

## LLM Response Formats

### Draft Finding (Phase 1)
```
*DRAFT: Buffer Overflow in parse_input
*TYPE: CWE-120
*SEVERITY: High
*LINE: 42
*SNIPPET: strcpy(buffer, input);
*REASON: No bounds checking on input
*END_DRAFT
```

### Verification (Phase 2)
```
*VOTE: VERIFY
*CONFIDENCE: 92
*REASONING: User input flows directly to strcpy without bounds check
*END_VERIFIED
```

### Enrichment (Phase 3)
```
*FINDING: Buffer Overflow via Unbounded strcpy
*CATEGORY: CWE-120 Buffer Copy without Checking Size
*SEVERITY: High
*CVSS: 8.1
*IMPACTED_CODE: ...
*VULNERABILITY_DETAILS: ...
*PROOF_OF_CONCEPT: ...
*CORRECTED_CODE: ...
*REMEDIATION_STEPS: ...
*REFERENCES: ...
*END_FINDING
```

## Key Features

- **Multi-model voting**: Multiple models scan in parallel, findings aggregated by signature
- **Per-model tracking**: `source_models` column tracks which models detected each finding
- **Thinking tag stripping**: Automatically removes `<thinking>` and `<think>` tags from model outputs
- **Fuzzy parsing**: Handles variations in LLM response formats
- **Code intelligence**: Tree-sitter AST parsing for context retrieval
- **Static rules**: Regex patterns for instant detection of common vulnerabilities
- **Tab persistence**: Config page remembers active tab via localStorage

## Test Samples

`test_samples/vulnerable_cpp/` contains test files with intentional vulnerabilities:
- `network_client.cpp` - Buffer overflow (CWE-120)
- `firmware_updater.cpp` - Command injection (CWE-78)
- `memory_pool.cpp` - Use-after-free (CWE-416)
- `logger_service.cpp` - Format string (CWE-134)

## Development Notes

### Adding a New Model Role
1. Add column to `ModelConfig` in `scanner_models.py`
2. Add checkbox to model forms in `config.html`
3. Update `modelsData` JS object and form handlers
4. Add migration if needed: `ALTER TABLE model_configs ADD COLUMN is_xxx BOOLEAN DEFAULT 0`

### Adding a New Analyzer Field
1. Add column to `ProfileAnalyzer` in `scanner_models.py`
2. Update forms in `config.html`
3. Update `add_analyzer` and `update_analyzer` endpoints
4. Update profile API response

### Debugging Scans
```bash
# Check scan progress
curl http://localhost:8000/scan/{id}/progress | python3 -m json.tool

# Check database
sqlite3 /tmp/scans.db "SELECT * FROM scans ORDER BY id DESC LIMIT 5;"
sqlite3 /tmp/scans.db "SELECT * FROM draft_findings WHERE scan_id=X;"
```

### Database Migrations

For output mode support (guided JSON/structured output), run:
```sql
-- Add output_mode to analyzers and verifiers (December 2025)
ALTER TABLE profile_analyzers ADD COLUMN output_mode VARCHAR DEFAULT 'markers';
ALTER TABLE profile_analyzers ADD COLUMN json_schema TEXT;
ALTER TABLE profile_verifiers ADD COLUMN output_mode VARCHAR DEFAULT 'markers';
ALTER TABLE profile_verifiers ADD COLUMN json_schema TEXT;
```

For GitHub support (added November 2025), run:
```sql
-- Create github_repos table
CREATE TABLE IF NOT EXISTS github_repos (
    id INTEGER PRIMARY KEY,
    name VARCHAR NOT NULL,
    github_url VARCHAR NOT NULL DEFAULT 'https://api.github.com',
    github_token VARCHAR,
    owner VARCHAR NOT NULL,
    repo VARCHAR NOT NULL,
    description VARCHAR,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

-- Add provider fields to repo_watchers
ALTER TABLE repo_watchers ADD COLUMN provider VARCHAR DEFAULT 'gitlab';
ALTER TABLE repo_watchers ADD COLUMN github_repo_id INTEGER REFERENCES github_repos(id);
ALTER TABLE repo_watchers ADD COLUMN github_url VARCHAR DEFAULT 'https://api.github.com';
ALTER TABLE repo_watchers ADD COLUMN github_token VARCHAR;
ALTER TABLE repo_watchers ADD COLUMN github_owner VARCHAR;
ALTER TABLE repo_watchers ADD COLUMN github_repo VARCHAR;

-- Add provider fields to mr_reviews
ALTER TABLE mr_reviews ADD COLUMN provider VARCHAR DEFAULT 'gitlab';
ALTER TABLE mr_reviews ADD COLUMN github_repo_id INTEGER REFERENCES github_repos(id);
```

## Future Features

See `backend/docs/FEATURE_ROADMAP.md` for planned features:
- GitLab Merge Request reviewer
- Findings analysis & prioritization
- Webhook security alerts
