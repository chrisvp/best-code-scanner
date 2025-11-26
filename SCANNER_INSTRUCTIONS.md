# Code Scanner - Session Instructions

## Current State
- **Server**: Running at `http://localhost:8000`
- **Database**: `/tmp/scans.db` (fresh, with model configs)
- **OpenSSH 9.7p1**: Extracted at `/mnt/c/Users/acrvp/code/code-scanner/backend/sandbox/openssh-9.7p1/`

## Model Configuration (already in DB)

| Model | Role | Max Tokens | Concurrency |
|-------|------|-----------|-------------|
| gpt-oss-120b | Analyzer + Verifier | 128K | 10 |
| mistral-small | Verifier | 128K | 5 |
| llama3.3-70b-instruct | Verifier | 128K | 5 |
| gemma-3-27b-it | Verifier | 128K | 5 |

- **vLLM endpoint**: `https://192.168.33.158:5000/v1`
- **API key**: `testkeyforchrisvp`

## To Start Scan of OpenSSH 9.7p1

```bash
# Full scan of all C files
curl -X POST "http://localhost:8000/scan/start" \
  -F "target_url=/mnt/c/Users/acrvp/code/code-scanner/backend/sandbox/openssh-9.7p1" \
  -F "chunk_size=8000" \
  -F "chunk_strategy=smart" \
  -F "file_filter=*.c"
```

## Monitor Progress

```bash
curl http://localhost:8000/scan/{scan_id}/progress
```

Or visit `http://localhost:8000` in browser.

## Goal

Test if the scanner can detect CVE-2024-6387 (signal handler race condition) without any hints.

## If Server Needs Restart

```bash
cd /mnt/c/Users/acrvp/code/code-scanner/backend
source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

## If Model Configs Need Re-adding

```bash
sqlite3 /tmp/scans.db "
INSERT INTO model_configs (name, base_url, api_key, max_tokens, max_concurrent, is_analyzer, is_verifier) VALUES
('gpt-oss-120b', 'https://192.168.33.158:5000/v1', 'testkeyforchrisvp', 128000, 10, 1, 1),
('mistral-small', 'https://192.168.33.158:5000/v1', 'testkeyforchrisvp', 128000, 5, 0, 1),
('llama3.3-70b-instruct', 'https://192.168.33.158:5000/v1', 'testkeyforchrisvp', 128000, 5, 0, 1),
('gemma-3-27b-it', 'https://192.168.33.158:5000/v1', 'testkeyforchrisvp', 128000, 5, 0, 1);
"
```

## Key Paths

- **Backend code**: `/mnt/c/Users/acrvp/code/code-scanner/backend/`
- **Sandbox**: `/mnt/c/Users/acrvp/code/code-scanner/backend/sandbox/`
- **Database**: `/tmp/scans.db`
- **OpenSSH source**: `/mnt/c/Users/acrvp/code/code-scanner/backend/sandbox/openssh-9.7p1/`
