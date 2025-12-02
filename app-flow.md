# Davy Code Scanner - Application Flow

## Overview

Davy Code Scanner is an LLM-powered security vulnerability scanner that uses a **three-phase pipeline** with **multi-model voting** to reduce false positives while catching real vulnerabilities.

## The Three-Phase Pipeline

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Phase 1    │     │  Phase 2    │     │  Phase 3    │
│  DISCOVERY  │ ──▶ │VERIFICATION │ ──▶ │ ENRICHMENT  │
│ (Draft Scan)│     │  (Voting)   │     │ (Full Report)│
└─────────────┘     └─────────────┘     └─────────────┘
     Fast             2/3 majority        CVSS, PoC,
   detection           consensus          remediation
```

**Phase 1 - Discovery (Draft Scanning)**
- Files are chunked based on configurable token sizes
- Each chunk runs through two detection methods in parallel:
  - **Static Rules**: Regex patterns catch obvious vulnerabilities instantly (e.g., `gets()`, `strcpy(argv)`, `system(user_input)`) - no LLM needed
  - **LLM Analysis**: For chunks with "interesting patterns" (keywords like `system`, `malloc`, `eval`), the LLM scans for vulnerabilities
- Output: Draft findings with title, CWE type, severity, line number, and code snippet

**Phase 2 - Verification (Multi-Model Voting)**
- Each draft finding goes to **multiple verifier models** in parallel
- Each verifier votes: VERIFY, WEAKNESS, or REJECT with confidence %
- **2/3 majority required** - if 2 out of 3 models agree it's real, it passes
- Context-aware: verifiers see function callers, full file content, and data flow
- Filters out false positives like safe patterns (`strncpy` with bounds, alignment idioms)

**Phase 3 - Enrichment**
- Verified findings get full security reports generated:
  - CWE category matching
  - CVSS score
  - Detailed vulnerability explanation
  - Proof-of-concept attack example
  - Corrected code (on-demand)
  - Remediation steps
  - References (OWASP, CWE links)

## Multi-Model Architecture

```
┌──────────────────────────────────────┐
│        Model Orchestrator            │
├──────────────────────────────────────┤
│  Model Pool: Qwen-32B (analyzer)     │──▶ Batch processing
│  Model Pool: DeepSeek-8B (verifier)  │──▶ Concurrent requests
│  Model Pool: Llama-70B (verifier)    │──▶ Per-model rate limits
└──────────────────────────────────────┘
```

- Models have **roles**: `is_analyzer`, `is_verifier`, `is_cleanup`
- Each model pool manages concurrent connections with semaphores
- Batch processing sends multiple prompts in parallel
- Findings track which models detected them (`source_models` column)

## Static Rules Engine

Fast regex-based detection runs first, catching obvious vulnerabilities without LLM cost:

| Pattern | CWE | Example |
|---------|-----|---------|
| `gets()` | CWE-120 | Buffer overflow - no bounds |
| `system(argv[])` | CWE-78 | Command injection |
| `printf(user_var)` | CWE-134 | Format string attack |
| `free(ptr); ptr->` | CWE-416 | Use-after-free |
| `password = "..."` | CWE-798 | Hardcoded credentials |

Rules are configurable via the UI - add your own regex patterns.

## Profile System

Scan Profiles define how scans run:
- **Analyzers**: Each profile can have multiple analyzers
- **File Filters**: `*.c,*.h` to target specific files
- **Custom Prompts**: Tailor detection for specific vulnerability types
- **Chunk Sizes**: Balance context vs. token usage

## Key Features

- **Supports Python, C, C++** code analysis
- **Git repos or ZIP uploads** as scan targets
- **Caching**: Same code chunk returns cached results
- **Cleanup Model**: Fixes malformed LLM responses
- **Code Intelligence**: Tree-sitter AST parsing for context retrieval
- **GitLab MR Integration**: Auto-review merge requests

---

## Detailed Scan Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              SCAN INITIATION                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│  User Input: Git URL or ZIP Upload                                              │
│       │                                                                         │
│       ▼                                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                         │
│  │ Clone Repo  │ OR │Extract ZIP  │ ──▶│ Discover    │                         │
│  │ (git clone) │    │ (to sandbox)│    │ Files       │                         │
│  └─────────────┘    └─────────────┘    └─────────────┘                         │
│                                              │                                  │
│                                              ▼                                  │
│                                   Filter by extension                           │
│                                   (.c, .cpp, .h, .py)                           │
└─────────────────────────────────────────────────────────────────────────────────┘
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              FILE CHUNKING                                      │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   file.c (500 lines)                                                            │
│   ┌──────────────────┐                                                          │
│   │ Lines 1-150      │ ──▶ Chunk 1 (fits in token limit)                       │
│   │ Lines 151-300    │ ──▶ Chunk 2                                              │
│   │ Lines 301-500    │ ──▶ Chunk 3                                              │
│   └──────────────────┘                                                          │
│                                                                                 │
│   Chunk size controlled by profile analyzer settings (default ~4000 tokens)     │
│   Each chunk stored in: scan_file_chunks table                                  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         PHASE 1: DRAFT SCANNING                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   For each chunk:                                                               │
│   ┌─────────────────────────────────────────────────────────────────────┐      │
│   │                                                                     │      │
│   │  ┌─────────────────┐         ┌─────────────────────────────┐       │      │
│   │  │  STATIC RULES   │         │      LLM ANALYZERS          │       │      │
│   │  │  (instant)      │         │  (parallel per-model)       │       │      │
│   │  │                 │         │                             │       │      │
│   │  │ • Regex match   │         │  Model A ───┐               │       │      │
│   │  │ • gets() → vuln │         │  Model B ───┼──▶ Aggregate  │       │      │
│   │  │ • system(argv)  │         │  Model C ───┘    by sig     │       │      │
│   │  │                 │         │                             │       │      │
│   │  └────────┬────────┘         └──────────────┬──────────────┘       │      │
│   │           │                                 │                       │      │
│   │           │    Also determines:             │                       │      │
│   │           │    needs_llm = true/false       │                       │      │
│   │           │    (has dangerous keywords?)    │                       │      │
│   │           │                                 │                       │      │
│   │           └─────────────┬───────────────────┘                       │      │
│   │                         ▼                                           │      │
│   │              ┌─────────────────────┐                                │      │
│   │              │   DRAFT FINDINGS    │                                │      │
│   │              │   (deduplicated)    │                                │      │
│   │              └─────────────────────┘                                │      │
│   │                                                                     │      │
│   └─────────────────────────────────────────────────────────────────────┘      │
│                                                                                 │
│   Draft Finding Format:                                                         │
│   ┌────────────────────────────────────────────┐                               │
│   │ *DRAFT: Buffer Overflow in parse_input     │                               │
│   │ *TYPE: CWE-120                             │                               │
│   │ *SEVERITY: High                            │                               │
│   │ *LINE: 42                                  │                               │
│   │ *SNIPPET: strcpy(buffer, user_input);      │                               │
│   │ *REASON: Unbounded copy to fixed buffer    │                               │
│   │ *END_DRAFT                                 │                               │
│   └────────────────────────────────────────────┘                               │
│                                                                                 │
│   Stored in: draft_findings table                                              │
│   Tracks: source_models (which models found it)                                │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                       PHASE 2: VERIFICATION (VOTING)                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   For each draft finding:                                                       │
│   ┌─────────────────────────────────────────────────────────────────────┐      │
│   │                                                                     │      │
│   │   1. Gather Context                                                 │      │
│   │   ┌──────────────────────────────────────────────────┐             │      │
│   │   │ • Full file content (highlighted focus area)     │             │      │
│   │   │ • Function callers (who calls this code?)        │             │      │
│   │   │ • Other files in codebase                        │             │      │
│   │   │ • Data flow context                              │             │      │
│   │   └──────────────────────────────────────────────────┘             │      │
│   │                         │                                           │      │
│   │                         ▼                                           │      │
│   │   2. Send to Verifier Models (parallel)                             │      │
│   │   ┌─────────────────────────────────────────────────────┐          │      │
│   │   │                                                     │          │      │
│   │   │  Verifier 1 ──▶ VERIFY (85% confidence)            │          │      │
│   │   │  Verifier 2 ──▶ REJECT (70% confidence)            │          │      │
│   │   │  Verifier 3 ──▶ VERIFY (90% confidence)            │          │      │
│   │   │                                                     │          │      │
│   │   └─────────────────────────────────────────────────────┘          │      │
│   │                         │                                           │      │
│   │                         ▼                                           │      │
│   │   3. Vote Aggregation (2/3 majority required)                       │      │
│   │   ┌─────────────────────────────────────────────────────┐          │      │
│   │   │  VERIFY: 2 votes  ──▶  PASSES (majority)           │          │      │
│   │   │  REJECT: 1 vote                                     │          │      │
│   │   │                                                     │          │      │
│   │   │  Final: VERIFIED with 66% consensus                 │          │      │
│   │   └─────────────────────────────────────────────────────┘          │      │
│   │                                                                     │      │
│   └─────────────────────────────────────────────────────────────────────┘      │
│                                                                                 │
│   Vote Options:                                                                 │
│   • VERIFY   - Real vulnerability, exploitable                                  │
│   • WEAKNESS - Real but low impact (DoS only, theoretical)                     │
│   • REJECT   - False positive (safe pattern, no attacker path)                 │
│                                                                                 │
│   Stored in: verified_findings table                                           │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        PHASE 3: ENRICHMENT                                      │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   For each verified finding:                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐      │
│   │                                                                     │      │
│   │   LLM generates full security report:                               │      │
│   │                                                                     │      │
│   │   ┌──────────────────────────────────────────────────────────────┐ │      │
│   │   │ *FINDING: Command Injection via User Input in Shell Call     │ │      │
│   │   │ *CATEGORY: CWE-78 OS Command Injection                       │ │      │
│   │   │ *SEVERITY: Critical                                          │ │      │
│   │   │ *CVSS: 9.8                                                   │ │      │
│   │   │ *IMPACTED_CODE:                                              │ │      │
│   │   │   snprintf(cmd, sizeof(cmd), "ping %s", user_input);         │ │      │
│   │   │   system(cmd);                                               │ │      │
│   │   │ *VULNERABILITY_DETAILS:                                      │ │      │
│   │   │   User-controlled input flows directly to system()...        │ │      │
│   │   │ *PROOF_OF_CONCEPT:                                           │ │      │
│   │   │   curl -X POST -d "host=; cat /etc/passwd"                   │ │      │
│   │   │ *CORRECTED_CODE: (generated on-demand)                       │ │      │
│   │   │ *REMEDIATION_STEPS:                                          │ │      │
│   │   │   1. Use execve() with argument array                        │ │      │
│   │   │   2. Validate input against allowlist                        │ │      │
│   │   │ *REFERENCES:                                                 │ │      │
│   │   │   - https://cwe.mitre.org/data/definitions/78.html           │ │      │
│   │   │ *END_FINDING                                                 │ │      │
│   │   └──────────────────────────────────────────────────────────────┘ │      │
│   │                                                                     │      │
│   └─────────────────────────────────────────────────────────────────────┘      │
│                                                                                 │
│   Stored in: findings table (final output)                                     │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            FINAL OUTPUT                                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Dashboard displays:                                                           │
│   ┌─────────────────────────────────────────────────────────────────────┐      │
│   │  Scan #15 - vulnerable.zip                     Status: Completed    │      │
│   │  ───────────────────────────────────────────────────────────────    │      │
│   │  Files scanned: 4     Chunks: 12     Duration: 45s                  │      │
│   │                                                                     │      │
│   │  Findings:                                                          │      │
│   │  ┌─────────────────────────────────────────────────────────────┐   │      │
│   │  │ ● Critical (2)  ● High (3)  ● Medium (1)  ● Low (0)         │   │      │
│   │  └─────────────────────────────────────────────────────────────┘   │      │
│   │                                                                     │      │
│   │  [View Details] [Export JSON] [Generate Report]                     │      │
│   └─────────────────────────────────────────────────────────────────────┘      │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Database Flow

```
scan_files          scan_file_chunks       draft_findings      verified_findings      findings
───────────         ────────────────       ──────────────      ─────────────────      ────────
file.c         ──▶  chunk 1           ──▶  draft 1        ──▶  verified 1        ──▶  finding 1
                    chunk 2           ──▶  draft 2 (rejected)
                    chunk 3           ──▶  draft 3        ──▶  verified 2        ──▶  finding 2
```

## Parallel Processing Points

```
┌───────────────────────────────────────────────────────────────┐
│                     PARALLELISM MAP                           │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  Phase 1 (Draft):                                             │
│  ├── Chunks processed in batches (10 at a time)              │
│  ├── Multiple analyzer models run in parallel                 │
│  └── Static rules + LLM run concurrently                     │
│                                                               │
│  Phase 2 (Verify):                                            │
│  ├── All verifier models vote in parallel                    │
│  └── Context fetched once, shared across verifiers           │
│                                                               │
│  Phase 3 (Enrich):                                            │
│  └── Batch enrichment (multiple findings per call)           │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

## Typical Scan Flow

1. User uploads `vulnerable.zip` or provides Git URL
2. Scanner discovers files, chunks them by token size
3. Static rules fire instantly on obvious patterns
4. LLM analyzers scan chunks for subtle vulnerabilities
5. Draft findings aggregated by signature (line + CWE type)
6. Verifiers vote on each draft - majority wins
7. Verified findings get enriched with full reports
8. Final report shows confirmed vulnerabilities with fixes
