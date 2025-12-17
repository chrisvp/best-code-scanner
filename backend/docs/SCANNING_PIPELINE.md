# Scanning Pipeline Documentation

Complete documentation of the three-phase vulnerability scanning pipeline with multi-model voting and agentic verification.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            SCAN PIPELINE                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [Ingestion] → [Indexing] → [Chunking] → [Parallel Analysis]                │
│                                                ↓                            │
│                                    ┌──────────┴──────────┐                  │
│                                    ↓                     ↓                  │
│                          ┌─────────────────┐   ┌─────────────────┐          │
│                          │  PHASE 1        │   │  PHASE 2        │          │
│                          │  Draft Scanner  │   │  Verifier       │          │
│                          │  (Multi-Model)  │   │  (Voting/Agent) │          │
│                          └────────┬────────┘   └────────┬────────┘          │
│                                   └──────────┬──────────┘                   │
│                                              ↓                              │
│                                    ┌─────────────────┐                      │
│                                    │  PHASE 3        │                      │
│                                    │  Enricher       │                      │
│                                    │  (Reports)      │                      │
│                                    └─────────────────┘                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Phase 1: Draft Scanning

**Purpose:** Fast initial vulnerability detection using lightweight marker format.

### How It Works

1. **Static Detection First** - Regex patterns for instant matches (strcpy, system(), etc.)
2. **Code Chunking** - Files split into analyzable chunks with line numbers
3. **Multi-Model Parallel** - Same chunk sent to all analyzer models
4. **Vote Aggregation** - Findings grouped by signature (line + type)
5. **Deduplication** - Merge duplicate findings, combine vote counts

### Output Format

```
*DRAFT: Buffer Overflow in parse_input
*TYPE: CWE-120
*SEVERITY: High
*LINE: 42
*SNIPPET: strcpy(buffer, input);
*REASON: No bounds checking on input
*END_DRAFT
```

### Multi-Model Voting (Scanner)

- All analyzer models scan each chunk in parallel
- Findings grouped by `signature = line:vuln_type`
- Vote threshold: 0.5 (any model can report)
- Severity: most common value when models disagree
- Tracks: `_votes` count and `_models` list per finding

### Key Features

| Feature | Description |
|---------|-------------|
| Profile-Aware | Custom prompts per analyzer |
| Output Modes | markers, json, guided_json |
| Caching | `content_hash:analyzer_id` prevents re-analysis |
| Static Pre-check | Regex patterns before LLM |
| Cleanup Model | Retries malformed responses |

---

## Phase 2: Verification

**Purpose:** Validate draft findings, eliminate false positives, categorize as vulnerabilities or weaknesses.

### Three Verification Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Standard Voting** | Parallel multi-model voting | Fast triage |
| **Agentic** | Multi-turn tool-using agent | Deep analysis |
| **Hybrid** | Voting first, agentic for uncertain | Balance speed/accuracy |

### Verification Outcomes

```
Draft Finding
      ↓
   Verify?
      ↓
┌─────┼─────┬─────────────┐
↓     ↓     ↓             ↓
VERIFY  WEAKNESS  REJECT  ABSTAIN
  ↓         ↓        ↓       ↓
Create   Mark as   Mark as  Skip
Verified  weakness rejected (no vote)
Finding
```

| Outcome | Action | Example |
|---------|--------|---------|
| **VERIFY** | Real vulnerability → Create VerifiedFinding → Enrich | Command injection, buffer overflow |
| **WEAKNESS** | Code quality issue → Skip enrichment | Missing null check, theoretical overflow |
| **REJECT** | False positive → Discard | Safe strncpy, snprintf with bounds |
| **ABSTAIN** | Insufficient info → Don't count | Incomplete context |

### Standard Multi-Model Voting

```python
# Voting Logic
total_votes = verify + weakness + reject
majority = 2 if total_votes >= 3 else (total_votes + 1) // 2

# Decision Priority
if verify_count >= majority:
    return VERIFIED
elif weakness_count >= majority and weakness_count > verify_count:
    return WEAKNESS
else:
    return REJECTED

# Confidence = winning_votes / total_votes * 100
```

### Vote Prompt Structure

```
=== FINDING TO VERIFY ===
Title, Type, Severity, Line
[Reported Code]
[Scanner's Reason]

=== PRE-FETCHED CONTEXT ===
[Full file, codebase structure, entry points]

=== VERIFICATION CRITERIA ===
VERIFY if:
- Dangerous sink (system, strcpy, printf user format)
- AND attacker data can reach it
- AND real security impact

WEAKNESS if:
- Risky but limited impact
- OR requires unlikely conditions

REJECT if:
- Safe variant used
- OR no attacker data reaches sink
```

---

## Phase 2b: Agentic Verification

**Purpose:** Deep multi-turn investigation using code exploration tools.

### Agent Runtime Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AGENT RUNTIME                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Initialize with Task + Finding Details                     │
│                    ↓                                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  LOOP (max_steps = 8):                               │   │
│  │    1. Call LLM with context                          │   │
│  │    2. Parse response for tool calls                  │   │
│  │    3. If tool call:                                  │   │
│  │       - Execute tool                                 │   │
│  │       - Add result to context                        │   │
│  │       - Continue loop                                │   │
│  │    4. If final answer + min_tool_uses met:           │   │
│  │       - Return verdict                               │   │
│  │    5. Else: prompt for more investigation            │   │
│  └──────────────────────────────────────────────────────┘   │
│                    ↓                                        │
│  Return: VERDICT, CONFIDENCE, REASONING, ATTACK_PATH        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Available Tools

| Tool | Parameters | Purpose |
|------|------------|---------|
| `read_file` | path, start_line, end_line | Get file content |
| `search_code` | pattern (regex) | Find code matches |
| `list_files` | - | List all source files |
| `find_callers` | function_name | Who calls this function |
| `trace_data_flow` | variable_name | Track variable origins |
| `get_call_graph` | function_name | Build function call graph |

### Agent Step Structure

```python
@dataclass
class AgentStep:
    step_number: int
    thought: str           # LLM reasoning
    tool_name: str         # Which tool used
    tool_params: dict      # Tool parameters
    tool_result: str       # Tool output
    is_final: bool         # Final answer?
    final_answer: str      # The verdict
```

### Agent Session Logging

Every agentic verification creates an `AgentSession` record:

```sql
agent_sessions (
    id, scan_id, finding_id, draft_finding_id,
    status,              -- running/completed/failed/max_steps
    model_name,          -- which model ran
    verdict,             -- VERIFIED/REJECTED
    confidence,          -- 0-100
    reasoning,           -- explanation
    attack_path,         -- exploitation method
    total_steps,         -- steps taken
    total_tokens,        -- token usage
    duration_ms,         -- execution time
    execution_trace,     -- full step details (JSON)
    task_prompt,         -- what agent was asked
    prefetched_context,  -- available files
    error_message        -- if failed
)
```

### Hybrid Mode

Combines speed of voting with depth of agentic:

```
┌─────────────────┐
│ All Findings    │
└────────┬────────┘
         ↓
┌─────────────────┐
│ Standard Voting │  ← Fast first pass
└────────┬────────┘
         ↓
┌─────────────────┐     ┌─────────────────┐
│ Clear Cases     │     │ Uncertain Cases │
│ (High confidence│     │ - Close margins │
│  VERIFY/REJECT) │     │ - High sev + low│
└────────┬────────┘     │   conf reject   │
         │              └────────┬────────┘
         │                       ↓
         │              ┌─────────────────┐
         │              │ Agentic Verify  │  ← Deep investigation
         │              └────────┬────────┘
         │                       ↓
         └───────────────┬───────┘
                         ↓
                ┌─────────────────┐
                │ Final Results   │
                └─────────────────┘
```

### Standard vs Agentic Comparison

| Feature | Standard Voting | Agentic |
|---------|-----------------|---------|
| **Approach** | Parallel voting | Sequential multi-turn |
| **Investigation** | Pre-fetched context only | Tool-based exploration |
| **Speed** | Very fast (one pass) | Slow (8+ steps/finding) |
| **Accuracy** | Good for obvious cases | Excellent for ambiguous |
| **Tools** | None | 6 code exploration tools |
| **Best For** | Initial triage | Complex vulnerabilities |
| **Session Logging** | VerificationVote records | Full AgentSession trace |

---

## Phase 3: Enrichment

**Purpose:** Generate detailed security reports with CVSS, PoC, and remediation.

### Enrichment Process

1. Fetch full file content for verified finding
2. Get function callers/references
3. Format enrichment prompt with all context
4. Call enrichment model
5. Parse structured response
6. Match/create vulnerability category (CWE)
7. Create final Finding record

### Output Format

```
*FINDING: Command Injection via User Input in process_command
*CATEGORY: CWE-78 OS Command Injection
*SEVERITY: High
*CVSS: 8.1
*IMPACTED_CODE:
char cmd[256];
sprintf(cmd, "ping %s", user_input);
system(cmd);
*VULNERABILITY_DETAILS:
User-controlled input is concatenated into a shell command
without sanitization, allowing arbitrary command execution.
*PROOF_OF_CONCEPT:
curl -X POST -d "host=; cat /etc/passwd" http://target/ping
*CORRECTED_CODE:
// Use execvp with argument array instead of system()
char *args[] = {"ping", "-c", "1", sanitized_host, NULL};
execvp("ping", args);
*REMEDIATION_STEPS:
1. Use parameterized command execution (execvp)
2. Validate input against allowlist
3. Remove shell metacharacters
*REFERENCES:
- https://cwe.mitre.org/data/definitions/78.html
*END_FINDING
```

### Final Finding Record

| Field | Source |
|-------|--------|
| `scan_id` | Scan.id |
| `verified_id` | VerifiedFinding.id |
| `draft_id` | DraftFinding.id |
| `file_path` | ScanFile.path |
| `line_number` | Draft.line |
| `severity` | Normalized (Critical/High/Medium/Low) |
| `category` | Matched CWE |
| `cvss_score` | Numeric 0.0-10.0 |
| `vulnerability_details` | Enriched explanation |
| `proof_of_concept` | Attack example |
| `corrected_code` | Fixed code |
| `remediation_steps` | Fix guide |
| `references` | External links |

---

## Data Flow & Traceability

```
┌─────────────────┐
│  DraftFinding   │  ← Created by Scanner
│  - scan_id      │
│  - chunk_id     │
│  - dedup_key    │
│  - status       │
│  - votes        │
│  - source_models│
└────────┬────────┘
         │ verified
         ↓
┌─────────────────┐
│ VerifiedFinding │  ← Created by Verifier
│  - draft_id     │
│  - scan_id      │
│  - confidence   │
│  - attack_vector│
│  - data_flow    │
│  - status       │
└────────┬────────┘
         │ enriched
         ↓
┌─────────────────┐
│    Finding      │  ← Created by Enricher (Final Report)
│  - scan_id      │
│  - verified_id  │
│  - draft_id     │
│  - category     │
│  - cvss_score   │
│  - details      │
│  - poc          │
│  - fix          │
└─────────────────┘
```

---

## Configuration

### Scan Profile Settings

```python
ScanProfile:
    name, description
    enabled: bool

    # Agentic Verification Settings
    agentic_verifier_mode: "skip" | "hybrid" | "full"
    agentic_verifier_model_id: ModelConfig.id
    agentic_verifier_max_steps: int (default 8)

    # Relationships
    analyzers: [ProfileAnalyzer]   # Scanner customization
    verifiers: [ProfileVerifier]   # Verifier customization
```

### Analyzer Configuration

```python
ProfileAnalyzer:
    profile_id, model_id
    name, enabled
    run_order: int              # Execution sequence
    file_filter: "*.c,*.h"      # Glob patterns
    language_filter: ["c"]      # Languages
    prompt_template: str        # Custom prompt
    output_mode: "markers"      # markers/json/guided_json
    stop_on_findings: bool      # Early exit
```

### Model Roles

| Role | Purpose |
|------|---------|
| `is_analyzer` | Can scan for vulnerabilities |
| `is_verifier` | Can vote on findings |
| `is_chat` | Default for chat interface and cleanup tasks |

---

## Error Handling & Resilience

| Feature | Behavior |
|---------|----------|
| **Retry** | Exponential backoff: 2s, 4s, 8s (max 3 retries) |
| **Auto-Pause** | After 5 consecutive errors, scan pauses |
| **Resume** | Phase tracking enables resume from interruption |
| **Cleanup Model** | Retries malformed LLM responses |
| **Metrics** | LLMCallMetric tracks timing/tokens per model |

---

## Performance Optimizations

| Optimization | Description |
|--------------|-------------|
| **Parallel Phases** | Scanner, Verifier, Enricher run concurrently |
| **Batch Processing** | Configurable batch sizes per phase |
| **Caching** | Per-scan cache prevents duplicate analysis |
| **Static Pre-check** | Regex patterns before LLM calls |
| **Deduplication** | Merge duplicate findings from multi-model |
| **Thinking Tag Strip** | Remove `<thinking>` tags from responses |
| **Fuzzy Parsing** | Handle LLM response variations |

---

## Quick Reference

### Start a Scan
```bash
curl -X POST http://localhost:8000/scan/start \
  -d "repo_url=https://github.com/user/repo" \
  -d "profile_id=1"
```

### Check Progress
```bash
curl http://localhost:8000/scan/{id}/progress
```

### Get Findings
```bash
curl http://localhost:8000/scan/{id}/findings
```

### Database Queries
```bash
# Recent scans
sqlite3 /tmp/scans.db "SELECT * FROM scans ORDER BY id DESC LIMIT 5;"

# Draft findings for scan
sqlite3 /tmp/scans.db "SELECT * FROM draft_findings WHERE scan_id=X;"

# Agent sessions
sqlite3 /tmp/scans.db "SELECT * FROM agent_sessions WHERE scan_id=X;"
```
