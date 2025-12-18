# Benchmark Context Fetching

## Overview

The benchmark system now fetches REAL file context just like production verifiers, ensuring test conditions exactly match production conditions.

## Context Variables

Benchmarks provide two types of code information to models:

### 1. `{snippet}` - The Vulnerable Line
- Single line of code that triggered the finding
- Extracted from `draft.snippet` field
- Shows the exact line that's problematic
- Example: `KeyboardFlag += Addr;`

### 2. `{context}` - Full File Context
- Complete function containing the vulnerability
- Surrounding code with ±50 lines of context
- Vulnerable line marked with `>>>` prefix
- Retrieved using `ContextRetriever.get_context_for_file()`
- Same context production verifiers see
- Typically 2000-4000 characters
- Shows initialization, data flow, function boundaries

## Template Structure

All 31 tuning prompt templates now follow this pattern:

```
Code context:
```{language}
{snippet}
```

Full file context:
{context}

Reported vulnerability:
- Title: {title}
- Type: {vuln_type}
...
```

This gives models both:
1. **Pinpoint precision**: Exact vulnerable line
2. **Big picture**: Full function context to understand if it's actually exploitable

## Context Retrieval

When `test_case.draft_finding_id` is set:

1. Load the draft finding from the database
2. Resolve file path via draft.file_path or chunk → scan_file relationship
3. Call `ContextRetriever.get_context_for_file(file_path, line_number)`
4. If file doesn't exist or retrieval fails: exception propagates → test marked as error

No special-casing. If context can't be fetched, that test just errors out.

## Example

**Snippet**:
```c
KeyboardFlag += Addr;
```

**Context** (3509 chars):
```c
=== CODE CONTEXT ===
File: Legacy.c

    3968: EFI_STATUS
    3969: UpdateBdaKeyboardFlag (VOID)
    3970: {
    3971:   EFI_STATUS Status;
    3972:   UINT8 *KeyboardFlag = 0;
    3973:   UINTN Addr = 0x417;
    ...
>>> 4012:       KeyboardFlag += Addr;
    4013:
    4014:       if (SctSystemConfig->NumLock == 1) {
    4015:           *KeyboardFlag |= 0x20;
    ...
```

With full context, the model can see:
- KeyboardFlag initialized to 0 (NULL)
- Then incremented by hardcoded address
- Then dereferenced without validation
- **Verdict**: REAL vulnerability

Without context, models often can't tell if it's exploitable or just poor style.
