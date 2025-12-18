# Prompt Template Variables

## Standard Variables (Use These!)

All verifier and benchmark prompt templates use these standardized variable names:

### Finding Information
| Variable | Description | Example |
|----------|-------------|---------|
| `{title}` | Finding title | "Buffer Overflow in parse_input" |
| `{vuln_type}` | CWE type | "CWE-120" |
| `{severity}` | Severity level | "High", "Medium", "Low" |
| `{line}` | Line number | 42 |
| `{snippet}` | Code snippet | "strcpy(buf, input);" |
| `{reason}` | Scanner's reasoning | "No bounds checking on input" |

### File/Context Information
| Variable | Description | Example |
|----------|-------------|---------|
| `{file_path}` | File path | "src/parser.c" |
| `{language}` | Programming language | "c", "python", "cpp" |
| `{context}` | Pre-fetched code context (scan verifiers only) | Full file + callers + entry points |

### Output Control
| Variable | Description |
|----------|-------------|
| `{output_format}` | Output format instructions (markers or JSON schema) |

## Output Format

The `{output_format}` variable is automatically populated based on the verifier/analyzer configuration:

### Markers Format (default)
```
=== OUTPUT FORMAT ===
*VOTE: REAL or FALSE_POSITIVE or WEAKNESS or NEEDS_VERIFIED
*CONFIDENCE: [0-100]
*REASONING: [Your analysis]
*END_VERIFIED
```

### JSON Format (guided output)
```json
{
  "vote": "REAL",
  "confidence": 85,
  "reasoning": "Buffer overflow confirmed..."
}
```

## Valid Vote Values

- **REAL**: Confirmed exploitable vulnerability
- **FALSE_POSITIVE**: Not a vulnerability, code is safe
- **WEAKNESS**: Code quality issue but not exploitable
- **NEEDS_VERIFIED**: Cannot confirm from available context

## Best Practices

1. **Always use `{output_format}`** instead of hardcoding output instructions
2. **Use simple variable names** like `{title}` instead of `{finding_title}` for readability
3. **Don't assume `{context}` exists** - only verifiers with context retrieval provide it
4. **Test templates** in both scan and benchmark contexts to ensure compatibility

## Example Template

```
You are verifying a potential security vulnerability.

=== FINDING TO VERIFY ===
Title: {title}
Type: {vuln_type}
Severity: {severity}
Line: {line}

Reported Code:
{snippet}

Scanner's Reason: {reason}

=== PRE-FETCHED CONTEXT ===
{context}

=== YOUR TASK ===
Classify this finding into ONE of these categories:

**FALSE_POSITIVE**: The scanner is wrong. There is NO vulnerability here.
**REAL**: This is a confirmed exploitable vulnerability.
**NEEDS_VERIFIED**: Cannot confirm from what's shown. Need more investigation.
**WEAKNESS**: Poor coding practice but not directly exploitable.

{output_format}
```

## Context Variable Details

The `{context}` variable provides comprehensive code context for scan verifiers:
- **Full file content** (or ±100 lines if file is huge)
- **Application type** and threat model
- **Entry points** where external input enters the codebase
- **Function definitions** and callers
- **Symbol references** and imports

**Note:** Benchmark templates don't have real file chunks, so `{context}` may be empty during testing. Use the simulator to provide realistic context for benchmarking.

## Recent Updates

- **2025-12-18**: All 31 benchmark templates standardized to use simple variable names (`{title}` not `{finding_title}`)
- **2025-12-18**: All templates updated to use `{output_format}` placeholder instead of hardcoded output sections
