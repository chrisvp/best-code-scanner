# Prompt Template Variables

## Available Variables

All verifier and benchmark prompt templates can use these variables:

### Finding Information
| Variable | Aliases | Description | Example |
|----------|---------|-------------|---------|
| `{title}` | `{finding_title}`, `{issue}` | Finding title | "Buffer Overflow in parse_input" |
| `{vuln_type}` | `{finding_type}`, `{vulnerability_type}` | CWE type | "CWE-120" |
| `{severity}` | `{finding_severity}` | Severity level | "High", "Medium", "Low" |
| `{line}` | `{finding_line}`, `{line_number}` | Line number | 42 |
| `{snippet}` | `{code_snippet}`, `{code}` | Code snippet | "strcpy(buf, input);" |
| `{reason}` | `{finding_reason}`, `{claim}`, `{details}` | Scanner's reasoning | "No bounds checking on input" |

### File/Context Information
| Variable | Aliases | Description | Example |
|----------|---------|-------------|---------|
| `{file_path}` | `{file}` | File path | "src/parser.c" |
| `{language}` | - | Programming language | "c", "python", "cpp" |
| `{context}` | `{code_context}` | Pre-fetched code context (verifier only) | Surrounding functions/definitions |

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

## Migration Note

**TODO**: Update all benchmark templates to use `{output_format}` instead of hardcoded output sections.
