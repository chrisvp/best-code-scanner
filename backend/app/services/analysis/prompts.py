"""
Default analyzer prompts for different scan profiles.
Prompts support placeholders: {code}, {language}, {file_path}, {context}
"""

# General security analysis prompt - works for all languages
GENERAL_SECURITY_PROMPT = """Analyze this {language} code for security vulnerabilities.

File: {file_path}

```{language}
{code}
```

Look for:
- Injection vulnerabilities (SQL, command, XSS, path traversal)
- Authentication and authorization issues
- Cryptographic weaknesses
- Input validation problems
- Information disclosure
- Race conditions
- Resource leaks

For each vulnerability found, respond with JSON:
```json
[
  {{
    "title": "Brief descriptive title",
    "vulnerability_type": "CWE-XXX or category name",
    "severity": "Critical|High|Medium|Low",
    "line_number": <line number in the code>,
    "snippet": "relevant code snippet",
    "reason": "detailed explanation of why this is vulnerable"
  }}
]
```

If no vulnerabilities found, respond with: []
"""

# C/C++ specific memory safety prompt
C_MEMORY_SAFETY_PROMPT = """Analyze this C/C++ code for memory safety vulnerabilities.

File: {file_path}

```c
{code}
```

Focus specifically on:
- Buffer overflows (stack and heap)
- Use-after-free vulnerabilities
- Double-free conditions
- Null pointer dereferences
- Integer overflows leading to buffer issues
- Format string vulnerabilities
- Uninitialized memory usage
- Out-of-bounds reads/writes
- Memory leaks in error paths

For each vulnerability found, respond with JSON:
```json
[
  {{
    "title": "Brief descriptive title",
    "vulnerability_type": "CWE-XXX",
    "severity": "Critical|High|Medium|Low",
    "line_number": <line number>,
    "snippet": "vulnerable code snippet",
    "reason": "detailed explanation including potential exploit scenario"
  }}
]
```

If no vulnerabilities found, respond with: []
"""

# Signal handler safety prompt - specifically for CVE-2024-6387 type bugs
SIGNAL_HANDLER_PROMPT = """Analyze this C/C++ code for signal handler safety issues.

File: {file_path}

```c
{code}
```

CRITICAL: Look for signal handlers that call async-signal-UNSAFE functions.

Async-signal-UNSAFE functions include (but not limited to):
- printf, fprintf, sprintf, snprintf, vprintf (and variants)
- malloc, free, realloc, calloc
- syslog, openlog, closelog
- exit (use _exit instead)
- pthread functions
- stdio functions (fopen, fclose, fread, fwrite, etc.)
- string functions that allocate (strdup, etc.)
- Any function that acquires locks or uses global/static state

Signal handlers should ONLY call async-signal-safe functions like:
- _exit, _Exit
- write (not printf!)
- signal, sigaction
- Simple variable assignments to volatile sig_atomic_t

Race condition pattern to detect:
1. Signal handler registered with signal() or sigaction()
2. Handler calls any async-signal-unsafe function
3. This creates exploitable race condition (potential RCE)

For each issue found, respond with JSON:
```json
[
  {{
    "title": "Async-signal-unsafe function in signal handler",
    "vulnerability_type": "CWE-364 Signal Handler Race Condition",
    "severity": "Critical",
    "line_number": <line of the unsafe call>,
    "snippet": "the signal handler code",
    "reason": "Signal handler 'X' calls async-signal-unsafe function 'Y'. This can cause a race condition if the signal interrupts Y or a function that holds locks Y needs. Can lead to RCE (CVE-2024-6387 pattern)."
  }}
]
```

If no vulnerabilities found, respond with: []
"""

# Python specific prompt
PYTHON_SECURITY_PROMPT = """Analyze this Python code for security vulnerabilities.

File: {file_path}

```python
{code}
```

Focus on:
- SQL Injection (raw queries, f-strings in SQL)
- Command Injection (os.system, subprocess with shell=True, eval, exec)
- Path Traversal (unsanitized file paths)
- SSRF (unvalidated URLs)
- Deserialization (pickle.loads, yaml.load without Loader)
- Template Injection (Jinja2 with user input)
- Hardcoded secrets/credentials
- Insecure random (random module for crypto)
- XML vulnerabilities (XXE with lxml/xml.etree)

For each vulnerability found, respond with JSON:
```json
[
  {{
    "title": "Brief descriptive title",
    "vulnerability_type": "CWE-XXX or category",
    "severity": "Critical|High|Medium|Low",
    "line_number": <line number>,
    "snippet": "vulnerable code",
    "reason": "detailed explanation"
  }}
]
```

If no vulnerabilities found, respond with: []
"""

# Cryptographic weakness prompt
CRYPTO_AUDIT_PROMPT = """Analyze this code for cryptographic weaknesses.

File: {file_path}

```{language}
{code}
```

Look for:
- Weak algorithms: MD5, SHA1 (for security), DES, 3DES, RC4, Blowfish
- Weak key sizes: RSA < 2048, ECC < 256, AES < 128
- ECB mode usage (deterministic encryption)
- Static/hardcoded IVs or keys
- Missing authentication (encryption without MAC/AEAD)
- Weak PRNGs for cryptographic use
- Deprecated TLS versions (< 1.2)
- Weak Diffie-Hellman groups (group1, group2)
- Certificate validation disabled
- Timing-vulnerable comparisons for secrets

For each weakness found, respond with JSON:
```json
[
  {{
    "title": "Brief descriptive title",
    "vulnerability_type": "CWE-327 or specific CWE",
    "severity": "Critical|High|Medium|Low",
    "line_number": <line number>,
    "snippet": "weak crypto code",
    "reason": "explanation of the weakness and recommended fix"
  }}
]
```

If no vulnerabilities found, respond with: []
"""

# Race condition prompt
RACE_CONDITION_PROMPT = """Analyze this code for race conditions and concurrency vulnerabilities.

File: {file_path}

```{language}
{code}
```

Look for:
- TOCTOU (Time-of-check to time-of-use) bugs
- Unprotected shared state access
- Missing synchronization primitives
- Deadlock potential
- Signal handler races (async-signal-unsafe calls)
- File system races (symlink attacks, temp file races)
- Double-checked locking anti-pattern
- Atomic operation assumptions on non-atomic types

For each race condition found, respond with JSON:
```json
[
  {{
    "title": "Brief descriptive title",
    "vulnerability_type": "CWE-362 or specific CWE",
    "severity": "Critical|High|Medium|Low",
    "line_number": <line number>,
    "snippet": "code with race condition",
    "reason": "detailed explanation of the race and exploit scenario"
  }}
]
```

If no vulnerabilities found, respond with: []
"""

# Verification prompt
VERIFICATION_PROMPT = """You are verifying a potential security vulnerability.

File: {file_path}

Code context:
```{language}
{code}
```

Reported vulnerability:
- Title: {finding_title}
- Type: {finding_type}
- Severity: {finding_severity}
- Line: {finding_line}
- Reason: {finding_reason}

Analyze whether this is a TRUE POSITIVE or FALSE POSITIVE.

Consider:
1. Is the vulnerable pattern actually present?
2. Is there input validation/sanitization we missed?
3. Is this code reachable with attacker-controlled input?
4. Are there mitigating factors (sandboxing, permissions)?

Respond with JSON:
```json
{{
  "verdict": "true_positive|false_positive",
  "confidence": <1-10>,
  "reasoning": "detailed explanation of your verdict",
  "adjusted_severity": "Critical|High|Medium|Low|null"
}}
```
"""

# All prompts indexed by name for easy lookup
PROMPTS = {
    "general_security": GENERAL_SECURITY_PROMPT,
    "c_memory_safety": C_MEMORY_SAFETY_PROMPT,
    "signal_handler": SIGNAL_HANDLER_PROMPT,
    "python_security": PYTHON_SECURITY_PROMPT,
    "crypto_audit": CRYPTO_AUDIT_PROMPT,
    "race_condition": RACE_CONDITION_PROMPT,
    "verification": VERIFICATION_PROMPT,
}
