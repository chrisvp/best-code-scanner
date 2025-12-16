"""
Default analyzer prompts for different scan profiles.
Prompts support placeholders: {code}, {language}, {file_path}, {context}

All prompts use MARKER FORMAT (*FIELD: value) for reliable parsing.
"""

# Output format instructions shared across prompts
MARKER_FORMAT_INSTRUCTIONS = """
=== OUTPUT FORMAT ===
*DRAFT: descriptive title
*TYPE: CWE-XXX or vulnerability category
*SEVERITY: Critical/High/Medium/Low
*LINE: exact line number from the code
*SNIPPET: the vulnerable code
*REASON: one sentence explanation of why this is vulnerable
*END_DRAFT

Report each finding separately. If no vulnerabilities found: *DRAFT:NONE
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

=== EXAMPLES ===

 42 | query = "SELECT * FROM users WHERE id = " + user_id

*DRAFT: SQL Injection via String Concatenation
*TYPE: CWE-89 SQL Injection
*SEVERITY: Critical
*LINE: 42
*SNIPPET: query = "SELECT * FROM users WHERE id = " + user_id
*REASON: User input directly concatenated into SQL query without parameterization
*END_DRAFT

 15 | os.system("rm -rf " + user_path)

*DRAFT: Command Injection via os.system
*TYPE: CWE-78 OS Command Injection
*SEVERITY: Critical
*LINE: 15
*SNIPPET: os.system("rm -rf " + user_path)
*REASON: User-controlled path passed to shell command without sanitization
*END_DRAFT
""" + MARKER_FORMAT_INSTRUCTIONS

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

=== EXAMPLES ===

 331 | strcpy(credentials, username);
 332 | strcat(credentials, password);

*DRAFT: Buffer Overflow in Credential Handling
*TYPE: CWE-120 Buffer Overflow
*SEVERITY: High
*LINE: 331
*SNIPPET: strcpy(credentials, username);
*REASON: Unbounded copy of username into fixed-size buffer without length check
*END_DRAFT

 410 | free(block);
 411 | process_data(block->data);

*DRAFT: Use-After-Free Memory Access
*TYPE: CWE-416 Use After Free
*SEVERITY: High
*LINE: 411
*SNIPPET: process_data(block->data);
*REASON: Accessing block->data after block was freed on previous line
*END_DRAFT
""" + MARKER_FORMAT_INSTRUCTIONS

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

=== EXAMPLE ===

 100 | void sigalarm_handler(int sig) {
 101 |     syslog(LOG_WARNING, "Timeout reached");
 102 |     cleanup_connection();
 103 | }

*DRAFT: Async-Signal-Unsafe Function in Signal Handler
*TYPE: CWE-364 Signal Handler Race Condition
*SEVERITY: Critical
*LINE: 101
*SNIPPET: syslog(LOG_WARNING, "Timeout reached");
*REASON: Signal handler calls syslog() which is async-signal-unsafe, creating exploitable race condition (CVE-2024-6387 pattern)
*END_DRAFT
""" + MARKER_FORMAT_INSTRUCTIONS

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

=== EXAMPLES ===

 25 | result = eval(user_expression)

*DRAFT: Code Injection via eval()
*TYPE: CWE-94 Code Injection
*SEVERITY: Critical
*LINE: 25
*SNIPPET: result = eval(user_expression)
*REASON: User input passed directly to eval() allows arbitrary code execution
*END_DRAFT

 88 | data = pickle.loads(request.data)

*DRAFT: Insecure Deserialization
*TYPE: CWE-502 Deserialization of Untrusted Data
*SEVERITY: Critical
*LINE: 88
*SNIPPET: data = pickle.loads(request.data)
*REASON: Deserializing untrusted data with pickle allows arbitrary code execution
*END_DRAFT
""" + MARKER_FORMAT_INSTRUCTIONS

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

=== EXAMPLES ===

 45 | hash = hashlib.md5(password.encode()).hexdigest()

*DRAFT: Weak Password Hashing with MD5
*TYPE: CWE-327 Use of Broken Crypto Algorithm
*SEVERITY: High
*LINE: 45
*SNIPPET: hash = hashlib.md5(password.encode()).hexdigest()
*REASON: MD5 is cryptographically broken; use bcrypt/scrypt/argon2 for passwords
*END_DRAFT

 72 | SECRET_KEY = "hardcoded_secret_123"

*DRAFT: Hardcoded Cryptographic Key
*TYPE: CWE-798 Hardcoded Credentials
*SEVERITY: High
*LINE: 72
*SNIPPET: SECRET_KEY = "hardcoded_secret_123"
*REASON: Cryptographic key hardcoded in source code; should use environment variables or key management
*END_DRAFT
""" + MARKER_FORMAT_INSTRUCTIONS

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

=== EXAMPLES ===

 55 | if os.path.exists(filepath):
 56 |     with open(filepath, 'r') as f:

*DRAFT: TOCTOU Race Condition
*TYPE: CWE-367 Time-of-check Time-of-use
*SEVERITY: Medium
*LINE: 55
*SNIPPET: if os.path.exists(filepath):
*REASON: File existence check and open are not atomic; file could be modified between check and use
*END_DRAFT

 120 | temp_file = "/tmp/app_" + str(random.randint(0, 1000))

*DRAFT: Predictable Temporary File Name
*TYPE: CWE-377 Insecure Temporary File
*SEVERITY: Medium
*LINE: 120
*SNIPPET: temp_file = "/tmp/app_" + str(random.randint(0, 1000))
*REASON: Predictable temp filename enables symlink attacks; use tempfile.mkstemp()
*END_DRAFT
""" + MARKER_FORMAT_INSTRUCTIONS

# Verification prompt - uses *VOTE markers with 4 vote types
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

Analyze this finding and vote on its validity.

Consider:
1. Is the vulnerable pattern actually present?
2. Is there input validation/sanitization we missed?
3. Is this code reachable with attacker-controlled input?
4. Are there mitigating factors (sandboxing, permissions)?

=== OUTPUT FORMAT ===
*VOTE: REAL/WEAKNESS/FALSE_POSITIVE/NEEDS_VERIFIED
*CONFIDENCE: 0-100
*REASONING: your explanation
*END_VERIFIED

Vote meanings:
- REAL: Confirmed exploitable vulnerability
- WEAKNESS: Poor coding practice but not directly exploitable
- FALSE_POSITIVE: Scanner is wrong, code is safe
- NEEDS_VERIFIED: Uncertain, requires deeper analysis (agentic verification)
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
