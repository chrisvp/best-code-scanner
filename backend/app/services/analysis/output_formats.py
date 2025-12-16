# Output format templates - appended to prompts based on output_mode
# These are injected via the {output_format} placeholder in prompt templates
#
# Templates can be customized via the UI (stored in global_settings table)
# These hardcoded values serve as defaults when no DB override exists

import time
from typing import Optional, Dict, Any

# Simple in-memory cache for templates (avoids DB calls during scans)
_template_cache: Dict[str, Any] = {}
_cache_ttl = 300  # 5 minutes
_cache_timestamp = 0.0


def _get_cached_templates() -> Optional[Dict[str, str]]:
    """Get cached templates if still valid"""
    global _cache_timestamp
    if time.time() - _cache_timestamp < _cache_ttl and _template_cache:
        return _template_cache
    return None


def _set_cached_templates(templates: Dict[str, str]):
    """Update template cache"""
    global _template_cache, _cache_timestamp
    _template_cache = templates
    _cache_timestamp = time.time()


def invalidate_template_cache():
    """Invalidate the template cache (call when templates are updated)"""
    global _template_cache, _cache_timestamp
    _template_cache = {}
    _cache_timestamp = 0.0


def _load_templates_from_db() -> Dict[str, str]:
    """Load custom templates from global_settings table"""
    # Check cache first
    cached = _get_cached_templates()
    if cached is not None:
        return cached

    try:
        from app.core.database import SessionLocal
        from app.models.scanner_models import GlobalSetting

        db = SessionLocal()
        try:
            # Load all output format related settings in one query
            settings = db.query(GlobalSetting).filter(
                GlobalSetting.key.like('output_format_%')
            ).all()

            templates = {s.key: s.value for s in settings if s.value}
            _set_cached_templates(templates)
            return templates
        finally:
            db.close()
    except Exception:
        # If DB access fails, return empty dict (will use defaults)
        return {}


# Combined output format templates with examples included
# Each template contains both the format instructions AND examples
OUTPUT_FORMAT_TEMPLATES = {
    # For analyzers (draft scanning)
    "analyzer": {
        "markers": """=== OUTPUT FORMAT ===
For each vulnerability found, use this EXACT format:

*DRAFT: [descriptive title]
*TYPE: CWE-XXX
*SEVERITY: Critical/High/Medium/Low
*LINE: [exact line number from code above]
*SNIPPET: [the vulnerable code]
*REASON: [one sentence explanation]
*END_DRAFT

If no vulnerabilities found, respond with: *DRAFT:NONE

=== EXAMPLES ===

 42 | query = "SELECT * FROM users WHERE id = " + user_id

*DRAFT: SQL Injection via String Concatenation
*TYPE: CWE-89
*SEVERITY: High
*LINE: 42
*SNIPPET: query = "SELECT * FROM users WHERE id = " + user_id
*REASON: User input directly concatenated into SQL query without sanitization
*END_DRAFT

331 | strcpy(credentials, username);
332 | strcat(credentials, password);

*DRAFT: Buffer Overflow in Credential Handling
*TYPE: CWE-120
*SEVERITY: Critical
*LINE: 331
*SNIPPET: strcpy(credentials, username);
*REASON: No bounds checking on credential buffer copy
*END_DRAFT""",

        "json": """=== OUTPUT FORMAT ===
Respond with a JSON object containing a "findings" array. Each finding should have:
- title: Brief descriptive title
- vulnerability_type: CWE ID (e.g., "CWE-78")
- severity: "Critical", "High", "Medium", or "Low"
- line_number: Exact line number from the code
- snippet: The vulnerable code
- reason: One sentence explanation

If no vulnerabilities: {"findings": []}

=== EXAMPLES ===

For code like:
 42 | query = "SELECT * FROM users WHERE id = " + user_id

Respond with:
{"findings": [{"title": "SQL Injection via String Concatenation", "vulnerability_type": "CWE-89", "severity": "High", "line_number": 42, "snippet": "query = \\"SELECT * FROM users WHERE id = \\" + user_id", "reason": "User input directly concatenated into SQL query without sanitization"}]}

For code like:
331 | strcpy(credentials, username);
332 | strcat(credentials, password);

Respond with:
{"findings": [{"title": "Buffer Overflow in Credential Handling", "vulnerability_type": "CWE-120", "severity": "Critical", "line_number": 331, "snippet": "strcpy(credentials, username);", "reason": "No bounds checking on credential buffer copy"}]}""",

        "guided_json": """=== OUTPUT FORMAT ===
Respond with JSON matching the required schema. Include all findings in the "findings" array.
Each finding must have: title, vulnerability_type (CWE-XXX), severity, line_number, snippet, reason.
If no vulnerabilities found, return: {"findings": []}

Follow the JSON schema. For each vulnerability found, include all required fields.
Example finding structure: title, vulnerability_type (CWE-XXX), severity (Critical/High/Medium/Low), line_number, snippet, reason."""
    },

    # For verifiers (voting)
    "verifier": {
        "markers": """=== OUTPUT FORMAT ===
Respond with your vote using this EXACT format:

*VOTE: REAL/WEAKNESS/FALSE_POSITIVE/NEEDS_VERIFIED
*CONFIDENCE: [0-100]
*REASONING: [your explanation]
*END_VERIFIED

Vote meanings:
- FALSE_POSITIVE: Scanner is wrong, code is safe
- REAL: Confirmed exploitable vulnerability
- NEEDS_VERIFIED: Can't confirm from visible code, needs agent verification
- WEAKNESS: Poor practice but not directly exploitable

=== EXAMPLES ===

Example for a false positive (safe code):
*VOTE: FALSE_POSITIVE
*CONFIDENCE: 88
*REASONING: Input is validated on line 25 before reaching this code path
*END_VERIFIED

Example for a real vulnerability:
*VOTE: REAL
*CONFIDENCE: 92
*REASONING: User input flows directly to strcpy without bounds checking, classic buffer overflow
*END_VERIFIED

Example for uncertain case needing deeper analysis:
*VOTE: NEEDS_VERIFIED
*CONFIDENCE: 60
*REASONING: Complex data flow requires deeper analysis to confirm exploitability
*END_VERIFIED

Example for a code quality issue:
*VOTE: WEAKNESS
*CONFIDENCE: 75
*REASONING: Missing null check is bad practice but not directly exploitable in this context
*END_VERIFIED""",

        "json": """=== OUTPUT FORMAT ===
Respond with a JSON object:
- vote: "REAL", "WEAKNESS", "FALSE_POSITIVE", or "NEEDS_VERIFIED"
- confidence: Number 0-100
- reasoning: Your explanation

Vote meanings:
- FALSE_POSITIVE: Scanner is wrong, code is safe
- REAL: Confirmed exploitable vulnerability
- NEEDS_VERIFIED: Can't confirm from visible code, needs agent verification
- WEAKNESS: Poor practice but not directly exploitable

=== EXAMPLES ===

For a false positive: {"vote": "FALSE_POSITIVE", "confidence": 88, "reasoning": "Input is validated on line 25 before reaching this code path"}
For a real vulnerability: {"vote": "REAL", "confidence": 92, "reasoning": "User input flows directly to strcpy without bounds checking"}
For uncertain case: {"vote": "NEEDS_VERIFIED", "confidence": 60, "reasoning": "Complex data flow requires deeper analysis to confirm exploitability"}
For a code quality issue: {"vote": "WEAKNESS", "confidence": 75, "reasoning": "Missing null check is bad practice but not directly exploitable"}""",

        "guided_json": """=== OUTPUT FORMAT ===
Respond with JSON matching the required schema.
Vote must be one of: REAL, WEAKNESS, FALSE_POSITIVE, NEEDS_VERIFIED
Confidence is 0-100. Include your reasoning.

Vote meanings:
- FALSE_POSITIVE: Scanner is wrong, code is safe
- REAL: Confirmed exploitable vulnerability
- NEEDS_VERIFIED: Can't confirm from visible code, needs agent verification
- WEAKNESS: Poor practice but not directly exploitable

Follow the JSON schema. Vote must be REAL, WEAKNESS, FALSE_POSITIVE, or NEEDS_VERIFIED. Confidence 0-100. Include detailed reasoning."""
    },

    # For enrichers (full reports)
    "enricher": {
        "markers": """=== OUTPUT FORMAT ===
*FINDING: [title]
*CATEGORY: [CWE category]
*SEVERITY: Critical/High/Medium/Low
*CVSS: [0.0-10.0]
*VULNERABILITY_DETAILS: [detailed explanation]
*PROOF_OF_CONCEPT: [exploitation steps or code]
*CORRECTED_CODE: [fixed version of vulnerable code]
*REMEDIATION_STEPS: [how to fix]
*REFERENCES: [relevant links or documentation]
*END_FINDING

=== EXAMPLE ===

*FINDING: Buffer Overflow in strcpy Call
*CATEGORY: CWE-120 Buffer Copy without Checking Size of Input
*SEVERITY: Critical
*CVSS: 9.8
*VULNERABILITY_DETAILS: The function copies user-supplied input into a fixed-size buffer without bounds checking...
*PROOF_OF_CONCEPT: Send input longer than buffer size to trigger overflow...
*CORRECTED_CODE: Use strncpy with explicit size limit...
*REMEDIATION_STEPS: 1. Replace strcpy with strncpy 2. Add input length validation...
*REFERENCES: https://cwe.mitre.org/data/definitions/120.html
*END_FINDING""",

        "json": """=== OUTPUT FORMAT ===
Respond with a JSON object containing:
- title, category, severity, cvss_score (0-10)
- vulnerability_details: Detailed explanation
- proof_of_concept: How to exploit
- corrected_code: Fixed code
- remediation_steps: How to fix
- references: Relevant documentation

=== EXAMPLE ===

{
  "title": "Buffer Overflow in strcpy Call",
  "category": "CWE-120 Buffer Copy without Checking Size of Input",
  "severity": "Critical",
  "cvss_score": 9.8,
  "vulnerability_details": "The function copies user-supplied input...",
  "proof_of_concept": "Send input longer than buffer size...",
  "corrected_code": "Use strncpy with explicit size limit...",
  "remediation_steps": "1. Replace strcpy with strncpy...",
  "references": "https://cwe.mitre.org/data/definitions/120.html"
}""",

        "guided_json": """=== OUTPUT FORMAT ===
Respond with JSON matching the required schema with all fields populated.

Follow the JSON schema exactly. Include all fields: title, category, severity, cvss_score, vulnerability_details, proof_of_concept, corrected_code, remediation_steps, references."""
    }
}


def get_output_format(role: str, output_mode: str) -> str:
    """
    Get the output format instructions for a given role and output mode.

    Checks DB for custom templates first (cached), falls back to hardcoded defaults.

    Args:
        role: "analyzer", "verifier", or "enricher"
        output_mode: "markers", "json", or "guided_json"

    Returns:
        The format instructions string to append to prompts
    """
    # Check for DB override first (uses cache)
    db_key = f"output_format_{role}_{output_mode}"
    db_templates = _load_templates_from_db()
    if db_key in db_templates:
        return db_templates[db_key]

    # Fall back to hardcoded defaults
    role_templates = OUTPUT_FORMAT_TEMPLATES.get(role, OUTPUT_FORMAT_TEMPLATES["analyzer"])
    return role_templates.get(output_mode, role_templates["markers"])


def get_all_templates() -> Dict[str, Dict[str, str]]:
    """
    Get all output format templates for UI display.
    Returns the effective values (DB overrides or defaults).
    """
    db_templates = _load_templates_from_db()

    result = {}

    for role in ["analyzer", "verifier", "enricher"]:
        result[role] = {}

        for mode in ["markers", "json", "guided_json"]:
            format_key = f"output_format_{role}_{mode}"
            if format_key in db_templates:
                result[role][mode] = db_templates[format_key]
            else:
                result[role][mode] = OUTPUT_FORMAT_TEMPLATES.get(role, {}).get(mode, "")

    return result
