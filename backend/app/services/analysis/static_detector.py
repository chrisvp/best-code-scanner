import re
from typing import List, Tuple


class StaticPatternDetector:
    """Fast static detection - no LLM needed for obvious patterns"""

    # Definite vulnerabilities - auto-create draft finding
    DEFINITE_VULNS = {
        'c': [
            (r'gets\s*\(', 'Buffer Overflow', 'Critical', 'gets() has no bounds checking'),
            (r'strcpy\s*\([^,]+,\s*argv', 'Buffer Overflow', 'High', 'Unbounded copy from argv'),
            (r'sprintf\s*\([^,]+,\s*[^,]*%s', 'Format String', 'High', 'sprintf with %s, no bounds'),
            (r'system\s*\(\s*argv', 'Command Injection', 'Critical', 'Direct argv to system()'),
            (r'scanf\s*\(\s*"%s"', 'Buffer Overflow', 'High', 'scanf %s without width limit'),
            (r'strcat\s*\([^,]+,\s*argv', 'Buffer Overflow', 'High', 'Unbounded strcat from argv'),
            # Hardcoded credentials
            (r'(password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{4,}["\']', 'Hardcoded Credentials', 'High', 'Hardcoded secret in source'),
            # TOCTOU
            (r'access\s*\([^)]+\)\s*[^{]*\bfopen\s*\(', 'TOCTOU Race Condition', 'Medium', 'access() check before fopen()'),
        ],
        'cpp': [
            (r'gets\s*\(', 'Buffer Overflow', 'Critical', 'gets() has no bounds checking'),
            (r'strcpy\s*\([^,]+,\s*argv', 'Buffer Overflow', 'High', 'Unbounded copy from argv'),
            (r'sprintf\s*\([^,]+,\s*[^,]*%s', 'Format String', 'High', 'sprintf with %s, no bounds'),
            (r'system\s*\(\s*argv', 'Command Injection', 'Critical', 'Direct argv to system()'),
            # Hardcoded credentials
            (r'(password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{4,}["\']', 'Hardcoded Credentials', 'High', 'Hardcoded secret in source'),
            # TOCTOU
            (r'access\s*\([^)]+\)\s*[^{]*\bfopen\s*\(', 'TOCTOU Race Condition', 'Medium', 'access() check before fopen()'),
        ],
        'py': [
            (r'eval\s*\(\s*request\.', 'Code Injection', 'Critical', 'eval() on request data'),
            (r'exec\s*\(\s*request\.', 'Code Injection', 'Critical', 'exec() on request data'),
            (r'pickle\.loads?\s*\(\s*request\.', 'Deserialization', 'Critical', 'Pickle on untrusted data'),
            (r'yaml\.load\s*\([^)]*Loader\s*=\s*None', 'Deserialization', 'High', 'yaml.load without safe Loader'),
            (r'subprocess.*shell\s*=\s*True.*request\.', 'Command Injection', 'Critical', 'Shell=True with user input'),
            (r'os\.system\s*\(\s*request\.', 'Command Injection', 'Critical', 'os.system with request data'),
            (r'__import__\s*\(\s*request\.', 'Code Injection', 'Critical', '__import__ with user input'),
            # Hardcoded credentials
            (r'(password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{4,}["\']', 'Hardcoded Credentials', 'High', 'Hardcoded secret in source'),
        ],
        'h': [],
        'hpp': [],
    }

    # Dangerous patterns that warrant LLM analysis
    DANGEROUS_PATTERNS = {
        'c': ['system', 'exec', 'popen', 'strcpy', 'strcat', 'sprintf', 'scanf', 'gets',
              'malloc', 'free', 'memcpy', 'recv', 'send', 'fopen', 'fread', 'fwrite',
              'access', 'strlen', 'password', 'secret', 'token', 'credential', 'auth'],
        'cpp': ['system', 'exec', 'popen', 'strcpy', 'strcat', 'sprintf', 'scanf', 'gets',
                'new', 'delete', 'memcpy', 'recv', 'send', 'access', 'strlen',
                'password', 'secret', 'token', 'credential', 'auth', 'nullptr', 'NULL'],
        'py': ['eval', 'exec', 'system', 'popen', 'subprocess', 'pickle', 'marshal',
               'yaml.load', 'execute', 'shell', 'open', 'input', 'os.', 'importlib',
               '__import__', 'compile', 'globals', 'locals', 'setattr', 'getattr',
               'password', 'secret', 'token', 'credential', 'auth'],
        'h': ['password', 'secret', 'token', 'auth', 'credential'],
        'hpp': ['password', 'secret', 'token', 'auth', 'credential', 'delete', 'new'],
    }

    def scan_fast(self, chunk, language: str) -> Tuple[List[dict], bool]:
        """
        Fast static scan without LLM.
        Returns (findings, needs_llm)
        """
        content = self._get_content(chunk)
        findings = []

        # Normalize language
        if language in ('h', 'hpp'):
            language = 'c' if language == 'h' else 'cpp'

        # Check definite vulnerabilities
        for pattern, vuln_type, severity, reason in self.DEFINITE_VULNS.get(language, []):
            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    'title': f'{vuln_type} detected',
                    'vulnerability_type': vuln_type,
                    'severity': severity,
                    'line_number': line_num,
                    'snippet': self._extract_snippet(content, match),
                    'reason': reason,
                    'auto_detected': True
                })

        # Check if LLM analysis is needed
        needs_llm = self._has_interesting_patterns(content, language)

        return findings, needs_llm

    def _get_content(self, chunk) -> str:
        """Get content from chunk object or dict"""
        if hasattr(chunk, 'content'):
            return chunk.content
        if isinstance(chunk, dict):
            return chunk.get('content', '')

        # Try to read from file
        from app.models.scanner_models import ScanFile, ScanFileChunk
        from app.core.database import SessionLocal

        if hasattr(chunk, 'scan_file_id'):
            db = SessionLocal()
            try:
                scan_file = db.query(ScanFile).filter(
                    ScanFile.id == chunk.scan_file_id
                ).first()
                if scan_file:
                    with open(scan_file.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                    return ''.join(lines[chunk.start_line - 1:chunk.end_line])
            finally:
                db.close()

        return ""

    def _extract_snippet(self, content: str, match) -> str:
        """Extract code snippet around match"""
        lines = content.split('\n')
        match_line = content[:match.start()].count('\n')

        start = max(0, match_line - 1)
        end = min(len(lines), match_line + 2)

        return '\n'.join(lines[start:end])

    def _has_interesting_patterns(self, content: str, language: str) -> bool:
        """Check if content has patterns worth LLM analysis"""
        content_lower = content.lower()

        # Skip if mostly data/constants
        if self._is_mostly_data(content):
            return False

        # Check for dangerous patterns
        patterns = self.DANGEROUS_PATTERNS.get(language, [])
        return any(p in content_lower for p in patterns)

    def _is_mostly_data(self, content: str) -> bool:
        """Check if content is mostly data (arrays, strings, etc.)"""
        # Count code-like tokens vs data
        code_tokens = len(re.findall(r'\b(if|for|while|def|class|function|return|switch|case)\b', content))
        data_tokens = len(re.findall(r'["\'][^"\']{20,}["\']', content))

        # If many long strings and few control structures, likely data
        if data_tokens > 5 and code_tokens < 2:
            return True

        return False
