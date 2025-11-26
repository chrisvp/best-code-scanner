import re
from typing import List, Tuple, Optional


class StaticPatternDetector:
    """Fast static detection using database rules - no LLM needed for obvious patterns"""

    # Fallback rules if database is empty (used for seeding)
    DEFAULT_RULES = [
        # C/C++ Critical
        {'name': 'gets() Buffer Overflow', 'pattern': r'gets\s*\(', 'languages': ['c', 'cpp'],
         'cwe_id': 'CWE-120', 'vulnerability_type': 'Buffer Overflow', 'severity': 'Critical',
         'description': 'gets() has no bounds checking - always vulnerable'},
        {'name': 'Direct argv to system()', 'pattern': r'system\s*\(\s*argv', 'languages': ['c', 'cpp'],
         'cwe_id': 'CWE-78', 'vulnerability_type': 'Command Injection', 'severity': 'Critical',
         'description': 'Command line argument passed directly to system()'},

        # C/C++ High - Buffer Overflows
        {'name': 'strcpy from argv', 'pattern': r'strcpy\s*\([^,]+,\s*argv', 'languages': ['c', 'cpp'],
         'cwe_id': 'CWE-120', 'vulnerability_type': 'Buffer Overflow', 'severity': 'High',
         'description': 'Unbounded copy from command line argument'},
        {'name': 'strcat from argv', 'pattern': r'strcat\s*\([^,]+,\s*argv', 'languages': ['c', 'cpp'],
         'cwe_id': 'CWE-120', 'vulnerability_type': 'Buffer Overflow', 'severity': 'High',
         'description': 'Unbounded concatenation from command line argument'},
        {'name': 'scanf %s without width', 'pattern': r'scanf\s*\(\s*"%s"', 'languages': ['c', 'cpp'],
         'cwe_id': 'CWE-120', 'vulnerability_type': 'Buffer Overflow', 'severity': 'High',
         'description': 'scanf %s without width limit allows buffer overflow'},

        # C/C++ High - Command Injection (sprintf + system pattern)
        {'name': 'sprintf building system command', 'pattern': r'sprintf\s*\([^;]+\);\s*\n?\s*system\s*\(',
         'languages': ['c', 'cpp'], 'cwe_id': 'CWE-78', 'vulnerability_type': 'Command Injection',
         'severity': 'Critical', 'description': 'sprintf builds string passed to system() - command injection'},
        {'name': 'snprintf building system command', 'pattern': r'snprintf\s*\([^;]+\);\s*\n?\s*system\s*\(',
         'languages': ['c', 'cpp'], 'cwe_id': 'CWE-78', 'vulnerability_type': 'Command Injection',
         'severity': 'Critical', 'description': 'snprintf builds string passed to system() - command injection'},

        # C/C++ - Format String (only when user input IS the format)
        {'name': 'printf with variable format', 'pattern': r'printf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)',
         'languages': ['c', 'cpp'], 'cwe_id': 'CWE-134', 'vulnerability_type': 'Format String',
         'severity': 'High', 'description': 'printf with variable as format string'},
        {'name': 'fprintf with variable format', 'pattern': r'fprintf\s*\([^,]+,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)',
         'languages': ['c', 'cpp'], 'cwe_id': 'CWE-134', 'vulnerability_type': 'Format String',
         'severity': 'High', 'description': 'fprintf with variable as format string'},

        # C/C++ - Memory issues
        {'name': 'free then use pattern', 'pattern': r'free\s*\(\s*(\w+)\s*\)[^}]*\1\s*->',
         'languages': ['c', 'cpp'], 'cwe_id': 'CWE-416', 'vulnerability_type': 'Use-After-Free',
         'severity': 'Critical', 'description': 'Pointer used after being freed'},
        {'name': 'Double free pattern', 'pattern': r'free\s*\(\s*(\w+)\s*\)[^}]*free\s*\(\s*\1\s*\)',
         'languages': ['c', 'cpp'], 'cwe_id': 'CWE-415', 'vulnerability_type': 'Double-Free',
         'severity': 'Critical', 'description': 'Same pointer freed twice'},

        # C/C++ - TOCTOU
        {'name': 'access then fopen TOCTOU', 'pattern': r'access\s*\([^)]+\)[^;]*;[^}]*fopen\s*\(',
         'languages': ['c', 'cpp'], 'cwe_id': 'CWE-367', 'vulnerability_type': 'TOCTOU Race Condition',
         'severity': 'Medium', 'description': 'Time-of-check to time-of-use race condition'},

        # Python Critical
        {'name': 'eval on request data', 'pattern': r'eval\s*\(\s*request\.', 'languages': ['py'],
         'cwe_id': 'CWE-94', 'vulnerability_type': 'Code Injection', 'severity': 'Critical',
         'description': 'eval() called on user request data'},
        {'name': 'exec on request data', 'pattern': r'exec\s*\(\s*request\.', 'languages': ['py'],
         'cwe_id': 'CWE-94', 'vulnerability_type': 'Code Injection', 'severity': 'Critical',
         'description': 'exec() called on user request data'},
        {'name': 'pickle on request data', 'pattern': r'pickle\.loads?\s*\(\s*request\.', 'languages': ['py'],
         'cwe_id': 'CWE-502', 'vulnerability_type': 'Insecure Deserialization', 'severity': 'Critical',
         'description': 'Pickle deserialization of untrusted data'},
        {'name': 'os.system with request', 'pattern': r'os\.system\s*\(\s*request\.', 'languages': ['py'],
         'cwe_id': 'CWE-78', 'vulnerability_type': 'Command Injection', 'severity': 'Critical',
         'description': 'os.system() with user request data'},
        {'name': 'subprocess shell=True with user input', 'pattern': r'subprocess\.(run|call|Popen)\s*\([^)]*shell\s*=\s*True[^)]*request\.',
         'languages': ['py'], 'cwe_id': 'CWE-78', 'vulnerability_type': 'Command Injection',
         'severity': 'Critical', 'description': 'subprocess with shell=True and user input'},

        # Python High
        {'name': 'yaml.load unsafe', 'pattern': r'yaml\.load\s*\([^)]*\)', 'languages': ['py'],
         'cwe_id': 'CWE-502', 'vulnerability_type': 'Insecure Deserialization', 'severity': 'High',
         'description': 'yaml.load without SafeLoader allows code execution'},
        {'name': '__import__ with user input', 'pattern': r'__import__\s*\(\s*request\.', 'languages': ['py'],
         'cwe_id': 'CWE-94', 'vulnerability_type': 'Code Injection', 'severity': 'Critical',
         'description': 'Dynamic import with user-controlled module name'},

        # Cross-language - Hardcoded Credentials
        {'name': 'Hardcoded password', 'pattern': r'(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
         'languages': ['c', 'cpp', 'py', 'js', 'java'], 'cwe_id': 'CWE-798',
         'vulnerability_type': 'Hardcoded Credentials', 'severity': 'High',
         'description': 'Hardcoded password in source code'},
        {'name': 'Hardcoded API key', 'pattern': r'(api_key|apikey|api_secret)\s*=\s*["\'][^"\']{8,}["\']',
         'languages': ['c', 'cpp', 'py', 'js', 'java'], 'cwe_id': 'CWE-798',
         'vulnerability_type': 'Hardcoded Credentials', 'severity': 'High',
         'description': 'Hardcoded API key in source code'},
        {'name': 'Hardcoded secret/token', 'pattern': r'(secret|token|auth_token)\s*=\s*["\'][^"\']{8,}["\']',
         'languages': ['c', 'cpp', 'py', 'js', 'java'], 'cwe_id': 'CWE-798',
         'vulnerability_type': 'Hardcoded Credentials', 'severity': 'High',
         'description': 'Hardcoded secret or token in source code'},

        # SQL Injection patterns
        {'name': 'SQL string concatenation', 'pattern': r'(SELECT|INSERT|UPDATE|DELETE)[^"\']*\+\s*\w+',
         'languages': ['py', 'js', 'java'], 'cwe_id': 'CWE-89',
         'vulnerability_type': 'SQL Injection', 'severity': 'High',
         'description': 'SQL query built with string concatenation'},
        {'name': 'SQL f-string interpolation', 'pattern': r'f["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?\{',
         'languages': ['py'], 'cwe_id': 'CWE-89',
         'vulnerability_type': 'SQL Injection', 'severity': 'High',
         'description': 'SQL query built with f-string interpolation'},
    ]

    # Keywords that trigger LLM analysis (not definite vulns, but worth checking)
    DANGEROUS_KEYWORDS = {
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

    def __init__(self, rules: Optional[List] = None):
        """
        Initialize with rules from database or defaults.

        Args:
            rules: List of StaticRule objects or dicts. If None, uses DEFAULT_RULES.
        """
        self._rules = []
        self._rules_by_language = {}

        if rules:
            self._load_rules(rules)
        else:
            self._load_rules(self.DEFAULT_RULES)

    def _load_rules(self, rules: List):
        """Load rules and index by language for fast lookup"""
        self._rules = []
        self._rules_by_language = {}

        for rule in rules:
            # Handle both dict and ORM objects
            if hasattr(rule, '__dict__'):
                rule_dict = {
                    'id': getattr(rule, 'id', None),
                    'name': rule.name,
                    'pattern': rule.pattern,
                    'languages': rule.languages or [],
                    'cwe_id': getattr(rule, 'cwe_id', None),
                    'vulnerability_type': rule.vulnerability_type,
                    'severity': rule.severity,
                    'description': getattr(rule, 'description', ''),
                    'is_definite': getattr(rule, 'is_definite', True),
                    'enabled': getattr(rule, 'enabled', True),
                }
            else:
                rule_dict = rule
                rule_dict.setdefault('enabled', True)
                rule_dict.setdefault('is_definite', True)

            if not rule_dict.get('enabled', True):
                continue

            # Compile regex
            try:
                rule_dict['compiled'] = re.compile(rule_dict['pattern'], re.IGNORECASE | re.MULTILINE)
            except re.error as e:
                print(f"Invalid regex in rule '{rule_dict.get('name')}': {e}")
                continue

            self._rules.append(rule_dict)

            # Index by language
            for lang in rule_dict.get('languages', []):
                if lang not in self._rules_by_language:
                    self._rules_by_language[lang] = []
                self._rules_by_language[lang].append(rule_dict)

    @classmethod
    def load_from_db(cls, db_session) -> 'StaticPatternDetector':
        """Load rules from database and create detector instance"""
        from app.models.scanner_models import StaticRule

        rules = db_session.query(StaticRule).filter(StaticRule.enabled == True).all()

        if not rules:
            # Seed default rules if table is empty
            cls.seed_default_rules(db_session)
            rules = db_session.query(StaticRule).filter(StaticRule.enabled == True).all()

        return cls(rules=rules)

    @classmethod
    def seed_default_rules(cls, db_session):
        """Seed database with default rules"""
        from app.models.scanner_models import StaticRule

        existing = db_session.query(StaticRule).count()
        if existing > 0:
            return  # Already seeded

        for rule_data in cls.DEFAULT_RULES:
            rule = StaticRule(
                name=rule_data['name'],
                pattern=rule_data['pattern'],
                languages=rule_data['languages'],
                cwe_id=rule_data.get('cwe_id'),
                vulnerability_type=rule_data['vulnerability_type'],
                severity=rule_data['severity'],
                description=rule_data.get('description', ''),
                is_definite=True,
                enabled=True,
                built_in=True,
            )
            db_session.add(rule)

        db_session.commit()
        print(f"Seeded {len(cls.DEFAULT_RULES)} default static rules")

    def scan_fast(self, chunk, language: str, content: str = None) -> Tuple[List[dict], bool]:
        """
        Fast static scan using database rules.
        Returns (findings, needs_llm)
        """
        if content is None:
            content = self._get_content(chunk)

        findings = []
        matched_rule_ids = []

        # Normalize language
        lang_map = {'h': 'c', 'hpp': 'cpp'}
        language = lang_map.get(language, language)

        # Get rules for this language
        rules = self._rules_by_language.get(language, [])

        # Check each rule
        for rule in rules:
            compiled = rule.get('compiled')
            if not compiled:
                continue

            for match in compiled.finditer(content):
                line_num = content[:match.start()].count('\n') + 1

                # Adjust line number for chunk offset
                if hasattr(chunk, 'start_line'):
                    line_num += chunk.start_line - 1

                findings.append({
                    'title': f"{rule['name']}",
                    'vulnerability_type': rule.get('cwe_id') or rule['vulnerability_type'],
                    'severity': rule['severity'],
                    'line_number': line_num,
                    'snippet': self._extract_snippet(content, match),
                    'reason': rule.get('description', f"Static pattern match: {rule['name']}"),
                    'auto_detected': True,
                    'rule_id': rule.get('id'),
                    '_models': ['static'],  # Track as static detection for metrics
                    '_votes': 1,
                })

                if rule.get('id'):
                    matched_rule_ids.append(rule['id'])

        # Check if LLM analysis is needed
        needs_llm = self._has_interesting_patterns(content, language)

        return findings, needs_llm

    def get_matched_rule_ids(self) -> List[int]:
        """Return IDs of rules that matched (for incrementing match_count)"""
        return getattr(self, '_matched_rule_ids', [])

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

        # Check for dangerous keywords
        keywords = self.DANGEROUS_KEYWORDS.get(language, [])
        return any(kw in content_lower for kw in keywords)

    def _is_mostly_data(self, content: str) -> bool:
        """Check if content is mostly data (arrays, strings, etc.)"""
        # Count code-like tokens vs data
        code_tokens = len(re.findall(r'\b(if|for|while|def|class|function|return|switch|case)\b', content))
        data_tokens = len(re.findall(r'["\'][^"\']{20,}["\']', content))

        # If many long strings and few control structures, likely data
        if data_tokens > 5 and code_tokens < 2:
            return True

        return False
