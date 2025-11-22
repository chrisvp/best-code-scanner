# Implement Analysis Components

Create static detector, parsers, scanner, verifier, enricher, and chunker.

## Task

Implement all analysis pipeline components.

## Files to Create

### 1. backend/app/services/analysis/__init__.py

### 2. backend/app/services/analysis/static_detector.py

```python
class StaticPatternDetector:
    DEFINITE_VULNS = {
        'c': [
            (r'gets\s*\(', 'Buffer Overflow', 'Critical', 'gets() has no bounds checking'),
            (r'strcpy\s*\([^,]+,\s*argv', 'Buffer Overflow', 'High', 'Unbounded copy from argv'),
            (r'sprintf\s*\([^,]+,\s*[^,]*%s', 'Format String', 'High', 'sprintf with %s'),
            (r'system\s*\(\s*argv', 'Command Injection', 'Critical', 'Direct argv to system()'),
            (r'scanf\s*\(\s*"%s"', 'Buffer Overflow', 'High', 'scanf %s without width'),
        ],
        'python': [
            (r'eval\s*\(\s*request\.', 'Code Injection', 'Critical', 'eval() on request data'),
            (r'exec\s*\(\s*request\.', 'Code Injection', 'Critical', 'exec() on request data'),
            (r'pickle\.loads?\s*\(\s*request\.', 'Deserialization', 'Critical', 'Pickle untrusted'),
            (r'yaml\.load\s*\([^)]*Loader\s*=\s*None', 'Deserialization', 'High', 'yaml.load unsafe'),
            (r'subprocess.*shell\s*=\s*True.*request\.', 'Command Injection', 'Critical', 'Shell with input'),
        ]
    }

    DANGEROUS_PATTERNS = {
        'c': ['system', 'exec', 'popen', 'strcpy', 'strcat', 'sprintf', 'scanf', 'gets',
              'malloc', 'free', 'memcpy', 'recv', 'send'],
        'python': ['eval', 'exec', 'system', 'popen', 'subprocess', 'pickle',
                   'yaml.load', 'execute', 'shell', 'open', 'input', 'os.']
    }

    def scan_fast(self, chunk, language: str) -> Tuple[List[dict], bool]:
        content = chunk.content if hasattr(chunk, 'content') else self._get_content(chunk)
        findings = []

        # Check definite vulnerabilities
        for pattern, vuln_type, severity, reason in self.DEFINITE_VULNS.get(language, []):
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    'title': f'{vuln_type} detected',
                    'vulnerability_type': vuln_type,
                    'severity': severity,
                    'line_number': line_num,
                    'snippet': self._extract_snippet(content, match),
                    'reason': reason
                })

        # Check if needs LLM
        needs_llm = any(p in content.lower() for p in self.DANGEROUS_PATTERNS.get(language, []))

        return findings, needs_llm
```

### 3. backend/app/services/analysis/parsers.py

```python
class DraftParser:
    def parse(self, response: str) -> Optional[List[dict]]:
        response = self._strip_code_blocks(response)

        if any(x in response.lower() for x in ['draft:none', 'no findings']):
            return []

        drafts = []
        sections = response.split('*DRAFT:')

        for section in sections[1:]:
            draft = {}
            # Extract title (before first field)
            title_match = re.search(r'^(.+?)(?=\*[A-Z])', section.strip())
            if title_match:
                draft['title'] = title_match.group(1).strip()

            # Extract fields
            for field in ['TYPE', 'SEVERITY', 'LINE', 'SNIPPET', 'REASON']:
                match = re.search(rf'\*{field}:\s*(.+?)(?=\*[A-Z]|\*END_DRAFT|$)', section, re.DOTALL)
                if match:
                    draft[field.lower()] = match.group(1).strip()

            if draft.get('title'):
                drafts.append(draft)
            else:
                return None  # Parse error

        return drafts


class VerificationParser:
    def parse(self, response: str) -> dict:
        if '*REJECTED:' in response:
            match = re.search(r'\*REJECTED:\s*(.+?)\*REASON:\s*(.+?)\*END_REJECTED', response, re.DOTALL)
            if match:
                return {
                    'verified': False,
                    'title': match.group(1).strip(),
                    'reason': match.group(2).strip()
                }

        if '*VERIFIED:' in response:
            result = {'verified': True}
            patterns = {
                'title': r'\*VERIFIED:\s*(.+?)(?=\*[A-Z])',
                'confidence': r'\*CONFIDENCE:\s*(\d+)',
                'attack_vector': r'\*ATTACK_VECTOR:\s*(.+?)(?=\*[A-Z]|\*END)',
                'data_flow': r'\*DATA_FLOW:\s*(.+?)(?=\*[A-Z]|\*END)',
                'adjusted_severity': r'\*ADJUSTED_SEVERITY:\s*(\w+)'
            }
            for field, pattern in patterns.items():
                match = re.search(pattern, response, re.DOTALL)
                if match:
                    value = match.group(1).strip()
                    result[field] = int(value) if field == 'confidence' else value
            return result

        return {'verified': False, 'reason': 'Parse error'}


class EnrichmentParser:
    FIELDS = ['FINDING', 'CATEGORY', 'SEVERITY', 'CVSS', 'IMPACTED_CODE',
              'VULNERABILITY_DETAILS', 'PROOF_OF_CONCEPT', 'CORRECTED_CODE',
              'REMEDIATION_STEPS', 'REFERENCES']

    def parse(self, response: str) -> dict:
        finding = {}
        for i, field in enumerate(self.FIELDS):
            start_marker = f'*{field}:'
            end_marker = f'*{self.FIELDS[i+1]}:' if i < len(self.FIELDS) - 1 else '*END_FINDING'

            start = response.find(start_marker)
            if start == -1:
                continue

            start += len(start_marker)
            end = response.find(end_marker, start)
            if end == -1:
                end = len(response)

            finding[field.lower()] = response[start:end].strip()

        return finding
```

### 4. backend/app/services/analysis/draft_scanner.py

```python
class DraftScanner:
    SCAN_PROMPT = """Scan this code for potential security vulnerabilities.
Be fast - flag anything suspicious. We'll verify later.

{code}

Format:
*DRAFT: title
*TYPE: vulnerability type
*SEVERITY: Critical/High/Medium/Low
*LINE: line number
*SNIPPET: suspicious code
*REASON: one sentence why
*END_DRAFT

Or *DRAFT:NONE if nothing suspicious."""

    def __init__(self, scan_id: int, model_pool, cache):
        self.scan_id = scan_id
        self.model_pool = model_pool
        self.cache = cache
        self.static_detector = StaticPatternDetector()
        self.parser = DraftParser()

    async def scan_batch(self, chunks: List) -> Dict[int, List[dict]]:
        results = {}
        to_llm = []
        to_llm_meta = []

        for chunk in chunks:
            content = self._get_content(chunk)
            content_hash = AnalysisCache.hash_content(content)

            # Check cache
            cached = self.cache.get_analysis(content_hash)
            if cached is not None:
                results[chunk.id] = cached
                continue

            # Static detection
            lang = self._get_language(chunk)
            static_findings, needs_llm = self.static_detector.scan_fast(chunk, lang)

            if not needs_llm:
                results[chunk.id] = static_findings
                self.cache.set_analysis(content_hash, static_findings)
                continue

            # Queue for LLM
            prompt = self.SCAN_PROMPT.format(code=content[:8000])
            to_llm.append(prompt)
            to_llm_meta.append((chunk.id, content_hash, static_findings))

        # Batch LLM call
        if to_llm:
            responses = await self.model_pool.call_batch(to_llm)
            for (chunk_id, content_hash, static), response in zip(to_llm_meta, responses):
                llm_findings = self.parser.parse(response) or []
                all_findings = static + llm_findings
                results[chunk_id] = all_findings
                self.cache.set_analysis(content_hash, all_findings)

        return results
```

### 5. backend/app/services/analysis/verifier.py

```python
class FindingVerifier:
    VERIFY_PROMPT = """Verify if this is a real vulnerability.

=== DRAFT FINDING ===
{draft}

=== CODE CONTEXT ===
{context}

Investigate:
1. Where does data come from?
2. Is it validated/sanitized?
3. Can attacker exploit this?

Respond with:
*VERIFIED: title
*CONFIDENCE: 0-100
*ATTACK_VECTOR: how to exploit
*DATA_FLOW: source → sink
*ADJUSTED_SEVERITY: Critical/High/Medium/Low (if different)
*END_VERIFIED

Or:
*REJECTED: title
*REASON: why not exploitable
*END_REJECTED"""

    def __init__(self, scan_id: int, model_pool, context_retriever):
        self.scan_id = scan_id
        self.model_pool = model_pool
        self.context_retriever = context_retriever
        self.parser = VerificationParser()

    async def verify_batch(self, drafts: List) -> List[dict]:
        prompts = []
        for draft in drafts:
            context = await self.context_retriever.get_context(draft.chunk)
            draft_text = f"Title: {draft.title}\nType: {draft.vulnerability_type}\nSnippet: {draft.snippet}\nReason: {draft.reason}"
            prompt = self.VERIFY_PROMPT.format(draft=draft_text, context=context)
            prompts.append(prompt)

        responses = await self.model_pool.call_batch(prompts)
        return [self.parser.parse(r) for r in responses]
```

### 6. backend/app/services/analysis/enricher.py

```python
class FindingEnricher:
    ENRICH_PROMPT = """Generate a detailed security report for this verified vulnerability.

Title: {title}
Type: {attack_vector}
Severity: {severity}
Data Flow: {data_flow}

Provide complete analysis:
*FINDING: detailed title
*CATEGORY: CWE category
*SEVERITY: {severity}
*CVSS: score (0-10)
*IMPACTED_CODE: the vulnerable code
*VULNERABILITY_DETAILS: full explanation, attack scenario
*PROOF_OF_CONCEPT: example exploit or curl command
*CORRECTED_CODE: fixed version of the code
*REMEDIATION_STEPS: numbered steps to fix
*REFERENCES: relevant CWE/OWASP links
*END_FINDING"""

    def __init__(self, model_pool):
        self.model_pool = model_pool
        self.parser = EnrichmentParser()

    async def enrich_batch(self, verified_list: List) -> List[dict]:
        prompts = []
        for v in verified_list:
            prompt = self.ENRICH_PROMPT.format(
                title=v.title,
                attack_vector=v.attack_vector,
                severity=v.adjusted_severity or 'High',
                data_flow=v.data_flow or ''
            )
            prompts.append(prompt)

        responses = await self.model_pool.call_batch(prompts)
        return [self.parser.parse(r) for r in responses]
```

### 7. backend/app/services/analysis/file_chunker.py

```python
class FileChunker:
    def __init__(self, max_tokens: int = 3000):
        self.max_tokens = max_tokens
        self.parser = ASTParser()

    def chunk_file(self, file_path: str, content: str = None) -> List[dict]:
        if content is None:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

        # Small file
        if self._count_tokens(content) <= self.max_tokens:
            return [{
                'chunk_index': 0,
                'chunk_type': 'full_file',
                'start_line': 1,
                'end_line': content.count('\n') + 1,
                'content_hash': hashlib.md5(content.encode()).hexdigest()
            }]

        # Try semantic chunking
        try:
            parsed = self.parser.parse_file(file_path, content)
            return self._chunk_by_symbols(parsed, content)
        except:
            return self._simple_chunk(content)

    def _chunk_by_symbols(self, parsed, content):
        chunks = []
        preamble = self._extract_preamble(parsed, content)

        for i, func in enumerate(parsed.extract_functions()):
            func_content = content.split('\n')[func.start_line-1:func.end_line]
            chunk_content = preamble + '\n\n' + '\n'.join(func_content)

            chunks.append({
                'chunk_index': i,
                'chunk_type': 'function',
                'symbol_name': func.name,
                'start_line': func.start_line,
                'end_line': func.end_line,
                'content_hash': hashlib.md5(chunk_content.encode()).hexdigest()
            })

        return chunks if chunks else self._simple_chunk(content)

    def _count_tokens(self, text: str) -> int:
        return len(text) // 4  # Rough estimate
```
