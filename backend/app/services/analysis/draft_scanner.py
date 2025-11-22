from typing import List, Dict
import os
import asyncio

from app.models.scanner_models import ScanFileChunk, ScanFile
from app.services.analysis.static_detector import StaticPatternDetector
from app.services.analysis.parsers import DraftParser
from app.services.orchestration.cache import AnalysisCache
from app.services.orchestration.model_orchestrator import ModelPool
from app.core.database import SessionLocal


class DraftScanner:
    """Scans chunks for draft findings with multi-model voting support"""

    SCAN_PROMPT = """Scan this code for security vulnerabilities. Be thorough - flag anything suspicious.

CRITICAL PATTERNS TO CHECK:

**Memory Safety (C/C++):**
- Buffer overflow: strcpy, sprintf, gets without bounds
- Use-after-free: pointer used after free/delete without nulling
- Double-free: same pointer freed twice
- Uninitialized memory: structs/buffers sent without full initialization
- Integer overflow: size calculations that can wrap (a + b, a * b)

**Injection:**
- Command injection: system(), popen(), exec() with user data
- SQL injection: string concatenation in queries
- Format string: printf/sprintf with user-controlled format

**Authentication/Crypto:**
- Hardcoded credentials: passwords, API keys, tokens in source
- Timing attacks: early return or byte-by-byte comparison in auth
- Weak crypto: MD5, SHA1, DES, hardcoded IVs/keys

**Race Conditions:**
- TOCTOU: check then use (access() then open())
- Shared state without locks
- Dangling pointers after free in class members

**Other:**
- Path traversal: file operations with user paths
- Information disclosure: detailed errors, uninitialized data in responses
- Off-by-one: loop bounds, null terminator handling

{code}

Format each finding as:
*DRAFT: short title
*TYPE: vulnerability type
*SEVERITY: Critical/High/Medium/Low
*LINE: line number
*SNIPPET: the suspicious code
*REASON: one sentence why it's suspicious
*END_DRAFT

Multiple findings are OK. If nothing suspicious, respond with *DRAFT:NONE"""

    def __init__(self, scan_id: int, model_pools: List[ModelPool], cache: AnalysisCache):
        """
        Initialize scanner with multiple model pools for voting.

        Args:
            scan_id: The scan ID
            model_pools: List of model pools to use for voting (minimum 1)
            cache: Analysis cache for deduplication
        """
        self.scan_id = scan_id
        self.model_pools = model_pools if isinstance(model_pools, list) else [model_pools]
        self.cache = cache
        self.static_detector = StaticPatternDetector()
        self.parser = DraftParser()

    async def scan_batch(self, chunks: List[ScanFileChunk]) -> Dict[int, List[dict]]:
        """
        Scan multiple chunks using multi-model voting.
        Returns dict mapping chunk_id to list of findings.
        """
        results = {}
        to_llm = []
        to_llm_meta = []

        for chunk in chunks:
            content = self._get_chunk_content(chunk)
            content_hash = AnalysisCache.hash_content(content)

            # Check cache first
            cached = self.cache.get_analysis(content_hash)
            if cached is not None:
                results[chunk.id] = cached
                continue

            # Get language for static detection
            language = self._get_language(chunk)

            # Run static detection
            static_findings, needs_llm = self.static_detector.scan_fast(chunk, language)

            if not needs_llm:
                # No interesting patterns - just return static findings
                results[chunk.id] = static_findings
                self.cache.set_analysis(content_hash, static_findings)
                continue

            # Queue for LLM analysis
            prompt = self.SCAN_PROMPT.format(code=content[:8000])
            to_llm.append(prompt)
            to_llm_meta.append((chunk.id, content_hash, static_findings))

        # Multi-model batch LLM calls
        if to_llm:
            try:
                # Send to all models in parallel
                async def get_model_responses(pool: ModelPool):
                    try:
                        responses = await pool.call_batch(to_llm)
                        return (pool.config.name, responses)
                    except Exception as e:
                        print(f"Model {pool.config.name} failed: {e}")
                        return (pool.config.name, ["" for _ in to_llm])

                model_tasks = [get_model_responses(pool) for pool in self.model_pools]
                all_model_results = await asyncio.gather(*model_tasks)

                # Process each chunk's responses from all models
                for idx, (chunk_id, content_hash, static_findings) in enumerate(to_llm_meta):
                    # Collect findings from each model
                    model_findings = []
                    for model_name, responses in all_model_results:
                        response = responses[idx] if idx < len(responses) else ""
                        findings = self.parser.parse(response)
                        if findings is None:
                            findings = await self._try_correction(response)
                        if findings:
                            for f in findings:
                                f['_model'] = model_name
                            model_findings.append((model_name, findings))

                    # Aggregate findings using voting
                    voted_findings = self._aggregate_findings(model_findings)
                    all_findings = static_findings + voted_findings
                    results[chunk_id] = all_findings
                    self.cache.set_analysis(content_hash, all_findings)

            except Exception as e:
                print(f"Multi-model scan failed: {e}")
                # Return static findings for all
                for chunk_id, content_hash, static_findings in to_llm_meta:
                    results[chunk_id] = static_findings
                    self.cache.set_analysis(content_hash, static_findings)

        return results

    def _aggregate_findings(self, model_findings: List[tuple]) -> List[dict]:
        """
        Aggregate findings from multiple models using voting.
        A finding is included if it appears in majority of models (2+ out of 3).
        Similar findings are merged based on line number and type.
        """
        if not model_findings:
            return []

        num_models = len(self.model_pools)

        # If only one model, return its findings directly
        if num_models == 1:
            return model_findings[0][1] if model_findings else []

        # Group findings by signature (line + type)
        finding_votes = {}  # signature -> {finding, votes, models}

        for model_name, findings in model_findings:
            for f in findings:
                # Create signature for matching
                sig = self._finding_signature(f)

                if sig not in finding_votes:
                    finding_votes[sig] = {
                        'finding': f,
                        'votes': 0,
                        'models': [],
                        'severities': []
                    }

                finding_votes[sig]['votes'] += 1
                finding_votes[sig]['models'].append(model_name)
                finding_votes[sig]['severities'].append(f.get('severity', 'Medium'))

        # Filter by vote threshold (at least 1 model must report)
        # Lower threshold to catch more findings - verifiers will filter
        threshold = 0.5  # Any model can report (was num_models / 2)
        voted_findings = []

        for sig, data in finding_votes.items():
            if data['votes'] >= threshold:
                finding = data['finding'].copy()
                # Use most common severity
                finding['severity'] = max(set(data['severities']), key=data['severities'].count)
                # Add voting metadata
                finding['_votes'] = data['votes']
                finding['_models'] = data['models']
                voted_findings.append(finding)

        return voted_findings

    def _finding_signature(self, finding: dict) -> str:
        """Create a signature for matching similar findings across models."""
        line = finding.get('line', finding.get('line_number', 0))
        vuln_type = finding.get('type', finding.get('vulnerability_type', '')).lower()
        # Normalize common type variations
        vuln_type = vuln_type.replace(' ', '_').replace('-', '_')
        return f"{line}:{vuln_type}"

    async def _try_correction(self, response: str) -> List[dict]:
        """Try to correct a malformed response"""
        correction_prompt = f"""The previous response did not follow the required format.
Please reformat any findings to match exactly:

*DRAFT: title
*TYPE: vulnerability type
*SEVERITY: Critical/High/Medium/Low
*LINE: number
*SNIPPET: code
*REASON: explanation
*END_DRAFT

Or *DRAFT:NONE if no findings.

Previous response:
{response[:2000]}"""

        try:
            # Use first model pool for correction
            corrected = await self.model_pools[0].call(correction_prompt)
            return self.parser.parse(corrected) or []
        except Exception:
            return []

    def _get_chunk_content(self, chunk: ScanFileChunk) -> str:
        """Get the actual content of a chunk"""
        db = SessionLocal()
        try:
            scan_file = db.query(ScanFile).filter(
                ScanFile.id == chunk.scan_file_id
            ).first()

            if not scan_file:
                return ""

            with open(scan_file.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            return ''.join(lines[chunk.start_line - 1:chunk.end_line])
        except Exception as e:
            print(f"Error reading chunk content: {e}")
            return ""
        finally:
            db.close()

    def _get_language(self, chunk: ScanFileChunk) -> str:
        """Get the language/extension for a chunk"""
        db = SessionLocal()
        try:
            scan_file = db.query(ScanFile).filter(
                ScanFile.id == chunk.scan_file_id
            ).first()

            if scan_file:
                ext = os.path.splitext(scan_file.file_path)[1]
                return ext.lstrip('.')

            return 'unknown'
        finally:
            db.close()
