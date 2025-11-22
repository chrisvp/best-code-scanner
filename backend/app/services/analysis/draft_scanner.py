from typing import List, Dict
import os

from app.models.scanner_models import ScanFileChunk, ScanFile
from app.services.analysis.static_detector import StaticPatternDetector
from app.services.analysis.parsers import DraftParser
from app.services.orchestration.cache import AnalysisCache
from app.services.orchestration.model_orchestrator import ModelPool
from app.core.database import SessionLocal


class DraftScanner:
    """Scans chunks for draft findings with batching support"""

    SCAN_PROMPT = """Scan this code for potential security vulnerabilities.

Be fast - flag anything suspicious. We'll verify later with more context.
Focus on: injection, buffer overflows, authentication issues, data exposure.

{code}

Format each finding as:
*DRAFT: short title
*TYPE: vulnerability type (e.g., SQL Injection, Buffer Overflow)
*SEVERITY: Critical/High/Medium/Low
*LINE: line number
*SNIPPET: the suspicious code
*REASON: one sentence why it's suspicious
*END_DRAFT

Multiple findings are OK. If nothing suspicious, respond with *DRAFT:NONE"""

    def __init__(self, scan_id: int, model_pool: ModelPool, cache: AnalysisCache):
        self.scan_id = scan_id
        self.model_pool = model_pool
        self.cache = cache
        self.static_detector = StaticPatternDetector()
        self.parser = DraftParser()

    async def scan_batch(self, chunks: List[ScanFileChunk]) -> Dict[int, List[dict]]:
        """
        Scan multiple chunks in one batch.
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

        # Batch LLM call
        if to_llm:
            try:
                responses = await self.model_pool.call_batch(to_llm)

                for (chunk_id, content_hash, static_findings), response in zip(to_llm_meta, responses):
                    llm_findings = self.parser.parse(response)

                    if llm_findings is None:
                        # Parsing failed - try correction
                        llm_findings = await self._try_correction(response)

                    all_findings = static_findings + (llm_findings or [])
                    results[chunk_id] = all_findings
                    self.cache.set_analysis(content_hash, all_findings)

            except Exception as e:
                print(f"LLM batch call failed: {e}")
                # Return static findings for all
                for chunk_id, content_hash, static_findings in to_llm_meta:
                    results[chunk_id] = static_findings
                    self.cache.set_analysis(content_hash, static_findings)

        return results

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
            corrected = await self.model_pool.call(correction_prompt)
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
