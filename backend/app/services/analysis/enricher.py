import re
import os
from typing import List, Optional
from sqlalchemy.orm import Session

from app.models.scanner_models import VerifiedFinding, VulnerabilityCategory, DraftFinding, ScanFileChunk, ScanFile
from app.services.analysis.parsers import EnrichmentParser
from app.services.orchestration.model_orchestrator import ModelPool


class CategoryMatcher:
    """Matches LLM category output to standardized categories"""

    def __init__(self, db: Session):
        self.db = db

    def match_or_create(self, raw_category: str) -> str:
        """Find matching category or create new one. Returns standardized name."""
        if not raw_category:
            return "Unknown"

        # Normalize unicode dashes to regular hyphens for CWE matching
        normalized = raw_category.replace('‑', '-').replace('–', '-').replace('—', '-')

        # Extract CWE ID if present (handles various dash types after normalization)
        cwe_match = re.search(r'CWE-(\d+)', normalized, re.IGNORECASE)
        cwe_id = f"CWE-{cwe_match.group(1)}" if cwe_match else None

        # Try exact CWE match first
        if cwe_id:
            existing = self.db.query(VulnerabilityCategory).filter(
                VulnerabilityCategory.cwe_id == cwe_id
            ).first()
            if existing:
                existing.usage_count += 1
                self.db.commit()
                return existing.name

        # Try fuzzy keyword match
        raw_lower = normalized.lower()
        keywords = self._extract_keywords(raw_lower)

        all_cats = self.db.query(VulnerabilityCategory).all()
        best_match = None
        best_score = 0

        for cat in all_cats:
            if cat.keywords:
                # Count keyword matches, but exclude generic terms like "cwe", "buffer", etc.
                generic_terms = {'cwe', 'buffer', 'code', 'copy', 'size', 'check', 'related', 'also'}
                meaningful_matches = sum(1 for kw in cat.keywords if kw in raw_lower and kw not in generic_terms)
                if meaningful_matches > best_score:
                    best_score = meaningful_matches
                    best_match = cat

        # Require at least 2 meaningful keyword matches to use existing category
        if best_match and best_score >= 2:
            best_match.usage_count += 1
            self.db.commit()
            return best_match.name

        # Create new category
        new_cat = VulnerabilityCategory(
            name=raw_category.strip(),
            cwe_id=cwe_id,
            short_name=self._extract_short_name(raw_category),
            keywords=keywords,
            usage_count=1
        )
        self.db.add(new_cat)
        self.db.commit()
        return new_cat.name

    def _extract_keywords(self, text: str) -> list:
        """Extract searchable keywords from category text"""
        # Remove CWE prefix and common words
        text = re.sub(r'cwe-\d+', '', text)
        words = re.findall(r'\w+', text)
        stopwords = {'a', 'an', 'the', 'of', 'in', 'to', 'and', 'or', 'via', 'through'}
        return [w for w in words if len(w) > 2 and w not in stopwords]

    def _extract_short_name(self, text: str) -> Optional[str]:
        """Extract short name if present (e.g., XSS, SQLi)"""
        # Look for common abbreviations
        abbrevs = re.findall(r'\b[A-Z]{2,6}\b', text)
        if abbrevs:
            return abbrevs[0]
        return None


class FindingEnricher:
    """Generates full detailed reports for verified findings"""

    ENRICH_PROMPT = """Generate a detailed security vulnerability report.

=== VERIFIED FINDING ===
Title: {title}
Type: {vuln_type}
Severity: {severity}
File: {file_name}
Line: {line_number}
Attack Vector: {attack_vector}
Data Flow: {data_flow}
Confidence: {confidence}%

=== VULNERABLE CODE SNIPPET ===
{snippet}

=== PRE-FETCHED CONTEXT (already gathered for you) ===

--- Full File Content ---
{full_file}

--- Other Files in Codebase ---
{file_list}

--- Function Callers ---
{callers}

=== INSTRUCTIONS ===
Using the pre-fetched context above, generate a complete security report.
You have all the code you need - do NOT ask for more context.

*FINDING: detailed vulnerability title
*CATEGORY: CWE category (e.g., CWE-78 OS Command Injection)
*SEVERITY: {severity}
*CVSS: score 0.0-10.0
*IMPACTED_CODE:
(paste the exact vulnerable code lines from the full file content)
*VULNERABILITY_DETAILS:
Detailed explanation including:
- What the vulnerability is
- Why it's dangerous
- Specific attack scenario with data flow from entry point to sink
- Potential impact
*PROOF_OF_CONCEPT:
Example attack or curl command showing exploitation
*REMEDIATION_STEPS:
1. First step
2. Second step
...
*REFERENCES:
- https://cwe.mitre.org/...
- https://owasp.org/...
*END_FINDING"""

    def __init__(self, model_pool: ModelPool, db: Session = None):
        self.model_pool = model_pool
        self.db = db
        self.parser = EnrichmentParser()
        self.category_matcher = CategoryMatcher(db) if db else None

    FIX_PROMPT = """Generate ONLY the corrected code that fixes this security vulnerability.

=== VULNERABILITY ===
{title}

=== VULNERABLE CODE ===
{impacted_code}

=== ISSUE ===
{vulnerability_details}

=== INSTRUCTIONS ===
Provide ONLY the corrected code. No explanations, no markdown formatting, just the fixed code.
The fix should address the security issue while maintaining the original functionality."""

    async def enrich_batch(self, verified_list: List[VerifiedFinding]) -> List[dict]:
        """
        Enrich multiple verified findings in batch.
        Returns list of enriched finding dicts with pre-fetched context.
        """
        prompts = []

        for v in verified_list:
            # Fetch draft and chunk info
            snippet = ""
            vuln_type = ""
            file_name = ""
            line_number = 0
            full_file = "(File content not available)"
            file_list = "(No files)"
            callers = "(No caller info)"

            if self.db:
                draft = self.db.query(DraftFinding).filter(
                    DraftFinding.id == v.draft_id
                ).first()
                if draft:
                    snippet = draft.snippet or ""
                    vuln_type = draft.vulnerability_type or ""
                    line_number = draft.line_number or 0

                    # Get chunk and file info for pre-fetched context
                    chunk = self.db.query(ScanFileChunk).filter(
                        ScanFileChunk.id == draft.chunk_id
                    ).first()

                    if chunk:
                        scan_file = self.db.query(ScanFile).filter(
                            ScanFile.id == chunk.scan_file_id
                        ).first()

                        if scan_file:
                            file_name = os.path.basename(scan_file.file_path)

                            # Pre-fetch full file content
                            full_file = self._get_full_file_content(scan_file, line_number)

                            # Pre-fetch file list
                            file_list = self._get_codebase_files(scan_file.scan_id)

                            # Pre-fetch callers (search for function calls)
                            callers = self._get_function_callers(scan_file.scan_id, file_name, line_number)

            prompt = self.ENRICH_PROMPT.format(
                title=v.title,
                vuln_type=vuln_type,
                severity=v.adjusted_severity or 'High',
                file_name=file_name,
                line_number=line_number,
                attack_vector=v.attack_vector or 'Unknown',
                data_flow=v.data_flow or 'Unknown',
                snippet=snippet,
                confidence=v.confidence or 50,
                full_file=full_file,
                file_list=file_list,
                callers=callers
            )
            prompts.append(prompt)

        # Set logging context
        scan_id = verified_list[0].scan_id if verified_list else None
        self.model_pool.set_log_context(
            scan_id=scan_id,
            phase='enricher',
        )

        # Batch call for enrichment
        try:
            responses = await self.model_pool.call_batch(prompts)
            results = [self.parser.parse(r) for r in responses]

            # Normalize categories if db available
            if self.category_matcher:
                for result in results:
                    raw_cat = result.get('category', '')
                    result['category'] = self.category_matcher.match_or_create(raw_cat)

            # Don't auto-generate fixes - user can request on-demand
            return results
        except Exception as e:
            print(f"Enrichment batch failed: {e}")
            # Return minimal findings
            return [self._minimal_finding(v) for v in verified_list]

    async def _generate_fixes_batch(self, enriched_results: List[dict]) -> List[dict]:
        """
        Generate corrected code for each enriched finding in a dedicated LLM call.
        This focused approach produces higher quality fixes.
        """
        prompts = []

        for result in enriched_results:
            prompt = self.FIX_PROMPT.format(
                title=result.get('finding', 'Security Vulnerability'),
                impacted_code=result.get('impacted_code', ''),
                vulnerability_details=result.get('vulnerability_details', '')
            )
            prompts.append(prompt)

        try:
            responses = await self.model_pool.call_batch(prompts)

            for i, response in enumerate(responses):
                # Clean the response - strip markdown if present
                fixed_code = self._clean_fix_response(response)
                enriched_results[i]['corrected_code'] = fixed_code

        except Exception as e:
            print(f"Fix generation failed: {e}")
            # Leave corrected_code empty on failure

        return enriched_results

    def _clean_fix_response(self, response: str) -> str:
        """Clean the fix response, removing thinking tags and markdown formatting"""
        import re
        if not response:
            return ''

        text = response.strip()

        # Remove thinking tags and their content (multiple formats)
        text = re.sub(r'<thinking>.*?</thinking>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'</thinking>', '', text, flags=re.IGNORECASE)
        text = re.sub(r'<thinking>', '', text, flags=re.IGNORECASE)
        text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'</think>', '', text, flags=re.IGNORECASE)
        text = re.sub(r'<think>', '', text, flags=re.IGNORECASE)

        text = text.strip()

        # Remove markdown code blocks
        if text.startswith('```'):
            first_newline = text.find('\n')
            if first_newline != -1:
                text = text[first_newline + 1:]
            else:
                text = text[3:]

        if text.rstrip().endswith('```'):
            text = text.rstrip()[:-3]

        return text.strip()

    def _minimal_finding(self, verified: VerifiedFinding) -> dict:
        """Create minimal finding when enrichment fails"""
        return {
            'finding': verified.title,
            'category': 'Unknown',
            'severity': verified.adjusted_severity or 'Medium',
            'cvss': '5.0',
            'impacted_code': '',
            'vulnerability_details': verified.attack_vector or '',
            'proof_of_concept': '',
            'corrected_code': '',
            'remediation_steps': 'Review and fix the identified vulnerability.',
            'references': ''
        }

    async def enrich_single(self, verified: VerifiedFinding) -> dict:
        """Enrich a single verified finding"""
        results = await self.enrich_batch([verified])
        return results[0] if results else self._minimal_finding(verified)

    async def generate_fix(self, title: str, impacted_code: str, vulnerability_details: str) -> str:
        """Generate fix on-demand for a single finding"""
        prompt = self.FIX_PROMPT.format(
            title=title,
            impacted_code=impacted_code,
            vulnerability_details=vulnerability_details
        )

        try:
            responses = await self.model_pool.call_batch([prompt])
            if responses and responses[0]:
                return self._clean_fix_response(responses[0])
        except Exception as e:
            print(f"Fix generation failed: {e}")

        return ''

    def _get_full_file_content(self, scan_file: ScanFile, focus_line: int) -> str:
        """Get full file content with line numbers, focusing around the vulnerable line"""
        try:
            with open(scan_file.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            total_lines = len(lines)

            # For smaller files, show everything
            if total_lines <= 200:
                result = []
                for i, line in enumerate(lines):
                    line_num = i + 1
                    # Highlight vulnerable line region
                    marker = ">>>" if abs(line_num - focus_line) <= 3 else "   "
                    result.append(f"{marker} {line_num:4d} | {line.rstrip()}")
                return "\n".join(result)

            # For larger files, show 50 lines before and after focus line
            start = max(0, focus_line - 50)
            end = min(total_lines, focus_line + 50)

            result = [f"(Showing lines {start+1}-{end} of {total_lines} total)"]
            for i in range(start, end):
                line_num = i + 1
                marker = ">>>" if abs(line_num - focus_line) <= 3 else "   "
                result.append(f"{marker} {line_num:4d} | {lines[i].rstrip()}")

            return "\n".join(result)

        except Exception as e:
            return f"(Error reading file: {e})"

    def _get_codebase_files(self, scan_id: int) -> str:
        """Get list of all files in the codebase for context"""
        if not self.db:
            return "(No database connection)"

        all_files = self.db.query(ScanFile).filter(
            ScanFile.scan_id == scan_id
        ).all()

        if not all_files:
            return "(No files found)"

        file_names = [os.path.basename(f.file_path) for f in all_files]

        if len(file_names) <= 20:
            return "\n".join(f"- {name}" for name in file_names)
        else:
            return "\n".join(f"- {name}" for name in file_names[:20]) + f"\n... and {len(file_names) - 20} more files"

    def _get_function_callers(self, scan_id: int, file_name: str, line_number: int) -> str:
        """Search for potential callers of the vulnerable function across the codebase"""
        if not self.db:
            return "(No database connection)"

        # Get all files in scan
        all_files = self.db.query(ScanFile).filter(
            ScanFile.scan_id == scan_id
        ).all()

        callers = []

        # Search each file for references to the target file/function
        for scan_file in all_files:
            # Skip the file itself
            if os.path.basename(scan_file.file_path) == file_name:
                continue

            try:
                with open(scan_file.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                # Look for includes/imports of the target file
                base_name = os.path.splitext(file_name)[0]
                for i, line in enumerate(lines):
                    # Check for include statements or function calls
                    if base_name in line or f'#include' in line and file_name in line:
                        caller_file = os.path.basename(scan_file.file_path)
                        callers.append(f"- {caller_file}:{i+1}: {line.strip()[:80]}")

                        if len(callers) >= 10:
                            break

            except Exception:
                continue

            if len(callers) >= 10:
                break

        if not callers:
            return "(No direct callers found in codebase)"

        return "\n".join(callers)
