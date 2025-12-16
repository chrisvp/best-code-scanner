import re
import os
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.scanner_models import VerifiedFinding, VulnerabilityCategory, DraftFinding, ScanFileChunk, ScanFile, GlobalSetting, ModelConfig
from app.services.analysis.parsers import EnrichmentParser
from app.services.orchestration.model_orchestrator import ModelPool
from app.services.analysis.output_formats import get_output_format
import json

# Required fields for a complete enrichment - all findings should have these filled
REQUIRED_ENRICHMENT_FIELDS = [
    'finding',
    'category',
    'severity',
    'vulnerability_details',
    'proof_of_concept',
    'remediation_steps',
]

# Fields that are good to have but not strictly required
OPTIONAL_ENRICHMENT_FIELDS = [
    'cvss',
    'impacted_code',
    'corrected_code',
    'references',
]

# JSON schema for guided enrichment output
ENRICHMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "finding": {
            "type": "string",
            "description": "Detailed vulnerability title"
        },
        "category": {
            "type": "string",
            "description": "CWE category (e.g., CWE-78 OS Command Injection)"
        },
        "severity": {
            "type": "string",
            "enum": ["Critical", "High", "Medium", "Low"],
            "description": "Severity level"
        },
        "cvss": {
            "type": "string",
            "description": "CVSS score (0.0-10.0)"
        },
        "impacted_code": {
            "type": "string",
            "description": "The exact vulnerable code lines from the full file content"
        },
        "vulnerability_details": {
            "type": "string",
            "description": "Detailed explanation including what it is, why dangerous, attack scenario with data flow, and potential impact"
        },
        "proof_of_concept": {
            "type": "string",
            "description": "Example attack or curl command showing exploitation"
        },
        "corrected_code": {
            "type": "string",
            "description": "Fixed version of the vulnerable code"
        },
        "remediation_steps": {
            "type": "string",
            "description": "Step-by-step instructions on how to fix"
        },
        "references": {
            "type": "string",
            "description": "Relevant links or documentation (CWE, OWASP, etc.)"
        }
    },
    "required": ["finding", "category", "severity", "vulnerability_details", "proof_of_concept", "remediation_steps"],
    "additionalProperties": False
}


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

{output_format}"""

    def __init__(self, model_pool: ModelPool, db: Session = None, output_mode: str = "guided_json", json_schema: str = None):
        self.model_pool = model_pool
        self.db = db
        self.parser = EnrichmentParser()
        self.category_matcher = CategoryMatcher(db) if db else None
        self.output_mode = output_mode or "guided_json"  # Default to guided_json for backwards compat
        self.json_schema = json_schema or json.dumps(ENRICHMENT_SCHEMA)  # Use default schema if not provided

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

                    # Get file_path from draft directly (Joern findings) or from chunk's ScanFile
                    file_path_full = draft.file_path if draft.file_path else None

                    # Get chunk and file info for pre-fetched context
                    chunk = self.db.query(ScanFileChunk).filter(
                        ScanFileChunk.id == draft.chunk_id
                    ).first()

                    scan_file = None
                    if chunk:
                        scan_file = self.db.query(ScanFile).filter(
                            ScanFile.id == chunk.scan_file_id
                        ).first()

                        if scan_file:
                            if not file_path_full:
                                file_path_full = scan_file.file_path
                            file_name = os.path.basename(scan_file.file_path)

                            # Pre-fetch full file content
                            full_file = self._get_full_file_content(scan_file, line_number)

                            # Pre-fetch file list
                            file_list = self._get_codebase_files(scan_file.scan_id)

                            # Pre-fetch callers (search for function calls)
                            callers = self._get_function_callers(scan_file.scan_id, file_name, line_number)

                    # Fallback: if we have draft.file_path but no chunk/scan_file (Joern finding)
                    if not scan_file and file_path_full and os.path.exists(file_path_full):
                        file_name = os.path.basename(file_path_full)
                        # Read file directly for Joern findings without chunks
                        full_file = self._get_full_file_content_by_path(file_path_full, line_number)

            # Inject output format instructions based on output_mode
            output_format = get_output_format("enricher", self.output_mode)

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
                callers=callers,
                output_format=output_format
            )
            prompts.append(prompt)

        # Set logging context
        scan_id = verified_list[0].scan_id if verified_list else None
        self.model_pool.set_log_context(
            scan_id=scan_id,
            phase='enricher',
        )

        # Batch call for enrichment with validation, retry, and cleanup fallback
        # Use configured output mode (defaults to guided_json for structured output)
        try:
            responses = await self.model_pool.call_batch(
                prompts,
                output_mode=self.output_mode,
                json_schema=self.json_schema if self.output_mode == "guided_json" else None
            )
            # Parse JSON responses instead of marker format
            results = []
            for r in responses:
                try:
                    parsed = json.loads(r) if r.strip() else {}
                    results.append(parsed)
                except json.JSONDecodeError:
                    # Fallback to marker parser if JSON fails
                    results.append(self.parser.parse(r))

            # Check for incomplete results and collect indices for retry
            incomplete_indices = []
            for i, (result, verified, prompt) in enumerate(zip(results, verified_list, prompts)):
                missing = self._get_missing_fields(result)
                if missing:
                    print(f"[Enricher] Finding '{verified.title}' missing fields: {missing}")
                    incomplete_indices.append((i, verified, prompt, result))

            # Retry incomplete results once with enhanced prompt
            if incomplete_indices:
                print(f"[Enricher] Retrying {len(incomplete_indices)} incomplete enrichments...")
                retry_prompts = []
                for i, verified, original_prompt, partial_result in incomplete_indices:
                    missing = self._get_missing_fields(partial_result)
                    retry_prompt = self._build_retry_prompt(original_prompt, partial_result, missing)
                    retry_prompts.append(retry_prompt)

                try:
                    retry_responses = await self.model_pool.call_batch(
                        retry_prompts,
                        output_mode=self.output_mode,
                        json_schema=self.json_schema if self.output_mode == "guided_json" else None
                    )
                    for (i, verified, _, partial_result), retry_response in zip(incomplete_indices, retry_responses):
                        try:
                            retry_result = json.loads(retry_response) if retry_response.strip() else {}
                        except json.JSONDecodeError:
                            retry_result = self.parser.parse(retry_response)
                        # Merge retry result with original (retry takes precedence for filled fields)
                        merged = self._merge_results(partial_result, retry_result)
                        results[i] = merged

                        # Check if still incomplete after retry
                        still_missing = self._get_missing_fields(merged)
                        if still_missing:
                            print(f"[Enricher] Finding '{verified.title}' still missing after retry: {still_missing}")
                except Exception as e:
                    print(f"[Enricher] Retry batch failed: {e}")

            # Try cleanup model for any still-incomplete results
            still_incomplete = []
            for i, (result, verified) in enumerate(zip(results, verified_list)):
                missing = self._get_missing_fields(result)
                if missing:
                    still_incomplete.append((i, verified, result))

            if still_incomplete and self.db:
                print(f"[Enricher] Attempting cleanup model for {len(still_incomplete)} incomplete results...")
                for i, verified, partial_result in still_incomplete:
                    cleaned = await self._try_cleanup_model(partial_result, verified)
                    if cleaned:
                        results[i] = cleaned

            # Normalize categories if db available
            if self.category_matcher:
                for result in results:
                    raw_cat = result.get('category', '')
                    result['category'] = self.category_matcher.match_or_create(raw_cat)

            return results
        except Exception as e:
            print(f"Enrichment batch failed: {e}")
            # Return minimal findings
            return [self._minimal_finding(v) for v in verified_list]

    def _get_missing_fields(self, result: dict) -> List[str]:
        """Check which required fields are missing or empty"""
        missing = []
        for field in REQUIRED_ENRICHMENT_FIELDS:
            value = result.get(field, '')
            if not value or (isinstance(value, str) and not value.strip()):
                missing.append(field)
        return missing

    def _build_retry_prompt(self, original_prompt: str, partial_result: dict, missing_fields: List[str]) -> str:
        """Build a retry prompt that emphasizes the missing fields"""
        existing_content = []
        for field in ['finding', 'category', 'severity', 'cvss', 'impacted_code',
                      'vulnerability_details', 'proof_of_concept', 'remediation_steps', 'references']:
            value = partial_result.get(field, '')
            if value and isinstance(value, str) and value.strip():
                existing_content.append(f"*{field.upper()}: {value}")

        existing_text = "\n".join(existing_content) if existing_content else "(No content extracted)"

        return f"""{original_prompt}

=== IMPORTANT: RETRY REQUEST ===
Your previous response was incomplete. The following sections were missing or empty:
{', '.join(f.upper() for f in missing_fields)}

Previously extracted content:
{existing_text}

Please provide a COMPLETE response with ALL sections filled out, especially:
{', '.join(f'*{f.upper()}' for f in missing_fields)}

Remember: Every finding MUST have proof_of_concept, remediation_steps, and references filled out."""

    def _merge_results(self, original: dict, retry: dict) -> dict:
        """Merge retry results with original, preferring non-empty values"""
        merged = dict(original)
        for key, value in retry.items():
            if value and isinstance(value, str) and value.strip():
                # Only overwrite if original was empty or retry is non-empty
                if not merged.get(key) or (isinstance(merged.get(key), str) and not merged[key].strip()):
                    merged[key] = value
        return merged

    async def _try_cleanup_model(self, partial_result: dict, verified: VerifiedFinding) -> Optional[dict]:
        """Try to use the cleanup model to fill in missing sections"""
        try:
            # Get cleanup model from global settings
            cleanup_model_setting = self.db.query(GlobalSetting).filter(
                GlobalSetting.key == "cleanup_model_id"
            ).first()

            if not cleanup_model_setting or not cleanup_model_setting.value:
                return None

            cleanup_model = self.db.query(ModelConfig).filter(
                ModelConfig.id == int(cleanup_model_setting.value)
            ).first()
            if not cleanup_model:
                return None

            # Build context from what we have
            existing_content = []
            for field in ['finding', 'category', 'severity', 'cvss', 'impacted_code',
                          'vulnerability_details', 'proof_of_concept', 'remediation_steps', 'references']:
                value = partial_result.get(field, '')
                if value and isinstance(value, str) and value.strip():
                    existing_content.append(f"*{field.upper()}: {value}")

            missing = self._get_missing_fields(partial_result)

            cleanup_prompt = f"""Complete this security vulnerability report. Some sections are missing.

=== EXISTING CONTENT ===
{chr(10).join(existing_content)}

=== MISSING SECTIONS (you MUST fill these in) ===
{', '.join(f'*{f.upper()}' for f in missing)}

=== CONTEXT ===
Title: {verified.title}
Type: {verified.confidence}% confidence
Attack Vector: {verified.attack_vector or 'Unknown'}

=== INSTRUCTIONS ===
Generate ONLY the missing sections in the marker format. For example:
*PROOF_OF_CONCEPT:
[actual exploit example or curl command]
*REMEDIATION_STEPS:
1. [step one]
2. [step two]
*REFERENCES:
- https://cwe.mitre.org/...

Be specific and practical. Do not leave any section empty."""

            from app.services.llm_provider import llm_provider

            result = await llm_provider.chat_completion(
                messages=[{"role": "user", "content": cleanup_prompt}],
                model=cleanup_model.name
            )
            response = result.get("content", "")

            if response:
                cleanup_result = self.parser.parse(response)
                # Merge with original
                merged = self._merge_results(partial_result, cleanup_result)
                return merged

        except Exception as e:
            print(f"[Enricher] Cleanup model failed: {e}")

        return None

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

    def _get_full_file_content_by_path(self, file_path: str, focus_line: int) -> str:
        """Get full file content by path (for Joern findings without ScanFile)"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            total_lines = len(lines)

            # For smaller files, show everything
            if total_lines <= 200:
                result = []
                for i, line in enumerate(lines):
                    line_num = i + 1
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
