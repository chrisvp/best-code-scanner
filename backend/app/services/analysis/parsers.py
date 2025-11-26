"""
Fuzzy parsers for LLM responses using marker format.

These parsers are designed to be robust and recover from common LLM mistakes:
- Missing *END_DRAFT markers
- Missing asterisks (DRAFT: instead of *DRAFT:)
- Field name variations (TYPE vs VULN_TYPE vs VULNERABILITY_TYPE)
- Extra whitespace and formatting
- Different casing
"""

import re
import json
from typing import List, Optional, Dict


class DraftParser:
    """Parse lightweight draft findings from LLM response with fuzzy matching"""

    # Field name variations to handle different LLM outputs
    FIELD_ALIASES = {
        'type': ['type', 'vuln_type', 'vulnerability_type', 'cwe', 'category'],
        'severity': ['severity', 'sev', 'risk', 'risk_level'],
        'line': ['line', 'line_number', 'line_num', 'lineno'],
        'snippet': ['snippet', 'code', 'code_snippet', 'vulnerable_code'],
        'reason': ['reason', 'description', 'explanation', 'details', 'why'],
    }

    def parse(self, response: str) -> Optional[List[dict]]:
        """
        Parse draft findings from response.
        Supports marker format with fuzzy matching.
        Returns None if parsing fails completely (triggers correction).
        """
        if not response:
            return []

        # First, strip thinking tags
        response = self._strip_thinking_tags(response)
        response = self._strip_code_blocks(response)

        # Handle no findings
        no_finding_indicators = [
            'draft:none', '*draft:none', 'no findings', 'no vulnerabilities',
            'no issues', 'no security issues', 'nothing suspicious',
            'no potential vulnerabilities', 'code appears safe',
            '[]'  # Empty JSON array
        ]
        clean_response = response.strip().lower()
        if clean_response == '[]' or any(ind in clean_response for ind in no_finding_indicators):
            return []

        # Try marker format parsing (primary method)
        drafts = self._parse_marker_format(response)
        if drafts:
            return drafts

        # Try JSON parsing as fallback
        json_results = self._try_json_parse(response)
        if json_results is not None:
            return json_results

        # Last resort: try to extract any structured data
        return self._try_extract_any_findings(response)

    def _parse_marker_format(self, response: str) -> Optional[List[dict]]:
        """Parse marker format with fuzzy matching"""
        drafts = []

        # Find all draft sections - handle both *DRAFT: and DRAFT: (missing asterisk)
        # Also handle variations like **DRAFT: or ## DRAFT:
        draft_pattern = r'(?:^|\n)\s*(?:\*+|#{1,2}\s*\**)?\s*DRAFT\s*:\s*(.+?)(?=(?:\n\s*(?:\*+|#{1,2}\s*\**)?\s*DRAFT\s*:)|$)'
        matches = list(re.finditer(draft_pattern, response, re.IGNORECASE | re.DOTALL))

        if not matches:
            return None

        for match in matches:
            section = match.group(1)
            draft = self._extract_draft_fuzzy(section)
            if draft:
                drafts.append(draft)

        return drafts if drafts else None

    def _extract_draft_fuzzy(self, section: str) -> Optional[dict]:
        """Extract fields from a draft section with fuzzy matching"""
        draft = {}

        # Extract title - everything before the first field marker
        # Handle both *TYPE: and TYPE: patterns
        title_match = re.search(r'^(.+?)(?=\n\s*\*?[A-Z_]+\s*:|\Z)', section.strip(), re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
            # Clean up title (remove leading/trailing punctuation, markdown)
            title = re.sub(r'^[\*#\-]+\s*', '', title)
            title = re.sub(r'\s*[\*#\-]+$', '', title)
            title = title.strip()
            if title and len(title) > 2:
                draft['title'] = title

        if not draft.get('title'):
            return None

        # Extract each field with fuzzy matching
        for canonical_name, aliases in self.FIELD_ALIASES.items():
            value = self._extract_field_fuzzy(section, aliases)
            if value:
                draft[canonical_name] = value

        # Ensure line number is an integer
        if 'line' in draft:
            try:
                # Extract first number from the line field
                line_nums = re.findall(r'\d+', str(draft['line']))
                if line_nums:
                    draft['line'] = int(line_nums[0])
                else:
                    del draft['line']
            except (ValueError, TypeError):
                del draft['line']

        return draft

    def _extract_field_fuzzy(self, text: str, field_aliases: List[str]) -> Optional[str]:
        """Extract a field value using fuzzy matching on field names"""
        text_for_search = text

        for alias in field_aliases:
            # Try various marker patterns
            patterns = [
                rf'\*{alias}\s*:\s*(.+?)(?=\n\s*\*[A-Z_]+\s*:|(?:\n\s*)?(?:\*END|\Z))',  # *FIELD:
                rf'(?:^|\n)\s*{alias}\s*:\s*(.+?)(?=\n\s*[A-Z_]+\s*:|\n\s*\*|\Z)',  # FIELD: (no asterisk)
                rf'\*\*{alias}\s*:\*?\*?\s*(.+?)(?=\n\s*\*|\Z)',  # **FIELD:** markdown
            ]

            for pattern in patterns:
                match = re.search(pattern, text_for_search, re.IGNORECASE | re.DOTALL)
                if match:
                    value = match.group(1).strip()
                    # Clean up the value
                    value = re.sub(r'\*END_DRAFT.*$', '', value, flags=re.IGNORECASE | re.DOTALL)
                    value = re.sub(r'\*END_VERIFIED.*$', '', value, flags=re.IGNORECASE | re.DOTALL)
                    value = re.sub(r'\*END_REJECTED.*$', '', value, flags=re.IGNORECASE | re.DOTALL)
                    value = value.strip()
                    if value:
                        return value

        return None

    def _strip_thinking_tags(self, text: str) -> str:
        """Remove thinking tags and their content.

        Handles multiple formats:
        - <thinking>...</thinking> (Claude, Anthropic models)
        - <think>...</think> (Kimi k1/k1.5, DeepSeek R1)
        """
        # Handle <thinking>...</thinking> tags
        text = re.sub(r'<thinking>.*?</thinking>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'</thinking>', '', text, flags=re.IGNORECASE)
        text = re.sub(r'<thinking>', '', text, flags=re.IGNORECASE)
        # Handle <think>...</think> tags (Kimi, DeepSeek format)
        text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'</think>', '', text, flags=re.IGNORECASE)
        text = re.sub(r'<think>', '', text, flags=re.IGNORECASE)
        return text.strip()

    def _try_json_parse(self, text: str) -> Optional[List[dict]]:
        """Try to parse response as JSON array of findings (fallback)"""
        # Look for JSON array in the response
        try:
            # Try direct parse
            data = json.loads(text)
            if isinstance(data, list):
                return self._normalize_json_findings(data)
        except json.JSONDecodeError:
            pass

        # Try to extract JSON array from response
        return self._try_extract_json_array(text)

    def _try_extract_json_array(self, text: str) -> Optional[List[dict]]:
        """Extract JSON array from text that may contain other content"""
        # Look for ```json ... ``` blocks
        json_block_match = re.search(r'```(?:json)?\s*(\[[\s\S]*?\])\s*```', text)
        if json_block_match:
            try:
                data = json.loads(json_block_match.group(1))
                if isinstance(data, list):
                    return self._normalize_json_findings(data)
            except json.JSONDecodeError:
                pass

        # Look for bare JSON array
        array_match = re.search(r'\[\s*\{[\s\S]*?\}\s*\]', text)
        if array_match:
            try:
                data = json.loads(array_match.group(0))
                if isinstance(data, list):
                    return self._normalize_json_findings(data)
            except json.JSONDecodeError:
                pass

        # Look for empty array
        if re.search(r'\[\s*\]', text):
            return []

        return None

    def _normalize_json_findings(self, findings: List[dict]) -> List[dict]:
        """Normalize JSON findings to expected format"""
        normalized = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            # Map various field names to expected format
            normalized_finding = {
                'title': f.get('title', f.get('name', f.get('finding', 'Unknown'))),
                'type': f.get('vulnerability_type', f.get('type', f.get('cwe', f.get('category', 'Unknown')))),
                'severity': f.get('severity', f.get('risk', 'Medium')),
                'line': f.get('line_number', f.get('line', f.get('lineno', 0))),
                'snippet': f.get('snippet', f.get('code', f.get('code_snippet', ''))),
                'reason': f.get('reason', f.get('description', f.get('explanation', '')))
            }
            # Only include if it has a title
            if normalized_finding['title'] and normalized_finding['title'] != 'Unknown':
                normalized.append(normalized_finding)
        return normalized

    def _try_extract_any_findings(self, text: str) -> Optional[List[dict]]:
        """Last resort: try to extract any structured vulnerability info"""
        # Look for patterns like "Buffer Overflow at line 42" or "SQL Injection in line 15"
        findings = []

        # Pattern: Title-like text followed by line number
        pattern = r'([A-Z][A-Za-z\s\-]+(?:Overflow|Injection|XSS|SSRF|Traversal|Vulnerability|Issue|Bug))[^\d]*(?:line|at|on)?\s*[:\s]*(\d+)'
        matches = re.finditer(pattern, text, re.IGNORECASE)

        for match in matches:
            title = match.group(1).strip()
            line = int(match.group(2))
            if title and line > 0:
                findings.append({
                    'title': title,
                    'line': line,
                    'type': 'Unknown',
                    'severity': 'Medium',
                    'snippet': '',
                    'reason': 'Extracted from unstructured response'
                })

        return findings if findings else None

    def _strip_code_blocks(self, text: str) -> str:
        """Remove markdown code blocks wrapper"""
        text = text.strip()
        # Only strip outer code blocks, not inner ones
        if text.startswith('```') and text.count('```') == 2:
            lines = text.split('\n')
            if lines[0].startswith('```') and lines[-1].strip() == '```':
                # Remove first and last lines
                text = '\n'.join(lines[1:-1])
        return text


class VerificationParser:
    """Parse verification results from LLM response with fuzzy matching"""

    def parse(self, response: str) -> dict:
        """Parse verification response into result dict"""
        response = self._strip_thinking_tags(response)
        response = self._strip_code_blocks(response)

        # Check for rejection - handle both *REJECTED and REJECTED
        if re.search(r'\*?REJECTED\s*:', response, re.IGNORECASE):
            return self._parse_rejection(response)

        # Check for verification - handle both *VERIFIED and VERIFIED
        if re.search(r'\*?VERIFIED\s*:', response, re.IGNORECASE):
            return self._parse_verification(response)

        # Check for VOTE format (from verifier.py)
        if re.search(r'\*?VOTE\s*:', response, re.IGNORECASE):
            return self._parse_vote_format(response)

        # Default to not verified
        return {'verified': False, 'reason': 'Unable to parse response'}

    def _parse_rejection(self, response: str) -> dict:
        """Parse a rejection response"""
        result = {'verified': False}

        # Extract title after REJECTED:
        title_match = re.search(r'\*?REJECTED\s*:\s*(.+?)(?=\n|\*REASON|$)', response, re.IGNORECASE | re.DOTALL)
        if title_match:
            result['title'] = title_match.group(1).strip()

        # Extract reason
        reason_match = re.search(r'\*?REASON\s*:\s*(.+?)(?=\*END|$)', response, re.IGNORECASE | re.DOTALL)
        if reason_match:
            result['reason'] = reason_match.group(1).strip()
        else:
            result['reason'] = 'Rejected (no reason provided)'

        return result

    def _parse_verification(self, response: str) -> dict:
        """Parse a verification response"""
        result = {'verified': True}

        # Field patterns with fuzzy matching
        fields = {
            'title': r'\*?VERIFIED\s*:\s*(.+?)(?=\n\s*\*?[A-Z_]+\s*:|\*END|$)',
            'confidence': r'\*?CONFIDENCE\s*:\s*(\d+)',
            'attack_vector': r'\*?ATTACK_VECTOR\s*:\s*(.+?)(?=\n\s*\*?[A-Z_]+\s*:|\*END|$)',
            'data_flow': r'\*?DATA_FLOW\s*:\s*(.+?)(?=\n\s*\*?[A-Z_]+\s*:|\*END|$)',
            'adjusted_severity': r'\*?ADJUSTED_SEVERITY\s*:\s*(\w+)',
        }

        for field, pattern in fields.items():
            match = re.search(pattern, response, re.IGNORECASE | re.DOTALL)
            if match:
                value = match.group(1).strip()
                if field == 'confidence':
                    try:
                        value = int(value)
                    except ValueError:
                        value = 50
                result[field] = value

        return result

    def _parse_vote_format(self, response: str) -> dict:
        """Parse VOTE format from verifier"""
        result = {'verified': False}

        # Extract vote decision
        vote_match = re.search(r'\*?VOTE\s*:\s*(\w+)', response, re.IGNORECASE)
        if vote_match:
            decision = vote_match.group(1).upper()
            if decision == 'VERIFY':
                result['verified'] = True
            elif decision == 'WEAKNESS':
                result['verified'] = True
                result['is_weakness'] = True

        # Extract confidence
        conf_match = re.search(r'\*?CONFIDENCE\s*:\s*(\d+)', response, re.IGNORECASE)
        if conf_match:
            result['confidence'] = int(conf_match.group(1))

        # Extract reasoning
        reason_match = re.search(r'\*?REASONING\s*:\s*(.+?)(?=\*END|\*[A-Z_]+:|$)', response, re.IGNORECASE | re.DOTALL)
        if reason_match:
            result['reason'] = reason_match.group(1).strip()

        return result

    def _strip_thinking_tags(self, text: str) -> str:
        """Remove thinking tags from reasoning models"""
        text = re.sub(r'<thinking>.*?</thinking>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'</thinking>', '', text, flags=re.IGNORECASE)
        text = re.sub(r'<thinking>', '', text, flags=re.IGNORECASE)
        text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'</think>', '', text, flags=re.IGNORECASE)
        text = re.sub(r'<think>', '', text, flags=re.IGNORECASE)
        return text.strip()

    def _strip_code_blocks(self, text: str) -> str:
        text = text.strip()
        if text.startswith('```') and text.count('```') == 2:
            lines = text.split('\n')
            if lines[0].startswith('```') and lines[-1].strip() == '```':
                text = '\n'.join(lines[1:-1])
        return text


class EnrichmentParser:
    """Parse full enriched findings from LLM response using fuzzy split-based parsing"""

    FIELDS = [
        'FINDING', 'CATEGORY', 'SEVERITY', 'CVSS', 'IMPACTED_CODE',
        'VULNERABILITY_DETAILS', 'PROOF_OF_CONCEPT', 'CORRECTED_CODE',
        'REMEDIATION_STEPS', 'REFERENCES'
    ]

    # Aliases for field names
    FIELD_ALIASES = {
        'FINDING': ['FINDING', 'TITLE', 'VULNERABILITY', 'NAME'],
        'CATEGORY': ['CATEGORY', 'TYPE', 'CWE', 'VULN_TYPE'],
        'SEVERITY': ['SEVERITY', 'RISK', 'RISK_LEVEL'],
        'CVSS': ['CVSS', 'CVSS_SCORE', 'SCORE'],
        'IMPACTED_CODE': ['IMPACTED_CODE', 'VULNERABLE_CODE', 'CODE', 'AFFECTED_CODE'],
        'VULNERABILITY_DETAILS': ['VULNERABILITY_DETAILS', 'DETAILS', 'DESCRIPTION', 'EXPLANATION'],
        'PROOF_OF_CONCEPT': ['PROOF_OF_CONCEPT', 'POC', 'EXPLOIT', 'ATTACK'],
        'CORRECTED_CODE': ['CORRECTED_CODE', 'FIXED_CODE', 'FIX', 'REMEDIATED_CODE'],
        'REMEDIATION_STEPS': ['REMEDIATION_STEPS', 'REMEDIATION', 'FIX_STEPS', 'MITIGATION'],
        'REFERENCES': ['REFERENCES', 'REFS', 'LINKS', 'RESOURCES'],
    }

    def parse(self, response: str) -> dict:
        """Parse enriched finding from response using split-based fuzzy parsing"""
        response = self._normalize_response(response)
        finding = {}

        for field in self.FIELDS:
            value = self._extract_field(response, field)
            if value:
                finding[field.lower()] = value

        return finding

    def _extract_field(self, text: str, field: str) -> Optional[str]:
        """Extract field value using split-based fuzzy matching"""
        text_lower = text.lower()

        # Get all aliases for this field
        aliases = self.FIELD_ALIASES.get(field, [field])

        # Find the best matching marker position
        best_pos = -1
        best_marker_len = 0

        for alias in aliases:
            alias_lower = alias.lower()
            # Try different possible markers
            for marker in [
                f'\n{alias_lower}:',
                f'\n*{alias_lower}:',
                f'\n**{alias_lower}:',
                f'\n## {alias_lower}:',
                f'\n## **{alias_lower}:',
                f'\n[]{alias_lower}:',
                f'{alias_lower}:',  # At start of text
            ]:
                pos = text_lower.find(marker)
                if pos != -1 and (best_pos == -1 or pos < best_pos):
                    best_pos = pos
                    best_marker_len = len(marker)

        if best_pos == -1:
            return None

        # Extract content after the marker
        start = best_pos + best_marker_len
        content = text[start:]

        # Find where the next field starts
        end_pos = len(content)

        # Check for all possible next field markers
        all_field_names = []
        for aliases in self.FIELD_ALIASES.values():
            all_field_names.extend(aliases)
        all_field_names.append('END_FINDING')

        for next_field in all_field_names:
            if next_field.upper() == field:
                continue
            for marker in [
                f'\n{next_field.lower()}:',
                f'\n*{next_field.lower()}:',
                f'\n**{next_field.lower()}:',
                f'\n## {next_field.lower()}:',
                f'\n## **{next_field.lower()}:',
                f'\n[]{next_field.lower()}:',
            ]:
                pos = content.lower().find(marker)
                if pos != -1 and pos < end_pos:
                    end_pos = pos

        value = content[:end_pos].strip()
        return self._clean_value(value) if value else None

    def _normalize_response(self, text: str) -> str:
        """Normalize the response text, removing LLM artifacts"""
        text = text.strip()

        # Remove thinking tags and their content (multiple formats)
        text = re.sub(r'<thinking>.*?</thinking>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'</thinking>', '', text, flags=re.IGNORECASE)
        text = re.sub(r'<thinking>', '', text, flags=re.IGNORECASE)
        # Handle <think> tags (Kimi, DeepSeek format)
        text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'</think>', '', text, flags=re.IGNORECASE)
        text = re.sub(r'<think>', '', text, flags=re.IGNORECASE)

        # Remove outer code blocks
        if text.startswith('```') and '```' in text[3:]:
            first_newline = text.find('\n')
            last_fence = text.rfind('```')
            if first_newline != -1 and last_fence > first_newline:
                text = text[first_newline + 1:last_fence]

        return text.strip()

    def _clean_value(self, value: str) -> str:
        """Clean extracted value of markdown artifacts"""
        # Strip code block markers
        value = self._strip_code_blocks(value)

        # Remove leading markdown formatting but preserve content
        lines = value.split('\n')
        cleaned_lines = []
        for line in lines:
            # Strip leading *, #, spaces but preserve the rest
            stripped = line.lstrip('*# \t')
            # Don't strip trailing * as it might be markdown emphasis
            cleaned_lines.append(stripped)
        value = '\n'.join(cleaned_lines)
        return value.strip()

    def _strip_code_blocks(self, text: str) -> str:
        """Remove markdown code block markers"""
        text = text.strip()
        # Remove opening code fence with optional language
        if text.startswith('```'):
            first_newline = text.find('\n')
            if first_newline != -1:
                text = text[first_newline + 1:]
            else:
                text = text[3:]
        # Remove closing code fence
        if text.rstrip().endswith('```'):
            text = text.rstrip()[:-3]
        return text.strip()
