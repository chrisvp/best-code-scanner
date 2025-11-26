import re
import json
from typing import List, Optional, Dict


class DraftParser:
    """Parse lightweight draft findings from LLM response"""

    def parse(self, response: str) -> Optional[List[dict]]:
        """
        Parse draft findings from response.
        Supports both JSON format and *DRAFT: marker format.
        Returns None if parsing fails (triggers correction).
        """
        # First, strip thinking tags
        response = self._strip_thinking_tags(response)
        response = self._strip_code_blocks(response)

        # Handle no findings
        no_finding_indicators = [
            'draft:none', 'no findings', 'no vulnerabilities',
            'no issues', 'no security issues', 'nothing suspicious',
            '[]'  # Empty JSON array
        ]
        clean_response = response.strip()
        if clean_response == '[]' or any(ind in response.lower() for ind in no_finding_indicators):
            return []

        # Try JSON parsing first (for prompts that ask for JSON output)
        json_results = self._try_json_parse(response)
        if json_results is not None:
            return json_results

        # Fall back to *DRAFT: marker format
        drafts = []
        sections = response.split('*DRAFT:')

        if len(sections) == 1:
            # No findings marker found - try to extract JSON from anywhere in response
            return self._try_extract_json_array(response)

        for section in sections[1:]:
            draft = self._extract_draft(section)
            if draft:
                drafts.append(draft)
            else:
                # Parsing error
                return None

        return drafts

    def _strip_thinking_tags(self, text: str) -> str:
        """Remove thinking tags and their content.

        Handles multiple formats:
        - <thinking>...</thinking> (Claude, Anthropic models)
        - <think>...</think> (Kimi k1/k1.5, DeepSeek R1)
        - reasoning_content field (returned separately by some APIs)
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
        """Try to parse response as JSON array of findings"""
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
                'title': f.get('title', f.get('name', 'Unknown')),
                'type': f.get('vulnerability_type', f.get('type', f.get('cwe', 'Unknown'))),
                'severity': f.get('severity', 'Medium'),
                'line': f.get('line_number', f.get('line', 0)),
                'snippet': f.get('snippet', f.get('code', '')),
                'reason': f.get('reason', f.get('description', f.get('explanation', '')))
            }
            # Only include if it has a title
            if normalized_finding['title'] and normalized_finding['title'] != 'Unknown':
                normalized.append(normalized_finding)
        return normalized

    def _extract_draft(self, section: str) -> Optional[dict]:
        """Extract fields from a draft section"""
        draft = {}

        # Extract title (everything before first *FIELD:)
        title_match = re.search(r'^(.+?)(?=\*[A-Z])', section.strip(), re.DOTALL)
        if title_match:
            draft['title'] = title_match.group(1).strip()
        else:
            return None

        # Extract standard fields
        field_patterns = {
            'type': r'\*TYPE:\s*(.+?)(?=\*[A-Z]|\*END_DRAFT|$)',
            'severity': r'\*SEVERITY:\s*(.+?)(?=\*[A-Z]|\*END_DRAFT|$)',
            'line': r'\*LINE:\s*(\d+)',
            'snippet': r'\*SNIPPET:\s*(.+?)(?=\*[A-Z]|\*END_DRAFT|$)',
            'reason': r'\*REASON:\s*(.+?)(?=\*[A-Z]|\*END_DRAFT|$)',
        }

        for field, pattern in field_patterns.items():
            match = re.search(pattern, section, re.DOTALL | re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                draft[field] = value

        # Ensure we have minimum required fields
        if not draft.get('title'):
            return None

        return draft

    def _strip_code_blocks(self, text: str) -> str:
        """Remove markdown code blocks"""
        text = text.strip()
        while text.startswith('```') and text.endswith('```'):
            text = text[3:-3].strip()
            # Remove language identifier
            if '\n' in text:
                first_line = text.split('\n')[0]
                if first_line.replace('-', '').replace('_', '').isalnum():
                    text = '\n'.join(text.split('\n')[1:])
        return text


class VerificationParser:
    """Parse verification results from LLM response"""

    def parse(self, response: str) -> dict:
        """Parse verification response into result dict"""
        response = self._strip_thinking_tags(response)
        response = self._strip_code_blocks(response)

        # Check for rejection
        if '*REJECTED:' in response:
            match = re.search(
                r'\*REJECTED:\s*(.+?)\*REASON:\s*(.+?)(?:\*END_REJECTED|$)',
                response, re.DOTALL
            )
            if match:
                return {
                    'verified': False,
                    'title': match.group(1).strip(),
                    'reason': match.group(2).strip()
                }
            return {'verified': False, 'reason': 'Rejected (parse error)'}

        # Check for verification
        if '*VERIFIED:' in response:
            result = {'verified': True}

            patterns = {
                'title': r'\*VERIFIED:\s*(.+?)(?=\*[A-Z])',
                'confidence': r'\*CONFIDENCE:\s*(\d+)',
                'attack_vector': r'\*ATTACK_VECTOR:\s*(.+?)(?=\*[A-Z]|\*END|$)',
                'data_flow': r'\*DATA_FLOW:\s*(.+?)(?=\*[A-Z]|\*END|$)',
                'adjusted_severity': r'\*ADJUSTED_SEVERITY:\s*(\w+)',
            }

            for field, pattern in patterns.items():
                match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
                if match:
                    value = match.group(1).strip()
                    if field == 'confidence':
                        try:
                            value = int(value)
                        except ValueError:
                            value = 50
                    result[field] = value

            return result

        # Default to not verified
        return {'verified': False, 'reason': 'Unable to parse response'}

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
        while text.startswith('```') and text.endswith('```'):
            text = text[3:-3].strip()
        return text


class EnrichmentParser:
    """Parse full enriched findings from LLM response using fuzzy split-based parsing"""

    FIELDS = [
        'FINDING', 'CATEGORY', 'SEVERITY', 'CVSS', 'IMPACTED_CODE',
        'VULNERABILITY_DETAILS', 'PROOF_OF_CONCEPT', 'CORRECTED_CODE',
        'REMEDIATION_STEPS', 'REFERENCES'
    ]

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
        field_lower = field.lower()

        # Find any line containing the field name followed by colon
        # Handles: *FIELD:, ## **FIELD:, FIELD:, []FIELD:, etc.
        best_pos = -1
        best_marker = None

        # Try different possible markers
        for marker in [
            f'\n{field_lower}:',
            f'\n*{field_lower}:',
            f'\n**{field_lower}:',
            f'\n## {field_lower}:',
            f'\n## **{field_lower}:',
            f'\n[]{field_lower}:',
            f'{field_lower}:',  # At start of text
        ]:
            pos = text_lower.find(marker)
            if pos != -1 and (best_pos == -1 or pos < best_pos):
                best_pos = pos
                best_marker = marker

        if best_pos == -1:
            return None

        # Extract content after the marker
        start = best_pos + len(best_marker)
        content = text[start:]

        # Find where the next field starts
        end_pos = len(content)
        for next_field in self.FIELDS + ['END_FINDING']:
            if next_field == field:
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

        # Remove leading markdown formatting
        lines = value.split('\n')
        cleaned_lines = []
        for line in lines:
            # Strip leading and trailing *, #, spaces but preserve content
            stripped = line.strip('*# \t')
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
