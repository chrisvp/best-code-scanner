"""
Universal LLM Response Parser

Handles JSON and marker syntax formats with fuzzy matching.
When parsing fails, returns a result indicating cleanup is needed.

Supported formats:
- JSON: {"vote": "VERIFY", "confidence": 90}
- Marker: *VOTE: VERIFY / **VOTE:** VERIFY / VOTE: VERIFY
"""

import re
import json
from typing import Any, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum


class ResponseFormat(Enum):
    """Detected format of LLM response"""
    JSON = "json"
    MARKER = "marker"
    UNKNOWN = "unknown"


@dataclass
class ParseResult:
    """Result of parsing an LLM response"""
    success: bool
    format_detected: ResponseFormat
    fields: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    needs_cleanup: bool = False  # True if cleanup model should be invoked

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self.fields[key]

    def __contains__(self, key: str) -> bool:
        return key in self.fields


class UniversalParser:
    """
    Universal parser for LLM responses - JSON and marker formats only.

    Features:
    - Normalizes unicode (full-width colons, em-dashes, etc.)
    - Strips thinking tags (<thinking>, <think>)
    - Fuzzy marker matching (handles *, **, markdown headers, bullets)
    - Field aliasing and type coercion
    - Returns needs_cleanup=True when parsing fails
    """

    # Characters that can appear before a field keyword
    FIELD_PREFIX_CHARS = r'[\s\*#\-•→►▸>\[\]\(\)\|]*'

    # Characters that act as separators between keyword and value
    SEPARATOR_CHARS = r'[\s\*]*[:=\-–—→>]+[\s\*]*'

    def __init__(self,
                 field_aliases: Optional[Dict[str, List[str]]] = None,
                 type_coercions: Optional[Dict[str, type]] = None,
                 required_fields: Optional[List[str]] = None):
        self.field_aliases = field_aliases or {}
        self.type_coercions = type_coercions or {}
        self.required_fields = required_fields or []

        # Build reverse alias map
        self._alias_to_canonical = {}
        for canonical, aliases in self.field_aliases.items():
            for alias in aliases:
                self._alias_to_canonical[alias.lower()] = canonical

        # Build all keywords list for marker detection
        self._all_keywords = set()
        for aliases in self.field_aliases.values():
            self._all_keywords.update(a.lower() for a in aliases)

    def parse(self, response: str) -> ParseResult:
        """Parse LLM response, auto-detecting format."""
        if not response or not response.strip():
            return ParseResult(
                success=False,
                format_detected=ResponseFormat.UNKNOWN,
                errors=["Empty response"],
                needs_cleanup=False  # Can't cleanup empty
            )

        # Normalize and clean
        cleaned = self._preprocess(response)

        # Try JSON first
        json_result = self._try_parse_json(cleaned)
        if json_result.success:
            return self._validate_required_fields(json_result)

        # Try marker format
        marker_result = self._parse_marker_format(cleaned)
        if marker_result.success:
            return self._validate_required_fields(marker_result)

        # Nothing worked - needs cleanup
        return ParseResult(
            success=False,
            format_detected=ResponseFormat.UNKNOWN,
            errors=["Could not parse response"],
            needs_cleanup=True
        )

    def _preprocess(self, text: str) -> str:
        """Normalize and clean response text."""
        # Strip thinking/reasoning tags
        text = self._strip_thinking_tags(text)

        # Normalize unicode
        text = self._normalize_unicode(text)

        # Strip outer code blocks
        text = self._strip_code_blocks(text)

        # Normalize whitespace
        text = re.sub(r'\r\n', '\n', text)
        text = re.sub(r'\r', '\n', text)

        return text.strip()

    def _strip_thinking_tags(self, text: str) -> str:
        """Remove thinking/reasoning tags from LLM output."""
        patterns = [
            (r'<thinking>.*?</thinking>', re.DOTALL | re.IGNORECASE),
            (r'<think>.*?</think>', re.DOTALL | re.IGNORECASE),
            (r'<reasoning>.*?</reasoning>', re.DOTALL | re.IGNORECASE),
            (r'<reflection>.*?</reflection>', re.DOTALL | re.IGNORECASE),
            # Unclosed tags (model got cut off)
            (r'<thinking>(?:(?!</thinking>).)*$', re.DOTALL | re.IGNORECASE),
            (r'<think>(?:(?!</think>).)*$', re.DOTALL | re.IGNORECASE),
        ]
        for pattern, flags in patterns:
            text = re.sub(pattern, '', text, flags=flags)

        # Also strip any remaining orphan tags
        text = re.sub(r'</?(?:thinking|think|reasoning|reflection)>', '', text, flags=re.IGNORECASE)

        return text

    def _normalize_unicode(self, text: str) -> str:
        """Normalize unicode characters to ASCII equivalents."""
        replacements = {
            # Colons
            '：': ':',  # Full-width colon
            '﹕': ':',  # Small colon
            # Dashes
            '—': '-',   # Em-dash
            '–': '-',   # En-dash
            '−': '-',   # Minus sign
            '‐': '-',   # Hyphen
            '‑': '-',   # Non-breaking hyphen
            # Asterisks
            '＊': '*',  # Full-width asterisk
            '⁎': '*',   # Low asterisk
            '∗': '*',   # Asterisk operator
            # Quotes
            '"': '"',   # Left double quote
            '"': '"',   # Right double quote
            ''': "'",   # Left single quote
            ''': "'",   # Right single quote
            # Spaces
            '\u00a0': ' ',  # Non-breaking space
            '\u2003': ' ',  # Em space
            '\u2002': ' ',  # En space
            '\u2009': ' ',  # Thin space
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text

    def _strip_code_blocks(self, text: str) -> str:
        """Remove outer markdown code block wrappers."""
        text = text.strip()

        if not text.startswith('```'):
            return text

        lines = text.split('\n')

        # Find closing fence
        close_idx = -1
        for i in range(len(lines) - 1, 0, -1):
            if lines[i].strip() == '```':
                close_idx = i
                break

        if close_idx > 0:
            text = '\n'.join(lines[1:close_idx])

        return text.strip()

    def _try_parse_json(self, text: str) -> ParseResult:
        """Attempt to parse as JSON."""
        # Try direct parse
        try:
            data = json.loads(text)
            return self._json_to_result(data)
        except json.JSONDecodeError:
            pass

        # Look for JSON in code block
        json_block = re.search(r'```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```', text, re.DOTALL)
        if json_block:
            try:
                data = json.loads(json_block.group(1))
                return self._json_to_result(data)
            except json.JSONDecodeError:
                pass

        # Look for embedded JSON object/array
        # Try to find balanced braces/brackets
        for start_char, end_char, pattern in [
            ('{', '}', r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'),  # Object with one level nesting
            ('[', ']', r'\[[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*\]'),  # Array with one level nesting
        ]:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group(0))
                    return self._json_to_result(data)
                except json.JSONDecodeError:
                    continue

        return ParseResult(success=False, format_detected=ResponseFormat.UNKNOWN)

    def _json_to_result(self, data: Union[dict, list]) -> ParseResult:
        """Convert parsed JSON to ParseResult."""
        if isinstance(data, list):
            return ParseResult(
                success=True,
                format_detected=ResponseFormat.JSON,
                fields={'items': data}
            )

        if isinstance(data, dict):
            fields = {}
            for key, value in data.items():
                canonical = self._get_canonical_field(key)
                coerced = self._coerce_type(canonical, value)
                fields[canonical] = coerced

            return ParseResult(
                success=True,
                format_detected=ResponseFormat.JSON,
                fields=fields
            )

        return ParseResult(success=False, format_detected=ResponseFormat.UNKNOWN)

    def _parse_marker_format(self, text: str) -> ParseResult:
        """Parse marker format with fuzzy matching."""
        fields = {}

        # Get keywords to search for
        keywords = self._all_keywords if self._all_keywords else self._detect_keywords(text)

        for keyword in keywords:
            value = self._extract_marker_value(text, keyword)
            if value is not None:
                canonical = self._get_canonical_field(keyword)
                coerced = self._coerce_type(canonical, value)
                # Don't overwrite if we already have a value (first match wins)
                if canonical not in fields:
                    fields[canonical] = coerced

        if not fields:
            return ParseResult(success=False, format_detected=ResponseFormat.UNKNOWN)

        return ParseResult(
            success=True,
            format_detected=ResponseFormat.MARKER,
            fields=fields
        )

    def _detect_keywords(self, text: str) -> set:
        """Auto-detect field keywords in text."""
        # Look for UPPERCASE_WORD followed by separator
        pattern = r'(?:^|\n)\s*[\*#\-]*\s*([A-Z][A-Z_]{1,20})\s*[:\-=]'
        matches = re.findall(pattern, text, re.MULTILINE)
        return set(m.lower() for m in matches)

    def _extract_marker_value(self, text: str, keyword: str) -> Optional[str]:
        """
        Extract value for a keyword using fuzzy matching.

        Handles many formats:
        - *KEYWORD: value
        - **KEYWORD:** value
        - **KEYWORD**: value
        - ## KEYWORD: value
        - - KEYWORD: value
        - KEYWORD: value
        - KEYWORD = value
        """
        keyword_pattern = re.escape(keyword)

        # Build flexible pattern
        # Prefix: start of line, optional markdown/bullet chars, optional asterisks
        prefix = r'(?:^|\n)' + self.FIELD_PREFIX_CHARS

        # Keyword with optional surrounding asterisks (for **KEYWORD**)
        kw = r'\*{0,3}\s*' + keyword_pattern + r'\s*\*{0,3}'

        # Separator: colon, equals, dash, arrow with optional surrounding chars
        sep = self.SEPARATOR_CHARS

        # Value: everything until next field marker or end
        # Next field is: newline + optional prefix + UPPERCASE_WORD + separator
        next_field = r'(?=\n' + self.FIELD_PREFIX_CHARS + r'[A-Z][A-Z_]*\s*[:\-=])'
        end_marker = r'(?=\n\s*\*?END|\Z)'

        value_pattern = r'(.+?)(?:' + next_field + r'|' + end_marker + r')'

        full_pattern = prefix + kw + sep + value_pattern

        match = re.search(full_pattern, text, re.IGNORECASE | re.DOTALL)
        if match:
            value = match.group(1).strip()
            return self._clean_value(value)

        # Fallback: simpler inline pattern
        inline_pattern = keyword_pattern + r'\s*[:\-=]\s*([^,\n]+)'
        match = re.search(inline_pattern, text, re.IGNORECASE)
        if match:
            value = match.group(1).strip()
            return self._clean_value(value)

        return None

    def _clean_value(self, value: str) -> str:
        """Clean extracted value."""
        # Remove END markers
        value = re.sub(r'\*?END[_A-Z]*.*$', '', value, flags=re.IGNORECASE | re.DOTALL)

        # Remove trailing asterisks/markdown
        value = re.sub(r'[\*#]+\s*$', '', value)

        # Remove surrounding quotes
        value = value.strip()
        if len(value) >= 2:
            if (value[0] == '"' and value[-1] == '"') or (value[0] == "'" and value[-1] == "'"):
                value = value[1:-1]

        # For single-line values, just take first line
        lines = value.split('\n')
        first_line = lines[0].strip()

        # If first line looks complete (short or ends with punctuation), use it
        if len(first_line) < 100 or first_line[-1] in '.!?)':
            # But check if remaining content looks like continuation
            if len(lines) > 1:
                remaining = '\n'.join(lines[1:]).strip()
                # If remaining starts with field marker, definitely stop at first line
                if remaining and re.match(r'^\s*[\*#\-]*\s*[A-Z]', remaining):
                    return first_line
                # If remaining is short continuation, might be multi-line value
                if remaining and len(remaining) < 500 and not remaining.startswith('*'):
                    return value.strip()
            return first_line

        return value.strip()

    def _get_canonical_field(self, field_name: str) -> str:
        """Get canonical field name from alias."""
        return self._alias_to_canonical.get(field_name.lower(), field_name.lower())

    def _coerce_type(self, field_name: str, value: Any) -> Any:
        """Coerce value to expected type."""
        if field_name not in self.type_coercions:
            return value

        target_type = self.type_coercions[field_name]

        try:
            if target_type == bool:
                if isinstance(value, bool):
                    return value
                if isinstance(value, str):
                    return value.lower().strip() in ('true', 'yes', '1', 'verify', 'verified')
                return bool(value)

            if target_type == int:
                if isinstance(value, int):
                    return value
                if isinstance(value, str):
                    nums = re.findall(r'\d+', value)
                    if nums:
                        return int(nums[0])
                return int(value)

            if target_type == float:
                if isinstance(value, (int, float)):
                    return float(value)
                if isinstance(value, str):
                    nums = re.findall(r'[\d.]+', value)
                    if nums:
                        return float(nums[0])
                return float(value)

            return target_type(value)
        except (ValueError, TypeError):
            return value

    def _validate_required_fields(self, result: ParseResult) -> ParseResult:
        """Check required fields and mark needs_cleanup if missing."""
        if not self.required_fields:
            return result

        missing = [f for f in self.required_fields if f not in result.fields]
        if missing:
            result.success = False
            result.errors.append(f"Missing required fields: {missing}")
            result.needs_cleanup = True

        return result


class VoteParser(UniversalParser):
    """Parser for verification vote responses."""

    def __init__(self):
        super().__init__(
            field_aliases={
                'vote': ['vote', 'decision', 'verdict', 'result', 'judgment', 'judgement'],
                'confidence': ['confidence', 'conf', 'certainty', 'score', 'probability'],
                'reasoning': ['reasoning', 'reason', 'explanation', 'rationale', 'analysis',
                             'model_reasoning', 'justification', 'why'],
                'attack_scenario': ['attack_scenario', 'attack', 'exploit', 'attack_vector',
                                   'poc', 'proof_of_concept', 'exploitation'],
            },
            type_coercions={
                'confidence': int,
            },
            required_fields=['vote']
        )

    def parse_vote(self, response: str) -> Dict[str, Any]:
        """Parse vote response and return standardized result."""
        result = self.parse(response)

        vote_result = {
            'decision': 'ABSTAIN',
            'confidence': 50,
            'reasoning': '',
            'attack_scenario': '',
            'parse_success': result.success,
            'format_detected': result.format_detected.value,
            'needs_cleanup': result.needs_cleanup
        }

        if not result.fields:
            vote_result['reasoning'] = 'Failed to parse response'
            return vote_result

        # Extract vote decision
        vote_value = result.get('vote', '')
        if isinstance(vote_value, str):
            vote_upper = vote_value.upper().strip()
            # Check for decision keywords anywhere in the value
            if 'REJECT' in vote_upper:
                vote_result['decision'] = 'REJECT'
            elif 'WEAKNESS' in vote_upper:
                vote_result['decision'] = 'WEAKNESS'
            elif 'VERIFY' in vote_upper or 'CONFIRM' in vote_upper or 'VALID' in vote_upper:
                vote_result['decision'] = 'VERIFY'

        # Extract confidence
        confidence = result.get('confidence', 50)
        if isinstance(confidence, int):
            vote_result['confidence'] = min(100, max(0, confidence))
        elif isinstance(confidence, str):
            nums = re.findall(r'\d+', confidence)
            if nums:
                vote_result['confidence'] = min(100, max(0, int(nums[0])))

        # Extract reasoning
        reasoning = result.get('reasoning', '')
        if reasoning:
            vote_result['reasoning'] = str(reasoning)[:1000]

        # Extract attack scenario
        attack = result.get('attack_scenario', '')
        if attack:
            vote_result['attack_scenario'] = str(attack)[:500]

        return vote_result


class DraftFindingParser(UniversalParser):
    """Parser for draft vulnerability findings."""

    NO_FINDINGS_PHRASES = [
        'no findings', 'no vulnerabilities', 'no issues', 'no security issues',
        'nothing suspicious', 'no potential vulnerabilities', 'code appears safe',
        'draft:none', '*draft:none', '[]', 'no problems', 'code is safe',
        'no security concerns', 'no weaknesses'
    ]

    def __init__(self):
        super().__init__(
            field_aliases={
                'title': ['title', 'name', 'finding', 'vulnerability', 'issue', 'summary'],
                'type': ['type', 'vuln_type', 'vulnerability_type', 'cwe', 'category', 'class'],
                'severity': ['severity', 'sev', 'risk', 'risk_level', 'priority', 'impact'],
                'line': ['line', 'line_number', 'line_num', 'lineno', 'location', 'line_no'],
                'snippet': ['snippet', 'code', 'code_snippet', 'vulnerable_code',
                           'affected_code', 'source'],
                'reason': ['reason', 'description', 'explanation', 'details', 'why',
                          'rationale', 'analysis'],
            },
            type_coercions={
                'line': int,
            }
        )

    def parse_drafts(self, response: str) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Parse draft findings from response.

        Returns (list of findings, needs_cleanup).
        """
        if not response or not response.strip():
            return [], False

        cleaned = self._preprocess(response)

        # Check for no-findings indicators
        cleaned_lower = cleaned.lower().strip()
        if any(phrase in cleaned_lower for phrase in self.NO_FINDINGS_PHRASES):
            return [], False

        # Try JSON array first
        json_result = self._try_parse_json(cleaned)
        if json_result.success:
            if 'items' in json_result.fields:
                items = json_result.fields['items']
                if isinstance(items, list):
                    findings = [self._normalize_finding(f) for f in items if isinstance(f, dict)]
                    return findings, False
            elif json_result.fields:
                # Single finding as JSON object
                return [self._normalize_finding(json_result.fields)], False

        # Try marker format - look for DRAFT sections
        drafts = self._parse_draft_sections(cleaned)
        if drafts:
            return drafts, False

        # Couldn't parse - needs cleanup
        return [], True

    def _parse_draft_sections(self, text: str) -> List[Dict[str, Any]]:
        """Parse multiple DRAFT sections."""
        drafts = []

        # Pattern for DRAFT markers with various prefixes
        draft_pattern = re.compile(
            r'(?:^|\n)\s*' + self.FIELD_PREFIX_CHARS +
            r'DRAFT\s*[:\-=]\s*(.+?)(?=(?:\n\s*' + self.FIELD_PREFIX_CHARS +
            r'DRAFT\s*[:\-=])|(?:\n\s*\*?END)|$)',
            re.IGNORECASE | re.DOTALL
        )

        for match in draft_pattern.finditer(text):
            section = match.group(1)
            finding = self._parse_finding_section(section)
            if finding and finding.get('title'):
                drafts.append(finding)

        return drafts

    def _parse_finding_section(self, section: str) -> Optional[Dict[str, Any]]:
        """Parse a single finding section."""
        # Title is first line or content before first field
        title_match = re.match(r'^(.+?)(?=\n\s*[\*#\-]*\s*[A-Z_]+\s*[:\-=]|\Z)',
                               section.strip(), re.DOTALL)
        if not title_match:
            return None

        title = title_match.group(1).strip()
        title = re.sub(r'^[\*#\-\s]+', '', title)
        title = re.sub(r'[\*#\-\s]+$', '', title)

        if not title or len(title) < 3:
            return None

        finding = {'title': title}

        # Extract other fields
        for canonical, aliases in self.field_aliases.items():
            if canonical == 'title':
                continue
            for alias in aliases:
                value = self._extract_marker_value(section, alias)
                if value:
                    finding[canonical] = self._coerce_type(canonical, value)
                    break

        return finding

    def _normalize_finding(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize finding to standard format."""
        return {
            'title': data.get('title', data.get('name', data.get('finding', 'Unknown'))),
            'type': data.get('type', data.get('vulnerability_type', data.get('cwe', 'Unknown'))),
            'severity': data.get('severity', data.get('risk', 'Medium')),
            'line': data.get('line', data.get('line_number', 0)),
            'snippet': data.get('snippet', data.get('code', '')),
            'reason': data.get('reason', data.get('description', ''))
        }


class EnrichedFindingParser(UniversalParser):
    """Parser for enriched/detailed vulnerability findings."""

    def __init__(self):
        super().__init__(
            field_aliases={
                'finding': ['finding', 'title', 'vulnerability', 'name', 'summary'],
                'category': ['category', 'type', 'cwe', 'vuln_type', 'vulnerability_type'],
                'severity': ['severity', 'risk', 'risk_level', 'priority'],
                'cvss': ['cvss', 'cvss_score', 'score', 'cvss_rating'],
                'impacted_code': ['impacted_code', 'vulnerable_code', 'code', 'affected_code'],
                'vulnerability_details': ['vulnerability_details', 'details', 'description',
                                         'explanation', 'analysis'],
                'proof_of_concept': ['proof_of_concept', 'poc', 'exploit', 'attack',
                                    'exploitation', 'attack_scenario'],
                'corrected_code': ['corrected_code', 'fixed_code', 'fix', 'remediated_code',
                                  'solution', 'patched_code'],
                'remediation_steps': ['remediation_steps', 'remediation', 'fix_steps',
                                     'mitigation', 'recommendations', 'how_to_fix'],
                'references': ['references', 'refs', 'links', 'resources', 'sources'],
            },
            type_coercions={
                'cvss': float,
            }
        )

    def parse_enriched(self, response: str) -> Tuple[Dict[str, Any], bool]:
        """
        Parse enriched finding from response.

        Returns (finding dict, needs_cleanup).
        """
        result = self.parse(response)

        if result.success:
            return result.fields, False
        else:
            return {}, result.needs_cleanup
