import re
from typing import List, Optional
from sqlalchemy.orm import Session

from app.models.scanner_models import VerifiedFinding, VulnerabilityCategory
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

        # Extract CWE ID if present
        cwe_match = re.search(r'CWE-(\d+)', raw_category, re.IGNORECASE)
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
        raw_lower = raw_category.lower()
        keywords = self._extract_keywords(raw_lower)

        all_cats = self.db.query(VulnerabilityCategory).all()
        best_match = None
        best_score = 0

        for cat in all_cats:
            if cat.keywords:
                score = sum(1 for kw in cat.keywords if kw in raw_lower)
                if score > best_score:
                    best_score = score
                    best_match = cat

        if best_match and best_score >= 1:
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
Severity: {severity}
Attack Vector: {attack_vector}
Data Flow: {data_flow}
Confidence: {confidence}%

=== INSTRUCTIONS ===
Provide a complete security report with:

*FINDING: detailed vulnerability title
*CATEGORY: CWE category (e.g., CWE-78 OS Command Injection)
*SEVERITY: {severity}
*CVSS: score 0.0-10.0
*IMPACTED_CODE:
(paste the vulnerable code here)
*VULNERABILITY_DETAILS:
Detailed explanation including:
- What the vulnerability is
- Why it's dangerous
- Specific attack scenario
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
        Returns list of enriched finding dicts.
        """
        prompts = []

        for v in verified_list:
            prompt = self.ENRICH_PROMPT.format(
                title=v.title,
                severity=v.adjusted_severity or 'High',
                attack_vector=v.attack_vector or 'Unknown',
                data_flow=v.data_flow or 'Unknown',
                confidence=v.confidence or 50
            )
            prompts.append(prompt)

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
        """Clean the fix response, removing any markdown formatting"""
        if not response:
            return ''

        text = response.strip()

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
