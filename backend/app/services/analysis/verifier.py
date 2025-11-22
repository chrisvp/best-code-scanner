import asyncio
from typing import List, Dict

from app.models.scanner_models import DraftFinding, ScanFileChunk
from app.services.intelligence.context_retriever import ContextRetriever
from app.services.orchestration.model_orchestrator import ModelPool, ModelOrchestrator
from app.core.database import SessionLocal


class FindingVerifier:
    """Verifies draft findings using multi-model voting with adversarial analysis"""

    # Adversarial prompt - make the model argue AGAINST the finding first
    VOTE_PROMPT = """You are a security expert reviewing a potential vulnerability finding. Your job is to be SKEPTICAL and find reasons why this might be a FALSE POSITIVE.

=== DRAFT FINDING ===
Title: {title}
Type: {vuln_type}
Severity: {severity}
Code Snippet:
{snippet}

Initial Reason: {reason}

=== CODE CONTEXT ===
{context}

=== YOUR TASK ===

First, try to DISPROVE this finding by answering:

1. **Application Type**: Is this a CLI tool, web service, library, or embedded system?
2. **Threat Model**: Who would attack this? Do they already have the access this "vulnerability" would give them?
3. **Attack Prerequisites**: What would an attacker need? (network access, local access, credentials, etc.)
4. **Realistic Exploitation**: Can this actually be exploited in the real world, or is it theoretical?
5. **Mitigating Factors**: Are there sanitization, validation, or architectural protections not shown in the snippet?

Then make your decision:

=== RESPONSE FORMAT ===

*VOTE: REJECT, WEAKNESS, or VERIFY
*CONFIDENCE: 0-100
*MODEL_REASONING:
[Your detailed analysis. Be specific about the application context and threat model.]
*ATTACK_SCENARIO:
[If VERIFY: Concrete step-by-step attack. If WEAKNESS: What could go wrong. If REJECT: Why no realistic issue exists]
*END_VOTE

Vote meanings:
- VERIFY: Exploitable security vulnerability requiring immediate fix
- WEAKNESS: Bad practice, code quality issue, or defense-in-depth concern (report as Info/Low)
- REJECT: Not a real issue in this context

Examples:
- Path traversal in CLI tool → REJECT (user already has shell access)
- Unchecked file operations → WEAKNESS (bad practice, could cause crashes)
- SQL injection in web app → VERIFY (exploitable vulnerability)"""

    def __init__(self, scan_id: int, orchestrator: ModelOrchestrator, context_retriever: ContextRetriever):
        self.scan_id = scan_id
        self.orchestrator = orchestrator
        self.context_retriever = context_retriever

    async def verify_batch(self, drafts: List[DraftFinding]) -> List[dict]:
        """
        Verify multiple draft findings using multi-model voting.
        Each verifier model votes on each finding.
        Returns list of aggregated verification results with vote details.
        """
        verifier_pools = self.orchestrator.get_verifiers()

        if not verifier_pools:
            # No verifiers configured - pass through with warning
            return [{'verified': True, 'reason': 'No verifiers configured', 'votes': []} for _ in drafts]

        # Build prompts for each draft
        draft_prompts = []
        for draft in drafts:
            db = SessionLocal()
            try:
                chunk = db.query(ScanFileChunk).filter(
                    ScanFileChunk.id == draft.chunk_id
                ).first()

                if chunk:
                    context = await self.context_retriever.get_context(chunk)
                else:
                    context = "No additional context available."
            finally:
                db.close()

            prompt = self.VOTE_PROMPT.format(
                title=draft.title,
                vuln_type=draft.vulnerability_type,
                severity=draft.severity,
                snippet=draft.snippet or '',
                reason=draft.reason or '',
                context=context
            )
            draft_prompts.append(prompt)

        # Collect votes from ALL verifier models
        all_votes = []  # List of (model_name, [responses for each draft])

        # Run all models in parallel
        async def get_model_votes(pool: ModelPool) -> tuple:
            try:
                responses = await pool.call_batch(draft_prompts)
                return (pool.config.name, responses)
            except Exception as e:
                print(f"Verifier {pool.config.name} failed: {e}")
                return (pool.config.name, ["" for _ in draft_prompts])

        vote_tasks = [get_model_votes(pool) for pool in verifier_pools]
        all_votes = await asyncio.gather(*vote_tasks)

        # Aggregate votes for each draft
        results = []
        for draft_idx, draft in enumerate(drafts):
            votes = []

            for model_name, responses in all_votes:
                response = responses[draft_idx] if draft_idx < len(responses) else ""
                vote = self._parse_vote(response, model_name)
                votes.append(vote)

            # Aggregate: majority vote wins
            result = self._aggregate_votes(votes, draft)
            results.append(result)

        return results

    def _parse_vote(self, response: str, model_name: str) -> dict:
        """Parse a single model's vote response"""
        vote = {
            'model': model_name,
            'decision': 'ABSTAIN',
            'confidence': 0,
            'reasoning': '',
            'attack_scenario': ''
        }

        if not response:
            vote['reasoning'] = 'No response from model'
            return vote

        response_lower = response.lower()

        # Extract vote decision
        if '*vote:' in response_lower:
            # Find the vote line
            for line in response.split('\n'):
                if '*vote:' in line.lower():
                    line_lower = line.lower()
                    if 'reject' in line_lower:
                        vote['decision'] = 'REJECT'
                    elif 'weakness' in line_lower:
                        vote['decision'] = 'WEAKNESS'
                    elif 'verify' in line_lower:
                        vote['decision'] = 'VERIFY'
                    break

        # Extract confidence
        if '*confidence:' in response_lower:
            for line in response.split('\n'):
                if '*confidence:' in line.lower():
                    try:
                        # Extract number from line
                        import re
                        nums = re.findall(r'\d+', line)
                        if nums:
                            vote['confidence'] = min(100, int(nums[0]))
                    except:
                        pass
                    break

        # Extract reasoning
        if '*model_reasoning:' in response_lower:
            start = response_lower.find('*model_reasoning:')
            end = response_lower.find('*attack_scenario:', start)
            if end == -1:
                end = response_lower.find('*end_vote', start)
            if start != -1 and end != -1:
                vote['reasoning'] = response[start + 17:end].strip()
            elif start != -1:
                vote['reasoning'] = response[start + 17:].strip()[:500]

        # Extract attack scenario
        if '*attack_scenario:' in response_lower:
            start = response_lower.find('*attack_scenario:')
            end = response_lower.find('*end_vote', start)
            if start != -1:
                if end != -1:
                    vote['attack_scenario'] = response[start + 17:end].strip()
                else:
                    vote['attack_scenario'] = response[start + 17:].strip()[:500]

        return vote

    def _aggregate_votes(self, votes: List[dict], draft: DraftFinding) -> dict:
        """
        Aggregate votes from multiple models.
        Uses weighted voting based on confidence.
        WEAKNESS votes count as partial VERIFY (creates Info/Low findings).
        """
        verify_score = 0
        weakness_score = 0
        reject_score = 0

        for vote in votes:
            weight = vote['confidence'] / 100.0 if vote['confidence'] > 0 else 0.5

            if vote['decision'] == 'VERIFY':
                verify_score += weight
            elif vote['decision'] == 'WEAKNESS':
                weakness_score += weight
            elif vote['decision'] == 'REJECT':
                reject_score += weight
            # ABSTAIN adds nothing

        # WEAKNESS counts as half a VERIFY for aggregation
        combined_verify_score = verify_score + (weakness_score * 0.5)
        total_score = combined_verify_score + reject_score

        # Need majority to create finding
        verified = combined_verify_score > reject_score and total_score > 0

        # Determine if primarily weakness (for severity adjustment)
        is_weakness = weakness_score > verify_score and verified

        # Calculate overall confidence
        if total_score > 0:
            confidence = int((max(combined_verify_score, reject_score) / total_score) * 100)
        else:
            confidence = 0

        # Build result with vote details
        result = {
            'verified': verified,
            'is_weakness': is_weakness,
            'confidence': confidence,
            'votes': votes,
            'verify_score': round(verify_score, 2),
            'weakness_score': round(weakness_score, 2),
            'reject_score': round(reject_score, 2)
        }

        if verified:
            # Find best verify or weakness vote for details
            verify_votes = [v for v in votes if v['decision'] == 'VERIFY']
            weakness_votes = [v for v in votes if v['decision'] == 'WEAKNESS']

            if verify_votes:
                best_vote = max(verify_votes, key=lambda v: v['confidence'])
            elif weakness_votes:
                best_vote = max(weakness_votes, key=lambda v: v['confidence'])
            else:
                best_vote = None

            if best_vote:
                result['title'] = draft.title
                result['attack_vector'] = best_vote['attack_scenario']
                # Mark weaknesses as their own category
                if is_weakness:
                    result['adjusted_severity'] = 'Weakness'
                else:
                    result['adjusted_severity'] = draft.severity
                result['data_flow'] = ''
                result['reasoning'] = best_vote['reasoning']
        else:
            # Find best reject vote for reason
            best_reject = max(
                [v for v in votes if v['decision'] == 'REJECT'],
                key=lambda v: v['confidence'],
                default=None
            )
            if best_reject:
                result['reason'] = best_reject['reasoning']
            else:
                result['reason'] = 'No consensus reached'

        return result

    async def verify_single(self, draft: DraftFinding) -> dict:
        """Verify a single draft finding"""
        results = await self.verify_batch([draft])
        return results[0] if results else {'verified': False, 'reason': 'Verification failed', 'votes': []}
