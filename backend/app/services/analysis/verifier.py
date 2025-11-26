import asyncio
import os
from typing import List, Dict, Optional

from app.models.scanner_models import DraftFinding, ScanFileChunk, ScanFile
from app.models.models import Scan
from app.services.intelligence.context_retriever import ContextRetriever
from app.services.orchestration.model_orchestrator import ModelPool, ModelOrchestrator
from app.core.database import SessionLocal

# Import agentic verification components
try:
    from app.services.intelligence.codebase_tools import CodebaseTools
    from app.services.intelligence.agent_runtime import AgenticVerifier
    AGENTIC_AVAILABLE = True
except ImportError:
    AGENTIC_AVAILABLE = False


class FindingVerifier:
    """Verifies draft findings using multi-model voting with adversarial analysis"""

    VOTE_PROMPT = """You are verifying a potential security vulnerability.

=== FINDING TO VERIFY ===
Title: {title}
Type: {vuln_type}
Severity: {severity}
Line: {line}

Reported Code:
{snippet}

Scanner's Reason: {reason}

=== PRE-FETCHED CONTEXT (already gathered for you) ===
{context}

=== VERIFICATION CRITERIA ===

IMPORTANT: Missing a real vulnerability is worse than a false positive, BUT low-quality findings waste developer time.
Your goal is to identify EXPLOITABLE vulnerabilities while filtering out safe patterns.

=== SAFE PATTERNS TO REJECT ===

These are FALSE POSITIVES - REJECT them:
- `(size + 7) & ~7` or similar alignment - standard idiom, unexploitable
- `strncpy(dst, src, sizeof(dst) - 1)` - bounded copy, safe even without explicit null-term
- `strncpy(dst, src, sizeof(dst)); dst[sizeof(dst)-1] = '\\0';` - bounded with null-term
- `strncpy(dst, src, N)` where N <= sizeof(dst) - size-limited is safe
- `snprintf(buf, sizeof(buf), ...)` - size-limited, safe
- `vsnprintf(buf, sizeof(buf), ...)` - size-limited, safe
- Integer overflow in display/logging only (no security impact)
- Functions with no callers and not exported (dead code)
- Missing null-termination claims when strncpy uses sizeof(dst)-1 (leaves room for null)

=== WEAKNESS PATTERNS ===

These are real but low-priority - mark as WEAKNESS:
- Theoretical overflow with no realistic attack path
- Missing null-termination where buffer is always overwritten
- Bad practice in non-security-critical code path
- DoS-only impact (no RCE, no data leak)

=== VERIFY PATTERNS ===

These are TRUE POSITIVES - VERIFY them:
- `system(user_input)` or `popen(user_input)` - command injection
- `strcpy(fixed_buf, user_input)` - unbounded copy
- `sprintf(buf, user_fmt)` where user controls format - format string
- `printf(user_str)` - format string (user string AS the format)
- `free(ptr); use(ptr);` - use-after-free
- SQL/path with concatenated user input - injection

=== DECISION GUIDE ===

VERIFY if:
1. Dangerous sink function (system, strcpy, printf with user format)
2. AND attacker data can reach it (trace the data flow)
3. AND security impact exists (RCE, memory corruption, data leak)

WEAKNESS if:
- Pattern is risky but impact is limited (DoS, info leak of non-sensitive data)
- OR requires unlikely conditions to exploit

REJECT if:
- Safe variant used (strncpy with limit, snprintf)
- OR standard safe idiom (alignment, bounded copy)
- OR no attacker-controlled input reaches the sink

=== RESPONSE ===
*VOTE: VERIFY, WEAKNESS, or REJECT
*CONFIDENCE: 0-100 (lower if uncertain)
*REASONING: [2-3 sentences explaining data flow and exploitability]
*END_VOTE"""

    def __init__(self, scan_id: int, orchestrator: ModelOrchestrator, context_retriever: ContextRetriever,
                 use_agentic: bool = False, agentic_model_pool: Optional[ModelPool] = None):
        self.scan_id = scan_id
        self.orchestrator = orchestrator
        self.context_retriever = context_retriever
        self.use_agentic = use_agentic and AGENTIC_AVAILABLE
        self.agentic_model_pool = agentic_model_pool

        # Initialize agentic verifier if enabled
        self._agentic_verifier = None
        self._codebase_tools = None

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

        # Prepare context data for each draft
        draft_contexts = []
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
            
            draft_contexts.append({
                'title': draft.title,
                'vuln_type': draft.vulnerability_type,
                'severity': draft.severity,
                'line': draft.line_number,
                'snippet': draft.snippet or '',
                'reason': draft.reason or '',
                'context': context
            })

        # Collect votes from ALL verifier models
        all_votes = []  # List of (model_name, [responses for each draft])

        # Run all models in parallel
        async def get_model_votes(pool: ModelPool) -> tuple:
            try:
                # Use custom prompt if configured, else default
                template = pool.config.verification_prompt_template or self.VOTE_PROMPT
                
                # Generate prompts specific to this model
                model_prompts = [template.format(**ctx) for ctx in draft_contexts]
                
                responses = await pool.call_batch(model_prompts)
                return (pool.config.name, responses)
            except Exception as e:
                print(f"Verifier {pool.config.name} failed: {e}")
                return (pool.config.name, ["" for _ in draft_contexts])

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
        import re

        vote = {
            'model': model_name,
            'decision': 'ABSTAIN',
            'confidence': 50,  # Default to 50 if not specified
            'reasoning': '',
            'attack_scenario': ''
        }

        if not response:
            vote['reasoning'] = 'No response from model'
            return vote

        response_lower = response.lower()

        # Extract vote decision
        if '*vote:' in response_lower:
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
                        nums = re.findall(r'\d+', line)
                        if nums:
                            vote['confidence'] = min(100, int(nums[0]))
                    except:
                        pass
                    break

        # Extract reasoning (supports both old and new format)
        reasoning_markers = ['*reasoning:', '*model_reasoning:']
        for marker in reasoning_markers:
            if marker in response_lower:
                start = response_lower.find(marker)
                # Find end marker
                end = response_lower.find('*end_vote', start)
                if end == -1:
                    end = response_lower.find('*attack_scenario:', start)

                if start != -1:
                    content_start = start + len(marker)
                    if end != -1:
                        vote['reasoning'] = response[content_start:end].strip()
                    else:
                        vote['reasoning'] = response[content_start:].strip()[:500]
                break

        # Extract attack scenario if present
        if '*attack_scenario:' in response_lower:
            start = response_lower.find('*attack_scenario:')
            end = response_lower.find('*end_vote', start)
            if start != -1:
                content_start = start + 17
                if end != -1:
                    vote['attack_scenario'] = response[content_start:end].strip()
                else:
                    vote['attack_scenario'] = response[content_start:].strip()[:500]

        return vote

    def _aggregate_votes(self, votes: List[dict], draft: DraftFinding) -> dict:
        """
        Aggregate votes from multiple models using 2/3 majority voting.
        With 3 verifiers, need at least 2 to agree on VERIFY/WEAKNESS.
        WEAKNESS votes count as partial VERIFY (creates Info/Low findings).
        """
        verify_count = 0
        weakness_count = 0
        reject_count = 0
        verify_score = 0
        weakness_score = 0
        reject_score = 0

        for vote in votes:
            weight = vote['confidence'] / 100.0 if vote['confidence'] > 0 else 0.5

            if vote['decision'] == 'VERIFY':
                verify_count += 1
                verify_score += weight
            elif vote['decision'] == 'WEAKNESS':
                weakness_count += 1
                weakness_score += weight
            elif vote['decision'] == 'REJECT':
                reject_count += 1
                reject_score += weight
            # ABSTAIN adds nothing

        total_votes = verify_count + weakness_count + reject_count

        # Count VERIFY+WEAKNESS as "not reject" votes
        positive_count = verify_count + weakness_count

        # Require 2/3 majority for verification (at least 2 out of 3 models)
        # If only 2 models, require both to agree
        # If 3 models, require at least 2 to agree
        majority_threshold = (total_votes + 1) // 2  # Ceiling division for majority
        if total_votes >= 3:
            majority_threshold = 2  # Explicit: need 2/3 for 3 models

        # WEAKNESS counts as half a VERIFY for weighted scoring
        combined_verify_score = verify_score + (weakness_score * 0.5)
        total_score = combined_verify_score + reject_score

        # Need majority COUNT (not just weighted score) to verify
        verified = positive_count >= majority_threshold and total_votes > 0

        # If unanimous reject, definitely not verified
        if reject_count == total_votes:
            verified = False

        # Determine if primarily weakness (for severity adjustment)
        is_weakness = weakness_count > verify_count and verified

        # Calculate overall confidence based on agreement
        if total_votes > 0:
            agreement_ratio = max(positive_count, reject_count) / total_votes
            confidence = int(agreement_ratio * 100)
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

    def _init_agentic_verifier(self, root_dir: str, db) -> bool:
        """Initialize agentic verifier with codebase tools for current scan."""
        if not AGENTIC_AVAILABLE or not self.agentic_model_pool:
            return False

        try:
            self._codebase_tools = CodebaseTools(
                scan_id=self.scan_id,
                root_dir=root_dir,
                db=db
            )
            self._agentic_verifier = AgenticVerifier(
                model_pool=self.agentic_model_pool,
                tools=self._codebase_tools,
                max_steps=8
            )
            return True
        except Exception as e:
            print(f"Failed to initialize agentic verifier: {e}")
            return False

    async def verify_with_agent(self, draft: DraftFinding) -> dict:
        """
        Verify a finding using agentic code navigation.
        The agent can explore the codebase to trace data flow and prove/disprove.
        """
        if not self._agentic_verifier:
            # Fall back to standard voting
            return await self.verify_single(draft)

        db = SessionLocal()
        try:
            # Get file path
            chunk = db.query(ScanFileChunk).filter(
                ScanFileChunk.id == draft.chunk_id
            ).first()

            if not chunk:
                return {'verified': False, 'reason': 'Chunk not found', 'votes': []}

            scan_file = db.query(ScanFile).filter(
                ScanFile.id == chunk.scan_file_id
            ).first()

            if not scan_file:
                return {'verified': False, 'reason': 'File not found', 'votes': []}

            file_path = os.path.basename(scan_file.file_path)

            # Run agentic verification
            result = await self._agentic_verifier.verify(
                title=draft.title,
                vuln_type=draft.vulnerability_type,
                severity=draft.severity,
                file_path=file_path,
                line_number=draft.line_number,
                snippet=draft.snippet or '',
                reason=draft.reason or ''
            )

            # Convert to standard result format
            return {
                'verified': result['verified'],
                'confidence': result['confidence'],
                'is_weakness': False,  # Agentic doesn't distinguish weakness
                'reason' if not result['verified'] else 'reasoning': result['reasoning'],
                'attack_vector': result.get('attack_path', ''),
                'votes': [{
                    'model': 'agentic',
                    'decision': 'VERIFY' if result['verified'] else 'REJECT',
                    'confidence': result['confidence'],
                    'reasoning': result['reasoning'],
                    'attack_scenario': result.get('attack_path', '')
                }],
                'agentic_trace': result.get('trace', ''),
                'title': draft.title,
                'adjusted_severity': draft.severity
            }

        except Exception as e:
            print(f"Agentic verification failed: {e}")
            # Fall back to standard voting
            return await self.verify_single(draft)
        finally:
            db.close()

    async def verify_batch_agentic(self, drafts: List[DraftFinding]) -> List[dict]:
        """
        Verify multiple draft findings using agentic verification.
        Runs sequentially since each verification is multi-turn.
        """
        if not self.use_agentic:
            return await self.verify_batch(drafts)

        # Initialize agentic verifier if not already done
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == self.scan_id).first()
            if not scan:
                return await self.verify_batch(drafts)

            if not self._agentic_verifier:
                if not self._init_agentic_verifier(scan.target_path, db):
                    return await self.verify_batch(drafts)
        finally:
            db.close()

        results = []
        for draft in drafts:
            result = await self.verify_with_agent(draft)
            results.append(result)

        return results

    async def hybrid_verify_batch(self, drafts: List[DraftFinding]) -> List[dict]:
        """
        Hybrid verification: Use voting first, then agentic for uncertain cases.
        This provides speed for clear cases and depth for ambiguous ones.
        """
        # First pass: standard voting
        voting_results = await self.verify_batch(drafts)

        if not self.use_agentic:
            return voting_results

        # Identify uncertain cases (close votes or high severity rejections)
        uncertain_indices = []
        for i, (result, draft) in enumerate(zip(voting_results, drafts)):
            verify_score = result.get('verify_score', 0)
            reject_score = result.get('reject_score', 0)

            # Check if uncertain (close vote or high severity rejection)
            margin = abs(verify_score - reject_score)
            is_close = margin < 0.5
            is_high_severity_reject = (
                not result['verified'] and
                draft.severity in ['Critical', 'High'] and
                result.get('confidence', 100) < 80
            )

            if is_close or is_high_severity_reject:
                uncertain_indices.append(i)

        if not uncertain_indices:
            return voting_results

        # Initialize agentic verifier
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == self.scan_id).first()
            if not scan or not self._init_agentic_verifier(scan.target_path, db):
                return voting_results
        finally:
            db.close()

        # Re-verify uncertain cases with agentic
        for i in uncertain_indices:
            draft = drafts[i]
            agentic_result = await self.verify_with_agent(draft)

            # Merge agentic result with voting result
            voting_results[i]['agentic_verified'] = agentic_result['verified']
            voting_results[i]['agentic_confidence'] = agentic_result.get('confidence', 50)
            voting_results[i]['agentic_trace'] = agentic_result.get('agentic_trace', '')

            # Let agentic override if high confidence
            if agentic_result.get('confidence', 0) >= 80:
                voting_results[i]['verified'] = agentic_result['verified']
                voting_results[i]['reasoning'] = agentic_result.get('reasoning', '')
                voting_results[i]['attack_vector'] = agentic_result.get('attack_vector', '')

        return voting_results
