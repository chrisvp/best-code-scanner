import asyncio
import os
from typing import List, Dict, Optional

from app.models.scanner_models import DraftFinding, ScanFileChunk, ScanFile, VerificationVote, ProfileVerifier
from app.models.models import Scan
from app.services.intelligence.context_retriever import ContextRetriever
from app.services.orchestration.model_orchestrator import ModelPool, ModelOrchestrator
from app.core.database import SessionLocal
from app.services.analysis.universal_parser import VoteParser
from app.services.analysis.output_formats import get_output_format

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

{output_format}"""

    def __init__(self, scan_id: int, orchestrator: ModelOrchestrator, context_retriever: ContextRetriever,
                 use_agentic: bool = False, agentic_model_pool: Optional[ModelPool] = None,
                 agentic_max_steps: int = 8, profile_id: int = None):
        self.scan_id = scan_id
        self.orchestrator = orchestrator
        self.context_retriever = context_retriever
        self.use_agentic = use_agentic and AGENTIC_AVAILABLE
        self.agentic_model_pool = agentic_model_pool
        self.agentic_max_steps = agentic_max_steps
        self.profile_id = profile_id

        # Initialize agentic verifier if enabled
        self._agentic_verifier = None
        self._codebase_tools = None

        # Cache profile verifiers if profile_id is set
        self._profile_verifiers: Dict[int, ProfileVerifier] = {}  # model_id -> ProfileVerifier
        if profile_id:
            self._load_profile_verifiers()

    def _load_profile_verifiers(self):
        """Load profile verifiers and cache by model_id"""
        db = SessionLocal()
        try:
            verifiers = db.query(ProfileVerifier).filter(
                ProfileVerifier.profile_id == self.profile_id,
                ProfileVerifier.enabled == True
            ).all()
            # Detach from session to avoid refresh errors
            for v in verifiers:
                db.expunge(v)
                self._profile_verifiers[v.model_id] = v
            print(f"[Verifier] Loaded {len(verifiers)} profile verifiers for profile {self.profile_id}")
        finally:
            db.close()

    def _format_prompt(self, template: str, ctx: dict, output_mode: str = "markers") -> str:
        """Format a prompt template with context and output format (examples are combined in output_format)"""
        format_ctx = dict(ctx)

        # Inject output_format if the template contains the placeholder
        # Note: examples are now combined into output_format templates
        if '{output_format}' in template:
            format_ctx['output_format'] = get_output_format("verifier", output_mode)

        return template.format(**format_ctx)

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
                # Check for profile verifier configuration
                profile_verifier = self._profile_verifiers.get(pool.config.id)

                if profile_verifier and profile_verifier.prompt_template:
                    # Use profile verifier's prompt and output settings
                    template = profile_verifier.prompt_template
                    output_mode = profile_verifier.output_mode or "markers"
                    json_schema = profile_verifier.json_schema
                else:
                    # Fall back to model config or default
                    template = pool.config.verification_prompt_template or self.VOTE_PROMPT
                    output_mode = "markers"
                    json_schema = None

                # Generate prompts with output_format injection
                model_prompts = [self._format_prompt(template, ctx, output_mode) for ctx in draft_contexts]

                # Set logging context for the model pool
                pool.set_log_context(
                    scan_id=self.scan_id,
                    phase='verifier',
                )

                responses = await pool.call_batch(
                    model_prompts,
                    output_mode=output_mode,
                    json_schema=json_schema
                )
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
            raw_responses = []

            for model_name, responses in all_votes:
                response = responses[draft_idx] if draft_idx < len(responses) else ""
                raw_responses.append(response)
                vote = self._parse_vote(response, model_name)
                votes.append(vote)

            # Log votes to database for debugging
            self._log_votes(draft, votes, raw_responses)

            # Aggregate: majority vote wins
            result = self._aggregate_votes(votes, draft)
            results.append(result)

        return results

    # Shared parser instance for vote parsing
    _vote_parser = VoteParser()

    def _parse_vote(self, response: str, model_name: str) -> dict:
        """Parse a single model's vote response using universal parser"""
        vote = {
            'model': model_name,
            'decision': 'ABSTAIN',
            'confidence': 50,
            'reasoning': '',
            'attack_scenario': ''
        }

        if not response:
            vote['reasoning'] = 'No response from model'
            return vote

        # Use the universal VoteParser for fuzzy parsing
        parsed = self._vote_parser.parse_vote(response)

        vote['decision'] = parsed.get('decision', 'ABSTAIN')
        vote['confidence'] = parsed.get('confidence', 50)
        vote['reasoning'] = parsed.get('reasoning', '')
        vote['attack_scenario'] = parsed.get('attack_scenario', '')

        return vote

    def _log_votes(self, draft: DraftFinding, votes: List[dict], raw_responses: List[str] = None):
        """Log individual votes to the verification_votes table for debugging."""
        db = SessionLocal()
        try:
            for i, vote in enumerate(votes):
                raw_response = raw_responses[i] if raw_responses and i < len(raw_responses) else None

                vote_record = VerificationVote(
                    scan_id=self.scan_id,
                    draft_finding_id=draft.id,
                    model_name=vote.get('model', 'unknown'),
                    decision=vote.get('decision', 'ABSTAIN'),
                    confidence=vote.get('confidence', 50),
                    reasoning=vote.get('reasoning', '')[:2000] if vote.get('reasoning') else None,
                    attack_scenario=vote.get('attack_scenario', '')[:1000] if vote.get('attack_scenario') else None,
                    raw_response=raw_response[:5000] if raw_response else None,
                    parse_success=vote.get('parse_success', True),
                    format_detected=vote.get('format_detected'),
                    vote_weight=vote.get('weight', 1.0)
                )
                db.add(vote_record)

            db.commit()
        except Exception as e:
            print(f"Failed to log votes: {e}")
            db.rollback()
        finally:
            db.close()

    def _aggregate_votes(self, votes: List[dict], draft: DraftFinding) -> dict:
        """
        Aggregate votes from multiple models.

        Voting logic:
        - VERIFY: Majority voted VERIFY -> verified vulnerability, proceed to enrichment
        - WEAKNESS: Majority voted WEAKNESS -> accepted as code quality issue, skip enrichment
        - REJECT: Majority voted REJECT (or no majority) -> false positive, discarded

        WEAKNESS does NOT count toward VERIFY. They are separate categories.
        """
        verify_count = 0
        weakness_count = 0
        reject_count = 0
        abstain_count = 0
        verify_score = 0
        weakness_score = 0
        reject_score = 0

        for vote in votes:
            weight = vote.get('weight', 1.0) * (vote['confidence'] / 100.0 if vote['confidence'] > 0 else 0.5)

            if vote['decision'] == 'VERIFY':
                verify_count += 1
                verify_score += weight
            elif vote['decision'] == 'WEAKNESS':
                weakness_count += 1
                weakness_score += weight
            elif vote['decision'] == 'REJECT':
                reject_count += 1
                reject_score += weight
            else:  # ABSTAIN
                abstain_count += 1

        # Only count actual votes (not abstentions)
        total_votes = verify_count + weakness_count + reject_count

        if total_votes == 0:
            # All abstained - needs cleanup or reject
            return {
                'verified': False,
                'is_weakness': False,
                'confidence': 0,
                'votes': votes,
                'verify_count': 0,
                'weakness_count': 0,
                'reject_count': 0,
                'reason': 'All models abstained (parsing failures)'
            }

        # Calculate majority threshold
        majority_threshold = (total_votes + 1) // 2  # Ceiling for majority
        if total_votes >= 3:
            majority_threshold = 2  # Need 2/3 for 3+ models

        # Determine outcome - each category needs majority independently
        # VERIFY wins if it has majority of VERIFY votes
        # WEAKNESS wins if it has majority AND more than VERIFY
        # Otherwise REJECT

        is_verified = verify_count >= majority_threshold
        is_weakness = weakness_count >= majority_threshold and weakness_count > verify_count
        is_rejected = reject_count >= majority_threshold or (not is_verified and not is_weakness)

        # Calculate confidence based on agreement
        if is_verified:
            confidence = int((verify_count / total_votes) * 100)
        elif is_weakness:
            confidence = int((weakness_count / total_votes) * 100)
        elif is_rejected:
            confidence = int((reject_count / total_votes) * 100)
        else:
            confidence = 0

        # Build result
        result = {
            'verified': is_verified,
            'is_weakness': is_weakness,
            'rejected': is_rejected,
            'confidence': confidence,
            'votes': votes,
            'verify_count': verify_count,
            'weakness_count': weakness_count,
            'reject_count': reject_count,
            'abstain_count': abstain_count,
            'verify_score': round(verify_score, 2),
            'weakness_score': round(weakness_score, 2),
            'reject_score': round(reject_score, 2)
        }

        if is_verified:
            # Find best VERIFY vote for details
            verify_votes = [v for v in votes if v['decision'] == 'VERIFY']
            best_vote = max(verify_votes, key=lambda v: v['confidence']) if verify_votes else None

            if best_vote:
                result['title'] = draft.title
                result['attack_vector'] = best_vote.get('attack_scenario', '')
                result['adjusted_severity'] = draft.severity
                result['data_flow'] = ''
                result['reasoning'] = best_vote.get('reasoning', '')

        elif is_weakness:
            # Find best WEAKNESS vote for details
            weakness_votes = [v for v in votes if v['decision'] == 'WEAKNESS']
            best_vote = max(weakness_votes, key=lambda v: v['confidence']) if weakness_votes else None

            if best_vote:
                result['title'] = draft.title
                result['adjusted_severity'] = 'Weakness'
                result['reasoning'] = best_vote.get('reasoning', '')
                result['reason'] = best_vote.get('reasoning', '')

        else:
            # Rejected - find best reject vote for reason
            reject_votes = [v for v in votes if v['decision'] == 'REJECT']
            best_reject = max(reject_votes, key=lambda v: v['confidence']) if reject_votes else None
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
                max_steps=self.agentic_max_steps,
                scan_id=self.scan_id
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
            if not self._agentic_verifier:
                # Get codebase path from first scan file
                scan_file = db.query(ScanFile).filter(ScanFile.scan_id == self.scan_id).first()
                if not scan_file:
                    return await self.verify_batch(drafts)
                # Extract codebase root from file path (e.g., sandbox/3/src/file.c -> sandbox/3)
                import os
                codebase_path = scan_file.file_path
                # Walk up to find sandbox root
                while codebase_path and os.path.basename(os.path.dirname(codebase_path)) != 'sandbox':
                    codebase_path = os.path.dirname(codebase_path)
                if not codebase_path or not os.path.exists(codebase_path):
                    codebase_path = f"sandbox/{self.scan_id}"
                if not self._init_agentic_verifier(codebase_path, db):
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
            if not self._agentic_verifier:
                # Get codebase path from first scan file
                scan_file = db.query(ScanFile).filter(ScanFile.scan_id == self.scan_id).first()
                if not scan_file:
                    return voting_results
                import os
                codebase_path = scan_file.file_path
                while codebase_path and os.path.basename(os.path.dirname(codebase_path)) != 'sandbox':
                    codebase_path = os.path.dirname(codebase_path)
                if not codebase_path or not os.path.exists(codebase_path):
                    codebase_path = f"sandbox/{self.scan_id}"
                if not self._init_agentic_verifier(codebase_path, db):
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
