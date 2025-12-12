"""
Prompt tuner service - standalone utility for testing verification prompts.

This service bypasses all scanning queues and makes direct API calls to LLMs
to test different prompt variations against ground truth test cases.
"""

import asyncio
import re
import time
from datetime import datetime
from typing import List, Dict, Optional
from sqlalchemy.orm import Session

from app.models.tuning_models import TuningPromptTemplate, TuningTestCase, TuningRun, TuningResult
from app.models.scanner_models import ModelConfig
from app.services.orchestration.model_orchestrator import ModelPool
from app.services.tuning.run_controller import TuningRunController


class PromptTuner:
    """Execute tuning runs - test prompts against ground truth test cases"""

    def __init__(self, db: Session):
        self.db = db

    async def run_tuning(
        self,
        model_ids: List[int],
        prompt_ids: List[int],
        test_case_ids: List[int],
        concurrency: int = 4,
        run_name: Optional[str] = None,
        run_description: Optional[str] = None,
    ) -> int:
        """
        Execute a tuning run with specified models, prompts, and test cases.

        Args:
            model_ids: List of model IDs to test
            prompt_ids: List of prompt template IDs to test
            test_case_ids: List of test case IDs to test
            concurrency: Number of concurrent requests (default: 4)
            run_name: Optional name for the run
            run_description: Optional description

        Returns:
            Run ID
        """
        # Create run record
        total_tests = len(model_ids) * len(prompt_ids) * len(test_case_ids)
        run = TuningRun(
            name=run_name,
            description=run_description,
            model_ids=model_ids,
            prompt_ids=prompt_ids,
            test_case_ids=test_case_ids,
            concurrency=concurrency,
            status="running",
            total_tests=total_tests,
            completed_tests=0,
        )
        self.db.add(run)
        self.db.commit()
        self.db.refresh(run)

        start_time = time.time()

        try:
            # Generate all test combinations
            tasks = []
            for model_id in model_ids:
                for prompt_id in prompt_ids:
                    for test_case_id in test_case_ids:
                        tasks.append((run.id, model_id, prompt_id, test_case_id))

            # Run tests with concurrency limit
            semaphore = asyncio.Semaphore(concurrency)
            results = await asyncio.gather(
                *[self._run_single_test(task, semaphore) for task in tasks],
                return_exceptions=True
            )

            # Count errors
            error_count = sum(1 for r in results if isinstance(r, Exception))
            if error_count > 0:
                run.status = "completed"
                run.error_message = f"{error_count} tests failed with errors"
            else:
                run.status = "completed"

            # Update run metrics
            run.completed_tests = len(results)
            run.total_duration_ms = (time.time() - start_time) * 1000
            run.completed_at = datetime.now()
            self.db.commit()

            return run.id

        except Exception as e:
            run.status = "failed"
            run.error_message = str(e)
            run.total_duration_ms = (time.time() - start_time) * 1000
            self.db.commit()
            raise

    async def run_tuning_with_existing_run(
        self,
        run_id: int,
        model_ids: List[int],
        prompt_ids: List[int],
        test_case_ids: List[int],
        concurrency: int = 4,
    ) -> int:
        """
        Execute tuning tests using an existing run record.
        Supports pause/resume/cancel via TuningRunController.

        Args:
            run_id: Existing TuningRun ID to update
            model_ids: List of model IDs to test
            prompt_ids: List of prompt template IDs to test
            test_case_ids: List of test case IDs to test
            concurrency: Number of concurrent requests (default: 4)

        Returns:
            Run ID
        """
        run = self.db.query(TuningRun).filter(TuningRun.id == run_id).first()
        if not run:
            raise ValueError(f"Run {run_id} not found")

        # Create run state for pause/resume/cancel control
        controller = TuningRunController.get_instance()
        run_state = controller.create_run_state(run_id)

        start_time = time.time()
        error_count = 0

        try:
            # Generate all test combinations
            tasks = []
            for model_id in model_ids:
                for prompt_id in prompt_ids:
                    for test_case_id in test_case_ids:
                        tasks.append((run.id, model_id, prompt_id, test_case_id))

            # Run tests sequentially with pause/cancel checks
            semaphore = asyncio.Semaphore(concurrency)

            for task in tasks:
                # Check if run was cancelled
                if run_state.cancel_event.is_set():
                    run.status = "cancelled"
                    self.db.commit()
                    break

                # Wait if paused (blocks until resumed)
                await run_state.pause_event.wait()

                # Check again after unpausing (might have been cancelled while paused)
                if run_state.cancel_event.is_set():
                    run.status = "cancelled"
                    self.db.commit()
                    break

                # Run the test
                try:
                    result_id = await self._run_single_test(task, semaphore)

                    # Increment completed count
                    run.completed_tests += 1
                    self.db.commit()

                    # Get the result from database to broadcast
                    result = self.db.query(TuningResult).filter(TuningResult.id == result_id).first()

                    if result:
                        # Broadcast result event to SSE subscribers
                        await controller.broadcast_event(run_id, {
                            "type": "result",
                            "data": {
                                "id": result.id,
                                "model_name": result.model_name,
                                "prompt_id": result.prompt_id,
                                "test_case_id": result.test_case_id,
                                "predicted_vote": result.predicted_vote,
                                "confidence": result.confidence,
                                "correct": result.correct,
                                "duration_ms": result.duration_ms,
                            },
                            "progress": {
                                "completed": run.completed_tests,
                                "total": run.total_tests,
                                "percent": (run.completed_tests / run.total_tests * 100) if run.total_tests > 0 else 0
                            }
                        })

                except Exception as e:
                    error_count += 1
                    # Error already logged in _run_single_test

            # Determine final status
            if run.status != "cancelled":
                if error_count > 0:
                    run.status = "completed"
                    run.error_message = f"{error_count} tests failed with errors"
                else:
                    run.status = "completed"

            # Update run metrics
            run.total_duration_ms = (time.time() - start_time) * 1000
            run.completed_at = datetime.now()
            self.db.commit()

            # Broadcast completion event
            await controller.broadcast_event(run_id, {
                "type": "completed",
                "status": run.status,
                "completed_tests": run.completed_tests,
                "total_tests": run.total_tests,
                "total_duration_ms": run.total_duration_ms,
                "error_message": run.error_message
            })

            return run.id

        except Exception as e:
            run.status = "failed"
            run.error_message = str(e)
            run.total_duration_ms = (time.time() - start_time) * 1000
            self.db.commit()

            # Broadcast failure event
            await controller.broadcast_event(run_id, {
                "type": "failed",
                "error": str(e)
            })

            raise

        finally:
            # Cleanup run state
            controller.cleanup_run(run_id)

    async def _run_single_test(self, task: tuple, semaphore: asyncio.Semaphore) -> Optional[int]:
        """
        Run a single test (one model + one prompt + one test case).

        Returns the result ID or raises exception on failure.
        """
        run_id, model_id, prompt_id, test_case_id = task

        async with semaphore:
            start_time = time.time()

            try:
                # Load test data
                model = self.db.query(ModelConfig).filter(ModelConfig.id == model_id).first()
                prompt_template = self.db.query(TuningPromptTemplate).filter(
                    TuningPromptTemplate.id == prompt_id
                ).first()
                test_case = self.db.query(TuningTestCase).filter(
                    TuningTestCase.id == test_case_id
                ).first()

                if not model or not prompt_template or not test_case:
                    raise ValueError(f"Missing model, prompt, or test case")

                # Get test case data with ALL fields for real verification format
                test_data = self._get_test_case_data(test_case)

                # Fill in prompt placeholders with comprehensive data
                full_prompt = prompt_template.template.format(**test_data)

                # Make direct LLM call (bypass queues)
                messages = [{"role": "user", "content": full_prompt}]
                response = await ModelPool.simple_chat_completion(
                    messages=messages,
                    model=model.name,
                    temperature=0.1,
                    max_tokens=2048,
                )

                raw_response = response.get("content", "")
                duration_ms = (time.time() - start_time) * 1000

                # Parse response to extract vote and confidence
                parsed = self._parse_verification_response(raw_response)

                # Check correctness
                correct = self._check_correctness(parsed["vote"], test_case.verdict)

                # Create result record
                result = TuningResult(
                    run_id=run_id,
                    model_id=model_id,
                    model_name=model.name,
                    prompt_id=prompt_id,
                    test_case_id=test_case_id,
                    full_prompt=full_prompt,
                    raw_response=raw_response,
                    predicted_vote=parsed["vote"],
                    confidence=parsed["confidence"],
                    reasoning=parsed["reasoning"],
                    correct=correct,
                    parse_success=parsed["parse_success"],
                    parse_error=parsed.get("parse_error"),
                    duration_ms=duration_ms,
                    tokens_in=response.get("usage", {}).get("prompt_tokens"),
                    tokens_out=response.get("usage", {}).get("completion_tokens"),
                )
                self.db.add(result)
                self.db.commit()
                self.db.refresh(result)

                return result.id

            except Exception as e:
                # Log error result
                result = TuningResult(
                    run_id=run_id,
                    model_id=model_id,
                    model_name=model.name if model else "unknown",
                    prompt_id=prompt_id,
                    test_case_id=test_case_id,
                    full_prompt=full_prompt if 'full_prompt' in locals() else "",
                    raw_response=None,
                    predicted_vote=None,
                    confidence=None,
                    reasoning=None,
                    correct=False,
                    parse_success=False,
                    parse_error=str(e),
                    duration_ms=(time.time() - start_time) * 1000,
                )
                self.db.add(result)
                self.db.commit()
                raise

    def _get_test_case_data(self, test_case: TuningTestCase) -> dict:
        """
        Get test case data in the EXACT format used by real verification.
        Returns dict matching the context passed to verifier _format_prompt()

        Args:
            test_case: The test case

        Returns:
            Dict with all placeholders for prompt formatting
        """
        # If draft_finding_id is set, load from draft_finding
        if test_case.draft_finding_id:
            from app.models.scanner_models import DraftFinding
            draft = self.db.query(DraftFinding).filter(
                DraftFinding.id == test_case.draft_finding_id
            ).first()

            if draft:
                file_path = draft.file_path or "Unknown"
                language = self._get_language_from_path(file_path)

                return {
                    # Primary placeholders (real verification format):
                    'file_path': file_path,
                    'language': language,
                    'finding_title': draft.title or "Unknown",
                    'finding_type': draft.vulnerability_type or "Unknown",
                    'finding_severity': draft.severity or "Medium",
                    'finding_line': draft.line_number or 0,
                    'finding_reason': draft.reason or "",
                    'code_snippet': draft.snippet or "",
                    'code_context': "",  # Would need context retriever

                    # Aliases for flexibility:
                    'title': draft.title or "Unknown",
                    'vuln_type': draft.vulnerability_type or "Unknown",
                    'vulnerability_type': draft.vulnerability_type or "Unknown",
                    'severity': draft.severity or "Medium",
                    'line': draft.line_number or 0,
                    'line_number': draft.line_number or 0,
                    'snippet': draft.snippet or "",
                    'reason': draft.reason or "",
                    'details': draft.reason or "",
                    'context': "",

                    # Backwards compat (old format):
                    'code': draft.snippet or "",
                    'claim': draft.reason or "",
                    'issue': draft.title or "",
                    'file': file_path,
                }

        # Fall back to test_case fields (with new column names)
        file_path = test_case.file_path or test_case.file or "unknown"
        return {
            # Primary placeholders:
            'file_path': file_path,
            'language': test_case.language or self._get_language_from_path(file_path),
            'finding_title': test_case.title or test_case.issue or "Unknown",
            'finding_type': test_case.vulnerability_type or test_case.issue or "Unknown",
            'finding_severity': test_case.severity or "Medium",
            'finding_line': test_case.line_number or 0,
            'finding_reason': test_case.reason or test_case.claim or "",
            'code_snippet': test_case.snippet or test_case.code or "",
            'code_context': "",

            # Aliases:
            'title': test_case.title or test_case.issue or "Unknown",
            'vuln_type': test_case.vulnerability_type or test_case.issue or "Unknown",
            'vulnerability_type': test_case.vulnerability_type or test_case.issue or "Unknown",
            'severity': test_case.severity or "Medium",
            'line': test_case.line_number or 0,
            'line_number': test_case.line_number or 0,
            'snippet': test_case.snippet or test_case.code or "",
            'reason': test_case.reason or test_case.claim or "",
            'details': test_case.reason or test_case.claim or "",
            'context': "",

            # Backwards compat:
            'code': test_case.snippet or test_case.code or "",
            'claim': test_case.reason or test_case.claim or "",
            'issue': test_case.title or test_case.issue or "",
            'file': file_path,
        }

    def _get_language_from_path(self, file_path: str) -> str:
        """Extract language from file extension"""
        if not file_path or file_path == "unknown":
            return "c"

        ext = file_path.lower().split('.')[-1] if '.' in file_path else ''
        language_map = {
            'c': 'c',
            'h': 'c',
            'cpp': 'cpp',
            'cc': 'cpp',
            'cxx': 'cpp',
            'hpp': 'cpp',
            'py': 'python',
            'js': 'javascript',
            'ts': 'typescript',
            'java': 'java',
            'go': 'go',
            'rs': 'rust',
        }
        return language_map.get(ext, 'c')

    def _parse_verification_response(self, response: str) -> Dict:
        """
        Parse verification response to extract vote, confidence, and reasoning.

        Supports multiple formats:
        - Vote: [verdict]
        - *VOTE: [verdict]
        - Confidence: [0-100]
        - Reasoning: [text]
        """
        result = {
            "vote": None,
            "confidence": None,
            "reasoning": None,
            "parse_success": True,
            "parse_error": None,
        }

        if not response:
            result["parse_success"] = False
            result["parse_error"] = "Empty response"
            return result

        # Strip thinking tags
        response = self._strip_thinking_tags(response)

        # Extract vote - handle multiple formats
        vote_patterns = [
            r'(?:\*)?Vote\s*:\s*(\w+)',
            r'(?:\*)?VOTE\s*:\s*(\w+)',
            r'(?:\*)?Decision\s*:\s*(\w+)',
            r'(?:\*)?Verdict\s*:\s*(\w+)',
            r'(?:\*)?VERIFIED\s*:\s*(\w+)',
        ]

        for pattern in vote_patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                vote = match.group(1).upper().strip()
                # Normalize vote values
                if vote in ["REAL", "VERIFIED", "TRUE", "YES", "VERIFY"]:
                    result["vote"] = "REAL"
                elif vote in ["FALSE_POSITIVE", "FP", "REJECTED", "FALSE", "NO", "REJECT"]:
                    result["vote"] = "FALSE_POSITIVE"
                elif vote in ["WEAKNESS", "WEAK", "CODE_SMELL"]:
                    result["vote"] = "WEAKNESS"
                elif vote in ["NEEDS_VERIFIED", "UNCLEAR", "UNCERTAIN", "UNSURE"]:
                    result["vote"] = "NEEDS_VERIFIED"
                else:
                    result["vote"] = vote
                break

        # Extract confidence
        conf_patterns = [
            r'(?:\*)?Confidence\s*:\s*(\d+)',
            r'(?:\*)?CONFIDENCE\s*:\s*(\d+)',
            r'confidence[:\s]+(\d+)',
        ]

        for pattern in conf_patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                try:
                    result["confidence"] = int(match.group(1))
                except ValueError:
                    pass
                break

        # Extract reasoning
        reasoning_patterns = [
            r'(?:\*)?Reasoning\s*:\s*(.+?)(?=\n\s*(?:\*)?[A-Z][a-z]+\s*:|$)',
            r'(?:\*)?REASONING\s*:\s*(.+?)(?=\n\s*(?:\*)?[A-Z][a-z]+\s*:|$)',
            r'(?:\*)?Analysis\s*:\s*(.+?)(?=\n\s*(?:\*)?[A-Z][a-z]+\s*:|$)',
            r'(?:\*)?Explanation\s*:\s*(.+?)(?=\n\s*(?:\*)?[A-Z][a-z]+\s*:|$)',
        ]

        for pattern in reasoning_patterns:
            match = re.search(pattern, response, re.IGNORECASE | re.DOTALL)
            if match:
                result["reasoning"] = match.group(1).strip()
                break

        # If we couldn't extract a vote, mark as parse failure
        if result["vote"] is None:
            result["parse_success"] = False
            result["parse_error"] = "Could not extract vote from response"

        return result

    def _strip_thinking_tags(self, text: str) -> str:
        """Remove thinking tags from reasoning models"""
        text = re.sub(r'<thinking>.*?</thinking>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'</thinking>', '', text, flags=re.IGNORECASE)
        text = re.sub(r'<thinking>', '', text, flags=re.IGNORECASE)
        text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'</think>', '', text, flags=re.IGNORECASE)
        text = re.sub(r'<think>', '', text, flags=re.IGNORECASE)
        return text

    def _check_correctness(self, predicted_vote: Optional[str], ground_truth: str) -> bool:
        """
        Check if predicted vote matches ground truth.

        Args:
            predicted_vote: Model's predicted vote (e.g., "REAL", "FALSE_POSITIVE")
            ground_truth: Ground truth verdict from test case

        Returns:
            True if prediction matches ground truth
        """
        if predicted_vote is None:
            return False

        # Normalize both values
        predicted = predicted_vote.upper().strip()
        truth = ground_truth.upper().strip()

        # Direct match
        if predicted == truth:
            return True

        # Handle aliases
        real_aliases = {"REAL", "VERIFIED", "TRUE", "VERIFY"}
        fp_aliases = {"FALSE_POSITIVE", "FP", "REJECTED", "REJECT"}
        weakness_aliases = {"WEAKNESS", "WEAK", "CODE_SMELL"}
        unclear_aliases = {"NEEDS_VERIFIED", "UNCLEAR", "UNCERTAIN"}

        if predicted in real_aliases and truth in real_aliases:
            return True
        if predicted in fp_aliases and truth in fp_aliases:
            return True
        if predicted in weakness_aliases and truth in weakness_aliases:
            return True
        if predicted in unclear_aliases and truth in unclear_aliases:
            return True

        return False

    def get_run_analysis(self, run_id: int) -> Dict:
        """
        Analyze results of a tuning run.

        Returns:
            Dict with overall metrics, per-model analysis, per-prompt analysis,
            per-test-case analysis, and model×prompt performance matrix.
        """
        results = self.db.query(TuningResult).filter(TuningResult.run_id == run_id).all()

        if not results:
            return {"error": "No results found for this run"}

        # Overall metrics
        total = len(results)
        correct = sum(1 for r in results if r.correct)
        parse_success = sum(1 for r in results if r.parse_success)
        accuracy = (correct / total) * 100 if total > 0 else 0
        parse_rate = (parse_success / total) * 100 if total > 0 else 0

        # Per-model analysis
        model_stats = {}
        for result in results:
            if result.model_name not in model_stats:
                model_stats[result.model_name] = {
                    "total": 0,
                    "correct": 0,
                    "parse_success": 0,
                    "avg_confidence": [],
                    "avg_duration_ms": [],
                }
            stats = model_stats[result.model_name]
            stats["total"] += 1
            if result.correct:
                stats["correct"] += 1
            if result.parse_success:
                stats["parse_success"] += 1
            if result.confidence is not None:
                stats["avg_confidence"].append(result.confidence)
            if result.duration_ms is not None:
                stats["avg_duration_ms"].append(result.duration_ms)

        # Calculate averages and accuracy for each model
        for model_name, stats in model_stats.items():
            stats["accuracy"] = (stats["correct"] / stats["total"]) * 100 if stats["total"] > 0 else 0
            stats["parse_rate"] = (stats["parse_success"] / stats["total"]) * 100 if stats["total"] > 0 else 0
            stats["avg_confidence"] = sum(stats["avg_confidence"]) / len(stats["avg_confidence"]) if stats["avg_confidence"] else None
            stats["avg_duration_ms"] = sum(stats["avg_duration_ms"]) / len(stats["avg_duration_ms"]) if stats["avg_duration_ms"] else None

        # Per-prompt analysis
        prompt_stats = {}
        for result in results:
            prompt_id = result.prompt_id
            if prompt_id not in prompt_stats:
                prompt = self.db.query(TuningPromptTemplate).filter(TuningPromptTemplate.id == prompt_id).first()
                prompt_stats[prompt_id] = {
                    "prompt_name": prompt.name if prompt else f"Prompt {prompt_id}",
                    "total": 0,
                    "correct": 0,
                    "parse_success": 0,
                }
            stats = prompt_stats[prompt_id]
            stats["total"] += 1
            if result.correct:
                stats["correct"] += 1
            if result.parse_success:
                stats["parse_success"] += 1

        for prompt_id, stats in prompt_stats.items():
            stats["accuracy"] = (stats["correct"] / stats["total"]) * 100 if stats["total"] > 0 else 0
            stats["parse_rate"] = (stats["parse_success"] / stats["total"]) * 100 if stats["total"] > 0 else 0

        # Per-test-case analysis (which cases are hardest?)
        case_stats = {}
        for result in results:
            case_id = result.test_case_id
            if case_id not in case_stats:
                test_case = self.db.query(TuningTestCase).filter(TuningTestCase.id == case_id).first()
                case_stats[case_id] = {
                    "case_name": test_case.name if test_case else f"Case {case_id}",
                    "verdict": test_case.verdict if test_case else "Unknown",
                    "total": 0,
                    "correct": 0,
                }
            stats = case_stats[case_id]
            stats["total"] += 1
            if result.correct:
                stats["correct"] += 1

        for case_id, stats in case_stats.items():
            stats["accuracy"] = (stats["correct"] / stats["total"]) * 100 if stats["total"] > 0 else 0

        # Model × Prompt performance matrix
        matrix = {}
        for result in results:
            key = (result.model_name, result.prompt_id)
            if key not in matrix:
                prompt = self.db.query(TuningPromptTemplate).filter(TuningPromptTemplate.id == result.prompt_id).first()
                matrix[key] = {
                    "model_name": result.model_name,
                    "prompt_name": prompt.name if prompt else f"Prompt {result.prompt_id}",
                    "total": 0,
                    "correct": 0,
                }
            matrix[key]["total"] += 1
            if result.correct:
                matrix[key]["correct"] += 1

        for key, stats in matrix.items():
            stats["accuracy"] = (stats["correct"] / stats["total"]) * 100 if stats["total"] > 0 else 0

        return {
            "overall": {
                "total_tests": total,
                "correct": correct,
                "accuracy": accuracy,
                "parse_success": parse_success,
                "parse_rate": parse_rate,
            },
            "by_model": model_stats,
            "by_prompt": prompt_stats,
            "by_test_case": case_stats,
            "matrix": list(matrix.values()),
        }
