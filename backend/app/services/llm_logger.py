"""
LLM Request/Response Logger for debugging parsing issues.

Usage:
    from app.services.llm_logger import llm_logger

    # Log a request/response
    llm_logger.log(
        scan_id=scan_id,
        model_name="llama3.3-70b",
        phase="scanner",
        request_prompt=prompt,
        raw_response=response,
        parsed_result=findings,
        parse_success=True,
        findings_count=len(findings)
    )
"""
import time
from typing import Optional, Any, List
from app.core.database import SessionLocal
from app.models.scanner_models import LLMRequestLog


class LLMLogger:
    """Logs LLM requests and responses for debugging."""

    def __init__(self):
        self._enabled = True

    def enable(self):
        """Enable logging."""
        self._enabled = True

    def disable(self):
        """Disable logging."""
        self._enabled = False

    def log(
        self,
        model_name: str,
        phase: str,
        request_prompt: str,
        raw_response: str,
        scan_id: Optional[int] = None,
        mr_review_id: Optional[int] = None,
        analyzer_name: Optional[str] = None,
        file_path: Optional[str] = None,
        chunk_id: Optional[int] = None,
        parsed_result: Optional[Any] = None,
        parse_success: bool = True,
        parse_error: Optional[str] = None,
        findings_count: int = 0,
        tokens_in: Optional[int] = None,
        tokens_out: Optional[int] = None,
        duration_ms: Optional[float] = None,
    ) -> Optional[int]:
        """
        Log an LLM request/response pair.

        Returns the log ID if successful, None otherwise.
        """
        if not self._enabled:
            return None

        try:
            db = SessionLocal()
            try:
                # Truncate very long prompts/responses to avoid DB issues
                # Keep first and last parts for context
                max_prompt_len = 50000
                max_response_len = 50000

                if len(request_prompt) > max_prompt_len:
                    half = max_prompt_len // 2
                    request_prompt = request_prompt[:half] + "\n\n... [TRUNCATED] ...\n\n" + request_prompt[-half:]

                if len(raw_response) > max_response_len:
                    half = max_response_len // 2
                    raw_response = raw_response[:half] + "\n\n... [TRUNCATED] ...\n\n" + raw_response[-half:]

                log_entry = LLMRequestLog(
                    scan_id=scan_id,
                    mr_review_id=mr_review_id,
                    model_name=model_name,
                    phase=phase,
                    analyzer_name=analyzer_name,
                    file_path=file_path,
                    chunk_id=chunk_id,
                    request_prompt=request_prompt,
                    raw_response=raw_response,
                    parsed_result=parsed_result,
                    parse_success=parse_success,
                    parse_error=parse_error,
                    findings_count=findings_count,
                    tokens_in=tokens_in,
                    tokens_out=tokens_out,
                    duration_ms=duration_ms,
                )

                db.add(log_entry)
                db.commit()
                return log_entry.id

            finally:
                db.close()

        except Exception as e:
            print(f"[LLMLogger] Failed to log request: {e}")
            return None

    def log_batch(
        self,
        model_name: str,
        phase: str,
        prompts: List[str],
        responses: List[str],
        scan_id: Optional[int] = None,
        analyzer_name: Optional[str] = None,
        file_paths: Optional[List[str]] = None,
        chunk_ids: Optional[List[int]] = None,
        parsed_results: Optional[List[Any]] = None,
        parse_successes: Optional[List[bool]] = None,
        parse_errors: Optional[List[str]] = None,
        findings_counts: Optional[List[int]] = None,
        durations_ms: Optional[List[float]] = None,
    ) -> List[int]:
        """
        Log a batch of LLM requests/responses.

        Returns list of log IDs for successful logs.
        """
        if not self._enabled:
            return []

        log_ids = []
        for i, (prompt, response) in enumerate(zip(prompts, responses)):
            log_id = self.log(
                model_name=model_name,
                phase=phase,
                request_prompt=prompt,
                raw_response=response,
                scan_id=scan_id,
                analyzer_name=analyzer_name,
                file_path=file_paths[i] if file_paths and i < len(file_paths) else None,
                chunk_id=chunk_ids[i] if chunk_ids and i < len(chunk_ids) else None,
                parsed_result=parsed_results[i] if parsed_results and i < len(parsed_results) else None,
                parse_success=parse_successes[i] if parse_successes and i < len(parse_successes) else True,
                parse_error=parse_errors[i] if parse_errors and i < len(parse_errors) else None,
                findings_count=findings_counts[i] if findings_counts and i < len(findings_counts) else 0,
                duration_ms=durations_ms[i] if durations_ms and i < len(durations_ms) else None,
            )
            if log_id:
                log_ids.append(log_id)

        return log_ids


# Global singleton instance
llm_logger = LLMLogger()
