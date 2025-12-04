"""
LLM Request/Response Logger for debugging parsing issues.

Usage:
    from app.services.llm_logger import llm_logger

    # Log a pending request first, then update with response
    log_id = llm_logger.log_pending(
        scan_id=scan_id,
        model_name="llama3.3-70b",
        phase="scanner",
        request_prompt=prompt,
    )
    # ... make LLM call ...
    llm_logger.log_response(
        log_id=log_id,
        raw_response=response,
        parsed_result=findings,
        parse_success=True,
        findings_count=len(findings)
    )

    # Or log both at once (legacy)
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

    def _truncate(self, text: str, max_len: int = 50000) -> str:
        """Truncate text keeping first and last parts."""
        if not text or len(text) <= max_len:
            return text
        half = max_len // 2
        return text[:half] + "\n\n... [TRUNCATED] ...\n\n" + text[-half:]

    def log_pending(
        self,
        model_name: str,
        phase: str,
        request_prompt: str,
        scan_id: Optional[int] = None,
        mr_review_id: Optional[int] = None,
        analyzer_name: Optional[str] = None,
        file_path: Optional[str] = None,
        chunk_id: Optional[int] = None,
    ) -> Optional[int]:
        """
        Log a pending LLM request (before the response is received).

        Returns the log ID to use when updating with the response.
        """
        if not self._enabled:
            return None

        try:
            db = SessionLocal()
            try:
                log_entry = LLMRequestLog(
                    scan_id=scan_id,
                    mr_review_id=mr_review_id,
                    model_name=model_name,
                    phase=phase,
                    analyzer_name=analyzer_name,
                    file_path=file_path,
                    chunk_id=chunk_id,
                    request_prompt=self._truncate(request_prompt),
                    status="pending",
                )

                db.add(log_entry)
                db.commit()
                return log_entry.id

            finally:
                db.close()

        except Exception as e:
            print(f"[LLMLogger] Failed to log pending request: {e}")
            return None

    def log_response(
        self,
        log_id: int,
        raw_response: str,
        parsed_result: Optional[Any] = None,
        parse_success: bool = True,
        parse_error: Optional[str] = None,
        findings_count: int = 0,
        tokens_in: Optional[int] = None,
        tokens_out: Optional[int] = None,
        duration_ms: Optional[float] = None,
        status: str = "completed",
    ) -> bool:
        """
        Update a pending log entry with the response.

        Returns True if successful, False otherwise.
        """
        if not self._enabled or not log_id:
            return False

        try:
            db = SessionLocal()
            try:
                log_entry = db.query(LLMRequestLog).filter(LLMRequestLog.id == log_id).first()
                if not log_entry:
                    return False

                log_entry.raw_response = self._truncate(raw_response)
                log_entry.parsed_result = parsed_result
                log_entry.parse_success = parse_success
                log_entry.parse_error = parse_error
                log_entry.findings_count = findings_count
                log_entry.tokens_in = tokens_in
                log_entry.tokens_out = tokens_out
                log_entry.duration_ms = duration_ms
                log_entry.status = status

                db.commit()
                return True

            finally:
                db.close()

        except Exception as e:
            print(f"[LLMLogger] Failed to update response: {e}")
            return False

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
        Log an LLM request/response pair (legacy method - logs as completed).

        Returns the log ID if successful, None otherwise.
        """
        if not self._enabled:
            return None

        try:
            db = SessionLocal()
            try:
                log_entry = LLMRequestLog(
                    scan_id=scan_id,
                    mr_review_id=mr_review_id,
                    model_name=model_name,
                    phase=phase,
                    analyzer_name=analyzer_name,
                    file_path=file_path,
                    chunk_id=chunk_id,
                    request_prompt=self._truncate(request_prompt),
                    raw_response=self._truncate(raw_response),
                    parsed_result=parsed_result,
                    parse_success=parse_success,
                    parse_error=parse_error,
                    findings_count=findings_count,
                    tokens_in=tokens_in,
                    tokens_out=tokens_out,
                    duration_ms=duration_ms,
                    status="completed",
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
