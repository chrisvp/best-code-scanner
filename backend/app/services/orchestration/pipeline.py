import asyncio
import os
import hashlib
import re
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import case, func


def parse_cvss_score(cvss_value) -> Optional[float]:
    """Extract numeric CVSS score from various formats"""
    if not cvss_value:
        return None

    cvss_str = str(cvss_value).strip()

    # Try direct float conversion first
    try:
        score = float(cvss_str)
        if 0.0 <= score <= 10.0:
            return score
    except ValueError:
        pass

    # Extract score from CVSS vector (e.g., "CVSS:3.1/AV:N/..." or "9.8 (Critical)")
    match = re.search(r'(\d+\.?\d*)', cvss_str)
    if match:
        try:
            score = float(match.group(1))
            if 0.0 <= score <= 10.0:
                return score
        except ValueError:
            pass

    return None


def normalize_severity(severity_value: str) -> str:
    """
    Normalize severity values to valid options: Critical, High, Medium, Low.

    Handles common LLM output issues:
    - Trailing asterisks: "High*" -> "High"
    - Markdown artifacts: "**High**" -> "High"
    - Case variations: "HIGH" -> "High"
    - Compound values: "Medium-High" -> "High"
    - Verbose responses: "High (due to...)" -> "High"
    """
    if not severity_value:
        return "Medium"

    # Clean the value - strip markdown, asterisks, punctuation
    cleaned = str(severity_value).strip()
    cleaned = re.sub(r'[\*#\-_]+', '', cleaned)  # Remove *, #, -, _
    cleaned = re.sub(r'\s*\(.*\)$', '', cleaned)  # Remove trailing (...)
    cleaned = cleaned.strip()

    # Map to normalized values (case-insensitive)
    severity_map = {
        'critical': 'Critical',
        'crit': 'Critical',
        'high': 'High',
        'medium': 'Medium',
        'med': 'Medium',
        'moderate': 'Medium',
        'low': 'Low',
        'info': 'Low',
        'informational': 'Low',
        'weakness': 'Low',
    }

    cleaned_lower = cleaned.lower()

    # Direct match
    if cleaned_lower in severity_map:
        return severity_map[cleaned_lower]

    # Partial match (e.g., "high severity" -> "high")
    for key, value in severity_map.items():
        if key in cleaned_lower:
            return value

    # Default to Medium if unrecognized
    return "Medium"

from app.models.models import Scan, Finding
from app.models.scanner_models import (
    ScanConfig, ScanFile, ScanFileChunk, DraftFinding, VerifiedFinding, LLMCallMetric, ScanMetrics, ScanErrorLog,
    ScanProfile
)
from app.services.orchestration.model_orchestrator import ModelOrchestrator
from app.services.orchestration.cache import AnalysisCache
from app.services.orchestration.checkpoint import ScanCheckpoint
from app.services.ingestion import ingestion_service

# Error handling constants
MAX_CONSECUTIVE_ERRORS = 5  # Auto-pause after this many consecutive errors
MAX_RETRY_COUNT = 3  # Maximum retries per chunk
BASE_RETRY_DELAY = 2.0  # Base delay in seconds for exponential backoff


def classify_error(error: Exception) -> str:
    """Classify error type for logging and handling"""
    error_str = str(error).lower()
    if 'timeout' in error_str or 'timed out' in error_str:
        return 'timeout'
    if 'rate limit' in error_str or '429' in error_str:
        return 'rate_limit'
    if 'model' in error_str or 'inference' in error_str:
        return 'model_error'
    if 'parse' in error_str or 'json' in error_str:
        return 'parse_error'
    if 'connection' in error_str or 'network' in error_str:
        return 'connection_error'
    return 'unknown'


class ScanPipeline:
    """Coordinates the three-phase scanning pipeline"""

    def __init__(self, scan_id: int, config: ScanConfig, db: Session):
        self.scan_id = scan_id
        self.config = config
        self.db = db

        self.model_orchestrator: Optional[ModelOrchestrator] = None
        # Use scan-specific cache to avoid cross-contamination between scans
        self.cache = AnalysisCache.for_scan(scan_id)
        self.checkpoint = ScanCheckpoint(scan_id, db)

        self._scanner_complete = False
        self._verifier_complete = False

        # Error tracking for auto-pause
        self._consecutive_errors = 0
        self._is_auto_paused = False

    def _log_error(self, phase: str, error: Exception, chunk_id: int = None,
                   model_name: str = None, file_path: str = None, chunk_index: int = None):
        """Log error to database for tracking and recovery"""
        error_type = classify_error(error)
        error_log = ScanErrorLog(
            scan_id=self.scan_id,
            chunk_id=chunk_id,
            phase=phase,
            error_type=error_type,
            error_message=str(error)[:1000],  # Truncate long errors
            model_name=model_name,
            file_path=file_path,
            chunk_index=chunk_index
        )
        try:
            self.db.add(error_log)
            self.db.commit()
        except Exception:
            self.db.rollback()

        return error_type

    def _calculate_retry_delay(self, retry_count: int) -> float:
        """Calculate exponential backoff delay: 2s, 4s, 8s, ..."""
        return BASE_RETRY_DELAY * (2 ** retry_count)

    def _schedule_retry(self, chunk: ScanFileChunk, error: Exception, file_path: str = None):
        """Schedule a chunk for retry with exponential backoff"""
        chunk.retry_count += 1
        chunk.last_error = str(error)[:500]

        if chunk.retry_count <= MAX_RETRY_COUNT:
            # Calculate next retry time with exponential backoff
            delay = self._calculate_retry_delay(chunk.retry_count)
            chunk.next_retry_at = datetime.now(timezone.utc) + timedelta(seconds=delay)
            chunk.status = "pending"
            print(f"[Scan {self.scan_id}] Chunk {chunk.id} scheduled for retry #{chunk.retry_count} in {delay:.0f}s")
        else:
            # Max retries exceeded, mark as failed
            chunk.status = "failed"
            print(f"[Scan {self.scan_id}] Chunk {chunk.id} failed after {MAX_RETRY_COUNT} retries")

    def _check_auto_pause(self, error_occurred: bool) -> bool:
        """Check if scan should be auto-paused due to too many consecutive errors"""
        if error_occurred:
            self._consecutive_errors += 1
            if self._consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
                if scan.status == "running":
                    scan.status = "paused"
                    scan.logs = (scan.logs or "") + f"\n[AUTO-PAUSED] {self._consecutive_errors} consecutive errors"
                    self.db.commit()
                    self._is_auto_paused = True
                    print(f"[Scan {self.scan_id}] AUTO-PAUSED after {self._consecutive_errors} consecutive errors")
                return True
        else:
            # Reset error counter on success
            self._consecutive_errors = 0
        return False

    def _get_retry_ready_chunks(self, base_query):
        """Filter chunks that are ready for retry (past their next_retry_at time)"""
        now = datetime.now(timezone.utc)
        return base_query.filter(
            (ScanFileChunk.next_retry_at.is_(None)) |
            (ScanFileChunk.next_retry_at <= now)
        )

    def _log_timing(self, phase: str, duration: float):
        """Log timing to scan record"""
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        timing_log = f"{phase}: {duration:.1f}s"
        scan.logs = (scan.logs or "") + f"\n{timing_log}"
        self.db.commit()
        print(f"[Scan {self.scan_id}] {timing_log}")

    def _record_metric(self, model_name: str, phase: str, call_count: int, time_ms: float, tokens_in: int = 0):
        """Record LLM call metrics to database"""
        metric = LLMCallMetric(
            scan_id=self.scan_id,
            model_name=model_name,
            phase=phase,
            call_count=call_count,
            total_time_ms=time_ms,
            tokens_in=tokens_in
        )
        self.db.add(metric)
        self.db.commit()

    async def run(self):
        """Run the full scanning pipeline"""
        from app.services.intelligence.code_indexer import CodeIndexer

        total_start = time.time()

        # Initialize model orchestrator
        self.model_orchestrator = ModelOrchestrator(self.db, scan_id=self.scan_id)
        await self.model_orchestrator.initialize()

        try:
            # Get scan target and ingest
            scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
            target = scan.target_url
            scan_dir = f"sandbox/{self.scan_id}"

            # Ingest code
            ingest_start = time.time()
            if target.endswith(".zip") or target.endswith(".tar.gz"):
                scan_dir = await ingestion_service.extract_archive(target, str(self.scan_id))
            else:
                scan_dir = await ingestion_service.clone_repo(target, str(self.scan_id))
            self._log_timing("Ingestion", time.time() - ingest_start)

            # Build code index
            index_start = time.time()
            indexer = CodeIndexer(self.scan_id, self.db, self.cache)
            await indexer.build_index(str(scan_dir))
            self._log_timing("Indexing", time.time() - index_start)

            # Discover and chunk files
            chunk_start = time.time()
            await self._discover_and_chunk_files(str(scan_dir))
            self._log_timing("Chunking", time.time() - chunk_start)

            # Run three phases in parallel
            phases_start = time.time()
            await asyncio.gather(
                self._run_scanner_phase(),
                self._run_verifier_phase(),
                self._run_enricher_phase()
            )
            self._log_timing("Analysis phases", time.time() - phases_start)
            self._log_timing("Total", time.time() - total_start)

        finally:
            await self.model_orchestrator.shutdown()
            # Clean up scan-specific cache to free memory
            AnalysisCache.cleanup_scan(self.scan_id)
            print(f"[Scan {self.scan_id}] Cache cleaned up")

    async def run_from_verification(self, profile_id: int = None):
        """Run the pipeline starting from verification phase (skip scanning)

        This is used for re-validation with a different profile's verifiers.
        Draft findings are kept but reset to pending, then re-verified and enriched.
        """
        import time as time_module
        from app.services.intelligence.code_indexer import CodeIndexer

        total_start = time_module.time()

        # Initialize model orchestrator with the specified profile
        self.model_orchestrator = ModelOrchestrator(self.db, profile_id=profile_id, scan_id=self.scan_id)
        await self.model_orchestrator.initialize()

        try:
            scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
            scan_dir = f"sandbox/{self.scan_id}"

            # Rebuild code index for context retrieval
            if os.path.exists(scan_dir):
                index_start = time_module.time()
                indexer = CodeIndexer(self.scan_id, self.db, self.cache)
                await indexer.build_index(str(scan_dir))
                self._log_timing("Re-indexing", time_module.time() - index_start)

            # Mark scanner as complete since we're skipping it
            self._scanner_complete = True

            # Run verification and enrichment phases
            phases_start = time_module.time()
            await asyncio.gather(
                self._run_verifier_phase(),
                self._run_enricher_phase()
            )
            self._log_timing("Re-validation phases", time_module.time() - phases_start)
            self._log_timing("Re-validation total", time_module.time() - total_start)

        finally:
            await self.model_orchestrator.shutdown()
            AnalysisCache.cleanup_scan(self.scan_id)
            print(f"[Scan {self.scan_id}] Re-validation cache cleaned up")

    async def _discover_and_chunk_files(self, root_dir: str):
        """Discover files and create chunks for scanning"""
        from app.services.analysis.file_chunker import FileChunker
        import fnmatch
        from pathlib import PurePath

        # Use configured chunk size and strategy
        chunk_size = self.config.chunk_size or 3000
        chunk_strategy = getattr(self.config, 'chunk_strategy', 'smart') or 'smart'
        chunker = FileChunker(max_tokens=chunk_size, strategy=chunk_strategy)
        supported_extensions = {'.py', '.c', '.cpp', '.h', '.hpp'}

        # Get file filter pattern(s) from config or profile
        file_filter = getattr(self.config, 'file_filter', None)

        # If no explicit file_filter but using a profile, get combined filters from profile's analyzers
        if not file_filter and self.config.profile_id:
            profile = self.db.query(ScanProfile).filter(
                ScanProfile.id == self.config.profile_id
            ).first()
            if profile and profile.analyzers:
                # Collect unique file filters from all enabled analyzers
                profile_filters = set()
                for analyzer in profile.analyzers:
                    if analyzer.enabled and analyzer.file_filter:
                        for f in analyzer.file_filter.split(','):
                            if f.strip():
                                profile_filters.add(f.strip())
                if profile_filters:
                    file_filter = ','.join(profile_filters)
                    print(f"[Scan {self.scan_id}] Using file filter from profile analyzers: {profile_filters}")

        filter_patterns = []
        if file_filter:
            # Support comma-separated patterns: "sshd.c,auth.c" or single: "*.c"
            filter_patterns = [p.strip() for p in file_filter.split(',') if p.strip()]
            print(f"[Scan {self.scan_id}] File filter active: {filter_patterns}")

        # Track chunk sizes for metrics
        chunk_token_sizes = []
        files_checked = 0
        files_matched = 0

        for root, _, files in os.walk(root_dir):
            for filename in files:
                ext = os.path.splitext(filename)[1].lower()  # Case-insensitive extension check
                if ext not in supported_extensions:
                    continue

                files_checked += 1
                file_path = os.path.join(root, filename)

                # Apply file filter if specified
                if filter_patterns:
                    # Get relative path from root_dir for matching
                    rel_path = os.path.relpath(file_path, root_dir)
                    matched = False
                    for pattern in filter_patterns:
                        # For simple extension patterns like *.c, match against filename
                        # For path patterns, use PurePath.match() which supports ** globs
                        if fnmatch.fnmatch(filename.lower(), pattern.lower()):
                            matched = True
                            break
                        if fnmatch.fnmatch(rel_path.lower(), pattern.lower()):
                            matched = True
                            break
                        # Also try PurePath.match for recursive patterns
                        if PurePath(rel_path).match(pattern):
                            matched = True
                            break
                    if not matched:
                        continue

                files_matched += 1

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    file_hash = hashlib.md5(content.encode()).hexdigest()

                    # Determine risk level
                    risk_level = self._assess_risk(file_path)

                    # Create ScanFile
                    scan_file = ScanFile(
                        scan_id=self.scan_id,
                        file_path=file_path,
                        file_hash=file_hash,
                        risk_level=risk_level,
                        status="pending"
                    )
                    self.db.add(scan_file)
                    self.db.flush()

                    # Create chunks
                    chunks = chunker.chunk_file(file_path, content)
                    lines = content.split('\n')
                    for chunk_data in chunks:
                        # Calculate chunk token size
                        chunk_lines = lines[chunk_data['start_line'] - 1:chunk_data['end_line']]
                        chunk_content = '\n'.join(chunk_lines)
                        chunk_tokens = len(chunk_content) // 4  # Rough estimate
                        chunk_token_sizes.append(chunk_tokens)

                        chunk = ScanFileChunk(
                            scan_file_id=scan_file.id,
                            chunk_index=chunk_data['chunk_index'],
                            chunk_type=chunk_data['chunk_type'],
                            symbol_name=chunk_data.get('symbol_name'),
                            start_line=chunk_data['start_line'],
                            end_line=chunk_data['end_line'],
                            content_hash=chunk_data['content_hash'],
                            status="pending"
                        )
                        self.db.add(chunk)

                except Exception as e:
                    print(f"Error processing {file_path}: {e}")
                    continue

        # Log file filter results
        if filter_patterns:
            print(f"[Scan {self.scan_id}] File filter: {files_checked} supported files checked, {files_matched} matched filter")

        self.db.commit()

        # Save chunk metrics (update if exists, insert if not)
        if chunk_token_sizes:
            existing_metrics = self.db.query(ScanMetrics).filter(ScanMetrics.scan_id == self.scan_id).first()
            if existing_metrics:
                existing_metrics.total_chunks = len(chunk_token_sizes)
                existing_metrics.avg_chunk_tokens = sum(chunk_token_sizes) / len(chunk_token_sizes)
                existing_metrics.min_chunk_tokens = min(chunk_token_sizes)
                existing_metrics.max_chunk_tokens = max(chunk_token_sizes)
                existing_metrics.chunk_size_setting = chunk_size
                scan_metrics = existing_metrics
            else:
                scan_metrics = ScanMetrics(
                    scan_id=self.scan_id,
                    total_chunks=len(chunk_token_sizes),
                    avg_chunk_tokens=sum(chunk_token_sizes) / len(chunk_token_sizes),
                    min_chunk_tokens=min(chunk_token_sizes),
                    max_chunk_tokens=max(chunk_token_sizes),
                    chunk_size_setting=chunk_size
                )
                self.db.add(scan_metrics)
            self.db.commit()
            print(f"[Scan {self.scan_id}] Chunks: {len(chunk_token_sizes)}, avg tokens: {scan_metrics.avg_chunk_tokens:.0f}")

    def _assess_risk(self, file_path: str) -> str:
        """Assess risk level of a file based on path patterns"""
        path_lower = file_path.lower()

        high_risk = ['auth', 'login', 'password', 'crypt', 'token', 'session',
                     'admin', 'root', 'sudo', 'exec', 'eval', 'system',
                     'sql', 'query', 'database', 'upload', 'parse']

        low_risk = ['test', 'spec', 'mock', 'doc', 'example', 'sample',
                    'vendor', 'third_party', 'external']

        if any(pattern in path_lower for pattern in low_risk):
            return "low"
        if any(pattern in path_lower for pattern in high_risk):
            return "high"
        return "normal"

    async def _run_scanner_phase(self):
        """Phase 1: Scan chunks for draft findings"""
        from app.services.analysis.draft_scanner import DraftScanner, ProfileAwareScanner
        from app.services.analysis.static_detector import StaticPatternDetector

        # Load static detection rules from database (once per scan)
        static_detector = StaticPatternDetector.load_from_db(self.db)
        print(f"Loaded {len(static_detector._rules)} static detection rules")

        # Check if a scan profile is configured
        profile = None
        if self.config.profile_id:
            profile = self.db.query(ScanProfile).filter(
                ScanProfile.id == self.config.profile_id,
                ScanProfile.enabled == True
            ).first()

        # Use profile-aware scanner if profile is configured
        if profile:
            print(f"[Scan {self.scan_id}] Using scan profile: {profile.name}")
            scanner = ProfileAwareScanner(
                self.scan_id, profile, self.model_orchestrator,
                self.cache, static_detector=static_detector
            )
            use_profile_scanning = True
        else:
            # Fall back to standard multi-model scanning
            analyzers = self.model_orchestrator.get_analyzers()
            if not analyzers:
                self._scanner_complete = True
                return

            # Use single model or all analyzers based on config
            if self.config.multi_model_scan:
                scan_models = analyzers
            else:
                # Use just the primary analyzer (first one)
                scan_models = [analyzers[0]] if analyzers else []

            scanner = DraftScanner(self.scan_id, scan_models, self.cache, static_detector=static_detector)
            use_profile_scanning = False

        batch_size = self.config.batch_size or 10

        # Track timing and tokens per model (for non-profile scanning)
        if use_profile_scanning:
            # Profile scanning tracks metrics internally
            model_times = {}
            model_calls = {}
            model_tokens = {}
            scan_models = []
        else:
            model_times = {pool.config.name: 0.0 for pool in scan_models}
            model_calls = {pool.config.name: 0 for pool in scan_models}
            model_tokens = {pool.config.name: 0 for pool in scan_models}

        while True:
            # Check for pause
            scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
            if scan.status == "paused":
                await asyncio.sleep(1)
                continue

            # Get batch of pending chunks that are ready for retry
            base_query = self.db.query(ScanFileChunk).join(ScanFile).filter(
                ScanFile.scan_id == self.scan_id,
                ScanFileChunk.status == "pending",
                ScanFileChunk.retry_count <= MAX_RETRY_COUNT
            )
            # Filter out chunks that are waiting for retry backoff
            chunks = self._get_retry_ready_chunks(base_query).order_by(
                case({'high': 0, 'normal': 1, 'low': 2}, value=ScanFile.risk_level)
            ).limit(batch_size).all()

            if not chunks:
                break

            # Mark as scanning
            for chunk in chunks:
                chunk.status = "scanning"
            self.db.commit()

            # Scan batch with timing
            try:
                batch_start = time.time()
                # Use profile-aware method or standard scan_batch
                if use_profile_scanning:
                    results = await scanner.scan_batch_with_profile(chunks)
                else:
                    results = await scanner.scan_batch(chunks)
                batch_time = (time.time() - batch_start) * 1000  # ms

                # Estimate tokens for this batch (based on line count)
                batch_tokens = sum((chunk.end_line - chunk.start_line + 1) * 40 for chunk in chunks)

                # Attribute time and tokens to each model (split evenly for now)
                # Skip metric tracking for profile scanning (tracked per-analyzer internally)
                if not use_profile_scanning:
                    for pool in scan_models:
                        model_times[pool.config.name] += batch_time / len(scan_models)
                        model_calls[pool.config.name] += len(chunks)
                        model_tokens[pool.config.name] += batch_tokens

                # Save draft findings with dedup keys
                for chunk in chunks:
                    # Get file path for dedup key
                    scan_file = self.db.query(ScanFile).filter(
                        ScanFile.id == chunk.scan_file_id
                    ).first()
                    file_path = scan_file.file_path if scan_file else "unknown"

                    findings = results.get(chunk.id, [])
                    for f in findings:
                        line_num = int(f.get('line', f.get('line_number', 0))) if f.get('line') or f.get('line_number') else 0
                        vuln_type = f.get('type', f.get('vulnerability_type', 'Unknown'))

                        # Create dedup key: file + line + type
                        dedup_key = hashlib.md5(
                            f"{file_path}:{line_num}:{vuln_type}".encode()
                        ).hexdigest()

                        # Track source - either model list or analyzer name
                        if use_profile_scanning:
                            analyzer_name = f.get('_analyzer', 'unknown')
                            model_name = f.get('_model', 'unknown')
                            source_info = [f"{analyzer_name}:{model_name}"]
                        else:
                            source_info = f.get('_models')

                        draft = DraftFinding(
                            scan_id=self.scan_id,
                            chunk_id=chunk.id,
                            title=f.get('title', 'Unknown'),
                            vulnerability_type=vuln_type,
                            severity=normalize_severity(f.get('severity', 'Medium')),
                            line_number=line_num,
                            snippet=f.get('snippet', ''),
                            reason=f.get('reason', ''),
                            auto_detected=f.get('auto_detected', False),
                            initial_votes=f.get('_votes', f.get('votes', 1)),
                            source_models=source_info,  # Track which models/analyzers detected this
                            dedup_key=dedup_key,
                            status="pending"
                        )
                        self.db.add(draft)

                    chunk.status = "scanned"

                self.db.commit()

                # Success - reset error counter
                self._check_auto_pause(error_occurred=False)

            except Exception as e:
                print(f"Scanner error: {e}")
                self.db.rollback()

                # Log error to database
                for chunk in chunks:
                    scan_file = self.db.query(ScanFile).filter(
                        ScanFile.id == chunk.scan_file_id
                    ).first()
                    file_path = scan_file.file_path if scan_file else None

                    self._log_error(
                        phase="scanner",
                        error=e,
                        chunk_id=chunk.id,
                        file_path=file_path,
                        chunk_index=chunk.chunk_index
                    )

                    # Schedule for retry with exponential backoff
                    self._schedule_retry(chunk, e, file_path)

                try:
                    self.db.commit()
                except Exception:
                    self.db.rollback()

                # Check if we should auto-pause
                if self._check_auto_pause(error_occurred=True):
                    # Wait for resume
                    while True:
                        await asyncio.sleep(2)
                        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
                        if scan.status != "paused":
                            self._consecutive_errors = 0  # Reset on resume
                            break

        # Deduplicate drafts if enabled
        if self.config.deduplicate_drafts:
            self._deduplicate_drafts()

        # Record scanner metrics
        for model_name, total_time in model_times.items():
            if model_calls.get(model_name, 0) > 0:
                self._record_metric(model_name, "scanner", model_calls[model_name], total_time, model_tokens.get(model_name, 0))

        self._scanner_complete = True

    def _deduplicate_drafts(self):
        """Merge duplicate drafts based on dedup_key, combining votes"""
        from sqlalchemy import func as sqla_func

        # Find all dedup_keys with multiple drafts
        duplicates = self.db.query(
            DraftFinding.dedup_key,
            sqla_func.count(DraftFinding.id).label('count')
        ).filter(
            DraftFinding.scan_id == self.scan_id,
            DraftFinding.dedup_key.isnot(None)
        ).group_by(DraftFinding.dedup_key).having(
            sqla_func.count(DraftFinding.id) > 1
        ).all()

        merged_count = 0
        for dedup_key, count in duplicates:
            # Get all drafts with this key
            drafts = self.db.query(DraftFinding).filter(
                DraftFinding.scan_id == self.scan_id,
                DraftFinding.dedup_key == dedup_key
            ).order_by(DraftFinding.id).all()

            if len(drafts) > 1:
                # Keep first, merge votes and source models, delete rest
                primary = drafts[0]
                total_votes = sum(d.initial_votes or 1 for d in drafts)
                primary.initial_votes = total_votes

                # Merge source_models from all duplicates
                all_models = set()
                for d in drafts:
                    if d.source_models:
                        all_models.update(d.source_models)
                if all_models:
                    primary.source_models = list(all_models)

                for dup in drafts[1:]:
                    self.db.delete(dup)
                    merged_count += 1

        if merged_count > 0:
            self.db.commit()
            print(f"[Scan {self.scan_id}] Deduplicated {merged_count} duplicate drafts")

    async def _run_verifier_phase(self):
        """Phase 2: Verify draft findings with context"""
        from app.services.analysis.verifier import FindingVerifier
        from app.services.intelligence.context_retriever import ContextRetriever
        from app.services.orchestration.model_orchestrator import ModelPool

        # Check we have at least one verifier
        if not self.model_orchestrator.get_verifiers():
            # Fall back to analyzers as verifiers
            if not self.model_orchestrator.get_analyzers():
                self._verifier_complete = True
                return

        # Load profile for agentic verifier settings
        profile = None
        agentic_mode = "skip"
        agentic_model_pool = None
        agentic_max_steps = 8

        if self.config.profile_id:
            profile = self.db.query(ScanProfile).filter(
                ScanProfile.id == self.config.profile_id
            ).first()

            if profile:
                agentic_mode = profile.agentic_verifier_mode or "skip"
                agentic_max_steps = profile.agentic_verifier_max_steps or 8

                # Create model pool for agentic verifier if configured
                if agentic_mode != "skip" and profile.agentic_verifier_model_id:
                    agentic_model_config = self.db.query(ModelConfig).filter(
                        ModelConfig.id == profile.agentic_verifier_model_id
                    ).first()

                    if agentic_model_config:
                        agentic_model_pool = ModelPool(agentic_model_config)
                        await agentic_model_pool.start()
                        print(f"[Scan {self.scan_id}] Agentic verifier: {agentic_mode} mode with {agentic_model_config.name} (max {agentic_max_steps} steps)")

        context_retriever = ContextRetriever(self.scan_id, self.db)
        # Pass orchestrator and agentic settings to verifier
        use_agentic = agentic_mode != "skip" and agentic_model_pool is not None
        verifier = FindingVerifier(
            self.scan_id,
            self.model_orchestrator,
            context_retriever,
            use_agentic=use_agentic,
            agentic_model_pool=agentic_model_pool,
            agentic_max_steps=agentic_max_steps
        )
        batch_size = self.config.batch_size or 10
        min_votes = self.config.min_votes_to_verify or 1

        # Track timing and tokens per verifier model
        verifier_models = self.model_orchestrator.get_verifiers() or self.model_orchestrator.get_analyzers()
        model_times = {pool.config.name: 0.0 for pool in verifier_models}
        model_calls = {pool.config.name: 0 for pool in verifier_models}
        model_tokens = {pool.config.name: 0 for pool in verifier_models}

        # Skip low-vote drafts if min_votes > 1
        if min_votes > 1:
            skipped = self.db.query(DraftFinding).filter(
                DraftFinding.scan_id == self.scan_id,
                DraftFinding.status == "pending",
                DraftFinding.initial_votes < min_votes
            ).update({DraftFinding.status: "skipped"})
            if skipped > 0:
                self.db.commit()
                print(f"[Scan {self.scan_id}] Skipped {skipped} drafts with < {min_votes} votes")

        while True:
            # Check for pause
            scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
            if scan.status == "paused":
                await asyncio.sleep(1)
                continue

            # Get batch of pending drafts with sufficient votes, prioritized by severity
            drafts = self.db.query(DraftFinding).filter(
                DraftFinding.scan_id == self.scan_id,
                DraftFinding.status == "pending",
                DraftFinding.initial_votes >= min_votes
            ).order_by(
                case({'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}, value=DraftFinding.severity),
                DraftFinding.initial_votes.desc(),  # Higher votes first
                DraftFinding.created_at
            ).limit(batch_size).all()

            if not drafts:
                if self._scanner_complete:
                    # Double-check no more pending
                    remaining = self.db.query(DraftFinding).filter(
                        DraftFinding.scan_id == self.scan_id,
                        DraftFinding.status == "pending",
                        DraftFinding.initial_votes >= min_votes
                    ).count()
                    if remaining == 0:
                        break
                await asyncio.sleep(0.5)
                continue

            # Mark as verifying
            for draft in drafts:
                draft.status = "verifying"
            self.db.commit()

            # Verify batch with timing (using appropriate method based on agentic mode)
            try:
                batch_start = time.time()
                if agentic_mode == "full":
                    results = await verifier.verify_batch_agentic(drafts)
                elif agentic_mode == "hybrid":
                    results = await verifier.hybrid_verify_batch(drafts)
                else:
                    results = await verifier.verify_batch(drafts)
                batch_time = (time.time() - batch_start) * 1000  # ms

                # Estimate tokens for this batch (draft snippet + reason)
                batch_tokens = sum(
                    (len(draft.snippet or '') + len(draft.reason or '')) // 4
                    for draft in drafts
                )

                # Attribute time and tokens to each verifier model
                for pool in verifier_models:
                    model_times[pool.config.name] += batch_time / len(verifier_models)
                    model_calls[pool.config.name] += len(drafts)
                    model_tokens[pool.config.name] += batch_tokens

                for draft, result in zip(drafts, results):
                    # Calculate total votes
                    votes = result.get('votes', [])
                    verify_count = sum(1 for v in votes if v.get('decision') == 'VERIFY')
                    weakness_count = sum(1 for v in votes if v.get('decision') == 'WEAKNESS')
                    reject_count = sum(1 for v in votes if v.get('decision') == 'REJECT')

                    if result.get('verified'):
                        # VERIFY: Real vulnerability, proceed to enrichment
                        adj_sev = result.get('adjusted_severity')
                        verified = VerifiedFinding(
                            draft_id=draft.id,
                            scan_id=self.scan_id,
                            title=result.get('title', draft.title),
                            confidence=result.get('confidence', 50),
                            attack_vector=result.get('attack_vector', ''),
                            data_flow=result.get('data_flow', ''),
                            adjusted_severity=normalize_severity(adj_sev) if adj_sev else None,
                            status="pending"
                        )
                        self.db.add(verified)
                        draft.status = "verified"
                        draft.verification_votes = verify_count
                        draft.verification_notes = result.get('reasoning', '')[:500]

                    elif result.get('is_weakness'):
                        # WEAKNESS: Accepted as code quality issue, skip enrichment
                        # Does NOT create a VerifiedFinding, does NOT count toward findings total
                        draft.status = "weakness"
                        draft.verification_votes = weakness_count
                        draft.verification_notes = result.get('reasoning', result.get('reason', ''))[:500]

                    else:
                        # REJECT: False positive, discarded
                        draft.status = "rejected"
                        draft.verification_votes = reject_count
                        draft.verification_notes = result.get('reason', '')[:500]

                self.db.commit()

            except Exception as e:
                print(f"Verifier error: {e}")
                for draft in drafts:
                    draft.status = "pending"
                self.db.commit()

        # Record verifier metrics
        for model_name, total_time in model_times.items():
            if model_calls.get(model_name, 0) > 0:
                self._record_metric(model_name, "verifier", model_calls[model_name], total_time, model_tokens.get(model_name, 0))

        # Cleanup agentic model pool if used
        if agentic_model_pool:
            await agentic_model_pool.stop()

        self._verifier_complete = True

    async def _run_enricher_phase(self):
        """Phase 3: Generate full reports for verified findings"""
        from app.services.analysis.enricher import FindingEnricher

        enricher_pool = self.model_orchestrator.get_primary_analyzer()
        if not enricher_pool:
            return

        enricher = FindingEnricher(enricher_pool, self.db)
        batch_size = 3

        # Track timing and tokens for enricher model
        enricher_time = 0.0
        enricher_calls = 0
        enricher_tokens = 0

        while True:
            # Check for pause
            scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
            if scan.status == "paused":
                await asyncio.sleep(1)
                continue

            # Get batch of pending verified findings
            verified_list = self.db.query(VerifiedFinding).filter(
                VerifiedFinding.scan_id == self.scan_id,
                VerifiedFinding.status == "pending"
            ).limit(batch_size).all()

            if not verified_list:
                if self._verifier_complete:
                    remaining = self.db.query(VerifiedFinding).filter(
                        VerifiedFinding.scan_id == self.scan_id,
                        VerifiedFinding.status == "pending"
                    ).count()
                    if remaining == 0:
                        break
                await asyncio.sleep(0.5)
                continue

            # Mark as enriching
            for v in verified_list:
                v.status = "enriching"
            self.db.commit()

            # Enrich batch with timing
            try:
                batch_start = time.time()
                results = await enricher.enrich_batch(verified_list)
                batch_time = (time.time() - batch_start) * 1000  # ms
                enricher_time += batch_time
                enricher_calls += len(verified_list)

                # Estimate tokens for this batch
                batch_tokens = sum(
                    (len(v.title or '') + len(v.attack_vector or '') + len(v.data_flow or '')) // 4
                    for v in verified_list
                )
                enricher_tokens += batch_tokens

                for v, result in zip(verified_list, results):
                    # Get the draft to find file info
                    draft = self.db.query(DraftFinding).filter(
                        DraftFinding.id == v.draft_id
                    ).first()

                    chunk = self.db.query(ScanFileChunk).filter(
                        ScanFileChunk.id == draft.chunk_id
                    ).first() if draft else None

                    scan_file = self.db.query(ScanFile).filter(
                        ScanFile.id == chunk.scan_file_id
                    ).first() if chunk else None

                    finding = Finding(
                        scan_id=self.scan_id,
                        verified_id=v.id,
                        file_path=scan_file.file_path if scan_file else "unknown",
                        line_number=draft.line_number if draft else 0,
                        severity=normalize_severity(v.adjusted_severity or result.get('severity', 'Medium')),
                        description=result.get('finding', v.title),
                        snippet=result.get('impacted_code', draft.snippet if draft else ''),
                        remediation=result.get('remediation_steps', ''),
                        category=result.get('category', ''),
                        cvss_score=parse_cvss_score(result.get('cvss')),
                        vulnerability_details=result.get('vulnerability_details', ''),
                        proof_of_concept=result.get('proof_of_concept', ''),
                        corrected_code=result.get('corrected_code', ''),
                        remediation_steps=result.get('remediation_steps', ''),
                        references=result.get('references', '')
                    )
                    self.db.add(finding)
                    v.status = "complete"

                self.db.commit()

            except Exception as e:
                print(f"Enricher error: {e}")
                for v in verified_list:
                    v.status = "pending"
                self.db.commit()

        # Record enricher metrics
        if enricher_calls > 0:
            self._record_metric(enricher_pool.config.name, "enricher", enricher_calls, enricher_time, enricher_tokens)
