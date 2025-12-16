import asyncio
import os
import hashlib
import re
import time
from datetime import datetime, timedelta
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
    ScanProfile, ModelConfig
)
from app.services.orchestration.model_orchestrator import ModelOrchestrator
from app.services.orchestration.cache import AnalysisCache
from app.services.orchestration.checkpoint import ScanCheckpoint
from app.services.orchestration.queue_manager import phase_allocator
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
            chunk.next_retry_at = datetime.now().astimezone() + timedelta(seconds=delay)
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
        now = datetime.now().astimezone()
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

    def _update_phase(self, phase: str):
        """Update the current phase in the database"""
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if scan:
            scan.current_phase = phase
            self.db.commit()
            print(f"[Scan {self.scan_id}] Phase: {phase}")

    async def _check_paused(self) -> bool:
        """Check if scan is paused and wait if so. Returns True if should continue, False if stopped."""
        while True:
            scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
            if not scan:
                return False
            if scan.status == "paused":
                await asyncio.sleep(1)
                continue
            if scan.status in ("failed", "completed", "stopped"):
                return False
            return True

    async def run(self):
        """Run the full scanning pipeline with resume support"""
        from app.services.intelligence.code_indexer import CodeIndexer

        total_start = time.time()

        # Initialize model orchestrator with profile_id for profile-specific verifiers
        profile_id = self.config.profile_id if self.config else None
        self.model_orchestrator = ModelOrchestrator(self.db, profile_id=profile_id, scan_id=self.scan_id)
        await self.model_orchestrator.initialize()

        try:
            # Get scan and determine where to resume from
            scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
            target = scan.target_url
            scan_dir = f"sandbox/{self.scan_id}"
            current_phase = scan.current_phase or "queued"

            # Define phase order for comparison
            phase_order = ["queued", "ingestion", "indexing", "chunking", "scanning", "verifying", "enriching", "completed"]
            current_phase_idx = phase_order.index(current_phase) if current_phase in phase_order else 0

            # Skip phases that are already complete
            skip_ingestion = current_phase_idx > phase_order.index("ingestion")
            skip_indexing = current_phase_idx > phase_order.index("indexing")
            skip_chunking = current_phase_idx > phase_order.index("chunking")

            print(f"[Scan {self.scan_id}] Resuming from phase: {current_phase}")

            # Check if paused before starting
            if not await self._check_paused():
                return

            # Ingest code (skip if already done)
            if not skip_ingestion:
                self._update_phase("ingestion")
                ingest_start = time.time()
                if self.config.source_scan_id:
                    # Reuse existing scan's sandbox (no copy - just reference it)
                    # Pass db to trace through source_scan_id chain if needed
                    scan_dir = await ingestion_service.copy_from_scan(
                        str(self.config.source_scan_id), str(self.scan_id), db=self.db
                    )
                elif target.endswith(".zip") or target.endswith(".tar.gz"):
                    scan_dir = await ingestion_service.extract_archive(target, str(self.scan_id))
                else:
                    scan_dir = await ingestion_service.clone_repo(target, str(self.scan_id))
                self._log_timing("Ingestion", time.time() - ingest_start)

                if not await self._check_paused():
                    return
            else:
                print(f"[Scan {self.scan_id}] Skipping ingestion (already complete)")

            # Build code index (skip if already done)
            if not skip_indexing:
                self._update_phase("indexing")
                index_start = time.time()
                indexer = CodeIndexer(self.scan_id, self.db, self.cache)
                await indexer.build_index(str(scan_dir))
                self._log_timing("Indexing", time.time() - index_start)

                if not await self._check_paused():
                    return
            else:
                print(f"[Scan {self.scan_id}] Skipping indexing (already complete)")
                # Still need to rebuild cache for context retrieval
                indexer = CodeIndexer(self.scan_id, self.db, self.cache)
                await indexer.build_index(str(scan_dir))

            # Discover and chunk files (skip if already done)
            if not skip_chunking:
                self._update_phase("chunking")
                chunk_start = time.time()
                await self._discover_and_chunk_files(str(scan_dir))
                self._log_timing("Chunking", time.time() - chunk_start)

                if not await self._check_paused():
                    return
            else:
                print(f"[Scan {self.scan_id}] Skipping chunking (already complete)")

            # Update phase to scanning (the parallel phases track their own progress)
            self._update_phase("scanning")

            # Register with phase allocator for auto-adaptive slot allocation
            # Use scanner_concurrency as the base for total slots
            total_slots = self.config.scanner_concurrency or 10
            phase_allocator.register_scan(self.scan_id, total_slots)

            # Run three phases in parallel
            phases_start = time.time()
            try:
                await asyncio.gather(
                    self._run_scanner_phase(),
                    self._run_verifier_phase(),
                    self._run_enricher_phase()
                )
            finally:
                # Unregister from phase allocator when done
                phase_allocator.unregister_scan(self.scan_id)
            self._log_timing("Analysis phases", time.time() - phases_start)
            self._log_timing("Total", time.time() - total_start)

            # Mark as completed
            self._update_phase("completed")

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
            scan_dir = self._resolve_scan_directory()

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

    def _resolve_scan_directory(self) -> str:
        """Resolve the actual scan directory, tracing back through rescan chains.

        For rescans, the sandbox/{scan_id} directory doesn't exist because rescans
        reuse the original scan's sandbox. This method traces the source_scan_id
        chain to find the original sandbox with the actual code.
        """
        # Start with the default path for this scan
        scan_dir = f"sandbox/{self.scan_id}"
        if os.path.exists(scan_dir):
            return scan_dir

        # If no direct sandbox, trace back through source_scan_id chain
        if not self.config or not self.config.source_scan_id:
            return scan_dir  # No rescan chain, return default (will fail exists check)

        current_scan_id = str(self.config.source_scan_id)
        visited = []

        while current_scan_id:
            if current_scan_id in visited:
                break  # Cycle detection
            visited.append(current_scan_id)

            # Check if this scan's sandbox exists
            candidate_dir = f"sandbox/{current_scan_id}"
            if os.path.exists(candidate_dir):
                print(f"[Scan {self.scan_id}] Using sandbox from scan {current_scan_id}")
                return candidate_dir

            # Try to find the parent scan's source_scan_id
            config = self.db.query(ScanConfig).filter(
                ScanConfig.scan_id == int(current_scan_id)
            ).first()
            if config and config.source_scan_id:
                current_scan_id = str(config.source_scan_id)
            else:
                break

        # Nothing found, return original path (will fail exists check)
        return scan_dir

    async def _run_joern_scanner(self, profile: ScanProfile, mode: str):
        """Run Joern CPG-based vulnerability scanning

        Modes:
        - hybrid: Create DraftFindings, let verification phase handle them
        - joern: Create DraftFindings, auto-promote to VerifiedFindings with "joern" vote
        """
        from app.services.analysis.joern_scanner import JoernScanner
        from app.models.scanner_models import VerificationVote

        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        scan_dir = self._resolve_scan_directory()

        if not scan_dir or not os.path.exists(scan_dir):
            print(f"[Scan {self.scan_id}] Joern: Scan directory not found: {scan_dir}")
            return

        # Get Joern settings from profile
        query_set = getattr(profile, 'joern_query_set', 'default') or 'default'
        chunk_strategy = getattr(profile, 'joern_chunk_strategy', 'directory') or 'directory'
        max_files_per_cpg = getattr(profile, 'joern_max_files_per_cpg', 100) or 100

        print(f"[Scan {self.scan_id}] Starting Joern scan (mode={mode}, queries={query_set})")

        try:
            joern_scanner = JoernScanner(
                scan_id=self.scan_id,
                source_path=scan_dir,
                query_set=query_set,
                chunk_strategy=chunk_strategy,
                max_files_per_cpg=max_files_per_cpg,
                db=self.db
            )

            findings = await joern_scanner.scan()
            print(f"[Scan {self.scan_id}] Joern found {len(findings)} potential issues")

            # Convert Joern findings to DraftFindings
            created_drafts = []
            for f in findings:
                # Get or create ScanFile for this finding
                file_path = os.path.join(scan_dir, f.get('file_path', ''))
                scan_file = self.db.query(ScanFile).filter(
                    ScanFile.scan_id == self.scan_id,
                    ScanFile.file_path == file_path
                ).first()

                chunk_id = None
                if scan_file:
                    # Find the chunk containing this line
                    line_num = f.get('line_number', 0)
                    chunk = self.db.query(ScanFileChunk).filter(
                        ScanFileChunk.scan_file_id == scan_file.id,
                        ScanFileChunk.start_line <= line_num,
                        ScanFileChunk.end_line >= line_num
                    ).first()
                    if chunk:
                        chunk_id = chunk.id

                vuln_type = f.get('type', f.get('vulnerability_type', 'Unknown'))
                line_num = f.get('line', f.get('line_number', 0))

                # Create dedup key
                dedup_key = hashlib.md5(
                    f"{file_path}:{line_num}:{vuln_type}".encode()
                ).hexdigest()

                draft = DraftFinding(
                    scan_id=self.scan_id,
                    chunk_id=chunk_id,
                    title=f.get('title', 'Unknown'),
                    vulnerability_type=vuln_type,
                    severity=normalize_severity(f.get('severity', 'Medium')),
                    line_number=line_num,
                    file_path=file_path,  # Store file path directly for Joern findings
                    snippet=f.get('snippet', ''),
                    reason=f.get('reason', ''),
                    auto_detected=True,  # Joern findings are deterministic
                    initial_votes=1,
                    source_models=['joern-cpg'],
                    analyzer_id=None,
                    analyzer_name='joern',
                    dedup_key=dedup_key,
                    status="pending" if mode == "hybrid" else "verified"
                )
                self.db.add(draft)
                created_drafts.append(draft)

            self.db.commit()
            print(f"[Scan {self.scan_id}] Created {len(findings)} draft findings from Joern")

            # In joern-only mode, auto-promote drafts to verified findings
            # This skips the LLM verification phase entirely
            if mode == 'joern' and created_drafts:
                print(f"[Scan {self.scan_id}] Auto-promoting {len(created_drafts)} Joern findings (skipping verification)")

                for draft in created_drafts:
                    # Create a "joern" verification vote to track that verification was skipped
                    vote = VerificationVote(
                        scan_id=self.scan_id,
                        draft_finding_id=draft.id,
                        model_name='joern-cpg',
                        verifier_id=None,
                        decision='VERIFY',
                        confidence=100,  # Joern pattern matching is deterministic
                        reasoning='Auto-verified by Joern CPG analysis (verification phase skipped)',
                        vote_weight=1.0
                    )
                    self.db.add(vote)

                    # Create VerifiedFinding for enrichment phase
                    verified = VerifiedFinding(
                        draft_id=draft.id,
                        scan_id=self.scan_id,
                        title=draft.title,
                        confidence=100,
                        attack_vector=f"Joern CPG pattern match: {draft.vulnerability_type}",
                        data_flow='',
                        adjusted_severity=draft.severity,
                        status="pending"  # Ready for enrichment
                    )
                    self.db.add(verified)

                    draft.status = "verified"
                    draft.verification_votes = 1
                    draft.verification_notes = "Auto-verified by Joern (joern-only mode)"

                self.db.commit()
                print(f"[Scan {self.scan_id}] Created {len(created_drafts)} verified findings for enrichment")

        except Exception as e:
            print(f"[Scan {self.scan_id}] Joern scanner error: {e}")
            import traceback
            traceback.print_exc()

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

        # Check if Joern scanning is enabled
        # Modes:
        #   - llm: LLM scan → verify → enrich (default)
        #   - joern: Joern scan → enrich (skip verify - deterministic findings)
        #   - hybrid: Joern + LLM scan → verify → enrich
        first_phase_method = getattr(profile, 'first_phase_method', 'llm') if profile else 'llm'
        if first_phase_method in ('joern', 'hybrid'):
            await self._run_joern_scanner(profile, first_phase_method)
            if first_phase_method == 'joern':
                # Joern-only mode - skip LLM scanning, findings go straight to enrichment
                self._scanner_complete = True
                self._verifier_complete = True  # Skip verification for deterministic findings
                return
            # Hybrid mode continues to LLM scanning below

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

            # Update phase allocator with pending work count (for adaptive allocation)
            pending_count = self._get_retry_ready_chunks(base_query).count()
            phase_allocator.update_queue_depth(self.scan_id, "scanner", pending_count)

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
                            analyzer_id = f.get('_analyzer_id')
                            model_name = f.get('_model', 'unknown')
                            source_info = [f"{analyzer_name}:{model_name}"]
                        else:
                            analyzer_name = None
                            analyzer_id = None
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
                            analyzer_id=analyzer_id,  # Link to ProfileAnalyzer
                            analyzer_name=analyzer_name,  # Denormalized for display
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
                        # Detach from session to avoid refresh errors later
                        self.db.expunge(agentic_model_config)
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
            agentic_max_steps=agentic_max_steps,
            profile_id=self.config.profile_id
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

            # Update phase allocator with pending draft count (for adaptive allocation)
            pending_drafts = self.db.query(DraftFinding).filter(
                DraftFinding.scan_id == self.scan_id,
                DraftFinding.status == "pending",
                DraftFinding.initial_votes >= min_votes
            ).count()
            phase_allocator.update_queue_depth(self.scan_id, "verifier", pending_drafts)

            if not drafts:
                if self._scanner_complete:
                    # Double-check no more pending
                    if pending_drafts == 0:
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
                    real_count = sum(1 for v in votes if v.get('decision') == 'REAL')
                    weakness_count = sum(1 for v in votes if v.get('decision') == 'WEAKNESS')
                    false_positive_count = sum(1 for v in votes if v.get('decision') == 'FALSE_POSITIVE')
                    needs_verified_count = sum(1 for v in votes if v.get('decision') == 'NEEDS_VERIFIED')

                    if result.get('needs_agentic'):
                        # NEEDS_VERIFIED: Majority voted for agentic verification
                        # Mark as pending for agentic verification (can be handled in future iteration)
                        draft.status = "needs_agentic"
                        draft.verification_votes = needs_verified_count
                        draft.verification_notes = result.get('reason', 'Requires agentic verification')[:500]
                        # Note: Actual agentic verification can be triggered separately

                    elif result.get('verified'):
                        # REAL: Real vulnerability, proceed to enrichment
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
                        draft.verification_votes = real_count
                        draft.verification_notes = result.get('reasoning', '')[:500]

                    elif result.get('is_weakness'):
                        # WEAKNESS: Accepted as code quality issue, skip enrichment
                        # Does NOT create a VerifiedFinding, does NOT count toward findings total
                        draft.status = "weakness"
                        draft.verification_votes = weakness_count
                        draft.verification_notes = result.get('reasoning', result.get('reason', ''))[:500]

                    else:
                        # FALSE_POSITIVE: Scanner mistake, discarded
                        draft.status = "rejected"
                        draft.verification_votes = false_positive_count
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
        from app.models.scanner_models import ScanProfile

        enricher_pool = self.model_orchestrator.get_primary_analyzer()
        if not enricher_pool:
            return

        # Use guided_json as default for best results
        # TODO: When scans get associated with profiles, read from profile settings
        output_mode = "guided_json"
        json_schema = None

        enricher = FindingEnricher(enricher_pool, self.db, output_mode=output_mode, json_schema=json_schema)
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

            # Update phase allocator with pending verified count (for adaptive allocation)
            pending_verified = self.db.query(VerifiedFinding).filter(
                VerifiedFinding.scan_id == self.scan_id,
                VerifiedFinding.status == "pending"
            ).count()
            phase_allocator.update_queue_depth(self.scan_id, "enricher", pending_verified)

            if not verified_list:
                if self._verifier_complete:
                    if pending_verified == 0:
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

                    # Get file_path: prefer draft.file_path (Joern), then scan_file, then "unknown"
                    file_path = "unknown"
                    if draft and draft.file_path:
                        file_path = draft.file_path
                    elif scan_file:
                        file_path = scan_file.file_path

                    finding = Finding(
                        scan_id=self.scan_id,
                        verified_id=v.id,
                        draft_id=v.draft_id,  # Direct link to original draft for traceability
                        file_path=file_path,
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
