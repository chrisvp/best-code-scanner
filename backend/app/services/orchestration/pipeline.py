import asyncio
import os
import hashlib
import time
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import case, func

from app.models.models import Scan, Finding
from app.models.scanner_models import (
    ScanConfig, ScanFile, ScanFileChunk, DraftFinding, VerifiedFinding
)
from app.services.orchestration.model_orchestrator import ModelOrchestrator
from app.services.orchestration.cache import AnalysisCache
from app.services.orchestration.checkpoint import ScanCheckpoint
from app.services.ingestion import ingestion_service


class ScanPipeline:
    """Coordinates the three-phase scanning pipeline"""

    def __init__(self, scan_id: int, config: ScanConfig, db: Session):
        self.scan_id = scan_id
        self.config = config
        self.db = db

        self.model_orchestrator: Optional[ModelOrchestrator] = None
        self.cache = AnalysisCache()
        self.checkpoint = ScanCheckpoint(scan_id, db)

        self._scanner_complete = False
        self._verifier_complete = False

    def _log_timing(self, phase: str, duration: float):
        """Log timing to scan record"""
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        timing_log = f"{phase}: {duration:.1f}s"
        scan.logs = (scan.logs or "") + f"\n{timing_log}"
        self.db.commit()
        print(f"[Scan {self.scan_id}] {timing_log}")

    async def run(self):
        """Run the full scanning pipeline"""
        from app.services.intelligence.code_indexer import CodeIndexer

        total_start = time.time()

        # Initialize model orchestrator
        self.model_orchestrator = ModelOrchestrator(self.db)
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

    async def _discover_and_chunk_files(self, root_dir: str):
        """Discover files and create chunks for scanning"""
        from app.services.analysis.file_chunker import FileChunker

        chunker = FileChunker()
        supported_extensions = {'.py', '.c', '.cpp', '.h', '.hpp'}

        for root, _, files in os.walk(root_dir):
            for filename in files:
                ext = os.path.splitext(filename)[1]
                if ext not in supported_extensions:
                    continue

                file_path = os.path.join(root, filename)

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
                    for chunk_data in chunks:
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

        self.db.commit()

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
        from app.services.analysis.draft_scanner import DraftScanner

        analyzer = self.model_orchestrator.get_primary_analyzer()
        if not analyzer:
            self._scanner_complete = True
            return

        scanner = DraftScanner(self.scan_id, analyzer, self.cache)
        batch_size = 10

        while True:
            # Check for pause
            scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
            if scan.status == "paused":
                await asyncio.sleep(1)
                continue

            # Get batch of pending chunks
            chunks = self.db.query(ScanFileChunk).join(ScanFile).filter(
                ScanFile.scan_id == self.scan_id,
                ScanFileChunk.status == "pending"
            ).order_by(
                case({'high': 0, 'normal': 1, 'low': 2}, value=ScanFile.risk_level)
            ).limit(batch_size).all()

            if not chunks:
                break

            # Mark as scanning
            for chunk in chunks:
                chunk.status = "scanning"
            self.db.commit()

            # Scan batch
            try:
                results = await scanner.scan_batch(chunks)

                # Save draft findings
                for chunk in chunks:
                    findings = results.get(chunk.id, [])
                    for f in findings:
                        draft = DraftFinding(
                            scan_id=self.scan_id,
                            chunk_id=chunk.id,
                            title=f.get('title', 'Unknown'),
                            vulnerability_type=f.get('type', f.get('vulnerability_type', 'Unknown')),
                            severity=f.get('severity', 'Medium'),
                            line_number=int(f.get('line', f.get('line_number', 0))) if f.get('line') or f.get('line_number') else 0,
                            snippet=f.get('snippet', ''),
                            reason=f.get('reason', ''),
                            auto_detected=f.get('auto_detected', False),
                            status="pending"
                        )
                        self.db.add(draft)

                    chunk.status = "scanned"

                self.db.commit()

            except Exception as e:
                print(f"Scanner error: {e}")
                self.db.rollback()
                try:
                    for chunk in chunks:
                        chunk.status = "pending"
                        chunk.retry_count += 1
                    self.db.commit()
                except Exception:
                    self.db.rollback()

        self._scanner_complete = True

    async def _run_verifier_phase(self):
        """Phase 2: Verify draft findings with context"""
        from app.services.analysis.verifier import FindingVerifier
        from app.services.intelligence.context_retriever import ContextRetriever

        # Check we have at least one verifier
        if not self.model_orchestrator.get_verifiers():
            # Fall back to analyzers as verifiers
            if not self.model_orchestrator.get_analyzers():
                self._verifier_complete = True
                return

        context_retriever = ContextRetriever(self.scan_id, self.db)
        # Pass orchestrator so verifier can use ALL verifier models for voting
        verifier = FindingVerifier(self.scan_id, self.model_orchestrator, context_retriever)
        batch_size = 5

        while True:
            # Check for pause
            scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
            if scan.status == "paused":
                await asyncio.sleep(1)
                continue

            # Get batch of pending drafts, prioritized by severity
            drafts = self.db.query(DraftFinding).filter(
                DraftFinding.scan_id == self.scan_id,
                DraftFinding.status == "pending"
            ).order_by(
                case({'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}, value=DraftFinding.severity),
                DraftFinding.created_at
            ).limit(batch_size).all()

            if not drafts:
                if self._scanner_complete:
                    # Double-check no more pending
                    remaining = self.db.query(DraftFinding).filter(
                        DraftFinding.scan_id == self.scan_id,
                        DraftFinding.status == "pending"
                    ).count()
                    if remaining == 0:
                        break
                await asyncio.sleep(0.5)
                continue

            # Mark as verifying
            for draft in drafts:
                draft.status = "verifying"
            self.db.commit()

            # Verify batch
            try:
                results = await verifier.verify_batch(drafts)

                for draft, result in zip(drafts, results):
                    if result.get('verified'):
                        verified = VerifiedFinding(
                            draft_id=draft.id,
                            scan_id=self.scan_id,
                            title=result.get('title', draft.title),
                            confidence=result.get('confidence', 50),
                            attack_vector=result.get('attack_vector', ''),
                            data_flow=result.get('data_flow', ''),
                            adjusted_severity=result.get('adjusted_severity'),
                            status="pending"
                        )
                        self.db.add(verified)
                        draft.status = "verified"
                    else:
                        draft.status = "rejected"

                self.db.commit()

            except Exception as e:
                print(f"Verifier error: {e}")
                for draft in drafts:
                    draft.status = "pending"
                self.db.commit()

        self._verifier_complete = True

    async def _run_enricher_phase(self):
        """Phase 3: Generate full reports for verified findings"""
        from app.services.analysis.enricher import FindingEnricher

        enricher_pool = self.model_orchestrator.get_primary_analyzer()
        if not enricher_pool:
            return

        enricher = FindingEnricher(enricher_pool, self.db)
        batch_size = 3

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

            # Enrich batch
            try:
                results = await enricher.enrich_batch(verified_list)

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
                        severity=v.adjusted_severity or result.get('severity', 'Medium'),
                        description=result.get('finding', v.title),
                        snippet=result.get('impacted_code', draft.snippet if draft else ''),
                        remediation=result.get('remediation_steps', ''),
                        category=result.get('category', ''),
                        cvss_score=float(result.get('cvss', 0)) if result.get('cvss') else None,
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
