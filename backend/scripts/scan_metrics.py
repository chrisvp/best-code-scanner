#!/usr/bin/env python3
"""
Scan Metrics Query Script
Run: python scripts/scan_metrics.py [scan_id]

Provides breakdown of LLM calls and time by phase and model.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import SessionLocal
from app.models.scanner_models import (
    ScanConfig, ScanFile, ScanFileChunk, DraftFinding,
    VerifiedFinding, LLMCallMetric, ModelConfig, ScanMetrics
)
from app.models.models import Scan
from sqlalchemy import func


def get_scan_metrics(scan_id: int = None):
    db = SessionLocal()

    try:
        # Get latest scan if not specified
        if scan_id is None:
            scan = db.query(Scan).order_by(Scan.id.desc()).first()
            if not scan:
                print("No scans found")
                return
            scan_id = scan.id
        else:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                print(f"Scan {scan_id} not found")
                return

        print(f"\n{'='*60}")
        print(f"SCAN METRICS - Scan #{scan_id}")
        print(f"{'='*60}")
        print(f"Target: {scan.target_url}")
        print(f"Status: {scan.status}")

        # Get config
        config = db.query(ScanConfig).filter(ScanConfig.scan_id == scan_id).first()
        if config:
            print(f"\nConfig:")
            print(f"  - Multi-model scan: {config.multi_model_scan}")
            print(f"  - Batch size: {config.batch_size}")
            print(f"  - Chunk size: {config.chunk_size}")
            print(f"  - Min votes to verify: {config.min_votes_to_verify}")
            print(f"  - Deduplicate drafts: {config.deduplicate_drafts}")

        # Get scan metrics (chunk data)
        scan_metrics = db.query(ScanMetrics).filter(ScanMetrics.scan_id == scan_id).first()
        if scan_metrics:
            print(f"\nChunk Metrics:")
            print(f"  - Total chunks: {scan_metrics.total_chunks}")
            print(f"  - Avg tokens/chunk: {scan_metrics.avg_chunk_tokens:.0f}")
            print(f"  - Min tokens/chunk: {scan_metrics.min_chunk_tokens}")
            print(f"  - Max tokens/chunk: {scan_metrics.max_chunk_tokens}")
            print(f"  - Chunk size setting: {scan_metrics.chunk_size_setting}")

        # Count metrics
        files = db.query(ScanFile).filter(ScanFile.scan_id == scan_id).count()
        chunks = db.query(ScanFileChunk).join(ScanFile).filter(
            ScanFile.scan_id == scan_id
        ).count()
        drafts = db.query(DraftFinding).filter(DraftFinding.scan_id == scan_id).count()
        verified = db.query(VerifiedFinding).filter(
            VerifiedFinding.scan_id == scan_id
        ).count()

        # Draft status breakdown
        draft_statuses = db.query(
            DraftFinding.status,
            func.count(DraftFinding.id)
        ).filter(
            DraftFinding.scan_id == scan_id
        ).group_by(DraftFinding.status).all()

        print(f"\n{'='*60}")
        print("SCAN COUNTS")
        print(f"{'='*60}")
        print(f"Files scanned:     {files}")
        print(f"Chunks analyzed:   {chunks}")
        print(f"Drafts created:    {drafts}")
        for status, count in draft_statuses:
            print(f"  - {status}: {count}")
        print(f"Verified findings: {verified}")

        # Get model configs
        models = db.query(ModelConfig).all()
        analyzer_count = len([m for m in models if m.is_analyzer])
        verifier_count = len([m for m in models if m.is_verifier])

        print(f"\n{'='*60}")
        print("LLM CALL ESTIMATES")
        print(f"{'='*60}")

        # Scanner phase
        if config and config.multi_model_scan:
            scanner_calls = chunks * analyzer_count
            print(f"\nScanner Phase (multi-model):")
            print(f"  {analyzer_count} analyzers × {chunks} chunks = {scanner_calls} calls")
        else:
            scanner_calls = chunks
            print(f"\nScanner Phase (single-model):")
            print(f"  1 analyzer × {chunks} chunks = {scanner_calls} calls")

        # Verifier phase
        verifier_calls = drafts * verifier_count
        print(f"\nVerifier Phase:")
        print(f"  {verifier_count} verifiers × {drafts} drafts = {verifier_calls} calls")

        # Enricher phase
        enricher_calls = verified
        print(f"\nEnricher Phase:")
        print(f"  1 enricher × {verified} findings = {enricher_calls} calls")

        total_calls = scanner_calls + verifier_calls + enricher_calls
        print(f"\n{'='*60}")
        print(f"TOTAL LLM CALLS: {total_calls}")
        print(f"{'='*60}")

        # If we have actual metrics, show them
        metrics = db.query(LLMCallMetric).filter(
            LLMCallMetric.scan_id == scan_id
        ).all()

        if metrics:
            print(f"\n{'='*60}")
            print("ACTUAL METRICS (from LLMCallMetric table)")
            print(f"{'='*60}")

            # Group by phase and model
            by_phase = db.query(
                LLMCallMetric.phase,
                LLMCallMetric.model_name,
                func.sum(LLMCallMetric.call_count).label('calls'),
                func.sum(LLMCallMetric.total_time_ms).label('time_ms')
            ).filter(
                LLMCallMetric.scan_id == scan_id
            ).group_by(
                LLMCallMetric.phase,
                LLMCallMetric.model_name
            ).all()

            current_phase = None
            for phase, model, calls, time_ms in by_phase:
                if phase != current_phase:
                    print(f"\n{phase.upper()}:")
                    current_phase = phase
                time_s = (time_ms or 0) / 1000
                print(f"  {model}: {calls} calls, {time_s:.1f}s")

        # Severity breakdown
        print(f"\n{'='*60}")
        print("FINDINGS BY SEVERITY")
        print(f"{'='*60}")

        severities = db.query(
            VerifiedFinding.adjusted_severity,
            func.count(VerifiedFinding.id)
        ).filter(
            VerifiedFinding.scan_id == scan_id,
            VerifiedFinding.status == "complete"
        ).group_by(VerifiedFinding.adjusted_severity).all()

        for severity, count in severities:
            print(f"  {severity or 'Unknown'}: {count}")

    finally:
        db.close()


if __name__ == "__main__":
    scan_id = int(sys.argv[1]) if len(sys.argv) > 1 else None
    get_scan_metrics(scan_id)
