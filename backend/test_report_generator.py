#!/usr/bin/env python3
"""
Quick test script for report generator.
Tests single scan report generation.
"""

import asyncio
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from app.core.database import SessionLocal
from app.services.analysis.report_generator import ReportGenerator
from app.models.models import Scan
from app.models.scanner_models import DraftFinding
# Import auth models to ensure they're registered
from app.models import auth_models


async def test_report_generator():
    """Test report generation on existing scan data"""

    db = SessionLocal()

    try:
        # Find a completed scan with data
        scan = db.query(Scan).filter(
            Scan.status == "completed"
        ).first()

        if not scan:
            print("No completed scans found. Run a scan first.")
            return

        print(f"Testing report generation for scan {scan.id}: {scan.target_url}")

        # Count some basic stats
        draft_count = db.query(DraftFinding).filter(
            DraftFinding.scan_id == scan.id
        ).count()

        print(f"Scan has {draft_count} draft findings")

        if draft_count == 0:
            print("Scan has no findings. Try a different scan.")
            return

        # Generate report
        print("\nGenerating report...")
        generator = ReportGenerator(db)
        report = await generator.generate_scan_report(scan.id)

        # Extract data from report
        data = report.report_data
        draft_metrics = data.get("draft_metrics", {})
        verification_metrics = data.get("verification_metrics", {})
        findings_metrics = data.get("findings_metrics", {})
        cwe_metrics = data.get("cwe_metrics", {})
        performance_metrics = data.get("performance_metrics", {})
        quality_issues = data.get("quality_issues", [])

        print("\n=== SCAN QUALITY REPORT ===")
        print(f"Grade: {report.overall_grade} ({data.get('grade_score', 0):.1f}/100)")
        print(f"\nDraft Quality:")
        print(f"  Total drafts: {draft_metrics.get('total_drafts', 0)}")
        print(f"  Verified: {draft_metrics.get('drafts_verified', 0)}")
        print(f"  Rejected: {draft_metrics.get('drafts_rejected', 0)}")
        print(f"  Weakness: {draft_metrics.get('drafts_weakness', 0)}")
        print(f"  Precision: {draft_metrics.get('draft_precision', 0):.1%}")

        print(f"\nVerification:")
        print(f"  Total votes: {verification_metrics.get('total_votes', 0)}")
        print(f"  Avg confidence: {verification_metrics.get('avg_confidence', 0):.1f}%")
        print(f"  Consensus rate: {verification_metrics.get('consensus_rate', 0):.1%}")

        print(f"\nFindings:")
        print(f"  Total: {findings_metrics.get('total', 0)}")
        print(f"  Critical: {findings_metrics.get('critical', 0)}")
        print(f"  High: {findings_metrics.get('high', 0)}")
        print(f"  Medium: {findings_metrics.get('medium', 0)}")
        print(f"  Low: {findings_metrics.get('low', 0)}")

        print(f"\nCWE Distribution:")
        cwe_dist = cwe_metrics.get("distribution", {})
        if cwe_dist:
            for cwe, count in sorted(
                cwe_dist.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]:
                print(f"  {cwe}: {count}")
            print(f"  Top CWE: {cwe_metrics.get('top_cwe')}")
            print(f"  Diversity score: {cwe_metrics.get('diversity_score', 0):.2f}")

        print(f"\nPerformance:")
        print(f"  Total time: {performance_metrics.get('total_time_ms', 0)/1000:.1f}s")
        print(f"  Findings/min: {performance_metrics.get('findings_per_minute', 0):.1f}")
        print(f"  Avg tokens/finding: {performance_metrics.get('avg_tokens_per_finding', 0)}")

        if quality_issues:
            print(f"\nQuality Issues ({len(quality_issues)}):")
            for issue in quality_issues:
                print(f"  [{issue['severity'].upper()}] {issue['message']}")

        print(f"\nSummary:")
        print(f"  {report.summary}")

        print(f"\nReport saved with ID: {report.id}")

    finally:
        db.close()


if __name__ == "__main__":
    asyncio.run(test_report_generator())
