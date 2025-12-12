#!/usr/bin/env python3
"""
Import draft findings as test cases with ground truth determination.

Ground truth logic:
- Has verified_findings → verdict = "REAL"
- Status = "weakness" → verdict = "WEAKNESS"
- Status = "rejected" or no verified_findings → verdict = "FALSE_POSITIVE"
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import get_db
# Import all models to avoid circular import issues
from app.models import scanner_models, tuning_models
from app.models.scanner_models import DraftFinding, VerifiedFinding
from app.models.tuning_models import TuningTestCase
from sqlalchemy import func
import argparse

def determine_verdict(draft, db):
    """Determine ground truth verdict for a draft finding"""

    # Check if it has verified findings
    verified = db.query(VerifiedFinding).filter(
        VerifiedFinding.draft_id == draft.id
    ).first()

    if verified:
        return "REAL"

    # Check draft status
    if draft.status == "weakness":
        return "WEAKNESS"
    elif draft.status == "verified":
        # Verified but no VerifiedFinding record? Still real
        return "REAL"
    elif draft.status == "rejected":
        return "FALSE_POSITIVE"
    else:
        # Pending or unknown - assume false positive
        return "FALSE_POSITIVE"

def import_draft_findings(db, limit=None, only_verified=False, scan_id=None, balance=True):
    """Import draft findings as test cases"""

    query = db.query(DraftFinding)

    if scan_id:
        query = query.filter(DraftFinding.scan_id == scan_id)

    if only_verified:
        # Only import findings that went through verification
        query = query.filter(DraftFinding.status.in_(['verified', 'rejected', 'weakness']))

    if limit:
        query = query.limit(limit)

    drafts = query.all()

    imported = 0
    skipped = 0
    verdict_counts = {'REAL': 0, 'FALSE_POSITIVE': 0, 'WEAKNESS': 0}

    for draft in drafts:
        # Check if already exists
        existing = db.query(TuningTestCase).filter(
            TuningTestCase.draft_finding_id == draft.id
        ).first()

        if existing:
            skipped += 1
            continue

        # Determine verdict
        verdict = determine_verdict(draft, db)

        # If balancing, check if we have enough of this verdict type
        if balance and limit:
            target_per_verdict = limit // 3
            if verdict_counts.get(verdict, 0) >= target_per_verdict:
                continue

        # Create test case - link to draft_finding for dynamic data loading
        test_case = TuningTestCase(
            name=f"draft_{draft.id}_{draft.title[:50] if draft.title else 'unknown'}",
            verdict=verdict,
            draft_finding_id=draft.id,
            # These will be loaded dynamically from draft_finding:
            title=draft.title,
            vulnerability_type=draft.vulnerability_type,
            severity=draft.severity,
            line_number=draft.line_number,
            snippet=draft.snippet,
            reason=draft.reason,
            file_path=draft.file_path,
            # Backwards compat fields:
            issue=draft.title,
            file=draft.file_path or "unknown",
            code=draft.snippet,
            claim=draft.reason,
        )

        db.add(test_case)
        imported += 1
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

        if imported % 100 == 0:
            db.commit()
            print(f"Imported {imported} test cases...")

    db.commit()

    print(f"\nImport complete:")
    print(f"- Imported: {imported}")
    print(f"- Skipped (already exists): {skipped}")
    total = db.query(TuningTestCase).count()
    print(f"- Total test cases: {total}")

    # Show verdict distribution
    result = db.query(
        TuningTestCase.verdict,
        func.count(TuningTestCase.id)
    ).group_by(TuningTestCase.verdict).all()

    print(f"\nVerdict distribution:")
    for verdict, count in result:
        print(f"  {verdict}: {count}")

def main():
    parser = argparse.ArgumentParser(description="Import draft findings as test cases")
    parser.add_argument("--limit", type=int, help="Limit number of imports")
    parser.add_argument("--only-verified", action="store_true",
                       help="Only import findings that went through verification")
    parser.add_argument("--scan-id", type=int, help="Import from specific scan")
    parser.add_argument("--clear", action="store_true",
                       help="Clear existing test cases first")
    parser.add_argument("--no-balance", action="store_true",
                       help="Don't try to balance verdict types")

    args = parser.parse_args()

    # Create database session
    db = next(get_db())

    try:
        if args.clear:
            count = db.query(TuningTestCase).delete()
            db.commit()
            print(f"Cleared {count} existing test cases")

        import_draft_findings(
            db,
            limit=args.limit,
            only_verified=args.only_verified,
            scan_id=args.scan_id,
            balance=not args.no_balance
        )
    finally:
        db.close()

if __name__ == "__main__":
    main()
