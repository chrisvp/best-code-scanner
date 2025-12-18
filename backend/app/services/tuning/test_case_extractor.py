"""
Test Case Extractor - Extract real verification test cases from historical scans.

Pulls draft findings with full context (code chunks, verification votes, surrounding code)
to create realistic test cases that mirror actual scan verification workload.
"""

import json
from typing import List, Dict, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_

from app.models.scanner_models import (
    DraftFinding, VerificationVote, ScanFileChunk, ScanFile
)
from app.models.models import Scan
from app.models.tuning_models import TuningTestCase


class TestCaseExtractor:
    """Extract test cases from historical scan data"""

    def __init__(self, db: Session):
        self.db = db

    def extract_from_scans(
        self,
        scan_ids: List[int],
        target_count: int = 100,
        balance_classes: bool = True,
        min_confidence: float = 0.7
    ) -> List[TuningTestCase]:
        """
        Extract test cases from specified scans.

        Args:
            scan_ids: List of scan IDs to extract from
            target_count: Target number of test cases to extract
            balance_classes: Balance REAL/FALSE_POSITIVE/WEAKNESS
            min_confidence: Minimum average vote confidence (0-1)

        Returns:
            List of TuningTestCase objects (not yet committed to DB)
        """
        print(f"[TestCaseExtractor] Extracting {target_count} test cases from scans {scan_ids}")

        # Get all draft findings with verification results
        candidates = self._get_candidates(scan_ids, min_confidence)
        print(f"[TestCaseExtractor] Found {len(candidates)} candidate findings")

        # Balance classes if requested
        if balance_classes:
            candidates = self._balance_classes(candidates, target_count)
            print(f"[TestCaseExtractor] Balanced to {len(candidates)} test cases")

        # Convert to TuningTestCase objects
        test_cases = []
        for candidate in candidates[:target_count]:
            test_case = self._convert_to_test_case(candidate)
            if test_case:
                test_cases.append(test_case)

        print(f"[TestCaseExtractor] Created {len(test_cases)} test cases")
        return test_cases

    def _get_candidates(
        self,
        scan_ids: List[int],
        min_confidence: float
    ) -> List[Dict]:
        """Get draft findings with full context and verification votes"""

        # Query draft findings with their chunks, votes, and consensus
        query = self.db.query(
            DraftFinding.id.label('draft_id'),
            DraftFinding.title,
            DraftFinding.vulnerability_type,
            DraftFinding.severity,
            DraftFinding.line_number,
            DraftFinding.snippet,
            DraftFinding.reason,
            DraftFinding.file_path,
            DraftFinding.status,  # verified, rejected, weakness
            DraftFinding.chunk_id,
            DraftFinding.scan_id,
            ScanFileChunk.start_line,
            ScanFileChunk.end_line,
            ScanFile.file_path.label('full_file_path'),
            Scan.target_url.label('scan_name')
        ).join(
            ScanFileChunk, DraftFinding.chunk_id == ScanFileChunk.id, isouter=True
        ).join(
            ScanFile, ScanFileChunk.scan_file_id == ScanFile.id, isouter=True
        ).join(
            Scan, DraftFinding.scan_id == Scan.id
        ).filter(
            and_(
                DraftFinding.scan_id.in_(scan_ids),
                DraftFinding.status.in_(['verified', 'rejected', 'weakness']),  # Has been verified
                or_(
                    DraftFinding.chunk_id.isnot(None),  # Has chunk context
                    DraftFinding.file_path.isnot(None)   # Or direct file path (Joern findings)
                )
            )
        ).all()

        candidates = []
        for row in query:
            # Get verification votes for this draft
            votes = self.db.query(
                VerificationVote.model_name,
                VerificationVote.decision,
                VerificationVote.confidence,
                VerificationVote.reasoning
            ).filter(
                VerificationVote.draft_finding_id == row.draft_id
            ).all()

            if not votes:
                continue  # Skip if no votes

            # Calculate average confidence
            avg_confidence = sum(v.confidence or 0 for v in votes) / len(votes) if votes else 0

            if avg_confidence < min_confidence * 100:  # Convert 0-1 to 0-100
                continue  # Skip low confidence cases

            # Determine consensus vote
            vote_counts = {}
            for v in votes:
                vote_counts[v.decision] = vote_counts.get(v.decision, 0) + 1

            consensus = max(vote_counts, key=vote_counts.get) if vote_counts else None

            # Build verification votes JSON
            votes_json = [
                {
                    "model": v.model_name,
                    "decision": v.decision,
                    "confidence": v.confidence,
                    "reasoning": v.reasoning
                }
                for v in votes
            ]

            # Extract CWE type
            cwe_type = None
            if row.vulnerability_type:
                # Try to extract CWE-XXX from vulnerability_type
                import re
                cwe_match = re.search(r'CWE-\d+', row.vulnerability_type)
                if cwe_match:
                    cwe_type = cwe_match.group(0)

            # Get full code chunk content from file system
            full_code_chunk = None
            if row.chunk_id and row.full_file_path and row.start_line and row.end_line:
                full_code_chunk = self._get_chunk_content(
                    row.full_file_path, row.start_line, row.end_line
                )

            candidates.append({
                'draft_id': row.draft_id,
                'title': row.title,
                'vulnerability_type': row.vulnerability_type,
                'severity': row.severity,
                'line_number': row.line_number,
                'snippet': row.snippet,
                'reason': row.reason,
                'file_path': row.file_path or row.full_file_path,
                'status': row.status,  # Ground truth
                'chunk_id': row.chunk_id,
                'full_code_chunk': full_code_chunk,
                'scan_id': row.scan_id,
                'scan_name': row.scan_name,
                'verification_votes': votes_json,
                'consensus_vote': consensus,
                'avg_confidence': avg_confidence / 100,  # Normalize to 0-1
                'cwe_type': cwe_type,
                'num_votes': len(votes)
            })

        return candidates

    def _balance_classes(self, candidates: List[Dict], target_count: int) -> List[Dict]:
        """Balance test cases across verdict classes"""

        # Group by status (verified=REAL, rejected=FALSE_POSITIVE, weakness=WEAKNESS)
        by_class = {
            'verified': [],
            'rejected': [],
            'weakness': []
        }

        for c in candidates:
            status = c['status']
            if status in by_class:
                by_class[status].append(c)

        # Calculate target per class (try to balance equally)
        per_class = target_count // 3

        # Take samples from each class
        balanced = []
        for status, items in by_class.items():
            # Sort by difficulty (cases with disagreement are more interesting)
            items_sorted = sorted(items, key=lambda x: -abs(0.5 - x['avg_confidence']))
            balanced.extend(items_sorted[:per_class])

        # If we don't have enough, backfill with any remaining
        if len(balanced) < target_count:
            all_remaining = [c for c in candidates if c not in balanced]
            balanced.extend(all_remaining[:target_count - len(balanced)])

        return balanced

    def _convert_to_test_case(self, candidate: Dict) -> Optional[TuningTestCase]:
        """Convert candidate finding to TuningTestCase"""

        try:
            # Map status to verdict
            verdict_map = {
                'verified': 'REAL',
                'rejected': 'FALSE_POSITIVE',
                'weakness': 'WEAKNESS'
            }
            verdict = verdict_map.get(candidate['status'], 'UNKNOWN')

            # Generate unique name
            scan_id = candidate['scan_id']
            draft_id = candidate['draft_id']
            cwe = candidate.get('cwe_type', 'unknown')
            name = f"scan{scan_id}_draft{draft_id}_{cwe}_{verdict}"

            # Calculate difficulty score (based on vote disagreement)
            # High confidence cases = easy (0.0), low confidence = hard (1.0)
            difficulty = 1.0 - candidate['avg_confidence']

            # Extract tags from vulnerability type and reason
            tags = self._extract_tags(candidate)

            test_case = TuningTestCase(
                name=name,
                verdict=verdict,

                # Link to original draft
                draft_finding_id=candidate['draft_id'],

                # Core finding data
                title=candidate['title'],
                vulnerability_type=candidate['vulnerability_type'],
                severity=candidate['severity'],
                line_number=candidate['line_number'],
                snippet=candidate['snippet'],
                reason=candidate['reason'],
                file_path=candidate['file_path'],

                # Full context
                full_code_chunk=candidate['full_code_chunk'],
                chunk_id=candidate['chunk_id'],
                surrounding_lines=10,

                # Source provenance
                source_scan_id=candidate['scan_id'],
                source_scan_name=candidate['scan_name'],

                # Historical verification
                verification_votes_json=candidate['verification_votes'],
                consensus_vote=candidate['consensus_vote'],
                vote_confidence_avg=candidate['avg_confidence'],

                # Categorization
                cwe_type=candidate.get('cwe_type'),
                is_synthetic=False,
                difficulty_score=difficulty,
                tags=tags
            )

            return test_case

        except Exception as e:
            print(f"[TestCaseExtractor] Error converting candidate {candidate.get('draft_id')}: {e}")
            return None

    def _extract_tags(self, candidate: Dict) -> List[str]:
        """Extract relevant tags from finding for filtering"""
        tags = []

        vuln_type = candidate.get('vulnerability_type', '').lower()
        reason = candidate.get('reason', '').lower()
        combined = f"{vuln_type} {reason}"

        # Common vulnerability patterns
        if 'buffer' in combined or 'overflow' in combined:
            tags.append('buffer-overflow')
        if 'sql' in combined or 'injection' in combined:
            tags.append('injection')
        if 'xss' in combined or 'cross-site' in combined:
            tags.append('xss')
        if 'pointer' in combined:
            tags.append('pointer-arithmetic')
        if 'memory' in combined or 'leak' in combined:
            tags.append('memory-issue')
        if 'integer' in combined:
            tags.append('integer-overflow')
        if 'format' in combined:
            tags.append('format-string')
        if 'command' in combined:
            tags.append('command-injection')
        if 'path' in combined or 'traversal' in combined:
            tags.append('path-traversal')

        # Difficulty indicators
        if candidate.get('difficulty_score', 0) > 0.7:
            tags.append('difficult')
        elif candidate.get('difficulty_score', 0) < 0.3:
            tags.append('easy')

        # Vote patterns
        num_votes = candidate.get('num_votes', 0)
        if num_votes >= 5:
            tags.append('high-agreement')
        elif num_votes >= 3:
            tags.append('medium-agreement')

        return tags

    def _get_chunk_content(self, file_path: str, start_line: int, end_line: int) -> Optional[str]:
        """Get the actual content of a code chunk from file system"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            return ''.join(lines[start_line - 1:end_line])
        except Exception as e:
            print(f"[TestCaseExtractor] Error reading chunk from {file_path}:{start_line}-{end_line}: {e}")
            return None

    def import_test_cases(self, test_cases: List[TuningTestCase]) -> Tuple[int, List[str]]:
        """
        Import test cases into database, handling duplicates.

        Returns:
            (num_imported, list_of_errors)
        """
        imported = 0
        errors = []

        for tc in test_cases:
            try:
                # Check if already exists (by name)
                existing = self.db.query(TuningTestCase).filter(
                    TuningTestCase.name == tc.name
                ).first()

                if existing:
                    errors.append(f"Test case {tc.name} already exists, skipping")
                    continue

                self.db.add(tc)
                imported += 1

            except Exception as e:
                errors.append(f"Error importing {tc.name}: {e}")

        if imported > 0:
            try:
                self.db.commit()
                print(f"[TestCaseExtractor] Imported {imported} test cases")
            except Exception as e:
                self.db.rollback()
                errors.append(f"Commit failed: {e}")
                imported = 0

        return imported, errors


def extract_and_import(
    db: Session,
    scan_ids: List[int],
    target_count: int = 100,
    balance: bool = True,
    min_confidence: float = 0.7
) -> Dict:
    """
    Convenience function to extract and import test cases in one call.

    Returns summary dict with stats.
    """
    extractor = TestCaseExtractor(db)

    # Extract test cases
    test_cases = extractor.extract_from_scans(
        scan_ids=scan_ids,
        target_count=target_count,
        balance_classes=balance,
        min_confidence=min_confidence
    )

    # Import to database
    num_imported, errors = extractor.import_test_cases(test_cases)

    # Calculate stats
    verdict_counts = {}
    cwe_counts = {}
    for tc in test_cases:
        verdict_counts[tc.verdict] = verdict_counts.get(tc.verdict, 0) + 1
        if tc.cwe_type:
            cwe_counts[tc.cwe_type] = cwe_counts.get(tc.cwe_type, 0) + 1

    return {
        'extracted': len(test_cases),
        'imported': num_imported,
        'errors': errors,
        'verdict_distribution': verdict_counts,
        'cwe_distribution': cwe_counts,
        'scan_ids': scan_ids
    }
