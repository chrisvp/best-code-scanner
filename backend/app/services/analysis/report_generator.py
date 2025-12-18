"""
Report generation service for scan quality analysis.

Computes metrics from database stats and generates comprehensive reports
for individual scans or comparative analysis across multiple scans.

Uses the existing ScanReport model which stores data in a flexible JSON format.
"""

import math
import re
from collections import Counter
from typing import List, Dict, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, case

from app.models.scanner_models import (
    ScanReport, DraftFinding, VerifiedFinding, VerificationVote,
    ScanMetrics, ProfileAnalyzer
)
from app.models.models import Scan, Finding


class ReportGenerator:
    """Generate quality analysis reports for scans"""

    def __init__(self, db: Session):
        self.db = db

    async def generate_scan_report(self, scan_id: int) -> ScanReport:
        """
        Generate quality analysis report for a single scan.

        Analyzes:
        - Draft quality (precision, false positive rate)
        - Verification voting patterns
        - CWE distribution and diversity
        - Performance metrics
        - Model-specific breakdowns (scanner, verifier, enricher performance)
        - Overall quality grade (A-F)

        Returns comprehensive report_data with model_breakdown showing:
        - Scanner models: drafts found, verified/rejected counts, precision, top CWEs
        - Verifier models: vote distribution, avg confidence, agreement rate
        - Enricher model: which model enriched findings
        """

        # Check if scan exists
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        # Compute all metrics
        draft_metrics = self._compute_draft_metrics(scan_id)
        verification_metrics = self._compute_verification_metrics(scan_id)
        findings_metrics = self._compute_findings_metrics(scan_id)
        cwe_metrics = self._compute_cwe_metrics(scan_id)
        performance_metrics = self._compute_performance_metrics(scan_id)
        model_breakdown = self._compute_model_breakdown(scan_id)

        # Calculate overall grade
        grade, grade_score = self._calculate_grade({
            **draft_metrics,
            **verification_metrics,
            **findings_metrics,
            **cwe_metrics,
            **performance_metrics
        })

        # Detect quality issues
        quality_issues = self._detect_quality_issues(
            scan_id, draft_metrics, cwe_metrics, verification_metrics
        )

        # Generate summary
        quality_summary = self._generate_summary(
            scan_id, grade, draft_metrics, findings_metrics, quality_issues
        )

        # Create or update report
        report = self.db.query(ScanReport).filter(
            ScanReport.scan_id == scan_id,
            ScanReport.report_type == "quality_analysis"
        ).first()

        if not report:
            report = ScanReport(
                scan_id=scan_id,
                report_type="quality_analysis"
            )
            self.db.add(report)

        # Build comprehensive report data
        report_data = {
            "draft_metrics": draft_metrics,
            "verification_metrics": verification_metrics,
            "findings_metrics": findings_metrics,
            "cwe_metrics": cwe_metrics,
            "performance_metrics": performance_metrics,
            "model_breakdown": model_breakdown,
            "quality_issues": quality_issues,
            "grade": grade,
            "grade_score": grade_score
        }

        # Store in JSON field
        report.report_data = report_data

        # Populate denormalized quick-access fields
        report.overall_grade = grade
        report.draft_count = draft_metrics["total_drafts"]
        report.verified_count = draft_metrics["drafts_verified"]
        report.false_positive_rate = (
            draft_metrics["drafts_rejected"] / draft_metrics["total_drafts"]
            if draft_metrics["total_drafts"] > 0 else 0.0
        )
        report.title = f"Quality Analysis for Scan {scan_id}"
        report.summary = quality_summary

        self.db.commit()
        self.db.refresh(report)

        return report

    async def generate_comparative_report(
        self,
        scan_ids: List[int],
        primary_scan_id: Optional[int] = None
    ) -> ScanReport:
        """
        Generate comparative analysis across multiple scans.

        Useful for:
        - Comparing different models on same codebase
        - Tracking scan quality over time
        - Identifying model biases and patterns
        """

        if len(scan_ids) < 2:
            raise ValueError("Comparative reports require at least 2 scans")

        # Use first scan as primary if not specified
        if primary_scan_id is None:
            primary_scan_id = scan_ids[0]

        if primary_scan_id not in scan_ids:
            raise ValueError("Primary scan must be in scan_ids list")

        # Generate individual reports for each scan
        individual_reports = []
        for scan_id in scan_ids:
            report = await self.generate_scan_report(scan_id)
            individual_reports.append(report)

        # Compute comparative metrics
        comparative_metrics = self._compute_comparative_metrics(scan_ids)
        model_stats = self._analyze_model_performance(scan_ids)

        # Aggregate metrics from individual reports
        total_drafts = sum(
            r.report_data.get("draft_metrics", {}).get("total_drafts", 0)
            for r in individual_reports
        )
        drafts_verified = sum(
            r.report_data.get("draft_metrics", {}).get("drafts_verified", 0)
            for r in individual_reports
        )

        # Calculate average grade
        avg_grade_score = sum(
            r.report_data.get("grade_score", 0)
            for r in individual_reports
        ) / len(individual_reports)
        avg_grade = self._score_to_grade(avg_grade_score)

        # Build comparative report data
        comparative_summary = self._generate_comparative_summary(
            scan_ids, individual_reports, comparative_metrics
        )

        report_data = {
            "scan_ids": scan_ids,
            "individual_reports": [
                {
                    "scan_id": r.scan_id,
                    "grade": r.report_data.get("grade"),
                    "grade_score": r.report_data.get("grade_score"),
                    "draft_count": r.draft_count,
                    "verified_count": r.verified_count,
                    "false_positive_rate": r.false_positive_rate
                }
                for r in individual_reports
            ],
            "aggregate_metrics": {
                "total_drafts": total_drafts,
                "drafts_verified": drafts_verified,
                "avg_grade_score": avg_grade_score
            },
            "model_stats": model_stats,
            "comparative_metrics": comparative_metrics
        }

        # Create comparative report
        report = ScanReport(
            scan_id=primary_scan_id,
            report_type="comparative",
            report_data=report_data,
            related_scan_ids=scan_ids,
            overall_grade=avg_grade,
            draft_count=total_drafts,
            verified_count=drafts_verified,
            title=f"Comparative Analysis: {len(scan_ids)} Scans",
            summary=comparative_summary
        )
        self.db.add(report)

        self.db.commit()
        self.db.refresh(report)

        return report

    def _compute_draft_metrics(self, scan_id: int) -> Dict:
        """Compute draft finding quality metrics"""

        total = self.db.query(func.count(DraftFinding.id)).filter(
            DraftFinding.scan_id == scan_id
        ).scalar() or 0

        verified = self.db.query(func.count(DraftFinding.id)).filter(
            DraftFinding.scan_id == scan_id,
            DraftFinding.status == "verified"
        ).scalar() or 0

        rejected = self.db.query(func.count(DraftFinding.id)).filter(
            DraftFinding.scan_id == scan_id,
            DraftFinding.status == "rejected"
        ).scalar() or 0

        weakness = self.db.query(func.count(DraftFinding.id)).filter(
            DraftFinding.scan_id == scan_id,
            DraftFinding.status == "weakness"
        ).scalar() or 0

        precision = verified / total if total > 0 else 0.0

        return {
            "total_drafts": total,
            "drafts_verified": verified,
            "drafts_rejected": rejected,
            "drafts_weakness": weakness,
            "draft_precision": precision
        }

    def _compute_verification_metrics(self, scan_id: int) -> Dict:
        """Compute verification voting metrics"""

        total_votes = self.db.query(func.count(VerificationVote.id)).filter(
            VerificationVote.scan_id == scan_id
        ).scalar() or 0

        avg_confidence = self.db.query(func.avg(VerificationVote.confidence)).filter(
            VerificationVote.scan_id == scan_id
        ).scalar() or 0.0

        # Calculate consensus rate - % of drafts where all votes agreed
        drafts_with_votes = self.db.query(DraftFinding.id).filter(
            DraftFinding.scan_id == scan_id
        ).all()

        consensus_count = 0
        for (draft_id,) in drafts_with_votes:
            votes = self.db.query(VerificationVote.decision).filter(
                VerificationVote.draft_finding_id == draft_id
            ).all()

            if votes and len(set(v[0] for v in votes)) == 1:
                consensus_count += 1

        consensus_rate = (
            consensus_count / len(drafts_with_votes)
            if drafts_with_votes else 0.0
        )

        return {
            "total_votes": total_votes,
            "avg_confidence": float(avg_confidence),
            "consensus_rate": consensus_rate
        }

    def _compute_findings_metrics(self, scan_id: int) -> Dict:
        """Compute final findings metrics by severity"""

        findings = self.db.query(Finding.severity).filter(
            Finding.scan_id == scan_id
        ).all()

        severity_counts = Counter(f[0].upper() for f in findings)

        return {
            "total": len(findings),
            "critical": severity_counts.get("CRITICAL", 0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0)
        }

    def _compute_cwe_metrics(self, scan_id: int) -> Dict:
        """Analyze CWE distribution and detect spam patterns"""

        # Extract CWE from draft findings
        drafts = self.db.query(DraftFinding.vulnerability_type).filter(
            DraftFinding.scan_id == scan_id
        ).all()

        # Extract CWE IDs from vulnerability types
        cwe_pattern = re.compile(r'CWE-(\d+)')
        cwe_ids = []
        for (vuln_type,) in drafts:
            if vuln_type:
                match = cwe_pattern.search(vuln_type)
                if match:
                    cwe_ids.append(f"CWE-{match.group(1)}")

        # Count distribution
        cwe_distribution = dict(Counter(cwe_ids))
        top_cwe = max(cwe_distribution.items(), key=lambda x: x[1])[0] if cwe_distribution else None

        # Calculate diversity using Shannon entropy
        diversity_score = self._calculate_shannon_entropy(list(cwe_distribution.values()))

        return {
            "distribution": cwe_distribution,
            "top_cwe": top_cwe,
            "diversity_score": diversity_score
        }

    def _compute_performance_metrics(self, scan_id: int) -> Dict:
        """Compute performance and efficiency metrics"""

        metrics = self.db.query(ScanMetrics).filter(
            ScanMetrics.scan_id == scan_id
        ).first()

        findings_count = self.db.query(func.count(Finding.id)).filter(
            Finding.scan_id == scan_id
        ).scalar() or 0

        if not metrics:
            return {
                "total_time_ms": 0.0,
                "findings_per_minute": 0.0,
                "avg_tokens_per_finding": 0
            }

        total_time_ms = metrics.total_time_ms or 0.0
        findings_per_minute = (
            (findings_count / (total_time_ms / 1000 / 60))
            if total_time_ms > 0 else 0.0
        )

        total_tokens = (metrics.total_tokens_in or 0) + (metrics.total_tokens_out or 0)
        avg_tokens_per_finding = (
            total_tokens // findings_count
            if findings_count > 0 else 0
        )

        return {
            "total_time_ms": total_time_ms,
            "findings_per_minute": findings_per_minute,
            "avg_tokens_per_finding": avg_tokens_per_finding
        }

    def _compute_model_breakdown(self, scan_id: int) -> Dict:
        """
        Compute per-model performance breakdown.

        Shows which models scanned, verified, and enriched, with detailed stats
        for each model's accuracy and contribution.
        """

        breakdown = {
            "scanners": [],
            "verifiers": [],
            "enricher": {}
        }

        # Scanner model breakdown
        # Group drafts by analyzer_name, compute stats per model
        scanner_stats = self.db.query(
            DraftFinding.analyzer_name,
            func.count(DraftFinding.id).label('drafts_found'),
            func.sum(case((DraftFinding.status == 'verified', 1), else_=0)).label('verified'),
            func.sum(case((DraftFinding.status == 'rejected', 1), else_=0)).label('rejected'),
            func.sum(case((DraftFinding.status == 'weakness', 1), else_=0)).label('weakness')
        ).filter(
            DraftFinding.scan_id == scan_id
        ).group_by(DraftFinding.analyzer_name).all()

        # Get CWE distribution per scanner
        for analyzer_name, drafts_found, verified, rejected, weakness in scanner_stats:
            if not analyzer_name:
                continue

            # Get CWE distribution for this analyzer
            cwe_pattern = re.compile(r'CWE-(\d+)')
            drafts_for_analyzer = self.db.query(DraftFinding.vulnerability_type).filter(
                DraftFinding.scan_id == scan_id,
                DraftFinding.analyzer_name == analyzer_name
            ).all()

            cwe_ids = []
            for (vuln_type,) in drafts_for_analyzer:
                if vuln_type:
                    match = cwe_pattern.search(vuln_type)
                    if match:
                        cwe_ids.append(f"CWE-{match.group(1)}")

            cwe_distribution = Counter(cwe_ids)
            top_cwes = cwe_distribution.most_common(3)

            precision = verified / drafts_found if drafts_found > 0 else 0.0

            breakdown["scanners"].append({
                "model": analyzer_name,
                "drafts_found": drafts_found,
                "verified": verified,
                "rejected": rejected,
                "weakness": weakness,
                "precision": round(precision, 3),
                "top_cwes": [[cwe, count] for cwe, count in top_cwes]
            })

        # Verifier model breakdown
        # Group votes by model_name, compute vote distribution and confidence
        verifier_stats = self.db.query(
            VerificationVote.model_name,
            VerificationVote.decision,
            func.count(VerificationVote.id).label('vote_count'),
            func.avg(VerificationVote.confidence).label('avg_confidence')
        ).filter(
            VerificationVote.scan_id == scan_id
        ).group_by(
            VerificationVote.model_name,
            VerificationVote.decision
        ).all()

        # Organize votes by model
        verifier_vote_map = {}
        for model_name, decision, vote_count, avg_confidence in verifier_stats:
            if model_name not in verifier_vote_map:
                verifier_vote_map[model_name] = {
                    "model": model_name,
                    "votes": {},
                    "avg_confidence": 0.0,
                    "total_votes": 0,
                    "agreement_rate": 0.0
                }

            verifier_vote_map[model_name]["votes"][decision] = vote_count
            verifier_vote_map[model_name]["total_votes"] += vote_count

        # Calculate avg confidence and agreement rate for each verifier
        for model_name in verifier_vote_map:
            # Get average confidence across all votes from this model
            avg_conf = self.db.query(func.avg(VerificationVote.confidence)).filter(
                VerificationVote.scan_id == scan_id,
                VerificationVote.model_name == model_name
            ).scalar() or 0.0

            verifier_vote_map[model_name]["avg_confidence"] = round(float(avg_conf), 1)

            # Calculate agreement rate: how often this model's vote matched the final verdict
            # Get all votes from this model
            model_votes = self.db.query(
                VerificationVote.draft_finding_id,
                VerificationVote.decision
            ).filter(
                VerificationVote.scan_id == scan_id,
                VerificationVote.model_name == model_name
            ).all()

            agreements = 0
            for draft_id, model_decision in model_votes:
                # Get the final status of this draft
                draft = self.db.query(DraftFinding.status).filter(
                    DraftFinding.id == draft_id
                ).first()

                if draft:
                    final_status = draft[0]
                    # Map decision to status
                    # VERIFY -> verified, REJECT -> rejected, WEAKNESS -> weakness
                    if (model_decision == "VERIFY" and final_status == "verified") or \
                       (model_decision == "REJECT" and final_status == "rejected") or \
                       (model_decision == "WEAKNESS" and final_status == "weakness"):
                        agreements += 1

            total_votes = len(model_votes)
            agreement_rate = agreements / total_votes if total_votes > 0 else 0.0
            verifier_vote_map[model_name]["agreement_rate"] = round(agreement_rate, 3)

        breakdown["verifiers"] = list(verifier_vote_map.values())

        # Enricher breakdown
        # Find which model did enrichment (look at findings)
        enricher_info = self.db.query(
            Finding.source_model,
            func.count(Finding.id).label('findings_enriched')
        ).filter(
            Finding.scan_id == scan_id
        ).group_by(Finding.source_model).first()

        if enricher_info:
            model_name, findings_enriched = enricher_info
            breakdown["enricher"] = {
                "model": model_name,
                "findings_enriched": findings_enriched
            }

        return breakdown

    def _calculate_grade(self, stats: Dict) -> Tuple[str, float]:
        """
        Calculate A-F grade based on multiple quality metrics.

        Grading criteria:
        - Draft precision (50%): How many drafts are actually vulnerabilities
        - Verification consensus (20%): How often verifiers agree
        - CWE diversity (15%): Not spamming the same CWE
        - Findings quality (15%): Critical/High ratio
        """

        score = 0.0

        # Draft precision (50 points max)
        draft_precision = stats.get("draft_precision", 0.0)
        score += draft_precision * 50

        # Verification consensus (20 points max)
        consensus_rate = stats.get("consensus_rate", 0.0)
        score += consensus_rate * 20

        # CWE diversity (15 points max)
        # Higher entropy = more diverse = better
        diversity_score = stats.get("diversity_score", 0.0)
        # Normalize to 0-1 (typical entropy for 5-10 CWEs is 1.5-2.5)
        normalized_diversity = min(diversity_score / 2.5, 1.0)
        score += normalized_diversity * 15

        # Findings quality (15 points max)
        # Prefer critical/high findings over medium/low
        total_findings = stats.get("total", 0)
        if total_findings > 0:
            high_severity_count = (
                stats.get("critical", 0) + stats.get("high", 0)
            )
            quality_ratio = high_severity_count / total_findings
            score += quality_ratio * 15

        grade = self._score_to_grade(score)
        return grade, score

    def _score_to_grade(self, score: float) -> str:
        """Convert numeric score to letter grade"""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    def _detect_quality_issues(
        self,
        scan_id: int,
        draft_metrics: Dict,
        cwe_metrics: Dict,
        verification_metrics: Dict
    ) -> List[Dict]:
        """Detect common quality issues in scan results"""

        issues = []

        # Issue 1: Low draft precision (high false positive rate)
        if draft_metrics["draft_precision"] < 0.5:
            issues.append({
                "type": "low_precision",
                "severity": "high",
                "message": f"Low draft precision ({draft_metrics['draft_precision']:.1%}). "
                           f"Over half of initial findings are false positives."
            })

        # Issue 2: CWE spam (one CWE dominates)
        if cwe_metrics["distribution"]:
            total_cwes = sum(cwe_metrics["distribution"].values())
            top_cwe_count = cwe_metrics["distribution"].get(cwe_metrics["top_cwe"], 0)

            if top_cwe_count / total_cwes > 0.6:
                issues.append({
                    "type": "cwe_spam",
                    "severity": "medium",
                    "message": f"Potential CWE spam: {cwe_metrics['top_cwe']} "
                               f"represents {top_cwe_count/total_cwes:.1%} of all findings."
                })

        # Issue 3: Low verification consensus
        if verification_metrics["consensus_rate"] < 0.5:
            issues.append({
                "type": "low_consensus",
                "severity": "medium",
                "message": f"Low verification consensus ({verification_metrics['consensus_rate']:.1%}). "
                           f"Verifiers frequently disagree, indicating unclear findings."
            })

        # Issue 4: Very low CWE diversity
        if cwe_metrics["diversity_score"] < 1.0:
            issues.append({
                "type": "low_diversity",
                "severity": "low",
                "message": "Low CWE diversity. Model may be biased toward certain vulnerability types."
            })

        return issues

    def _generate_summary(
        self,
        scan_id: int,
        grade: str,
        draft_metrics: Dict,
        findings_metrics: Dict,
        quality_issues: List[Dict]
    ) -> str:
        """Generate human-readable summary of scan quality"""

        summary_parts = [
            f"Scan Quality Grade: {grade}",
            f"Found {findings_metrics['total']} vulnerabilities "
            f"({findings_metrics['critical']} critical, {findings_metrics['high']} high).",
            f"Draft precision: {draft_metrics['draft_precision']:.1%} "
            f"({draft_metrics['drafts_verified']} verified out of {draft_metrics['total_drafts']} initial findings)."
        ]

        if quality_issues:
            summary_parts.append(
                f"Detected {len(quality_issues)} quality issue(s): " +
                ", ".join(issue["type"] for issue in quality_issues)
            )
        else:
            summary_parts.append("No major quality issues detected.")

        return " ".join(summary_parts)

    def _calculate_shannon_entropy(self, counts: List[int]) -> float:
        """Calculate Shannon entropy for diversity measurement"""

        if not counts or sum(counts) == 0:
            return 0.0

        total = sum(counts)
        probabilities = [c / total for c in counts]

        entropy = -sum(
            p * math.log2(p) for p in probabilities if p > 0
        )

        return entropy

    def _compute_comparative_metrics(self, scan_ids: List[int]) -> Dict:
        """Compute metrics that only make sense in comparative context"""

        # Find common files scanned across all scans
        # Find overlapping findings (same file + line + type)
        # Calculate inter-scan agreement rate

        # TODO: Implement when needed for comparative analysis
        return {}

    def _analyze_model_performance(self, scan_ids: List[int]) -> Dict:
        """Analyze per-model performance across scans"""

        model_stats = {}

        for scan_id in scan_ids:
            # Get all draft findings with source models
            drafts = self.db.query(DraftFinding).filter(
                DraftFinding.scan_id == scan_id
            ).all()

            for draft in drafts:
                if not draft.source_models:
                    continue

                for model_name in draft.source_models:
                    if model_name not in model_stats:
                        model_stats[model_name] = {
                            "total_drafts": 0,
                            "verified": 0,
                            "rejected": 0,
                            "weakness": 0,
                            "precision": 0.0
                        }

                    stats = model_stats[model_name]
                    stats["total_drafts"] += 1

                    if draft.status == "verified":
                        stats["verified"] += 1
                    elif draft.status == "rejected":
                        stats["rejected"] += 1
                    elif draft.status == "weakness":
                        stats["weakness"] += 1

        # Calculate precision for each model
        for model_name, stats in model_stats.items():
            if stats["total_drafts"] > 0:
                stats["precision"] = stats["verified"] / stats["total_drafts"]

        return model_stats

    def _generate_comparative_summary(
        self,
        scan_ids: List[int],
        individual_reports: List[ScanReport],
        comparative_metrics: Dict
    ) -> str:
        """Generate summary for comparative analysis"""

        avg_grade = sum(
            ord(r.grade[0]) for r in individual_reports
        ) / len(individual_reports)
        avg_grade_letter = chr(int(avg_grade))

        avg_precision = sum(
            r.draft_precision for r in individual_reports
        ) / len(individual_reports)

        total_findings = sum(r.total_findings for r in individual_reports)

        summary = (
            f"Comparative analysis of {len(scan_ids)} scans. "
            f"Average grade: {avg_grade_letter} "
            f"(precision: {avg_precision:.1%}). "
            f"Total findings across all scans: {total_findings}."
        )

        return summary
