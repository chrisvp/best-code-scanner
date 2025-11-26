"""
Findings Analysis & Prioritization Service

Analyzes all verified findings for a scan and provides actionable recommendations
including critical priorities, quick wins, root cause grouping, and remediation order.
"""

import json
import re
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.scanner_models import VerifiedFinding, DraftFinding, ScanFileChunk, ScanFile
from app.services.orchestration.model_orchestrator import ModelPool


class FindingsAnalyzer:
    """
    Analyzes verified findings for a scan and provides prioritized recommendations.

    Uses an LLM to:
    - Identify critical priority findings needing immediate attention
    - Identify quick wins (easy fixes with high impact)
    - Group findings by root cause
    - Suggest optimal remediation order
    """

    ANALYSIS_PROMPT = """You are a security expert analyzing vulnerability scan results.

=== SCAN FINDINGS ===
{findings_json}

=== INSTRUCTIONS ===
Analyze these {finding_count} security findings and provide actionable recommendations.

Return your analysis as valid JSON with this exact structure:
{{
    "summary": "Brief overview of findings (1-2 sentences). Include counts by severity.",
    "critical_priority": [
        {{
            "finding_id": <id>,
            "title": "<finding title>",
            "reason": "<why this needs immediate attention>",
            "cvss": <estimated CVSS score 0.0-10.0>
        }}
    ],
    "quick_wins": [
        {{
            "finding_id": <id>,
            "title": "<finding title>",
            "reason": "<why this is an easy fix>",
            "effort": "<estimated time: '5 min', '15 min', '30 min', '1 hour'>"
        }}
    ],
    "grouped": {{
        "<root cause description>": [<list of finding_ids>],
        "<another root cause>": [<list of finding_ids>]
    }},
    "remediation_order": [<ordered list of finding_ids to fix>]
}}

Guidelines:
- critical_priority: Findings with remote code execution, auth bypass, data exposure, or CVSS >= 9.0
- quick_wins: Simple input validation, config changes, or one-line fixes
- grouped: Group by underlying issue (e.g., "Missing input validation", "Hardcoded credentials")
- remediation_order: Consider dependencies and impact. Fix critical issues first, then group related fixes.

Return ONLY the JSON object, no other text."""

    def __init__(self, model_pool: ModelPool, db: Session):
        self.model_pool = model_pool
        self.db = db

    async def analyze(self, scan_id: int) -> Dict[str, Any]:
        """
        Analyze all verified findings for a scan and return prioritized recommendations.

        Args:
            scan_id: The ID of the scan to analyze

        Returns:
            Dict containing summary, critical_priority, quick_wins, grouped, and remediation_order
        """
        # Query all verified findings for the scan
        verified_findings = self.db.query(VerifiedFinding).filter(
            VerifiedFinding.scan_id == scan_id,
            VerifiedFinding.status == "complete"
        ).all()

        if not verified_findings:
            return {
                "summary": "No verified findings to analyze.",
                "critical_priority": [],
                "quick_wins": [],
                "grouped": {},
                "remediation_order": []
            }

        # Build finding details for LLM analysis
        findings_data = []
        for vf in verified_findings:
            finding_info = self._build_finding_info(vf)
            findings_data.append(finding_info)

        # Format prompt
        findings_json = json.dumps(findings_data, indent=2)
        prompt = self.ANALYSIS_PROMPT.format(
            findings_json=findings_json,
            finding_count=len(findings_data)
        )

        # Call LLM
        try:
            responses = await self.model_pool.call_batch([prompt])
            if responses and responses[0]:
                return self._parse_response(responses[0], verified_findings)
        except Exception as e:
            print(f"Findings analysis failed: {e}")

        # Return fallback analysis if LLM fails
        return self._fallback_analysis(verified_findings)

    def _build_finding_info(self, verified: VerifiedFinding) -> Dict[str, Any]:
        """Build detailed info dict for a verified finding"""
        info = {
            "id": verified.id,
            "title": verified.title,
            "severity": verified.adjusted_severity or "Medium",
            "confidence": verified.confidence or 50,
            "attack_vector": verified.attack_vector,
            "data_flow": verified.data_flow
        }

        # Get additional context from draft finding
        draft = self.db.query(DraftFinding).filter(
            DraftFinding.id == verified.draft_id
        ).first()

        if draft:
            info["vulnerability_type"] = draft.vulnerability_type
            info["line_number"] = draft.line_number
            info["snippet"] = (draft.snippet or "")[:200]  # Truncate for context
            info["reason"] = draft.reason

            # Get file path from chunk
            chunk = self.db.query(ScanFileChunk).filter(
                ScanFileChunk.id == draft.chunk_id
            ).first()

            if chunk:
                scan_file = self.db.query(ScanFile).filter(
                    ScanFile.id == chunk.scan_file_id
                ).first()
                if scan_file:
                    info["file_path"] = scan_file.file_path

        return info

    def _parse_response(self, response: str, verified_findings: List[VerifiedFinding]) -> Dict[str, Any]:
        """Parse LLM response into structured analysis"""
        # Strip thinking tags if present (from reasoning models)
        response = re.sub(r'<thinking>.*?</thinking>', '', response, flags=re.DOTALL)
        response = response.strip()

        # Try to extract JSON from response
        json_match = re.search(r'\{[\s\S]*\}', response)
        if not json_match:
            return self._fallback_analysis(verified_findings)

        try:
            result = json.loads(json_match.group())

            # Validate structure and add defaults
            if "summary" not in result:
                result["summary"] = f"{len(verified_findings)} findings analyzed."

            if "critical_priority" not in result:
                result["critical_priority"] = []

            if "quick_wins" not in result:
                result["quick_wins"] = []

            if "grouped" not in result:
                result["grouped"] = {}

            if "remediation_order" not in result:
                # Default order by severity
                result["remediation_order"] = [vf.id for vf in verified_findings]

            # Validate finding IDs exist
            valid_ids = {vf.id for vf in verified_findings}
            result["critical_priority"] = [
                cp for cp in result["critical_priority"]
                if cp.get("finding_id") in valid_ids
            ]
            result["quick_wins"] = [
                qw for qw in result["quick_wins"]
                if qw.get("finding_id") in valid_ids
            ]
            result["remediation_order"] = [
                fid for fid in result["remediation_order"]
                if fid in valid_ids
            ]

            # Clean grouped to only contain valid IDs
            cleaned_grouped = {}
            for cause, ids in result.get("grouped", {}).items():
                valid = [fid for fid in ids if fid in valid_ids]
                if valid:
                    cleaned_grouped[cause] = valid
            result["grouped"] = cleaned_grouped

            return result

        except json.JSONDecodeError as e:
            print(f"Failed to parse LLM response as JSON: {e}")
            return self._fallback_analysis(verified_findings)

    def _fallback_analysis(self, verified_findings: List[VerifiedFinding]) -> Dict[str, Any]:
        """Generate basic analysis when LLM fails"""
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        critical_priority = []

        for vf in verified_findings:
            severity = vf.adjusted_severity or "Medium"
            if severity in severity_counts:
                severity_counts[severity] += 1

            # Auto-detect critical priority based on severity
            if severity in ("Critical", "High") and vf.confidence and vf.confidence >= 80:
                critical_priority.append({
                    "finding_id": vf.id,
                    "title": vf.title,
                    "reason": f"{severity} severity with {vf.confidence}% confidence",
                    "cvss": 9.0 if severity == "Critical" else 7.5
                })

        summary_parts = []
        for sev, count in severity_counts.items():
            if count > 0:
                summary_parts.append(f"{count} {sev}")

        summary = f"{len(verified_findings)} findings analyzed: {', '.join(summary_parts)}."

        # Sort by severity for remediation order
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_findings = sorted(
            verified_findings,
            key=lambda vf: severity_order.get(vf.adjusted_severity or "Medium", 2)
        )

        return {
            "summary": summary,
            "critical_priority": critical_priority[:5],  # Top 5 critical
            "quick_wins": [],  # Cannot determine without LLM
            "grouped": {},  # Cannot determine without LLM
            "remediation_order": [vf.id for vf in sorted_findings]
        }
