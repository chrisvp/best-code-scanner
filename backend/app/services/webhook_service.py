"""
Webhook Service for Security Alerts

Sends webhook notifications for security findings, particularly those
with malicious intent indicators (backdoors, credential harvesting, etc.)
"""

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy.orm import Session

from app.models.scanner_models import (
    WebhookConfig, WebhookDeliveryLog, DraftFinding, VerifiedFinding
)


# Malicious intent indicators - patterns that suggest intentional malicious code
MALICIOUS_INDICATORS = {
    "backdoor": {
        "patterns": [
            r"reverse\s*shell",
            r"bind\s*shell",
            r"nc\s+-[elp]",  # netcat with exec/listen flags
            r"bash\s+-i\s+>&",  # bash reverse shell
            r"/dev/tcp/",  # bash network redirect
            r"socket\.connect.*\(.*,\s*\d+\)",  # socket connection
            r"subprocess\.Popen.*shell\s*=\s*True",
            r"os\.system\s*\(\s*['\"].*sh",
            r"hidden[_\s]?admin",
            r"secret[_\s]?backdoor",
            r"debug[_\s]?shell",
            r"master[_\s]?password",
        ],
        "description": "Backdoor/Remote Access"
    },
    "credential_harvesting": {
        "patterns": [
            r"keylog",
            r"password.*dump",
            r"credential.*steal",
            r"harvest.*password",
            r"capture.*credential",
            r"\.ssh/id_rsa",
            r"\.aws/credentials",
            r"/etc/shadow",
            r"mimikatz",
            r"lsass",
        ],
        "description": "Credential Harvesting"
    },
    "data_exfiltration": {
        "patterns": [
            r"exfil",
            r"upload.*sensitive",
            r"send.*to.*server",
            r"post.*data.*external",
            r"curl.*-d.*password",
            r"requests\.post.*secret",
            r"base64.*encode.*send",
            r"dns.*tunnel",
        ],
        "description": "Data Exfiltration"
    },
    "obfuscation": {
        "patterns": [
            r"exec\s*\(\s*base64",
            r"eval\s*\(\s*base64",
            r"fromCharCode",
            r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}",  # hex encoded strings
            r"chr\s*\(\s*\d+\s*\)\s*\+\s*chr",  # string building from chars
            r"exec\s*\(\s*['\"].*['\"]\s*\.\s*decode",
            r"__import__\s*\(\s*['\"]os",
            r"getattr.*__builtins__",
        ],
        "description": "Obfuscated Code Execution"
    },
    "crypto_mining": {
        "patterns": [
            r"stratum\+tcp",
            r"xmr\.pool",
            r"monero",
            r"coinhive",
            r"crypto.*mine",
            r"hashrate",
            r"--cpu-priority",
        ],
        "description": "Cryptocurrency Mining"
    },
    "persistence": {
        "patterns": [
            r"crontab",
            r"/etc/rc\.local",
            r"systemd.*service",
            r"HKEY.*Run",
            r"startup.*folder",
            r"launchd",
            r"\.bashrc.*curl",
            r"\.profile.*wget",
        ],
        "description": "Persistence Mechanism"
    },
    "privilege_escalation": {
        "patterns": [
            r"setuid",
            r"setgid",
            r"sudo.*NOPASSWD",
            r"chmod\s+[47]755",
            r"chmod\s+u\+s",
            r"pkexec",
            r"doas",
        ],
        "description": "Privilege Escalation"
    }
}

# Severity ranking for comparison
SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0
}


class WebhookService:
    """Service for managing and sending webhook alerts"""

    def __init__(self, db: Session, scanner_url: str = "http://localhost:8000"):
        self.db = db
        self.scanner_url = scanner_url
        self.http_client = httpx.AsyncClient(timeout=30.0)

    async def close(self):
        """Close the HTTP client"""
        await self.http_client.aclose()

    def _sign_payload(self, payload: str, secret: str) -> str:
        """
        Create HMAC-SHA256 signature for payload

        Args:
            payload: JSON string payload
            secret: Webhook secret key

        Returns:
            Hex-encoded HMAC-SHA256 signature
        """
        signature = hmac.new(
            secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        )
        return f"sha256={signature.hexdigest()}"

    def _check_malicious_intent(self, finding: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Check if a finding indicates malicious intent

        Args:
            finding: Finding dictionary with title, snippet, reason, etc.

        Returns:
            Tuple of (is_malicious, list of detected indicators)
        """
        indicators = []

        # Combine searchable text from finding
        search_text = " ".join([
            str(finding.get("title", "")),
            str(finding.get("snippet", "")),
            str(finding.get("reason", "")),
            str(finding.get("vulnerability_type", "")),
            str(finding.get("description", "")),
        ]).lower()

        # Check each indicator category
        for category, info in MALICIOUS_INDICATORS.items():
            for pattern in info["patterns"]:
                if re.search(pattern, search_text, re.IGNORECASE):
                    indicator_msg = f"{info['description']}: matched pattern '{pattern}'"
                    if indicator_msg not in indicators:
                        indicators.append(indicator_msg)
                    break  # One match per category is enough

        return len(indicators) > 0, indicators

    def _severity_meets_threshold(self, severity: str, min_severity: str) -> bool:
        """Check if severity meets minimum threshold"""
        severity_upper = severity.upper() if severity else "LOW"
        min_upper = min_severity.upper() if min_severity else "LOW"

        return SEVERITY_RANK.get(severity_upper, 0) >= SEVERITY_RANK.get(min_upper, 0)

    def _build_finding_payload(
        self,
        finding: Dict[str, Any],
        event_type: str,
        scan_id: int,
        indicators: List[str] = None
    ) -> Dict[str, Any]:
        """Build the webhook payload for a finding alert"""

        payload = {
            "event": event_type,
            "severity": finding.get("severity", "MEDIUM").upper(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": scan_id,
            "finding": {
                "id": finding.get("id"),
                "title": finding.get("title"),
                "file": finding.get("file_path"),
                "line": finding.get("line_number"),
                "snippet": finding.get("snippet", "")[:500],  # Truncate long snippets
                "vulnerability_type": finding.get("vulnerability_type"),
                "confidence": finding.get("confidence", finding.get("initial_votes", 1) * 20),
            },
            "scanner_url": f"{self.scanner_url}/scan/{scan_id}"
        }

        if indicators:
            payload["indicators"] = indicators

        if finding.get("reason"):
            payload["finding"]["reason"] = finding["reason"][:1000]

        return payload

    def _build_scan_complete_payload(
        self,
        scan_id: int,
        summary: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build the webhook payload for scan completion"""

        return {
            "event": "scan_complete",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": scan_id,
            "summary": {
                "total_findings": summary.get("total_findings", 0),
                "critical": summary.get("critical", 0),
                "high": summary.get("high", 0),
                "medium": summary.get("medium", 0),
                "low": summary.get("low", 0),
                "malicious_intent_count": summary.get("malicious_intent_count", 0),
                "files_scanned": summary.get("files_scanned", 0),
                "duration_seconds": summary.get("duration_seconds", 0),
            },
            "scanner_url": f"{self.scanner_url}/scan/{scan_id}"
        }

    async def _deliver_webhook(
        self,
        webhook: WebhookConfig,
        payload: Dict[str, Any],
        event_type: str,
        scan_id: Optional[int] = None,
        finding_id: Optional[int] = None
    ) -> bool:
        """
        Deliver a webhook payload to the configured endpoint

        Args:
            webhook: Webhook configuration
            payload: Payload dictionary to send
            event_type: Type of event being delivered
            scan_id: Associated scan ID
            finding_id: Associated finding ID

        Returns:
            True if delivery succeeded, False otherwise
        """
        # Create delivery log entry
        delivery_log = WebhookDeliveryLog(
            webhook_id=webhook.id,
            event_type=event_type,
            scan_id=scan_id,
            finding_id=finding_id,
            payload=payload,
            status="pending",
            attempt_count=1
        )
        self.db.add(delivery_log)
        self.db.flush()

        # Serialize payload
        payload_json = json.dumps(payload, default=str)

        # Build headers
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SecurityScanner-Webhook/1.0",
            "X-Webhook-Event": event_type,
            "X-Webhook-Delivery": str(delivery_log.id),
        }

        # Add signature if secret is configured
        if webhook.secret:
            signature = self._sign_payload(payload_json, webhook.secret)
            headers["X-Webhook-Signature"] = signature

        try:
            response = await self.http_client.post(
                webhook.url,
                content=payload_json,
                headers=headers
            )

            # Update delivery log
            delivery_log.status_code = response.status_code
            delivery_log.response_body = response.text[:1000] if response.text else None

            if 200 <= response.status_code < 300:
                delivery_log.status = "success"
                delivery_log.delivered_at = datetime.now(timezone.utc)

                # Update webhook stats
                webhook.last_triggered = datetime.now(timezone.utc)
                webhook.trigger_count = (webhook.trigger_count or 0) + 1
                webhook.last_error = None

                self.db.commit()
                return True
            else:
                delivery_log.status = "failed"
                delivery_log.error_message = f"HTTP {response.status_code}"
                webhook.last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                self.db.commit()
                return False

        except Exception as e:
            delivery_log.status = "failed"
            delivery_log.error_message = str(e)[:500]
            webhook.last_error = str(e)[:500]
            self.db.commit()
            return False

    def get_matching_webhooks(
        self,
        event_type: str,
        severity: Optional[str] = None
    ) -> List[WebhookConfig]:
        """
        Get all webhooks that match the event type and severity

        Args:
            event_type: Type of event (malicious_intent, critical_finding, scan_complete)
            severity: Finding severity (for filtering by min_severity)

        Returns:
            List of matching webhook configurations
        """
        webhooks = self.db.query(WebhookConfig).filter(
            WebhookConfig.enabled == True
        ).all()

        matching = []
        for webhook in webhooks:
            # Check if event type matches
            events = webhook.events or []
            if event_type not in events:
                continue

            # Check severity threshold for finding events
            if severity and event_type in ["critical_finding", "malicious_intent"]:
                if not self._severity_meets_threshold(severity, webhook.min_severity):
                    continue

            matching.append(webhook)

        return matching

    async def send_alert(
        self,
        finding: Dict[str, Any],
        scan_id: int,
        force_event_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send alert for a finding to all matching webhooks

        Args:
            finding: Finding dictionary with id, title, snippet, severity, etc.
            scan_id: ID of the scan
            force_event_type: Override automatic event type detection

        Returns:
            Dictionary with delivery results
        """
        # Check for malicious intent
        is_malicious, indicators = self._check_malicious_intent(finding)

        # Determine event type
        if force_event_type:
            event_type = force_event_type
        elif is_malicious:
            event_type = "malicious_intent"
        elif finding.get("severity", "").upper() == "CRITICAL":
            event_type = "critical_finding"
        else:
            event_type = "critical_finding"

        # Build payload
        payload = self._build_finding_payload(
            finding,
            event_type,
            scan_id,
            indicators if is_malicious else None
        )

        # Get matching webhooks
        webhooks = self.get_matching_webhooks(event_type, finding.get("severity"))

        results = {
            "event_type": event_type,
            "is_malicious": is_malicious,
            "indicators": indicators if is_malicious else [],
            "webhooks_matched": len(webhooks),
            "deliveries": []
        }

        # Send to all matching webhooks
        for webhook in webhooks:
            success = await self._deliver_webhook(
                webhook,
                payload,
                event_type,
                scan_id,
                finding.get("id")
            )
            results["deliveries"].append({
                "webhook_id": webhook.id,
                "webhook_name": webhook.name,
                "success": success
            })

        return results

    async def send_scan_complete(
        self,
        scan_id: int,
        summary: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Send scan completion notification to all matching webhooks

        Args:
            scan_id: ID of the completed scan
            summary: Summary statistics dictionary

        Returns:
            Dictionary with delivery results
        """
        event_type = "scan_complete"
        payload = self._build_scan_complete_payload(scan_id, summary)

        # Get matching webhooks (no severity filter for scan_complete)
        webhooks = self.get_matching_webhooks(event_type)

        results = {
            "event_type": event_type,
            "webhooks_matched": len(webhooks),
            "deliveries": []
        }

        for webhook in webhooks:
            success = await self._deliver_webhook(
                webhook,
                payload,
                event_type,
                scan_id
            )
            results["deliveries"].append({
                "webhook_id": webhook.id,
                "webhook_name": webhook.name,
                "success": success
            })

        return results

    async def send_test_webhook(self, webhook_id: int) -> Dict[str, Any]:
        """
        Send a test webhook to verify configuration

        Args:
            webhook_id: ID of the webhook to test

        Returns:
            Dictionary with test results
        """
        webhook = self.db.query(WebhookConfig).filter(
            WebhookConfig.id == webhook_id
        ).first()

        if not webhook:
            return {"success": False, "error": "Webhook not found"}

        # Build test payload
        payload = {
            "event": "test",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": "This is a test webhook from the Security Scanner",
            "webhook_id": webhook_id,
            "webhook_name": webhook.name,
            "scanner_url": self.scanner_url
        }

        success = await self._deliver_webhook(
            webhook,
            payload,
            "test",
            scan_id=None,
            finding_id=None
        )

        # Get the delivery log for details
        delivery = self.db.query(WebhookDeliveryLog).filter(
            WebhookDeliveryLog.webhook_id == webhook_id,
            WebhookDeliveryLog.event_type == "test"
        ).order_by(WebhookDeliveryLog.id.desc()).first()

        return {
            "success": success,
            "webhook_id": webhook_id,
            "webhook_name": webhook.name,
            "status_code": delivery.status_code if delivery else None,
            "response": delivery.response_body if delivery else None,
            "error": delivery.error_message if delivery else None
        }

    def get_recent_deliveries(
        self,
        limit: int = 50,
        webhook_id: Optional[int] = None,
        scan_id: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Get recent webhook delivery logs

        Args:
            limit: Maximum number of entries to return
            webhook_id: Filter by webhook ID
            scan_id: Filter by scan ID

        Returns:
            List of delivery log dictionaries
        """
        query = self.db.query(WebhookDeliveryLog)

        if webhook_id:
            query = query.filter(WebhookDeliveryLog.webhook_id == webhook_id)
        if scan_id:
            query = query.filter(WebhookDeliveryLog.scan_id == scan_id)

        deliveries = query.order_by(
            WebhookDeliveryLog.created_at.desc()
        ).limit(limit).all()

        return [
            {
                "id": d.id,
                "webhook_id": d.webhook_id,
                "webhook_name": d.webhook.name if d.webhook else None,
                "event_type": d.event_type,
                "scan_id": d.scan_id,
                "finding_id": d.finding_id,
                "status": d.status,
                "status_code": d.status_code,
                "error_message": d.error_message,
                "attempt_count": d.attempt_count,
                "created_at": d.created_at.isoformat() if d.created_at else None,
                "delivered_at": d.delivered_at.isoformat() if d.delivered_at else None,
            }
            for d in deliveries
        ]


# Convenience function to check a finding for malicious intent without sending
def analyze_malicious_intent(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a finding for malicious intent indicators without sending webhooks

    Args:
        finding: Finding dictionary

    Returns:
        Analysis result with is_malicious and indicators
    """
    service = WebhookService.__new__(WebhookService)
    is_malicious, indicators = service._check_malicious_intent(finding)

    return {
        "is_malicious": is_malicious,
        "indicators": indicators,
        "indicator_count": len(indicators)
    }
