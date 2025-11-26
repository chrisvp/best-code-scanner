# Feature Roadmap

Future features to implement. This document captures ideas for later development.

---

## 1. GitLab Merge Request Reviewer

### Overview
Automated security review of GitLab merge requests with continuous repo watching.

### Components

#### 1.1 Repo Watchers Tab
- New tab in UI: "Repo Watchers"
- List of configured repository watchers with status (running/paused/error)
- Start/stop controls for each watcher
- Real-time status indicators

#### 1.2 Watcher Configuration
Each repo watcher config includes:
- **GitLab connection**: URL, access token, project ID
- **Trigger settings**: Watch all MRs, specific branches, specific labels
- **Scan profile**: Link to existing scan profile (reuse profiles from Settings)
- **Review models**: Which models to use for MR review vs full scan
- **Notification settings**: Who to notify, webhook URLs

#### 1.3 Two-Phase Review Process

**Phase 1: Classic MR Diff Review**
- Analyze the diff/patch directly
- Post inline comments on specific lines
- General MR summary comment
- Approve/request changes based on findings

**Phase 2: Full File Scan**
- Scan all files that were changed (not just the diff)
- Run through selected scan profile
- Cross-reference findings with the specific changes
- Flag new vulnerabilities introduced by the MR

#### 1.4 Database Models
```python
class RepoWatcher(Base):
    id = Column(Integer, primary_key=True)
    name = Column(String)
    gitlab_url = Column(String)
    gitlab_token = Column(String)  # encrypted
    project_id = Column(String)
    branch_filter = Column(String)  # regex or glob
    scan_profile_id = Column(Integer, ForeignKey("scan_profiles.id"))
    review_model_id = Column(Integer, ForeignKey("model_configs.id"))
    status = Column(String)  # running, paused, error
    last_check = Column(DateTime)
    webhook_url = Column(String)  # for alerts
    enabled = Column(Boolean, default=True)

class MRReview(Base):
    id = Column(Integer, primary_key=True)
    watcher_id = Column(Integer, ForeignKey("repo_watchers.id"))
    mr_iid = Column(Integer)
    mr_title = Column(String)
    mr_url = Column(String)
    status = Column(String)  # pending, reviewing, completed
    diff_findings = Column(JSON)
    scan_id = Column(Integer, ForeignKey("scans.id"))  # full scan
    created_at = Column(DateTime)
```

---

## 2. Findings Analysis & Prioritization

### Overview
AI-powered analysis button that reviews all findings and provides actionable recommendations.

### Features

#### 2.1 "Analyze Findings" Button
Add to scan details view, triggers analysis of all findings.

#### 2.2 Recommendation Categories
- **Most Critical**: Highest risk findings that need immediate attention
- **Quick Wins**: Easy fixes that can be done quickly (low effort, high impact)
- **Grouped by Root Cause**: Findings that share the same underlying issue

#### 2.3 Output Format
```json
{
  "summary": "15 findings analyzed...",
  "critical_priority": [
    {"finding_id": 1, "reason": "Remote code execution in auth handler"}
  ],
  "quick_wins": [
    {"finding_id": 5, "reason": "Simple input validation fix, 2 lines", "effort": "5 min"}
  ],
  "grouped": {
    "Missing input validation": [3, 5, 7],
    "Hardcoded secrets": [2, 9]
  },
  "remediation_order": [1, 5, 3, 2, ...]
}
```

#### 2.4 UI
- Modal or side panel showing analysis results
- Click-to-navigate to specific findings
- Export as report/checklist

---

## 3. Quick Chat Window

### Overview
Simple chat interface for quick questions about the codebase or findings.

### Features

#### 3.1 Chat Panel
- Collapsible chat panel in bottom-right corner
- Available on all pages
- Context-aware (knows current scan if viewing one)

#### 3.2 Client-Side History
- Store chat history in localStorage
- Clear history button
- History persists across page refreshes
- Separate history per scan

#### 3.3 Capabilities
- Ask about specific findings
- Ask about code patterns
- Get remediation advice
- General security questions

#### 3.4 Implementation
```javascript
// Client-side storage
const CHAT_KEY = `chat_history_${scanId}`;
const history = JSON.parse(localStorage.getItem(CHAT_KEY) || '[]');

function saveMessage(role, content) {
  history.push({ role, content, timestamp: Date.now() });
  localStorage.setItem(CHAT_KEY, JSON.stringify(history));
}

function clearHistory() {
  localStorage.removeItem(CHAT_KEY);
}
```

---

## 4. Webhook Security Alerts

### Overview
Real-time webhook notifications for findings that indicate malicious intent.

### Trigger Conditions

#### 4.1 Malicious Intent Indicators
- Backdoor patterns detected
- Suspicious obfuscation
- Credential harvesting code
- Data exfiltration patterns
- Known malware signatures
- Unusual network callbacks
- Crypto mining code
- Reverse shells

#### 4.2 Alert Severity Levels
- **CRITICAL**: Definite malicious code (backdoor, malware)
- **HIGH**: Suspicious patterns warranting investigation
- **MEDIUM**: Unusual code that could be legitimate

### Webhook Payload
```json
{
  "alert_type": "malicious_intent",
  "severity": "CRITICAL",
  "timestamp": "2024-01-15T10:30:00Z",
  "scan_id": 123,
  "finding": {
    "id": 456,
    "title": "Backdoor detected in auth module",
    "file": "src/auth/login.py",
    "line": 45,
    "snippet": "...",
    "confidence": 95
  },
  "indicators": [
    "Base64 encoded shell command",
    "Network callback to external IP",
    "Code hidden in error handler"
  ],
  "source": {
    "repo": "https://gitlab.example.com/project",
    "branch": "feature/new-auth",
    "commit": "abc123",
    "author": "user@example.com"
  }
}
```

### Configuration
```python
class WebhookConfig(Base):
    id = Column(Integer, primary_key=True)
    name = Column(String)
    url = Column(String)
    secret = Column(String)  # for HMAC signing
    events = Column(JSON)  # ["malicious_intent", "critical_finding", "scan_complete"]
    min_severity = Column(String)  # CRITICAL, HIGH, MEDIUM
    enabled = Column(Boolean, default=True)
```

### Integration Points
- Slack (formatted messages with actions)
- Discord
- Microsoft Teams
- PagerDuty
- Custom webhooks
- Email (SMTP)

---

## Implementation Priority

| Feature | Effort | Impact | Priority |
|---------|--------|--------|----------|
| Quick Chat | Low | Medium | 1 |
| Findings Analysis | Medium | High | 2 |
| Webhook Alerts | Medium | High | 3 |
| GitLab MR Reviewer | High | Very High | 4 |

---

## Notes

- GitLab MR reviewer could later extend to GitHub PRs
- Webhook alerts should integrate with existing static rules system
- Chat could use existing interactive agent code from `agent_runtime.py`
- Consider rate limiting for webhook alerts to prevent spam
