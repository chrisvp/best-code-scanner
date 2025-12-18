# Report Generator

Quality analysis report generation service for scan assessment and comparison.

## Overview

The `ReportGenerator` service computes quality metrics from scan data and generates comprehensive reports. Reports are compute-based (no LLM calls) and analyze:

- Draft finding precision (true positive rate)
- Verification voting patterns and consensus
- CWE distribution and diversity
- Performance metrics (speed, token efficiency)
- Overall quality grade (A-F)

## Usage

```python
from app.core.database import SessionLocal
from app.services.analysis.report_generator import ReportGenerator

db = SessionLocal()
generator = ReportGenerator(db)

# Generate single scan report
report = await generator.generate_scan_report(scan_id=123)

# Generate comparative report across multiple scans
report = await generator.generate_comparative_report(
    scan_ids=[123, 124, 125],
    primary_scan_id=123  # Optional, defaults to first
)
```

## Report Types

### Quality Analysis (Single Scan)

Analyzes a single scan's quality metrics:

```python
report = await generator.generate_scan_report(scan_id=123)

# Access report data
data = report.report_data
grade = report.overall_grade  # A, B, C, D, F
draft_precision = data["draft_metrics"]["draft_precision"]
cwe_distribution = data["cwe_metrics"]["distribution"]
```

**Report Structure:**
```json
{
  "draft_metrics": {
    "total_drafts": 148,
    "drafts_verified": 75,
    "drafts_rejected": 54,
    "drafts_weakness": 19,
    "draft_precision": 0.507
  },
  "verification_metrics": {
    "total_votes": 780,
    "avg_confidence": 73.9,
    "consensus_rate": 0.007
  },
  "findings_metrics": {
    "total": 76,
    "critical": 2,
    "high": 53,
    "medium": 20,
    "low": 1
  },
  "cwe_metrics": {
    "distribution": {"CWE-190": 66, "CWE-120": 37, ...},
    "top_cwe": "CWE-190",
    "diversity_score": 2.11
  },
  "performance_metrics": {
    "total_time_ms": 45000,
    "findings_per_minute": 101.3,
    "avg_tokens_per_finding": 1250
  },
  "quality_issues": [
    {
      "type": "low_consensus",
      "severity": "medium",
      "message": "Low verification consensus (0.7%). Verifiers frequently disagree."
    }
  ],
  "grade": "F",
  "grade_score": 49.0
}
```

### Comparative Analysis (Multiple Scans)

Compares multiple scans and analyzes model performance:

```python
report = await generator.generate_comparative_report(
    scan_ids=[123, 124, 125]
)

# Access comparative data
data = report.report_data
model_stats = data["model_stats"]  # Per-model precision
individual_reports = data["individual_reports"]
```

**Comparative Report Structure:**
```json
{
  "scan_ids": [123, 124, 125],
  "individual_reports": [
    {
      "scan_id": 123,
      "grade": "F",
      "grade_score": 49.0,
      "draft_count": 148,
      "verified_count": 75,
      "false_positive_rate": 0.365
    },
    ...
  ],
  "aggregate_metrics": {
    "total_drafts": 400,
    "drafts_verified": 200,
    "avg_grade_score": 65.5
  },
  "model_stats": {
    "llama3.3-70b": {
      "total_drafts": 150,
      "verified": 80,
      "rejected": 50,
      "weakness": 20,
      "precision": 0.533
    },
    "qwen2.5-32b": {
      "total_drafts": 140,
      "verified": 90,
      "rejected": 40,
      "weakness": 10,
      "precision": 0.643
    }
  }
}
```

## Grading System

Reports are graded A-F based on multiple quality factors:

| Grade | Score | Description |
|-------|-------|-------------|
| A | 90-100 | Excellent quality, high precision, good consensus |
| B | 80-89 | Good quality, minor issues |
| C | 70-79 | Acceptable quality, some concerns |
| D | 60-69 | Poor quality, needs improvement |
| F | 0-59 | Failing quality, major issues |

**Grading Criteria (100 points total):**
- **Draft Precision (50%)**: verified / total_drafts
- **Verification Consensus (20%)**: % of findings with unanimous votes
- **CWE Diversity (15%)**: Shannon entropy of CWE distribution
- **Findings Quality (15%)**: Ratio of critical/high vs medium/low

## Quality Issues Detection

The report generator automatically detects common quality issues:

### Low Precision
```json
{
  "type": "low_precision",
  "severity": "high",
  "message": "Low draft precision (45%). Over half of initial findings are false positives."
}
```
**Trigger**: Draft precision < 50%

### CWE Spam
```json
{
  "type": "cwe_spam",
  "severity": "medium",
  "message": "Potential CWE spam: CWE-190 represents 82% of all findings."
}
```
**Trigger**: Single CWE > 60% of total

### Low Consensus
```json
{
  "type": "low_consensus",
  "severity": "medium",
  "message": "Low verification consensus (35%). Verifiers frequently disagree."
}
```
**Trigger**: Consensus rate < 50%

### Low Diversity
```json
{
  "type": "low_diversity",
  "severity": "low",
  "message": "Low CWE diversity. Model may be biased toward certain vulnerability types."
}
```
**Trigger**: Shannon entropy < 1.0

## Database Schema

Reports are stored in the `scan_reports` table with a flexible JSON-based structure:

```sql
CREATE TABLE scan_reports (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    report_type VARCHAR NOT NULL,  -- 'quality_analysis', 'comparative'
    report_data JSON NOT NULL,  -- Full report data

    -- Quick-access denormalized fields
    overall_grade VARCHAR,
    draft_count INTEGER,
    verified_count INTEGER,
    false_positive_rate FLOAT,

    -- Metadata
    title VARCHAR,
    summary TEXT,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- For comparative reports
    related_scan_ids JSON
);
```

The `report_data` JSON field stores the full structured report, while denormalized fields enable efficient querying without parsing JSON.

## Performance Metrics

The report generator computes performance statistics from `scan_metrics` table:

- **Total Time**: End-to-end scan duration
- **Findings Per Minute**: Finding detection throughput
- **Avg Tokens Per Finding**: Token efficiency

## CWE Analysis

CWE distribution is analyzed using Shannon entropy to detect:
- **Low diversity**: Model bias toward certain CWE types
- **CWE spam**: Single CWE dominating results (e.g., CWE-190 spam from integer overflow false positives)

**Shannon Entropy Formula:**
```
H = -Σ(p_i * log2(p_i))
```

Where `p_i` is the probability of each CWE.

**Interpretation:**
- `H < 1.0`: Very low diversity (2-3 dominant CWEs)
- `H = 1.5-2.5`: Normal diversity (5-10 CWEs)
- `H > 3.0`: High diversity (many different CWEs)

## Example: Analyzing Scan Quality

```python
import asyncio
from app.core.database import SessionLocal
from app.services.analysis.report_generator import ReportGenerator

async def analyze_scan(scan_id: int):
    db = SessionLocal()
    try:
        generator = ReportGenerator(db)
        report = await generator.generate_scan_report(scan_id)

        print(f"Scan {scan_id} Grade: {report.overall_grade}")
        print(f"Draft Precision: {report.false_positive_rate:.1%} FP rate")

        # Check for issues
        issues = report.report_data.get("quality_issues", [])
        if issues:
            print(f"Found {len(issues)} quality issues:")
            for issue in issues:
                print(f"  - [{issue['severity']}] {issue['message']}")

        # Check CWE distribution
        cwe_dist = report.report_data["cwe_metrics"]["distribution"]
        print(f"Top 3 CWEs:")
        for cwe, count in sorted(cwe_dist.items(), key=lambda x: x[1], reverse=True)[:3]:
            print(f"  {cwe}: {count}")

    finally:
        db.close()

asyncio.run(analyze_scan(123))
```

## Testing

Run the test script to validate report generation:

```bash
cd /home/aiadmin/web-davy-code-scanner/backend
python test_report_generator.py
```

## Future Enhancements

Planned features (not yet implemented):

1. **LLM-Enhanced Reports**: Generate natural language summaries and insights
2. **Trend Analysis**: Track quality metrics over time
3. **Benchmark Comparison**: Compare against known vulnerability datasets
4. **Recommendation Engine**: Suggest configuration improvements based on quality issues
5. **Export Formats**: PDF, HTML, Markdown report generation
