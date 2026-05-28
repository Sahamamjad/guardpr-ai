"""JSON report export."""

import json
from pathlib import Path
from uuid import UUID

from sqlalchemy.orm import Session

from app.db.models import Finding, Scan, ScanReport
from app.utils.redaction import redact_secrets


def generate_json_report(db: Session, scan: Scan, storage_dir: Path) -> ScanReport:
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    pr = scan.pull_request
    repo = pr.repository if pr else None

    report = {
        "repository": repo.full_name if repo else None,
        "pr_number": pr.pr_number if pr else None,
        "scan_id": str(scan.id),
        "scan_date": scan.completed_at.isoformat() if scan.completed_at else None,
        "overall_risk": scan.overall_risk,
        "overall_risk_score": float(scan.overall_risk_score) if scan.overall_risk_score else None,
        "findings_summary": scan.findings_count,
        "findings": [
            {
                "id": str(f.id),
                "scanner": f.scanner_name,
                "severity": f.severity,
                "title": redact_secrets(f.title or ""),
                "file_path": f.file_path,
                "line": f.line_start,
                "owasp_category": f.owasp_category,
                "status": f.status,
                "remediation": redact_secrets(f.remediation or ""),
                "exploitability_score": f.exploitability_score,
            }
            for f in findings
        ],
        "recommended_next_steps": _next_steps(scan.overall_risk),
    }

    storage_dir.mkdir(parents=True, exist_ok=True)
    path = storage_dir / f"{scan.id}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    record = ScanReport(scan_id=scan.id, format="json", storage_path=str(path))
    db.add(record)
    db.flush()
    return record


def _next_steps(risk: str | None) -> list[str]:
    if risk in {"Critical", "High"}:
        return ["Fix Critical/High findings before merge.", "Re-run scan after remediation."]
    if risk == "Medium":
        return ["Review Medium findings and accept or remediate.", "Consider adding tests for fixed issues."]
    return ["No blocking issues detected.", "Continue standard code review."]
