"""Run a local demo scan without GitHub — for testing the dashboard."""

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.base import Base
from app.db.models import AITriageResult, Finding, GitHubInstallation, PullRequest, Repository, Scan, User
from app.db.session import SessionLocal, engine
from app.services.ai.triage import triage_findings
from app.services.audit import write_audit_log
from app.services.findings.risk_scorer import overall_risk_from_findings, score_finding, severity_breakdown
from app.services.scanners.orchestrator import ScanOrchestrator
from app.utils.hashing import finding_fingerprint
from app.utils.redaction import redact_secrets

DEMO_WORKSPACE = Path("/demo/vulnerable-flask-api")
if not DEMO_WORKSPACE.exists():
    DEMO_WORKSPACE = Path(__file__).resolve().parents[2] / "demo" / "vulnerable-flask-api"


def run_demo_scan():
    if not DEMO_WORKSPACE.exists():
        print(f"Demo code not found at {DEMO_WORKSPACE}")
        sys.exit(1)

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        inst = db.query(GitHubInstallation).filter(GitHubInstallation.account_login == "demo-org").first()
        if not inst:
            print("Run seed_demo_data.py first")
            sys.exit(1)

        repo = db.query(Repository).filter(Repository.full_name == "demo-org/vulnerable-flask-api").first()
        pr = db.query(PullRequest).filter(PullRequest.repository_id == repo.id, PullRequest.pr_number == 1).first()

        scan = Scan(
            pull_request_id=pr.id,
            status="running",
            trigger_event="demo.local_scan",
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.flush()
        write_audit_log(db, "scan.started", resource_type="scan", resource_id=scan.id, metadata={"mode": "demo"})
        db.commit()

        print(f"Scanning {DEMO_WORKSPACE} ...")
        orchestrator = ScanOrchestrator(enabled_scanners=["semgrep", "gitleaks"])
        raw_findings = orchestrator.run(DEMO_WORKSPACE)
        triage_results = triage_findings(raw_findings)

        severities = []
        for raw, triage in zip(raw_findings, triage_results):
            triage = triage or {}
            meta = triage.pop("_meta", {})
            if triage.get("is_likely_false_positive"):
                continue

            severity = triage.get("severity") or raw.severity
            confidence = triage.get("confidence") or "Medium"
            exploitability = triage.get("exploitability_score")

            finding = Finding(
                scan_id=scan.id,
                fingerprint=finding_fingerprint(raw.scanner, raw.rule_id, raw.file_path, raw.line_start),
                scanner_name=raw.scanner,
                rule_id=raw.rule_id,
                file_path=raw.file_path,
                line_start=raw.line_start,
                line_end=raw.line_end,
                severity=severity,
                confidence=confidence,
                vulnerability_type=raw.title,
                owasp_category=triage.get("owasp_category"),
                title=triage.get("title") or raw.title,
                description=redact_secrets(triage.get("technical_explanation") or raw.description),
                remediation=redact_secrets(triage.get("remediation", "")),
                secure_code_example=redact_secrets(triage.get("secure_code_example", "")),
                status="open",
                risk_score=score_finding(severity, exploitability, confidence),
                exploitability_score=exploitability,
                is_newly_introduced=True,
            )
            db.add(finding)
            db.flush()
            if triage:
                db.add(
                    AITriageResult(
                        finding_id=finding.id,
                        model_name=meta.get("model_name"),
                        prompt_version=meta.get("prompt_version"),
                        triage_json=triage,
                        tokens_used=meta.get("tokens_used"),
                        latency_ms=meta.get("latency_ms"),
                    )
                )
            severities.append(severity)

        overall_risk, overall_score = overall_risk_from_findings(severities)
        scan.status = "completed"
        scan.overall_risk = overall_risk
        scan.overall_risk_score = overall_score
        scan.findings_count = severity_breakdown(raw_findings)
        scan.completed_at = datetime.now(timezone.utc)
        repo.security_score = max(0, 100 - overall_score)
        repo.last_scan_at = scan.completed_at

        write_audit_log(db, "scan.completed", resource_type="scan", resource_id=scan.id, metadata={"findings": len(severities), "mode": "demo"})
        db.commit()

        print(f"Demo scan complete: {scan.id}")
        print(f"Risk: {overall_risk} | Findings: {len(severities)}")
        print(f"Open dashboard → scan: http://localhost:5173/scans/{scan.id}")
    finally:
        db.close()


if __name__ == "__main__":
    run_demo_scan()
