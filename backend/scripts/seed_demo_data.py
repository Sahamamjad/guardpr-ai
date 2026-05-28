"""Seed demo user, repository, and sample scan findings."""

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.security import hash_password
from app.db.models import (
    AITriageResult,
    Finding,
    GitHubInstallation,
    PullRequest,
    Repository,
    Scan,
    User,
)
from app.db.session import SessionLocal, engine
from app.db.base import Base
from app.utils.hashing import finding_fingerprint


DEMO_FINDINGS = [
    {
        "scanner_name": "semgrep",
        "rule_id": "python.lang.security.audit.formatted-sql-query",
        "file_path": "app.py",
        "line_start": 14,
        "severity": "High",
        "confidence": "High",
        "title": "SQL Injection Risk",
        "description": "User input is concatenated into a SQL query without sanitization.",
        "owasp_category": "A03: Injection",
        "remediation": "Use parameterized queries instead of string concatenation.",
        "secure_code_example": "cursor.execute('SELECT * FROM users WHERE email = %s', (email,))",
        "exploitability_score": 8,
        "triage": {
            "title": "SQL Injection Risk",
            "severity": "High",
            "confidence": "High",
            "owasp_category": "A03: Injection",
            "exploitability_score": 8,
            "business_impact": "An attacker may access or modify unauthorized database records.",
            "technical_explanation": "The email parameter is interpolated into the SQL string via an f-string.",
            "remediation": "Use parameterized queries instead of string concatenation.",
            "secure_code_example": "cursor.execute('SELECT * FROM users WHERE email = %s', (email,))",
            "false_positive_reasoning": "User-controlled input reaches a SQL execution sink.",
            "developer_comment": "Replace f-string SQL with parameterized queries before merge.",
            "is_likely_false_positive": False,
        },
    },
    {
        "scanner_name": "semgrep",
        "rule_id": "python.flask.security.xss.audit.explicit-unescaped-without-markup",
        "file_path": "app.py",
        "line_start": 21,
        "severity": "Medium",
        "confidence": "High",
        "title": "Cross-Site Scripting (XSS)",
        "description": "User input is returned in HTML without escaping.",
        "owasp_category": "A03: Injection",
        "remediation": "Escape user input or use a templating engine with auto-escaping.",
        "secure_code_example": "from markupsafe import escape\nreturn f'<html><body>Results for: {escape(q)}</body></html>'",
        "exploitability_score": 6,
        "triage": {
            "title": "Reflected XSS",
            "severity": "Medium",
            "confidence": "High",
            "owasp_category": "A03: Injection",
            "exploitability_score": 6,
            "business_impact": "Attackers could execute scripts in victims' browsers.",
            "technical_explanation": "The search query parameter is reflected directly into HTML.",
            "remediation": "HTML-escape all user-controlled output.",
            "secure_code_example": "return render_template('search.html', q=q)",
            "false_positive_reasoning": "Reflected user input in HTML response without encoding.",
            "developer_comment": "Escape or sanitize the q parameter before rendering.",
            "is_likely_false_positive": False,
        },
    },
    {
        "scanner_name": "gitleaks",
        "rule_id": "generic-api-key",
        "file_path": ".env.example",
        "line_start": 1,
        "severity": "High",
        "confidence": "High",
        "title": "Hardcoded Secret Detected",
        "description": "A potential API key or secret was found in source code.",
        "owasp_category": "A07: Identification and Authentication Failures",
        "remediation": "Remove secrets from code and use environment variables or a secrets manager.",
        "secure_code_example": "API_KEY = os.environ.get('API_KEY')",
        "exploitability_score": 7,
        "triage": {
            "title": "Hardcoded Secret",
            "severity": "High",
            "confidence": "High",
            "owasp_category": "A07: Identification and Authentication Failures",
            "exploitability_score": 7,
            "business_impact": "Leaked credentials may allow unauthorized API access.",
            "technical_explanation": "Scanner detected a secret-like pattern in committed files.",
            "remediation": "Rotate the credential and store it outside the repository.",
            "secure_code_example": "Load secrets from environment variables only.",
            "false_positive_reasoning": "Pattern matches known secret formats.",
            "developer_comment": "Remove hardcoded secrets and rotate affected credentials.",
            "is_likely_false_positive": False,
        },
    },
]


def seed():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.email == "admin@guardpr.local").first():
            db.add(User(email="admin@guardpr.local", password_hash=hash_password("admin123"), full_name="Admin", role="admin"))

        inst = db.query(GitHubInstallation).filter(GitHubInstallation.account_login == "demo-org").first()
        if not inst:
            inst = GitHubInstallation(installation_id=999001, account_login="demo-org", account_type="Organization", is_active=True)
            db.add(inst)
            db.flush()

        repo = db.query(Repository).filter(Repository.full_name == "demo-org/vulnerable-flask-api").first()
        if not repo:
            repo = Repository(installation_id=inst.id, github_repo_id=999001, full_name="demo-org/vulnerable-flask-api", default_branch="main")
            db.add(repo)
            db.flush()

        pr = db.query(PullRequest).filter(PullRequest.repository_id == repo.id, PullRequest.pr_number == 1).first()
        if not pr:
            pr = PullRequest(
                repository_id=repo.id,
                pr_number=1,
                title="Add user login endpoint",
                author_login="dev1",
                state="open",
                github_url="https://github.com/demo-org/vulnerable-flask-api/pull/1",
            )
            db.add(pr)
            db.flush()

        # Create a fresh completed demo scan with findings
        scan = Scan(
            pull_request_id=pr.id,
            status="completed",
            trigger_event="demo.seed",
            overall_risk="High",
            overall_risk_score=80.0,
            findings_count={"high": 2, "medium": 1, "low": 0},
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.flush()

        for item in DEMO_FINDINGS:
            fp = finding_fingerprint(item["scanner_name"], item["rule_id"], item["file_path"], item["line_start"])
            finding = Finding(
                scan_id=scan.id,
                fingerprint=fp,
                scanner_name=item["scanner_name"],
                rule_id=item["rule_id"],
                file_path=item["file_path"],
                line_start=item["line_start"],
                severity=item["severity"],
                confidence=item["confidence"],
                title=item["title"],
                description=item["description"],
                owasp_category=item["owasp_category"],
                remediation=item["remediation"],
                secure_code_example=item["secure_code_example"],
                exploitability_score=item["exploitability_score"],
                risk_score=75.0,
                status="open",
                is_newly_introduced=True,
            )
            db.add(finding)
            db.flush()
            db.add(
                AITriageResult(
                    finding_id=finding.id,
                    model_name="demo",
                    prompt_version="v1",
                    triage_json=item["triage"],
                )
            )

        repo.security_score = 20.0
        repo.last_scan_at = scan.completed_at
        db.commit()
        print("Demo data seeded with findings.")
        print("Login: admin@guardpr.local / admin123")
        print(f"Demo scan: http://localhost:5173/scans/{scan.id}")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
