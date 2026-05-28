"""Pull request scan Celery task."""

import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from app.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.db.models import (
    AITriageResult,
    Finding,
    PRComment,
    PullRequest,
    Repository,
    RepositorySettings,
    Scan,
)
from app.db.session import SessionLocal
from app.services.ai.triage import triage_findings
from app.services.audit import write_audit_log
from app.services.findings.baseline import mark_baseline_findings
from app.services.findings.risk_scorer import overall_risk_from_findings, score_finding, severity_breakdown
from app.services.github.auth import get_installation_token
from app.services.github.comments import build_inline_comment, build_summary_comment, post_inline_comment, post_pr_comment
from app.services.github.pr_files import download_file_content, fetch_pr_files
from app.services.policy.gate import evaluate_policy
from app.services.reports.json_export import generate_json_report
from app.services.reports.pdf_export import generate_pdf_report
from app.services.reports.sarif_export import generate_sarif_report
from app.services.scanners.orchestrator import ScanOrchestrator
from app.utils.hashing import finding_fingerprint
from app.utils.redaction import redact_dict_values, redact_secrets
from app.workers.celery_app import celery_app

configure_logging()
logger = get_logger(__name__)


@celery_app.task(bind=True, name="scan_pull_request", max_retries=3, default_retry_delay=30)
def scan_pull_request_task(
    self,
    scan_id: str,
    installation_id: int,
    repo_full_name: str,
    pr_number: int,
    head_sha: str,
):
    db = SessionLocal()
    settings = get_settings()
    scan_uuid = UUID(scan_id)
    workspace = Path(tempfile.mkdtemp(prefix="guardpr-scan-"))

    try:
        scan = db.query(Scan).filter(Scan.id == scan_uuid).first()
        if not scan:
            logger.error("scan_not_found", scan_id=scan_id)
            return

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()
        write_audit_log(db, "scan.started", resource_type="scan", resource_id=scan.id)
        db.commit()

        owner, repo = repo_full_name.split("/", 1)
        token = _run_async(get_installation_token(installation_id))

        pr_files = _run_async(fetch_pr_files(token, owner, repo, pr_number))
        for pf in pr_files:
            dest = workspace / pf.filename
            dest.parent.mkdir(parents=True, exist_ok=True)
            if pf.raw_url:
                content = _run_async(download_file_content(token, pf.raw_url))
                dest.write_text(content, encoding="utf-8")
            elif pf.patch:
                dest.write_text(pf.patch, encoding="utf-8")

        repo_row = (
            db.query(Repository)
            .join(PullRequest)
            .filter(PullRequest.id == scan.pull_request_id)
            .first()
        )
        repo_settings = None
        if repo_row:
            repo_settings = db.query(RepositorySettings).filter(RepositorySettings.repository_id == repo_row.id).first()

        orchestrator = ScanOrchestrator(
            enabled_scanners=(repo_settings.enabled_scanners if repo_settings else None) or ["semgrep", "gitleaks"],
            ignored_paths=(repo_settings.ignored_paths if repo_settings else None) or [],
        )
        raw_findings = orchestrator.run(workspace)

        triage_results = triage_findings(raw_findings) if settings.ai_triage_enabled else [None] * len(raw_findings)

        db_findings: list[Finding] = []
        severities: list[str] = []
        for raw, triage in zip(raw_findings, triage_results):
            triage = triage or {}
            meta = triage.pop("_meta", {})
            severity = triage.get("severity") or raw.severity
            confidence = triage.get("confidence") or "Medium"
            exploitability = triage.get("exploitability_score")

            if triage.get("is_likely_false_positive"):
                continue

            fp = finding_fingerprint(raw.scanner, raw.rule_id, raw.file_path, raw.line_start)
            risk_score = score_finding(severity, exploitability, confidence)

            finding = Finding(
                scan_id=scan.id,
                fingerprint=fp,
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
                raw_scanner_output=redact_dict_values(raw.raw),
                remediation=redact_secrets(triage.get("remediation", "")),
                secure_code_example=redact_secrets(triage.get("secure_code_example", "")),
                status="open",
                risk_score=risk_score,
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
            db_findings.append(finding)
            severities.append(severity)

        if repo_row:
            mark_baseline_findings(db, scan.id, repo_row.id, raw_findings)

        overall_risk, overall_score = overall_risk_from_findings(severities)
        scan.overall_risk = overall_risk
        scan.overall_risk_score = overall_score
        scan.findings_count = severity_breakdown(db_findings)
        scan.completed_at = datetime.now(timezone.utc)
        scan.status = "completed"
        if repo_row:
            repo_row.last_scan_at = scan.completed_at
            repo_row.security_score = max(0, 100 - overall_score)
        db.commit()

        # Reload findings with AI triage for inline comments
        from sqlalchemy.orm import joinedload

        db_findings = (
            db.query(Finding)
            .options(joinedload(Finding.ai_triage))
            .filter(Finding.scan_id == scan.id)
            .all()
        )

        dashboard_url = settings.frontend_url.rstrip("/")
        summary_body = build_summary_comment(scan.id, overall_risk, db_findings, dashboard_url)
        comment_id = _run_async(post_pr_comment(token, owner, repo, pr_number, summary_body))
        db.add(
            PRComment(
                scan_id=scan.id,
                github_comment_id=comment_id,
                comment_type="summary",
                body_redacted=summary_body,
            )
        )

        if repo_settings and repo_settings.inline_comments_enabled:
            for finding in db_findings:
                if finding.line_start and finding.is_newly_introduced:
                    inline_body = build_inline_comment(finding)
                    gh_id = _run_async(
                        post_inline_comment(token, owner, repo, pr_number, head_sha, finding.file_path, finding.line_start, inline_body)
                    )
                    db.add(
                        PRComment(
                            scan_id=scan.id,
                            finding_id=finding.id,
                            github_comment_id=gh_id,
                            comment_type="inline",
                            body_redacted=inline_body,
                        )
                    )

        policy = evaluate_policy(repo_settings, db_findings)
        if policy["blocked"]:
            policy_body = "## GuardPR AI Policy Gate\n\n**Merge blocked** by repository policy.\n\n" + "\n".join(f"- {w}" for w in policy["warnings"])
            _run_async(post_pr_comment(token, owner, repo, pr_number, policy_body))

        report_dir = Path(settings.report_storage_path)
        generate_json_report(db, scan, report_dir)
        generate_sarif_report(db, scan, report_dir)
        generate_pdf_report(db, scan, report_dir)

        write_audit_log(db, "scan.completed", resource_type="scan", resource_id=scan.id, metadata={"findings": len(db_findings)})
        write_audit_log(db, "comment.posted", resource_type="scan", resource_id=scan.id)
        db.commit()
        logger.info("scan_completed", scan_id=scan_id, findings=len(db_findings))

    except Exception as exc:
        logger.exception("scan_failed", scan_id=scan_id)
        scan = db.query(Scan).filter(Scan.id == scan_uuid).first()
        if scan:
            scan.status = "failed"
            scan.error_message = redact_secrets(str(exc))[:2000]
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
        raise self.retry(exc=exc) from exc
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
        db.close()


def _run_async(coro):
    import asyncio

    return asyncio.run(coro)
