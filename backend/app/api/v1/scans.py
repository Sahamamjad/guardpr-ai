"""Scan API."""

from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.exceptions import NotFoundError
from app.db.models import AITriageResult, Finding, PullRequest, Repository, Scan, User
from app.db.session import get_db
from app.dependencies import get_current_user
from app.schemas import ScanResponse
from app.services.audit import write_audit_log
from app.workers.tasks.scan_pr import scan_pull_request_task

router = APIRouter(prefix="/scans", tags=["scans"])


def _scan_to_response(scan: Scan, db: Session) -> dict:
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    finding_payload = []
    for f in findings:
        triage = db.query(AITriageResult).filter(AITriageResult.finding_id == f.id).first()
        finding_payload.append(
            {
                "id": f.id,
                "scanner_name": f.scanner_name,
                "rule_id": f.rule_id,
                "file_path": f.file_path,
                "line_start": f.line_start,
                "severity": f.severity,
                "confidence": f.confidence,
                "owasp_category": f.owasp_category,
                "title": f.title,
                "description": f.description,
                "remediation": f.remediation,
                "secure_code_example": f.secure_code_example,
                "status": f.status,
                "risk_score": float(f.risk_score) if f.risk_score else None,
                "exploitability_score": f.exploitability_score,
                "is_newly_introduced": f.is_newly_introduced,
                "ai_triage": triage.triage_json if triage else None,
            }
        )
    pr = db.query(PullRequest).filter(PullRequest.id == scan.pull_request_id).first()
    return {
        "id": scan.id,
        "status": scan.status,
        "trigger_event": scan.trigger_event,
        "overall_risk": scan.overall_risk,
        "overall_risk_score": float(scan.overall_risk_score) if scan.overall_risk_score else None,
        "findings_count": scan.findings_count,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "created_at": scan.created_at,
        "pull_request": pr,
        "findings": finding_payload,
    }


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise NotFoundError("Scan not found")
    return _scan_to_response(scan, db)


@router.post("/{scan_id}/rerun")
def rerun_scan(
    scan_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise NotFoundError("Scan not found")
    pr = db.query(PullRequest).filter(PullRequest.id == scan.pull_request_id).first()
    repo = db.query(Repository).filter(Repository.id == pr.repository_id).first()
    installation = repo.installation

    new_scan = Scan(
        pull_request_id=pr.id,
        status="queued",
        trigger_event="manual.rerun",
        head_sha=pr.head_sha,
    )
    db.add(new_scan)
    db.flush()
    write_audit_log(db, "scan.rerun", actor_user_id=user.id, actor_type="user", resource_type="scan", resource_id=new_scan.id)
    db.commit()

    scan_pull_request_task.delay(
        str(new_scan.id),
        installation.installation_id,
        repo.full_name,
        pr.pr_number,
        pr.head_sha or "",
    )
    return {"scan_id": str(new_scan.id), "status": "queued"}


@router.get("/{scan_id}/report")
def download_report(
    scan_id: UUID,
    format: str = "json",
    db: Annotated[Session, Depends(get_db)] = None,
    user: Annotated[User, Depends(get_current_user)] = None,
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise NotFoundError("Scan not found")

    settings = get_settings()
    ext = {"json": "json", "pdf": "pdf", "sarif": "sarif.json"}.get(format, "json")
    path = Path(settings.report_storage_path) / f"{scan_id}.{ext}"
    if not path.exists():
        from app.services.reports.json_export import generate_json_report
        from app.services.reports.pdf_export import generate_pdf_report
        from app.services.reports.sarif_export import generate_sarif_report

        report_dir = Path(settings.report_storage_path)
        if format == "pdf":
            generate_pdf_report(db, scan, report_dir)
        elif format == "sarif":
            generate_sarif_report(db, scan, report_dir)
        else:
            generate_json_report(db, scan, report_dir)
        db.commit()

    write_audit_log(db, "report.exported", actor_user_id=user.id, resource_type="scan", resource_id=scan.id, metadata={"format": format})
    db.commit()

    media = {"json": "application/json", "pdf": "application/pdf", "sarif": "application/sarif+json"}.get(format, "application/octet-stream")
    return FileResponse(path, media_type=media, filename=f"guardpr-{scan_id}.{ext}")


@router.get("/{scan_id}/sarif")
def download_sarif(
    scan_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    return download_report(scan_id, format="sarif", db=db, user=user)
