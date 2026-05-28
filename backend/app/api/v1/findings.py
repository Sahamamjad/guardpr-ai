"""Finding API."""

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.db.models import AITriageResult, Finding, User
from app.db.session import get_db
from app.dependencies import get_current_user
from app.schemas import AcceptRiskRequest, FalsePositiveRequest
from app.services.audit import write_audit_log

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/{finding_id}")
def get_finding(
    finding_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise NotFoundError("Finding not found")
    triage = db.query(AITriageResult).filter(AITriageResult.finding_id == finding.id).first()
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "scanner_name": finding.scanner_name,
        "rule_id": finding.rule_id,
        "file_path": finding.file_path,
        "line_start": finding.line_start,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "owasp_category": finding.owasp_category,
        "title": finding.title,
        "description": finding.description,
        "remediation": finding.remediation,
        "secure_code_example": finding.secure_code_example,
        "status": finding.status,
        "risk_score": float(finding.risk_score) if finding.risk_score else None,
        "exploitability_score": finding.exploitability_score,
        "is_newly_introduced": finding.is_newly_introduced,
        "exists_in_baseline": finding.exists_in_baseline,
        "ai_triage": triage.triage_json if triage else None,
        "created_at": finding.created_at,
        "updated_at": finding.updated_at,
    }


@router.post("/{finding_id}/false-positive")
def mark_false_positive(
    finding_id: UUID,
    payload: FalsePositiveRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise NotFoundError("Finding not found")
    finding.status = "false_positive"
    finding.updated_at = datetime.now(timezone.utc)
    write_audit_log(
        db,
        "finding.false_positive",
        actor_user_id=user.id,
        actor_type="user",
        resource_type="finding",
        resource_id=finding.id,
        metadata={"reason": payload.reason},
    )
    db.commit()
    return {"id": str(finding.id), "status": finding.status}


@router.post("/{finding_id}/accept-risk")
def accept_risk(
    finding_id: UUID,
    payload: AcceptRiskRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise NotFoundError("Finding not found")
    finding.status = "accepted_risk"
    finding.updated_at = datetime.now(timezone.utc)
    write_audit_log(
        db,
        "finding.accepted_risk",
        actor_user_id=user.id,
        actor_type="user",
        resource_type="finding",
        resource_id=finding.id,
        metadata={"reason": payload.reason, "expires_at": payload.expires_at.isoformat() if payload.expires_at else None},
    )
    db.commit()
    return {"id": str(finding.id), "status": finding.status}
