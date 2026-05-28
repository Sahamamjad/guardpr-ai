"""Audit log API."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.models import AuditLog, User
from app.db.session import get_db
from app.dependencies import get_current_user

router = APIRouter(prefix="/audit-logs", tags=["audit"])


@router.get("")
def list_audit_logs(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
):
    rows = db.query(AuditLog).order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    return [
        {
            "id": str(r.id),
            "action": r.action,
            "actor_type": r.actor_type,
            "resource_type": r.resource_type,
            "resource_id": str(r.resource_id) if r.resource_id else None,
            "metadata": r.metadata_json,
            "created_at": r.created_at,
        }
        for r in rows
    ]
