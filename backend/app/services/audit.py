"""Audit logging service."""

from uuid import UUID

from sqlalchemy.orm import Session

from app.db.models import AuditLog


def write_audit_log(
    db: Session,
    action: str,
    *,
    actor_user_id: UUID | None = None,
    actor_type: str = "system",
    resource_type: str | None = None,
    resource_id: UUID | None = None,
    metadata: dict | None = None,
    ip_address: str | None = None,
) -> AuditLog:
    entry = AuditLog(
        actor_user_id=actor_user_id,
        actor_type=actor_type,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        metadata_json=metadata or {},
        ip_address=ip_address,
    )
    db.add(entry)
    db.flush()
    return entry
