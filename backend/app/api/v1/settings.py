"""Repository settings API."""

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.db.models import IgnoredRule, Repository, RepositorySettings, User
from app.db.session import get_db
from app.dependencies import get_current_user
from app.schemas import RepositorySettingsUpdate
from app.services.audit import write_audit_log

router = APIRouter(prefix="/repos", tags=["settings"])


@router.get("/{repo_id}/settings")
def get_settings(
    repo_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
):
    repo = db.query(Repository).filter(Repository.id == repo_id).first()
    if not repo:
        raise NotFoundError("Repository not found")
    settings = db.query(RepositorySettings).filter(RepositorySettings.repository_id == repo_id).first()
    ignored = db.query(IgnoredRule).filter(IgnoredRule.repository_id == repo_id).all()
    return {
        "repository_id": str(repo_id),
        "settings": settings,
        "ignored_rules": [{"scanner_name": r.scanner_name, "rule_id": r.rule_id, "reason": r.reason} for r in ignored],
        "installation_active": repo.installation.is_active if repo.installation else False,
    }


@router.post("/{repo_id}/settings")
def update_settings(
    repo_id: UUID,
    payload: RepositorySettingsUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    repo = db.query(Repository).filter(Repository.id == repo_id).first()
    if not repo:
        raise NotFoundError("Repository not found")

    settings = db.query(RepositorySettings).filter(RepositorySettings.repository_id == repo_id).first()
    if not settings:
        settings = RepositorySettings(repository_id=repo_id)
        db.add(settings)

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(settings, field, value)
    settings.updated_at = datetime.now(timezone.utc)

    write_audit_log(db, "policy.changed", actor_user_id=user.id, resource_type="repository", resource_id=repo_id, metadata=payload.model_dump(exclude_unset=True))
    db.commit()
    db.refresh(settings)
    return settings
