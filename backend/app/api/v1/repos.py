"""Repository API."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.models import GitHubInstallation, Repository, User
from app.db.session import get_db
from app.dependencies import get_current_user
from app.schemas import RepositoryResponse

router = APIRouter(prefix="/repos", tags=["repos"])


@router.get("", response_model=list[RepositoryResponse])
def list_repos(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
):
    return db.query(Repository).join(GitHubInstallation).filter(GitHubInstallation.is_active.is_(True)).order_by(Repository.full_name).all()


@router.get("/{repo_id}/pull-requests")
def list_pull_requests(
    repo_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
):
    from app.db.models import PullRequest, Scan

    prs = db.query(PullRequest).filter(PullRequest.repository_id == repo_id).order_by(PullRequest.pr_number.desc()).all()
    result = []
    for pr in prs:
        latest_scan = db.query(Scan).filter(Scan.pull_request_id == pr.id).order_by(Scan.created_at.desc()).first()
        result.append(
            {
                "id": str(pr.id),
                "pr_number": pr.pr_number,
                "title": pr.title,
                "author_login": pr.author_login,
                "state": pr.state,
                "github_url": pr.github_url,
                "latest_scan": {
                    "id": str(latest_scan.id),
                    "status": latest_scan.status,
                    "overall_risk": latest_scan.overall_risk,
                    "findings_count": latest_scan.findings_count,
                    "created_at": latest_scan.created_at,
                }
                if latest_scan
                else None,
            }
        )
    return result
