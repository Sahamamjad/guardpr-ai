"""GitHub webhook handler."""

import json
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, Response
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.logging import get_logger
from app.db.models import GitHubInstallation, PullRequest, Repository, Scan
from app.db.session import get_db
from app.services.audit import write_audit_log
from app.services.github.webhook_verify import verify_github_signature
from app.workers.tasks.scan_pr import scan_pull_request_task

logger = get_logger(__name__)
router = APIRouter(prefix="/webhooks", tags=["webhooks"])

PR_EVENTS = {"opened", "reopened", "synchronize"}


@router.post("/github")
async def github_webhook(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    x_hub_signature_256: Annotated[str | None, Header()] = None,
    x_github_event: Annotated[str | None, Header()] = None,
    x_github_delivery: Annotated[str | None, Header()] = None,
):
    settings = get_settings()
    body = await request.body()

    if not verify_github_signature(body, x_hub_signature_256, settings.github_webhook_secret):
        logger.warning("webhook_invalid_signature", delivery=x_github_delivery)
        return Response(status_code=401, content="Invalid signature")

    payload = json.loads(body.decode("utf-8"))
    action = payload.get("action")
    event = x_github_event

    write_audit_log(
        db,
        "webhook.received",
        actor_type="github_app",
        metadata={"event": event, "action": action, "delivery": x_github_delivery},
    )
    db.commit()

    if event == "installation":
        _handle_installation(db, payload, action)
        db.commit()
        return Response(status_code=202)

    if event == "pull_request" and action in PR_EVENTS:
        scan_id = _handle_pull_request(db, payload, action)
        db.commit()
        if scan_id:
            pr = payload["pull_request"]
            repo = payload["repository"]
            installation_id = payload["installation"]["id"]
            scan_pull_request_task.delay(
                str(scan_id),
                installation_id,
                repo["full_name"],
                pr["number"],
                pr["head"]["sha"],
            )
        return Response(status_code=202)

    return Response(status_code=202)


def _handle_installation(db: Session, payload: dict, action: str) -> None:
    installation = payload.get("installation", {})
    inst_id = installation.get("id")
    if not inst_id:
        return

    row = db.query(GitHubInstallation).filter(GitHubInstallation.installation_id == inst_id).first()
    if action == "deleted":
        if row:
            row.is_active = False
        return

    account = installation.get("account", {})
    if not row:
        row = GitHubInstallation(
            installation_id=inst_id,
            account_login=account.get("login", "unknown"),
            account_type=account.get("type"),
            permissions_json=installation.get("permissions"),
            is_active=True,
            installed_at=datetime.now(timezone.utc),
        )
        db.add(row)
        db.flush()
    else:
        row.is_active = True
        row.account_login = account.get("login", row.account_login)
        row.permissions_json = installation.get("permissions")

    for repo_data in payload.get("repositories", []) or []:
        _upsert_repository(db, row.id, repo_data)

    if payload.get("repository"):
        _upsert_repository(db, row.id, payload["repository"])

    write_audit_log(db, f"installation.{action}", resource_type="installation", metadata={"installation_id": inst_id})


def _upsert_repository(db: Session, installation_id: UUID, repo_data: dict) -> Repository:
    gh_id = repo_data["id"]
    row = db.query(Repository).filter(Repository.github_repo_id == gh_id).first()
    if not row:
        row = Repository(
            installation_id=installation_id,
            github_repo_id=gh_id,
            full_name=repo_data["full_name"],
            default_branch=repo_data.get("default_branch", "main"),
        )
        db.add(row)
    else:
        row.full_name = repo_data["full_name"]
        row.default_branch = repo_data.get("default_branch", row.default_branch)
    db.flush()
    return row


def _handle_pull_request(db: Session, payload: dict, action: str) -> UUID | None:
    repo_data = payload["repository"]
    pr_data = payload["pull_request"]
    installation_id = payload["installation"]["id"]

    installation = db.query(GitHubInstallation).filter(GitHubInstallation.installation_id == installation_id).first()
    if not installation:
        installation = GitHubInstallation(
            installation_id=installation_id,
            account_login=repo_data.get("owner", {}).get("login", "unknown"),
            account_type="Organization",
            is_active=True,
            installed_at=datetime.now(timezone.utc),
        )
        db.add(installation)
        db.flush()

    repository = _upsert_repository(db, installation.id, repo_data)

    pr = (
        db.query(PullRequest)
        .filter(PullRequest.repository_id == repository.id, PullRequest.pr_number == pr_data["number"])
        .first()
    )
    if not pr:
        pr = PullRequest(repository_id=repository.id, pr_number=pr_data["number"])
        db.add(pr)

    pr.title = pr_data.get("title")
    pr.author_login = pr_data.get("user", {}).get("login")
    pr.head_sha = pr_data.get("head", {}).get("sha")
    pr.base_branch = pr_data.get("base", {}).get("ref")
    pr.head_branch = pr_data.get("head", {}).get("ref")
    pr.state = pr_data.get("state")
    pr.github_url = pr_data.get("html_url")
    db.flush()

    scan = Scan(
        pull_request_id=pr.id,
        status="queued",
        trigger_event=f"pull_request.{action}",
        head_sha=pr.head_sha,
    )
    db.add(scan)
    db.flush()
    return scan.id
