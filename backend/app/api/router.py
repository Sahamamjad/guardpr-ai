"""API router aggregation."""

from fastapi import APIRouter

from app.api.health import router as health_router
from app.api.v1 import audit_logs, auth, findings, repos, scans, settings
from app.api.webhooks.github import router as github_webhook_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(github_webhook_router)
api_router.include_router(auth.router, prefix="/api/v1")
api_router.include_router(repos.router, prefix="/api/v1")
api_router.include_router(scans.router, prefix="/api/v1")
api_router.include_router(findings.router, prefix="/api/v1")
api_router.include_router(settings.router, prefix="/api/v1")
api_router.include_router(audit_logs.router, prefix="/api/v1")
