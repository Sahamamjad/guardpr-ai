"""Health check endpoints."""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
def health():
    return {"status": "ok", "service": "guardpr-ai"}


@router.get("/ready")
def ready():
    return {"status": "ready"}
