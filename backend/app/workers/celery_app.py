"""Celery application."""

from celery import Celery

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "guardpr",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.tasks.scan_pr"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_default_queue="scans",
)
