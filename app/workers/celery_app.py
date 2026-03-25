"""Celery application instance."""

from celery import Celery

from app.config import settings

celery_app = Celery(
    "suricata_worker",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="Asia/Taipei",
    enable_utc=True,
    task_track_started=True,
    task_default_queue="analysis",
    worker_concurrency=settings.MAX_WORKER_CONCURRENCY,
)

celery_app.autodiscover_tasks(["app.workers"], related_name="analysis_task")
