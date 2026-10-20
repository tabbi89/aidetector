"""Celery application — scans run as async jobs (wired up in phase 3)."""
from __future__ import annotations

from celery import Celery

from app.core.config import settings

celery = Celery(
    "aidetector",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.workers.tasks"],
)
celery.conf.update(
    task_track_started=True,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    beat_schedule={
        "dispatch-scheduled-scans": {
            "task": "dispatch_scheduled_scans",
            "schedule": 60.0,  # check every minute for due schedules
        },
        "prune-auth-throttle": {
            "task": "prune_auth_throttle",
            "schedule": 3600.0,  # drop sign-in/sign-up counters past their window
        },
        "reap-stale-scans": {
            "task": "reap_stale_scans",
            "schedule": 60.0,  # fail scans whose worker died or never started
        },
        "deliver-notifications": {
            "task": "deliver_notifications",
            "schedule": 30.0,  # drain the outbox
        },
        "dispatch-overdue-work": {
            "task": "dispatch_overdue_work",
            "schedule": 3600.0,  # idempotent daily check, enqueue-deduped
        },
        "dispatch-daily-monitoring": {
            "task": "dispatch_daily_monitoring",
            "schedule": 3600.0,  # idempotent UTC-day check for each monitor
        },
        "dispatch-rapid-monitoring": {
            "task": "dispatch_rapid_monitoring",
            # Opted-in monitors only; each tick scores the newest complete hour.
            "schedule": float(settings.monitoring_rapid_interval_seconds),
        },
    },
)


@celery.task(name="ping")
def ping() -> str:
    """Smoke-test task so the worker has something to run in phase 0."""
    return "pong"
