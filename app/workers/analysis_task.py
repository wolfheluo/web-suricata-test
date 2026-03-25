"""Celery task: run_full_analysis — orchestrates the entire analysis pipeline."""

import json
import os
import shutil
from datetime import datetime, timezone

from app.workers.celery_app import celery_app

# Use sync DB access inside Celery worker (not async)
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.config import settings

# Convert async URL to sync for Celery worker
_sync_url = settings.DATABASE_URL.replace("+aiomysql", "+pymysql")
_engine = create_engine(_sync_url, pool_pre_ping=True)


def _get_sync_session() -> Session:
    return Session(_engine)


def _send_ws_progress(task_id: str, step: str, progress: int, message: str = ""):
    """Publish progress via Redis pub/sub for WebSocket relay."""
    import redis

    r = redis.from_url(settings.REDIS_URL)
    r.publish(
        f"task:{task_id}:progress",
        json.dumps({"step": step, "progress": progress, "message": message}),
    )
    r.close()


@celery_app.task(bind=True, max_retries=0, time_limit=3600)
def run_full_analysis(self, task_id: str):
    from app.models.task import AnalysisResult, Task
    from app.services.nas_service import nas_service

    work_dir = f"/tmp/suricata-{task_id}"
    os.makedirs(work_dir, exist_ok=True)

    try:
        # 1. Load task, set running
        with _get_sync_session() as session:
            task = session.get(Task, task_id)
            if not task:
                raise RuntimeError(f"Task {task_id} not found")
            task.status = "running"
            session.commit()

            nas_project = task.nas_project
            pcap_files = task.pcap_files

        # 2. Resolve NAS paths
        pcap_paths = nas_service.get_pcap_paths(nas_project, pcap_files)

        # 3. Run Suricata
        _send_ws_progress(task_id, "suricata", 10, "開始 Suricata 分析...")
        from app.services.suricata_service import run_analysis

        merged_log_path = run_analysis(
            task_id=task_id,
            pcap_paths=pcap_paths,
            work_dir=work_dir,
            max_workers=settings.MAX_WORKER_CONCURRENCY,
        )
        _send_ws_progress(task_id, "suricata", 30, "Suricata 分析完成")

        # 4. Run tshark analysis
        _send_ws_progress(task_id, "tshark", 35, "開始 tshark 分析...")
        from app.services.tshark_service import analyze as tshark_analyze

        summary = tshark_analyze(
            task_id=task_id,
            pcap_paths=pcap_paths,
            geoip_db_path=settings.GEOIP_DB_PATH,
        )
        _send_ws_progress(task_id, "tshark", 55, "tshark 分析完成")

        # 5. Run deep analysis (DNS/HTTP/TLS)
        _send_ws_progress(task_id, "deep", 60, "開始深度封包分析...")
        from app.services.pcap_deep_service import deep_analyze

        def deep_progress(step: str, progress: int):
            _send_ws_progress(task_id, step, progress, f"深度分析: {step}")

        deep_results = deep_analyze(
            task_id=task_id,
            pcap_paths=pcap_paths,
            progress_callback=deep_progress,
        )
        summary["deep"] = deep_results
        _send_ws_progress(task_id, "deep", 80, "深度分析完成")

        # 6. Generate report
        _send_ws_progress(task_id, "report", 85, "產生報告...")
        from app.services.report_service import generate as generate_report

        report_path = os.path.join(work_dir, "report.png")
        generate_report(task_id, summary, merged_log_path, report_path)
        _send_ws_progress(task_id, "report", 90, "報告產生完成")

        # 7. Parse alerts from merged fast.log
        alerts = []
        if os.path.exists(merged_log_path):
            with open(merged_log_path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    alerts.append(line.strip())

        # 8. Store results + report path in summary
        summary["report_path"] = report_path

        with _get_sync_session() as session:
            task = session.get(Task, task_id)
            task.status = "done"
            task.finished_at = datetime.now(timezone.utc)

            existing = session.get(AnalysisResult, task_id)
            if existing:
                existing.summary = summary
                existing.alerts = alerts
            else:
                ar = AnalysisResult(
                    task_id=task_id, summary=summary, alerts=alerts
                )
                session.add(ar)
            session.commit()

        _send_ws_progress(task_id, "done", 100, "分析完成")

    except Exception as exc:
        # Set failed status
        with _get_sync_session() as session:
            task = session.get(Task, task_id)
            if task:
                task.status = "failed"
                task.error_msg = str(exc)[:1000]
                task.finished_at = datetime.now(timezone.utc)
                session.commit()

        _send_ws_progress(task_id, "error", 0, str(exc)[:500])
        raise

    finally:
        # Always clean up work directory
        shutil.rmtree(work_dir, ignore_errors=True)
