"""Report and export endpoints — PNG, JSON, CSV."""

import csv
import io
import os

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.task import AnalysisResult, Task
from app.models.user import User
from app.routers.auth import get_current_user

router = APIRouter(prefix="/api/v1/tasks", tags=["reports"])


async def _get_ar(task_id: str, db: AsyncSession, user: User) -> AnalysisResult:
    result = await db.execute(select(Task).where(Task.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "NOT_FOUND", "message": "任務 ID 不存在", "detail": None},
        )
    if user.role != "admin" and task.owner_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "FORBIDDEN", "message": "無此資源權限", "detail": None},
        )
    ar_result = await db.execute(
        select(AnalysisResult).where(AnalysisResult.task_id == task_id)
    )
    ar = ar_result.scalar_one_or_none()
    if not ar:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "NOT_FOUND", "message": "分析結果尚未完成", "detail": None},
        )
    return ar


@router.get("/{task_id}/report")
async def get_report(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ar = await _get_ar(task_id, db, user)
    report_path = ar.summary.get("report_path", "")
    if not report_path or not os.path.exists(report_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "NOT_FOUND", "message": "報告檔案不存在", "detail": None},
        )
    return FileResponse(report_path, media_type="image/png", filename=f"report_{task_id}.png")


@router.get("/{task_id}/export")
async def export_result(
    task_id: str,
    format: str = Query("json", pattern="^(json|csv)$"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ar = await _get_ar(task_id, db, user)

    if format == "json":
        return {"data": ar.summary, "message": "ok"}

    # CSV export — alerts
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "priority", "event", "src_ip", "src_port",
                     "dst_ip", "dst_port", "protocol"])
    import re
    for line in ar.alerts:
        # Parse fast.log line
        ts_match = re.match(r"^(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)", line)
        ts = ts_match.group(1) if ts_match else ""
        pri_match = re.search(r"\[Priority:\s*(\d+)\]", line)
        priority = pri_match.group(1) if pri_match else ""
        event_match = re.search(r"\[\*\*\]\s*\[.*?\]\s*(.*?)\s*\[\*\*\]", line)
        event = event_match.group(1) if event_match else ""
        ip_match = re.search(
            r"(\d+\.\d+\.\d+\.\d+):(\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+):(\d+)", line
        )
        if ip_match:
            src_ip, src_port, dst_ip, dst_port = ip_match.groups()
        else:
            src_ip = src_port = dst_ip = dst_port = ""
        proto_match = re.search(r"\{(\w+)\}", line)
        protocol = proto_match.group(1) if proto_match else ""
        writer.writerow([ts, priority, event, src_ip, src_port, dst_ip, dst_port, protocol])

    output.seek(0)
    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=alerts_{task_id}.csv"},
    )
