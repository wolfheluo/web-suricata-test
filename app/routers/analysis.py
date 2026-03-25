"""Analysis result endpoints — flow, top IP, geo, events, anomaly, deep."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.task import AnalysisResult, Task
from app.models.user import User
from app.routers.auth import get_current_user
from app.services.anomaly_service import detect_anomalies

router = APIRouter(prefix="/api/v1/tasks", tags=["analysis"])


async def _get_result(
    task_id: str, db: AsyncSession, user: User
) -> AnalysisResult:
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


@router.get("/{task_id}/flow")
async def get_flow(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ar = await _get_result(task_id, db, user)
    return {"data": ar.summary.get("flow", {}), "message": "ok"}


@router.get("/{task_id}/flow/{time_period}")
async def get_flow_detail(
    task_id: str,
    time_period: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ar = await _get_result(task_id, db, user)
    flow = ar.summary.get("flow", {})
    top_ips = flow.get("top_ip_per_10_minutes", {}).get(time_period, [])
    bytes_val = flow.get("per_10_minutes", {}).get(time_period, 0)
    return {
        "data": {"time_period": time_period, "bytes": bytes_val, "top_connections": top_ips},
        "message": "ok",
    }


@router.get("/{task_id}/top_ip")
async def get_top_ip(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ar = await _get_result(task_id, db, user)
    return {"data": ar.summary.get("top_ip", []), "message": "ok"}


@router.get("/{task_id}/geo")
async def get_geo(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ar = await _get_result(task_id, db, user)
    return {"data": ar.summary.get("geo", {}), "message": "ok"}


@router.get("/{task_id}/events")
async def get_events(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ar = await _get_result(task_id, db, user)
    return {"data": ar.summary.get("event", {}), "message": "ok"}


@router.get("/{task_id}/events/{protocol}")
async def get_event_protocol(
    task_id: str,
    protocol: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ar = await _get_result(task_id, db, user)
    events = ar.summary.get("event", {})
    proto_data = events.get(protocol.upper())
    if proto_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "NOT_FOUND", "message": f"協定 {protocol} 無資料", "detail": None},
        )
    return {"data": proto_data, "message": "ok"}


@router.get("/{task_id}/anomaly")
async def get_anomaly(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ar = await _get_result(task_id, db, user)
    anomalies = detect_anomalies(ar.summary)
    return {"data": anomalies, "message": "ok"}


@router.get("/{task_id}/deep/dns")
async def get_deep_dns(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ar = await _get_result(task_id, db, user)
    return {"data": ar.summary.get("deep", {}).get("dns", {}), "message": "ok"}


@router.get("/{task_id}/deep/http")
async def get_deep_http(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ar = await _get_result(task_id, db, user)
    return {"data": ar.summary.get("deep", {}).get("http", {}), "message": "ok"}


@router.get("/{task_id}/deep/tls")
async def get_deep_tls(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ar = await _get_result(task_id, db, user)
    return {"data": ar.summary.get("deep", {}).get("tls", {}), "message": "ok"}
