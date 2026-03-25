"""Task CRUD endpoints."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.task import AnalysisResult, Task
from app.models.user import User
from app.routers.auth import get_current_user, require_role
from app.schemas.task import TaskCreate, TaskOut
from app.services.nas_service import nas_service

router = APIRouter(prefix="/api/v1/tasks", tags=["tasks"])


def _task_or_404(task: Task | None) -> Task:
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "NOT_FOUND", "message": "任務 ID 不存在", "detail": None},
        )
    return task


def _check_owner_or_admin(task: Task, user: User):
    if user.role != "admin" and task.owner_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "FORBIDDEN", "message": "無此資源權限", "detail": None},
        )


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def create_task(
    body: TaskCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Validate NAS project path
    try:
        nas_service._validate_path(body.nas_project)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "VALIDATION_ERROR", "message": str(e), "detail": None},
        )

    # Determine pcap files
    if body.pcap_files:
        pcap_files = body.pcap_files
        # Verify files exist on NAS
        try:
            nas_service.get_pcap_paths(body.nas_project, pcap_files)
        except (ValueError, FileNotFoundError) as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "VALIDATION_ERROR", "message": str(e), "detail": None},
            )
    else:
        # Use all PCAPs in folder
        files_info = nas_service.get_pcap_files(body.nas_project)
        pcap_files = [f["name"] for f in files_info]
        if not pcap_files:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "VALIDATION_ERROR",
                    "message": "資料夾中沒有 PCAP 檔案",
                    "detail": None,
                },
            )

    task = Task(
        id=str(uuid.uuid4()),
        name=body.name,
        owner_id=user.id,
        nas_project=body.nas_project,
        pcap_files=pcap_files,
        status="pending",
        pcap_count=len(pcap_files),
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)

    return {"data": TaskOut.model_validate(task).model_dump(), "message": "ok"}


@router.post("/{task_id}/start", status_code=status.HTTP_202_ACCEPTED)
async def start_task(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Task).where(Task.id == task_id))
    task = _task_or_404(result.scalar_one_or_none())
    _check_owner_or_admin(task, user)

    if task.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "CONFLICT",
                "message": "任務非待處理狀態，無法啟動",
                "detail": None,
            },
        )

    from app.workers.analysis_task import run_full_analysis

    celery_result = run_full_analysis.delay(task_id)
    task.status = "running"
    task.celery_task_id = celery_result.id
    await db.commit()

    return {"data": {"task_id": task_id, "status": "running"}, "message": "ok"}


@router.get("")
async def list_tasks(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = select(Task)
    count_query = select(func.count(Task.id))

    # Non-admin users only see their own tasks
    if user.role != "admin":
        query = query.where(Task.owner_id == user.id)
        count_query = count_query.where(Task.owner_id == user.id)

    if status_filter:
        query = query.where(Task.status == status_filter)
        count_query = count_query.where(Task.status == status_filter)

    total_result = await db.execute(count_query)
    total = total_result.scalar()

    query = query.order_by(Task.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    tasks = result.scalars().all()

    return {
        "data": [TaskOut.model_validate(t).model_dump() for t in tasks],
        "total": total,
        "page": page,
        "page_size": page_size,
        "message": "ok",
    }


@router.get("/{task_id}")
async def get_task(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Task).where(Task.id == task_id))
    task = _task_or_404(result.scalar_one_or_none())
    _check_owner_or_admin(task, user)
    return {"data": TaskOut.model_validate(task).model_dump(), "message": "ok"}


@router.post("/{task_id}/cancel")
async def cancel_task(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Task).where(Task.id == task_id))
    task = _task_or_404(result.scalar_one_or_none())
    _check_owner_or_admin(task, user)

    if task.status != "running":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "CONFLICT",
                "message": "任務非執行中狀態，無法撤銷",
                "detail": None,
            },
        )

    from app.workers.celery_app import celery_app

    celery_app.control.revoke(task.celery_task_id, terminate=True)
    task.status = "failed"
    task.error_msg = "使用者手動撤銷"
    task.finished_at = datetime.now(timezone.utc)
    await db.commit()

    return {"data": {"task_id": task_id, "status": "failed"}, "message": "ok"}


@router.delete("/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_task(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Task).where(Task.id == task_id))
    task = _task_or_404(result.scalar_one_or_none())
    _check_owner_or_admin(task, user)

    if task.status == "running":
        from app.workers.celery_app import celery_app

        celery_app.control.revoke(task.celery_task_id, terminate=True)
        task.status = "failed"
        task.error_msg = "任務刪除時強制終止"

    await db.delete(task)
    await db.commit()
