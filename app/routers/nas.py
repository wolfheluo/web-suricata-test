"""NAS browsing endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status

from app.models.user import User
from app.routers.auth import get_current_user
from app.services.nas_service import nas_service

router = APIRouter(prefix="/api/v1/nas", tags=["nas"])


@router.get("/projects")
async def list_projects(_user: User = Depends(get_current_user)):
    try:
        projects = nas_service.list_project_folders()
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "INTERNAL_ERROR", "message": "NAS 掛載點不可用", "detail": None},
        )
    return {"data": {"projects": projects}, "message": "ok"}


@router.get("/projects/{project_name}/files")
async def list_files(project_name: str, _user: User = Depends(get_current_user)):
    try:
        files = nas_service.get_pcap_files(project_name)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "VALIDATION_ERROR", "message": str(e), "detail": None},
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "NOT_FOUND", "message": "專案資料夾不存在", "detail": None},
        )
    return {
        "data": {
            "project": project_name,
            "files": files,
            "total": len(files),
        },
        "message": "ok",
    }
