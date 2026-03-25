"""Pydantic schemas for tasks."""

from datetime import datetime

from pydantic import BaseModel


class TaskCreate(BaseModel):
    name: str
    nas_project: str
    pcap_files: list[str] | None = None  # None = use all PCAPs in folder


class TaskOut(BaseModel):
    id: str
    name: str
    owner_id: str
    nas_project: str
    pcap_files: list[str]
    status: str
    pcap_count: int
    created_at: datetime
    finished_at: datetime | None = None
    error_msg: str | None = None

    model_config = {"from_attributes": True}


class TaskListResponse(BaseModel):
    data: list[TaskOut]
    total: int
    page: int
    page_size: int
    message: str = "ok"
