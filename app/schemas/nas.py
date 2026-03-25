"""Pydantic schemas for NAS browsing."""

from pydantic import BaseModel


class FileInfo(BaseModel):
    name: str
    size_bytes: int


class ProjectListResponse(BaseModel):
    projects: list[str]


class ProjectFilesResponse(BaseModel):
    project: str
    files: list[FileInfo]
    total: int
