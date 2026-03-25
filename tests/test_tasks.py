"""Task CRUD endpoint tests."""

import pytest
from unittest.mock import patch, MagicMock
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_task(client: AsyncClient, auth_headers, test_user):
    with patch("app.routers.tasks.nas_service") as mock_nas:
        mock_nas._validate_path.return_value = None
        mock_nas.get_pcap_files.return_value = [
            {"name": "test.pcap", "size_bytes": 1024},
        ]
        mock_nas.get_pcap_paths.return_value = ["/mnt/nas/proj/test.pcap"]

        resp = await client.post(
            "/api/v1/tasks",
            json={"name": "Test Task", "nas_project": "proj"},
            headers=auth_headers,
        )
    assert resp.status_code == 202
    data = resp.json()["data"]
    assert data["status"] == "pending"
    assert data["name"] == "Test Task"


@pytest.mark.asyncio
async def test_create_task_with_files(client: AsyncClient, auth_headers, test_user):
    with patch("app.routers.tasks.nas_service") as mock_nas:
        mock_nas._validate_path.return_value = None
        mock_nas.get_pcap_paths.return_value = ["/mnt/nas/proj/a.pcap"]

        resp = await client.post(
            "/api/v1/tasks",
            json={
                "name": "Selected Files",
                "nas_project": "proj",
                "pcap_files": ["a.pcap"],
            },
            headers=auth_headers,
        )
    assert resp.status_code == 202


@pytest.mark.asyncio
async def test_list_tasks(client: AsyncClient, auth_headers, test_user):
    with patch("app.routers.tasks.nas_service") as mock_nas:
        mock_nas._validate_path.return_value = None
        mock_nas.get_pcap_files.return_value = [
            {"name": "t.pcap", "size_bytes": 100},
        ]
        mock_nas.get_pcap_paths.return_value = ["/mnt/nas/p/t.pcap"]
        await client.post(
            "/api/v1/tasks",
            json={"name": "T1", "nas_project": "p"},
            headers=auth_headers,
        )

    resp = await client.get("/api/v1/tasks", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1


@pytest.mark.asyncio
async def test_get_task_404(client: AsyncClient, auth_headers, test_user):
    resp = await client.get("/api/v1/tasks/nonexistent-id", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_task_unauthenticated(client: AsyncClient):
    resp = await client.post(
        "/api/v1/tasks",
        json={"name": "Fail", "nas_project": "proj"},
    )
    assert resp.status_code == 401
