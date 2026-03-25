"""Cancel / Delete endpoint tests."""

import pytest
from unittest.mock import patch, MagicMock
from httpx import AsyncClient


async def _create_task(client, auth_headers):
    """Helper to create a task for testing."""
    with patch("app.routers.tasks.nas_service") as mock_nas:
        mock_nas._validate_path.return_value = None
        mock_nas.get_pcap_files.return_value = [
            {"name": "test.pcap", "size_bytes": 1024},
        ]
        mock_nas.get_pcap_paths.return_value = ["/mnt/nas/proj/test.pcap"]
        resp = await client.post(
            "/api/v1/tasks",
            json={"name": "CancelTest", "nas_project": "proj"},
            headers=auth_headers,
        )
    return resp.json()["data"]["id"]


@pytest.mark.asyncio
async def test_cancel_pending_returns_conflict(client: AsyncClient, auth_headers, test_user):
    """Cancel on a pending (not running) task should return 409."""
    task_id = await _create_task(client, auth_headers)
    resp = await client.post(f"/api/v1/tasks/{task_id}/cancel", headers=auth_headers)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_delete_pending_task(client: AsyncClient, auth_headers, test_user):
    """Delete a pending task should succeed with 204."""
    task_id = await _create_task(client, auth_headers)
    resp = await client.delete(f"/api/v1/tasks/{task_id}", headers=auth_headers)
    assert resp.status_code == 204

    # Verify it's gone
    resp2 = await client.get(f"/api/v1/tasks/{task_id}", headers=auth_headers)
    assert resp2.status_code == 404


@pytest.mark.asyncio
async def test_delete_running_task_revokes_celery(client: AsyncClient, auth_headers, test_user, db_session):
    """Delete a running task should call celery revoke and return 204."""
    task_id = await _create_task(client, auth_headers)

    # Manually set task to running state
    from app.models.task import Task
    from sqlalchemy import select

    result = await db_session.execute(select(Task).where(Task.id == task_id))
    task = result.scalar_one()
    task.status = "running"
    task.celery_task_id = "fake-celery-id"
    await db_session.commit()

    with patch("app.workers.celery_app.celery_app") as mock_celery:
        mock_celery.control = MagicMock()
        resp = await client.delete(f"/api/v1/tasks/{task_id}", headers=auth_headers)

    assert resp.status_code == 204
    mock_celery.control.revoke.assert_called_once_with("fake-celery-id", terminate=True)


@pytest.mark.asyncio
async def test_cancel_nonexistent_task(client: AsyncClient, auth_headers, test_user):
    resp = await client.post("/api/v1/tasks/no-such-id/cancel", headers=auth_headers)
    assert resp.status_code == 404
