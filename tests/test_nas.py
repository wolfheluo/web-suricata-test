"""NAS path validation tests."""

import pytest
from app.services.nas_service import NASService


def test_validate_path_traversal():
    svc = NASService()
    with pytest.raises(ValueError, match="路徑穿越"):
        svc._validate_path("../etc")


def test_validate_path_traversal_dotdot():
    svc = NASService()
    with pytest.raises(ValueError, match="路徑穿越"):
        svc._validate_path("project/../../etc")


def test_validate_path_normal(tmp_path):
    svc = NASService()
    svc.BASE_PATH = tmp_path
    project_dir = tmp_path / "project_A"
    project_dir.mkdir()
    result = svc._validate_path("project_A")
    assert result == project_dir.resolve()


def test_validate_path_with_dots(tmp_path):
    svc = NASService()
    svc.BASE_PATH = tmp_path
    project_dir = tmp_path / "my.project"
    project_dir.mkdir()
    result = svc._validate_path("my.project")
    assert result == project_dir.resolve()


def test_validate_path_multilevel(tmp_path):
    svc = NASService()
    svc.BASE_PATH = tmp_path
    deep_dir = tmp_path / "技術檢測" / "南區" / "科工館"
    deep_dir.mkdir(parents=True)
    result = svc._validate_path("技術檢測/南區/科工館")
    assert result == deep_dir.resolve()


def test_browse_directory(tmp_path):
    svc = NASService()
    svc.BASE_PATH = tmp_path
    (tmp_path / "folderA").mkdir()
    (tmp_path / "folderB").mkdir()
    (tmp_path / "test.pcap").write_bytes(b"\x00" * 50)
    result = svc.browse_directory("")
    assert "folderA" in result["folders"]
    assert "folderB" in result["folders"]
    assert len(result["files"]) == 1


def test_browse_directory_sublevel(tmp_path):
    svc = NASService()
    svc.BASE_PATH = tmp_path
    sub = tmp_path / "level1" / "level2"
    sub.mkdir(parents=True)
    (sub / "capture.pcap").write_bytes(b"\x00" * 100)
    result = svc.browse_directory("level1/level2")
    assert len(result["folders"]) == 0
    assert result["files"][0]["name"] == "capture.pcap"


def test_get_pcap_files(tmp_path):
    svc = NASService()
    svc.BASE_PATH = tmp_path
    project_dir = tmp_path / "test_project"
    project_dir.mkdir()
    (project_dir / "capture.pcap").write_bytes(b"\x00" * 100)
    (project_dir / "capture2.pcapng").write_bytes(b"\x00" * 200)
    (project_dir / "readme.txt").write_text("not a pcap")

    files = svc.get_pcap_files("test_project")
    assert len(files) == 2
    names = {f["name"] for f in files}
    assert "capture.pcap" in names
    assert "capture2.pcapng" in names
