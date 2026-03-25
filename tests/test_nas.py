"""NAS path validation tests."""

import pytest
from app.services.nas_service import NASService


def test_validate_path_traversal():
    svc = NASService()
    with pytest.raises(ValueError, match="無效的資料夾名稱"):
        svc._validate_path("../etc")


def test_validate_path_traversal_encoded():
    svc = NASService()
    with pytest.raises(ValueError, match="無效的資料夾名稱"):
        svc._validate_path("..%2Fetc")


def test_validate_path_invalid_chars():
    svc = NASService()
    with pytest.raises(ValueError, match="無效的資料夾名稱"):
        svc._validate_path("project;rm -rf /")


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


def test_safe_name_regex_rejects_slashes():
    svc = NASService()
    with pytest.raises(ValueError, match="無效的資料夾名稱"):
        svc._validate_path("project/../../etc")


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
