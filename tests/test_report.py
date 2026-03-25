"""Report service unit tests."""

import os
import pytest
from app.services.report_service import _parse_priorities, generate


def test_parse_priorities(tmp_path):
    """Parse priority counts from fast.log."""
    log = tmp_path / "fast.log"
    log.write_text(
        '[Priority: 1] line1\n'
        '[Priority: 2] line2\n'
        '[Priority: 1] line3\n'
        '[Priority: 3] line4\n'
    )
    result = _parse_priorities(str(log))
    assert result[1] == 2
    assert result[2] == 1
    assert result[3] == 1


def test_parse_priorities_missing_file():
    """Missing file → empty Counter."""
    result = _parse_priorities("/nonexistent/fast.log")
    assert len(result) == 0


def test_generate_png(tmp_path):
    """generate() should produce a PNG file."""
    summary = {
        "flow": {
            "total_bytes": 1024 * 1024,
            "start_time": "2024-01-01T00:00:00",
            "end_time": "2024-01-01T01:00:00",
        },
        "event": {"HTTP": {"count": 10}, "TLS": {"count": 20}},
    }
    log_path = str(tmp_path / "fast.log")
    with open(log_path, "w") as f:
        f.write("[Priority: 1] test\n")

    out_path = str(tmp_path / "report.png")
    result = generate("test-task-id", summary, log_path, out_path)
    assert result is True
    assert os.path.exists(out_path)
    assert os.path.getsize(out_path) > 0

    # Verify PNG magic
    with open(out_path, "rb") as f:
        header = f.read(4)
    assert header[:3] == b"\x89PN"  # PNG signature starts with 0x89 P N
