"""suricata_service unit tests — magic bytes and log filtering."""

import os
import pytest
from app.services.suricata_service import verify_pcap_magic, filter_log


def test_verify_pcap_magic_le(tmp_path, valid_pcap_le_bytes):
    """pcap little-endian magic → True."""
    path = tmp_path / "test.pcap"
    path.write_bytes(valid_pcap_le_bytes + b"\x00" * 100)
    assert verify_pcap_magic(str(path)) is True


def test_verify_pcap_magic_be(tmp_path, valid_pcap_be_bytes):
    """pcap big-endian magic → True."""
    path = tmp_path / "test.pcap"
    path.write_bytes(valid_pcap_be_bytes + b"\x00" * 100)
    assert verify_pcap_magic(str(path)) is True


def test_verify_pcap_magic_pcapng(tmp_path, valid_pcapng_bytes):
    """pcapng magic → True."""
    path = tmp_path / "test.pcapng"
    path.write_bytes(valid_pcapng_bytes + b"\x00" * 100)
    assert verify_pcap_magic(str(path)) is True


def test_verify_pcap_magic_invalid(tmp_path):
    """Invalid magic bytes → False."""
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"\x00\x00\x00\x00" + b"\x00" * 100)
    assert verify_pcap_magic(str(path)) is False


def test_verify_pcap_magic_text_file(tmp_path):
    """Text file → False."""
    path = tmp_path / "hello.txt"
    path.write_text("Hello World")
    assert verify_pcap_magic(str(path)) is False


def test_filter_log_dedup(tmp_path):
    """Duplicate lines should be deduplicated."""
    input_path = str(tmp_path / "fast.log")
    output_path = str(tmp_path / "filtered.log")

    line = '01/01/2024-00:00:00.000000  [**] [1:2000001:1] Test Event [**] [Classification: test] [Priority: 1] {TCP} 10.0.0.1:80 -> 10.0.0.2:443\n'
    with open(input_path, "w") as f:
        f.write(line * 5)

    kept = filter_log(input_path, output_path)
    assert kept == 1  # deduped to a single line


def test_filter_log_removes_priority3(tmp_path):
    """Priority 3 lines should be filtered out."""
    input_path = str(tmp_path / "fast.log")
    output_path = str(tmp_path / "filtered.log")

    p3_line = '01/01/2024-00:00:00.000000  [**] [1:2000001:1] Low Priority [**] [Classification: test] [Priority: 3] {TCP} 10.0.0.1:80 -> 10.0.0.2:443\n'
    p1_line = '01/01/2024-00:00:01.000000  [**] [1:2000002:1] High Priority [**] [Classification: test] [Priority: 1] {TCP} 10.0.0.1:80 -> 10.0.0.3:443\n'

    with open(input_path, "w") as f:
        f.write(p3_line + p1_line)

    kept = filter_log(input_path, output_path)
    assert kept == 1

    with open(output_path) as f:
        content = f.read()
    assert "High Priority" in content
    assert "Low Priority" not in content
