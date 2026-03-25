"""Suricata analysis service — run Suricata on PCAP files and filter/dedup logs."""

import glob
import os
import re
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


PRIORITY_FILTER = {3}
NOISE_PATTERNS = [
    re.compile(r"ET INFO HTTP Request to a.*\.tw domain"),
    re.compile(r"ET DNS Query for \.cc TLD"),
]
IP_PAIR_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+):\d+\s*->\s*"
    r"(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+):\d+"
)
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",  # pcap LE
    b"\xa1\xb2\xc3\xd4",  # pcap BE
    b"\x0a\x0d\x0d\x0a",  # pcapng
    b"\x4d\x3c\xb2\xa1",  # pcap nanosecond LE
}


def verify_pcap_magic(pcap_path: str) -> bool:
    """Return True only if file starts with a known PCAP/pcapng magic."""
    with open(pcap_path, "rb") as f:
        header = f.read(4)
    return header in PCAP_MAGIC


def _extract_key_fields(line: str):
    """Return (event_str, src_ip, dst_ip) for dedup key, or None to discard."""
    if "Priority: 3" in line:
        return None
    for pat in NOISE_PATTERNS:
        if pat.search(line):
            return None
    if "[**]" not in line:
        return None
    m = IP_PAIR_RE.search(line)
    if not m:
        return None
    event_start = line.find("[**]")
    return (line[event_start:], m.group(1), m.group(2))


def filter_log(input_path: str, output_path: str) -> int:
    """Filter and dedup fast.log. Return number of lines kept."""
    seen: set = set()
    kept = 0
    with open(input_path, "r", encoding="utf-8", errors="replace") as fin, \
         open(output_path, "w", encoding="utf-8") as fout:
        for line in fin:
            key = _extract_key_fields(line)
            if key and key not in seen:
                seen.add(key)
                fout.write(line)
                kept += 1
    return kept


def _run_suricata(pcap_path: str, out_dir: str, suricata_exe: str) -> str:
    """Run Suricata on a single PCAP; return status message."""
    os.makedirs(out_dir, exist_ok=True)
    tid = threading.current_thread().name
    result = subprocess.run(
        [suricata_exe, "-r", pcap_path, "-l", out_dir],
        capture_output=True, text=True, encoding="utf-8"
    )
    if result.returncode == 0:
        return f"[{tid}] OK: {pcap_path}"
    return f"[{tid}] FAIL: {pcap_path}\n{result.stderr[:500]}"


def run_analysis(
    task_id: str,
    pcap_paths: list[str],
    work_dir: str,
    suricata_exe: str = "suricata",
    max_workers: int = 4,
) -> str:
    """
    Run Suricata on each PCAP in parallel, then merge and filter all
    fast.log files into {work_dir}/merged_fast.log.

    Return path to merged filtered log.
    Raise RuntimeError if no fast.log was produced.
    """
    for p in pcap_paths:
        if not verify_pcap_magic(p):
            raise ValueError(f"非有效的 PCAP 檔案：{p}")

    workers = min(max_workers, len(pcap_paths)) or 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                _run_suricata, p, os.path.join(work_dir, Path(p).stem), suricata_exe
            ): p
            for p in pcap_paths
        }
        for fut in as_completed(futures):
            fut.result()

    # Merge all fast.log → merged_fast.log
    raw_path = os.path.join(work_dir, "_raw_fast.log")
    fast_logs = glob.glob(os.path.join(work_dir, "*", "fast.log"))
    if not fast_logs:
        raise RuntimeError(f"Suricata 在 {work_dir} 中未產生任何 fast.log")

    with open(raw_path, "w", encoding="utf-8") as out:
        for log_path in fast_logs:
            with open(log_path, encoding="utf-8", errors="replace") as f:
                out.write(f.read())

    merged_path = os.path.join(work_dir, "merged_fast.log")
    filter_log(raw_path, merged_path)
    os.unlink(raw_path)
    return merged_path
