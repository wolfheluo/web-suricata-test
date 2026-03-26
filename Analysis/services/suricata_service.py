"""Suricata PCAP 分析服務 — 執行 Suricata 分析 pcap 並合併/過濾 fast.log"""

import os
import re
import glob
import shutil
import subprocess
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import config


# ---------------------------------------------------------------------------
# fast.log 過濾邏輯
# ---------------------------------------------------------------------------

def _extract_key_fields(line):
    """從日誌行中提取關鍵字段用於去重和過濾，回傳 None 表示該行應被過濾"""
    if "Priority: 3" in line:
        return None
    if "ET INFO HTTP Request to a" in line and ".tw domain" in line:
        return None
    if "ET DNS Query for .cc TLD" in line:
        return None

    event_start = line.find("[**]")
    if event_start == -1:
        return None
    event = line[event_start:]

    ip_match = re.search(
        r"(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+):\d+\s*->\s*"
        r"(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+):\d+",
        line,
    )
    if not ip_match:
        return None
    src_ip, dst_ip = ip_match.groups()
    return (event, src_ip, dst_ip)


def filter_log_file(input_file: str, output_file: str) -> bool:
    """過濾日誌文件，去除低優先級和重複記錄"""
    if not os.path.exists(input_file):
        return False
    seen: set = set()
    count = 0
    with open(input_file, "r", encoding="utf-8") as infile, \
         open(output_file, "w", encoding="utf-8") as outfile:
        for line in infile:
            key = _extract_key_fields(line)
            if key and key not in seen:
                seen.add(key)
                outfile.write(line)
                count += 1
    return True


# ---------------------------------------------------------------------------
# 單一 pcap 處理
# ---------------------------------------------------------------------------

def _process_single_pcap(pcap_file: str, out_dir: str) -> str:
    """用 Suricata 分析單一 pcap，輸出到 out_dir/<stem>/"""
    pcap_path = Path(pcap_file)
    sub_dir = os.path.join(out_dir, pcap_path.stem)
    os.makedirs(sub_dir, exist_ok=True)

    thread_name = threading.current_thread().name
    cmd = [config.SURICATA_EXE, "-r", pcap_file, "-l", sub_dir]
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")

    if result.returncode == 0:
        msg = f"[{thread_name}] ✓ 成功分析 {pcap_path.name}"
    else:
        msg = f"[{thread_name}] ✗ 分析失敗 {pcap_path.name}: {result.stderr[:200]}"
    return msg


# ---------------------------------------------------------------------------
# 批次分析入口
# ---------------------------------------------------------------------------

def run_suricata_analysis(
    pcap_paths: list[str],
    out_base: str,
    on_progress=None,
) -> dict:
    """
    對一組 pcap 執行 Suricata 分析，合併 fast.log 並過濾。

    Args:
        pcap_paths: pcap 絕對路徑列表
        out_base: 輸出目錄 (project/<task_name>)
        on_progress: 回呼 (completed, total, message)

    Returns:
        {"merged_fast_log": str, "filtered_fast_log": str}
    """
    os.makedirs(out_base, exist_ok=True)
    total = len(pcap_paths)
    max_workers = min(config.MAX_WORKERS, total) if total > 1 else 1
    results: list[str] = []

    if max_workers > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(_process_single_pcap, p, out_base): p
                for p in pcap_paths
            }
            for future in as_completed(future_map):
                msg = future.result()
                results.append(msg)
                if on_progress:
                    on_progress(len(results), total, msg)
    else:
        for p in pcap_paths:
            msg = _process_single_pcap(p, out_base)
            results.append(msg)
            if on_progress:
                on_progress(len(results), total, msg)

    # 合併 fast.log
    merged_path = os.path.join(out_base, "merged_fast.log")
    with open(merged_path, "w", encoding="utf-8") as merged:
        for fast_log in glob.glob(os.path.join(out_base, "*", "fast.log")):
            with open(fast_log, "r", encoding="utf-8") as f:
                merged.write(f.read())

    # 過濾
    filtered_path = os.path.join(out_base, "filtered_merged_fast.log")
    filter_log_file(merged_path, filtered_path)

    return {"merged_fast_log": merged_path, "filtered_fast_log": filtered_path}
