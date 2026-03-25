"""Report generation service — renders a PNG summary report."""

import os
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle


def _parse_priorities(log_path: str) -> Counter:
    """Count Priority: N occurrences in fast.log."""
    counter: Counter = Counter()
    if not os.path.exists(log_path):
        return counter
    with open(log_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.search(r"\[Priority:\s*(\d+)\]", line)
            if m:
                counter[int(m.group(1))] += 1
    return counter


def _fmt_bytes(n: int) -> str:
    for unit, threshold in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= threshold:
            return f"{n / threshold:.2f} {unit}"
    return f"{n} B"


def _fmt_duration(start: str, end: str) -> str:
    try:
        delta = (datetime.fromisoformat(end.replace("Z", "+00:00")) -
                 datetime.fromisoformat(start.replace("Z", "+00:00")))
        h, rem = divmod(delta.seconds, 3600)
        m, s = divmod(rem, 60)
        return f"{h}h {m}m {s}s" if h else (f"{m}m {s}s" if m else f"{s}s")
    except Exception:
        return "N/A"


def generate(task_id: str, summary: dict, fast_log_path: str,
             output_path: str) -> bool:
    """Render PNG report for a task and save to output_path. Return True on success."""
    flow = summary.get("flow", {})
    events = summary.get("event", {})
    priorities = _parse_priorities(fast_log_path)

    start_time = flow.get("start_time", "N/A")
    end_time = flow.get("end_time", "N/A")
    total_bytes = flow.get("total_bytes", 0)
    total_events = sum(v.get("count", 0) for v in events.values())

    try:
        fmt_start = datetime.fromisoformat(
            start_time.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        fmt_start = start_time

    rows = [
        ("專案代號",        task_id,                             "#3498db"),
        ("開始時間",        fmt_start,                           "#2ecc71"),
        ("掃描時長",        _fmt_duration(start_time, end_time), "#f39c12"),
        ("總流量",          _fmt_bytes(total_bytes),             "#9b59b6"),
        ("協定事件數",      f"{total_events:,}",                 "#e74c3c"),
        ("Priority 1 告警", f"{priorities.get(1, 0):,}",        "#e74c3c"),
        ("Priority 2 告警", f"{priorities.get(2, 0):,}",        "#f39c12"),
        ("Priority 3 告警", f"{priorities.get(3, 0):,}",        "#95a5a6"),
    ]

    fig, ax = plt.subplots(figsize=(14, 8))
    ax.axis("off")
    fig.patch.set_facecolor("#f8f9fa")
    plt.rcParams.update({"font.family": "DejaVu Sans", "axes.unicode_minus": False})

    ax.add_patch(Rectangle((0.05, 0.90), 0.90, 0.08,
                            transform=ax.transAxes, facecolor="#2c3e50"))
    ax.text(0.5, 0.94, f"分析報告 — {task_id}",
            ha="center", va="center", fontsize=22, fontweight="bold",
            color="white", transform=ax.transAxes)

    ax.add_patch(Rectangle((0.08, 0.08), 0.84, 0.80,
                            transform=ax.transAxes,
                            facecolor="white", edgecolor="#dee2e6", linewidth=2))

    y, step = 0.85, 0.09
    for i, (label, value, color) in enumerate(rows):
        if i % 2 == 0:
            ax.add_patch(Rectangle((0.10, y - 0.035), 0.80, 0.06,
                                   transform=ax.transAxes,
                                   facecolor="#f8f9fa", zorder=1))
        ax.text(0.15, y, label, fontsize=13, color="#555",
                transform=ax.transAxes, zorder=2)
        ax.text(0.60, y, value, fontsize=13, fontweight="bold",
                color=color, transform=ax.transAxes, zorder=2)
        y -= step

    plt.tight_layout()
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return True
