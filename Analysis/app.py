"""PCAP 分析器 — 獨立網頁服務 (Flask)

整合 Suricata + Tshark 分析，連接 NAS 讀取 pcap，
提供 NAS 資料夾瀏覽 UI 與分析結果儀表板。
"""

import os
import json
import glob
import threading
import uuid
from datetime import datetime
from urllib.parse import unquote

from flask import (
    Flask, render_template, jsonify, request, redirect, url_for, flash,
)

import config
from services.nas_service import nas_service
from services.suricata_service import run_suricata_analysis
from services.tshark_service import run_tshark_analysis, parse_filter_ips

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# 確保輸出目錄存在
os.makedirs(config.PROJECT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# 任務狀態管理 (記憶體內，適合單機使用)
# ---------------------------------------------------------------------------
_tasks_lock = threading.Lock()
_tasks: dict[str, dict] = {}  # task_id -> { status, progress, total, message, ... }


def _set_task(task_id: str, **kwargs):
    with _tasks_lock:
        if task_id not in _tasks:
            _tasks[task_id] = {}
        _tasks[task_id].update(kwargs)


def _get_task(task_id: str) -> dict | None:
    with _tasks_lock:
        return _tasks.get(task_id, {}).copy() if task_id in _tasks else None


# ---------------------------------------------------------------------------
# 輔助函式
# ---------------------------------------------------------------------------

def _get_existing_tasks() -> list[dict]:
    """從 projects/ 目錄讀取已完成的分析任務"""
    tasks = []
    if not os.path.exists(config.PROJECT_DIR):
        return tasks

    for item in os.listdir(config.PROJECT_DIR):
        project_path = os.path.join(config.PROJECT_DIR, item)
        if not os.path.isdir(project_path):
            continue
        summary_file = os.path.join(project_path, "analysis_summary.json")
        if not os.path.exists(summary_file):
            continue
        try:
            with open(summary_file, "r", encoding="utf-8") as f:
                summary = json.load(f)

            analysis_files = glob.glob(os.path.join(project_path, "*_analysis.json"))
            events = summary.get("event", {})
            total_events = sum(e.get("count", 0) for e in events.values())

            task = {
                "name": item,
                "path": project_path,
                "pcap_count": len(analysis_files),
                "created_time": datetime.fromtimestamp(os.path.getctime(project_path)),
                "analyzed": True,
                "total_bytes": summary.get("flow", {}).get("total_bytes", 0),
                "start_time": summary.get("flow", {}).get("start_time", ""),
                "end_time": summary.get("flow", {}).get("end_time", ""),
                "total_events": total_events,
                "anomaly_count": _detect_anomalies(summary),
            }
            tasks.append(task)
        except Exception:
            continue

    # 加入正在進行中的任務
    with _tasks_lock:
        for tid, info in _tasks.items():
            if info.get("status") == "running":
                tasks.append({
                    "name": info.get("task_name", tid),
                    "path": "",
                    "pcap_count": info.get("total", 0),
                    "created_time": info.get("created_time", datetime.now()),
                    "analyzed": False,
                    "total_bytes": 0,
                    "start_time": "",
                    "end_time": "",
                    "total_events": 0,
                    "anomaly_count": 0,
                    "task_id": tid,
                    "progress": info.get("progress", 0),
                    "total": info.get("total", 0),
                })

    tasks.sort(key=lambda x: x["created_time"], reverse=True)
    return tasks


def _detect_anomalies(summary: dict) -> int:
    count = 0
    top_ip = summary.get("top_ip", [])
    if top_ip and top_ip[0].get("bytes", 0) > 100 * 1024 * 1024:
        count += 1
    events = summary.get("event", {})
    total_ev = sum(e.get("count", 0) for e in events.values())
    if total_ev > 0:
        tls = events.get("TLS", {}).get("count", 0)
        if tls / total_ev > 0.8:
            count += 1
    geo = summary.get("geo", {})
    total_geo = sum(geo.values())
    if total_geo > 0:
        susp = sum(v for k, v in geo.items() if k not in ("LOCAL", "TW", "US"))
        if susp / total_geo > 0.3:
            count += 1
    return count


def _generate_anomaly_alerts(summary: dict) -> list[dict]:
    alerts = []
    top_ip = summary.get("top_ip", [])
    flow = summary.get("flow", {})
    total_bytes = flow.get("total_bytes", 1)

    for i, conn in enumerate(top_ip[:5]):
        bv = conn.get("bytes", 0)
        if bv > 50 * 1024 * 1024:
            connection = conn.get("connection", "")
            src_ip = connection.split(" -> ")[0].split(":")[0] if " -> " in connection else ""
            alerts.append({
                "type": "high_traffic", "severity": "high" if bv > 200 * 1024 * 1024 else "medium",
                "title": "大流量連接警示",
                "description": f"偵測到異常大流量連接：{_fmt_bytes(bv)}",
                "ip": src_ip, "connection": connection,
                "time": flow.get("start_time", ""),
                "details": {"bytes": bv, "rank": i + 1, "percentage": round(bv / total_bytes * 100, 2)},
            })

    events = summary.get("event", {})
    total_ev = sum(e.get("count", 0) for e in events.values())
    if total_ev > 0:
        for proto, ed in events.items():
            cnt = ed.get("count", 0)
            pct = cnt / total_ev * 100
            if proto == "OTHER" and pct > 50:
                alerts.append({
                    "type": "protocol_anomaly", "severity": "medium",
                    "title": "未識別協議過多",
                    "description": f"未識別協議佔 {pct:.1f}%",
                    "ip": ed.get("top_ip", ""), "time": flow.get("start_time", ""),
                    "details": {"protocol": proto, "count": cnt, "percentage": round(pct, 2)},
                })
            elif proto in ("TLS", "TCP") and pct > 70:
                alerts.append({
                    "type": "protocol_anomaly", "severity": "low",
                    "title": f"{proto} 流量過多",
                    "description": f"{proto} 佔 {pct:.1f}%",
                    "ip": ed.get("top_ip", ""), "time": flow.get("start_time", ""),
                    "details": {"protocol": proto, "count": cnt, "percentage": round(pct, 2)},
                })

    geo = summary.get("geo", {})
    total_geo = sum(geo.values())
    if total_geo > 0:
        for cc, bv in geo.items():
            pct = bv / total_geo * 100
            if cc in ("RU", "CN", "KP", "IR") and pct > 5:
                alerts.append({
                    "type": "geo_anomaly", "severity": "medium",
                    "title": "可疑國家流量警示",
                    "description": f"來自 {cc} 的流量：{_fmt_bytes(bv)} ({pct:.1f}%)",
                    "ip": "", "time": flow.get("start_time", ""),
                    "details": {"country": cc, "bytes": bv, "percentage": round(pct, 2)},
                })

    p10 = flow.get("per_10_minutes", {})
    for ts, bv in p10.items():
        try:
            h = datetime.strptime(ts, "%Y-%m-%d %H:%M").hour
            if (h >= 22 or h <= 6) and bv > 100 * 1024 * 1024:
                alerts.append({
                    "type": "time_anomaly", "severity": "medium",
                    "title": "深夜異常流量",
                    "description": f"在 {ts} 偵測到 {_fmt_bytes(bv)}",
                    "ip": "", "time": ts,
                    "details": {"time_period": ts, "bytes": bv, "hour": h},
                })
        except ValueError:
            continue
    return alerts


def _fmt_bytes(b):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} PB"


# ---------------------------------------------------------------------------
# 頁面路由
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    tasks = _get_existing_tasks()
    return render_template("index.html", tasks=tasks)


@app.route("/dashboard/<task_name>")
def dashboard(task_name):
    summary_file = os.path.join(config.PROJECT_DIR, task_name, "analysis_summary.json")
    if not os.path.exists(summary_file):
        flash("專案不存在或分析結果缺失", "error")
        return redirect(url_for("index"))
    return render_template("dashboard.html", task_name=task_name)


# ---------------------------------------------------------------------------
# NAS 瀏覽 API
# ---------------------------------------------------------------------------

@app.route("/api/nas/browse")
def api_nas_browse():
    path = request.args.get("path", "")
    try:
        result = nas_service.browse_directory(path)
        return jsonify({"data": {"path": path, "folders": result["folders"], "files": result["files"]}, "message": "ok"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404


# ---------------------------------------------------------------------------
# 分析任務 API
# ---------------------------------------------------------------------------

@app.route("/api/tasks", methods=["POST"])
def api_create_task():
    """建立並啟動分析任務"""
    data = request.get_json(force=True)
    task_name = data.get("task_name", "").strip()
    nas_path = data.get("nas_path", "").strip()
    pcap_files = data.get("pcap_files", [])
    filter_ip_input = data.get("filter_ips", "")
    run_suricata = data.get("run_suricata", True)

    if not task_name or not nas_path or not pcap_files:
        return jsonify({"error": "缺少必要參數"}), 400

    # 安全驗證 task_name
    safe_name = "".join(c for c in task_name if c.isalnum() or c in ("-", "_", " ")).strip()
    if not safe_name:
        return jsonify({"error": "任務名稱無效"}), 400

    out_base = os.path.join(config.PROJECT_DIR, safe_name)
    if os.path.exists(os.path.join(out_base, "analysis_summary.json")):
        return jsonify({"error": "任務名稱已存在且已分析完成"}), 409

    try:
        pcap_paths = nas_service.get_pcap_paths(nas_path, pcap_files)
    except (ValueError, FileNotFoundError) as e:
        return jsonify({"error": str(e)}), 400

    filter_ips = parse_filter_ips(filter_ip_input) if filter_ip_input else None
    task_id = uuid.uuid4().hex[:12]

    _set_task(
        task_id,
        status="running",
        task_name=safe_name,
        progress=0,
        total=len(pcap_paths) * (2 if run_suricata else 1),
        message="啟動分析中...",
        created_time=datetime.now(),
        phase="suricata" if run_suricata else "tshark",
    )

    def _worker():
        try:
            completed = 0
            total_steps = len(pcap_paths) * (2 if run_suricata else 1)

            if run_suricata:
                def on_suricata_progress(done, tot, msg):
                    nonlocal completed
                    completed = done
                    _set_task(task_id, progress=completed, total=total_steps,
                              message=f"[Suricata] {msg}", phase="suricata")

                run_suricata_analysis(pcap_paths, out_base, on_progress=on_suricata_progress)
                _set_task(task_id, phase="tshark", message="Suricata 完成，開始 Tshark 分析...")

            def on_tshark_progress(done, tot, filename):
                nonlocal completed
                offset = len(pcap_paths) if run_suricata else 0
                completed = offset + done
                _set_task(task_id, progress=completed, total=total_steps,
                          message=f"[Tshark] 分析 {filename}", phase="tshark")

            run_tshark_analysis(pcap_paths, out_base, filter_ips=filter_ips, on_progress=on_tshark_progress)

            _set_task(task_id, status="done", progress=total_steps, total=total_steps,
                      message="分析完成！")
        except Exception as e:
            _set_task(task_id, status="error", message=f"分析失敗：{e}")

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"task_id": task_id, "task_name": safe_name, "message": "任務已建立"})


@app.route("/api/tasks/<task_id>/status")
def api_task_status(task_id):
    info = _get_task(task_id)
    if not info:
        return jsonify({"error": "任務不存在"}), 404
    return jsonify(info)


# ---------------------------------------------------------------------------
# 分析資料 API (供儀表板使用)
# ---------------------------------------------------------------------------

def _load_summary(task_name: str) -> dict | None:
    fp = os.path.join(config.PROJECT_DIR, task_name, "analysis_summary.json")
    if not os.path.exists(fp):
        return None
    with open(fp, "r", encoding="utf-8") as f:
        return json.load(f)


@app.route("/api/flow/<task_name>")
def api_flow(task_name):
    s = _load_summary(task_name)
    return jsonify(s["flow"]) if s else (jsonify({"error": "not found"}), 404)


@app.route("/api/flow_details/<task_name>/<path:time_period>")
def api_flow_details(task_name, time_period):
    s = _load_summary(task_name)
    if not s:
        return jsonify({"error": "not found"}), 404
    tp = unquote(time_period)
    flow = s["flow"]
    tip10 = flow.get("top_ip_per_10_minutes", {})
    if tp not in tip10:
        return jsonify({"error": f"找不到時間段 {tp}"}), 404
    return jsonify({
        "time_period": tp,
        "total_bytes": flow.get("per_10_minutes", {}).get(tp, 0),
        "top_connections": tip10[tp],
    })


@app.route("/api/top_ip/<task_name>")
def api_top_ip(task_name):
    s = _load_summary(task_name)
    return jsonify(s["top_ip"]) if s else (jsonify({"error": "not found"}), 404)


@app.route("/api/geo/<task_name>")
def api_geo(task_name):
    s = _load_summary(task_name)
    if not s:
        return jsonify({"error": "not found"}), 404
    geo = s.get("geo", {})
    filtered = {k: v for k, v in geo.items() if k.upper() not in ("LOCAL", "LOCALHOST", "PRIVATE", "LAN")}
    return jsonify(filtered)


@app.route("/api/events/<task_name>")
def api_events(task_name):
    s = _load_summary(task_name)
    return jsonify(s["event"]) if s else (jsonify({"error": "not found"}), 404)


@app.route("/api/event_details/<task_name>/<protocol>")
def api_event_details(task_name, protocol):
    s = _load_summary(task_name)
    if not s:
        return jsonify({"error": "not found"}), 404
    pd = s.get("event", {}).get(protocol)
    if not pd:
        return jsonify({"error": f"找不到協議 {protocol}"}), 404
    return jsonify({
        "protocol": protocol,
        "total_count": pd.get("count", 0),
        "top_connections": pd.get("detailed_stats", []),
    })


@app.route("/api/anomaly/<task_name>")
def api_anomaly(task_name):
    s = _load_summary(task_name)
    if not s:
        return jsonify({"error": "not found"}), 404
    return jsonify(_generate_anomaly_alerts(s))


# ---------------------------------------------------------------------------
# 刪除任務 API
# ---------------------------------------------------------------------------

@app.route("/api/tasks/<task_name>", methods=["DELETE"])
def api_delete_task(task_name):
    """刪除已完成的分析任務"""
    import shutil
    safe_name = "".join(c for c in task_name if c.isalnum() or c in ("-", "_", " ")).strip()
    project_path = os.path.join(config.PROJECT_DIR, safe_name)
    if not os.path.exists(project_path):
        return jsonify({"error": "任務不存在"}), 404
    # 確保路徑安全
    real_path = os.path.realpath(project_path)
    real_base = os.path.realpath(config.PROJECT_DIR)
    if not real_path.startswith(real_base + os.sep):
        return jsonify({"error": "路徑驗證失敗"}), 400
    shutil.rmtree(project_path)
    return jsonify({"message": "已刪除"})


# ---------------------------------------------------------------------------
# 啟動
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("🌐 啟動 PCAP 分析器 Web 服務")
    print(f"📁 NAS 掛載點: {config.NAS_MOUNT_PATH}")
    print(f"📁 分析結果目錄: {config.PROJECT_DIR}")
    print(f"🔗 http://{config.HOST}:{config.PORT}")
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
