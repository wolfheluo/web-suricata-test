"""Tshark 深度分析服務 — 使用 tshark + GeoIP 分析 pcap 並生成 JSON 報告"""

import os
import json
import subprocess
import ipaddress
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import geoip2.database
import geoip2.errors

import config


# ---------------------------------------------------------------------------
# 工具函式
# ---------------------------------------------------------------------------

def _run_tshark(pcap_file: str, fields: list[str], filter_expr: str = "") -> list[str]:
    """執行 tshark 命令並回傳每行結果"""
    cmd = [config.TSHARK_EXE, "-r", pcap_file, "-T", "fields", "-E", "separator=|"]
    for f in fields:
        cmd.extend(["-e", f])
    if filter_expr:
        cmd.extend(["-Y", filter_expr])
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    return result.stdout.strip().split("\n") if result.stdout.strip() else []


def _parse_multiple_values(value_string: str, value_type: str = "ip"):
    if not value_string:
        return None
    if "," not in value_string:
        return value_string.strip()
    values = [v.strip() for v in value_string.split(",") if v.strip()]
    if not values:
        return None
    if value_type == "ip":
        for v in values:
            try:
                ip_obj = ipaddress.ip_address(v)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast):
                    return v
            except ValueError:
                continue
        for v in values:
            try:
                ipaddress.ip_address(v)
                return v
            except ValueError:
                continue
    elif value_type == "port":
        for v in values:
            try:
                port_num = int(v)
                if 0 <= port_num <= 65535:
                    return v
            except ValueError:
                continue
    return values[0] if values else None


def _create_connection_string(src_ip, dst_ip, src_port, dst_port):
    ps = _parse_multiple_values(src_ip, "ip")
    pd = _parse_multiple_values(dst_ip, "ip")
    if not ps or not pd:
        return None
    pp_s = _parse_multiple_values(src_port, "port") if src_port else ""
    pp_d = _parse_multiple_values(dst_port, "port") if dst_port else ""
    if pp_s and pp_d:
        return f"{ps}:{pp_s} -> {pd}:{pp_d}"
    return f"{ps} -> {pd}"


def _get_country_code(geo_reader, ip_str):
    if not geo_reader or not ip_str:
        return None
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
            return "LOCAL"
        response = geo_reader.city(ip_str)
        return response.country.iso_code or "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def _should_filter(src_ip, dst_ip, filter_ips: set) -> bool:
    if not filter_ips:
        return False
    ps = _parse_multiple_values(src_ip, "ip") if src_ip else None
    pd = _parse_multiple_values(dst_ip, "ip") if dst_ip else None
    if ps and ps in filter_ips:
        return True
    if pd and pd in filter_ips:
        return True
    return False


def parse_filter_ips(ip_input: str) -> set:
    """解析使用者輸入的 IP 過濾清單"""
    result: set = set()
    if not ip_input or not ip_input.strip():
        return result
    parts = ip_input.replace(",", " ").replace(";", " ").split()
    for part in parts:
        part = part.strip()
        if not part:
            continue
        try:
            if "/" in part:
                network = ipaddress.ip_network(part, strict=False)
                if network.num_addresses <= 256:
                    for ip in network.hosts():
                        result.add(str(ip))
                    result.add(str(network.network_address))
                    result.add(str(network.broadcast_address))
            else:
                result.add(str(ipaddress.ip_address(part)))
        except ValueError:
            continue
    return result


# ---------------------------------------------------------------------------
# 個別分析函式
# ---------------------------------------------------------------------------

def _analyze_basic_info(pcap_file: str, filter_ips: set = None) -> dict | None:
    fields = [
        "frame.time_epoch", "frame.len", "ip.src", "ip.dst",
        "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    ]
    lines = _run_tshark(pcap_file, fields)
    if not lines or lines == [""]:
        return None

    timestamps, total_bytes, packet_count, filtered_count = [], 0, 0, 0
    per_10_min: dict[str, int] = {}
    per_10_min_ip: dict[str, dict] = {}

    for line in lines:
        if "|" not in line:
            continue
        parts = line.split("|")
        if len(parts) < 8:
            continue
        try:
            ts = float(parts[0])
            frame_len = int(parts[1])
            src_ip, dst_ip = parts[2], parts[3]
            tcp_sp, tcp_dp = parts[4], parts[5]
            udp_sp, udp_dp = parts[6], parts[7]

            if _should_filter(src_ip, dst_ip, filter_ips):
                filtered_count += 1
                continue

            timestamps.append(ts)
            total_bytes += frame_len
            packet_count += 1

            dt = datetime.fromtimestamp(ts)
            mb = (dt.minute // 10) * 10
            tk = dt.replace(minute=mb, second=0, microsecond=0).strftime("%Y-%m-%d %H:%M")

            per_10_min[tk] = per_10_min.get(tk, 0) + frame_len
            if tk not in per_10_min_ip:
                per_10_min_ip[tk] = defaultdict(int)

            if src_ip and dst_ip:
                sp = tcp_sp or udp_sp
                dp = tcp_dp or udp_dp
                conn = _create_connection_string(src_ip, dst_ip, sp, dp)
                if conn:
                    per_10_min_ip[tk][conn] += frame_len
        except (ValueError, IndexError):
            continue

    if not timestamps:
        return None

    top_ip_per_10 = {}
    for tk in sorted(per_10_min_ip):
        top = sorted(per_10_min_ip[tk].items(), key=lambda x: x[1], reverse=True)[:5]
        top_ip_per_10[tk] = [{"connection": c, "bytes": b} for c, b in top]

    return {
        "start_time": datetime.fromtimestamp(min(timestamps)).isoformat(),
        "end_time": datetime.fromtimestamp(max(timestamps)).isoformat(),
        "total_bytes": total_bytes,
        "per_10_minutes": dict(sorted(per_10_min.items())),
        "top_ip_per_10_minutes": top_ip_per_10,
        "filtered_packets": filtered_count,
    }


def _analyze_ip_traffic(pcap_file: str, filter_ips: set = None) -> list[dict]:
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst",
        "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "frame.len",
    ]
    lines = _run_tshark(pcap_file, fields)
    conn_stats: dict[str, int] = defaultdict(int)
    conn_time: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    conn_proto: dict[str, str] = {}
    total_traffic = 0

    for line in lines:
        if "|" not in line or not line.strip():
            continue
        parts = line.split("|")
        if len(parts) < 8:
            continue
        try:
            ts = float(parts[0]) if parts[0] else 0
            src_ip, dst_ip = parts[1] or "N/A", parts[2] or "N/A"
            tcp_sp, tcp_dp = parts[3] or "", parts[4] or ""
            udp_sp, udp_dp = parts[5] or "", parts[6] or ""
            frame_len = int(parts[7]) if parts[7] else 0

            if _should_filter(src_ip, dst_ip, filter_ips):
                continue
            total_traffic += frame_len

            sp, dp, proto = "", "", "OTHER"
            if tcp_sp and tcp_dp:
                sp, dp, proto = tcp_sp, tcp_dp, "TCP"
            elif udp_sp and udp_dp:
                sp, dp, proto = udp_sp, udp_dp, "UDP"

            if src_ip != "N/A" and dst_ip != "N/A":
                conn = _create_connection_string(src_ip, dst_ip, sp, dp)
                if conn:
                    conn_stats[conn] += frame_len
                    conn_proto[conn] = proto
                    if ts > 0:
                        dt = datetime.fromtimestamp(ts)
                        mb = (dt.minute // 10) * 10
                        tk = dt.replace(minute=mb, second=0, microsecond=0).strftime("%Y-%m-%d %H:%M")
                        conn_time[conn][tk] += frame_len
        except (ValueError, IndexError):
            continue

    result = []
    for conn, byt in sorted(conn_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
        top_periods = sorted(conn_time[conn].items(), key=lambda x: x[1], reverse=True)[:3]
        result.append({
            "connection": conn,
            "bytes": byt,
            "protocol": conn_proto.get(conn, "UNKNOWN"),
            "top_3_time_periods": [
                {
                    "rank": i + 1,
                    "time_period": tp,
                    "bytes": tb,
                    "percentage_of_total": round(tb / total_traffic * 100, 2) if total_traffic else 0,
                }
                for i, (tp, tb) in enumerate(top_periods)
            ],
        })
    return result


def _analyze_protocols(pcap_file: str, filter_ips: set = None) -> dict:
    TARGET = {
        "DNS", "DHCP", "SMTP", "TCP", "TLS", "SNMP",
        "HTTP", "FTP", "SMB3", "SMB2", "SMB", "HTTPS", "ICMP",
    }
    fields = ["frame.protocols", "ip.src", "ip.dst", "frame.len"]
    lines = _run_tshark(pcap_file, fields)

    proto_stats: dict[str, dict] = {}
    other = {"count": 0, "ip_stats": defaultdict(int), "connections": defaultdict(lambda: {"packet_count": 0, "packet_size": 0})}

    for line in lines:
        if "|" not in line or not line.strip():
            continue
        parts = line.split("|")
        if len(parts) < 4:
            continue
        try:
            protocols = parts[0].split(":") if parts[0] else []
            src_ip, dst_ip = parts[1] or "N/A", parts[2] or "N/A"
            frame_len = int(parts[3]) if parts[3] else 0

            if _should_filter(src_ip, dst_ip, filter_ips):
                continue

            found = None
            for p in reversed(protocols):
                if p.upper() in TARGET:
                    found = p.upper()
                    break

            if found:
                if found not in proto_stats:
                    proto_stats[found] = {
                        "count": 0,
                        "ip_stats": defaultdict(int),
                        "connections": defaultdict(lambda: {"packet_count": 0, "packet_size": 0}),
                    }
                target = proto_stats[found]
            else:
                target = other

            target["count"] += 1
            if src_ip != "N/A":
                target["ip_stats"][src_ip] += 1
            if dst_ip != "N/A":
                target["ip_stats"][dst_ip] += 1
            if src_ip != "N/A" and dst_ip != "N/A":
                ps = _parse_multiple_values(src_ip, "ip")
                pd = _parse_multiple_values(dst_ip, "ip")
                if ps and pd:
                    ck = f"{ps} -> {pd}"
                    target["connections"][ck]["packet_count"] += 1
                    target["connections"][ck]["packet_size"] += frame_len
        except (ValueError, IndexError):
            continue

    if other["count"] > 0:
        proto_stats["OTHER"] = other

    result = {}
    for proto, stats in proto_stats.items():
        top_ip = max(stats["ip_stats"].items(), key=lambda x: x[1])[0] if stats["ip_stats"] else ""
        conns = sorted(
            [
                {"src_ip": ck.split(" -> ")[0], "dst_ip": ck.split(" -> ")[1], "packet_count": cs["packet_count"], "packet_size": cs["packet_size"]}
                for ck, cs in stats["connections"].items()
            ],
            key=lambda x: x["packet_size"],
            reverse=True,
        )[:5]
        result[proto] = {"count": stats["count"], "top_ip": top_ip, "detailed_stats": conns}
    return result


def _analyze_geo(pcap_file: str, geo_reader, filter_ips: set = None) -> dict:
    fields = ["ip.src", "ip.dst", "frame.len"]
    lines = _run_tshark(pcap_file, fields)
    country_bytes: dict[str, int] = defaultdict(int)

    for line in lines:
        if "|" not in line or not line.strip():
            continue
        parts = line.split("|")
        if len(parts) < 3:
            continue
        try:
            src_ip, dst_ip = parts[0] or None, parts[1] or None
            frame_len = int(parts[2]) if parts[2] else 0

            if _should_filter(src_ip, dst_ip, filter_ips):
                continue

            for ip in (src_ip, dst_ip):
                if ip:
                    primary = _parse_multiple_values(ip, "ip")
                    if primary:
                        cc = _get_country_code(geo_reader, primary)
                        if cc:
                            country_bytes[cc] += frame_len
        except (ValueError, IndexError):
            continue

    return dict(sorted(country_bytes.items(), key=lambda x: x[1], reverse=True))


# ---------------------------------------------------------------------------
# 單檔分析
# ---------------------------------------------------------------------------

def _process_single(pcap_file: str, out_base: str, geo_reader, filter_ips: set = None) -> dict | str:
    try:
        flow = _analyze_basic_info(pcap_file, filter_ips)
        if not flow:
            return f"無法分析 {pcap_file}"
        top_ip = _analyze_ip_traffic(pcap_file, filter_ips)
        events = _analyze_protocols(pcap_file, filter_ips)
        geo = _analyze_geo(pcap_file, geo_reader, filter_ips)

        result = {
            "flow": flow,
            "top_ip": top_ip,
            "event": events,
            "geo": geo,
            "analysis_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_file": os.path.basename(pcap_file),
            "filter_settings": {
                "filtered_ips": list(filter_ips) if filter_ips else [],
                "total_filtered_ips": len(filter_ips) if filter_ips else 0,
            },
        }

        stem = Path(pcap_file).stem
        out_file = os.path.join(out_base, f"{stem}_analysis.json")
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        return result
    except Exception as e:
        return f"處理 {pcap_file} 時發生錯誤: {e}"


# ---------------------------------------------------------------------------
# 結果合併
# ---------------------------------------------------------------------------

def _merge_results(results: list, out_base: str, filter_ips: set = None) -> dict:
    """合併所有分析結果並產生 analysis_summary.json"""
    all_results = []
    current_files = set()

    for r in results:
        if isinstance(r, dict) and "flow" in r:
            all_results.append(r)
            if "source_file" in r:
                current_files.add(r["source_file"])

    # 讀取已存在的分析檔
    if os.path.exists(out_base):
        for fn in os.listdir(out_base):
            if fn.endswith("_analysis.json"):
                fp = os.path.join(out_base, fn)
                try:
                    with open(fp, "r", encoding="utf-8") as f:
                        existing = json.load(f)
                    if isinstance(existing, dict) and "flow" in existing:
                        if existing.get("source_file", "") not in current_files:
                            all_results.append(existing)
                except Exception:
                    continue

    merged_flow = {
        "start_time": None, "end_time": None, "total_bytes": 0,
        "per_10_minutes": defaultdict(int),
        "top_ip_per_10_minutes": defaultdict(lambda: defaultdict(int)),
        "total_filtered_packets": 0,
    }
    merged_top_ip: dict[str, int] = defaultdict(int)
    merged_top_ip_time: dict = defaultdict(lambda: defaultdict(int))
    merged_top_ip_proto: dict[str, str] = {}
    merged_events: dict = {}
    merged_geo: dict[str, int] = defaultdict(int)
    processed = 0

    for r in all_results:
        if not isinstance(r, dict) or "flow" not in r:
            continue
        processed += 1
        fl = r["flow"]

        if merged_flow["start_time"] is None or fl["start_time"] < merged_flow["start_time"]:
            merged_flow["start_time"] = fl["start_time"]
        if merged_flow["end_time"] is None or fl["end_time"] > merged_flow["end_time"]:
            merged_flow["end_time"] = fl["end_time"]
        merged_flow["total_bytes"] += fl["total_bytes"]
        merged_flow["total_filtered_packets"] += fl.get("filtered_packets", 0)

        for tk, bv in fl["per_10_minutes"].items():
            merged_flow["per_10_minutes"][tk] += bv
        for tk, conns in fl.get("top_ip_per_10_minutes", {}).items():
            for ci in conns:
                merged_flow["top_ip_per_10_minutes"][tk][ci["connection"]] += ci["bytes"]

        for ci in r["top_ip"]:
            conn = ci["connection"]
            merged_top_ip[conn] += ci["bytes"]
            if "protocol" in ci:
                merged_top_ip_proto[conn] = ci["protocol"]
            for pi in ci.get("top_3_time_periods", []):
                merged_top_ip_time[conn][pi["time_period"]] += pi["bytes"]

        for proto, pd in r["event"].items():
            if proto not in merged_events:
                merged_events[proto] = {
                    "count": 0, "top_ip": pd["top_ip"],
                    "connections": defaultdict(lambda: {"packet_count": 0, "packet_size": 0}),
                }
            merged_events[proto]["count"] += pd["count"]
            for st in pd["detailed_stats"]:
                ck = f"{st['src_ip']} -> {st['dst_ip']}"
                merged_events[proto]["connections"][ck]["packet_count"] += st["packet_count"]
                merged_events[proto]["connections"][ck]["packet_size"] += st["packet_size"]

        for cc, bv in r["geo"].items():
            merged_geo[cc] += bv

    # 整理 top_ip
    top_conns = []
    for conn, byt in sorted(merged_top_ip.items(), key=lambda x: x[1], reverse=True)[:10]:
        tp = sorted(merged_top_ip_time[conn].items(), key=lambda x: x[1], reverse=True)[:3]
        top_conns.append({
            "connection": conn, "bytes": byt,
            "protocol": merged_top_ip_proto.get(conn, "UNKNOWN"),
            "top_3_time_periods": [
                {"rank": i + 1, "time_period": t, "bytes": b,
                 "percentage_of_total": round(b / merged_flow["total_bytes"] * 100, 2) if merged_flow["total_bytes"] else 0}
                for i, (t, b) in enumerate(tp)
            ],
        })

    # 整理 events
    final_events = {}
    for proto, data in merged_events.items():
        conns = sorted(
            [{"src_ip": ck.split(" -> ")[0], "dst_ip": ck.split(" -> ")[1],
              "packet_count": cs["packet_count"], "packet_size": cs["packet_size"]}
             for ck, cs in data["connections"].items()],
            key=lambda x: x["packet_size"], reverse=True,
        )[:5]
        final_events[proto] = {"count": data["count"], "top_ip": data["top_ip"], "detailed_stats": conns}

    # top_ip_per_10_minutes
    final_tip10 = {}
    for tk in sorted(merged_flow["top_ip_per_10_minutes"]):
        top = sorted(merged_flow["top_ip_per_10_minutes"][tk].items(), key=lambda x: x[1], reverse=True)[:5]
        final_tip10[tk] = [{"connection": c, "bytes": b} for c, b in top]

    merged_flow["per_10_minutes"] = dict(sorted(merged_flow["per_10_minutes"].items()))
    merged_flow["top_ip_per_10_minutes"] = final_tip10

    summary = {
        "summary": {
            "total_files_processed": processed,
            "analysis_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "filter_settings": {
                "filtered_ips": list(filter_ips) if filter_ips else [],
                "total_filtered_ips": len(filter_ips) if filter_ips else 0,
                "total_filtered_packets": merged_flow["total_filtered_packets"],
            },
        },
        "flow": merged_flow,
        "top_ip": top_conns,
        "event": final_events,
        "geo": dict(sorted(merged_geo.items(), key=lambda x: x[1], reverse=True)),
    }

    summary_path = os.path.join(out_base, "analysis_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    return summary


# ---------------------------------------------------------------------------
# 公開入口
# ---------------------------------------------------------------------------

def run_tshark_analysis(
    pcap_paths: list[str],
    out_base: str,
    filter_ips: set | None = None,
    on_progress=None,
) -> dict:
    """
    對一組 pcap 執行 tshark 深度分析並產生 analysis_summary.json。

    Returns:
        合併後的 summary dict
    """
    os.makedirs(out_base, exist_ok=True)

    geo_reader = None
    if os.path.exists(config.GEOIP_DB_PATH):
        try:
            geo_reader = geoip2.database.Reader(config.GEOIP_DB_PATH)
        except Exception:
            pass

    total = len(pcap_paths)
    max_workers = min(config.MAX_WORKERS, total) if total > 1 else 1
    results: list = []

    if max_workers > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            fmap = {
                executor.submit(_process_single, p, out_base, geo_reader, filter_ips): p
                for p in pcap_paths
            }
            for future in as_completed(fmap):
                r = future.result()
                results.append(r)
                if on_progress:
                    on_progress(len(results), total, os.path.basename(fmap[future]))
    else:
        for p in pcap_paths:
            r = _process_single(p, out_base, geo_reader, filter_ips)
            results.append(r)
            if on_progress:
                on_progress(len(results), total, os.path.basename(p))

    summary = _merge_results(results, out_base, filter_ips)

    if geo_reader:
        geo_reader.close()

    return summary
