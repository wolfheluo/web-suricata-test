"""tshark-based PCAP analysis — flow, top IP, protocols, geo."""

import ipaddress
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import geoip2.database
import geoip2.errors


def _run_tshark(tshark_exe: str, pcap: str, fields: list[str],
                filter_expr: str = "") -> list[str]:
    cmd = [tshark_exe, "-r", pcap, "-T", "fields", "-E", "separator=|"]
    for f in fields:
        cmd += ["-e", f]
    if filter_expr:
        cmd += ["-Y", filter_expr]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    return r.stdout.strip().splitlines() if r.stdout.strip() else []


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _10min_key(epoch: float) -> str:
    dt = datetime.fromtimestamp(epoch)
    return dt.replace(minute=(dt.minute // 10) * 10, second=0,
                      microsecond=0).strftime("%Y-%m-%d %H:%M")


def analyze_flow(tshark_exe: str, pcap_paths: list[str]) -> dict:
    """Aggregate per-10-min bytes and top-5 connections per bucket."""
    fields = ["frame.time_epoch", "frame.len", "ip.src", "ip.dst",
              "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]
    per_10m: dict[str, int] = defaultdict(int)
    top_ip_per_10m: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    timestamps: list[float] = []
    total_bytes = 0

    for pcap in pcap_paths:
        for line in _run_tshark(tshark_exe, pcap, fields):
            parts = line.split("|")
            if len(parts) < 8:
                continue
            try:
                ts = float(parts[0])
                size = int(parts[1])
                src, dst = parts[2], parts[3]
                src_port = parts[4] or parts[6]
                dst_port = parts[5] or parts[7]
            except (ValueError, IndexError):
                continue
            timestamps.append(ts)
            total_bytes += size
            key = _10min_key(ts)
            per_10m[key] += size
            if src and dst:
                conn = f"{src}:{src_port} -> {dst}:{dst_port}"
                top_ip_per_10m[key][conn] += size

    if not timestamps:
        return {}

    top5 = {
        k: [{"connection": c, "bytes": b}
            for c, b in sorted(v.items(), key=lambda x: x[1], reverse=True)[:5]]
        for k, v in top_ip_per_10m.items()
    }

    return {
        "start_time": datetime.fromtimestamp(min(timestamps)).isoformat(),
        "end_time": datetime.fromtimestamp(max(timestamps)).isoformat(),
        "total_bytes": total_bytes,
        "per_10_minutes": dict(sorted(per_10m.items())),
        "top_ip_per_10_minutes": dict(sorted(top5.items())),
    }


def analyze_top_ip(tshark_exe: str, pcap_paths: list[str]) -> list[dict]:
    """Return top 10 connections by bytes with protocol and time breakdown."""
    fields = ["frame.time_epoch", "ip.src", "ip.dst",
              "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "frame.len"]
    conn_bytes: dict[str, int] = defaultdict(int)
    conn_proto: dict[str, str] = {}
    conn_time: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    total = 0

    for pcap in pcap_paths:
        for line in _run_tshark(tshark_exe, pcap, fields):
            parts = line.split("|")
            if len(parts) < 8:
                continue
            try:
                ts, src, dst = float(parts[0]), parts[1], parts[2]
                tcp_sp, tcp_dp = parts[3], parts[4]
                udp_sp, udp_dp = parts[5], parts[6]
                size = int(parts[7])
            except (ValueError, IndexError):
                continue
            proto = "TCP" if tcp_sp else ("UDP" if udp_sp else "OTHER")
            sp = tcp_sp or udp_sp
            dp = tcp_dp or udp_dp
            conn = f"{src}:{sp} -> {dst}:{dp}"
            conn_bytes[conn] += size
            conn_proto[conn] = proto
            conn_time[conn][_10min_key(ts)] += size
            total += size

    top10 = sorted(conn_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
    return [
        {
            "connection": c,
            "bytes": b,
            "protocol": conn_proto.get(c, "UNKNOWN"),
            "top_3_time_periods": [
                {"rank": i + 1, "time_period": tp,
                 "bytes": tb,
                 "percentage_of_total": round(tb / total * 100, 2) if total else 0}
                for i, (tp, tb) in enumerate(
                    sorted(conn_time[c].items(), key=lambda x: x[1], reverse=True)[:3]
                )
            ],
        }
        for c, b in top10
    ]


TARGET_PROTOCOLS = {"DNS", "DHCP", "SMTP", "TCP", "TLS", "SNMP",
                    "HTTP", "FTP", "SMB3", "SMB2", "SMB", "HTTPS", "ICMP"}


def analyze_protocols(tshark_exe: str, pcap_paths: list[str]) -> dict:
    """Return per-protocol packet counts, top_ip and top-5 connections by bytes."""
    fields = ["frame.protocols", "ip.src", "ip.dst", "frame.len"]
    stats: dict[str, dict] = {}

    for pcap in pcap_paths:
        for line in _run_tshark(tshark_exe, pcap, fields):
            parts = line.split("|")
            if len(parts) < 4:
                continue
            try:
                protos = parts[0].upper().split(":")
                src, dst = parts[1], parts[2]
                size = int(parts[3]) if parts[3] else 0
            except (ValueError, IndexError):
                continue
            proto = next((p for p in reversed(protos) if p in TARGET_PROTOCOLS), "OTHER")
            entry = stats.setdefault(proto, {
                "count": 0, "_ip": defaultdict(int),
                "_conns": defaultdict(lambda: {"packets": 0, "bytes": 0})
            })
            entry["count"] += 1
            if src:
                entry["_ip"][src] += 1
            if dst:
                entry["_ip"][dst] += 1
            if src and dst:
                k = f"{src} -> {dst}"
                entry["_conns"][k]["packets"] += 1
                entry["_conns"][k]["bytes"] += size

    result = {}
    for proto, entry in stats.items():
        top_ip = max(entry["_ip"], key=entry["_ip"].get) if entry["_ip"] else ""
        conns = sorted(entry["_conns"].items(),
                       key=lambda x: x[1]["bytes"], reverse=True)[:5]
        result[proto] = {
            "count": entry["count"],
            "top_ip": top_ip,
            "detailed_stats": [
                {"src_ip": k.split(" -> ")[0], "dst_ip": k.split(" -> ")[1],
                 "packet_count": v["packets"], "packet_size": v["bytes"]}
                for k, v in conns
            ],
        }
    return result


def analyze_geo(tshark_exe: str, pcap_paths: list[str],
                geoip_db_path: str) -> dict[str, int]:
    """Return {country_code: bytes} sorted descending; private IP → 'LOCAL'."""
    fields = ["ip.src", "ip.dst", "frame.len"]
    country_bytes: dict[str, int] = defaultdict(int)

    with geoip2.database.Reader(geoip_db_path) as reader:
        for pcap in pcap_paths:
            for line in _run_tshark(tshark_exe, pcap, fields):
                parts = line.split("|")
                if len(parts) < 3:
                    continue
                try:
                    src, dst, size = parts[0], parts[1], int(parts[2])
                except (ValueError, IndexError):
                    continue
                for ip in (src, dst):
                    if not ip:
                        continue
                    if _is_private(ip):
                        country_bytes["LOCAL"] += size
                        continue
                    try:
                        cc = reader.city(ip).country.iso_code or "UNKNOWN"
                    except Exception:
                        cc = "UNKNOWN"
                    country_bytes[cc] += size

    return dict(sorted(country_bytes.items(), key=lambda x: x[1], reverse=True))


def analyze(task_id: str, pcap_paths: list[str],
            geoip_db_path: str, tshark_exe: str = "tshark") -> dict:
    """Run all tshark analyses and return combined summary dict."""
    return {
        "flow": analyze_flow(tshark_exe, pcap_paths),
        "top_ip": analyze_top_ip(tshark_exe, pcap_paths),
        "event": analyze_protocols(tshark_exe, pcap_paths),
        "geo": analyze_geo(tshark_exe, pcap_paths, geoip_db_path),
    }
