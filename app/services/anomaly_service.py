"""Anomaly detection rules applied to analysis summary."""

from datetime import datetime

TRUSTED_COUNTRIES = {"LOCAL", "TW", "US"}
HIGH_TRAFFIC_THRESHOLD = 100 * 1024 * 1024  # 100 MB
TLS_RATIO_THRESHOLD = 0.80
FOREIGN_RATIO_THRESHOLD = 0.30
SUSPICIOUS_COUNTRIES = {"RU", "CN", "KP", "IR"}
NIGHT_HOURS = set(range(0, 6))  # 00:00 ~ 05:59


def detect_anomalies(summary: dict) -> list[dict]:
    """
    Check analysis summary and return list of anomaly dicts.
    Each: {"rule": str, "severity": "HIGH"|"MEDIUM"|"LOW", "detail": str,
           "value"?: number, "threshold"?: number}
    """
    anomalies: list[dict] = []

    # 1. Single connection > 100 MB
    for conn in summary.get("top_ip", []):
        if conn.get("bytes", 0) > HIGH_TRAFFIC_THRESHOLD:
            mb = conn["bytes"] / 1048576
            anomalies.append({
                "rule": "大量資料傳輸",
                "severity": "HIGH",
                "detail": f"{conn['connection']} 傳輸了 {mb:.1f} MB",
                "value": round(mb, 1),
                "threshold": round(HIGH_TRAFFIC_THRESHOLD / 1048576),
            })

    # 2. TLS > 80% of all protocol events
    events = summary.get("event", {})
    total_events = sum(v.get("count", 0) if isinstance(v, dict) else v
                       for v in events.values())
    if total_events > 0:
        tls_count = events.get("TLS", {})
        tls_val = tls_count.get("count", 0) if isinstance(tls_count, dict) else tls_count
        tls_ratio = tls_val / total_events
        if tls_ratio > TLS_RATIO_THRESHOLD:
            anomalies.append({
                "rule": "TLS 流量異常偏高",
                "severity": "MEDIUM",
                "detail": f"TLS 佔所有流量的 {tls_ratio:.0%}，可能存在加密隧道",
                "value": round(tls_ratio * 100, 1),
                "threshold": round(TLS_RATIO_THRESHOLD * 100),
            })

    # 3. Foreign traffic > 30%
    geo = summary.get("geo", {})
    total_geo = sum(geo.values()) if geo else 0
    if total_geo > 0:
        foreign = sum(b for cc, b in geo.items() if cc not in TRUSTED_COUNTRIES)
        foreign_ratio = foreign / total_geo
        if foreign_ratio > FOREIGN_RATIO_THRESHOLD:
            anomalies.append({
                "rule": "外國流量偏高",
                "severity": "MEDIUM",
                "detail": f"{foreign_ratio:.0%} 的流量來自非信任國家",
                "value": round(foreign_ratio * 100, 1),
                "threshold": round(FOREIGN_RATIO_THRESHOLD * 100),
            })

    # 4. Suspicious country traffic
    if geo:
        for cc in SUSPICIOUS_COUNTRIES:
            if cc in geo and geo[cc] > 0:
                mb = geo[cc] / 1048576
                anomalies.append({
                    "rule": f"可疑國家流量 ({cc})",
                    "severity": "HIGH",
                    "detail": f"偵測到來自 {cc} 的 {mb:.1f} MB 流量",
                    "value": round(mb, 1),
                    "threshold": 0,
                })

    # 5. Nighttime traffic
    flow = summary.get("flow", {})
    per_10m = flow.get("per_10_minutes", {})
    if per_10m:
        night_bytes = 0
        for time_key, bytes_val in per_10m.items():
            try:
                hour = int(time_key.split(" ")[1].split(":")[0]) if " " in time_key else -1
                if hour in NIGHT_HOURS:
                    night_bytes += bytes_val
            except (ValueError, IndexError):
                continue
        if night_bytes > 10 * 1024 * 1024:  # > 10 MB at night
            mb = night_bytes / 1048576
            anomalies.append({
                "rule": "夜間流量異常",
                "severity": "MEDIUM",
                "detail": f"凌晨 0-6 時有 {mb:.1f} MB 流量",
                "value": round(mb, 1),
                "threshold": 10,
            })

    # 6. DNS tunnel suspects
    deep = summary.get("deep", {})
    dns_data = deep.get("dns", {})
    tunnel_suspects = dns_data.get("tunnel_suspects", [])
    if tunnel_suspects:
        anomalies.append({
            "rule": "DNS 隧道嫌疑",
            "severity": "HIGH",
            "detail": f"偵測到 {len(tunnel_suspects)} 個可疑 DNS 查詢",
            "value": len(tunnel_suspects),
            "threshold": 0,
        })

    # 7. High NXDOMAIN ratio
    nxdomain_list = dns_data.get("nxdomain_list", [])
    total_queries = dns_data.get("total_queries", 0)
    if total_queries > 100:
        nx_count = sum(n.get("count", 0) for n in nxdomain_list)
        nx_ratio = nx_count / total_queries
        if nx_ratio > 0.20:
            anomalies.append({
                "rule": "NXDOMAIN 比率偏高",
                "severity": "MEDIUM",
                "detail": f"{nx_ratio:.0%} 的 DNS 查詢回應 NXDOMAIN，"
                          f"可能存在 DGA 惡意軟體",
                "value": round(nx_ratio * 100, 1),
                "threshold": 20,
            })

    # 8. Protocol anomaly — unusual protocols
    unusual_protos = {"FTP", "SMTP", "SNMP"}
    for proto in unusual_protos:
        if proto in events:
            p_data = events[proto]
            p_count = p_data.get("count", 0) if isinstance(p_data, dict) else p_data
            if p_count > 0:
                anomalies.append({
                    "rule": f"不常見協定 ({proto})",
                    "severity": "LOW",
                    "detail": f"偵測到 {p_count} 個 {proto} 事件",
                    "value": p_count,
                    "threshold": 0,
                })

    return anomalies
