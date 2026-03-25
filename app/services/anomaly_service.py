"""Anomaly detection rules applied to analysis summary."""

TRUSTED_COUNTRIES = {"LOCAL", "TW", "US"}
HIGH_TRAFFIC_THRESHOLD = 100 * 1024 * 1024  # 100 MB
TLS_RATIO_THRESHOLD = 0.80
FOREIGN_RATIO_THRESHOLD = 0.30


def detect_anomalies(summary: dict) -> list[dict]:
    """
    Check analysis summary and return list of anomaly dicts.
    Each: {"type": str, "severity": "HIGH"|"MEDIUM"|"LOW", "detail": str}
    """
    anomalies = []

    # 1. Single connection > 100 MB
    for conn in summary.get("top_ip", []):
        if conn.get("bytes", 0) > HIGH_TRAFFIC_THRESHOLD:
            anomalies.append({
                "type": "large_connection",
                "severity": "HIGH",
                "detail": f"{conn['connection']} 傳輸了 "
                          f"{conn['bytes'] / 1048576:.1f} MB",
            })

    # 2. TLS > 80% of all protocol events
    events = summary.get("event", {})
    total_events = sum(v.get("count", 0) for v in events.values())
    if total_events > 0:
        tls_ratio = events.get("TLS", {}).get("count", 0) / total_events
        if tls_ratio > TLS_RATIO_THRESHOLD:
            anomalies.append({
                "type": "high_tls_ratio",
                "severity": "MEDIUM",
                "detail": f"TLS 佔所有流量的 {tls_ratio:.0%}",
            })

    # 3. Foreign traffic > 30%
    geo = summary.get("geo", {})
    total_geo = sum(geo.values())
    if total_geo > 0:
        foreign = sum(b for cc, b in geo.items() if cc not in TRUSTED_COUNTRIES)
        if foreign / total_geo > FOREIGN_RATIO_THRESHOLD:
            anomalies.append({
                "type": "foreign_traffic",
                "severity": "MEDIUM",
                "detail": f"{foreign / total_geo:.0%} 的流量來自非信任國家",
            })

    return anomalies
