"""Deep packet analysis — DNS, HTTP, TLS."""

import re
import subprocess
from collections import Counter
from typing import Any

DNS_TUNNEL_LENGTH_THRESHOLD = 52
_B32_RE = re.compile(r"^[A-Z2-7]{20,}$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")

TLS_VERSION_MAP: dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


def _run_tshark(tshark_exe: str, pcap: str, fields: list[str],
                filter_expr: str = "") -> list[str]:
    cmd = [tshark_exe, "-r", pcap, "-T", "fields", "-E", "separator=|"]
    for f in fields:
        cmd += ["-e", f]
    if filter_expr:
        cmd += ["-Y", filter_expr]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    return r.stdout.strip().splitlines() if r.stdout.strip() else []


def _detect_dns_tunnel(qname: str) -> bool:
    if len(qname) > DNS_TUNNEL_LENGTH_THRESHOLD:
        return True
    labels = qname.rstrip(".").split(".")
    longest = max(labels, key=len) if labels else ""
    return bool(_B32_RE.match(longest.upper()) or _B64_RE.match(longest))


def analyze_dns(tshark_exe: str, pcap_paths: list[str]) -> dict[str, Any]:
    """Deep DNS analysis: top queries, NXDOMAIN, tunnel suspects."""
    fields = ["dns.qry.name", "dns.flags.rcode"]
    query_counter: Counter = Counter()
    nxdomain_counter: Counter = Counter()
    tunnel_suspects: dict[str, str] = {}

    for pcap in pcap_paths:
        for line in _run_tshark(tshark_exe, pcap, fields, filter_expr="dns"):
            parts = line.split("|")
            if len(parts) < 2:
                continue
            qname = parts[0].strip().lower()
            rcode = parts[1].strip()
            if not qname:
                continue
            query_counter[qname] += 1
            if rcode == "3":
                nxdomain_counter[qname] += 1
            if qname not in tunnel_suspects and _detect_dns_tunnel(qname):
                if len(qname) > DNS_TUNNEL_LENGTH_THRESHOLD:
                    reason = f"查詢名稱長度 {len(qname)} > 閾值 {DNS_TUNNEL_LENGTH_THRESHOLD}"
                else:
                    reason = "標籤符合 Base32/Base64 編碼特徵"
                tunnel_suspects[qname] = reason

    return {
        "top_queries": [{"qname": q, "count": c} for q, c in query_counter.most_common(20)],
        "nxdomain_list": [{"qname": q, "count": c} for q, c in nxdomain_counter.most_common()],
        "tunnel_suspects": [{"qname": q, "reason": r} for q, r in tunnel_suspects.items()],
        "total_queries": sum(query_counter.values()),
        "unique_qnames": len(query_counter),
    }


def analyze_http(tshark_exe: str, pcap_paths: list[str]) -> dict[str, Any]:
    """HTTP analysis: hosts, URIs, methods, user-agents, status codes."""
    fields = ["http.host", "http.request.uri", "http.request.method",
              "http.user_agent", "http.response.code"]
    host_counter: Counter = Counter()
    uri_counter: Counter = Counter()
    method_counter: Counter = Counter()
    ua_counter: Counter = Counter()
    status_counter: Counter = Counter()
    total_requests = 0

    for pcap in pcap_paths:
        for line in _run_tshark(tshark_exe, pcap, fields, filter_expr="http"):
            parts = line.split("|")
            if len(parts) < 5:
                continue
            host, uri, method, ua, status_code = (p.strip() for p in parts[:5])
            if method:
                total_requests += 1
                if host:   host_counter[host] += 1
                if uri:    uri_counter[uri] += 1
                if method: method_counter[method] += 1
                if ua:     ua_counter[ua] += 1
            if status_code:
                status_counter[status_code] += 1

    return {
        "top_hosts": [{"host": h, "count": c} for h, c in host_counter.most_common(20)],
        "top_uris": [{"uri": u, "count": c} for u, c in uri_counter.most_common(20)],
        "method_dist": dict(method_counter),
        "user_agent_dist": [{"user_agent": u, "count": c} for u, c in ua_counter.most_common(10)],
        "status_code_dist": dict(status_counter),
        "total_requests": total_requests,
    }


def analyze_tls(tshark_exe: str, pcap_paths: list[str]) -> dict[str, Any]:
    """TLS analysis: SNI, versions, cipher suites.

    Two-pass approach:
      1. tls.handshake for SNI + cipher suites (Client/Server Hello)
      2. tls.record.version for all TLS records (broader coverage)
    """
    # --- Pass 1: handshake details (SNI + ciphers) ---
    hs_fields = ["tls.handshake.extensions_server_name",
                 "tls.handshake.ciphersuite"]
    sni_counter: Counter = Counter()
    cipher_counter: Counter = Counter()
    total_handshakes = 0

    for pcap in pcap_paths:
        for line in _run_tshark(tshark_exe, pcap, hs_fields,
                                filter_expr="tls.handshake"):
            parts = line.split("|")
            if len(parts) < 2:
                continue
            sni, cipher = (p.strip() for p in parts[:2])
            total_handshakes += 1
            if sni:
                sni_counter[sni] += 1
            if cipher:
                cipher_counter[cipher] += 1

    # --- Pass 2: all TLS records for version distribution ---
    ver_fields = ["tls.record.version"]
    version_counter: Counter = Counter()
    total_records = 0

    for pcap in pcap_paths:
        for line in _run_tshark(tshark_exe, pcap, ver_fields,
                                filter_expr="tls"):
            raw_version = line.strip()
            if not raw_version:
                continue
            total_records += 1
            try:
                ver_int = int(raw_version, 16) if raw_version.startswith("0x") \
                          else int(raw_version)
                ver_str = TLS_VERSION_MAP.get(ver_int, f"Unknown(0x{ver_int:04x})")
            except ValueError:
                ver_str = raw_version
            version_counter[ver_str] += 1

    return {
        "top_sni": [{"sni": s, "count": c} for s, c in sni_counter.most_common(20)],
        "version_dist": dict(version_counter),
        "cipher_suite_dist": [{"cipher": c, "count": n}
                              for c, n in cipher_counter.most_common(15)],
        "total_handshakes": total_handshakes,
        "total_records": total_records,
    }


def deep_analyze(
    task_id: str,
    pcap_paths: list[str],
    tshark_exe: str = "tshark",
    progress_callback=None,
) -> dict[str, Any]:
    """Unified entry point for deep packet analysis (DNS → HTTP → TLS)."""
    steps = [
        ("dns",  analyze_dns,  60, 67),
        ("http", analyze_http, 67, 74),
        ("tls",  analyze_tls,  74, 80),
    ]
    results: dict[str, Any] = {}

    for step_name, func, prog_start, prog_end in steps:
        if progress_callback:
            progress_callback(step_name, prog_start)
        results[step_name] = func(tshark_exe, pcap_paths)
        if progress_callback:
            progress_callback(step_name, prog_end)

    return results
