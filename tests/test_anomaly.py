"""Anomaly detection rule tests."""

import pytest
from app.services.anomaly_service import detect_anomalies


def test_large_connection_triggers_high(analysis_summary_with_large_conn):
    """Single connection > 100 MB → HIGH severity."""
    results = detect_anomalies(analysis_summary_with_large_conn)
    large = [a for a in results if a["type"] == "large_connection"]
    assert len(large) == 1
    assert large[0]["severity"] == "HIGH"


def test_normal_connection_no_anomaly(analysis_summary_normal):
    """Normal summary with no violations → no anomalies."""
    results = detect_anomalies(analysis_summary_normal)
    large = [a for a in results if a["type"] == "large_connection"]
    assert len(large) == 0


def test_high_tls_ratio():
    """TLS > 80% → MEDIUM severity."""
    summary = {
        "top_ip": [],
        "event": {
            "TLS": {"count": 85},
            "HTTP": {"count": 10},
            "DNS": {"count": 5},
        },
        "geo": {},
    }
    results = detect_anomalies(summary)
    tls = [a for a in results if a["type"] == "high_tls_ratio"]
    assert len(tls) == 1
    assert tls[0]["severity"] == "MEDIUM"


def test_tls_below_threshold():
    """TLS < 80% → no anomaly."""
    summary = {
        "top_ip": [],
        "event": {
            "TLS": {"count": 50},
            "HTTP": {"count": 50},
        },
        "geo": {},
    }
    results = detect_anomalies(summary)
    tls = [a for a in results if a["type"] == "high_tls_ratio"]
    assert len(tls) == 0


def test_foreign_traffic():
    """Foreign traffic > 30% → MEDIUM severity."""
    summary = {
        "top_ip": [],
        "event": {},
        "geo": {"TW": 3000, "CN": 4000, "RU": 3000},
    }
    results = detect_anomalies(summary)
    foreign = [a for a in results if a["type"] == "foreign_traffic"]
    assert len(foreign) == 1
    assert foreign[0]["severity"] == "MEDIUM"


def test_trusted_countries_no_foreign_anomaly():
    """Only trusted countries (TW, US, LOCAL) → no anomaly."""
    summary = {
        "top_ip": [],
        "event": {},
        "geo": {"TW": 5000, "US": 3000, "LOCAL": 2000},
    }
    results = detect_anomalies(summary)
    foreign = [a for a in results if a["type"] == "foreign_traffic"]
    assert len(foreign) == 0


def test_empty_summary():
    """Empty summary → no anomalies."""
    results = detect_anomalies({"top_ip": [], "event": {}, "geo": {}})
    assert results == []
