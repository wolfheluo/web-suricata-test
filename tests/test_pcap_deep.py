"""pcap_deep_service unit tests — DNS tunnel detection."""

import pytest
from app.services.pcap_deep_service import _detect_dns_tunnel


def test_detect_tunnel_long_name():
    """Query name > 52 chars should be flagged."""
    long_name = "A" * 53 + ".evil.com"
    assert _detect_dns_tunnel(long_name) is True


def test_detect_tunnel_base32_label():
    """Base32-encoded label should be flagged."""
    name = "MFZWIZLTOQ3GC3DJONUXI33LNFWXA33SOR2Q.evil.com"
    assert _detect_dns_tunnel(name) is True


def test_detect_tunnel_base64_label():
    """Base64-encoded label should be flagged."""
    name = "c29tZUJhc2U2NHBheWxvYWQ=.evil.com"
    assert _detect_dns_tunnel(name) is True


def test_detect_tunnel_normal_domain():
    """Normal domain should NOT be flagged."""
    assert _detect_dns_tunnel("google.com") is False


def test_detect_tunnel_short_normal():
    """Short normal domain should NOT be flagged."""
    assert _detect_dns_tunnel("www.example.com") is False


def test_detect_tunnel_with_subdomain():
    """Normal subdomain should NOT be flagged."""
    assert _detect_dns_tunnel("mail.google.com") is False


def test_detect_tunnel_trailing_dot():
    """Name with trailing dot — strip and evaluate."""
    name = "A" * 53 + ".evil.com."
    assert _detect_dns_tunnel(name) is True
