"""Tests for DNS resolution and wildcard detection logic."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import dns.exception

from reconfuzz.dns_resolver import detect_wildcard, resolve_host


class TestResolveHost:
    def test_returns_ips_on_success(self):
        mock_answer = [type("R", (), {"__str__": lambda self: "1.2.3.4"})()]
        with patch("reconfuzz.dns_resolver._resolver.resolve", new=AsyncMock(return_value=mock_answer)):
            ips = asyncio.run(resolve_host("example.com"))
        assert ips == ["1.2.3.4"]

    def test_returns_none_on_dns_failure(self):
        with patch(
            "reconfuzz.dns_resolver._resolver.resolve",
            new=AsyncMock(side_effect=dns.exception.DNSException),
        ):
            ips = asyncio.run(resolve_host("nonexistent.example.com"))
        assert ips is None

    def test_returns_none_on_general_exception(self):
        with patch(
            "reconfuzz.dns_resolver._resolver.resolve",
            new=AsyncMock(side_effect=OSError("network down")),
        ):
            ips = asyncio.run(resolve_host("example.com"))
        assert ips is None


class TestWildcardDetection:
    def test_detects_wildcard_when_all_three_resolve(self):
        """All 3 random subdomains resolving → wildcard detected."""
        mock_answer = [type("R", (), {"__str__": lambda self: "1.2.3.4"})()]
        with patch("reconfuzz.dns_resolver._resolver.resolve", new=AsyncMock(return_value=mock_answer)):
            is_wildcard, baseline_ips = asyncio.run(detect_wildcard("example.com"))
        assert is_wildcard is True
        assert "1.2.3.4" in baseline_ips

    def test_no_wildcard_when_any_probe_fails(self):
        """Any non-resolving probe → no wildcard."""
        with patch(
            "reconfuzz.dns_resolver._resolver.resolve",
            new=AsyncMock(side_effect=dns.exception.DNSException),
        ):
            is_wildcard, baseline_ips = asyncio.run(detect_wildcard("example.com"))
        assert is_wildcard is False
        assert baseline_ips == set()

    def test_returns_baseline_ips_on_wildcard(self):
        """Wildcard baseline IPs are collected from all probes."""
        mock_answer = [type("R", (), {"__str__": lambda self: "10.0.0.1"})()]
        with patch("reconfuzz.dns_resolver._resolver.resolve", new=AsyncMock(return_value=mock_answer)):
            is_wildcard, baseline_ips = asyncio.run(detect_wildcard("example.com"))
        assert is_wildcard is True
        assert baseline_ips == {"10.0.0.1"}
