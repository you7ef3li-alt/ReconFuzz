"""Data models for ReconFuzz.

All scan tunables live in ScanConfig — a single object passed from CLI → engine.
ScanResult and SubdomainResult carry the per-request outcomes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Unified scan configuration
# ---------------------------------------------------------------------------


@dataclass
class ScanConfig:
    """All scan tunables, created in cli.py and passed into engine constructors.

    Centralising every option here prevents scattered keyword-argument drift
    and makes adding new flags a one-line change.
    """

    threads: int = 40
    rate: float = 0.0            # req/s; 0 = unlimited
    timeout: float = 4.0         # total HTTP timeout (connect hard-capped at 2 s)
    quiet: bool = False
    follow_redirects: bool = False
    proxy: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    # dir-specific
    extensions: list[str] = field(default_factory=list)
    match_codes: set[int] | None = None
    filter_codes: set[int] | None = None


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Outcome of a single directory-fuzzing probe."""

    url: str
    status: int
    size: int
    response_time_ms: float
    redirect: str | None = None

    def to_dict(self) -> dict:
        d: dict = {
            "url": self.url,
            "status": self.status,
            "size": self.size,
            "response_time_ms": round(self.response_time_ms, 1),
        }
        if self.redirect:
            d["redirect"] = self.redirect
        return d


@dataclass
class SubdomainResult:
    """Outcome of a single subdomain DNS resolution + HTTP probe."""

    hostname: str
    resolved_ips: list[str] = field(default_factory=list)
    http_status: int | None = None
    http_url: str | None = None
    response_time_ms: float | None = None
    size: int | None = None
    wildcard_match: bool = False  # True when IPs ⊆ wildcard baseline

    def to_dict(self) -> dict:
        d: dict = {
            "hostname": self.hostname,
            "resolved_ips": self.resolved_ips,
        }
        if self.http_status is not None:
            d["http_status"] = self.http_status
        if self.http_url is not None:
            d["http_url"] = self.http_url
        if self.response_time_ms is not None:
            d["response_time_ms"] = round(self.response_time_ms, 1)
        if self.size is not None:
            d["size"] = self.size
        if self.wildcard_match:
            d["wildcard_match"] = True
        return d
