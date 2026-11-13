"""Response filtering for ReconFuzz.

Responsibilities:
- Parse -mc / -fc strings into sets of HTTP codes (comma-list + range support).
- Evaluate should_display() with deterministic precedence (-fc always wins).
- Calibrate a Baseline404 via 3 concurrent random-path probes (build_baseline).
- is_404(): hard match (status + ±5% size variance) OR soft match (body hash).

Filtering precedence (deterministic, documented):
  1. filter_codes (-fc) wins unconditionally: status in filter_codes → HIDE.
  2. match_codes (-mc) gate: set but status ∉ match_codes → HIDE.
  3. Default → SHOW.
"""

from __future__ import annotations

import asyncio
import random
import string

import httpx

from reconfuzz.http_client import HTTPResponse, fetch

_CHARS = string.ascii_lowercase + string.digits


# ---------------------------------------------------------------------------
# Status-code parsing & filtering
# ---------------------------------------------------------------------------


def _parse_status_list(raw: str) -> set[int]:
    """Parse a comma-separated list of status codes and inclusive ranges.

    Examples
    --------
    ``"200"``         → ``{200}``
    ``"200,301,302"`` → ``{200, 301, 302}``
    ``"200-204"``     → ``{200, 201, 202, 203, 204}``
    ``"200,400-403"`` → ``{200, 400, 401, 402, 403}``
    """
    codes: set[int] = set()
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            lo_s, _, hi_s = token.partition("-")
            try:
                codes.update(range(int(lo_s), int(hi_s) + 1))
            except ValueError:
                pass
        else:
            try:
                codes.add(int(token))
            except ValueError:
                pass
    return codes


def parse_match_filter(
    mc: str | None,
    fc: str | None,
) -> tuple[set[int] | None, set[int] | None]:
    """Return ``(match_codes, filter_codes)`` parsed from CLI option strings."""
    return (
        _parse_status_list(mc) if mc else None,
        _parse_status_list(fc) if fc else None,
    )


def should_display(
    status: int,
    *,
    match_codes: set[int] | None,
    filter_codes: set[int] | None,
) -> bool:
    """Return True when this status code should appear in output.

    Precedence (deterministic — documented in module docstring):
    1. filter_codes wins: status in filter_codes → False.
    2. match_codes gate:  match_codes set and status ∉ match_codes → False.
    3. Default → True.
    """
    if filter_codes and status in filter_codes:
        return False
    if match_codes and status not in match_codes:
        return False
    return True


# ---------------------------------------------------------------------------
# 404 baseline
# ---------------------------------------------------------------------------


def _rnd_path(n: int = 16) -> str:
    return "".join(random.choices(_CHARS, k=n))  # noqa: S311


class Baseline404:
    """Calibrated not-found baseline for a single scan target.

    is_404() returns True (filter this response) when either:
    - Hard match: same HTTP status AND size within ±5% of any baseline sample.
    - Soft match: body hash is identical to any baseline body hash.
    """

    __slots__ = ("status", "sizes", "body_hashes", "_established")

    def __init__(self) -> None:
        self.status: int | None = None
        self.sizes: list[int] = []
        self.body_hashes: set[int] = set()
        self._established: bool = False

    @property
    def established(self) -> bool:
        return self._established

    def _size_within_variance(self, size: int, tol: float = 0.05) -> bool:
        """True if *size* is within *tol* (5%) of any reference size."""
        for ref in self.sizes:
            if ref == 0:
                if size == 0:
                    return True
                continue
            if abs(size - ref) / ref <= tol:
                return True
        return False

    def is_404(self, resp: HTTPResponse) -> bool:
        """True if *resp* should be suppressed as a baseline-matching response."""
        if not self._established:
            return False
        # Hard 404: status matches AND size within ±5%
        if self.status is not None and resp.status == self.status:
            if self._size_within_variance(resp.size):
                return True
        # Soft 404: body hash identical to a known 404-page hash
        return resp.body_hash in self.body_hashes

    def absorb(self, responses: list[HTTPResponse]) -> None:
        """Populate baseline fields from a list of probe responses."""
        if not responses:
            return
        statuses = [r.status for r in responses]
        self.status = max(set(statuses), key=statuses.count)
        self.sizes = [r.size for r in responses]
        self.body_hashes = {r.body_hash for r in responses}
        self._established = True


async def build_baseline(
    base_url: str,
    client: httpx.AsyncClient,
    *,
    n_probes: int = 3,
) -> Baseline404:
    """Fire *n_probes* random non-existent path probes **concurrently** to
    calibrate the 404 baseline.

    Concurrent probing (asyncio.gather) is significantly faster than sequential
    and yields a more representative sample across server configurations.
    """
    base = base_url.rstrip("/")
    probes = [f"{base}/.reconfuzz-{_rnd_path()}" for _ in range(n_probes)]

    raw = await asyncio.gather(
        *[fetch(client, url, retries=0) for url in probes],
        return_exceptions=True,
    )
    valid = [r for r in raw if isinstance(r, HTTPResponse)]

    baseline = Baseline404()
    baseline.absorb(valid)
    return baseline
