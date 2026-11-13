"""Utility functions for ReconFuzz.

Sections:
- Wordlist I/O  : iter_wordlist() lazy generator; load_wordlist() eager loader.
- URL helpers   : validate_url(), build_dir_urls().
- Rate limiter  : async token-bucket RateLimiter.
- Rich renderers: _print_dir_result(), _print_sub_result() — live terminal output.
- JSON export   : save_json() with orjson when available, stdlib json as fallback.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console

try:
    import orjson as _orjson

    def _dumps(obj: dict) -> str:
        return _orjson.dumps(obj, option=_orjson.OPT_INDENT_2).decode()

except ImportError:
    _orjson = None  # type: ignore[assignment]

    def _dumps(obj: dict) -> str:
        return json.dumps(obj, indent=2, ensure_ascii=False)


console = Console()

_STATUS_COLORS: dict[int, str] = {2: "green", 3: "cyan", 4: "yellow", 5: "red"}


# ---------------------------------------------------------------------------
# Wordlist I/O
# ---------------------------------------------------------------------------


def iter_wordlist(path: str) -> Iterator[str]:
    """Stream words from *path* lazily — no full-file RAM allocation.

    Rules applied per line:
    - Stripped of surrounding whitespace.
    - Skipped if empty or starts with ``#``.
    - Deduplicated: first occurrence wins, subsequent duplicates discarded.

    Raises FileNotFoundError if *path* does not exist.
    Encoding: UTF-8 with ``errors="replace"`` for robustness on non-ASCII files.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Wordlist not found: {path}")
    seen: set[str] = set()
    try:
        with p.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                word = line.strip()
                if not word or word.startswith("#"):
                    continue
                if word not in seen:
                    seen.add(word)
                    yield word
    except (OSError, UnicodeDecodeError) as exc:
        raise FileNotFoundError(f"Cannot read wordlist {path}: {exc}") from exc


def load_wordlist(path: str) -> list[str]:
    """Eagerly load wordlist into a list (for small files and unit tests)."""
    return list(iter_wordlist(path))


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def validate_url(url: str) -> str:
    """Validate and normalise *url*.

    Strips trailing slashes.
    Raises ValueError for unsupported schemes or missing host.
    """
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"URL must begin with http:// or https://: {url!r}")
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"URL has no host: {url!r}")
    return url.rstrip("/")


def build_dir_urls(base_url: str, word: str, extensions: list[str]) -> list[str]:
    """Return probe URLs for *word* and each extension variant.

    Always emits the bare word URL first; duplicates are silently suppressed.

    Example::

        build_dir_urls("https://t.com", "admin", ["php", "txt"])
        # → ["https://t.com/admin",
        #    "https://t.com/admin.php",
        #    "https://t.com/admin.txt"]
    """
    base = base_url.rstrip("/")
    seen: set[str] = set()
    urls: list[str] = []
    candidates = [word] + [f"{word}.{ext.lstrip('.')}" for ext in extensions]
    for cand in candidates:
        url = f"{base}/{cand.lstrip('/')}"
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Async token-bucket rate limiter (``rate=0`` → unlimited).

    A single asyncio.Lock serialises bucket checks so the global per-second
    budget is shared correctly across all concurrent workers.
    """

    __slots__ = ("_interval", "_last", "_lock")

    def __init__(self, rate: float) -> None:
        self._interval = 1.0 / rate if rate > 0 else 0.0
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self._interval == 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._interval - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()


# ---------------------------------------------------------------------------
# Rich terminal renderers
# ---------------------------------------------------------------------------


def _status_color(status: int) -> str:
    return _STATUS_COLORS.get(status // 100, "white")


def _fmt_size(n: int) -> str:
    if n >= 1_048_576:
        return f"{n / 1_048_576:.1f}MB"
    if n >= 1_024:
        return f"{n / 1_024:.1f}KB"
    return f"{n}B"


def print_dir_result(result: ScanResult, quiet: bool) -> None:  # noqa: F821
    """Print a directory scan hit to stdout."""
    from reconfuzz.models import ScanResult  # local import avoids circular dep

    assert isinstance(result, ScanResult)
    if quiet:
        console.print(result.url)
        return
    color = _status_color(result.status)
    redir = f"  → [dim]{result.redirect}[/dim]" if result.redirect else ""
    console.print(
        f"[{color}][{result.status}][/{color}] "
        f"{result.url:<60} "
        f"[dim]{_fmt_size(result.size):<8}[/dim]"
        f"[dim]{result.response_time_ms:.0f}ms[/dim]"
        f"{redir}"
    )


def print_sub_result(result: SubdomainResult, quiet: bool) -> None:  # noqa: F821
    """Print a subdomain discovery hit to stdout."""
    from reconfuzz.models import SubdomainResult  # local import avoids circular dep

    assert isinstance(result, SubdomainResult)
    if quiet:
        console.print(result.http_url or result.hostname)
        return
    ips = ", ".join(result.resolved_ips[:3])
    status_part = ""
    if result.http_status is not None:
        c = _status_color(result.http_status)
        status_part = f" [[{c}]{result.http_status}[/{c}]]"
    size_part = f" [dim]{_fmt_size(result.size)}[/dim]" if result.size is not None else ""
    time_part = (
        f" [dim]{result.response_time_ms:.0f}ms[/dim]"
        if result.response_time_ms is not None
        else ""
    )
    wc_tag = " [yellow][wc][/yellow]" if result.wildcard_match else ""
    console.print(
        f"[bright_blue]{result.hostname}[/bright_blue]"
        f" [dim]({ips})[/dim]"
        f"{status_part}{size_part}{time_part}{wc_tag}"
    )


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------


def save_json(path: str, payload: dict) -> None:
    """Write *payload* to *path* as pretty-printed JSON.

    Uses orjson when available (significantly faster for large result sets).
    Falls back to stdlib json transparently.
    """
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_dumps(payload))
        console.print(f"[dim]Results saved → {path}[/dim]")
    except OSError as exc:
        console.print(f"[bold red][ERROR][/bold red] Cannot write output file: {exc}")
