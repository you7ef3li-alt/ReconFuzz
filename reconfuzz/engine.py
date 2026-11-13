"""Unified async worker-pool execution engine for ReconFuzz.

Architecture — producer / consumer with bounded asyncio.Queue:
- Producer streams from iter_wordlist() lazily (constant memory regardless of
  wordlist size) and enqueues work items one at a time.
- N worker coroutines (N = cfg.threads) consume concurrently from the queue.
- Queue is bounded to 2 × cfg.threads to cap in-flight memory.
- Sentinel values (None) terminate workers cleanly — no task leakage.
- asyncio.Event provides cooperative stop() for SIGINT; workers check it before
  each probe so in-flight requests complete but no new ones are started.
- Workers share a single httpx.AsyncClient (passed in via cfg, never created here).
- All exceptions in worker bodies are caught; error counter is incremented.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator

import httpx
from rich.console import Console

from reconfuzz.dns_resolver import detect_wildcard, resolve_host
from reconfuzz.filters import Baseline404, build_baseline, should_display
from reconfuzz.http_client import HTTPResponse, fetch
from reconfuzz.models import ScanConfig, ScanResult, SubdomainResult
from reconfuzz.utils import RateLimiter, build_dir_urls, print_dir_result, print_sub_result

console = Console()


# ---------------------------------------------------------------------------
# Directory fuzzing engine
# ---------------------------------------------------------------------------


class DirEngine:
    """Bounded asyncio.Queue directory fuzzer.

    Accepts a ScanConfig so all tunables arrive in one object rather than
    a long list of keyword arguments.
    """

    def __init__(
        self,
        base_url: str,
        wordlist: Iterator[str],
        cfg: ScanConfig,
        client: httpx.AsyncClient,
    ) -> None:
        self.base_url = base_url
        self.wordlist = wordlist
        self.cfg = cfg
        self.client = client

        self._rate = RateLimiter(cfg.rate)
        self.results: list[ScanResult] = []
        self._requests = 0
        self._filtered = 0
        self._errors = 0
        self._stop = asyncio.Event()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def run(self) -> list[ScanResult]:
        """Run directory scan; return list of hits."""
        if not self.cfg.quiet:
            console.print("[dim]Building 404 baseline...[/dim]")

        try:
            baseline = await build_baseline(self.base_url, self.client)
        except Exception:  # noqa: BLE001
            baseline = Baseline404()

        if not self.cfg.quiet:
            if baseline.established:
                console.print(
                    f"[dim]404 baseline → status={baseline.status}  "
                    f"sizes={baseline.sizes}[/dim]"
                )
            else:
                console.print("[yellow][!] Could not establish 404 baseline[/yellow]")

        queue: asyncio.Queue[str | None] = asyncio.Queue(maxsize=self.cfg.threads * 2)
        workers = [
            asyncio.create_task(self._worker(queue, baseline))
            for _ in range(self.cfg.threads)
        ]

        try:
            await self._produce(queue)
        except Exception:  # noqa: BLE001
            pass
        finally:
            for _ in range(self.cfg.threads):
                await queue.put(None)  # sentinels

        await asyncio.gather(*workers, return_exceptions=True)
        return self.results

    def stop(self) -> None:
        """Cooperatively stop producers and workers (called on SIGINT)."""
        self._stop.set()

    def stats(self) -> dict:
        return {
            "requests": self._requests,
            "found": len(self.results),
            "filtered": self._filtered,
            "errors": self._errors,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _produce(self, queue: asyncio.Queue[str | None]) -> None:
        for word in self.wordlist:
            if self._stop.is_set():
                break
            for url in build_dir_urls(self.base_url, word, self.cfg.extensions):
                if self._stop.is_set():
                    return
                await self._rate.acquire()
                await queue.put(url)

    async def _worker(
        self, queue: asyncio.Queue[str | None], baseline: Baseline404
    ) -> None:
        while True:
            url = await queue.get()
            if url is None:
                queue.task_done()
                return
            try:
                await self._probe(url, baseline)
            except Exception:  # noqa: BLE001
                self._errors += 1
            finally:
                queue.task_done()

    async def _probe(self, url: str, baseline: Baseline404) -> None:
        if self._stop.is_set():
            return

        resp: HTTPResponse | None = await fetch(self.client, url)
        self._requests += 1

        if resp is None:
            self._errors += 1
            return

        if baseline.is_404(resp):
            self._filtered += 1
            return

        if not should_display(
            resp.status,
            match_codes=self.cfg.match_codes,
            filter_codes=self.cfg.filter_codes,
        ):
            self._filtered += 1
            return

        result = ScanResult(
            url=resp.url,
            status=resp.status,
            size=resp.size,
            response_time_ms=resp.response_time_ms,
            redirect=resp.redirect,
        )
        self.results.append(result)
        print_dir_result(result, self.cfg.quiet)


# ---------------------------------------------------------------------------
# Subdomain fuzzing engine
# ---------------------------------------------------------------------------


class SubEngine:
    """Bounded asyncio.Queue subdomain fuzzer.

    Per-word flow:
        1. DNS A-record resolution (non-blocking).
        2. Skip if no IPs returned.
        3. Wildcard check: flag if IPs ⊆ baseline_ips.
        4. HTTP probe: HTTPS first, HTTP as fallback.
        5. Append + display result.
    """

    def __init__(
        self,
        domain: str,
        wordlist: Iterator[str],
        cfg: ScanConfig,
        client: httpx.AsyncClient,
    ) -> None:
        self.domain = domain.lstrip(".")
        self.wordlist = wordlist
        self.cfg = cfg
        self.client = client

        self._rate = RateLimiter(cfg.rate)
        self.results: list[SubdomainResult] = []
        self._requests = 0
        self._errors = 0
        self._wildcard_ips: frozenset[str] = frozenset()
        self._stop = asyncio.Event()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def run(self) -> list[SubdomainResult]:
        """Run subdomain scan; return list of discovered subdomains."""
        if not self.cfg.quiet:
            console.print("[dim]Checking for wildcard DNS...[/dim]")

        try:
            is_wildcard, wildcard_ips = await detect_wildcard(self.domain)
        except Exception:  # noqa: BLE001
            is_wildcard, wildcard_ips = False, frozenset()

        self._wildcard_ips = wildcard_ips

        if is_wildcard:
            ip_list = ", ".join(sorted(wildcard_ips))
            console.print(
                f"[bold yellow][!] Wildcard DNS detected — all subdomains resolve. "
                f"Wildcard IPs: {ip_list}. "
                f"Results flagged [wc] may be false positives.[/bold yellow]"
            )

        queue: asyncio.Queue[str | None] = asyncio.Queue(maxsize=self.cfg.threads * 2)
        workers = [
            asyncio.create_task(self._worker(queue))
            for _ in range(self.cfg.threads)
        ]

        try:
            await self._produce(queue)
        except Exception:  # noqa: BLE001
            pass
        finally:
            for _ in range(self.cfg.threads):
                await queue.put(None)

        await asyncio.gather(*workers, return_exceptions=True)
        return self.results

    def stop(self) -> None:
        """Cooperatively stop producers and workers."""
        self._stop.set()

    def stats(self) -> dict:
        return {
            "requests": self._requests,
            "found": len(self.results),
            "errors": self._errors,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _produce(self, queue: asyncio.Queue[str | None]) -> None:
        for word in self.wordlist:
            if self._stop.is_set():
                break
            await self._rate.acquire()
            await queue.put(word)

    async def _worker(self, queue: asyncio.Queue[str | None]) -> None:
        while True:
            word = await queue.get()
            if word is None:
                queue.task_done()
                return
            try:
                await self._probe(word)
            except Exception:  # noqa: BLE001
                self._errors += 1
            finally:
                queue.task_done()

    async def _probe(self, word: str) -> None:
        if self._stop.is_set():
            return

        hostname = f"{word}.{self.domain}"
        ips: list[str] | None = await resolve_host(hostname)
        self._requests += 1

        if ips is None:
            return  # Does not resolve — skip HTTP probe

        result = SubdomainResult(hostname=hostname, resolved_ips=ips)

        # Flag if every resolved IP is in the wildcard baseline
        if self._wildcard_ips and frozenset(ips) <= self._wildcard_ips:
            result.wildcard_match = True

        # HTTP probe: HTTPS first, HTTP as fallback
        for scheme in ("https", "http"):
            url = f"{scheme}://{hostname}"
            resp: HTTPResponse | None = await fetch(self.client, url)
            if resp is not None:
                result.http_status = resp.status
                result.http_url = str(resp.url)
                result.response_time_ms = resp.response_time_ms
                result.size = resp.size
                break

        self.results.append(result)
        print_sub_result(result, self.cfg.quiet)
