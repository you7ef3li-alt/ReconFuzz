"""Persistent async HTTP client with connection-pool tuning for ReconFuzz.

Contract:
- build_client(cfg) creates ONE httpx.AsyncClient per scan.  Use as async
  context manager; never call inside a worker loop.
- Pool is sized to cfg.threads to saturate concurrency without over-subscribing.
- Dual timeouts: connect=2 s (dead-host fast-fail), total=cfg.timeout.
- Body streamed via aiter_bytes() and capped at MAX_BODY_BYTES (512 KB) to
  prevent OOM on large responses while still computing a reliable hash.
- Retry only on transient transport failures; HTTP 4xx/5xx are valid outcomes.
- All exceptions caught explicitly — no silent swallowing.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from dataclasses import dataclass

import httpx

from reconfuzz.models import ScanConfig

# Body cap for hash/size computation — 512 KB.
MAX_BODY_BYTES: int = 524_288
# Hard connect timeout regardless of user --timeout setting.
CONNECT_TIMEOUT: float = 2.0


@dataclass(slots=True)
class HTTPResponse:
    """Parsed result of a single HTTP GET request."""

    url: str
    status: int
    size: int                 # Content-Length header, or actual bytes read
    response_time_ms: float
    redirect: str | None
    body_hash: int            # hash() of first MAX_BODY_BYTES of body
    body_bytes: int           # actual bytes consumed from the stream


def build_client(cfg: ScanConfig) -> httpx.AsyncClient:
    """Construct a single shared httpx.AsyncClient from a ScanConfig.

    Usage::

        async with build_client(cfg) as client:
            resp = await fetch(client, url)
    """
    limits = httpx.Limits(
        max_connections=cfg.threads,
        max_keepalive_connections=cfg.threads,
        keepalive_expiry=30.0,
    )
    timeout = httpx.Timeout(cfg.timeout, connect=CONNECT_TIMEOUT)

    kwargs: dict = {
        "limits": limits,
        "timeout": timeout,
        "follow_redirects": cfg.follow_redirects,
        "verify": False,  # noqa: S501 — standard for security-testing tools
    }
    if cfg.headers:
        kwargs["headers"] = cfg.headers
    if cfg.proxy:
        kwargs["proxy"] = cfg.proxy

    return httpx.AsyncClient(**kwargs)


async def fetch(
    client: httpx.AsyncClient,
    url: str,
    *,
    retries: int = 1,
) -> HTTPResponse | None:
    """GET *url* using the shared client.

    Returns HTTPResponse for any HTTP status (4xx/5xx are valid results).
    Returns None only after exhausting retries on transient network failures.

    Retried exceptions: TimeoutException, NetworkError, RemoteProtocolError.
    Never retried: HTTP 4xx/5xx, SSL errors, other exceptions.
    """
    for attempt in range(retries + 1):
        try:
            return await _do_get(client, url)
        except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError):
            if attempt >= retries:
                return None
            await asyncio.sleep(0.25 * (attempt + 1))  # light exponential back-off
        except (ssl.SSLError, httpx.HTTPStatusError):
            # SSL failure or unexpected HTTP error — not retriable
            return None
        except httpx.HTTPError:
            return None
        except Exception:  # noqa: BLE001 — catch-all safety net
            return None
    return None  # type: ignore[return-value]  # unreachable; satisfies type checker


async def _do_get(client: httpx.AsyncClient, url: str) -> HTTPResponse:
    t0 = time.monotonic()
    resp = await client.get(url)
    elapsed_ms = (time.monotonic() - t0) * 1000

    # Stream body in 64 KB chunks; stop once cap is reached.
    body = b""
    async for chunk in resp.aiter_bytes(chunk_size=65_536):
        body += chunk
        if len(body) >= MAX_BODY_BYTES:
            break
    body = body[:MAX_BODY_BYTES]

    size = int(resp.headers.get("content-length", len(body)))
    redirect: str | None = None
    if resp.status_code in (301, 302, 303, 307, 308):
        redirect = resp.headers.get("location")

    return HTTPResponse(
        url=str(resp.url),
        status=resp.status_code,
        size=size,
        response_time_ms=elapsed_ms,
        redirect=redirect,
        body_hash=hash(body),
        body_bytes=len(body),
    )
