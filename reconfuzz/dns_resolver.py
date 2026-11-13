"""Non-blocking async DNS resolution and wildcard detection for ReconFuzz.

Contract:
- Module-level _resolver is configured once (timeout=2s, lifetime=3s) and
  shared across all coroutines — never re-instantiated per-request.
- resolve_host() catches every DNS failure mode explicitly and returns None.
- detect_wildcard() probes 3 UUID-derived random labels (20 hex chars =
  80 bits of entropy — false-positive probability is negligible).
- Returns (is_wildcard, frozenset[baseline_ips]) so engine can flag
  subdomain results whose IP set is a subset of the wildcard baseline.
- Strictly non-blocking: no dns.resolver.resolve, no socket.gethostbyname.
"""

from __future__ import annotations

import socket
import uuid

import dns.asyncresolver
import dns.exception
import dns.resolver

# ---------------------------------------------------------------------------
# Shared resolver — configured once at import time
# ---------------------------------------------------------------------------

_resolver = dns.asyncresolver.Resolver()
_resolver.timeout = 2.0   # per-nameserver query timeout (seconds)
_resolver.lifetime = 3.0  # total resolution budget across all nameservers


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def resolve_host(hostname: str) -> list[str] | None:
    """Resolve *hostname* A records asynchronously.

    Returns a list of IPv4 strings, or None on any failure:
    NXDOMAIN, SERVFAIL, timeout, socket error, etc.
    """
    try:
        answers = await _resolver.resolve(hostname, "A")
        return [str(rr) for rr in answers]
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        return None
    except dns.exception.Timeout:
        return None
    except dns.exception.DNSException:
        return None
    except (socket.gaierror, OSError):
        return None
    except Exception:  # noqa: BLE001
        return None


async def detect_wildcard(domain: str) -> tuple[bool, frozenset[str]]:
    """Probe 3 high-entropy random subdomains to detect wildcard DNS.

    Returns:
        (True,  frozenset of wildcard IPs)  — all 3 probes resolved.
        (False, frozenset())                — any probe did not resolve.

    The frozenset lets the engine test ``set(ips) <= wildcard_ips`` for each
    discovered subdomain and flag false-positive [wc] results.
    """
    labels = [uuid.uuid4().hex[:20] for _ in range(3)]
    baseline: set[str] = set()

    for label in labels:
        ips = await resolve_host(f"{label}.{domain}")
        if ips is None:
            # Any non-resolving probe conclusively rules out wildcard
            return False, frozenset()
        baseline.update(ips)

    return True, frozenset(baseline)
