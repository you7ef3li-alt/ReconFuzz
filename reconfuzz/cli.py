"""ReconFuzz CLI — unified entry point.

Flag inventory (zero shortcut collisions):
  Global:  --version/-V, --debug
  dir:     -u/--url, -w/--wordlist, -t/--threads, -e/--extensions,
           -mc/--match-status, -fc/--filter-status, -H/--header,
           -p/--proxy, --rate, --timeout, --follow, -q/--quiet, -o/--output
  sub:     -d/--domain, -w/--wordlist, -t/--threads, -H/--header,
           -p/--proxy, --rate, --timeout, --follow, -q/--quiet, -o/--output

Design notes:
- --timeout deliberately has NO single-char alias to avoid collision with -t.
- ScanConfig is built in CLI and passed to engines — one clean object.
- SIGINT is handled via engine.stop() (cooperative asyncio.Event drain).
- orjson used for JSON output when available; stdlib json as fallback.
- No Python tracebacks are emitted unless --debug is set.
"""

from __future__ import annotations

import asyncio
import signal
import sys
import time
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from reconfuzz import __version__
from reconfuzz.engine import DirEngine, SubEngine
from reconfuzz.filters import parse_match_filter
from reconfuzz.http_client import build_client
from reconfuzz.models import ScanConfig
from reconfuzz.utils import iter_wordlist, save_json, validate_url

app = typer.Typer(
    name="reconfuzz",
    help="ReconFuzz — Lightweight Directory & Subdomain Fuzzer",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)
_DEBUG = False


# ---------------------------------------------------------------------------
# Global callback
# ---------------------------------------------------------------------------


def _version_cb(value: bool) -> None:
    if value:
        console.print(f"ReconFuzz v{__version__}")
        raise typer.Exit()


@app.callback()
def _global(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version", "-V",
            callback=_version_cb,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = None,
    debug: Annotated[
        bool,
        typer.Option("--debug", help="Show full Python tracebacks on error."),
    ] = False,
) -> None:
    global _DEBUG
    _DEBUG = debug


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _err(msg: str) -> None:
    err_console.print(f"[bold red][ERROR][/bold red] {msg}")


def _banner(
    *,
    target: str,
    mode: str,
    threads: int,
    wordlist: str,
    extensions: list[str] | None = None,
) -> None:
    ext_line = (
        f"\n[bold]Extensions:[/bold] {', '.join(extensions)}"
        if extensions
        else ""
    )
    console.print(
        Panel(
            f"[bold cyan]ReconFuzz[/bold cyan] [dim]v{__version__}[/dim]\n"
            f"[dim]Directory & Subdomain Fuzzer[/dim]\n\n"
            f"[bold]Target:[/bold]   {target}\n"
            f"[bold]Mode:[/bold]     {mode}\n"
            f"[bold]Threads:[/bold]  {threads}\n"
            f"[bold]Wordlist:[/bold] {wordlist}"
            f"{ext_line}",
            border_style="cyan",
        )
    )


def _summary(stats: dict, elapsed: float, *, quiet: bool) -> None:
    if quiet:
        return
    console.rule()
    tbl = Table.grid(padding=(0, 2))
    tbl.add_column(style="bold")
    tbl.add_column()
    tbl.add_row("Scan completed", "")
    tbl.add_row("Requests:", str(stats.get("requests", 0)))
    tbl.add_row("Found:", f"[green]{stats.get('found', 0)}[/green]")
    if "filtered" in stats:
        tbl.add_row("Filtered:", str(stats["filtered"]))
    tbl.add_row("Errors:", str(stats.get("errors", 0)))
    tbl.add_row("Time:", f"{elapsed:.1f}s")
    console.print(tbl)
    console.rule()


def _parse_headers(header_list: list[str]) -> dict[str, str]:
    """Parse ``-H 'Name: Value'`` entries into a dict."""
    out: dict[str, str] = {}
    for h in header_list:
        if ":" not in h:
            _err(f"Invalid header (expected 'Name: Value'): {h!r}")
            raise typer.Exit(1)
        name, _, value = h.partition(":")
        out[name.strip()] = value.strip()
    return out


def _install_sigint(engine: DirEngine | SubEngine, loop: asyncio.AbstractEventLoop) -> None:
    """Install a cooperative SIGINT handler that calls engine.stop()."""
    original = signal.getsignal(signal.SIGINT)

    def _handler(*_: object) -> None:
        console.print("\n[bold yellow]Stopping scan...[/bold yellow]")
        engine.stop()
        # Restore original so a second Ctrl-C exits immediately
        signal.signal(signal.SIGINT, original)

    if sys.platform != "win32":
        loop.add_signal_handler(signal.SIGINT, _handler)
    else:
        signal.signal(signal.SIGINT, _handler)


def _remove_sigint(loop: asyncio.AbstractEventLoop) -> None:
    if sys.platform != "win32":
        try:
            loop.remove_signal_handler(signal.SIGINT)
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# dir command
# ---------------------------------------------------------------------------


@app.command()
def dir(  # noqa: A001 — shadowing built-in is expected for CLI naming
    url: Annotated[
        str, typer.Option("-u", "--url", help="Target URL.", show_default=False)
    ],
    wordlist: Annotated[
        str,
        typer.Option("-w", "--wordlist", help="Path to wordlist file.", show_default=False),
    ],
    threads: Annotated[
        int,
        typer.Option("-t", "--threads", help="Concurrent worker count."),
    ] = 40,
    extensions: Annotated[
        str | None,
        typer.Option("-e", "--extensions", help="Comma-separated extensions, e.g. php,txt,json."),
    ] = None,
    match_status: Annotated[
        str | None,
        typer.Option(
            "-mc", "--match-status",
            help="Show only these HTTP codes, e.g. 200,301 or 200-299.",
        ),
    ] = None,
    filter_status: Annotated[
        str | None,
        typer.Option(
            "-fc", "--filter-status",
            help="Hide these HTTP codes, e.g. 404. Takes precedence over -mc.",
        ),
    ] = None,
    header: Annotated[
        list[str] | None,
        typer.Option("-H", "--header", help="Custom header (repeatable). Format: 'Name: Value'"),
    ] = None,
    proxy: Annotated[
        str | None,
        typer.Option("-p", "--proxy", help="HTTP/HTTPS proxy URL, e.g. http://127.0.0.1:8080."),
    ] = None,
    rate: Annotated[
        float,
        typer.Option("--rate", help="Max requests per second (0 = unlimited)."),
    ] = 0.0,
    timeout: Annotated[
        float,
        # No short alias — avoids -t collision with --threads
        typer.Option("--timeout", help="Total HTTP request timeout in seconds."),
    ] = 4.0,
    follow: Annotated[
        bool,
        typer.Option("--follow", help="Follow HTTP redirects."),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("-q", "--quiet", help="Output only discovered URLs (pipe-friendly)."),
    ] = False,
    output: Annotated[
        str | None,
        typer.Option("-o", "--output", help="Write results to file (.json for JSON format)."),
    ] = None,
) -> None:
    """Fuzz directories / paths on a web server."""
    # --- validation ---
    try:
        clean_url = validate_url(url)
    except ValueError as exc:
        _err(str(exc))
        raise typer.Exit(1)

    try:
        words_iter = iter_wordlist(wordlist)
    except FileNotFoundError as exc:
        _err(str(exc))
        raise typer.Exit(1)

    ext_list = [x.strip() for x in extensions.split(",")] if extensions else []
    headers = _parse_headers(header or [])
    match_codes, filter_codes = parse_match_filter(match_status, filter_status)

    cfg = ScanConfig(
        threads=threads,
        rate=rate,
        timeout=timeout,
        quiet=quiet,
        follow_redirects=follow,
        proxy=proxy,
        headers=headers,
        extensions=ext_list,
        match_codes=match_codes,
        filter_codes=filter_codes,
    )

    if not quiet:
        _banner(
            target=clean_url,
            mode="Directory",
            threads=threads,
            wordlist=wordlist,
            extensions=ext_list or None,
        )

    # --- async runner ---
    _engine: DirEngine | None = None
    start = time.monotonic()

    async def _run() -> None:
        nonlocal _engine
        async with build_client(cfg) as client:
            _engine = DirEngine(clean_url, words_iter, cfg, client)
            loop = asyncio.get_running_loop()
            _install_sigint(_engine, loop)
            try:
                results = await _engine.run()
            finally:
                _remove_sigint(loop)

        elapsed = time.monotonic() - start
        _summary(_engine.stats(), elapsed, quiet=quiet)

        if output:
            save_json(
                output,
                {
                    "target": clean_url,
                    "mode": "directory",
                    "results": [r.to_dict() for r in results],
                },
            )

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        elapsed = time.monotonic() - start
        console.print("\n[bold yellow]Stopping scan...[/bold yellow]")
        if _engine:
            _summary(_engine.stats(), elapsed, quiet=quiet)
        console.print("[dim]Goodbye.[/dim]")
    except Exception as exc:  # noqa: BLE001
        if _DEBUG:
            raise
        _err(str(exc))
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# sub command
# ---------------------------------------------------------------------------


@app.command()
def sub(
    domain: Annotated[
        str, typer.Option("-d", "--domain", help="Target domain, e.g. example.com.", show_default=False)
    ],
    wordlist: Annotated[
        str,
        typer.Option("-w", "--wordlist", help="Path to wordlist file.", show_default=False),
    ],
    threads: Annotated[
        int,
        typer.Option("-t", "--threads", help="Concurrent worker count."),
    ] = 40,
    header: Annotated[
        list[str] | None,
        typer.Option("-H", "--header", help="Custom header (repeatable). Format: 'Name: Value'"),
    ] = None,
    proxy: Annotated[
        str | None,
        typer.Option("-p", "--proxy", help="HTTP/HTTPS proxy URL, e.g. http://127.0.0.1:8080."),
    ] = None,
    rate: Annotated[
        float,
        typer.Option("--rate", help="Max requests per second (0 = unlimited)."),
    ] = 0.0,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Total HTTP request timeout in seconds."),
    ] = 4.0,
    follow: Annotated[
        bool,
        typer.Option("--follow", help="Follow HTTP redirects."),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("-q", "--quiet", help="Output only discovered hostnames/URLs (pipe-friendly)."),
    ] = False,
    output: Annotated[
        str | None,
        typer.Option("-o", "--output", help="Write results to file (.json for JSON format)."),
    ] = None,
) -> None:
    """Fuzz subdomains via async DNS resolution + HTTP probing."""
    if not domain or "." not in domain:
        _err(f"Invalid domain: {domain!r}")
        raise typer.Exit(1)

    try:
        words_iter = iter_wordlist(wordlist)
    except FileNotFoundError as exc:
        _err(str(exc))
        raise typer.Exit(1)

    headers = _parse_headers(header or [])

    cfg = ScanConfig(
        threads=threads,
        rate=rate,
        timeout=timeout,
        quiet=quiet,
        follow_redirects=follow,
        proxy=proxy,
        headers=headers,
    )

    if not quiet:
        _banner(target=domain, mode="Subdomain", threads=threads, wordlist=wordlist)

    _engine: SubEngine | None = None
    start = time.monotonic()

    async def _run() -> None:
        nonlocal _engine
        async with build_client(cfg) as client:
            _engine = SubEngine(domain, words_iter, cfg, client)
            loop = asyncio.get_running_loop()
            _install_sigint(_engine, loop)
            try:
                results = await _engine.run()
            finally:
                _remove_sigint(loop)

        elapsed = time.monotonic() - start
        _summary(_engine.stats(), elapsed, quiet=quiet)

        if output:
            save_json(
                output,
                {
                    "target": domain,
                    "mode": "subdomain",
                    "results": [r.to_dict() for r in results],
                },
            )

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        elapsed = time.monotonic() - start
        console.print("\n[bold yellow]Stopping scan...[/bold yellow]")
        if _engine:
            _summary(_engine.stats(), elapsed, quiet=quiet)
        console.print("[dim]Goodbye.[/dim]")
    except Exception as exc:  # noqa: BLE001
        if _DEBUG:
            raise
        _err(str(exc))
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
