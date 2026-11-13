# ReconFuzz

**ReconFuzz** is a lightweight, asynchronous command-line tool for authorized web directory and subdomain discovery. It probes wordlists and reports useful HTTP/DNS findings in a readable terminal view, with optional JSON output.

> Use ReconFuzz only on systems you own or have explicit permission to assess. Follow the target's scope, rate limits, and applicable laws.

## Features

- Directory and path discovery over HTTP(S)
- Subdomain discovery with DNS resolution and HTTP probing
- Concurrent requests with configurable worker count and rate limit
- HTTP status, response size, elapsed time, and redirect information
- Smart filtering for common not-found responses and configurable status codes
- Optional extensions, custom headers, proxy, and JSON output
- Bundled starter wordlists in `wordlists/`

## Requirements

- Python 3.12 or newer
- Windows, macOS, or Linux

## Open and run in VS Code (Windows)

1. Open this folder in VS Code.
2. Install the recommended **Python** extension if prompted.
3. In the integrated PowerShell terminal, create and activate a virtual environment:

   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

4. Install ReconFuzz and its dependencies:

   ```powershell
   python -m pip install --upgrade pip
   python -m pip install -e .
   ```

5. Run a command against an authorized target:

   ```powershell
   reconfuzz --help
   reconfuzz dir -u https://example.com -w .\wordlists\common.txt
   reconfuzz sub -d example.com -w .\wordlists\subdomains.txt
   ```

If PowerShell does not recognize `py`, install Python 3.12+ and enable the Python launcher, or use `python` in the virtual-environment setup command.

## Usage

### Directory discovery

```text
reconfuzz dir -u https://example.com -w .\wordlists\common.txt
```

Add extensions, select status codes, or save results as JSON:

```text
reconfuzz dir -u https://example.com -w .\wordlists\common.txt -e php,txt,json -mc 200,301,403 -o results.json
```

### Subdomain discovery

```text
reconfuzz sub -d example.com -w .\wordlists\subdomains.txt -t 40
```

### Useful options

- `-t`, `--threads`: concurrent worker count (default: 40)
- `--rate`: maximum requests per second (0 means unlimited)
- `--timeout`: request timeout in seconds (default: 4)
- `-mc`, `--match-status`: show selected status codes or ranges
- `-fc`, `--filter-status`: hide selected status codes
- `-H`, `--header`: add a request header; repeat for multiple headers
- `-p`, `--proxy`: use an HTTP/HTTPS proxy
- `--follow`: follow HTTP redirects
- `-o`, `--output`: write results to a file; `.json` output is supported
- `-q`, `--quiet`: print only discovered URLs/hosts

Run `reconfuzz dir --help` or `reconfuzz sub --help` for all options.

## Development

Install development dependencies and run the test suite:

```powershell
python -m pip install -e ".[dev]"
python -m pytest
```

## License

This project is distributed under the MIT License. See [LICENSE](LICENSE).
