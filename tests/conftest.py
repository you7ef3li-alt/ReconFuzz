"""Test configuration and shared fixtures for ReconFuzz tests."""

from __future__ import annotations

import pytest


@pytest.fixture
def sample_wordlist(tmp_path):
    """Create a small temporary wordlist file."""
    wl = tmp_path / "words.txt"
    wl.write_text(
        "admin\n"
        "api\n"
        "# comment\n"
        "\n"
        "login\n"
        "admin\n"  # duplicate
        "backup\n",
        encoding="utf-8",
    )
    return str(wl)
