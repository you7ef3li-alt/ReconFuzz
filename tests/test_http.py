"""Tests for HTTP response parsing and URL normalization."""

from __future__ import annotations

import pytest

from reconfuzz.utils import build_dir_urls, load_wordlist, validate_url


class TestValidateUrl:
    def test_valid_https(self):
        assert validate_url("https://example.com") == "https://example.com"

    def test_valid_http(self):
        assert validate_url("http://example.com") == "http://example.com"

    def test_trailing_slash_stripped(self):
        assert validate_url("https://example.com/") == "https://example.com"

    def test_multiple_trailing_slashes(self):
        assert validate_url("https://example.com///") == "https://example.com"

    def test_invalid_no_scheme(self):
        with pytest.raises(ValueError):
            validate_url("example.com")

    def test_invalid_scheme(self):
        with pytest.raises(ValueError):
            validate_url("ftp://example.com")

    def test_invalid_no_host(self):
        with pytest.raises(ValueError):
            validate_url("https://")


class TestBuildDirUrls:
    def test_no_extensions(self):
        urls = build_dir_urls("https://example.com", "admin", [])
        assert urls == ["https://example.com/admin"]

    def test_with_extensions(self):
        urls = build_dir_urls("https://example.com", "admin", ["php", "txt"])
        assert "https://example.com/admin" in urls
        assert "https://example.com/admin.php" in urls
        assert "https://example.com/admin.txt" in urls

    def test_no_duplicates(self):
        urls = build_dir_urls("https://example.com", "admin", ["php", "php"])
        assert len(urls) == len(set(urls))

    def test_base_url_trailing_slash(self):
        urls = build_dir_urls("https://example.com/", "admin", [])
        assert urls[0] == "https://example.com/admin"


class TestLoadWordlist:
    def test_basic(self, sample_wordlist):
        words = load_wordlist(sample_wordlist)
        assert "admin" in words
        assert "api" in words
        assert "login" in words
        assert "backup" in words

    def test_ignores_comments(self, sample_wordlist):
        words = load_wordlist(sample_wordlist)
        assert not any(w.startswith("#") for w in words)

    def test_ignores_empty_lines(self, sample_wordlist):
        words = load_wordlist(sample_wordlist)
        assert "" not in words

    def test_deduplication(self, sample_wordlist):
        words = load_wordlist(sample_wordlist)
        assert words.count("admin") == 1

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_wordlist("/nonexistent/path/wordlist.txt")
