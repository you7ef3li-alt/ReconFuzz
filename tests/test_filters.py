"""Tests for status filtering, smart 404 baseline, and soft-404 detection."""

from __future__ import annotations

from reconfuzz.filters import (
    Baseline404,
    _parse_status_list,
    should_display,
)
from reconfuzz.http_client import HTTPResponse


def _make_resp(status: int, size: int, body_hash: int = 0) -> HTTPResponse:
    return HTTPResponse(
        url="https://example.com/test",
        status=status,
        size=size,
        response_time_ms=50.0,
        redirect=None,
        body_hash=body_hash,
        body_bytes=size,
    )


class TestParseStatusList:
    def test_single(self):
        assert _parse_status_list("200") == {200}

    def test_multiple(self):
        assert _parse_status_list("200,301,404") == {200, 301, 404}

    def test_range(self):
        result = _parse_status_list("200-202")
        assert result == {200, 201, 202}

    def test_mixed(self):
        result = _parse_status_list("200-202,404,500")
        assert 200 in result
        assert 201 in result
        assert 404 in result
        assert 500 in result

    def test_invalid_ignored(self):
        result = _parse_status_list("abc,200")
        assert result == {200}


class TestShouldDisplay:
    def test_no_filters(self):
        assert should_display(200, match_codes=None, filter_codes=None) is True
        assert should_display(404, match_codes=None, filter_codes=None) is True

    def test_match_codes_allows(self):
        assert should_display(200, match_codes={200, 301}, filter_codes=None) is True

    def test_match_codes_rejects(self):
        assert should_display(404, match_codes={200, 301}, filter_codes=None) is False

    def test_filter_codes_rejects(self):
        assert should_display(404, match_codes=None, filter_codes={404}) is False

    def test_filter_takes_priority_over_match(self):
        # -fc wins even when -mc would match
        assert should_display(200, match_codes={200}, filter_codes={200}) is False

    def test_filter_code_allows_others(self):
        assert should_display(200, match_codes=None, filter_codes={404}) is True


class TestBaseline404:
    def test_not_established_never_filters(self):
        baseline = Baseline404()
        resp = _make_resp(404, 1532)
        assert baseline.is_404(resp) is False

    def test_hard_404_match_exact_size(self):
        baseline = Baseline404()
        baseline.status = 404
        baseline.sizes = [1532]
        baseline.body_hashes = set()
        baseline._established = True

        resp = _make_resp(404, 1532)
        assert baseline.is_404(resp) is True

    def test_hard_404_match_within_5pct_variance(self):
        """Size within ±5% of baseline should be filtered."""
        baseline = Baseline404()
        baseline.status = 404
        baseline.sizes = [1000]
        baseline.body_hashes = set()
        baseline._established = True

        # 1045 is 4.5% above 1000 — within 5% tolerance
        resp = _make_resp(404, 1045)
        assert baseline.is_404(resp) is True

    def test_hard_404_outside_5pct_variance(self):
        """Size >5% different from baseline should NOT be filtered."""
        baseline = Baseline404()
        baseline.status = 404
        baseline.sizes = [1000]
        baseline.body_hashes = set()
        baseline._established = True

        # 1100 is 10% above 1000 — outside 5% tolerance
        resp = _make_resp(404, 1100)
        assert baseline.is_404(resp) is False

    def test_hard_404_different_status_not_filtered(self):
        baseline = Baseline404()
        baseline.status = 404
        baseline.sizes = [1532]
        baseline.body_hashes = set()
        baseline._established = True

        resp = _make_resp(200, 1532)  # size matches but status differs
        assert baseline.is_404(resp) is False

    def test_soft_404_via_body_hash(self):
        """Status 200 but body hash matches baseline → soft-404."""
        baseline = Baseline404()
        baseline.status = 404
        baseline.sizes = [512]
        baseline.body_hashes = {12345}
        baseline._established = True

        resp = _make_resp(200, 999, body_hash=12345)
        assert baseline.is_404(resp) is True

    def test_different_body_not_filtered(self):
        baseline = Baseline404()
        baseline.status = 404
        baseline.sizes = [1532]
        baseline.body_hashes = {12345}
        baseline._established = True

        resp = _make_resp(200, 999, body_hash=99999)
        assert baseline.is_404(resp) is False
