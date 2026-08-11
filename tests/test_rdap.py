import asyncio
import time

import httpx
import pytest
import respx

from wiederfrei.candidates import Candidate
from wiederfrei.config import RdapConfig
from wiederfrei.rdap import RdapClient, RdapStatus, TokenBucket, parse_retry_after

CANDIDATE = Candidate("abc.ch", "abc", "ch")
URL = "https://rdap.nic.ch/domain/abc.ch"


def make_cfg(**kw) -> RdapConfig:
    defaults = dict(rate_limit_per_second=1000.0, max_retries=2, timeout=5.0)
    defaults.update(kw)
    return RdapConfig(**defaults)


@respx.mock
async def test_404_means_available():
    respx.head(URL).mock(return_value=httpx.Response(404))
    async with RdapClient(make_cfg()) as client:
        result = await client.check(CANDIDATE)
    assert result.status is RdapStatus.AVAILABLE
    assert result.http_status == 404


@respx.mock
async def test_200_means_registered():
    respx.head(URL).mock(return_value=httpx.Response(200))
    async with RdapClient(make_cfg()) as client:
        result = await client.check(CANDIDATE)
    assert result.status is RdapStatus.REGISTERED


@respx.mock
@pytest.mark.parametrize("code", [401, 403])
async def test_auth_codes_mean_registered_not_available(code):
    """Switch answers 401 for a registered name an anonymous caller may not fully see.

    Reading that as "available" would be a false alert, which is the one outcome the
    design must never produce.
    """
    respx.head(URL).mock(return_value=httpx.Response(code))
    async with RdapClient(make_cfg()) as client:
        result = await client.check(CANDIDATE)
    assert result.status is RdapStatus.REGISTERED


@respx.mock
async def test_429_is_retried_and_then_succeeds():
    route = respx.head(URL).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(404),
        ]
    )
    async with RdapClient(make_cfg()) as client:
        result = await client.check(CANDIDATE)
    assert route.call_count == 2
    assert result.status is RdapStatus.AVAILABLE


@respx.mock
async def test_persistent_429_ends_unknown_never_available():
    respx.head(URL).mock(return_value=httpx.Response(429, headers={"Retry-After": "0"}))
    async with RdapClient(make_cfg(max_retries=1)) as client:
        result = await client.check(CANDIDATE)
    assert result.status is RdapStatus.UNKNOWN


@respx.mock
async def test_server_error_retried_then_unknown():
    route = respx.head(URL).mock(return_value=httpx.Response(503))
    async with RdapClient(make_cfg(max_retries=2)) as client:
        result = await client.check(CANDIDATE)
    assert route.call_count == 3
    assert result.status is RdapStatus.UNKNOWN


@respx.mock
async def test_unexpected_4xx_is_not_retried():
    route = respx.head(URL).mock(return_value=httpx.Response(418))
    async with RdapClient(make_cfg(max_retries=3)) as client:
        result = await client.check(CANDIDATE)
    assert route.call_count == 1
    assert result.status is RdapStatus.UNKNOWN


@respx.mock
async def test_network_error_becomes_unknown():
    respx.head(URL).mock(side_effect=httpx.ConnectError("boom"))
    async with RdapClient(make_cfg(max_retries=1)) as client:
        result = await client.check(CANDIDATE)
    assert result.status is RdapStatus.UNKNOWN
    assert "ConnectError" in result.detail


@respx.mock
async def test_user_agent_identifies_tool_and_contact():
    captured = {}

    def handler(request):
        captured["ua"] = request.headers["User-Agent"]
        return httpx.Response(404)

    respx.head(URL).mock(side_effect=handler)
    async with RdapClient(make_cfg(contact="me@example.com")) as client:
        await client.check(CANDIDATE)
    assert "wiederfrei/" in captured["ua"]
    assert "me@example.com" in captured["ua"]


@respx.mock
async def test_check_many_returns_one_result_per_candidate():
    respx.head(host="rdap.nic.ch").mock(return_value=httpx.Response(404))
    cands = [Candidate(f"ab{i}.ch", f"ab{i}", "ch") for i in range(5)]
    async with RdapClient(make_cfg()) as client:
        results = await client.check_many(cands)
    assert len(results) == 5
    assert {r.candidate.domain for r in results} == {c.domain for c in cands}


async def test_check_many_empty_makes_no_calls():
    async with RdapClient(make_cfg()) as client:
        assert await client.check_many([]) == []
        assert client.calls_made == 0


class TestTokenBucket:
    async def test_paces_requests_to_the_configured_rate(self):
        bucket = TokenBucket(rate_per_second=20.0, capacity=1.0)
        start = time.monotonic()
        for _ in range(4):
            await bucket.acquire()
        # 1 token banked, 3 more at 20/s = ~0.15s. Generous lower bound for CI jitter.
        assert time.monotonic() - start >= 0.10

    async def test_rejects_non_positive_rate(self):
        with pytest.raises(ValueError):
            TokenBucket(0)

    async def test_concurrent_callers_share_the_budget(self):
        bucket = TokenBucket(rate_per_second=50.0, capacity=1.0)
        start = time.monotonic()
        await asyncio.gather(*(bucket.acquire() for _ in range(5)))
        assert time.monotonic() - start >= 0.06


class TestRetryAfter:
    def test_delta_seconds(self):
        assert parse_retry_after("12") == 12.0

    def test_http_date(self):
        assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0

    def test_missing_and_garbage(self):
        assert parse_retry_after(None) is None
        assert parse_retry_after("soon") is None


def test_url_construction_uses_configured_endpoint():
    cfg = make_cfg(endpoints={"ch": "https://rdap.example.test/"})
    client = RdapClient(cfg)
    assert client.url_for(CANDIDATE) == "https://rdap.example.test/domain/abc.ch"
