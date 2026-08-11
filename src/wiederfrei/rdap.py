"""Tier 2: authoritative availability via RDAP.

Switch documents ``HEAD`` on ``/domain/<name>`` as the supported way to test whether a
name is registered without retrieving registration data: ``200`` registered, ``404`` not
registered. Only ``404`` is ever read as "available" -- every other outcome resolves to
registered or unknown, so a throttled or broken run can never produce a false alert.

Defaults here are deliberately conservative. Availability mining is exactly the traffic
pattern registries throttle, so the client paces itself, honours ``429``, and identifies
itself in the ``User-Agent``.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from enum import StrEnum

import httpx

from .candidates import Candidate
from .config import RdapConfig

logger = logging.getLogger(__name__)

#: HTTP statuses that prove the name exists. Switch returns 401 for a registered name
#: whose registration data an anonymous caller may not see -- that is still "registered".
REGISTERED_STATUSES = frozenset({200, 401, 403})
MAX_RETRY_AFTER = 300.0


class RdapStatus(StrEnum):
    REGISTERED = "registered"
    AVAILABLE = "available"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class RdapResult:
    candidate: Candidate
    status: RdapStatus
    http_status: int | None = None
    detail: str = ""


class TokenBucket:
    """Paces outbound requests to a steady rate, shared across concurrent callers."""

    def __init__(self, rate_per_second: float, capacity: float | None = None) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be greater than 0")
        self.rate = rate_per_second
        self.capacity = capacity if capacity is not None else max(rate_per_second, 1.0)
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._updated) * self.rate
                )
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self.rate
            await asyncio.sleep(wait)

    async def penalise(self, seconds: float) -> None:
        """Drain the bucket after a 429 so concurrent callers also back off."""
        async with self._lock:
            self._tokens = 0.0
            self._updated = time.monotonic() + max(0.0, seconds)


def parse_retry_after(value: str | None) -> float | None:
    """Parse a ``Retry-After`` header, in either delta-seconds or HTTP-date form."""
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    import datetime as _dt

    now = _dt.datetime.now(_dt.timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=_dt.timezone.utc)
    return max(0.0, (when - now).total_seconds())


class RdapClient:
    """Rate-limited RDAP availability checks."""

    def __init__(
        self,
        cfg: RdapConfig,
        *,
        client: httpx.AsyncClient | None = None,
        concurrency: int = 4,
    ) -> None:
        self.cfg = cfg
        self._bucket = TokenBucket(cfg.rate_limit_per_second)
        self._sem = asyncio.Semaphore(max(1, concurrency))
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=cfg.timeout,
            headers={"User-Agent": cfg.user_agent(), "Accept": "application/rdap+json"},
            follow_redirects=True,
        )
        self.calls_made = 0

    async def __aenter__(self) -> RdapClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def url_for(self, candidate: Candidate) -> str:
        return f"{self.cfg.endpoint_for(candidate.tld)}/domain/{candidate.domain}"

    async def check(self, candidate: Candidate) -> RdapResult:
        """Resolve one candidate's registration status, retrying transient failures."""
        url = self.url_for(candidate)
        last_detail = ""

        for attempt in range(self.cfg.max_retries + 1):
            async with self._sem:
                await self._bucket.acquire()
                try:
                    self.calls_made += 1
                    response = await self._client.head(url)
                except httpx.HTTPError as exc:
                    last_detail = f"{type(exc).__name__}: {exc}"
                    response = None

            if response is not None:
                code = response.status_code
                if code == 404:
                    return RdapResult(candidate, RdapStatus.AVAILABLE, code)
                if code in REGISTERED_STATUSES:
                    return RdapResult(candidate, RdapStatus.REGISTERED, code)
                if code == 429:
                    delay = parse_retry_after(response.headers.get("Retry-After"))
                    if delay is None:
                        delay = self._backoff(attempt)
                    delay = min(delay, MAX_RETRY_AFTER)
                    logger.warning(
                        "RDAP rate-limited on %s; backing off %.1fs", candidate.domain, delay
                    )
                    await self._bucket.penalise(delay)
                    last_detail = "HTTP 429"
                    await asyncio.sleep(delay)
                    continue
                if 500 <= code < 600:
                    last_detail = f"HTTP {code}"
                else:
                    # An unexpected 4xx is not a transient fault; do not keep hammering.
                    return RdapResult(
                        candidate, RdapStatus.UNKNOWN, code, f"unexpected HTTP {code}"
                    )

            if attempt < self.cfg.max_retries:
                await asyncio.sleep(self._backoff(attempt))

        return RdapResult(candidate, RdapStatus.UNKNOWN, None, last_detail or "retries exhausted")

    @staticmethod
    def _backoff(attempt: int) -> float:
        return min(2.0 ** attempt, 30.0) + random.uniform(0.0, 0.5)

    async def check_many(self, candidates: Sequence[Candidate] | Iterable[Candidate]) -> list[RdapResult]:
        """Check a batch concurrently; the token bucket still paces the whole batch."""
        items = list(candidates)
        if not items:
            return []
        return list(await asyncio.gather(*(self.check(c) for c in items)))
