"""Tier 1: the cheap DNS ``NS`` sweep.

Presence of an ``NS`` RRset proves a name is registered, so the sweep exists purely to
rule candidates *out*. Absence proves nothing -- a name can be registered without being
delegated -- so a negative result is only ever a referral to the RDAP tier, never an
availability claim.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from .candidates import Candidate
from .config import DnsConfig

logger = logging.getLogger(__name__)


class NsStatus(StrEnum):
    DELEGATED = "delegated"           # has NS -> definitely registered
    NO_DELEGATION = "no_delegation"   # no NS -> needs RDAP to decide
    UNKNOWN = "unknown"               # lookup failed -> retry next run, never alert


@dataclass(slots=True)
class SweepStats:
    checked: int = 0
    delegated: int = 0
    no_delegation: int = 0
    unknown: int = 0

    def record(self, status: NsStatus) -> None:
        self.checked += 1
        if status is NsStatus.DELEGATED:
            self.delegated += 1
        elif status is NsStatus.NO_DELEGATION:
            self.no_delegation += 1
        else:
            self.unknown += 1


@dataclass(slots=True)
class NsProbe:
    """Bounded-concurrency ``NS`` lookups against the configured resolvers."""

    cfg: DnsConfig
    _resolver: dns.asyncresolver.Resolver = field(init=False)
    _sem: asyncio.Semaphore = field(init=False)

    def __post_init__(self) -> None:
        self._resolver = dns.asyncresolver.Resolver(configure=not self.cfg.resolvers)
        if self.cfg.resolvers:
            self._resolver.nameservers = list(self.cfg.resolvers)
        self._resolver.timeout = self.cfg.timeout
        self._resolver.lifetime = self.cfg.lifetime
        self._sem = asyncio.Semaphore(self.cfg.concurrency)

    async def status(self, domain: str) -> NsStatus:
        """Resolve one name's ``NS`` RRset."""
        async with self._sem:
            try:
                answer = await self._resolver.resolve(domain, dns.rdatatype.NS)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                # Not in the TLD zone, or in it with no NS records. Either way the DNS
                # tier cannot rule this candidate out.
                return NsStatus.NO_DELEGATION
            except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
                return NsStatus.UNKNOWN
            except dns.exception.DNSException as exc:
                logger.debug("NS lookup failed for %s: %s", domain, exc)
                return NsStatus.UNKNOWN
            return NsStatus.DELEGATED if len(answer) else NsStatus.NO_DELEGATION

    async def sweep(
        self,
        candidates: Iterable[Candidate],
        *,
        on_batch: Callable[[list[tuple[Candidate, NsStatus]]], None] | None = None,
        progress_every: int = 25_000,
    ) -> SweepStats:
        """Resolve every candidate, handing results to ``on_batch`` as they complete.

        Results are streamed in batches rather than returned as one list: a full 3-4
        character sweep is 1.7M names, which should be committed to state incrementally
        so an interrupted run keeps its progress.
        """
        stats = SweepStats()
        chunk_size = max(self.cfg.concurrency * 8, 1)
        next_report = progress_every

        for chunk in _chunked(candidates, chunk_size):
            statuses = await asyncio.gather(*(self.status(c.domain) for c in chunk))
            batch = list(zip(chunk, statuses, strict=True))
            for _, status in batch:
                stats.record(status)
            if on_batch is not None:
                on_batch(batch)
            if stats.checked >= next_report:
                logger.info(
                    "DNS sweep: %d checked (%d delegated, %d without delegation, %d unknown)",
                    stats.checked, stats.delegated, stats.no_delegation, stats.unknown,
                )
                next_report = stats.checked + progress_every

        return stats


def _chunked(items: Iterable[Candidate], size: int) -> Iterator[list[Candidate]]:
    iterator = iter(items)
    while chunk := list(itertools.islice(iterator, size)):
        yield chunk
