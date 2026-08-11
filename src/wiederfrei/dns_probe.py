"""Tier 1: the cheap DNS ``NS`` sweep.

Presence of an ``NS`` RRset proves a name is registered, so the sweep exists purely to
rule candidates *out*. Absence proves nothing -- a name can be registered without being
delegated -- so a negative result is only ever a referral to the RDAP tier, never an
availability claim.

Two probes implement the same interface:

* :class:`AuthoritativeNsProbe` (default) asks the TLD's own nameservers directly.
* :class:`NsProbe` goes through a recursive resolver.

Authoritative is the default because a resolver cache cannot help here. The sweep asks
about ~1.7M *unique* names, so essentially every query is a cache miss and pays a full
recursion down to the same TLD servers we could have asked in the first place. Going
direct removes a round trip per name without increasing the load those servers see.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum

import dns.asyncquery
import dns.asyncresolver
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.resolver

from .candidates import Candidate
from .config import DnsConfig
from .rdap import TokenBucket

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


class _ProbeBase:
    """Shared sweep driver. Subclasses provide ``cfg`` and ``status()``."""

    cfg: DnsConfig

    async def status(self, domain: str) -> NsStatus:  # pragma: no cover - interface
        raise NotImplementedError

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


@dataclass
class NsProbe(_ProbeBase):
    """Bounded-concurrency ``NS`` lookups through a recursive resolver."""

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


def interpret_authoritative(response: dns.message.Message, qname: dns.name.Name) -> NsStatus:
    """Read a TLD server's answer to an ``NS`` query for one of its children.

    An authoritative server does not follow a delegation, it *reports* one, so the
    signal lives in the authority section rather than the answer section:

    ============================================  ==================
    Response                                      Verdict
    ============================================  ==================
    ``NOERROR`` + ``NS`` for qname (a referral)   ``DELEGATED``
    ``NXDOMAIN``                                  ``NO_DELEGATION``
    ``NOERROR``, no ``NS`` for qname (NODATA)     ``NO_DELEGATION``
    any other rcode                               ``UNKNOWN``
    ============================================  ==================

    The ``rrset.name == qname`` check is what separates a referral from NODATA: a NODATA
    answer carries the *zone's* SOA (and sometimes its NS), not the queried name's.
    """
    rcode = response.rcode()
    if rcode == dns.rcode.NXDOMAIN:
        return NsStatus.NO_DELEGATION
    if rcode != dns.rcode.NOERROR:
        return NsStatus.UNKNOWN

    for section in (response.answer, response.authority):
        for rrset in section:
            if rrset.rdtype == dns.rdatatype.NS and rrset.name == qname and len(rrset):
                return NsStatus.DELEGATED
    return NsStatus.NO_DELEGATION


@dataclass
class AuthoritativeNsProbe(_ProbeBase):
    """``NS`` lookups sent straight to the TLD's own nameservers.

    Removes the recursion that dominates a large sweep. Server addresses are discovered
    once per TLD on first use, then queries are spread round-robin across them under a
    shared queries-per-second budget.
    """

    cfg: DnsConfig
    _sem: asyncio.Semaphore = field(init=False)
    _bucket: TokenBucket = field(init=False)
    _servers: dict[str, list[str]] = field(init=False, default_factory=dict)
    _discovery: asyncio.Lock = field(init=False)
    _next: int = field(init=False, default=0)
    _fallback: NsProbe | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        self._sem = asyncio.Semaphore(self.cfg.concurrency)
        self._bucket = TokenBucket(self.cfg.qps)
        self._servers = {}
        self._discovery = asyncio.Lock()
        self._fallback = None

    async def is_authoritative(self, server: str, tld: str) -> bool:
        """Check that ``server`` really is the TLD's authority and not a resolver.

        Some networks transparently intercept UDP/53 and answer everything from their
        own recursive resolver. Such a resolver returns ``SERVFAIL`` to the ``RD=0``
        queries this probe sends, which would turn an entire sweep into ``UNKNOWN``
        with no obvious cause. A real authority answers its own apex with ``AA=1`` and
        never sets ``RA``; an interceptor does the opposite.
        """
        query = dns.message.make_query(f"{tld}.", dns.rdatatype.NS, use_edns=0)
        query.flags &= ~dns.flags.RD
        try:
            response = await dns.asyncquery.udp(query, server, timeout=self.cfg.timeout)
        except dns.exception.DNSException as exc:
            logger.debug("Preflight to %s failed: %s", server, exc)
            return False
        return bool(response.flags & dns.flags.AA)

    async def servers_for(self, tld: str) -> list[str]:
        """Addresses of the TLD's authoritative servers, discovered once and cached."""
        if tld in self._servers:
            return self._servers[tld]

        async with self._discovery:
            if tld in self._servers:      # another task won the race
                return self._servers[tld]

            if self.cfg.nameservers:
                addresses = list(self.cfg.nameservers)
            else:
                resolver = dns.asyncresolver.Resolver(configure=not self.cfg.resolvers)
                if self.cfg.resolvers:
                    resolver.nameservers = list(self.cfg.resolvers)
                resolver.timeout = self.cfg.timeout
                resolver.lifetime = self.cfg.lifetime

                addresses = []
                ns_answer = await resolver.resolve(f"{tld}.", dns.rdatatype.NS)
                for rdata in ns_answer:
                    host = str(rdata.target).rstrip(".")
                    try:
                        a_answer = await resolver.resolve(host, dns.rdatatype.A)
                    except dns.exception.DNSException as exc:
                        logger.debug("Could not resolve %s: %s", host, exc)
                        continue
                    addresses.extend(str(r.address) for r in a_answer)

            if not addresses:
                raise dns.exception.DNSException(
                    f"could not discover any authoritative server for .{tld}"
                )

            if not await self.is_authoritative(addresses[0], tld):
                logger.error(
                    "DNS interception detected: %s answered for .%s without the "
                    "authoritative flag, so RD=0 queries are being served by a recursive "
                    "resolver. Falling back to recursive mode -- results stay correct but "
                    "the sweep will be slower. Set dns.mode: recursive to silence this, "
                    "or run somewhere UDP/53 is not intercepted.",
                    addresses[0], tld,
                )
                self._fallback = NsProbe(self.cfg)
                self._servers[tld] = addresses
                return addresses

            logger.info(
                "Discovered %d authoritative server(s) for .%s", len(addresses), tld
            )
            self._servers[tld] = addresses
            return addresses

    async def status(self, domain: str) -> NsStatus:
        tld = domain.rsplit(".", 1)[-1]
        try:
            await self.servers_for(tld)
        except dns.exception.DNSException as exc:
            logger.warning("Authoritative server discovery failed for .%s: %s", tld, exc)
            return NsStatus.UNKNOWN

        if self._fallback is not None:
            return await self._fallback.status(domain)

        servers = self._servers[tld]

        qname = dns.name.from_text(domain)
        query = dns.message.make_query(qname, dns.rdatatype.NS, use_edns=0)
        # No recursion desired: we are talking to the authority, not a resolver.
        query.flags &= ~dns.flags.RD

        # Retry on a *different* server, so one sick instance does not strand a name
        # in UNKNOWN and cost it a whole extra sweep.
        for attempt in range(self.cfg.max_retries + 1):
            server = servers[self._next % len(servers)]
            self._next += 1

            async with self._sem:
                await self._bucket.acquire()
                try:
                    response = await dns.asyncquery.udp(
                        query, server, timeout=self.cfg.timeout
                    )
                    if response.flags & dns.flags.TC:
                        response = await dns.asyncquery.tcp(
                            query, server, timeout=self.cfg.timeout
                        )
                except dns.exception.DNSException as exc:
                    logger.debug("NS query to %s for %s failed: %s", server, domain, exc)
                    continue

            status = interpret_authoritative(response, qname)
            if status is not NsStatus.UNKNOWN or attempt == self.cfg.max_retries:
                return status

        return NsStatus.UNKNOWN


def build_probe(cfg: DnsConfig) -> _ProbeBase:
    """Select the probe named by ``dns.mode``."""
    if cfg.mode == "recursive":
        return NsProbe(cfg)
    return AuthoritativeNsProbe(cfg)


def _chunked(items: Iterable[Candidate], size: int) -> Iterator[list[Candidate]]:
    iterator = iter(items)
    while chunk := list(itertools.islice(iterator, size)):
        yield chunk
