import dns.exception
import dns.resolver
import pytest

from wiederfrei.candidates import Candidate
from wiederfrei.config import DnsConfig
from wiederfrei.dns_probe import NsProbe, NsStatus, SweepStats


def cand(name: str) -> Candidate:
    return Candidate(f"{name}.ch", name, "ch")


@pytest.fixture()
def probe():
    return NsProbe(DnsConfig(concurrency=4, timeout=0.1, lifetime=0.2))


class TestStatusMapping:
    async def test_answer_means_delegated(self, probe, monkeypatch):
        async def resolve(*a, **kw):
            return ["ns1.example.ch."]

        monkeypatch.setattr(probe._resolver, "resolve", resolve)
        assert await probe.status("abc.ch") is NsStatus.DELEGATED

    @pytest.mark.parametrize(
        "exc", [dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()]
    )
    async def test_nxdomain_and_noanswer_mean_no_delegation(self, probe, monkeypatch, exc):
        async def resolve(*a, **kw):
            raise exc

        monkeypatch.setattr(probe._resolver, "resolve", resolve)
        assert await probe.status("abc.ch") is NsStatus.NO_DELEGATION

    @pytest.mark.parametrize(
        "exc", [dns.exception.Timeout(), dns.resolver.NoNameservers()]
    )
    async def test_transient_failures_are_unknown_not_available(self, probe, monkeypatch, exc):
        """An unreachable resolver must never look like an available domain."""
        async def resolve(*a, **kw):
            raise exc

        monkeypatch.setattr(probe._resolver, "resolve", resolve)
        assert await probe.status("abc.ch") is NsStatus.UNKNOWN

    async def test_empty_answer_is_no_delegation(self, probe, monkeypatch):
        async def resolve(*a, **kw):
            return []

        monkeypatch.setattr(probe._resolver, "resolve", resolve)
        assert await probe.status("abc.ch") is NsStatus.NO_DELEGATION


class TestSweep:
    async def test_visits_every_candidate_and_batches_results(self, probe, monkeypatch):
        async def status(self, domain):
            return NsStatus.DELEGATED if domain.startswith("a") else NsStatus.NO_DELEGATION

        monkeypatch.setattr(NsProbe, "status", status)
        seen = []
        candidates = [cand("aa"), cand("bb"), cand("ac")]

        stats = await probe.sweep(candidates, on_batch=seen.append)

        assert stats.checked == 3
        assert stats.delegated == 2
        assert stats.no_delegation == 1
        assert sum(len(b) for b in seen) == 3

    async def test_empty_input(self, probe):
        stats = await probe.sweep([])
        assert stats.checked == 0

    async def test_batches_are_candidate_status_pairs(self, probe, monkeypatch):
        async def status(self, domain):
            return NsStatus.DELEGATED

        monkeypatch.setattr(NsProbe, "status", status)
        batches = []
        await probe.sweep([cand("aa")], on_batch=batches.append)
        candidate, ns_status = batches[0][0]
        assert candidate.domain == "aa.ch"
        assert ns_status is NsStatus.DELEGATED


def test_stats_tally():
    stats = SweepStats()
    for s in (NsStatus.DELEGATED, NsStatus.NO_DELEGATION, NsStatus.UNKNOWN, NsStatus.DELEGATED):
        stats.record(s)
    assert (stats.checked, stats.delegated, stats.no_delegation, stats.unknown) == (4, 2, 1, 1)


def test_custom_resolvers_are_applied():
    probe = NsProbe(DnsConfig(resolvers=["9.9.9.9"]))
    assert probe._resolver.nameservers == ["9.9.9.9"]
