import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest

from wiederfrei.candidates import Candidate
from wiederfrei.config import DnsConfig
from wiederfrei.dns_probe import (
    AuthoritativeNsProbe,
    NsProbe,
    NsStatus,
    SweepStats,
    build_probe,
    interpret_authoritative,
)


def cand(name: str) -> Candidate:
    return Candidate(f"{name}.ch", name, "ch")


@pytest.fixture()
def probe():
    return NsProbe(DnsConfig(concurrency=4, timeout=0.1, lifetime=0.2, mode="recursive"))


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
    probe = NsProbe(DnsConfig(resolvers=["9.9.9.9"], mode="recursive"))
    assert probe._resolver.nameservers == ["9.9.9.9"]


# --- authoritative probe --------------------------------------------------------

QNAME = dns.name.from_text("abc.ch.")
ZONE = dns.name.from_text("ch.")


def make_response(rcode=dns.rcode.NOERROR, *, answer=(), authority=(), flags=0):
    response = dns.message.make_response(
        dns.message.make_query(QNAME, dns.rdatatype.NS)
    )
    response.set_rcode(rcode)
    response.answer = list(answer)
    response.authority = list(authority)
    response.flags |= flags
    return response


def ns_rrset(name: dns.name.Name, target: str = "ns1.example.ch."):
    return dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.NS, target)


def soa_rrset(name: dns.name.Name = ZONE):
    return dns.rrset.from_text(
        name, 3600, dns.rdataclass.IN, dns.rdatatype.SOA,
        "a.nic.ch. dns.switch.ch. 1 900 600 604800 900",
    )


class TestInterpretAuthoritative:
    """A TLD server reports a delegation rather than following it, so the signal is
    an NS RRset in the authority section whose owner name is the queried name."""

    def test_referral_means_delegated(self):
        response = make_response(authority=[ns_rrset(QNAME)])
        assert interpret_authoritative(response, QNAME) is NsStatus.DELEGATED

    def test_nxdomain_means_no_delegation(self):
        response = make_response(dns.rcode.NXDOMAIN, authority=[soa_rrset()])
        assert interpret_authoritative(response, QNAME) is NsStatus.NO_DELEGATION

    def test_nodata_with_zone_soa_means_no_delegation(self):
        response = make_response(authority=[soa_rrset()])
        assert interpret_authoritative(response, QNAME) is NsStatus.NO_DELEGATION

    def test_zone_apex_ns_is_not_a_delegation_of_the_child(self):
        """The discriminator that matters: NS for 'ch.' is the zone's own NS, not a
        referral for 'abc.ch.'. Missing this would mark every name delegated."""
        response = make_response(authority=[ns_rrset(ZONE, "a.nic.ch.")])
        assert interpret_authoritative(response, QNAME) is NsStatus.NO_DELEGATION

    def test_ns_in_answer_section_also_counts(self):
        response = make_response(answer=[ns_rrset(QNAME)])
        assert interpret_authoritative(response, QNAME) is NsStatus.DELEGATED

    @pytest.mark.parametrize(
        "rcode", [dns.rcode.SERVFAIL, dns.rcode.REFUSED, dns.rcode.NOTIMP]
    )
    def test_other_rcodes_are_unknown_never_available(self, rcode):
        response = make_response(rcode)
        assert interpret_authoritative(response, QNAME) is NsStatus.UNKNOWN


@pytest.fixture()
def auth_probe(monkeypatch):
    """Probe with preflight stubbed to pass; interception is tested separately."""
    probe = AuthoritativeNsProbe(
        DnsConfig(concurrency=4, timeout=0.1, qps=10_000.0,
                  nameservers=["192.0.2.1", "192.0.2.2"], max_retries=1)
    )

    async def authoritative(server, tld):
        return True

    monkeypatch.setattr(probe, "is_authoritative", authoritative)
    return probe


class TestAuthoritativeProbe:
    async def test_configured_nameservers_skip_discovery(self, auth_probe):
        assert await auth_probe.servers_for("ch") == ["192.0.2.1", "192.0.2.2"]

    async def test_referral_resolves_to_delegated(self, auth_probe, monkeypatch):
        async def udp(query, server, **kw):
            return make_response(authority=[ns_rrset(QNAME)])

        monkeypatch.setattr("dns.asyncquery.udp", udp)
        assert await auth_probe.status("abc.ch") is NsStatus.DELEGATED

    async def test_query_has_recursion_desired_cleared(self, auth_probe, monkeypatch):
        seen = {}

        async def udp(query, server, **kw):
            seen["rd"] = bool(query.flags & dns.flags.RD)
            return make_response(authority=[ns_rrset(QNAME)])

        monkeypatch.setattr("dns.asyncquery.udp", udp)
        await auth_probe.status("abc.ch")
        assert seen["rd"] is False

    async def test_truncated_response_retries_over_tcp(self, auth_probe, monkeypatch):
        calls = []

        async def udp(query, server, **kw):
            calls.append("udp")
            return make_response(flags=dns.flags.TC)

        async def tcp(query, server, **kw):
            calls.append("tcp")
            return make_response(authority=[ns_rrset(QNAME)])

        monkeypatch.setattr("dns.asyncquery.udp", udp)
        monkeypatch.setattr("dns.asyncquery.tcp", tcp)
        assert await auth_probe.status("abc.ch") is NsStatus.DELEGATED
        assert calls == ["udp", "tcp"]

    async def test_timeout_retries_against_a_different_server(self, auth_probe, monkeypatch):
        servers = []

        async def udp(query, server, **kw):
            servers.append(server)
            if len(servers) == 1:
                raise dns.exception.Timeout
            return make_response(authority=[ns_rrset(QNAME)])

        monkeypatch.setattr("dns.asyncquery.udp", udp)
        assert await auth_probe.status("abc.ch") is NsStatus.DELEGATED
        assert servers[0] != servers[1]

    async def test_persistent_failure_is_unknown(self, auth_probe, monkeypatch):
        async def udp(query, server, **kw):
            raise dns.exception.Timeout

        monkeypatch.setattr("dns.asyncquery.udp", udp)
        assert await auth_probe.status("abc.ch") is NsStatus.UNKNOWN

    async def test_servfail_is_retried_then_unknown(self, auth_probe, monkeypatch):
        calls = []

        async def udp(query, server, **kw):
            calls.append(server)
            return make_response(dns.rcode.SERVFAIL)

        monkeypatch.setattr("dns.asyncquery.udp", udp)
        assert await auth_probe.status("abc.ch") is NsStatus.UNKNOWN
        assert len(calls) == 2

    async def test_discovery_failure_is_unknown_not_available(self, monkeypatch):
        p = AuthoritativeNsProbe(DnsConfig(timeout=0.1, qps=10_000.0))

        async def boom(tld):
            raise dns.exception.DNSException("no servers")

        monkeypatch.setattr(p, "servers_for", boom)
        assert await p.status("abc.ch") is NsStatus.UNKNOWN

    async def test_sweep_works_through_the_shared_driver(self, auth_probe, monkeypatch):
        async def udp(query, server, **kw):
            return make_response(authority=[ns_rrset(query.question[0].name)])

        monkeypatch.setattr("dns.asyncquery.udp", udp)
        stats = await auth_probe.sweep([cand("aa"), cand("bb")])
        assert (stats.checked, stats.delegated) == (2, 2)


class TestInterceptionDetection:
    """Some networks transparently intercept UDP/53 and answer from their own resolver.
    That resolver SERVFAILs the RD=0 queries this probe sends, which would silently turn
    a whole sweep into UNKNOWN. Detect it and degrade to correct-but-slower."""

    def make_probe(self):
        return AuthoritativeNsProbe(
            DnsConfig(concurrency=2, timeout=0.1, qps=10_000.0,
                      nameservers=["192.0.2.1"], max_retries=0)
        )

    async def test_aa_set_is_accepted_as_authoritative(self, monkeypatch):
        async def udp(query, server, **kw):
            return make_response(flags=dns.flags.AA)

        monkeypatch.setattr("dns.asyncquery.udp", udp)
        probe = self.make_probe()
        assert await probe.is_authoritative("192.0.2.1", "ch") is True

    async def test_missing_aa_with_ra_is_rejected(self, monkeypatch):
        """The real signature seen in the wild: AA=0, RA=1 -- a recursive resolver."""
        async def udp(query, server, **kw):
            return make_response(flags=dns.flags.RA)

        monkeypatch.setattr("dns.asyncquery.udp", udp)
        probe = self.make_probe()
        assert await probe.is_authoritative("192.0.2.1", "ch") is False

    async def test_preflight_failure_is_rejected(self, monkeypatch):
        async def udp(query, server, **kw):
            raise dns.exception.Timeout

        monkeypatch.setattr("dns.asyncquery.udp", udp)
        probe = self.make_probe()
        assert await probe.is_authoritative("192.0.2.1", "ch") is False

    async def test_interception_falls_back_and_stays_correct(self, monkeypatch, caplog):
        """An intercepted probe must return real verdicts, not a sweep full of UNKNOWN."""
        async def udp(query, server, **kw):
            return make_response(dns.rcode.SERVFAIL, flags=dns.flags.RA)

        monkeypatch.setattr("dns.asyncquery.udp", udp)

        async def recursive_status(self, domain):
            return NsStatus.DELEGATED

        monkeypatch.setattr(NsProbe, "status", recursive_status)

        probe = self.make_probe()
        with caplog.at_level("ERROR"):
            assert await probe.status("abc.ch") is NsStatus.DELEGATED
        assert probe._fallback is not None
        assert "interception detected" in caplog.text.lower()


class TestBuildProbe:
    def test_default_mode_is_authoritative(self):
        assert isinstance(build_probe(DnsConfig()), AuthoritativeNsProbe)

    def test_recursive_mode_selected_explicitly(self):
        assert isinstance(build_probe(DnsConfig(mode="recursive")), NsProbe)
