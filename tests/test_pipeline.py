"""End-to-end pipeline behaviour with DNS and RDAP mocked."""

import httpx
import pytest
import respx

from wiederfrei.config import Config, DnsConfig, RankingConfig, RdapConfig, ZoneConfig
from wiederfrei.dns_probe import NsStatus
from wiederfrei.errors import NotifyError
from wiederfrei.pipeline import run_sweep
from wiederfrei.rules import LengthRule
from wiederfrei.state import Store


class CollectingNotifier:
    name = "collect"

    def __init__(self):
        self.alerts = []

    def send(self, alert):
        self.alerts.append(alert)


class FailingNotifier:
    name = "failing"

    def send(self, alert):
        raise NotifyError("relay refused")


@pytest.fixture()
def cfg(tmp_path):
    """One two-letter rule over .ch: a 676-name space, small enough to sweep in a test."""
    rule = LengthRule(
        name="Two-letter .ch", tlds=["ch"], min_length=2, max_length=2,
        charset="alpha", notify=["collect"],
    )
    return Config(
        rules=[rule],
        # Pinned to recursive so fake_dns can patch NsProbe.status. The authoritative
        # probe is exercised directly in tests/test_dns_probe.py.
        dns=DnsConfig(concurrency=8, mode="recursive"),
        rdap=RdapConfig(rate_limit_per_second=1000.0, max_per_run=100, max_retries=1),
        ranking=RankingConfig(),
        zone=ZoneConfig(),
        state_path=tmp_path / "state.db",
        source_path=tmp_path / "rules.yaml",
    )


@pytest.fixture()
def store(cfg):
    with Store(cfg.state_path) as s:
        yield s


@pytest.fixture()
def fake_dns(monkeypatch):
    """Only 'aa.ch' and 'ab.ch' lack delegation; everything else is registered."""
    undelegated = {"aa.ch", "ab.ch"}

    async def fake_status(self, domain):
        return NsStatus.NO_DELEGATION if domain in undelegated else NsStatus.DELEGATED

    monkeypatch.setattr("wiederfrei.dns_probe.NsProbe.status", fake_status)
    return undelegated


def mock_rdap(available: set[str]):
    """Route RDAP HEADs: names in `available` 404, everything else 200."""
    def handler(request):
        domain = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(404 if domain in available else 200)

    respx.head(host="rdap.nic.ch").mock(side_effect=handler)


@respx.mock
async def test_available_domain_is_found_and_alerted(cfg, store, fake_dns):
    mock_rdap({"aa.ch"})
    notifier = CollectingNotifier()

    report = await run_sweep(cfg, store, notifiers=[notifier])

    assert report.dns_checked == 676
    assert report.dns_no_delegation == 2
    assert report.rdap_checked == 2
    assert report.available == 1
    assert report.alerts_sent == 1
    assert [f.domain for f in notifier.alerts[0].findings] == ["aa.ch"]


@respx.mock
async def test_alert_names_the_rule_that_fired(cfg, store, fake_dns):
    mock_rdap({"aa.ch"})
    notifier = CollectingNotifier()

    await run_sweep(cfg, store, notifiers=[notifier])

    alert = notifier.alerts[0]
    assert alert.findings[0].rule_names == ["Two-letter .ch"]
    assert alert.rule_definitions["Two-letter .ch"].startswith("length rule: 2-2")
    assert "Two-letter .ch" in alert.subject()


@respx.mock
async def test_registered_names_produce_no_alert(cfg, store, fake_dns):
    mock_rdap(set())
    notifier = CollectingNotifier()

    report = await run_sweep(cfg, store, notifiers=[notifier])

    assert report.available == 0
    assert notifier.alerts == []


@respx.mock
async def test_second_run_does_not_re_alert(cfg, store, fake_dns):
    mock_rdap({"aa.ch"})
    notifier = CollectingNotifier()

    await run_sweep(cfg, store, notifiers=[notifier])
    second = await run_sweep(cfg, store, notifiers=[notifier], skip_dns=True)

    assert len(notifier.alerts) == 1
    assert second.alerts_sent == 0
    assert second.skipped_already_alerted == 1


@respx.mock
async def test_failed_delivery_leaves_the_finding_unrecorded(cfg, store, fake_dns):
    """The old pickle committed state before output; a crash buried domains forever."""
    mock_rdap({"aa.ch"})

    with pytest.raises(NotifyError):
        await run_sweep(cfg, store, notifiers=[FailingNotifier()])

    assert store.list_alerts() == []

    # A later run with a working notifier still reports it.
    notifier = CollectingNotifier()
    report = await run_sweep(cfg, store, notifiers=[notifier], skip_dns=True)
    assert report.alerts_sent == 1


@respx.mock
async def test_dry_run_sends_nothing_and_records_nothing(cfg, store, fake_dns, capsys):
    mock_rdap({"aa.ch"})
    notifier = CollectingNotifier()

    report = await run_sweep(cfg, store, notifiers=[notifier], dry_run=True)

    assert notifier.alerts == []
    assert store.list_alerts() == []
    assert report.alerts_sent == 0
    assert "aa.ch" in capsys.readouterr().out


@respx.mock
async def test_limit_caps_the_candidate_stream(cfg, store, fake_dns):
    mock_rdap(set())
    report = await run_sweep(cfg, store, notifiers=[], limit=50)
    assert report.dns_checked == 50


@respx.mock
async def test_rdap_unknown_never_becomes_an_alert(cfg, store, fake_dns):
    """A throttled or broken registry must not produce a false 'available'."""
    respx.head(host="rdap.nic.ch").mock(
        return_value=httpx.Response(429, headers={"Retry-After": "0"})
    )
    notifier = CollectingNotifier()

    report = await run_sweep(cfg, store, notifiers=[notifier])

    assert report.available == 0
    assert notifier.alerts == []


@respx.mock
async def test_overlapping_rules_are_both_attributed(cfg, store, fake_dns):
    mock_rdap({"aa.ch"})
    cfg.rules.append(
        LengthRule(name="Any short .ch", tlds=["ch"], min_length=2, max_length=3,
                   charset="alnum", notify=["collect"])
    )
    notifier = CollectingNotifier()

    await run_sweep(cfg, store, notifiers=[notifier])

    names = notifier.alerts[0].findings[0].rule_names
    assert set(names) == {"Two-letter .ch", "Any short .ch"}


@respx.mock
async def test_skip_dns_reuses_cached_status(cfg, store, fake_dns):
    mock_rdap(set())
    await run_sweep(cfg, store, notifiers=[])

    report = await run_sweep(cfg, store, notifiers=[], skip_dns=True)
    assert report.dns_checked == 0
    # The two undelegated names are re-queued only once their verdict goes stale.
    assert report.rdap_checked == 0


@respx.mock
async def test_findings_with_no_notifier_are_not_recorded_as_alerted(cfg, store, fake_dns):
    mock_rdap({"aa.ch"})

    report = await run_sweep(cfg, store, notifiers=[])

    assert report.available == 1
    assert report.alerts_sent == 0
    assert store.list_alerts() == []


async def test_no_enabled_rules_is_a_noop(cfg, store):
    cfg.rules[0].enabled = False
    report = await run_sweep(cfg, store, notifiers=[])
    assert report.dns_checked == 0
    assert report.alerts_sent == 0
