import datetime as dt
import os

import pytest

from wiederfrei.candidates import Candidate
from wiederfrei.config import ZoneConfig
from wiederfrei.dns_probe import NsStatus
from wiederfrei.errors import ConfigError
from wiederfrei.zone import (
    TERMS,
    ZoneBackend,
    ZoneError,
    ZoneSnapshot,
    load_zone_file,
    parse_names,
    parse_zonefile,
    tsig_keyring_from_env,
)

NAMES_FILE = "abc.ch\nxyz.ch\n# a comment\n\nZüRich.ch\n"

ZONE_FILE = """\
$ORIGIN ch.
ch.       900 IN SOA a.nic.ch. dns.switch.ch. 1 900 600 604800 900
ch.       900 IN NS  a.nic.ch.
abc.ch.  3600 IN NS  ns1.example.ch.
         3600 IN NS  ns2.example.ch.
xyz.ch.  3600 IN NS  ns1.example.net.
nodel.ch. 3600 IN DS 1 8 2 AABB
"""


class TestParsers:
    def test_names_format(self):
        assert parse_names(NAMES_FILE.splitlines()) == {
            "abc.ch", "xyz.ch", "xn--zrich-kva.ch",
        }

    def test_names_format_normalises_idn_and_case(self):
        """Zone names must land in the same form candidates use, or nothing matches."""
        assert "xn--zrich-kva.ch" in parse_names(["ZüRich.ch"])

    def test_www_is_kept_as_a_registrable_label(self):
        """www.ch is a real three-letter domain. Stripping the prefix made the zone
        tier report it as undelegated on every run."""
        assert parse_names(["www.ch"]) == {"www.ch"}

    def test_zonefile_extracts_delegated_owners(self):
        names = parse_zonefile(ZONE_FILE.splitlines())
        assert "abc.ch" in names
        assert "xyz.ch" in names

    def test_zonefile_excludes_the_apex(self):
        assert "ch" not in parse_zonefile(ZONE_FILE.splitlines())

    def test_zonefile_excludes_names_without_ns(self):
        assert "nodel.ch" not in parse_zonefile(ZONE_FILE.splitlines())

    def test_zonefile_ignores_comments_and_directives(self):
        names = parse_zonefile(["$TTL 900", "; comment", "a.ch. IN NS x.ch. ; trailing"])
        assert names == {"a.ch"}


class TestLoad:
    def test_missing_file(self, tmp_path):
        with pytest.raises(ZoneError, match="not found"):
            load_zone_file(tmp_path / "nope.txt", "names")

    def test_empty_result_is_an_error_not_a_silent_empty_zone(self, tmp_path):
        """An empty set would mark every candidate undelegated and flood the RDAP tier."""
        path = tmp_path / "z.txt"
        path.write_text("# nothing here\n", encoding="utf-8")
        with pytest.raises(ZoneError, match="no delegated names"):
            load_zone_file(path, "names")


class TestSnapshot:
    def test_save_rotates_current_to_previous(self, tmp_path):
        snap = ZoneSnapshot(tmp_path, "ch")
        snap.save({"a.ch", "b.ch"})
        snap.save({"a.ch"})
        assert snap.load_current() == {"a.ch"}
        assert snap.previous.exists()

    def test_diff_reports_names_that_left_the_zone(self, tmp_path):
        snap = ZoneSnapshot(tmp_path, "ch")
        snap.save({"a.ch", "b.ch", "c.ch"})
        snap.save({"a.ch", "d.ch"})
        removed, added = snap.diff()
        assert removed == {"b.ch", "c.ch"}
        assert added == {"d.ch"}

    def test_diff_is_empty_without_two_snapshots(self, tmp_path):
        snap = ZoneSnapshot(tmp_path, "ch")
        snap.save({"a.ch"})
        assert snap.diff() == (set(), set())

    def test_age_hours_none_when_absent(self, tmp_path):
        assert ZoneSnapshot(tmp_path, "ch").age_hours() is None

    def test_age_hours_of_fresh_snapshot_is_near_zero(self, tmp_path):
        snap = ZoneSnapshot(tmp_path, "ch")
        snap.save({"a.ch"})
        assert snap.age_hours() < 0.1


class TestLicenceGate:
    def test_refuses_when_disabled(self):
        with pytest.raises(ConfigError, match="zone.enabled is false"):
            ZoneBackend(ZoneConfig(enabled=False))

    def test_refuses_without_acknowledgement(self):
        with pytest.raises(ConfigError) as exc:
            ZoneBackend(ZoneConfig(enabled=True, acknowledge_terms=False))
        assert "acknowledge_terms" in str(exc.value)

    def test_the_refusal_quotes_the_actual_terms(self):
        """The operator has to see what they are agreeing to, not just a flag name."""
        with pytest.raises(ConfigError) as exc:
            ZoneBackend(ZoneConfig(enabled=True))
        assert "public interest" in str(exc.value)
        assert TERMS in str(exc.value)

    def test_constructs_once_acknowledged(self, tmp_path):
        backend = ZoneBackend(
            ZoneConfig(enabled=True, acknowledge_terms=True, snapshot_dir=tmp_path)
        )
        assert backend.cfg.tld == "ch"


@pytest.fixture()
def file_backend(tmp_path):
    zone = tmp_path / "zone.txt"
    zone.write_text("aaa.ch\nbbb.ch\n", encoding="utf-8")
    return ZoneBackend(
        ZoneConfig(enabled=True, acknowledge_terms=True, source="file",
                   path=zone, format="names", snapshot_dir=tmp_path / "snap")
    )


class TestBackendAsTierOne:
    async def test_membership_decides_delegation(self, file_backend):
        assert await file_backend.status("aaa.ch") is NsStatus.DELEGATED
        assert await file_backend.status("zzz.ch") is NsStatus.NO_DELEGATION

    async def test_sweep_matches_the_probe_interface(self, file_backend):
        cands = [Candidate(f"{n}.ch", n, "ch") for n in ("aaa", "bbb", "zzz")]
        batches = []
        stats = await file_backend.sweep(cands, on_batch=batches.append)
        assert (stats.checked, stats.delegated, stats.no_delegation) == (3, 2, 1)
        assert sum(len(b) for b in batches) == 3

    async def test_sweep_sends_no_queries(self, file_backend, monkeypatch):
        def boom(*a, **kw):
            raise AssertionError("the zone backend must not query DNS")

        monkeypatch.setattr("dns.asyncquery.udp", boom)
        await file_backend.sweep([Candidate("aaa.ch", "aaa", "ch")])


class TestTransferGuard:
    def test_fresh_snapshot_is_reused_instead_of_refetching(self, tmp_path, monkeypatch):
        snap_dir = tmp_path / "snap"
        backend = ZoneBackend(
            ZoneConfig(enabled=True, acknowledge_terms=True, source="axfr",
                       snapshot_dir=snap_dir, min_transfer_interval_hours=24)
        )
        backend.snapshot.save({"aaa.ch"})

        def boom(*a, **kw):
            raise AssertionError("Switch asks for at most one transfer per 24h")

        monkeypatch.setattr("wiederfrei.zone.transfer_zone", boom)
        assert backend.refresh() == {"aaa.ch"}

    def test_stale_snapshot_triggers_a_transfer(self, tmp_path, monkeypatch):
        snap_dir = tmp_path / "snap"
        backend = ZoneBackend(
            ZoneConfig(enabled=True, acknowledge_terms=True, source="axfr",
                       snapshot_dir=snap_dir, min_transfer_interval_hours=24)
        )
        backend.snapshot.save({"old.ch"})
        old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=30)
        os.utime(backend.snapshot.current, (old.timestamp(), old.timestamp()))

        monkeypatch.setattr("wiederfrei.zone.transfer_zone", lambda cfg: {"new.ch"})
        assert backend.refresh() == {"new.ch"}

    def test_force_overrides_the_interval(self, tmp_path, monkeypatch):
        backend = ZoneBackend(
            ZoneConfig(enabled=True, acknowledge_terms=True, source="axfr",
                       snapshot_dir=tmp_path / "snap")
        )
        backend.snapshot.save({"old.ch"})
        monkeypatch.setattr("wiederfrei.zone.transfer_zone", lambda cfg: {"new.ch"})
        assert backend.refresh(force=True) == {"new.ch"}


class TestTsig:
    def test_unconfigured_returns_none(self):
        assert tsig_keyring_from_env({}) is None

    def test_partial_config_returns_none(self):
        assert tsig_keyring_from_env({"SWITCH_ZONE_TSIG_NAME": "k"}) is None

    def test_valid_key_builds_a_keyring(self):
        result = tsig_keyring_from_env({
            "SWITCH_ZONE_TSIG_NAME": "wiederfrei.",
            "SWITCH_ZONE_TSIG_KEY": "c2VjcmV0c2VjcmV0c2VjcmV0",
        })
        assert result is not None
        keyring, algorithm = result
        assert algorithm == "hmac-sha512"

    def test_invalid_secret_is_reported_clearly(self):
        with pytest.raises(ConfigError, match="not a valid TSIG secret"):
            tsig_keyring_from_env({
                "SWITCH_ZONE_TSIG_NAME": "k.",
                "SWITCH_ZONE_TSIG_KEY": "!!!not base64!!!",
            })

    def test_axfr_without_a_key_is_refused_before_connecting(self):
        from wiederfrei.zone import transfer_zone

        with pytest.raises(ConfigError, match="SWITCH_ZONE_TSIG"):
            transfer_zone(ZoneConfig(enabled=True, acknowledge_terms=True), env={})
