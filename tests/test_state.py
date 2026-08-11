import datetime as dt

import pytest

from wiederfrei.candidates import Candidate
from wiederfrei.dns_probe import NsStatus
from wiederfrei.rdap import RdapStatus
from wiederfrei.state import Store


@pytest.fixture()
def store(tmp_path):
    with Store(tmp_path / "test.db") as s:
        yield s


def cand(name: str, tld: str = "ch") -> Candidate:
    return Candidate(f"{name}.{tld}", name, tld)


class TestNsRecording:
    def test_upsert_is_idempotent(self, store):
        store.record_ns_batch([(cand("abc"), NsStatus.DELEGATED)])
        store.record_ns_batch([(cand("abc"), NsStatus.NO_DELEGATION)])
        assert store.counts()["domains"] == 1
        assert store.counts()["no_delegation"] == 1

    def test_empty_batch_is_a_noop(self, store):
        store.record_ns_batch([])
        assert store.counts()["domains"] == 0

    def test_previous_status_supports_the_newly_lost_ns_diff(self, store):
        store.record_ns_batch([(cand("abc"), NsStatus.DELEGATED)])
        before = store.previous_ns_status(["abc.ch", "zzz.ch"])
        assert before["abc.ch"] == "delegated"
        assert "zzz.ch" not in before

    def test_previous_status_batches_beyond_sqlite_variable_limit(self, store):
        names = [f"d{i:04d}" for i in range(1200)]
        store.record_ns_batch([(cand(n), NsStatus.DELEGATED) for n in names])
        got = store.previous_ns_status([f"{n}.ch" for n in names])
        assert len(got) == 1200


class TestRdapQueue:
    def test_only_undelegated_names_are_queued(self, store):
        store.record_ns_batch([
            (cand("aaa"), NsStatus.DELEGATED),
            (cand("bbb"), NsStatus.NO_DELEGATION),
            (cand("ccc"), NsStatus.UNKNOWN),
        ])
        queued = {r.domain for r in store.rdap_queue(recheck_after_days=7, limit=100)}
        assert queued == {"bbb.ch"}

    def test_respects_the_per_run_cap(self, store):
        store.record_ns_batch([(cand(f"n{i:03d}"), NsStatus.NO_DELEGATION) for i in range(50)])
        assert len(store.rdap_queue(recheck_after_days=7, limit=10)) == 10

    def test_fresh_verdicts_are_not_requeried(self, store):
        store.record_ns_batch([(cand("bbb"), NsStatus.NO_DELEGATION)])
        store.record_rdap("bbb.ch", RdapStatus.REGISTERED)
        assert store.rdap_queue(recheck_after_days=7, limit=100) == []

    def test_available_names_are_always_requeried(self, store):
        """Re-confirming known-available names each run is what makes a failed alert
        delivery recoverable, and catches a watched name being taken."""
        store.record_ns_batch([(cand("bbb"), NsStatus.NO_DELEGATION)])
        store.record_rdap("bbb.ch", RdapStatus.AVAILABLE)
        assert [r.domain for r in store.rdap_queue(recheck_after_days=7, limit=100)] == [
            "bbb.ch"
        ]

    def test_available_names_outrank_stale_ones_within_the_cap(self, store):
        store.record_ns_batch([
            (cand("free"), NsStatus.NO_DELEGATION),
            (cand("stale"), NsStatus.NO_DELEGATION),
        ])
        old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=30)).isoformat(
            timespec="seconds"
        )
        store.conn.execute(
            "UPDATE domain_status SET rdap_status = ?, last_rdap_check = ? WHERE domain = ?",
            (str(RdapStatus.REGISTERED), old, "stale.ch"),
        )
        store.conn.commit()
        store.record_rdap("free.ch", RdapStatus.AVAILABLE)
        queue = store.rdap_queue(recheck_after_days=7, limit=1)
        assert [r.domain for r in queue] == ["free.ch"]

    def test_stale_verdicts_are_requeried(self, store):
        store.record_ns_batch([(cand("bbb"), NsStatus.NO_DELEGATION)])
        old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=30)).isoformat(
            timespec="seconds"
        )
        store.conn.execute(
            "UPDATE domain_status SET rdap_status = ?, last_rdap_check = ? WHERE domain = ?",
            (str(RdapStatus.REGISTERED), old, "bbb.ch"),
        )
        store.conn.commit()
        assert len(store.rdap_queue(recheck_after_days=7, limit=100)) == 1

    def test_never_checked_names_are_prioritised_over_stale_ones(self, store):
        store.record_ns_batch([
            (cand("old"), NsStatus.NO_DELEGATION),
            (cand("new"), NsStatus.NO_DELEGATION),
        ])
        old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=30)).isoformat(
            timespec="seconds"
        )
        store.conn.execute(
            "UPDATE domain_status SET rdap_status = ?, last_rdap_check = ? WHERE domain = ?",
            (str(RdapStatus.REGISTERED), old, "old.ch"),
        )
        store.conn.commit()
        queue = store.rdap_queue(recheck_after_days=7, limit=1)
        assert [r.domain for r in queue] == ["new.ch"]


class TestAlertDedupe:
    def test_same_domain_and_rule_records_once(self, store):
        store.record_alert("abc.ch", "Short .ch")
        store.record_alert("abc.ch", "Short .ch")
        assert len(store.list_alerts()) == 1

    def test_same_domain_different_rules_are_separate(self, store):
        store.record_alert("abc.ch", "Short .ch")
        store.record_alert("abc.ch", "Three-letter .ch")
        assert len(store.list_alerts()) == 2

    def test_unalerted_rules_filters_out_known_ones(self, store):
        store.record_alert("abc.ch", "seen")
        assert store.unalerted_rules("abc.ch", ["seen", "fresh"]) == ["fresh"]

    def test_re_recording_updates_last_alerted_not_first(self, store):
        store.record_alert("abc.ch", "r")
        first = store.list_alerts()[0]["first_alerted"]
        store.record_alert("abc.ch", "r")
        row = store.list_alerts()[0]
        assert row["first_alerted"] == first


class TestRuns:
    def test_run_lifecycle_is_recorded(self, store):
        run_id = store.start_run()
        store.finish_run(run_id, dns_checked=10, rdap_checked=2, alerts_sent=1)
        row = store.conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        assert row["dns_checked"] == 10
        assert row["finished_at"] is not None


def test_store_creates_parent_directory(tmp_path):
    path = tmp_path / "nested" / "dir" / "state.db"
    with Store(path):
        pass
    assert path.exists()


def test_reopening_preserves_state(tmp_path):
    path = tmp_path / "state.db"
    with Store(path) as s:
        s.record_alert("abc.ch", "r")
    with Store(path) as s:
        assert s.already_alerted("abc.ch", "r")
