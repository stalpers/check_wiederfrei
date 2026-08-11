"""Persistent state, in SQLite.

This replaces the old ``seen_domains.pkl``. Three things the pickle could not do and
this must:

* record *why* a name was skipped, so RDAP verdicts can be cached and re-checked on a
  cadence rather than re-queried every night;
* survive an interrupted run, so the expensive first sweep resumes instead of restarting;
* commit alert records only *after* the notifier succeeds, so a failed send does not
  silently bury a find forever.
"""

from __future__ import annotations

import datetime as dt
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .dns_probe import NsStatus
from .rdap import RdapStatus

SCHEMA = """
CREATE TABLE IF NOT EXISTS domain_status (
    domain          TEXT PRIMARY KEY,
    tld             TEXT NOT NULL,
    label           TEXT NOT NULL,
    ns_status       TEXT,
    rdap_status     TEXT,
    last_dns_check  TEXT,
    last_rdap_check TEXT
);
CREATE INDEX IF NOT EXISTS idx_domain_status_ns ON domain_status (ns_status);
CREATE INDEX IF NOT EXISTS idx_domain_status_rdap ON domain_status (rdap_status);

CREATE TABLE IF NOT EXISTS alerts (
    domain        TEXT NOT NULL,
    rule_name     TEXT NOT NULL,
    first_alerted TEXT NOT NULL,
    last_alerted  TEXT NOT NULL,
    PRIMARY KEY (domain, rule_name)
);

CREATE TABLE IF NOT EXISTS runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    dns_checked  INTEGER NOT NULL DEFAULT 0,
    rdap_checked INTEGER NOT NULL DEFAULT 0,
    alerts_sent  INTEGER NOT NULL DEFAULT 0,
    note         TEXT
);
"""


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True, slots=True)
class DomainRow:
    domain: str
    tld: str
    label: str
    ns_status: str | None
    rdap_status: str | None
    last_dns_check: str | None
    last_rdap_check: str | None


class Store:
    """Thin SQLite wrapper. Not thread-safe; one instance per run."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        if self.path.parent and str(self.path.parent) not in ("", "."):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # --- DNS tier ---------------------------------------------------------------

    def previous_ns_status(self, domains: Sequence[str]) -> dict[str, str | None]:
        """Prior ``ns_status`` for the given domains, for the newly-lost-NS diff."""
        out: dict[str, str | None] = {}
        for start in range(0, len(domains), 500):
            batch = domains[start : start + 500]
            placeholders = ",".join("?" * len(batch))
            rows = self.conn.execute(
                f"SELECT domain, ns_status FROM domain_status WHERE domain IN ({placeholders})",
                batch,
            )
            out.update({r["domain"]: r["ns_status"] for r in rows})
        return out

    def record_ns_batch(self, batch: Iterable[tuple[object, NsStatus]]) -> None:
        """Upsert DNS results. Committed per batch so an interrupted sweep keeps progress."""
        now = utcnow()
        rows = [(c.domain, c.tld, c.label, str(status), now) for c, status in batch]
        if not rows:
            return
        self.conn.executemany(
            """
            INSERT INTO domain_status (domain, tld, label, ns_status, last_dns_check)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                tld = excluded.tld,
                label = excluded.label,
                ns_status = excluded.ns_status,
                last_dns_check = excluded.last_dns_check
            """,
            rows,
        )
        self.conn.commit()

    # --- RDAP tier --------------------------------------------------------------

    def rdap_queue(self, *, recheck_after_days: int, limit: int) -> list[DomainRow]:
        """Names needing an RDAP verdict, most informative first.

        Three groups qualify, and the ordering matters because ``limit`` is a hard budget:

        1. never checked -- includes everything that just lost its delegation;
        2. already known available -- re-confirmed every run. There are few of these by
           definition, and always re-checking them is what makes a failed alert delivery
           recoverable: the finding comes back next run instead of being buried until
           its verdict goes stale;
        3. stale cached verdicts, oldest first, rotating through the rest.
        """
        cutoff = (
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=recheck_after_days)
        ).isoformat(timespec="seconds")
        rows = self.conn.execute(
            """
            SELECT domain, tld, label, ns_status, rdap_status, last_dns_check, last_rdap_check
            FROM domain_status
            WHERE ns_status = ?
              AND (last_rdap_check IS NULL OR last_rdap_check < ? OR rdap_status = ?)
            ORDER BY (last_rdap_check IS NOT NULL) ASC,
                     (rdap_status = ?) DESC,
                     last_rdap_check ASC
            LIMIT ?
            """,
            (
                str(NsStatus.NO_DELEGATION),
                cutoff,
                str(RdapStatus.AVAILABLE),
                str(RdapStatus.AVAILABLE),
                limit,
            ),
        ).fetchall()
        return [DomainRow(**dict(r)) for r in rows]

    def record_rdap(self, domain: str, status: RdapStatus) -> None:
        self.conn.execute(
            "UPDATE domain_status SET rdap_status = ?, last_rdap_check = ? WHERE domain = ?",
            (str(status), utcnow(), domain),
        )
        self.conn.commit()

    # --- alerts -----------------------------------------------------------------

    def already_alerted(self, domain: str, rule_name: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM alerts WHERE domain = ? AND rule_name = ?", (domain, rule_name)
        ).fetchone()
        return row is not None

    def unalerted_rules(self, domain: str, rule_names: Iterable[str]) -> list[str]:
        return [r for r in rule_names if not self.already_alerted(domain, r)]

    def record_alert(self, domain: str, rule_name: str) -> None:
        """Mark a (domain, rule) as notified. Called only after the notifier succeeds."""
        now = utcnow()
        self.conn.execute(
            """
            INSERT INTO alerts (domain, rule_name, first_alerted, last_alerted)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(domain, rule_name) DO UPDATE SET last_alerted = excluded.last_alerted
            """,
            (domain, rule_name, now, now),
        )
        self.conn.commit()

    def list_alerts(self, limit: int = 100) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT domain, rule_name, first_alerted, last_alerted FROM alerts "
            "ORDER BY first_alerted DESC LIMIT ?",
            (limit,),
        ).fetchall()

    # --- runs -------------------------------------------------------------------

    def start_run(self) -> int:
        cur = self.conn.execute("INSERT INTO runs (started_at) VALUES (?)", (utcnow(),))
        self.conn.commit()
        return int(cur.lastrowid)

    def finish_run(
        self, run_id: int, *, dns_checked: int, rdap_checked: int, alerts_sent: int,
        note: str = "",
    ) -> None:
        self.conn.execute(
            """
            UPDATE runs SET finished_at = ?, dns_checked = ?, rdap_checked = ?,
                            alerts_sent = ?, note = ?
            WHERE id = ?
            """,
            (utcnow(), dns_checked, rdap_checked, alerts_sent, note, run_id),
        )
        self.conn.commit()

    def counts(self) -> dict[str, int]:
        def scalar(sql: str, args: tuple = ()) -> int:
            row = self.conn.execute(sql, args).fetchone()
            return int(row[0]) if row else 0

        return {
            "domains": scalar("SELECT COUNT(*) FROM domain_status"),
            "delegated": scalar(
                "SELECT COUNT(*) FROM domain_status WHERE ns_status = ?",
                (str(NsStatus.DELEGATED),),
            ),
            "no_delegation": scalar(
                "SELECT COUNT(*) FROM domain_status WHERE ns_status = ?",
                (str(NsStatus.NO_DELEGATION),),
            ),
            "available": scalar(
                "SELECT COUNT(*) FROM domain_status WHERE rdap_status = ?",
                (str(RdapStatus.AVAILABLE),),
            ),
            "alerts": scalar("SELECT COUNT(*) FROM alerts"),
        }
