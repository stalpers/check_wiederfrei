"""Optional tier-1 replacement: the published `.ch` zone file.

Presence in the zone *is* delegation, so a set membership test replaces the entire DNS
sweep -- one transfer instead of ~1.7M queries. Candidates absent from the zone fall
through to the RDAP tier exactly as before, so the availability contract is unchanged.

Diffing consecutive snapshots gives something the DNS sweep cannot: every name that
*left* the zone since yesterday. That is a true "recently released" feed, and almost
certainly how the original `@wiederfrei` bot worked.

**This is off by default and gated on an explicit acknowledgement.** Switch licenses the
zone data for a stated set of purposes (see ``TERMS``), and domain hunting plausibly is
not among them. The public ``antoinet/chzone`` mirror restates the same terms, so taking
the data from a mirror does not change the obligation. Whether a given use qualifies is
the operator's call, which is why the code refuses to act on it implicitly.
"""

from __future__ import annotations

import datetime as dt
import logging
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

import dns.name
import dns.query
import dns.rdatatype
import dns.tsigkeyring
import dns.zone

from .candidates import Candidate, normalise_domain
from .config import ZoneConfig
from .dns_probe import NsStatus, SweepStats, _chunked
from .errors import ConfigError, WiederfreiError

logger = logging.getLogger(__name__)

TERMS = (
    "Switch publishes the .ch and .li zone files as open data, restricted to "
    "\"combating cybercrime, scientific and social research or for other purposes in "
    "the public interest\", and asks that the zone be downloaded no more than once "
    "every 24 hours. See https://www.switch.ch/open-data/"
)


class ZoneError(WiederfreiError):
    """The zone could not be obtained or parsed."""


def parse_names(text: Iterable[str]) -> set[str]:
    """Parse a one-domain-per-line list (the ``chzone`` / ``ch_uniq.txt`` format)."""
    out: set[str] = set()
    for line in text:
        line = line.strip()
        if not line or line.startswith((";", "#")):
            continue
        out.add(normalise_domain(line))
    out.discard("")
    return out


def parse_zonefile(text: Iterable[str], origin: str = "ch") -> set[str]:
    """Extract delegated owner names from a zone file in presentation format.

    Deliberately a line scanner rather than ``dns.zone.from_file``: the `.ch` zone has
    millions of records, and all that is needed is the owner name of every ``NS`` RRset.

    The zone apex carries its own ``NS`` RRset, which is the zone's nameservers and not
    a delegation — including it would mark the TLD itself as a candidate.
    """
    out: set[str] = set()
    last_owner = ""
    for line in text:
        line = line.split(";", 1)[0].rstrip()
        if not line or line.startswith("$"):
            continue
        fields = line.split()
        if not fields:
            continue
        if line[0].isspace():
            owner, rest = last_owner, fields      # continuation uses the previous owner
        else:
            owner, rest = fields[0], fields[1:]
            last_owner = owner
        if not owner:
            continue
        for token in rest:
            upper = token.upper()
            if upper == "NS":
                if owner in ("@", origin, f"{origin}."):
                    break                          # zone apex, not a delegation
                name = owner[:-1] if owner.endswith(".") else f"{owner}.{origin}"
                out.add(normalise_domain(name))
                break
            if upper in {"SOA", "A", "AAAA", "DS", "RRSIG", "NSEC", "NSEC3", "TXT", "MX"}:
                break
    out.discard("")
    out.discard(origin)
    return out


def load_zone_file(path: Path, fmt: str, origin: str = "ch") -> set[str]:
    if not path.exists():
        raise ZoneError(f"zone file {path} not found")
    with open(path, encoding="utf-8", errors="replace") as fh:
        names = parse_names(fh) if fmt == "names" else parse_zonefile(fh, origin)
    if not names:
        raise ZoneError(f"zone file {path} yielded no delegated names -- wrong format?")
    logger.info("Loaded %d delegated names from %s", len(names), path)
    return names


def tsig_keyring_from_env(env: dict[str, str] | None = None) -> tuple[dict, str] | None:
    """Build a TSIG keyring from the environment. Returns ``None`` if unconfigured."""
    env = dict(os.environ if env is None else env)
    name = env.get("SWITCH_ZONE_TSIG_NAME", "").strip()
    secret = env.get("SWITCH_ZONE_TSIG_KEY", "").strip()
    if not name or not secret:
        return None
    algorithm = env.get("SWITCH_ZONE_TSIG_ALGORITHM", "hmac-sha512").strip()
    try:
        keyring = dns.tsigkeyring.from_text({name: secret})
    except Exception as exc:                       # malformed base64, bad name, ...
        raise ConfigError(f"SWITCH_ZONE_TSIG_KEY is not a valid TSIG secret: {exc}") from None
    return keyring, algorithm


def transfer_zone(cfg: ZoneConfig, env: dict[str, str] | None = None) -> set[str]:
    """Pull the zone by AXFR and return the set of delegated names."""
    keyring_algo = tsig_keyring_from_env(env)
    if keyring_algo is None:
        raise ConfigError(
            "zone.source is 'axfr' but SWITCH_ZONE_TSIG_NAME / SWITCH_ZONE_TSIG_KEY are "
            "unset. Request a key from Switch; see .env.example."
        )
    keyring, algorithm = keyring_algo
    origin = dns.name.from_text(f"{cfg.tld}.")

    logger.info("Requesting AXFR of %s from %s", origin, cfg.server)
    try:
        zone = dns.zone.from_xfr(
            dns.query.xfr(
                cfg.server, origin, keyring=keyring, keyalgorithm=algorithm,
                timeout=cfg.timeout, lifetime=cfg.lifetime,
            )
        )
    except Exception as exc:
        raise ZoneError(f"AXFR of {origin} from {cfg.server} failed: {exc}") from exc

    names: set[str] = set()
    for name, node in zone.nodes.items():
        if node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NS) is None:
            continue
        text = name.to_text(omit_final_dot=True)
        if text in (".", "@", cfg.tld):
            continue                                # the apex is not a delegation
        names.add(normalise_domain(f"{text}.{cfg.tld}" if "." not in text else text))
    names.discard("")
    logger.info("AXFR returned %d delegated names", len(names))
    return names


@dataclass(slots=True)
class ZoneSnapshot:
    """Where snapshots live, and the day-over-day diff taken between them."""

    directory: Path
    tld: str

    @property
    def current(self) -> Path:
        return self.directory / f"{self.tld}.current.txt"

    @property
    def previous(self) -> Path:
        return self.directory / f"{self.tld}.previous.txt"

    def age_hours(self) -> float | None:
        if not self.current.exists():
            return None
        mtime = dt.datetime.fromtimestamp(self.current.stat().st_mtime, dt.timezone.utc)
        return (dt.datetime.now(dt.timezone.utc) - mtime).total_seconds() / 3600.0

    def save(self, names: set[str]) -> None:
        """Write a new snapshot, rotating the existing one to ``previous``."""
        self.directory.mkdir(parents=True, exist_ok=True)
        if self.current.exists():
            self.current.replace(self.previous)
        tmp = self.current.with_suffix(".tmp")
        tmp.write_text("\n".join(sorted(names)) + "\n", encoding="utf-8")
        tmp.replace(self.current)

    def load_current(self) -> set[str]:
        return load_zone_file(self.current, "names")

    def diff(self) -> tuple[set[str], set[str]]:
        """``(removed, added)`` between the previous and current snapshots.

        ``removed`` is the drop feed: names that were delegated yesterday and are not
        today. They are candidates for release, not proof of it -- RDAP still decides.
        """
        if not self.previous.exists() or not self.current.exists():
            return set(), set()
        before = load_zone_file(self.previous, "names")
        after = load_zone_file(self.current, "names")
        return before - after, after - before


class ZoneBackend:
    """Tier-1 substitute driven by the zone file. Same interface as the DNS probes."""

    def __init__(self, cfg: ZoneConfig, dns_concurrency: int = 1000) -> None:
        if not cfg.enabled:
            raise ConfigError("zone backend used while zone.enabled is false")
        if not cfg.acknowledge_terms:
            raise ConfigError(
                "zone.enabled is true but zone.acknowledge_terms is not set.\n\n"
                + TERMS
                + "\n\nSet zone.acknowledge_terms: true only if your use qualifies."
            )
        self.cfg = cfg
        self.snapshot = ZoneSnapshot(Path(cfg.snapshot_dir), cfg.tld)
        self._names: set[str] | None = None
        self._chunk = max(dns_concurrency, 1) * 8

    def refresh(self, *, force: bool = False) -> set[str]:
        """Obtain the delegated set, respecting the once-per-24h request."""
        if self.cfg.source == "file":
            return load_zone_file(Path(self.cfg.path), self.cfg.format, self.cfg.tld)

        age = self.snapshot.age_hours()
        if not force and age is not None and age < self.cfg.min_transfer_interval_hours:
            logger.info(
                "Reusing zone snapshot from %.1fh ago (Switch asks for at most one "
                "transfer per %dh)", age, self.cfg.min_transfer_interval_hours,
            )
            return self.snapshot.load_current()

        names = transfer_zone(self.cfg)
        self.snapshot.save(names)
        removed, added = self.snapshot.diff()
        if removed or added:
            logger.info(
                "Zone diff since last snapshot: %d name(s) left the zone, %d joined",
                len(removed), len(added),
            )
        return names

    @property
    def names(self) -> set[str]:
        if self._names is None:
            self._names = self.refresh()
        return self._names

    async def status(self, domain: str) -> NsStatus:
        return NsStatus.DELEGATED if domain in self.names else NsStatus.NO_DELEGATION

    async def sweep(
        self,
        candidates: Iterable[Candidate],
        *,
        on_batch: Callable[[list[tuple[Candidate, NsStatus]]], None] | None = None,
        progress_every: int = 250_000,
    ) -> SweepStats:
        """Membership-test every candidate against the zone. No queries are sent."""
        delegated = self.names
        stats = SweepStats()
        next_report = progress_every

        for chunk in _chunked(candidates, self._chunk):
            batch = [
                (c, NsStatus.DELEGATED if c.domain in delegated else NsStatus.NO_DELEGATION)
                for c in chunk
            ]
            for _, status in batch:
                stats.record(status)
            if on_batch is not None:
                on_batch(batch)
            if stats.checked >= next_report:
                logger.info("Zone sweep: %d checked", stats.checked)
                next_report = stats.checked + progress_every

        return stats
