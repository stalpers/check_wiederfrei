"""Optional rank enrichment for alerts.

Ported from the original ``check_released_domains.py`` with its defects fixed:

* dict index instead of an O(domains x 11M) linear scan per lookup;
* ranks parsed as integers, not compared as strings;
* names normalised (lowercase, ``www.`` stripped, IDN to punycode) on both sides, so
  ``zürich.ch`` matches the ``xn--zrich-kva.ch`` the CSVs actually contain;
* symmetric missing-value handling;
* missing files are not fatal -- this is enrichment, not the point of the tool. The
  original called ``exit(99)``.
* the "Alexa" naming is gone: that CSV is the Cisco Umbrella top-1M (the URL in the old
  README was ``umbrella-static``), and Alexa itself was retired in 2022.

For 3-4 character names both lists are almost always a miss, which is why this is off by
default. ``intrinsic_score`` is the signal that actually discriminates short names, and
it needs no downloads.
"""

from __future__ import annotations

import csv
import logging
from dataclasses import dataclass
from pathlib import Path

from .candidates import ALPHA, DIGITS, normalise_domain
from .config import RankingConfig

logger = logging.getLogger(__name__)

VOWELS = frozenset("aeiou")


@dataclass(frozen=True, slots=True)
class RankInfo:
    """Whatever rank signals we could find. All fields optional."""

    umbrella_rank: int | None = None
    top10m_rank: int | None = None
    open_page_rank: float | None = None
    intrinsic: int = 0

    def summary(self) -> str:
        parts = [f"intrinsic {self.intrinsic}/100"]
        if self.umbrella_rank is not None:
            parts.append(f"Umbrella #{self.umbrella_rank:,}")
        if self.top10m_rank is not None:
            parts.append(f"Top10M #{self.top10m_rank:,}")
        if self.open_page_rank is not None:
            parts.append(f"OpenPageRank {self.open_page_rank:.2f}")
        return ", ".join(parts)


def intrinsic_score(label: str) -> int:
    """A cheap 0-100 desirability heuristic for a short label.

    Shorter is better, letters beat digits, hyphens hurt, and a vowel makes a name
    pronounceable. This deliberately does not pretend to be a valuation -- it just
    orders a batch of alerts so the interesting ones are at the top.
    """
    if not label:
        return 0
    score = 100

    score -= max(0, len(label) - 3) * 12

    digits = sum(1 for ch in label if ch in DIGITS)
    score -= digits * 15

    score -= label.count("-") * 20

    letters = [ch for ch in label if ch in ALPHA]
    if letters and not any(ch in VOWELS for ch in letters):
        score -= 10          # consonant clusters are hard to say and to sell

    return max(0, min(100, score))


class RankIndex:
    """Lazily-loaded dict indexes over the two rank CSVs."""

    def __init__(self, cfg: RankingConfig) -> None:
        self.cfg = cfg
        self._umbrella: dict[str, int] | None = None
        self._top10m: dict[str, tuple[int, float | None]] | None = None

    @property
    def enabled(self) -> bool:
        return self.cfg.enabled

    def _load_umbrella(self) -> dict[str, int]:
        index: dict[str, int] = {}
        path = self.cfg.umbrella_csv
        if path is None or not Path(path).exists():
            logger.info("Umbrella CSV not present; skipping that rank signal")
            return index
        # Umbrella top-1m has no header: rank,domain
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.reader(fh):
                if len(row) < 2:
                    continue
                try:
                    rank = int(row[0])
                except ValueError:
                    continue  # tolerates a header row if the format ever changes
                index.setdefault(normalise_domain(row[1], strip_www=True), rank)
        logger.info("Loaded %d Umbrella rows", len(index))
        return index

    def _load_top10m(self) -> dict[str, tuple[int, float | None]]:
        index: dict[str, tuple[int, float | None]] = {}
        path = self.cfg.top10m_csv
        if path is None or not Path(path).exists():
            logger.info("Top-10M CSV not present; skipping that rank signal")
            return index
        # DomCop top10milliondomains has a header: Rank,Domain,Open Page Rank
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.reader(fh)
            next(reader, None)
            for row in reader:
                if len(row) < 2:
                    continue
                try:
                    rank = int(row[0])
                except ValueError:
                    continue
                opr: float | None = None
                if len(row) > 2:
                    try:
                        opr = float(row[2])
                    except ValueError:
                        opr = None
                index.setdefault(normalise_domain(row[1], strip_www=True), (rank, opr))
        logger.info("Loaded %d Top-10M rows", len(index))
        return index

    def lookup(self, domain: str, label: str = "") -> RankInfo:
        """Rank signals for one domain. Always returns a value; never raises."""
        intrinsic = intrinsic_score(label or domain.split(".")[0])
        if not self.enabled:
            return RankInfo(intrinsic=intrinsic)

        if self._umbrella is None:
            self._umbrella = self._load_umbrella()
        if self._top10m is None:
            self._top10m = self._load_top10m()

        key = normalise_domain(domain, strip_www=True)
        top = self._top10m.get(key)
        return RankInfo(
            umbrella_rank=self._umbrella.get(key),
            top10m_rank=top[0] if top else None,
            open_page_rank=top[1] if top else None,
            intrinsic=intrinsic,
        )
