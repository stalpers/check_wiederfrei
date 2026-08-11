"""The rule engine.

A rule does two things: it may *generate* a candidate space, and it *decides* whether a
given label belongs to it. Length rules do both. Filter-only rules (the regex rules added
in phase 2) return ``None`` from ``candidates()`` and only ever decide, which is why
attribution is computed separately from generation -- see ``candidates.matching_rules``.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .candidates import CHARSETS, count_labels, is_valid_label, iter_labels
from .errors import ConfigError

CHARSET_DISPLAY = {
    "alpha": "a-z",
    "alnum": "a-z0-9",
    "alnum_hyphen": "a-z0-9 and hyphen",
}


@runtime_checkable
class Rule(Protocol):
    """What the pipeline needs from any rule type."""

    name: str
    tlds: list[str]
    enabled: bool
    notify: list[str]

    def candidates(self) -> Iterator[str] | None:
        """Labels this rule generates, or ``None`` if it is filter-only."""

    def matches(self, label: str) -> bool:
        """Whether this rule claims ``label``."""

    def describe(self) -> str:
        """One-line human definition, quoted verbatim in alerts."""

    def candidate_count(self) -> int | None:
        """Size of the generated space, or ``None`` if filter-only."""


@dataclass(slots=True)
class LengthRule:
    """Matches every label within a length range over a fixed character set."""

    name: str
    tlds: list[str]
    min_length: int
    max_length: int
    charset: str = "alnum"
    enabled: bool = True
    notify: list[str] = field(default_factory=lambda: ["email"])

    def candidates(self) -> Iterator[str]:
        return iter_labels(self.charset, self.min_length, self.max_length)

    def matches(self, label: str) -> bool:
        if not self.min_length <= len(label) <= self.max_length:
            return False
        allowed = CHARSETS[self.charset]
        if any(ch not in allowed for ch in label):
            return False
        return is_valid_label(label)

    def describe(self) -> str:
        tlds = ", ".join(f".{t}" for t in self.tlds)
        chars = CHARSET_DISPLAY.get(self.charset, self.charset)
        return (
            f"length rule: {self.min_length}-{self.max_length} characters, "
            f"charset {chars}, {tlds}"
        )

    def candidate_count(self) -> int:
        return count_labels(self.charset, self.min_length, self.max_length) * len(self.tlds)

    @classmethod
    def from_config(cls, cfg: dict[str, Any], name: str, tlds: list[str],
                    enabled: bool, notify: list[str]) -> LengthRule:
        try:
            min_length = int(cfg["min_length"])
            max_length = int(cfg["max_length"])
        except KeyError as exc:
            raise ConfigError(
                f"rule {name!r}: length rules require {exc.args[0]!r}"
            ) from None
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"rule {name!r}: length must be an integer ({exc})") from None

        if min_length < 1:
            raise ConfigError(f"rule {name!r}: min_length must be at least 1")
        if max_length < min_length:
            raise ConfigError(
                f"rule {name!r}: max_length ({max_length}) is below "
                f"min_length ({min_length})"
            )

        charset = str(cfg.get("charset", "alnum"))
        if charset not in CHARSETS:
            raise ConfigError(
                f"rule {name!r}: unknown charset {charset!r}; "
                f"expected one of {sorted(CHARSETS)}"
            )
        return cls(
            name=name,
            tlds=tlds,
            min_length=min_length,
            max_length=max_length,
            charset=charset,
            enabled=enabled,
            notify=notify,
        )


#: Rule ``type:`` values recognised in rules.yaml. Phase 2 registers "regex" here.
RULE_TYPES = {
    "length": LengthRule.from_config,
}


def build_rule(cfg: dict[str, Any], defaults: dict[str, Any]) -> Rule:
    """Construct one rule from its YAML mapping, applying ``defaults``."""
    if not isinstance(cfg, dict):
        raise ConfigError(f"each entry under 'rules' must be a mapping, got {type(cfg).__name__}")

    name = str(cfg.get("name", "")).strip()
    if not name:
        raise ConfigError("every rule needs a non-empty 'name' (alerts are attributed by it)")

    rule_type = str(cfg.get("type", "")).strip()
    if rule_type not in RULE_TYPES:
        known = sorted(RULE_TYPES)
        raise ConfigError(
            f"rule {name!r}: unknown type {rule_type!r}; expected one of {known}"
        )

    tlds = cfg.get("tlds", defaults.get("tlds", ["ch"]))
    if isinstance(tlds, str):
        tlds = [tlds]
    tlds = [str(t).lower().lstrip(".") for t in tlds]
    if not tlds:
        raise ConfigError(f"rule {name!r}: 'tlds' must list at least one TLD")

    notify = cfg.get("notify", defaults.get("notify", ["email"]))
    if isinstance(notify, str):
        notify = [notify]
    notify = [str(n) for n in notify]

    enabled = bool(cfg.get("enabled", True))

    return RULE_TYPES[rule_type](cfg, name, tlds, enabled, notify)
