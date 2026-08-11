"""Alert payloads and the notifier interface.

The requirement driving this module's shape: *an alert must clearly state the rule that
fired it*. Rule attribution is therefore structured data (``Finding.rule_names`` plus
``Alert.rule_definitions``), not prose assembled at render time, so every transport
renders the same attribution and no transport can quietly drop it.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ..candidates import to_display
from ..errors import NotifyError
from ..ranking import RankInfo


@dataclass(frozen=True, slots=True)
class Finding:
    """One available domain and every rule that claims it."""

    domain: str
    label: str
    tld: str
    rule_names: list[str]
    confirmed_at: str
    rank: RankInfo | None = None

    @property
    def display(self) -> str:
        return to_display(self.domain)


@dataclass(slots=True)
class Alert:
    """A batch of findings, grouped for delivery."""

    findings: list[Finding]
    rule_definitions: dict[str, str] = field(default_factory=dict)
    generated_at: str = ""

    def __post_init__(self) -> None:
        if not self.generated_at:
            self.generated_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    @property
    def rule_names(self) -> list[str]:
        """Every rule that fired, in the order rules are defined."""
        ordered: list[str] = []
        for name in self.rule_definitions:
            if any(name in f.rule_names for f in self.findings):
                ordered.append(name)
        for finding in self.findings:
            for name in finding.rule_names:
                if name not in ordered:
                    ordered.append(name)
        return ordered

    def by_rule(self) -> dict[str, list[Finding]]:
        """Findings grouped by rule. A domain matching two rules appears under both."""
        grouped: dict[str, list[Finding]] = {name: [] for name in self.rule_names}
        for finding in self.findings:
            for name in finding.rule_names:
                grouped.setdefault(name, []).append(finding)
        return grouped

    def subject(self) -> str:
        n = len(self.findings)
        noun = "domain" if n == 1 else "domains"
        names = self.rule_names
        if len(names) == 1:
            attribution = names[0]
        else:
            attribution = f"{len(names)} rules"
        return f"[wiederfrei] {n} {noun} available — {attribution}"


@runtime_checkable
class Notifier(Protocol):
    name: str

    def send(self, alert: Alert) -> None:
        """Deliver the alert, or raise ``NotifyError``."""


_REGISTRY: dict[str, type] = {}


def register(name: str, cls: type) -> None:
    _REGISTRY[name] = cls


def build_notifiers(names: Iterable[str]) -> list[Notifier]:
    """Instantiate notifiers by config name, deduplicated, preserving order."""
    from . import console, email_smtp  # noqa: F401  (import registers the built-ins)

    out: list[Notifier] = []
    seen: set[str] = set()
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        try:
            cls = _REGISTRY[name]
        except KeyError:
            raise NotifyError(
                f"unknown notifier {name!r}; expected one of {sorted(_REGISTRY)}"
            ) from None
        out.append(cls())
    return out
