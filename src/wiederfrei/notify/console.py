"""Console notifier -- used for local runs and ``--dry-run``."""

from __future__ import annotations

import sys

from tabulate import tabulate

from .base import Alert, register


def render_text(alert: Alert) -> str:
    """Plain-text alert body, grouped by rule. Shared with the email notifier."""
    lines = [alert.subject(), "=" * len(alert.subject()), ""]
    lines.append(f"Checked at {alert.generated_at} (UTC), confirmed by RDAP.")
    lines.append("")

    for rule_name, findings in alert.by_rule().items():
        definition = alert.rule_definitions.get(rule_name, "")
        lines.append(f"Rule: {rule_name}")
        if definition:
            lines.append(f"  {definition}")
        lines.append("")

        rows = []
        for f in sorted(findings, key=lambda x: (-(x.rank.intrinsic if x.rank else 0), x.domain)):
            others = [r for r in f.rule_names if r != rule_name]
            rows.append([
                f.display,
                f.confirmed_at,
                ", ".join(others) if others else "-",
                f.rank.summary() if f.rank else "-",
            ])
        lines.append(
            tabulate(
                rows,
                headers=["Domain", "Confirmed available (UTC)", "Also matched", "Signals"],
                tablefmt="outline",
            )
        )
        lines.append("")

    lines.append(
        "Availability was confirmed by an RDAP query to the registry at the time above. "
        "These names are first-come, first-served -- verify with your registrar before acting."
    )
    return "\n".join(lines)


class ConsoleNotifier:
    name = "console"

    def send(self, alert: Alert) -> None:
        print(render_text(alert), file=sys.stdout)


register("console", ConsoleNotifier)
