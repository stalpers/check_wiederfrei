"""Command-line interface."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from tabulate import tabulate

from . import __version__
from .candidates import Candidate, normalise_domain
from .config import DEFAULT_CONFIG_PATH, Config, load_config
from .errors import WiederfreiError
from .notify.base import Alert, Finding, build_notifiers
from .ranking import intrinsic_score
from .rdap import RdapClient
from .state import Store, utcnow

logger = logging.getLogger("wiederfrei")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        level=logging.DEBUG if verbose else logging.INFO,
        stream=sys.stderr,
    )


def _select_rules(cfg: Config, only: list[str] | None) -> None:
    """Disable every rule not named in ``--rule``. Mutates the loaded config."""
    if not only:
        return
    wanted = set(only)
    known = {r.name for r in cfg.rules}
    unknown = wanted - known
    if unknown:
        raise WiederfreiError(
            f"no such rule(s): {', '.join(sorted(unknown))}. Known rules: "
            f"{', '.join(sorted(known))}"
        )
    for rule in cfg.rules:
        rule.enabled = rule.enabled and rule.name in wanted


# --- commands -------------------------------------------------------------------


def cmd_rules(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    rows = []
    for rule in cfg.rules:
        count = rule.candidate_count()
        if count is None:
            shown = "filter only"
        elif count == 0:
            shown = "0  <-- will never fire"
        else:
            shown = f"{count:,}"
        rows.append([
            rule.name,
            "yes" if rule.enabled else "no",
            shown,
            ", ".join(rule.notify),
            rule.describe(),
        ])
    print(tabulate(rows, headers=["Rule", "Enabled", "Candidates", "Notify", "Definition"],
                   tablefmt="outline"))

    for rule in cfg.rules:
        if rule.enabled and rule.candidate_count() == 0:
            logger.warning("Rule %r generates no candidates and can never fire", rule.name)
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    if not Path(cfg.state_path).exists():
        print(f"No state yet at {cfg.state_path} - run a sweep first.")
        return 0
    with Store(cfg.state_path) as store:
        counts = store.counts()
        print(tabulate(sorted(counts.items()), headers=["Metric", "Count"], tablefmt="outline"))
        runs = store.conn.execute(
            "SELECT id, started_at, finished_at, dns_checked, rdap_checked, alerts_sent "
            "FROM runs ORDER BY id DESC LIMIT 10"
        ).fetchall()
        if runs:
            print("\nRecent runs:")
            print(tabulate([tuple(r) for r in runs],
                           headers=["#", "Started", "Finished", "DNS", "RDAP", "Alerts"],
                           tablefmt="outline"))
    return 0


def cmd_alerts(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    if not Path(cfg.state_path).exists():
        print(f"No state yet at {cfg.state_path} - run a sweep first.")
        return 0
    with Store(cfg.state_path) as store:
        rows = [tuple(r) for r in store.list_alerts(args.limit)]
    if not rows:
        print("No alerts recorded yet.")
        return 0
    print(tabulate(rows, headers=["Domain", "Rule", "First alerted", "Last alerted"],
                   tablefmt="outline"))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """One-off RDAP lookups. The quickest end-to-end confirmation that RDAP works."""
    cfg = load_config(args.config)

    candidates = []
    for raw in args.domains:
        domain = normalise_domain(raw)
        if "." not in domain:
            raise WiederfreiError(f"{raw!r} is not a fully qualified domain name")
        label, tld = domain.rsplit(".", 1)
        candidates.append(Candidate(domain=domain, label=label, tld=tld))

    async def run() -> list:
        async with RdapClient(cfg.rdap) as client:
            return await client.check_many(candidates)

    results = asyncio.run(run())
    rows = [
        [r.candidate.domain, r.status.value, r.http_status or "-", r.detail or "-",
         intrinsic_score(r.candidate.label)]
        for r in results
    ]
    print(tabulate(rows, headers=["Domain", "Status", "HTTP", "Detail", "Intrinsic"],
                   tablefmt="outline"))
    return 0


def cmd_notify_test(args: argparse.Namespace) -> int:
    """Send a fixture alert so you can confirm delivery and rule attribution."""
    cfg = load_config(args.config)
    rules = cfg.enabled_rules()
    if not rules:
        raise WiederfreiError("no enabled rules to attribute the test alert to")
    rule = rules[0]

    alert = Alert(
        findings=[
            Finding(
                domain=f"test-fixture.{rule.tlds[0]}",
                label="test-fixture",
                tld=rule.tlds[0],
                rule_names=[rule.name],
                confirmed_at=utcnow(),
                rank=None,
            )
        ],
        rule_definitions={r.name: r.describe() for r in rules},
    )

    notifiers = build_notifiers(args.via or rule.notify)
    for notifier in notifiers:
        notifier.send(alert)
        logger.info("Test alert sent via %s", notifier.name)
    return 0


def cmd_sweep(args: argparse.Namespace) -> int:
    from .pipeline import run_sweep

    cfg = load_config(args.config)
    _select_rules(cfg, args.rule)

    rules = cfg.enabled_rules()
    if not rules:
        raise WiederfreiError("no enabled rules")

    notifiers = []
    if not args.dry_run:
        names = [n for r in rules for n in r.notify]
        notifiers = build_notifiers(names)

    with Store(cfg.state_path) as store:
        report = asyncio.run(
            run_sweep(
                cfg,
                store,
                notifiers=notifiers,
                limit=args.limit,
                dry_run=args.dry_run,
                skip_dns=args.skip_dns,
            )
        )

    logger.info(
        "Sweep complete: DNS %d checked / RDAP %d checked / %d available / %d alerted "
        "(%d already known)",
        report.dns_checked, report.rdap_checked, report.available,
        report.alerts_sent, report.skipped_already_alerted,
    )
    return 0


# --- parser ---------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wiederfrei",
        description="Find and alert on available .ch domains matching configurable rules.",
    )
    parser.add_argument("--version", action="version", version=f"wiederfrei {__version__}")
    parser.add_argument(
        "-c", "--config", type=Path, default=DEFAULT_CONFIG_PATH,
        help=f"path to the rules file (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")

    sub = parser.add_subparsers(dest="command", required=True)

    p_sweep = sub.add_parser("sweep", help="run the full check and alert on new findings")
    p_sweep.add_argument("--limit", type=int, default=None,
                         help="check at most N candidates (for smoke tests)")
    p_sweep.add_argument("--dry-run", action="store_true",
                         help="print the alert instead of sending it; records no alerts")
    p_sweep.add_argument("--skip-dns", action="store_true",
                         help="reuse cached NS results and run only the RDAP tier")
    p_sweep.add_argument("--rule", action="append", default=None,
                         help="only run this rule (repeatable)")
    p_sweep.set_defaults(func=cmd_sweep)

    p_check = sub.add_parser("check", help="RDAP-check one or more domains right now")
    p_check.add_argument("domains", nargs="+")
    p_check.set_defaults(func=cmd_check)

    p_rules = sub.add_parser("rules", help="list configured rules and their candidate counts")
    p_rules.set_defaults(func=cmd_rules)

    p_alerts = sub.add_parser("alerts", help="list alerts already sent")
    p_alerts.add_argument("--limit", type=int, default=100)
    p_alerts.set_defaults(func=cmd_alerts)

    p_stats = sub.add_parser("stats", help="show state and recent runs")
    p_stats.set_defaults(func=cmd_stats)

    p_test = sub.add_parser("notify-test", help="send a fixture alert to check delivery")
    p_test.add_argument("--via", action="append", default=None,
                        help="notifier to use (default: the first rule's). Repeatable.")
    p_test.set_defaults(func=cmd_notify_test)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)
    try:
        return int(args.func(args))
    except WiederfreiError as exc:
        logger.error("%s", exc)
        return 2
    except KeyboardInterrupt:
        logger.warning("Interrupted; progress up to the last committed batch is saved")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
