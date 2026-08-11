"""The sweep: candidates -> DNS tier -> RDAP tier -> attributed alerts."""

from __future__ import annotations

import itertools
import logging
from collections.abc import Iterator
from dataclasses import dataclass, field

from .candidates import Candidate, iter_candidates, matching_rules
from .config import Config
from .dns_probe import NsProbe, NsStatus
from .notify.base import Alert, Finding, Notifier
from .ranking import RankIndex
from .rdap import RdapClient, RdapStatus
from .state import Store, utcnow

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SweepReport:
    dns_checked: int = 0
    dns_delegated: int = 0
    dns_no_delegation: int = 0
    dns_unknown: int = 0
    rdap_checked: int = 0
    available: int = 0
    alerts_sent: int = 0
    findings: list[Finding] = field(default_factory=list)
    skipped_already_alerted: int = 0


def _candidate_stream(cfg: Config, limit: int | None) -> Iterator[Candidate]:
    stream = iter_candidates(cfg.enabled_rules())
    if limit is not None:
        stream = itertools.islice(stream, limit)
    return stream


async def run_sweep(
    cfg: Config,
    store: Store,
    *,
    notifiers: list[Notifier],
    limit: int | None = None,
    dry_run: bool = False,
    skip_dns: bool = False,
) -> SweepReport:
    """Run one full sweep and deliver any new findings."""
    report = SweepReport()
    rules = cfg.enabled_rules()
    if not rules:
        logger.warning("No enabled rules; nothing to do")
        return report

    run_id = store.start_run()

    # --- Tier 1: DNS ------------------------------------------------------------
    if skip_dns:
        logger.info("Skipping DNS sweep; using cached NS status from previous runs")
    else:
        probe = NsProbe(cfg.dns)
        logger.info(
            "DNS sweep starting over %s candidate names",
            f"{sum(r.candidate_count() or 0 for r in rules):,}" if limit is None else f"<={limit:,}",
        )
        stats = await probe.sweep(
            _candidate_stream(cfg, limit),
            on_batch=store.record_ns_batch,
        )
        report.dns_checked = stats.checked
        report.dns_delegated = stats.delegated
        report.dns_no_delegation = stats.no_delegation
        report.dns_unknown = stats.unknown
        logger.info(
            "DNS sweep done: %d checked, %d delegated, %d without delegation, %d unknown",
            stats.checked, stats.delegated, stats.no_delegation, stats.unknown,
        )

    # --- Tier 2: RDAP -----------------------------------------------------------
    queue = store.rdap_queue(
        recheck_after_days=cfg.rdap.recheck_after_days,
        limit=cfg.rdap.max_per_run,
    )
    logger.info(
        "RDAP tier: %d name(s) to confirm (cap %d/run at %.1f req/s)",
        len(queue), cfg.rdap.max_per_run, cfg.rdap.rate_limit_per_second,
    )

    ranker = RankIndex(cfg.ranking)
    available: list[Finding] = []

    if queue:
        async with RdapClient(cfg.rdap) as client:
            for chunk_start in range(0, len(queue), 50):
                chunk = queue[chunk_start : chunk_start + 50]
                candidates = [Candidate(r.domain, r.label, r.tld) for r in chunk]
                results = await client.check_many(candidates)
                for result in results:
                    report.rdap_checked += 1
                    # Committed per result so an interrupted run keeps its progress.
                    store.record_rdap(result.candidate.domain, result.status)
                    if result.status is not RdapStatus.AVAILABLE:
                        continue
                    report.available += 1
                    names = matching_rules(result.candidate.label, result.candidate.tld, rules)
                    if not names:
                        continue
                    available.append(
                        Finding(
                            domain=result.candidate.domain,
                            label=result.candidate.label,
                            tld=result.candidate.tld,
                            rule_names=names,
                            confirmed_at=utcnow(),
                            rank=ranker.lookup(result.candidate.domain, result.candidate.label),
                        )
                    )

    # --- Alerting ---------------------------------------------------------------
    fresh: list[Finding] = []
    for finding in available:
        new_rules = store.unalerted_rules(finding.domain, finding.rule_names)
        if not new_rules:
            report.skipped_already_alerted += 1
            continue
        # Attribute only the rules that have not already been notified for this domain.
        fresh.append(
            Finding(
                domain=finding.domain,
                label=finding.label,
                tld=finding.tld,
                rule_names=new_rules,
                confirmed_at=finding.confirmed_at,
                rank=finding.rank,
            )
        )

    report.findings = fresh

    if fresh:
        alert = Alert(
            findings=fresh,
            rule_definitions={r.name: r.describe() for r in rules},
        )
        if dry_run:
            from .notify.console import render_text

            print(render_text(alert))
            logger.info("Dry run: %d finding(s) not recorded and no email sent", len(fresh))
        elif not notifiers:
            # Recording these as alerted would bury them silently, so don't.
            logger.warning(
                "%d finding(s) but no notifiers configured; not recording them as "
                "alerted. Add a 'notify:' target to your rules.", len(fresh),
            )
        else:
            for notifier in notifiers:
                notifier.send(alert)
            # Only now is the alert durable -- a failed send raises above and leaves the
            # finding unrecorded, so the next run reports it again.
            for finding in fresh:
                for rule_name in finding.rule_names:
                    store.record_alert(finding.domain, rule_name)
            report.alerts_sent = len(fresh)
    else:
        logger.info("No new available domains to report")

    store.finish_run(
        run_id,
        dns_checked=report.dns_checked,
        rdap_checked=report.rdap_checked,
        alerts_sent=report.alerts_sent,
        note="dry run" if dry_run else "",
    )

    return report
