# Backlog

Phase 1 (short-domain rules, RDAP verification, SQLite state, email alerts) is
implemented. What follows is not.

## Phase 2 — regex rules

Adds a second rule type. No change to the engine, DNS, RDAP, state, or notifier layers —
`RULE_TYPES` in `src/wiederfrei/rules.py` is the only registration point.

```yaml
- name: "Swiss city names"
  type: regex
  tlds: [ch]
  pattern: '^(zuerich|basel|bern|luzern|genf)$'
```

Work:

- `RegexRule` — compile the pattern at config load so an invalid one fails with a clear
  error naming the rule, not a traceback mid-sweep.
- `enumerate_from: wordlist` plus a `wordlist:` path, for regex rules that should widen
  the candidate universe rather than only filter it.
- Per-rule `realert_after_days`, so a name that is *still* available can be re-reported
  after an interval instead of only once.
- `wiederfrei rules` already reports candidate counts and warns on zero; extend the
  warning to regex rules that match nothing in the current universe.

**The constraint to design around:** a regex over an unbounded space cannot discover
anything by itself — `^.*shop$` has infinitely many members. `RegexRule.candidates()`
therefore returns `None`, and the rule filters the universe the length rules generate.
A regex matching nothing in that universe will silently never fire, which is why the
zero-candidate warning matters.

## Phase 3 — more TLDs

Currently `.ch` and `.li` work because Switch serves RDAP for both from `rdap.nic.ch`,
which is hardcoded as a default in `config.py`. Going wider needs:

- **RDAP endpoint discovery** via the IANA bootstrap registry
  (`https://data.iana.org/rdap/dns.json`), cached locally, instead of a static map.
- **Per-registry rate limits and terms review.** Limits vary by orders of magnitude, and
  some registries explicitly forbid availability mining. This is a per-TLD decision, not
  a global setting — `RdapConfig.rate_limit_per_second` would need to become per-endpoint.
- **WHOIS port-43 fallback** for TLDs with no RDAP service.
- **Per-TLD charset, length and IDN rules.** Minimum label length, permitted characters,
  and IDN tables all differ; the current `alpha`/`alnum`/`alnum_hyphen` sets are a `.ch`
  simplification.
- **Candidate-space scheduling.** 3–4 characters across 20 TLDs is roughly 35M DNS
  queries per pass. At the throughput measured in the README that is weeks, so TLDs would
  need to be swept on a rotation rather than all every run.

`.li` is nearly free to add today — same RDAP host, same rules, just add it to a rule's
`tlds:`.

## Smaller items

- **Zone-file fast path.** Switch publishes the `.ch`/`.li` zone by TSIG-authenticated
  `AXFR` from `zonedata.switch.ch` (max one transfer per 24h). It would replace the
  multi-hour DNS tier with a single transfer and a set subtraction. Deliberately not
  implemented: access is licensed for *"combating cybercrime, scientific and social
  research, or other purposes in the public interest"*, which domain hunting plausibly is
  not. If you obtain access for a qualifying purpose, it implements the same interface as
  `dns_probe.py`.
- **Cloudflare Radar ranking.** The only mainstream list with per-country ranking,
  including Switzerland — a much better fit than Umbrella's global DNS-volume ordering.
  Needs an API token.
- **Wayback CDX enrichment.** Snapshot count and first/last capture date, free and
  keyless. For a name that *was* in use, this is a better value signal than any backlink
  metric.
- **More notifiers.** The `Notifier` protocol and registry in `notify/base.py` already
  support this; a Slack or Telegram transport is one small module plus a `register()` call.
- **Structured output.** `--json` on `sweep` and `alerts`, for piping into other tooling.
