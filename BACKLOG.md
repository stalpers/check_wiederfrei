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

## Performance: direct-to-authoritative DNS probe

**Designed, not built.** This is the highest-leverage change available and needs no new data
source or licence.

The measured ~20 answers/s (see README) is not a network limit — it is recursion overhead.
An `NS` lookup for `abc.ch` is answered by the `.ch` authoritative servers, and with 1.7M
*unique* names the recursive resolver's cache hit rate is effectively zero, so the sweep pays
a full recursion 1.7M times. Resolving the `.ch` `NS` set once and querying those servers
directly is one UDP round trip per name.

Expected 5–10x: at 200 qps the full space is ~2.4h and all 46,656 three-letter names take
~4 minutes.

**Response interpretation** is the part to get right — an authoritative server returns a
*referral* rather than following it:

| Authoritative response | Verdict |
|---|---|
| `NOERROR` + `NS` in the authority section (referral) | `DELEGATED` |
| `NXDOMAIN` | `NO_DELEGATION` |
| `NOERROR`, no answer, no authority `NS` (NODATA) | `NO_DELEGATION` |
| `SERVFAIL` / `REFUSED` / timeout | `UNKNOWN` |

`dns.resolver.Resolver` must **not** be used here — it follows referrals, which is exactly the
cost being removed. Use `dns.asyncquery.udp()`, with `dns.asyncquery.tcp()` fallback on `TC`,
EDNS0 enabled.

Implementation notes:

- Add `AuthoritativeNsProbe` to `src/wiederfrei/dns_probe.py` with the **same** `status()` /
  `sweep()` interface as `NsProbe`, so `pipeline.py` needs no change.
- Reuse `NsStatus`, `SweepStats` and `_chunked` from that module, `Store.record_ns_batch`
  from `state.py`, and `TokenBucket` from `rdap.py` — do not write a second rate limiter.
- Round-robin candidates across the `.ch` authoritatives with a per-server bucket.
- `dns.mode: authoritative | recursive` in config, keeping the recursive path as a fallback.
- Default to a modest total `qps` (100). DNS carries no `User-Agent`, so rate is the only
  politeness lever available.

**Verification gate:** run both probes over the same 2,000 names and assert identical
verdicts before trusting the new one. A faster probe that disagrees with the current one is a
bug, and this catches referral-handling mistakes immediately. Outbound DNS works in most
environments even where HTTPS egress is restricted, so this is testable without registry
access.

## Performance: zone-diff backend (opt-in, licence-gated)

**Designed, not built.** Replaces the entire DNS tier with one transfer, and the diff between
consecutive zone snapshots *is* a "recently released" feed — every name that left the zone
since yesterday. This is almost certainly how the original `@wiederfrei` bot worked.

- New `src/wiederfrei/zone.py`, emitting the same `(Candidate, NsStatus)` batches as the DNS
  tier so it substitutes for tier 1 without touching `pipeline.py` or the RDAP tier.
- Sources: TSIG-authenticated `AXFR` from `zonedata.switch.ch` via `dns.query.xfr`, or a path
  to an already-downloaded zone file.
- Presence in the zone ⇒ `DELEGATED`; absence ⇒ `NO_DELEGATION`, which RDAP confirms as today.
  The tier becomes a set membership test.
- **Licence gate:** `zone.enabled: false` by default, plus a separate explicit
  `zone.acknowledge_terms: true`, with SWITCH's wording quoted next to it. Refuse to run
  otherwise. The public [`antoinet/chzone`](https://github.com/antoinet/chzone) mirror
  restates the same terms — using a mirror does not launder the licence.
- Enforce SWITCH's one-transfer-per-24h request in code, against a stored timestamp.
- TSIG key and key name from the environment (`SWITCH_ZONE_TSIG_NAME`, `SWITCH_ZONE_TSIG_KEY`),
  never from YAML — same rule as the SMTP credentials.

## Open question: expiry-driven scheduling

If anonymous `.ch` RDAP returns an `expiration` event, this beats both designs above: query
each registered name's expiry once, then re-check only as names approach it, turning the
nightly job into a small scheduled queue. `.ch` drops are predictable enough for it — renewal
happens five days after expiry, and deletion must be flagged at least 30 days ahead.

Switch's docs only say *holder* and *technical contact* data is withheld from anonymous
callers, so this is genuinely unknown. One command settles it:

```bash
curl -s https://rdap.nic.ch/domain/nic.ch | jq '.events'
```

Worth answering before building the direct-to-authoritative probe.

## Considered and rejected

- **NSEC3 zone walking.** `.ch` is DNSSEC-signed, and NSEC3 hashes can be harvested and
  brute-forced offline — entirely tractable for 3–4 character labels. It works, but it
  deliberately circumvents an anti-enumeration measure the registry chose on purpose, and it
  is a good way to get an IP blocked.

## Smaller items

- **Tiered per-rule cadence.** Give each rule its own sweep interval so three-letter names
  (46,656) run nightly while the 1.68M four-character space runs weekly. Free performance —
  config plus a small scheduler — and it makes the short-domain alert useful immediately.
  Today the same effect is available manually via `--rule`.

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
