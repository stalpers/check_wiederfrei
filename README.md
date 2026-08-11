# wiederfrei

Find `.ch` domain names that are **actually available right now**, matching rules you
define, and get emailed when one turns up.

Availability is confirmed against the registry over RDAP before anything is reported.
The only outcome that produces an alert is an explicit "not registered" answer from
Switch — a timeout, a rate-limit, or a broken network can never turn into a false alert.

## What changed from the original

The previous version of this repo read a Mastodon bot (`@wiederfrei@botsin.space`) for
`.ch`/`.li` domains announced as freed, and looked each one up in two static rank CSVs.
That approach no longer works and did less than it appeared to:

- **It never checked availability.** It trusted the bot and printed names as free
  without ever asking a registry.
- **Its data source is gone.** `botsin.space` went read-only in December 2024 and has
  since closed, so the account lookup fails outright.
- **A feed can only report the moment of a drop.** It can never tell you that a
  three-letter domain has been sitting unregistered for two years.
- Freshly dropped `.ch` names are first-come-first-served with no auction, so the good
  ones are gone in seconds — a batch script reading one page of a social feed was never
  going to win that race.

This version enumerates the candidate space itself and verifies every hit with the
registry. It targets *standing* availability — names nobody has taken — so there is no
race to lose.

## How it works

Two tiers, because checking 1.7 million names by RDAP would be neither feasible nor
polite:

1. **DNS `NS` sweep** — cheap, covers everything. A name with `NS` records is definitely
   registered, so it is ruled out. Absence of `NS` proves nothing (a name can be
   registered without being delegated), so it is only ever a referral to tier 2.
2. **RDAP `HEAD`** — authoritative, rate-limited. `HEAD https://rdap.nic.ch/domain/<name>`
   returns `200` for registered and `404` for not registered. This is the documented
   Switch mechanism for testing registration without retrieving registration data.

Verdicts are cached in SQLite with a TTL, so steady-state RDAP volume stays in the low
hundreds per run: only names that newly lost delegation, names already known available,
and a slow rotation through the rest are re-queried.

## Install

Requires **Python 3.11+**.

```bash
pip install -e .
```

## Configure

```bash
cp rules.example.yaml rules.yaml     # rules and operational settings
cp .env.example .env                 # SMTP credentials
```

Rules live in `rules.yaml`. Credentials never do — they come from the environment.

```yaml
rules:
  - name: "Short .ch domains (3-4 chars)"
    type: length
    tlds: [ch]
    min_length: 3
    max_length: 4
    charset: alnum        # alpha | alnum | alnum_hyphen
    notify: [email]
```

Rules may overlap. A domain matching several is checked once, and **every** matching rule
is named in the alert.

Check what a rule will actually do before running it:

```bash
wiederfrei rules
```

```
+--------------------------------+-----------+--------------+----------+--------------------------------------------------+
| Rule                           | Enabled   |   Candidates | Notify   | Definition                                       |
+================================+===========+==============+==========+==================================================+
| Short .ch domains (3-4 chars)  | yes       |    1,726,272 | email    | length rule: 3-4 characters, charset a-z0-9, .ch |
| Three-letter .ch domains (a-z) | yes       |       17,576 | email    | length rule: 3-3 characters, charset a-z, .ch    |
+--------------------------------+-----------+--------------+----------+--------------------------------------------------+
```

## Use

```bash
wiederfrei check abc.ch xyz.ch      # one-off RDAP lookup, right now
wiederfrei sweep --limit 2000 --dry-run   # smoke test: prints alerts, sends and saves nothing
wiederfrei sweep                    # the real thing
wiederfrei notify-test              # send a fixture alert to check SMTP and formatting
wiederfrei alerts                   # what has already been reported
wiederfrei stats                    # state and recent runs
```

Useful flags: `--rule "name"` to run one rule, `--skip-dns` to re-run only the RDAP tier
against cached DNS results, `-c path` for a different config.

## Sizing the sweep — read this before the first run

The 3–4 character `a-z0-9` space for `.ch` is **1,726,272 names**. How long a full sweep
takes is set almost entirely by your DNS resolver.

Measured against a stock container resolver (1,000 three-letter `.ch` names):

| `dns.concurrency` | Throughput | Timed out (`unknown`) |
|---|---|---|
| 25 | 20 names/s | 5% |
| 75 | 26 names/s | 15% |
| 150 | 29 names/s | 28% |
| 300 | — | 45% |

Throughput plateaus around 20 *useful* answers/s while the error rate climbs — extra
concurrency past what the resolver can serve just converts answers into timeouts. At that
rate a full sweep takes over a day.

**Run a local caching resolver** (`unbound`, `dnsmasq`) and point `dns.resolvers` at it.
That is worth far more than a high concurrency setting. Then tune by watching the
`unknown` count the sweep logs: if it is more than a few percent, lower `dns.concurrency`.

Timeouts are safe — an `unknown` is never reported as available, and the name is simply
swept again on the next run — but a high rate means you are re-doing work.

The first run is also the expensive one for RDAP, since every undelegated name needs a
verdict. Progress is committed incrementally, so an interrupted run resumes rather than
restarting.

## Scheduling with cron

```cron
# Nightly at 02:15. Give it a generous window; a full sweep is hours, not minutes.
15 2 * * *  cd /srv/wiederfrei && set -a && . ./.env && set +a && \
            /srv/wiederfrei/.venv/bin/wiederfrei sweep >> /var/log/wiederfrei.log 2>&1
```

State lives in the SQLite file named by `state_path`. Back it up if the alert history
matters to you; deleting it makes the next run re-report everything it finds.

## Being a good citizen

Availability mining is exactly the traffic pattern registries throttle. Defaults are
deliberately conservative: **2 requests/second**, `Retry-After` honoured on `429`,
exponential backoff with jitter, a hard `rdap.max_per_run` cap, and a `User-Agent` that
identifies the tool. Set `rdap.contact` to your email so Switch can reach you rather than
silently blocking you.

Please do not raise the rate limit without a reason. A slower sweep beats a blocked IP.

Note also that Switch publishes the `.ch` zone file as open data, which would replace the
entire DNS tier with a single transfer — but access is licensed for *"combating
cybercrime, scientific and social research, or other purposes in the public interest"*,
which domain hunting plausibly is not. This tool deliberately uses the DNS sweep instead.
If you hold zone access for a qualifying purpose, it slots in behind the same interface.

## Optional: rank enrichment

Off by default. If you have the CSVs, set `ranking.enabled: true` and point at them:

- Cisco Umbrella top-1M — `http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip`
- DomCop top 10M / Open PageRank — `https://www.domcop.com/files/top/top10milliondomains.csv.zip`

(The original README called the first of these "Alexa". It is not — the URL is Cisco's
Umbrella list, and Alexa itself was retired in 2022.)

Both are poor fits for this job: Umbrella ranks by global DNS query volume, so a domain
that matters only in Switzerland barely registers, and short names are essentially never
in either list. The signal that actually discriminates short names is the built-in
`intrinsic` score — length, letters over digits, no hyphens, pronounceable — which needs
no downloads and is always shown.

If you want better ranking data, **Cloudflare Radar** is the one worth adding: it is the
only mainstream list with per-country ranking, including Switzerland.

## Development

```bash
pip install -e '.[dev]'
pytest
```

The suite is fully offline — DNS and RDAP are mocked — and covers candidate-space sizes,
RDAP status handling including `429`, IDN/punycode normalisation, alert de-duplication,
and rule attribution in both the text and HTML email parts.

## Roadmap

Regex rules are next; more TLDs are on the backlog. See [BACKLOG.md](BACKLOG.md).

## Licence

Apache 2.0 — see [LICENSE](LICENSE).
