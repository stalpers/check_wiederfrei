"""Configuration loading.

Rules and operational knobs come from a YAML file (git-tracked). Secrets come from the
environment only -- nothing in ``rules.yaml`` is ever a credential.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import USER_AGENT_DEFAULT
from .errors import ConfigError
from .rules import Rule, build_rule

DEFAULT_CONFIG_PATH = Path("rules.yaml")

#: Switch serves RDAP for both .ch and .li from the same host.
DEFAULT_RDAP_ENDPOINTS = {
    "ch": "https://rdap.nic.ch",
    "li": "https://rdap.nic.ch",
}


@dataclass(slots=True)
class DnsConfig:
    # Conservative on purpose: past what the resolver can serve, extra concurrency
    # produces timeouts rather than throughput. See rules.example.yaml for measurements.
    concurrency: int = 50
    timeout: float = 3.0
    lifetime: float = 6.0
    resolvers: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RdapConfig:
    endpoints: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_RDAP_ENDPOINTS))
    rate_limit_per_second: float = 2.0
    max_per_run: int = 2000
    timeout: float = 15.0
    max_retries: int = 4
    recheck_after_days: int = 7
    contact: str = ""

    def user_agent(self) -> str:
        if self.contact:
            return f"{USER_AGENT_DEFAULT} contact={self.contact}"
        return USER_AGENT_DEFAULT

    def endpoint_for(self, tld: str) -> str:
        try:
            return self.endpoints[tld].rstrip("/")
        except KeyError:
            raise ConfigError(
                f"no RDAP endpoint configured for .{tld}; add one under rdap.endpoints"
            ) from None


@dataclass(slots=True)
class RankingConfig:
    """Rank enrichment is optional -- absent files are logged once, never fatal."""

    umbrella_csv: Path | None = None
    top10m_csv: Path | None = None
    enabled: bool = False


@dataclass(slots=True)
class EmailConfig:
    host: str
    port: int
    username: str
    password: str
    sender: str
    recipients: list[str]
    starttls: bool
    use_ssl: bool
    timeout: float


@dataclass(slots=True)
class Config:
    rules: list[Rule]
    dns: DnsConfig
    rdap: RdapConfig
    ranking: RankingConfig
    state_path: Path
    source_path: Path

    def enabled_rules(self) -> list[Rule]:
        return [r for r in self.rules if r.enabled]


def _as_mapping(value: Any, where: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"'{where}' must be a mapping, got {type(value).__name__}")
    return value


def load_config(path: Path | str = DEFAULT_CONFIG_PATH) -> Config:
    """Read and validate the rules file."""
    path = Path(path)
    if not path.exists():
        raise ConfigError(
            f"config file {path} not found -- copy rules.example.yaml to {path} to get started"
        )
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from None

    raw = _as_mapping(raw, str(path))
    defaults = _as_mapping(raw.get("defaults"), "defaults")

    rule_entries = raw.get("rules")
    if not rule_entries:
        raise ConfigError(f"{path} defines no rules under 'rules'")
    if not isinstance(rule_entries, list):
        raise ConfigError("'rules' must be a list")

    rules = [build_rule(entry, defaults) for entry in rule_entries]

    seen: set[str] = set()
    for rule in rules:
        if rule.name in seen:
            raise ConfigError(
                f"duplicate rule name {rule.name!r}; names must be unique because "
                "alerts are attributed by them"
            )
        seen.add(rule.name)

    dns_raw = _as_mapping(raw.get("dns"), "dns")
    dns = DnsConfig(
        concurrency=int(dns_raw.get("concurrency", 300)),
        timeout=float(dns_raw.get("timeout", 3.0)),
        lifetime=float(dns_raw.get("lifetime", 6.0)),
        resolvers=[str(r) for r in dns_raw.get("resolvers", [])],
    )
    if dns.concurrency < 1:
        raise ConfigError("dns.concurrency must be at least 1")

    rdap_raw = _as_mapping(raw.get("rdap"), "rdap")
    endpoints = dict(DEFAULT_RDAP_ENDPOINTS)
    endpoints.update(
        {
            str(k).lower().lstrip("."): str(v)
            for k, v in _as_mapping(rdap_raw.get("endpoints"), "rdap.endpoints").items()
        }
    )
    rdap = RdapConfig(
        endpoints=endpoints,
        rate_limit_per_second=float(rdap_raw.get("rate_limit_per_second", 2.0)),
        max_per_run=int(rdap_raw.get("max_per_run", 2000)),
        timeout=float(rdap_raw.get("timeout", 15.0)),
        max_retries=int(rdap_raw.get("max_retries", 4)),
        recheck_after_days=int(rdap_raw.get("recheck_after_days", 7)),
        contact=str(rdap_raw.get("contact", "")),
    )
    if rdap.rate_limit_per_second <= 0:
        raise ConfigError("rdap.rate_limit_per_second must be greater than 0")
    if rdap.max_per_run < 1:
        raise ConfigError("rdap.max_per_run must be at least 1")

    # Every TLD referenced by a rule needs somewhere to send RDAP queries.
    for rule in rules:
        for tld in rule.tlds:
            if tld not in rdap.endpoints:
                raise ConfigError(
                    f"rule {rule.name!r} targets .{tld} but no RDAP endpoint is "
                    "configured for it; add one under rdap.endpoints"
                )

    rank_raw = _as_mapping(raw.get("ranking"), "ranking")
    umbrella = rank_raw.get("umbrella_csv")
    top10m = rank_raw.get("top10m_csv")
    ranking = RankingConfig(
        umbrella_csv=Path(umbrella) if umbrella else None,
        top10m_csv=Path(top10m) if top10m else None,
        enabled=bool(rank_raw.get("enabled", False)),
    )

    state_path = Path(str(raw.get("state_path", "wiederfrei.db")))

    return Config(
        rules=rules,
        dns=dns,
        rdap=rdap,
        ranking=ranking,
        state_path=state_path,
        source_path=path,
    )


def _env_bool(env: dict[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def load_email_config(env: dict[str, str] | None = None) -> EmailConfig:
    """Build the SMTP config from the environment.

    Called only when the email notifier actually needs to send, so ``--dry-run`` and the
    console notifier work on a machine with no SMTP credentials set.
    """
    env = dict(os.environ if env is None else env)

    missing = [k for k in ("SMTP_HOST", "ALERT_FROM", "ALERT_TO") if not env.get(k)]
    if missing:
        raise ConfigError(
            "email notifier is configured but these environment variables are unset: "
            + ", ".join(missing)
            + " (see .env.example)"
        )

    use_ssl = _env_bool(env, "SMTP_SSL", False)
    starttls = _env_bool(env, "SMTP_STARTTLS", not use_ssl)
    default_port = 465 if use_ssl else 587

    raw_port = env.get("SMTP_PORT") or ""
    try:
        port = int(raw_port) if raw_port else default_port
    except ValueError:
        raise ConfigError(f"SMTP_PORT must be an integer, got {raw_port!r}") from None

    recipients = [r.strip() for r in env["ALERT_TO"].split(",") if r.strip()]
    if not recipients:
        raise ConfigError("ALERT_TO contained no addresses")

    return EmailConfig(
        host=env["SMTP_HOST"],
        port=port,
        username=env.get("SMTP_USER", ""),
        password=env.get("SMTP_PASSWORD", ""),
        sender=env["ALERT_FROM"],
        recipients=recipients,
        starttls=starttls,
        use_ssl=use_ssl,
        timeout=float(env.get("SMTP_TIMEOUT") or 30.0),
    )
