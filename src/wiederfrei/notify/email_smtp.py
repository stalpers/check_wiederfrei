"""Email notifier over stdlib SMTP.

No third-party dependency and no account to create: it speaks to whatever relay you
configure via the environment. Credentials are read from the environment at send time,
so a dry run works on a host with no SMTP settings at all.
"""

from __future__ import annotations

import html
import logging
import smtplib
from email.message import EmailMessage

from ..config import EmailConfig, load_email_config
from ..errors import NotifyError
from .base import Alert, register
from .console import render_text

logger = logging.getLogger(__name__)


def render_html(alert: Alert) -> str:
    """HTML body. Same grouping and the same rule attribution as the text part."""
    esc = html.escape
    parts = [
        "<html><body style=\"font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;"
        "line-height:1.45;color:#111\">",
        f"<h2 style=\"margin-bottom:4px\">{esc(alert.subject())}</h2>",
        f"<p style=\"color:#555;margin-top:0\">Checked at {esc(alert.generated_at)} (UTC), "
        "confirmed by RDAP.</p>",
    ]

    for rule_name, findings in alert.by_rule().items():
        definition = alert.rule_definitions.get(rule_name, "")
        parts.append(
            "<div style=\"margin:22px 0 6px;padding:8px 12px;background:#f4f6f8;"
            "border-left:4px solid #0b6bcb\">"
            f"<strong>Rule:</strong> {esc(rule_name)}"
        )
        if definition:
            parts.append(
                f"<br><span style=\"color:#555;font-size:90%\">{esc(definition)}</span>"
            )
        parts.append("</div>")

        parts.append(
            "<table cellpadding=\"6\" cellspacing=\"0\" "
            "style=\"border-collapse:collapse;font-size:94%\">"
            "<tr style=\"background:#eef1f4;text-align:left\">"
            "<th>Domain</th><th>Confirmed available (UTC)</th>"
            "<th>Also matched</th><th>Signals</th></tr>"
        )
        ordered = sorted(
            findings, key=lambda x: (-(x.rank.intrinsic if x.rank else 0), x.domain)
        )
        for f in ordered:
            others = [r for r in f.rule_names if r != rule_name]
            parts.append(
                "<tr style=\"border-top:1px solid #dde2e7\">"
                f"<td><strong>{esc(f.display)}</strong></td>"
                f"<td>{esc(f.confirmed_at)}</td>"
                f"<td>{esc(', '.join(others)) if others else '&ndash;'}</td>"
                f"<td>{esc(f.rank.summary()) if f.rank else '&ndash;'}</td>"
                "</tr>"
            )
        parts.append("</table>")

    parts.append(
        "<p style=\"color:#666;font-size:88%;margin-top:24px\">Availability was confirmed by "
        "an RDAP query to the registry at the time above. These names are first-come, "
        "first-served &mdash; verify with your registrar before acting.</p>"
    )
    parts.append("</body></html>")
    return "".join(parts)


def build_message(alert: Alert, cfg: EmailConfig) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = alert.subject()
    msg["From"] = cfg.sender
    msg["To"] = ", ".join(cfg.recipients)
    msg.set_content(render_text(alert))
    msg.add_alternative(render_html(alert), subtype="html")
    return msg


class EmailNotifier:
    name = "email"

    def __init__(self, cfg: EmailConfig | None = None) -> None:
        self._cfg = cfg

    @property
    def cfg(self) -> EmailConfig:
        if self._cfg is None:
            self._cfg = load_email_config()
        return self._cfg

    def send(self, alert: Alert) -> None:
        cfg = self.cfg
        msg = build_message(alert, cfg)
        try:
            if cfg.use_ssl:
                server: smtplib.SMTP = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=cfg.timeout)
            else:
                server = smtplib.SMTP(cfg.host, cfg.port, timeout=cfg.timeout)
            with server:
                server.ehlo()
                if cfg.starttls and not cfg.use_ssl:
                    server.starttls()
                    server.ehlo()
                if cfg.username:
                    server.login(cfg.username, cfg.password)
                server.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            raise NotifyError(f"SMTP delivery to {cfg.host}:{cfg.port} failed: {exc}") from exc

        logger.info(
            "Emailed %d finding(s) to %s", len(alert.findings), ", ".join(cfg.recipients)
        )


register("email", EmailNotifier)
