"""The alerts must clearly state which rule fired. These tests hold that line."""

import pytest

from wiederfrei.config import EmailConfig
from wiederfrei.errors import NotifyError
from wiederfrei.notify.base import Alert, Finding, build_notifiers
from wiederfrei.notify.console import render_text
from wiederfrei.notify.email_smtp import build_message, render_html
from wiederfrei.ranking import RankInfo

RULE_A = "Short .ch domains (3-4 chars)"
RULE_B = "Three-letter .ch domains (a-z)"
DEF_A = "length rule: 3-4 characters, charset a-z0-9, .ch"
DEF_B = "length rule: 3-3 characters, charset a-z, .ch"


def make_alert(**kw) -> Alert:
    findings = kw.pop("findings", None) or [
        Finding(
            domain="abc.ch", label="abc", tld="ch",
            rule_names=[RULE_A, RULE_B],
            confirmed_at="2026-08-11T06:00:00+00:00",
            rank=RankInfo(intrinsic=100),
        )
    ]
    return Alert(
        findings=findings,
        rule_definitions=kw.pop("rule_definitions", {RULE_A: DEF_A, RULE_B: DEF_B}),
        **kw,
    )


class TestSubject:
    def test_single_rule_is_named_in_the_subject(self):
        alert = make_alert(
            findings=[Finding("abc.ch", "abc", "ch", [RULE_A], "t")],
            rule_definitions={RULE_A: DEF_A},
        )
        assert RULE_A in alert.subject()
        assert "1 domain available" in alert.subject()

    def test_multiple_rules_are_counted_in_the_subject(self):
        assert "2 rules" in make_alert().subject()

    def test_plural_domains(self):
        alert = make_alert(findings=[
            Finding("abc.ch", "abc", "ch", [RULE_A], "t"),
            Finding("xyz.ch", "xyz", "ch", [RULE_A], "t"),
        ])
        assert "2 domains available" in alert.subject()


class TestGrouping:
    def test_domain_matching_two_rules_appears_under_both(self):
        grouped = make_alert().by_rule()
        assert set(grouped) == {RULE_A, RULE_B}
        assert grouped[RULE_A][0].domain == "abc.ch"
        assert grouped[RULE_B][0].domain == "abc.ch"

    def test_rule_names_follow_definition_order(self):
        assert make_alert().rule_names == [RULE_A, RULE_B]

    def test_rule_absent_from_definitions_still_appears(self):
        alert = Alert(
            findings=[Finding("abc.ch", "abc", "ch", ["Undeclared"], "t")],
            rule_definitions={},
        )
        assert alert.rule_names == ["Undeclared"]


class TestTextRendering:
    def test_states_every_rule_name_and_definition(self):
        body = render_text(make_alert())
        for token in (RULE_A, RULE_B, DEF_A, DEF_B):
            assert token in body

    def test_lists_the_domain_and_confirmation_time(self):
        body = render_text(make_alert())
        assert "abc.ch" in body
        assert "2026-08-11T06:00:00+00:00" in body

    def test_cross_references_the_other_matching_rule(self):
        body = render_text(make_alert())
        assert body.count(RULE_B) >= 2  # once as a heading, once as "also matched"

    def test_orders_findings_by_intrinsic_score(self):
        alert = make_alert(findings=[
            Finding("a1b.ch", "a1b", "ch", [RULE_A], "t", RankInfo(intrinsic=40)),
            Finding("abc.ch", "abc", "ch", [RULE_A], "t", RankInfo(intrinsic=100)),
        ])
        body = render_text(alert)
        assert body.index("abc.ch") < body.index("a1b.ch")

    def test_renders_idn_domains_for_humans(self):
        alert = make_alert(findings=[
            Finding("xn--zrich-kva.ch", "xn--zrich-kva", "ch", [RULE_A], "t")
        ])
        assert "zürich.ch" in render_text(alert)

    def test_handles_missing_rank_data(self):
        alert = make_alert(findings=[Finding("abc.ch", "abc", "ch", [RULE_A], "t", None)])
        assert "abc.ch" in render_text(alert)


class TestHtmlRendering:
    def test_states_every_rule_name_and_definition(self):
        body = render_html(make_alert())
        for token in (RULE_A, RULE_B, DEF_A, DEF_B):
            assert token in body

    def test_escapes_rule_names(self):
        alert = Alert(
            findings=[Finding("abc.ch", "abc", "ch", ["<script>x</script>"], "t")],
            rule_definitions={"<script>x</script>": "d"},
        )
        html = render_html(alert)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html


class TestMessageAssembly:
    @pytest.fixture()
    def cfg(self):
        return EmailConfig(
            host="smtp.test", port=587, username="u", password="p",
            sender="from@test", recipients=["a@test", "b@test"],
            starttls=True, use_ssl=False, timeout=10.0,
        )

    def test_headers(self, cfg):
        msg = build_message(make_alert(), cfg)
        assert msg["From"] == "from@test"
        assert msg["To"] == "a@test, b@test"
        # This fixture matches two rules, so the subject counts them rather than
        # naming one; the names themselves are in the body (asserted below).
        assert "2 rules" in msg["Subject"]

    def test_single_rule_subject_names_it(self, cfg):
        alert = make_alert(
            findings=[Finding("abc.ch", "abc", "ch", [RULE_A], "t")],
            rule_definitions={RULE_A: DEF_A},
        )
        assert RULE_A in build_message(alert, cfg)["Subject"]

    def test_is_multipart_with_both_parts_naming_the_rule(self, cfg):
        msg = build_message(make_alert(), cfg)
        bodies = {
            part.get_content_type(): part.get_content()
            for part in msg.walk()
            if part.get_content_type() in {"text/plain", "text/html"}
        }
        assert set(bodies) == {"text/plain", "text/html"}
        assert RULE_A in bodies["text/plain"]
        assert RULE_A in bodies["text/html"]


class TestRegistry:
    def test_builds_known_notifiers(self):
        assert [n.name for n in build_notifiers(["console"])] == ["console"]

    def test_deduplicates(self):
        assert len(build_notifiers(["console", "console"])) == 1

    def test_rejects_unknown_notifier(self):
        with pytest.raises(NotifyError, match="unknown notifier"):
            build_notifiers(["carrier-pigeon"])


class TestEmailNotifierFailure:
    def test_smtp_failure_raises_notify_error(self, monkeypatch):
        import smtplib

        from wiederfrei.notify.email_smtp import EmailNotifier

        cfg = EmailConfig(
            host="smtp.test", port=587, username="", password="",
            sender="f@test", recipients=["t@test"],
            starttls=False, use_ssl=False, timeout=1.0,
        )

        def boom(*a, **kw):
            raise smtplib.SMTPConnectError(421, "nope")

        monkeypatch.setattr(smtplib, "SMTP", boom)
        with pytest.raises(NotifyError, match="SMTP delivery"):
            EmailNotifier(cfg).send(make_alert())
