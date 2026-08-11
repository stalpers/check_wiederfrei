import pytest
import yaml

from wiederfrei.config import load_config, load_email_config
from wiederfrei.errors import ConfigError

MINIMAL = {
    "rules": [
        {"name": "short", "type": "length", "tlds": ["ch"],
         "min_length": 3, "max_length": 4, "charset": "alnum"}
    ]
}


def write(tmp_path, data):
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


class TestRulesFile:
    def test_loads_a_minimal_file(self, tmp_path):
        cfg = load_config(write(tmp_path, MINIMAL))
        assert len(cfg.rules) == 1
        assert cfg.rules[0].candidate_count() == 1_726_272

    def test_defaults_apply_to_rules(self, tmp_path):
        cfg = load_config(write(tmp_path, {
            "defaults": {"tlds": ["li"], "notify": ["console"]},
            "rules": [{"name": "r", "type": "length", "min_length": 3, "max_length": 3}],
        }))
        assert cfg.rules[0].tlds == ["li"]
        assert cfg.rules[0].notify == ["console"]

    def test_tld_leading_dot_is_tolerated(self, tmp_path):
        data = {"rules": [dict(MINIMAL["rules"][0], tlds=[".CH"])]}
        assert load_config(write(tmp_path, data)).rules[0].tlds == ["ch"]

    def test_missing_file(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            load_config(tmp_path / "nope.yaml")

    def test_invalid_yaml(self, tmp_path):
        path = tmp_path / "rules.yaml"
        path.write_text("rules: [oops\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="not valid YAML"):
            load_config(path)

    def test_no_rules(self, tmp_path):
        with pytest.raises(ConfigError, match="defines no rules"):
            load_config(write(tmp_path, {"rules": []}))

    def test_duplicate_rule_names_rejected(self, tmp_path):
        rule = MINIMAL["rules"][0]
        with pytest.raises(ConfigError, match="duplicate rule name"):
            load_config(write(tmp_path, {"rules": [rule, dict(rule)]}))

    def test_unnamed_rule_rejected(self, tmp_path):
        data = {"rules": [{"type": "length", "min_length": 3, "max_length": 3}]}
        with pytest.raises(ConfigError, match="non-empty 'name'"):
            load_config(write(tmp_path, data))

    def test_unknown_rule_type_rejected(self, tmp_path):
        with pytest.raises(ConfigError, match="unknown type"):
            load_config(write(tmp_path, {"rules": [{"name": "r", "type": "regex"}]}))

    def test_unknown_charset_rejected(self, tmp_path):
        data = {"rules": [dict(MINIMAL["rules"][0], charset="runes")]}
        with pytest.raises(ConfigError, match="unknown charset"):
            load_config(write(tmp_path, data))

    def test_inverted_length_range_rejected(self, tmp_path):
        data = {"rules": [dict(MINIMAL["rules"][0], min_length=5, max_length=2)]}
        with pytest.raises(ConfigError, match="below"):
            load_config(write(tmp_path, data))

    def test_missing_length_bound_rejected(self, tmp_path):
        data = {"rules": [{"name": "r", "type": "length", "min_length": 3}]}
        with pytest.raises(ConfigError, match="max_length"):
            load_config(write(tmp_path, data))

    def test_tld_without_rdap_endpoint_rejected(self, tmp_path):
        data = {"rules": [dict(MINIMAL["rules"][0], tlds=["example"])]}
        with pytest.raises(ConfigError, match="no RDAP endpoint"):
            load_config(write(tmp_path, data))


class TestOperationalSettings:
    def test_defaults(self, tmp_path):
        cfg = load_config(write(tmp_path, MINIMAL))
        assert cfg.rdap.rate_limit_per_second == 2.0
        assert cfg.rdap.endpoint_for("ch") == "https://rdap.nic.ch"
        assert cfg.rdap.endpoint_for("li") == "https://rdap.nic.ch"
        assert cfg.ranking.enabled is False

    def test_endpoint_override(self, tmp_path):
        data = dict(MINIMAL, rdap={"endpoints": {"ch": "https://rdap.test/"}})
        cfg = load_config(write(tmp_path, data))
        assert cfg.rdap.endpoint_for("ch") == "https://rdap.test"

    def test_contact_lands_in_user_agent(self, tmp_path):
        data = dict(MINIMAL, rdap={"contact": "me@example.com"})
        cfg = load_config(write(tmp_path, data))
        assert "me@example.com" in cfg.rdap.user_agent()

    def test_zero_rate_limit_rejected(self, tmp_path):
        data = dict(MINIMAL, rdap={"rate_limit_per_second": 0})
        with pytest.raises(ConfigError, match="greater than 0"):
            load_config(write(tmp_path, data))

    def test_zero_dns_concurrency_rejected(self, tmp_path):
        data = dict(MINIMAL, dns={"concurrency": 0})
        with pytest.raises(ConfigError, match="concurrency"):
            load_config(write(tmp_path, data))


class TestEmailEnv:
    BASE = {"SMTP_HOST": "smtp.test", "ALERT_FROM": "f@test", "ALERT_TO": "a@test"}

    def test_minimal_env(self):
        cfg = load_email_config(self.BASE)
        assert cfg.host == "smtp.test"
        assert cfg.recipients == ["a@test"]
        assert cfg.port == 587
        assert cfg.starttls is True

    def test_multiple_recipients(self):
        cfg = load_email_config({**self.BASE, "ALERT_TO": "a@test, b@test"})
        assert cfg.recipients == ["a@test", "b@test"]

    def test_ssl_defaults_to_port_465(self):
        cfg = load_email_config({**self.BASE, "SMTP_SSL": "true"})
        assert cfg.use_ssl is True
        assert cfg.port == 465
        assert cfg.starttls is False

    @pytest.mark.parametrize("missing", ["SMTP_HOST", "ALERT_FROM", "ALERT_TO"])
    def test_missing_required_var_is_reported_by_name(self, missing):
        env = {k: v for k, v in self.BASE.items() if k != missing}
        with pytest.raises(ConfigError, match=missing):
            load_email_config(env)

    def test_bad_port(self):
        with pytest.raises(ConfigError, match="SMTP_PORT"):
            load_email_config({**self.BASE, "SMTP_PORT": "eleven"})


def test_shipped_example_config_is_valid(tmp_path):
    """rules.example.yaml is what users copy; it must actually load."""
    import shutil
    from pathlib import Path

    src = Path(__file__).resolve().parent.parent / "rules.example.yaml"
    dst = tmp_path / "rules.yaml"
    shutil.copy(src, dst)
    cfg = load_config(dst)
    assert len(cfg.enabled_rules()) == 2
    assert cfg.rules[0].candidate_count() == 1_726_272
