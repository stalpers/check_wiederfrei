import pytest

from wiederfrei.candidates import (
    Candidate,
    count_labels,
    is_valid_label,
    iter_candidates,
    iter_labels,
    matching_rules,
    normalise_domain,
    to_display,
)
from wiederfrei.rules import LengthRule


class TestCandidateCounts:
    def test_three_char_alnum_space(self):
        assert count_labels("alnum", 3, 3) == 36**3 == 46_656

    def test_four_char_alnum_space(self):
        assert count_labels("alnum", 4, 4) == 36**4 == 1_679_616

    def test_full_three_to_four_sweep(self):
        assert count_labels("alnum", 3, 4) == 1_726_272

    def test_three_char_alpha_space(self):
        assert count_labels("alpha", 3, 3) == 17_576

    def test_count_matches_generation(self):
        generated = sum(1 for _ in iter_labels("alpha", 1, 3))
        assert generated == count_labels("alpha", 1, 3)

    def test_hyphen_charset_count_matches_generation(self):
        generated = sum(1 for _ in iter_labels("alnum_hyphen", 3, 3))
        assert generated == count_labels("alnum_hyphen", 3, 3)

    def test_unknown_charset_rejected(self):
        with pytest.raises(ValueError, match="unknown charset"):
            list(iter_labels("klingon", 3, 3))


class TestLabelValidity:
    @pytest.mark.parametrize("label", ["abc", "a1b", "ab-c", "x9"])
    def test_valid(self, label):
        assert is_valid_label(label)

    @pytest.mark.parametrize("label", ["", "-ab", "ab-", "xn--abc", "ab--c"])
    def test_invalid(self, label):
        assert not is_valid_label(label)

    def test_hyphen_sweep_excludes_reserved_and_edge_hyphens(self):
        labels = set(iter_labels("alnum_hyphen", 3, 4))
        assert "ab-" not in labels
        assert "-ab" not in labels
        assert "ab--" not in labels
        assert "a-b" in labels


class TestNormalisation:
    def test_lowercases(self):
        assert normalise_domain("ExAmPle.CH") == "example.ch"

    def test_strips_www_and_trailing_dot(self):
        assert normalise_domain("www.example.ch.") == "example.ch"

    def test_idn_to_punycode(self):
        assert normalise_domain("zürich.ch") == "xn--zrich-kva.ch"

    def test_idn_round_trip(self):
        assert to_display(normalise_domain("zürich.ch")) == "zürich.ch"

    def test_unicode_and_punycode_forms_compare_equal(self):
        assert normalise_domain("Zürich.CH") == normalise_domain("xn--zrich-kva.ch")

    def test_ascii_passthrough_is_untouched(self):
        assert normalise_domain("abc.ch") == "abc.ch"

    def test_empty_input(self):
        assert normalise_domain("   ") == ""

    def test_undecodable_label_falls_back_rather_than_raising(self):
        # Must not raise; the worst acceptable outcome is the input coming back.
        assert normalise_domain("xn--.ch")


class TestUnion:
    def test_overlapping_rules_yield_each_domain_once(self):
        broad = LengthRule(name="broad", tlds=["ch"], min_length=1, max_length=1,
                           charset="alpha")
        narrow = LengthRule(name="narrow", tlds=["ch"], min_length=1, max_length=1,
                            charset="alpha")
        domains = [c.domain for c in iter_candidates([broad, narrow])]
        assert len(domains) == len(set(domains)) == 26

    def test_multiple_tlds_expand(self):
        rule = LengthRule(name="r", tlds=["ch", "li"], min_length=1, max_length=1,
                          charset="alpha")
        domains = {c.domain for c in iter_candidates([rule])}
        assert "a.ch" in domains and "a.li" in domains
        assert len(domains) == 52

    def test_filter_only_rule_contributes_nothing(self):
        class FilterOnly:
            name = "filter"
            tlds = ["ch"]
            enabled = True
            notify = ["email"]

            def candidates(self):
                return None

            def matches(self, label):
                return True

        assert list(iter_candidates([FilterOnly()])) == []


class TestAttribution:
    def test_reports_every_matching_rule(self):
        three = LengthRule(name="three", tlds=["ch"], min_length=3, max_length=3,
                           charset="alpha")
        short = LengthRule(name="short", tlds=["ch"], min_length=3, max_length=4,
                           charset="alnum")
        assert matching_rules("abc", "ch", [three, short]) == ["three", "short"]

    def test_excludes_rules_for_other_tlds(self):
        rule = LengthRule(name="ch-only", tlds=["ch"], min_length=3, max_length=3,
                          charset="alpha")
        assert matching_rules("abc", "li", [rule]) == []

    def test_digit_label_excluded_from_alpha_rule(self):
        alpha = LengthRule(name="alpha", tlds=["ch"], min_length=3, max_length=3,
                           charset="alpha")
        alnum = LengthRule(name="alnum", tlds=["ch"], min_length=3, max_length=3,
                           charset="alnum")
        assert matching_rules("a1b", "ch", [alpha, alnum]) == ["alnum"]

    def test_candidate_is_hashable_and_frozen(self):
        c = Candidate("abc.ch", "abc", "ch")
        assert {c, Candidate("abc.ch", "abc", "ch")} == {c}
