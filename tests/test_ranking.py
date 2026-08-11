from wiederfrei.config import RankingConfig
from wiederfrei.ranking import RankIndex, intrinsic_score

UMBRELLA = "1,google.com\n2,example.ch\n3,xn--zrich-kva.ch\n"
TOP10M = '"Rank","Domain","Open Page Rank"\n"1","example.ch","7.55"\n"2","other.ch","3.10"\n'


def write_csvs(tmp_path):
    (tmp_path / "umbrella.csv").write_text(UMBRELLA, encoding="utf-8")
    (tmp_path / "top10m.csv").write_text(TOP10M, encoding="utf-8")
    return RankingConfig(
        umbrella_csv=tmp_path / "umbrella.csv",
        top10m_csv=tmp_path / "top10m.csv",
        enabled=True,
    )


class TestIntrinsicScore:
    def test_three_letters_beats_four(self):
        assert intrinsic_score("abc") > intrinsic_score("abcd")

    def test_letters_beat_digits(self):
        assert intrinsic_score("abc") > intrinsic_score("a1c")

    def test_hyphens_are_penalised(self):
        assert intrinsic_score("abcd") > intrinsic_score("a-cd")

    def test_pronounceable_beats_consonant_cluster(self):
        assert intrinsic_score("bad") > intrinsic_score("bcd")

    def test_bounded_to_0_100(self):
        assert intrinsic_score("a") <= 100
        assert intrinsic_score("9-9-9-9-9-9-9-9") >= 0

    def test_empty(self):
        assert intrinsic_score("") == 0


class TestRankIndex:
    def test_disabled_returns_intrinsic_only(self):
        info = RankIndex(RankingConfig(enabled=False)).lookup("example.ch", "example")
        assert info.umbrella_rank is None
        assert info.intrinsic > 0

    def test_missing_files_are_not_fatal(self, tmp_path):
        cfg = RankingConfig(
            umbrella_csv=tmp_path / "nope.csv",
            top10m_csv=tmp_path / "also-nope.csv",
            enabled=True,
        )
        info = RankIndex(cfg).lookup("example.ch", "example")
        assert info.umbrella_rank is None
        assert info.top10m_rank is None

    def test_finds_ranks_in_both_files(self, tmp_path):
        info = RankIndex(write_csvs(tmp_path)).lookup("example.ch", "example")
        assert info.umbrella_rank == 2
        assert info.top10m_rank == 1
        assert info.open_page_rank == 7.55

    def test_ranks_are_integers_not_strings(self, tmp_path):
        info = RankIndex(write_csvs(tmp_path)).lookup("example.ch", "example")
        assert isinstance(info.umbrella_rank, int)

    def test_lookup_normalises_the_query(self, tmp_path):
        index = RankIndex(write_csvs(tmp_path))
        assert index.lookup("WWW.Example.CH.", "example").umbrella_rank == 2

    def test_unicode_query_matches_punycode_row(self, tmp_path):
        """The old code missed every umlaut domain; this is that bug's regression test."""
        index = RankIndex(write_csvs(tmp_path))
        assert index.lookup("zürich.ch", "zürich").umbrella_rank == 3

    def test_miss_returns_intrinsic_only(self, tmp_path):
        info = RankIndex(write_csvs(tmp_path)).lookup("absent.ch", "absent")
        assert info.umbrella_rank is None
        assert info.top10m_rank is None
        assert info.intrinsic > 0

    def test_top10m_header_row_is_skipped(self, tmp_path):
        index = RankIndex(write_csvs(tmp_path))
        index.lookup("example.ch", "example")
        assert "domain" not in index._top10m

    def test_summary_is_human_readable(self, tmp_path):
        summary = RankIndex(write_csvs(tmp_path)).lookup("example.ch", "example").summary()
        assert "Umbrella #2" in summary
        assert "OpenPageRank 7.55" in summary
