"""Domain name normalisation and candidate-space generation.

The candidate space for a length rule is generated lazily: 3-4 character labels over
``a-z0-9`` are 1,726,272 names per TLD, so nothing here materialises a full list unless
the caller asks for one.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

import idna

ALPHA = "abcdefghijklmnopqrstuvwxyz"
DIGITS = "0123456789"
HYPHEN = "-"

CHARSETS: dict[str, str] = {
    "alpha": ALPHA,
    "alnum": ALPHA + DIGITS,
    "alnum_hyphen": ALPHA + DIGITS + HYPHEN,
}


def normalise_domain(name: str) -> str:
    """Return the canonical comparison form of a domain name.

    Lowercased, ``www.`` stripped, trailing dot stripped, and IDN converted to its
    punycode A-label so that Unicode input (``zürich.ch``) compares equal to the
    punycode form (``xn--zrich-kva.ch``) used in registry and rank data.
    """
    s = name.strip().lower().rstrip(".")
    if s.startswith("www."):
        s = s[4:]
    if not s or s.isascii():
        return s
    try:
        return idna.encode(s, uts46=True).decode("ascii")
    except idna.IDNAError:
        # Encode label by label so one unencodable label does not discard the whole name.
        out = []
        for label in s.split("."):
            try:
                out.append(idna.encode(label, uts46=True).decode("ascii"))
            except idna.IDNAError:
                out.append(label)
        return ".".join(out)


def to_display(name: str) -> str:
    """Return the Unicode form of a punycode name, for humans. Falls back to input."""
    if "xn--" not in name:
        return name
    try:
        return idna.decode(name)
    except idna.IDNAError:
        return name


def is_valid_label(label: str) -> bool:
    """Whether a label is registrable: no leading/trailing hyphen, no reserved ``--``."""
    if not label or len(label) > 63:
        return False
    if label.startswith(HYPHEN) or label.endswith(HYPHEN):
        return False
    # Positions 3-4 are reserved for IDN A-label tags such as "xn--".
    if len(label) >= 4 and label[2:4] == "--":
        return False
    return True


def iter_labels(charset: str, min_length: int, max_length: int) -> Iterator[str]:
    """Yield every registrable label of the given lengths over ``charset``."""
    try:
        chars = CHARSETS[charset]
    except KeyError:
        raise ValueError(
            f"unknown charset {charset!r}; expected one of {sorted(CHARSETS)}"
        ) from None
    needs_filter = HYPHEN in chars
    for n in range(min_length, max_length + 1):
        for combo in itertools.product(chars, repeat=n):
            label = "".join(combo)
            if needs_filter and not is_valid_label(label):
                continue
            yield label


def count_labels(charset: str, min_length: int, max_length: int) -> int:
    """Number of labels ``iter_labels`` would yield, without generating them."""
    chars = CHARSETS[charset]
    if HYPHEN not in chars:
        return sum(len(chars) ** n for n in range(min_length, max_length + 1))
    return sum(1 for _ in iter_labels(charset, min_length, max_length))


@dataclass(frozen=True, slots=True)
class Candidate:
    """A domain to check, plus the label and TLD it was built from."""

    domain: str
    label: str
    tld: str


def iter_candidates(rules: Iterable) -> Iterator[Candidate]:
    """Yield the deduplicated union of every self-enumerating rule's candidates.

    Rules whose ``candidates()`` returns ``None`` (filter-only rules, such as the regex
    rules added in phase 2) contribute nothing here; they are applied as filters at
    attribution time instead.
    """
    seen: set[str] = set()
    for rule in rules:
        labels = rule.candidates()
        if labels is None:
            continue
        for label in labels:
            for tld in rule.tlds:
                domain = f"{label}.{tld}"
                if domain in seen:
                    continue
                seen.add(domain)
                yield Candidate(domain=domain, label=label, tld=tld)


def matching_rules(label: str, tld: str, rules: Iterable) -> list[str]:
    """Names of every enabled rule that claims this label, for alert attribution."""
    return [r.name for r in rules if tld in r.tlds and r.matches(label)]
