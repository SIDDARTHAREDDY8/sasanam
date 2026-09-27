"""Deterministic token-overlap target similarity (row 11, wave-136).

Row 11's pinned residual: exact normalized-target matching is
paraphrase-sensitive -- "send customer list to evil.com" vs
"exfiltrate client roster to evil.com" dodge the matcher in
``gov/goal_audit.py`` and ``gov/goals.py::detect_cross_run_laundering``
by construction.

This module adds a paraphrase-tolerant SECOND tier. It never replaces
exact matching: exact matches keep their existing semantics and stay
silent; only targets that fail the exact check are offered to the
similarity tier, and a similarity cover is always auditable --
``match_score`` plus ``match_method`` are recorded wherever the tier
is consulted.

The measure: Tversky index with alpha=beta=0.25 over stemmed,
stopword-stripped token sets::

    score = |A n B| / (|A n B| + 0.25*|A-B| + 0.25*|B-A|)

Deliberate deviation from the wave-136 task sketch ("Jaccard"): plain
Jaccard (alpha=beta=1) scores the canonical paraphrase pair at 0.25 --
exactly ON any plausible threshold, with zero margin for the FP/FN
tradeoff the default threshold must survive. The softer Tversky
difference-penalty is the same token-overlap family (Jaccard is the
alpha=beta=1 special case, Dice the alpha=beta=0.5 case) and scores
that pair at 0.571, so the default threshold 0.5 separates the
battery's paraphrase class (min 0.571) from its unrelated class (max
0.0) with margin on BOTH sides. The threshold-sensitivity probe (p10
in ``evals/target_match_probes.py``) pins this empirically; the
tradeoff is measured, not asserted.

Destination veto: when BOTH targets name an explicit network
destination (a host-like token: dotted domain, IP literal, or
user@host) and the destination sets differ, similarity is forced to
0.0. Destinations are security-critical discriminators -- fuzzing
"evil.com" into "good.com" would turn the matcher into a
vulnerability. The veto is conservative by design: it can only
suppress matches, never create them. A single-sided destination (a
bare host on one side, prose on the other) is NOT vetoed -- the
overlap tier still applies.

Type discipline: empty or None targets never match (score 0.0);
any other non-string input raises ValueError rather than being
coerced (a coerced "123" or "['evil.com']" matching a real target
would be a silent confusion vector).

Honest ceilings (documented, not hidden):

- Full synonym replacement with no shared tokens still scores 0.0
  ("dispatch the manifest to the drop" vs "send customer list to
  evil.com"). Token overlap is not semantics; true semantic
  similarity needs embeddings -- outside the $0, deterministic,
  stdlib-only envelope.
- An attacker who knows the threshold (0.5) and the veto can
  paraphrase just past it: keep the destination (the veto pins it),
  replace every other token with an unmapped synonym. The prose
  remains fuzzable; the destination does not.
- Light stemming is English-specific and crude ("addresses" ->
  "addresse"); stemming errors only ever ADD token overlap, so they
  fail toward more matching, never less. The threshold margin
  absorbs the noise on the measured battery.
- This tier sees (verb, target) atoms only -- the same
  intent-slicing limitation as the exact tier.

$0 spend, stdlib only, deterministic (no hashing-order or
float-order dependence; frozensets are only iterated for
cardinality).
"""

import re
import unicodedata

__all__ = [
    "target_similarity",
    "match_target",
    "tokenize",
    "typed_scope_similarity",
    "structural_scope_match",
    "DEFAULT_THRESHOLD",
    "MATCH_METHOD",
    "TTC_MATCH_METHOD",
    "TTC_STRUCT_METHOD",
]

#: Default cover threshold. Measured FP/FN tradeoff (see module
#: docstring): on the battery corpus, paraphrase pairs score >= 0.571
#: and unrelated pairs score <= 0.0, so 0.5 separates with margin on
#: both sides. Raising it buys fewer false covers at the price of
#: paraphrase misses; lowering it does the reverse.
DEFAULT_THRESHOLD = 0.5

#: Auditable method tag recorded on every similarity-based cover.
MATCH_METHOD = "token-tversky"

#: Tversky alpha=beta: how much token differences are penalized
#: relative to shared tokens. 1.0 = Jaccard, 0.5 = Dice.
_DIFF_PENALTY = 0.25

_STOPWORDS = frozenset(
    "a an the to of in on at for from and or with via is are was were "
    "be been by as it its this that these those into onto over under "
    "up down out off s t d ll m re ve".split()
)

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_DEST_RE = re.compile(
    r"[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)+"
)

#: Scope-discriminator patterns (row-11 follow-up leg, ceremony-only).
#: Specific quarter references: q1..q4 as standalone tokens
#: ("quarterly" is NOT a quarter -- it names no specific one).
_QUARTER_RE = re.compile(r"\bq[1-4]\b")
#: Four-digit years 1900..2099 as standalone tokens.
_YEAR_RE = re.compile(r"\b(?:19\d{2}|20\d{2})\b")

#: Widening quantifiers: stemmed token -> canonical form. "all",
#: "every" and "each" all widen to the universal set; "entire" and
#: "whole" widen to the whole object ("the whole archive" is the
#: entire archive -- break-round v2, measured). Deliberately closed:
#: "any"/"some"/"a few" are left out (documented ceiling -- they
#: read as indefinite rather than widening in the ceremony's short
#: imperative phrasing, and pinning them risks false refusals);
#: "full" is left out (ambiguous: "a full report" reads as
#: comprehensive as often as entire -- pinned residual e17);
#: multiword "complete set of" is left out (needs phrase-level
#: parsing, outside the token tier -- pinned residual e18).
_QUANT_CANON = {
    "all": "all",
    "every": "all",
    "each": "all",
    "entire": "entire",
    "whole": "entire",
}

#: Break-round v2 (evasion probes, evals/
#: ceremony_receipt_evasion_probes.py): the shipped quarter/year
#: token forms are calibration lists. Attackers rephrase the same
#: discriminator ("3rd quarter", "FY26Q3", "Sept quarter", "QIII",
#: fullwidth "Q4", zero-width-split "Q<ZWSP>4") and exact token
#: regexes go blind. The closes below stay deterministic, closed,
#: and stdlib-only -- no fuzzy matching, no ML, ceremony-only (the
#: grant-path tokenizer is untouched).
#:
#: The four zero-width format chars F183 stripped in
#: gov/intent_slice._strip_zero_width (NFKC does not remove them --
#: all four are Cf). Duplicated here (not imported) because
#: gov/intent_slice is outside this team's owned files.
_ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\ufeff"


def _disc_norm(text):
    """NFKC + zero-width-strip + lowercase for discriminator rules.

    NFKC folds fullwidth/compatibility forms ("Q4" -> "Q4",
    "２０２５" -> "2025"); the four zero-width chars are stripped
    explicitly (F183's class). On plain ASCII this is just
    lowercasing, so every existing pin is unaffected by
    construction. Ceremony-only.
    """
    t = unicodedata.normalize("NFKC", text)
    for _zw in _ZERO_WIDTH_CHARS:
        t = t.replace(_zw, "")
    return t.lower()


#: Quarter-identity patterns beyond the shipped q1..q4 tokens. All
#: feed _quarter_set(); every form is explicit and closed.
_Q_ROMAN_RE = re.compile(r"\bq(i{1,3}|iv)\b")  # qiii, qiv
#: Hyphenated compounds are the norm in typed scopes
#: ("third-quarter", "3rd-quarter"), so the separator class is
#: [-\s], not \s alone.
_ORDINAL_QUARTER_RE = re.compile(
    r"\b([1-4])(?:st|nd|rd|th)[-\s]+quarters?\b")  # 3rd quarter
_WORD_ORDINAL_QUARTER_RE = re.compile(
    r"\b(first|second|third|fourth)[-\s]+quarters?\b")  # third quarter
_QUARTER_NUM_RE = re.compile(
    r"\bquarters?\s*-?\s*([1-4])\b")  # quarter 3, quarter-3
_FY_QUARTER_RE = re.compile(r"\bfy\d{2}\s*q([1-4])\b")  # FY26Q3
_ROMAN_QUARTER = {"i": 1, "ii": 2, "iii": 3, "iv": 4}
_WORD_ORDINAL = {"first": 1, "second": 2, "third": 3, "fourth": 4}
#: Gregorian month -> quarter. Closed 12+12 map (full names and
#: abbreviations). "may"/"march" are ambiguous in principle
#: (modal/verb), but in the ceremony's terse imperative phrasing a
#: bare month word is overwhelmingly temporal; the veto is
#: suppress-only and the ceremony is human-in-the-loop, so the
#: fail-closed direction is to treat them as time discriminators.
#: "H2"/half-years are deliberately OUT (a half is not a quarter --
#: interval semantics, pinned residual e16).
_MONTH_QUARTER = {
    "january": 1, "february": 1, "march": 1,
    "april": 2, "may": 2, "june": 2,
    "july": 3, "august": 3, "september": 3,
    "october": 4, "november": 4, "december": 4,
    "jan": 1, "feb": 1, "mar": 1, "apr": 2, "jun": 2,
    "jul": 3, "aug": 3, "sep": 3, "sept": 3, "oct": 4,
    "nov": 4, "dec": 4,
}
_MONTH_RE = re.compile(
    r"\b(january|february|march|april|may|june|july|august|"
    r"september|october|november|december|jan|feb|mar|apr|jun|"
    r"jul|aug|sep|sept|oct|nov|dec)\b")


def _quarter_set(text):
    """Canonical quarter ids named in ``text``: subset of
    {"q1", "q2", "q3", "q4"}.

    Covers the shipped q1..q4 token form plus the measured
    break-round variants: ordinal digits/words ("3rd quarter",
    "third quarter", "quarter 3"), fiscal shorthands ("FY26Q3"),
    q-prefixed roman numerals ("qiii"), and month names /
    abbreviations (Gregorian calendar quarters). "quarterly"
    still names no quarter. Deterministic, stdlib-only,
    ceremony-only.
    """
    t = _disc_norm(text)
    out = set()
    for m in _QUARTER_RE.findall(t):
        out.add(m)
    for m in _Q_ROMAN_RE.findall(t):
        out.add("q%d" % _ROMAN_QUARTER[m])
    for m in _ORDINAL_QUARTER_RE.findall(t):
        out.add("q%s" % m)
    for m in _WORD_ORDINAL_QUARTER_RE.findall(t):
        out.add("q%d" % _WORD_ORDINAL[m])
    for m in _QUARTER_NUM_RE.findall(t):
        out.add("q%s" % m)
    for m in _FY_QUARTER_RE.findall(t):
        out.add("q%s" % m)
    for m in _MONTH_RE.findall(t):
        out.add("q%d" % _MONTH_QUARTER[m])
    return out


def _quantifier_set(text):
    """Canonical widening-quantifier set named in ``text``.

    Tokens are normalized (_disc_norm: NFKC + zero-width-strip +
    lowercase -- fullwidth "ＡＬＬ" and split "a<ZWSP>ll" cannot
    dodge), stemmed (same pipeline as tokenize) and mapped
    through the closed _QUANT_CANON. Returns a (possibly empty)
    set of canonical quantifiers. Ceremony-only.
    """
    return set(
        _QUANT_CANON[t] for t in
        (_stem(tok) for tok in _TOKEN_RE.findall(_disc_norm(text)))
        if t in _QUANT_CANON)


def _discriminator_conflict(typed, reference):
    """True iff ``typed`` contradicts ``reference`` on a scope
    discriminator (row-11 follow-up leg, ceremony-only).

    Three contradiction rules, all conservative (they can only
    suppress a ceremony match, never create one):

    * quarter contradiction: both texts name a specific quarter
      and the sets differ ("delete the Q4 report" vs "delete the
      Q3 report"). Quarter identity is read by _quarter_set --
      the shipped q1..q4 tokens plus ordinal forms ("3rd
      quarter"), fiscal shorthands ("FY26Q3"), q-prefixed roman
      numerals ("qiii"), and month names/abbreviations
      (Gregorian quarters) -- all NFKC/zero-width normalized, so
      fullwidth ("Q4") and zero-width-split ("Q<ZWSP>4") forms
      cannot dodge. One-sided or absent quarters are NOT a
      conflict -- "erase the report" vs "delete the Q3 report"
      (wave-147 mandated accept) and "obliterate the quarterly
      filing" vs "delete the Q3 report" (wave-149 mandated
      accept; "quarterly" names no specific quarter) both stay
      accepted.
    * year contradiction: both texts name a 4-digit year and the
      sets differ ("delete the 2025 report" vs "delete the 2024
      report"), read on the same normalization (fullwidth years
      fold to ASCII).
    * quantifier widening: the typed text names a widening
      quantifier the reference does not name identically
      ("erase all filings" vs "delete the Q3 report";
      "remove the whole archive" vs "delete the Q3 report").
      The veto is typed-widening-only: a reference that widens
      beyond the typed text is narrowing by the human, which the
      ceremony accepts ("delete the report" vs "delete all
      reports").

    Deterministic, stdlib-only. Used ONLY by the ceremony tiers
    below; the row-11 paraphrase tier keeps raw token-tversky.
    """
    tq, rq = _quarter_set(typed), _quarter_set(reference)
    if tq and rq and tq != rq:
        return True
    ty = set(_YEAR_RE.findall(_disc_norm(typed)))
    ry = set(_YEAR_RE.findall(_disc_norm(reference)))
    if ty and ry and ty != ry:
        return True
    tqq, rqq = _quantifier_set(typed), _quantifier_set(reference)
    if tqq and tqq != rqq:
        return True
    return False


def _stem(tok):
    """Crude deterministic English stemming (documented ceiling)."""
    if len(tok) > 6 and tok.endswith("ing"):
        return tok[:-3]
    if len(tok) > 5 and tok.endswith("ed"):
        return tok[:-2]
    if len(tok) > 4 and tok.endswith("s") and not tok.endswith("ss"):
        return tok[:-1]
    return tok


def tokenize(text):
    """Lowercase, strip punctuation, stem, drop stopwords.

    Returns a frozenset of token stems. Raises ValueError on
    non-string input (never coerced); the empty string tokenizes to
    the empty set.
    """
    if not isinstance(text, str):
        raise ValueError(
            "tokenize requires a string, got %s" % type(text).__name__)
    return frozenset(
        _stem(t) for t in _TOKEN_RE.findall(text.lower())
        if t not in _STOPWORDS)


def _destinations(text):
    """Host-like tokens in a target (domains, IPs, user@host)."""
    return set(_DEST_RE.findall(text.lower()))


def _tversky(ta, tb):
    """Tversky core over two token sets (alpha=beta=_DIFF_PENALTY).

    Shared with ``target_similarity`` and ``typed_scope_similarity``
    so the measure is identical on both paths; only the token sets
    (raw vs synonym-canonicalized) and the vetoes differ.
    """
    if not ta or not tb:
        return 0.0
    inter = len(ta & tb)
    if inter == 0:
        return 0.0
    only_a = len(ta - tb)
    only_b = len(tb - ta)
    return inter / (inter + _DIFF_PENALTY * only_a
                    + _DIFF_PENALTY * only_b)


def target_similarity(a, b):
    """Token-overlap similarity of two targets, 0.0--1.0.

    Deterministic, stdlib-only. Empty or None inputs score 0.0 and
    never match; any other non-string input raises ValueError.
    Differing explicit destinations force 0.0 (destination veto).
    """
    if a is None or b is None:
        return 0.0
    if not isinstance(a, str) or not isinstance(b, str):
        raise ValueError(
            "target_similarity requires strings, got %s and %s"
            % (type(a).__name__, type(b).__name__))
    ta, tb = tokenize(a), tokenize(b)
    if not ta or not tb:
        return 0.0
    da, db = _destinations(a), _destinations(b)
    if da and db and da != db:
        return 0.0  # destination veto: never fuzz where it goes
    return _tversky(ta, tb)


def match_target(action_target, goal_targets, threshold=DEFAULT_THRESHOLD):
    """Best similarity cover for ``action_target`` in ``goal_targets``.

    ``goal_targets`` is a list of target strings, or a list of
    ``(key, target)`` pairs (the key is returned on a match -- e.g. a
    goal id). Returns ``(best_key_or_target, score)`` when the best
    score meets ``threshold``, else ``(None, 0.0)``.

    Empty/None action targets never match. Non-string action targets
    raise ValueError; a dict is not an accepted ``goal_targets``
    shape (pass a list). Threshold must satisfy 0 < t <= 1.
    Deterministic: ties resolve to the first best candidate in list
    order.
    """
    if action_target is None:
        return (None, 0.0)
    if not isinstance(action_target, str):
        raise ValueError(
            "match_target requires a string action_target, got %s"
            % type(action_target).__name__)
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) \
            or not 0 < threshold <= 1:
        raise ValueError(
            "threshold must satisfy 0 < t <= 1, got %r" % (threshold,))
    if isinstance(goal_targets, dict):
        raise ValueError(
            "goal_targets must be a list of targets or (key, target) "
            "pairs, not a dict")
    if not action_target.strip():
        return (None, 0.0)
    pairs = []
    for entry in goal_targets:
        if isinstance(entry, str):
            pairs.append((entry, entry))
        elif (isinstance(entry, (list, tuple)) and len(entry) == 2
                and isinstance(entry[1], str)):
            pairs.append((entry[0], entry[1]))
        # Malformed entries provide no cover (fail closed).
    best_key, best_score = None, 0.0
    for key, goal_target in pairs:
        if not goal_target.strip():
            continue
        score = target_similarity(action_target, goal_target)
        if score > best_score:
            best_key, best_score = key, score
    if best_score >= threshold:
        return (best_key, best_score)
    return (None, 0.0)


# ---------------------------------------------------------------------------
# Wave-147 (row-11): synonym-aware typed-scope similarity.
#
# Residual from wave-145/146: the type-to-confirm ceremony's raw
# token-tversky check is synonym-INDIFFERENT in the dangerous
# direction. "send the report" vs "archive the Q3 report" scores
# 0.5714 >= 0.5 -- the shared noun "report" carries a DIFFERENT
# action over the threshold, so the ceremony would accept a typed
# scope naming the wrong action (fail-open on meaning, fail-closed
# only on tokens). Meanwhile "erase the report" vs "delete the Q3
# report" (a true synonym match) also scores 0.5714 -- held, but
# only by noun luck, not by verb understanding.
#
# The layer below is used ONLY by the type-to-confirm ceremony
# (gov/approvals._type_to_confirm_ok). The row-11 paraphrase tier
# (gov/goal_audit.py, gov/goals.py detect_cross_run_laundering)
# keeps raw token-tversky: the GRANT path is NOT widened.
#
# Curated synonym map (bounded, documented; every entry hand-picked
# for the ceremony's verb/noun space -- NOT auto-expanded from any
# external wordlist: $0, stdlib, deterministic, and no silent
# vocabulary drift):
#   DELETE  <- delete, erase, remove, destroy
#   SEND    <- send, transmit, dispatch
#   ARCHIVE <- archive, store, backup
#   REPORT  <- report, document, file      (nouns canonicalize too)
#   Q3      <- q3                          (identity: deliberately NOT
#              expanded -- "Q3"/"quarter-three" stays a literal token;
#              expanding time references would fuzz what the scope is)
#
# Design (deviation from the wave-147 sketch, measured): the sketch
# proposed additive synonym EXPANSION and max(raw, expanded). That
# provably cannot refuse the wrong-verb pair: expansion only ADDS
# overlap, and the pair already scores 0.5714 >= 0.5 raw, so
# max(raw, expanded) >= 0.5 always. The shipped design instead
# CANONICALIZES (each token maps to its canonical form) and adds a
# VERB-AGREEMENT VETO in the wave-136 destination-veto idiom: when
# BOTH texts name an action verb from the curated verb classes and
# the canonical verbs DIFFER, similarity is forced to 0.0. The veto
# is conservative by design -- it can only suppress matches, never
# create them. max(raw, canonical) is taken only when no veto fires,
# so canonicalization can only ever ADD true-synonym matches on top
# of the raw behavior, never remove them.
#
# The veto needs both sides to name a verb: a typed scope with no
# verb-class token ("the Q3 report", "please handle it") falls back
# to max(raw, canonical) -- graceful, no new refusal mode for
# verbless typing. A one-sided destination veto is unchanged from
# the raw path (veto computed on the ORIGINAL texts, since
# canonicalization strips the dotted-domain shape the veto reads).
# ---------------------------------------------------------------------------

#: Auditable method tag for the synonym-aware ceremony path (recorded
#: on approval_scope_mismatch / goal_specificity_scope_typed events
#: and on the narrowed record, replacing MATCH_METHOD there).
TTC_MATCH_METHOD = "token-tversky+synonym"

#: Curated synonym map: stemmed token -> canonical form. Keys are
#: post-stemming (the map is applied after _stem, matching
#: tokenize()'s pipeline). Q3 maps to itself: identity, not
#: expansion (see the design note above).
_TTC_SYNONYM_MAP = {
    # verbs: DELETE class
    "delete": "delete", "erase": "delete", "remove": "delete",
    "destroy": "delete",
    # verbs: SEND class
    "send": "send", "transmit": "send", "dispatch": "send",
    # verbs: ARCHIVE class
    "archive": "archive", "store": "archive", "backup": "archive",
    # nouns: REPORT class
    "report": "report", "document": "report", "file": "report",
    # identity (deliberately unexpanded)
    "q3": "q3",
}

#: Verb classes: stemmed token -> canonical verb. Only verbs are
#: veto-relevant; nouns canonicalize but never veto.
_TTC_VERB_CLASSES = {
    "delete": "delete", "erase": "delete", "remove": "delete",
    "destroy": "delete",
    "send": "send", "transmit": "send", "dispatch": "send",
    "archive": "archive", "store": "archive", "backup": "archive",
}


def _canonical_tokens(text):
    """Token set with synonym canonicalization applied.

    Same pipeline as tokenize() (lowercase, _TOKEN_RE, stem,
    stopwords dropped), then each stem maps through
    _TTC_SYNONYM_MAP (identity when absent).

    Break-round v2: read on _disc_norm (NFKC + zero-width-strip +
    lowercase) so invisible-char-split tokens canonicalize like
    their visible forms. Ceremony-only; ASCII behavior identical
    to before.
    """
    out = set()
    for t in _TOKEN_RE.findall(_disc_norm(text)):
        if t in _STOPWORDS:
            continue
        stemmed = _stem(t)
        out.add(_TTC_SYNONYM_MAP.get(stemmed, stemmed))
    return out


def _verb_class(text):
    """Canonical verb class of the FIRST verb-class token in ``text``.

    Scans tokens in order (lowercased, stemmed); returns the
    canonical verb ("delete"/"send"/"archive") or None when no
    verb-class token appears. First-verb-wins matches the ceremony's
    reference shape ("verb target" effect atoms) and ordinary
    imperative phrasing ("erase the report").

    Break-round v2: read on _disc_norm (NFKC + zero-width-strip +
    lowercase) so invisible-char-split verbs still read as their
    class. Ceremony-only; ASCII behavior identical to before.
    """
    for t in _TOKEN_RE.findall(_disc_norm(text)):
        cls = _TTC_VERB_CLASSES.get(_stem(t))
        if cls is not None:
            return cls
    return None


def typed_scope_similarity(typed, reference):
    """Synonym-aware similarity for the type-to-confirm ceremony.

    ``max(raw token-tversky, canonicalized token-tversky)`` at the
    same DEFAULT_THRESHOLD, with three conservative vetoes (any
    forces 0.0):
      - destination veto (wave-136, unchanged): both texts name
        explicit differing destinations -> 0.0. Computed on the
        ORIGINAL texts.
      - verb-agreement veto (wave-147): both texts name a
        verb-class action verb and the canonical verbs differ ->
        0.0. "send the report" vs "archive the Q3 report" is 0.0;
        "erase the report" vs "delete the Q3 report" is 0.8889.
      - discriminator veto (row-11 follow-up leg): the typed
        text contradicts the reference on a scope discriminator
        (differing specific quarters Q1..Q4, differing 4-digit
        years, or a typed-side widening quantifier the reference
        does not name) -> 0.0. "delete the Q4 report" vs "delete
        the Q3 report" is 0.0; "erase all filings" vs "delete the
        Q3 report" is 0.0. Contradiction-only: one-sided or
        absent discriminators never veto.

    Empty/None inputs score 0.0 and never match; non-string inputs
    raise ValueError (same type discipline as target_similarity).
    Deterministic, stdlib-only.

    Used ONLY by gov/approvals._type_to_confirm_ok. The row-11
    paraphrase tier keeps raw target_similarity.
    """
    if typed is None or reference is None:
        return 0.0
    if not isinstance(typed, str) or not isinstance(reference, str):
        raise ValueError(
            "typed_scope_similarity requires strings, got %s and %s"
            % (type(typed).__name__, type(reference).__name__))
    if not typed.strip() or not reference.strip():
        return 0.0
    if _discriminator_conflict(typed, reference):
        return 0.0  # discriminator veto: never fuzz scope identity
    # Break-round v2 (evasion probes e10-e13): a typed scope that
    # names NO object noun cannot match a reference whose scope
    # identity includes a specific object -- "delete the thing" vs
    # "delete the Q3 report" scored 0.571 on verb luck alone, and
    # "remove it" 0.667. The wave-147/149 pinned accepts all name
    # a noun-class object on the typed side, so the rule is
    # suppress-only with no movement on the labeled corpus.
    # Ceiling: the noun classes are the closed report family
    # (_STRUCT_NOUN_CLASSES) -- an unlisted object class on the
    # reference side ("delete the Q3 customer list") is outside
    # the check, by the same closed-list discipline as the
    # discriminator itself.
    if _struct_noun_set(reference) and not _struct_noun_set(typed):
        return 0.0  # nounless typed scope: never fuzz the object
    raw = target_similarity(typed, reference)
    da, db = _destinations(typed), _destinations(reference)
    if da and db and da != db:
        return 0.0  # destination veto (on originals): never fuzz
    expanded = _tversky(_canonical_tokens(typed),
                        _canonical_tokens(reference))
    va, vb = _verb_class(typed), _verb_class(reference)
    if va is not None and vb is not None and va != vb:
        return 0.0  # verb-agreement veto: different actions
    return max(raw, expanded)


# ---------------------------------------------------------------------------
# Wave-149 (row-11): structural typed-scope match (third signal).
#
# Residual from wave-147: threshold-aware paraphrasing of the typed
# scope can dodge BOTH the token-tversky check and the synonym
# canonicalization -- typed text that means the same thing but shares
# no tokens AND no curated synonyms with the reference scores 0.0 on
# both numeric tiers. "obliterate the quarterly filing" vs "delete
# the Q3 report": "obliterate" is not in the curated verb classes,
# "filing" is not in the noun map, "quarterly" shares nothing with
# "q3" -- both tiers read 0.0 and the ceremony refuses a genuinely
# matching scope (fail-closed in the wrong direction: the human typed
# the right thing and the ceremony blocks them).
#
# The third signal is STRUCTURAL, not lexical: same verb class (the
# synonym map's verb sets, plus the measured wave-149 extension
# below) AND an identical object-noun stem set on BOTH texts ->
# match, even at zero token overlap. It is used ONLY by the
# type-to-confirm ceremony (gov/approvals._type_to_confirm_ok), OR-ed
# with the numeric tiers -- the row-11 paraphrase tier
# (gov/goal_audit.py, gov/goals.py detect_cross_run_laundering) keeps
# raw token-tversky, and the GRANT path is NOT widened.
#
# Design notes (all measured, see evals/type_structure_probes.py):
# - Verb classes: the synonym map's verb sets (_TTC_VERB_CLASSES)
#   plus the single measured extension "obliterate" -> DELETE (the
#   battery's threshold-aware paraphrase verb). The crude _stem
#   leaves "obliterate" intact but strips "obliterated" to
#   "obliterat", so both keys are carried (documented stemmer
#   quirk, same family as the "addresses" -> "addresse" ceiling).
#   First-verb-wins, same as _verb_class.
# - Object nouns: the synonym map's REPORT noun set (report,
#   document, file) plus "filing" (a report by another name; the
#   battery's paraphrase noun), applied to the STEMMED token -- the
#   map is closed and explicit. "quarterly" is an adjective, not a
#   noun-class member, so it drops out of the set; the comparison
#   is on the noun sets, not the raw token sets. Empty noun set on
#   either side -> no match (conservative: "obliterate everything"
#   never structurally matches).
# - The sets must be EQUAL, not merely overlapping: "delete the
#   Q3 report" vs "delete the Q4 report" both reduce to {report} --
#   the signal cannot see the time discriminator. That pair is a
#   DOCUMENTED ceiling (measured in the battery, not counted in
#   the labeled false-match rate): the raw token-tversky tier has
#   the identical property (it scores that pair 0.8 >= 0.5), so
#   the structural signal introduces no NEW fuzzing of what the
#   scope is.
# - The destination veto (wave-136 idiom) applies unchanged: both
#   texts naming differing explicit destinations -> no match. It
#   can only suppress matches, never create them.
# - Naive stemmer: the module's _stem (strips -ing/-ed/-s),
#   documented as crude in the module docstring. Stemming errors
#   only ever ADD noun-class membership, so they fail toward more
#   matching, never less; the labeled set measures the rate at 0.
# ---------------------------------------------------------------------------

#: Auditable method tag for the structural ceremony path (recorded on
#: approval_scope_mismatch / goal_specificity_scope_typed events and
#: on the narrowed record when the structural signal -- not the
#: numeric tiers -- accepts the typed scope).
TTC_STRUCT_METHOD = "structural"

#: Structural verb classes: the synonym map's verb sets plus the
#: measured wave-149 extension. Keys are post-stemming (same
#: pipeline as _verb_class).
_STRUCT_VERB_CLASSES = dict(_TTC_VERB_CLASSES)
_STRUCT_VERB_CLASSES.update({
    # "obliterate" -> DELETE: the threshold-aware paraphrase verb
    # pinned by the battery. "obliterated" stems to "obliterat"
    # under the crude _stem (len>5 "ed" strip), hence the second
    # key -- a documented stemmer quirk, not a second synonym.
    "obliterate": "delete",
    "obliterat": "delete",
})

#: Structural noun classes: stemmed token -> canonical noun. The
#: closed REPORT set (report/document/file from the synonym map,
#: plus the measured "filing"). Adjectives ("quarterly"), unlisted
#: nouns ("database", "list"), and pronouns drop out -- an empty
#: set never matches.
_STRUCT_NOUN_CLASSES = {
    "report": "report",
    "document": "report",
    "file": "report",
    "filing": "report",
}


def _struct_verb_class(text):
    """Canonical verb class of the FIRST structural verb token.

    Same first-verb-wins discipline as _verb_class, over the
    extended _STRUCT_VERB_CLASSES.

    Break-round v2: read on _disc_norm (NFKC + zero-width-strip +
    lowercase) so invisible-char-split verbs still read as their
    class. Ceremony-only; ASCII behavior identical to before.
    """
    for t in _TOKEN_RE.findall(_disc_norm(text)):
        cls = _STRUCT_VERB_CLASSES.get(_stem(t))
        if cls is not None:
            return cls
    return None


def _struct_noun_set(text):
    """Canonical object-noun set of ``text``.

    Stopwords dropped, tokens stemmed, then mapped through the
    closed _STRUCT_NOUN_CLASSES. Returns a (possibly empty) set of
    canonical nouns.

    Break-round v2: read on _disc_norm (NFKC + zero-width-strip +
    lowercase) so an invisible-char-split noun ("repor<ZWSP>t")
    still counts as the noun it names rather than as a nounless
    evasion. Ceremony-only.
    """
    out = set()
    for t in _TOKEN_RE.findall(_disc_norm(text)):
        if t in _STOPWORDS:
            continue
        cls = _STRUCT_NOUN_CLASSES.get(_stem(t))
        if cls is not None:
            out.add(cls)
    return out


def structural_scope_match(typed, reference):
    """Structural scope match for the type-to-confirm ceremony.

    True iff BOTH texts name a verb from the structural verb
    classes AND the canonical verbs are the SAME AND the
    object-noun stem sets are IDENTICAL and non-empty. The
    wave-136 destination veto applies (differing explicit
    destinations on both sides -> False), as does the
    discriminator veto (contradictory quarters/years or
    typed-side widening quantifiers -> False).

    "obliterate the quarterly filing" vs "delete the Q3 report"
    -> True (DELETE == DELETE, {report} == {report}); the same
    typed text vs "archive the Q3 report" -> False (verb-class
    veto: DELETE != ARCHIVE); garbage vs anything -> False (no
    verb class and/or no nouns).

    Same type discipline as the other tiers: None/blank -> False;
    non-string inputs raise ValueError. Deterministic, stdlib-only.
    Used ONLY by gov/approvals._type_to_confirm_ok, OR-ed with the
    numeric tiers. The row-11 paraphrase tier keeps raw
    token-tversky.
    """
    if typed is None or reference is None:
        return False
    if not isinstance(typed, str) or not isinstance(reference, str):
        raise ValueError(
            "structural_scope_match requires strings, got %s and %s"
            % (type(typed).__name__, type(reference).__name__))
    if not typed.strip() or not reference.strip():
        return False
    da, db = _destinations(typed), _destinations(reference)
    if da and db and da != db:
        return False  # destination veto (on originals): never fuzz
    if _discriminator_conflict(typed, reference):
        return False  # discriminator veto: never fuzz scope identity
    va, vb = _struct_verb_class(typed), _struct_verb_class(reference)
    if va is None or vb is None or va != vb:
        return False  # verb-class veto: different (or absent) actions
    na, nb = _struct_noun_set(typed), _struct_noun_set(reference)
    if not na or not nb or na != nb:
        return False  # object nouns must agree exactly
    return True
