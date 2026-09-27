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

__all__ = [
    "target_similarity",
    "match_target",
    "tokenize",
    "typed_scope_similarity",
    "DEFAULT_THRESHOLD",
    "MATCH_METHOD",
    "TTC_MATCH_METHOD",
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
    """
    out = set()
    for t in _TOKEN_RE.findall(text.lower()):
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
    """
    for t in _TOKEN_RE.findall(text.lower()):
        cls = _TTC_VERB_CLASSES.get(_stem(t))
        if cls is not None:
            return cls
    return None


def typed_scope_similarity(typed, reference):
    """Synonym-aware similarity for the type-to-confirm ceremony.

    ``max(raw token-tversky, canonicalized token-tversky)`` at the
    same DEFAULT_THRESHOLD, with two conservative vetoes (either
    forces 0.0):
      - destination veto (wave-136, unchanged): both texts name
        explicit differing destinations -> 0.0. Computed on the
        ORIGINAL texts.
      - verb-agreement veto (wave-147): both texts name a
        verb-class action verb and the canonical verbs differ ->
        0.0. "send the report" vs "archive the Q3 report" is 0.0;
        "erase the report" vs "delete the Q3 report" is 0.8889.

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
