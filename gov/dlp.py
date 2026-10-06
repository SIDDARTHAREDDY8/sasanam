"""Data-loss prevention: credential blocking and PII redaction.

Two jobs, with different severities:

* **Block.** Credential-looking patterns (API keys, private keys, tokens,
  JWTs, DB connection strings) in tool arguments cause the executor to DENY
  the call before any policy evaluation or execution. Secrets must never
  leave the boundary.
* **Redact.** PII patterns (SSN, credit-card numbers with a Luhn check,
  emails, phone numbers) are replaced with ``[REDACTED:<rule>]`` in anything
  written to the action log or the approval queue. PII in logs is a breach
  waiting to happen; the decision is logged, the value is not.

A conservative entropy tripwire blocks high-entropy tokens that appear next
to credential keywords (``password``, ``api_key``, ...) even when they do
not match a known format.

ENCODING-AWARE MATCHING (F2, extended F8, F428, F429, F430). The credential patterns above
are syntactic, so an attacker can smuggle a credential past them with one
encoding step (hex, base64, base32, URL-encoding, JSFuck, text escapes,
JS string expressions).
``find_credential``
therefore decodes likely encodings BEFORE pattern matching, bounded to 2
layers: each layer finds candidate encoded runs, decodes only those that
validate (base64/base32 round-trip / even-length hex / percent-decoding
that changes the text / strict static JSFuck evaluation / strict
static JS-expression evaluation / strict
backslash-escape, numeric-HTML-entity, and UTF-16-null decodes / NFKC +
zero-width confusable normalization) AND decode to
mostly-printable ASCII, then re-runs
the credential rules on the decoded variants. Innocent base64-looking text
(random tokens, hashes) decodes to binary and is rejected by the printable
check, so it is never blocked; text whose DECODED form matches a credential
regex is blocked because the decoded content genuinely contains a
credential-shaped string. The JSFuck decoder is a strict bounded
evaluator, never a JS engine: undecodable runs are ignored, and
Function() (arbitrary code) always fails closed. The text-escape decoders
(F429) are likewise strict static transforms -- malformed, surrogate, or
out-of-range sequences decode to nothing, never to a guess. The
JS-expression decoder (F430) is a strict bounded recursive-descent
parser for quoted '+' concatenation, template literals (no ${...}),
String.fromCharCode, .concat()/.repeat(), (F434) array-literal
+ .join(sep), (F437) .reduce(...) array-assembly plus identity .map(...)
/ constant-true .filter(...) passthroughs, and (F443) Array(N).fill(x)
construction plus .filter(Boolean) truthiness filtering -- never eval;
undecodable runs are ignored and bare
literals are not rewritten.

FORM VARIANTS (F8). Every candidate string (the original text and each
decoded variant) is also checked whitespace-stripped and reversed: those
are deterministic, precise transforms of a KNOWN-FORMAT credential, and a
match on any form blocks. The joined buffer of ALL string params is
scanned too (chunked-across-params), with regex rules only — never the
entropy tripwire, which stays on the original text (see below).

Deliberate boundary: the entropy tripwire runs on the ORIGINAL text only.
Running a heuristic tripwire on decoded variants would amplify its
false-positive surface (any printable decode containing a keyword plus a
long token); known-format credential rules on decoded text are precise.
An unknown-format credential smuggled via encoding next to a keyword is a
documented residual, not a silent bypass — the known-format defeat (F2)
is closed. Custom substitution ciphers (arbitrary bijections, F8 residual)
are NOT deterministically catchable and remain a documented residual.

Field-level policy (see ``scan_tool_args``): some fields are audit-relevant
and stay readable (email recipients, URLs, file paths); payloads and file
contents are summarized to ``{bytes, sha256}`` so secret material never
reaches the log at all.
"""

import base64
import hashlib
import math
import re
import unicodedata
from urllib.parse import unquote, unquote_plus, urlparse

# ---------------------------------------------------------------- patterns

_CREDENTIAL_RULES = [
    # (rule_id, compiled regex) -- a match BLOCKS the call.
    ("dlp-aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("dlp-github-token",
     re.compile(r"(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("dlp-stripe-live-key", re.compile(r"sk_live_[A-Za-z0-9]{16,}")),
    ("dlp-stripe-test-key", re.compile(r"sk_test_[A-Za-z0-9]{16,}")),
    ("dlp-private-key",
     re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("dlp-jwt",
     re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("dlp-slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("dlp-google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("dlp-connection-string",
     re.compile(r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^/\s]*@[^/\s]+")),
]

# F91 (Wave 25): the PII patterns below use digit-only boundaries
# (``(?<![0-9])`` / ``(?![0-9])``) instead of ``\b``. The AGT
# redaction-evasion class — affixing a word character to a sensitive
# value (``123-45-6789_old``, ``old_123-45-6789``) — defeated ``\b``
# and leaked the value into logs/approvals in cleartext. Digits and
# dashes adjacent to the pattern still suppress the match (a longer
# numeric run is not an SSN/phone/card); letters and underscores are
# treated as affixes and the sensitive core is still redacted, which
# is the fail-closed direction for log redaction.
_PII_RULES = [
    # (rule_id, compiled regex) -- a match is REDACTED in logs/approvals.
    ("pii-ssn", re.compile(r"(?<![0-9])\d{3}-\d{2}-\d{4}(?![0-9])")),
    ("pii-email",
     re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("pii-phone",
     re.compile(r"(?<![0-9])(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?![0-9])")),
]

_CARD_RE = re.compile(r"(?<![0-9])(?:\d[ -]*?){13,19}(?![0-9])")

# F16: the entropy tripwire's keyword list is matched in a NORMALIZED
# space — lowercase, leet-speak folded, and every whitespace RUN replaced
# by a \x00 boundary marker (no whitespace survives, but word edges do,
# so "deploy password" still has a boundary while "private key" and
# "privatekey" both match). Synonyms ("credentials"), spaced forms
# ("private key"), and leet ("p4ssw0rd" -> "password") all trip it. The
# window / token / entropy half still runs on the ORIGINAL text (match
# positions are mapped back), so the precise-credential regexes and the
# entropy behavior are untouched.
# F91 (Wave 25): the keyword boundaries are letter-only
# (``(?<![A-Za-z])`` / ``(?![A-Za-z])``) rather than ``\b``. The
# affix-evasion class (``password_old``, ``old_password``,
# ``api_key_backup``) defeated ``\b`` and let unknown-format secrets
# next to affixed keywords slip past the tripwire. Letters adjacent
# to a keyword still suppress the match — ``monkey`` / ``keyboard``
# must not trip — but ``_``/``-``/digits are treated as affixes
# (rotation-naming conventions like ``key2``), which is the
# fail-closed direction for a heuristic tripwire.
_TRIP_KEYWORDS = re.compile(
    r"(?<![A-Za-z])(password|passwd|passcode|pwd|secret|credentials?|creds|token|"
    r"api[_\-\x00]?key|private[_\-\x00]?key|key|access|auth|login|"
    r"aws_secret|client_secret)(?![A-Za-z])")

_LEET_FOLD = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "@": "a", "$": "s", "!": "i",
}


def _normalize_tripwire(text):
    """Normalize *text* for keyword matching.

    Returns (normalized, positions): lowercase, leet-speak folded, each
    whitespace run replaced by one \\x00 boundary marker;
    ``positions[i]`` is the index in the ORIGINAL text of
    ``normalized[i]``, so a keyword match in normalized space maps back
    to the true window for the token/entropy half.
    """
    norm, positions = [], []
    in_ws = False
    for i, ch in enumerate(text):
        if ch.isspace():
            if not in_ws:
                norm.append("\x00")
                positions.append(i)
                in_ws = True
            continue
        in_ws = False
        low = ch.lower()
        norm.append(_LEET_FOLD.get(low, low))
        positions.append(i)
    return "".join(norm), positions


def _tripwire_hit(text):
    """Entropy tripwire: a long high-entropy token sitting near a
    credential keyword (in normalized space) is an unknown key format."""
    norm, positions = _normalize_tripwire(text)
    for m in _TRIP_KEYWORDS.finditer(norm):
        ws = max(0, m.start() - 10)
        we = min(len(norm), m.end() + 80)
        window = text[positions[ws]:positions[we - 1] + 1]
        for token in _HIGH_ENTROPY_TOKEN_RE.findall(window):
            if _shannon_entropy(token) > HIGH_ENTROPY_TOKEN_MIN_ENTROPY:
                return True
    return False


# F99 (Wave 27): parameters shared by the keyword-adjacent entropy
# tripwire (``_tripwire_hit``, DENY effect) and the keyword-free framed
# secret tripwire (``has_high_entropy_token``, QUEUE effect via the
# policy engine). 20 chars / entropy > 4.3 is the FP-analyzed boundary
# inherited from F2/F8: hex digests (~3.7), UUIDs (~3.4) and random
# base64-of-binary fixtures (~4.26) stay under it, while unknown-format
# framed secrets (the F99 probe token: 4.375) trip it. Without a
# credential keyword nearby the signal can only justify human review,
# never a block.
#
# F106 (Wave 27): the signal covers the api_call ENDPOINT URL too
# (query values + path segments, per-segment so adjacent low-entropy
# segments never join into a phantom run through '/'/'=' — both in the
# token alphabet). F105 (Wave 27) is the accepted encoding residual:
# hex/base32 alphabets cap entropy below 4.3, so decode-and-rescan
# cannot separate honest from adversarial hex — measured 2026-09-22: an
# honest SHA-256 digest decodes to per-byte entropy 4.875, an
# adversarial 32-byte secret to 4.938 (same distribution; no threshold
# separates them). Queueing decoded-hex hits would FP-collapse on
# honest digests, which the closure's FP analysis requires to EXECUTE.
# Low-alphabet encodings of unknown-format secrets are therefore a
# documented residual of this rule, not a silent bypass.
HIGH_ENTROPY_TOKEN_MIN_LEN = 20
HIGH_ENTROPY_TOKEN_MIN_ENTROPY = 4.3
_HIGH_ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9_+/=-]{%d,}"
                                    % HIGH_ENTROPY_TOKEN_MIN_LEN)


def has_high_entropy_token(text):
    """Keyword-free framed-secret tripwire (F99).

    True when *text* contains a token-like run of at least
    ``HIGH_ENTROPY_TOKEN_MIN_LEN`` chars whose Shannon entropy exceeds
    ``HIGH_ENTROPY_TOKEN_MIN_ENTROPY``. This is the unknown-format /
    paraphrase exfil channel DLP cannot name (no credential keyword to
    anchor on), so callers must use it for require_approval (queue)
    decisions only — never deny. Scans the given text only; callers
    must not join cross-field buffers (the F2/F8 boundary: the entropy
    tripwire stays on the original text). Low-alphabet encodings
    (hex/base32) of secrets never trip by construction (alphabet cap
    4.0 < 4.3) — the documented F105 residual, not a miss.
    """
    if not text:
        return False
    for token in _HIGH_ENTROPY_TOKEN_RE.findall(text):
        if _shannon_entropy(token) > HIGH_ENTROPY_TOKEN_MIN_ENTROPY:
            return True
    return False


def params_have_high_entropy_token(params):
    """F99: True when any string inside a (possibly nested) params
    mapping carries a high-entropy token-like run.

    The params-side half of the executor's ``high_entropy_payload``
    signal — see ``api_call_high_entropy_payload`` for the full
    composition (params + endpoint URL), which is what the executor
    and the simulator's replay recomputation must call. Single source
    of truth for the params traversal; do not reimplement the
    traversal elsewhere (a divergent copy would silently desync
    replay).
    """
    stack = [params]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            if has_high_entropy_token(v):
                return True
        elif isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend(v)
    return False


def endpoint_url_has_high_entropy_token(endpoint):
    """F106: True when the endpoint URL's query string or path carries
    a high-entropy token-like run.

    The URL is a first-class exfil channel to the allowlisted host (the
    F94 allowlist matches hostname only), and DLP's ``find_credential``
    needs a known pattern or keyword adjacency — an unknown-format
    token in a query string or path matches neither. Scanned per query
    VALUE (``k=v`` pairs split on ``&``/``;``; keys are not content,
    the params-side convention) and per path SEGMENT (split on ``/``),
    each both raw and percent-decoded: splitting first keeps adjacent
    low-entropy segments from joining into a phantom run through
    ``/``/``=`` (both in the token alphabet) — e.g. a git-SHA path
    ``/repos/x/commits/<sha>`` stays clean — while decoding catches
    URL-encoded tokens. Fragments are not scanned (never sent to the
    server); userinfo is out of scope (noted residual).
    """
    if not endpoint or not isinstance(endpoint, str):
        return False
    try:
        parts = urlparse(endpoint)
    except Exception:
        return False
    for pair in re.split(r"[&;]", parts.query or ""):
        if not pair:
            continue
        value = pair.split("=", 1)[1] if "=" in pair else pair
        if (has_high_entropy_token(value)
                or has_high_entropy_token(unquote_plus(value))):
            return True
    for seg in (parts.path or "").split("/"):
        if not seg:
            continue
        if (has_high_entropy_token(seg)
                or has_high_entropy_token(unquote(seg))):
            return True
    return False


def api_call_high_entropy_payload(args):
    """F99/F106: the single source of truth for the executor's
    ``high_entropy_payload`` policy-context key (and the simulator's
    deterministic recomputation).

    True when the api_call's params (any nested string value) OR its
    endpoint URL (query values / path segments) carries a high-entropy
    token-like run. Do not reimplement this composition elsewhere —
    a divergent copy would silently desync replay.
    """
    args = args or {}
    return (params_have_high_entropy_token(args.get("params"))
            or endpoint_url_has_high_entropy_token(args.get("endpoint")))


def _luhn_ok(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _shannon_entropy(text):
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ------------------------------------------------- encoding-aware matching
# F2/F428/F429: decode likely encodings BEFORE credential pattern matching,
# bounded to 2 layers. Every candidate must VALIDATE (strict decode +
# round-trip for base64, even-length for hex, strict static evaluation for
# JSFuck, strict static decode for text escapes) and decode
# to mostly-printable ASCII;
# otherwise it is not a hidden credential, it is a random token/hash, and it
# is ignored. This keeps innocent base64-looking text unblocked.

_B64_RUN = re.compile(r"[A-Za-z0-9+/\-_]{24,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")
_B32_RUN = re.compile(r"[A-Z2-7]{24,}={0,6}")
# F445: short base64/base64url and base32 runs (8-23 payload chars). The
# 24-char floor above is an FP guard against word-like runs; short runs
# are attempted ONLY when the strict decode round-trips AND the decoded
# text is credential-shaped (the guard made precise -- see
# _b64_short_variants / _b32_short_variants). The negative
# lookbehind/lookahead keep these from matching interior slices of
# longer runs (already handled by the long path); padding '=' is not a
# boundary char, so a padded short run still matches.
_B64_SHORT_RUN = re.compile(
    r"(?<![A-Za-z0-9+/\-_])[A-Za-z0-9+/\-_]{8,23}={0,2}"
    r"(?![A-Za-z0-9+/\-_])")
_B32_SHORT_RUN = re.compile(
    r"(?<![A-Z2-7])[A-Z2-7]{8,23}={0,6}(?![A-Z2-7])")
# F445: floor on short-run decode attempts. 8 payload chars decode to 6
# bytes (b64) / 5 bytes (b32); no credential rule can match that little
# (the shortest rule needs 15 chars: xox[baprs]- plus 10), so the floor
# only gates attempts, never blocking decisions -- same discipline as
# the F428 JSFuck threshold.
_B64_SHORT_FLOOR = 8
# F428: JSFuck is a JS-execution encoding over the alphabet []()!+- (unary
# minus included). A run of 64+ alphabet chars is essentially never
# innocent text; genuine single-char JSFuck is shorter but a single
# decoded char can never match a credential rule, so the threshold only
# gates decode ATTEMPTS, never blocking decisions.
_JSFUCK_RUN = re.compile(r"[\[\]()!+\-]{64,}")
# F429: text-escape runs. Backslash escapes (\uXXXX / \UXXXXXXXX / \xXX
# / octal / CSS \HHHHHH<space>) need only 1+ escapes before a decode is
# attempted (F432: a single escaped char decodes to the raw credential in
# any real JSON/JS/CSS parser). The ASCII-printable gate and the
# credential-rule match still protect precision: a lone escape that
# decodes to non-credential text never blocks.
# F433: CSS escapes may also terminate space-free -- per CSS Syntax L3
# 4.3.7 the escape ends at the first non-hex code point, which is NOT
# consumed (\78o -> 'x' + 'o'), and a single following whitespace
# (space, tab, LF, FF, CR, or CRLF) is consumed as part of the escape.
# The bare [0-9a-fA-F]{1,6} alternative (after the whitespace-terminated
# form) lets space-free runs be found; the strict decoders below
# validate them. NOTE: a non-whitespace terminator (e.g. '!') is NOT
# consumed, so it survives decoding and breaks consecutiveness -- only
# backslash- and whitespace-terminated escapes form runs.
_ESC_RUN = re.compile(
    r"(?:\\(?:u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|x[0-9a-fA-F]{2}"
    r"|[0-9a-fA-F]{1,6}(?:\r\n|[ \t\n\f])"
    r"|[0-9a-fA-F]{1,6}|[0-7]{1,3}))+")
# F429: numeric HTML entities (&#x..; / &#..;), 1+ (F432: a single
# entity decodes to the raw credential in any real HTML parser).
# F436: the trailing semicolon is OPTIONAL -- a real HTML parser
# (html.unescape) recovers the legacy no-semicolon form (&#65), so a
# no-semicolon entity inside a base64 run poisons the run match while
# the parser still recovers the credential. Greedy digit consumption
# (6 hex / 7 decimal max) mirrors html.unescape; 7+ hex or 8+ decimal
# digits are always out of range, so the cap is semantically identical.
_ENTITY_RUN = re.compile(r"(?:&#[xX][0-9a-fA-F]{1,6};?|&#[0-9]{1,7};?)+")
# F429: UTF-16 null-interleaved runs (ASCII bytes separated by NULs).
_UTF16N_RUN = re.compile(r"(?:[\x20-\x7e]\x00){4,}|(?:\x00[\x20-\x7e]){4,}")
# F429: zero-width / invisible joiners stripped by the confusable
# normalizer (whole-string variant, alongside NFKC).
_ZERO_WIDTH_RUN = re.compile("[\u200b\u200c\u200d\ufeff]")
# F431: bidi-override controls (U+202A-U+202E, U+2066-U+2069). An
# attacker interleaves RLO (U+202E) so the VISUAL rendering shows the
# credential while the byte sequence does not match. The bidi
# normalizer strips every control and reverses right-to-left-governed
# runs (RLO and RLE) to visual order; LRO/LRE/isolates keep logical
# order (FSI's first-strong is content-dependent -- the strip variant
# still catches logical-order credentials inside them). Bounded,
# static, never executes.
_BIDI_RLO = "\u202e"
_BIDI_LRO = "\u202d"
_BIDI_RLE = "\u202b"
_BIDI_REVERSING = frozenset((_BIDI_RLO, _BIDI_RLE))  # RTL display order
_BIDI_EMBED = frozenset(("\u202a",))                   # LRE (LTR: no reverse)
_BIDI_ISOLATE = frozenset(("\u2066", "\u2067", "\u2068"))  # LRI, RLI, FSI
_BIDI_POP = frozenset(("\u202c", "\u2069"))            # PDF, PDI
_BIDI_ALL = (_BIDI_REVERSING | frozenset((_BIDI_LRO,)) | _BIDI_EMBED
             | _BIDI_ISOLATE | _BIDI_POP)
_MAX_BIDI_CONTROLS = 128  # bound on processed bidi controls per text
# F431: Cyrillic homoglyphs that do NOT NFKC-fold to ASCII (U+043E
# stays U+043E under NFKC). Bounded static map of verified visual
# homoglyphs, applied after NFKC in the confusable normalizer. Every
# entry is pinned by evals/w344_f431close_probes.py.
_CYRILLIC_HOMOGLYPHS = {
    "\u0430": "a",  # CYRILLIC SMALL LETTER A
    "\u0435": "e",  # CYRILLIC SMALL LETTER IE
    "\u043e": "o",  # CYRILLIC SMALL LETTER O (F431 verified miss)
    "\u0440": "p",  # CYRILLIC SMALL LETTER ER
    "\u0441": "c",  # CYRILLIC SMALL LETTER ES
    "\u0445": "x",  # CYRILLIC SMALL LETTER HA
    "\u0456": "i",  # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "\u0458": "j",  # CYRILLIC SMALL LETTER JE
    "\u0455": "s",  # CYRILLIC SMALL LETTER DZE
    "\u043c": "m",  # CYRILLIC SMALL LETTER EM
    "\u043a": "k",  # CYRILLIC SMALL LETTER KA
    "\u043d": "H",  # CYRILLIC SMALL LETTER EN (looks like capital H)
    "\u0410": "A",  # CYRILLIC CAPITAL LETTER A
    "\u0412": "B",  # CYRILLIC CAPITAL LETTER VE
    "\u0421": "C",  # CYRILLIC CAPITAL LETTER ES
    "\u0415": "E",  # CYRILLIC CAPITAL LETTER IE
    "\u041d": "H",  # CYRILLIC CAPITAL LETTER EN
    "\u041a": "K",  # CYRILLIC CAPITAL LETTER KA
    "\u041c": "M",  # CYRILLIC CAPITAL LETTER EM
    "\u041e": "O",  # CYRILLIC CAPITAL LETTER O
    "\u0420": "P",  # CYRILLIC CAPITAL LETTER ER
    "\u0422": "T",  # CYRILLIC CAPITAL LETTER TE
    "\u0425": "X",  # CYRILLIC CAPITAL LETTER HA
}
_CYRILLIC_FOLD = {ord(k): v for k, v in _CYRILLIC_HOMOGLYPHS.items()}
# F435: Greek + Cherokee homoglyphs that do NOT NFKC-fold to ASCII
# (U+03BF omicron stays U+03BF under NFKC, same for the others).
# Bounded static map of verified visual homoglyphs, applied after
# NFKC in the confusable normalizer alongside the Cyrillic map.
# The four verified misses (small alpha/omicron/rho, Cherokee O)
# anchor the class; the capital siblings and the Cherokee small
# letter are the same visual-homoglyph class (Unicode confusables).
# Every entry is pinned by evals/w345_f435close_probes.py.
_GREEK_CHEROKEE_HOMOGLYPHS = {
    "\u03b1": "a",  # GREEK SMALL LETTER ALPHA (F435 verified miss)
    "\u03bf": "o",  # GREEK SMALL LETTER OMICRON (F435 verified miss)
    "\u03c1": "p",  # GREEK SMALL LETTER RHO (F435 verified miss)
    "\u13a3": "o",  # CHEROKEE LETTER O (F435 verified miss)
    "\u0391": "A",  # GREEK CAPITAL LETTER ALPHA (same visual class)
    "\u039f": "O",  # GREEK CAPITAL LETTER OMICRON (same visual class)
    "\u03a1": "P",  # GREEK CAPITAL LETTER RHO (same visual class)
    "\uab73": "o",  # CHEROKEE SMALL LETTER O (same letter as U+13A3)
}
_GREEK_CHEROKEE_FOLD = {ord(k): v for k, v in _GREEK_CHEROKEE_HOMOGLYPHS.items()}
_WS_RUN = re.compile(r"\s+")
_MAX_DECODE_BYTES = 4096  # bound on any single decoded blob
_MAX_JSFUCK_BYTES = 100000  # bound on a JSFuck run (artifact: 34635)
_MAX_CANDIDATES = 8       # bound on decode attempts per layer
# F436: bound on entities / escape runs decoded by a whole-text pass.
# One whole-text variant is a single decode attempt, so the item bound
# is a DoS guard, not an attempt budget: 64 stacked fragments still
# compose in 2 layers; beyond 64 the per-run path still tries.
_MAX_WHOLETEXT_ITEMS = 64
# F439: bound on base64 decode rounds in the decode-until-fixpoint pass.
# A credential wrapped in up to 3 base64 layers blocks; depth-4+ stays a
# documented non-goal (bounded decode budget, not a finding).
_MAX_B64_ROUNDS = 3


def _printable_ascii(data, min_ratio=0.9):
    if not data:
        return False
    good = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return good / len(data) >= min_ratio


def _try_b64_decode(run, min_payload=24):
    """Strict base64/base64url decode with round-trip validation.

    Returns the decoded ASCII string, or None when the run is not really
    base64 (wrong alphabet after normalization, bad padding, no round-trip,
    or decodes to binary rather than text).

    min_payload is the floor on payload chars (default 24: the F2/F8-era
    FP guard against word-like runs). The F445 short path passes 8 --
    the remaining guards (strict decode, exact round-trip,
    mostly-printable ASCII) are unchanged; the credential-shape gate in
    _b64_short_variants decides which short decodes become variants.
    """
    norm = run.replace("-", "+").replace("_", "/").rstrip("=")
    if len(norm) < min_payload:
        return None
    norm += "=" * (-len(norm) % 4)
    try:
        raw = base64.b64decode(norm, validate=True)
    except Exception:
        return None
    if len(raw) > _MAX_DECODE_BYTES:
        return None
    # Round-trip: re-encoding must reproduce the candidate (modulo padding).
    # Without this, arbitrary word-char runs "decode" to garbage bytes.
    if base64.b64encode(raw).decode("ascii").rstrip("=") != run.replace(
            "-", "+").replace("_", "/").rstrip("="):
        return None
    if not _printable_ascii(raw):
        return None
    # _printable_ascii is a 0.9-ratio heuristic, so up to 10% of the
    # bytes may still be non-ASCII: guard the final decode (wave-52
    # RT19: innocent base64-looking traffic crashed the scanner here).
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return None


def _b64_fixpoint_variants(text):
    """Bounded base64 decode-until-fixpoint variants (F439).

    For each base64/base64url run in *text*, decode repeatedly (at most
    _MAX_B64_ROUNDS rounds) and yield one variant per round with the run
    replaced by that round's decoded output. Decoding stops early (fail
    closed) when a round is not strict base64 (bad padding, no
    round-trip, binary output) or makes no progress, so this always
    terminates: valid decodes strictly shrink the run. These variants are
    checked directly by the strict scan and are NOT fed back into the
    layer pipeline, so the total base64 decode depth across the scan
    stays <= _MAX_B64_ROUNDS.
    """
    seen = set()
    for m in list(_B64_RUN.finditer(text))[:_MAX_CANDIDATES]:
        run = m.group(0)
        prev = run
        for _ in range(_MAX_B64_ROUNDS):
            decoded = _try_b64_decode(prev)
            if decoded is None:
                # F445: the innermost run of a short-credential stack can
                # be under 24 payload chars -- attempt the
                # credential-shape-gated short decode rather than
                # failing closed on the floor. The gate is identical to
                # the pipeline short path: only a credential-shaped
                # decode becomes a variant. (On a 24+ run this retry is
                # a no-op -- the floor is the only difference.)
                gated = _try_b64_decode(prev,
                                        min_payload=_B64_SHORT_FLOOR)
                if (gated is None
                        or _match_credential_forms(gated) is None):
                    break
                decoded = gated
            if decoded == prev:
                break
            variant = text[:m.start()] + decoded + text[m.end():]
            if variant not in seen:
                seen.add(variant)
                yield variant
            prev = decoded


def _b64_short_variants(text):
    """F445: short base64/base64url runs (8-23 payload chars) attempted
    only when the decoded candidate is credential-shaped.

    For each short run: strict-decode with the lowered floor
    (_B64_SHORT_FLOOR); a run that fails strict decode, round-trip, or
    the printable-ASCII gate is ignored. A run that DOES decode is a
    genuine encoding -- but it becomes a variant ONLY when the decoded
    text matches a credential rule. That credential-shape gate is the
    24-char floor's FP guard made precise: innocent short decodes
    (junk text, word fragments, UUIDs) never enter the variant
    pipeline, so they cannot block and cannot starve the
    _MAX_CANDIDATES budget either. One decode layer only -- stacked
    short runs compose via the 2-layer pipeline (an outer long run
    decodes in layer 1, the inner short run in layer 2). Bounded,
    static, never executes.
    """
    for m in list(_B64_SHORT_RUN.finditer(text))[:_MAX_CANDIDATES]:
        run = m.group(0)
        decoded = _try_b64_decode(run, min_payload=_B64_SHORT_FLOOR)
        if decoded is None:
            continue
        if _match_credential_forms(decoded) is None:
            continue
        variant = text[:m.start()] + decoded + text[m.end():]
        if variant != text:
            yield variant


def _b32_short_variants(text):
    """F445: short base32 runs (8-23 payload chars), same contract as
    _b64_short_variants -- strict decode plus the credential-shape gate
    before a variant is emitted. Same mechanism class as the base64
    gate, closed together."""
    for m in list(_B32_SHORT_RUN.finditer(text))[:_MAX_CANDIDATES]:
        run = m.group(0)
        decoded = _try_b32_decode(run, min_payload=_B64_SHORT_FLOOR)
        if decoded is None:
            continue
        if _match_credential_forms(decoded) is None:
            continue
        variant = text[:m.start()] + decoded + text[m.end():]
        if variant != text:
            yield variant


def _try_hex_decode(run):
    """Hex decode guarded by the printable-ASCII check."""
    if len(run) > 2 * _MAX_DECODE_BYTES:
        return None
    try:
        raw = bytes.fromhex(run)
    except ValueError:
        return None
    if not _printable_ascii(raw):
        return None
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return None


def _try_b32_decode(run, min_payload=24):
    """Strict base32 decode with round-trip validation (F8).

    Same contract as the base64 path: the run must be a genuine base32
    encoding (strict alphabet, valid padding, exact round-trip) that
    decodes to mostly-printable ASCII. Without the round-trip check,
    arbitrary uppercase/digit runs would "decode" to garbage bytes.

    min_payload is the floor on payload chars (default 24); the F445
    short path passes 8, with the credential-shape gate in
    _b32_short_variants deciding which short decodes become variants.
    """
    norm = run.rstrip("=")
    if len(norm) < min_payload:
        return None
    try:
        raw = base64.b32decode(norm + "=" * (-len(norm) % 8),
                               casefold=False)
    except Exception:
        return None
    if len(raw) > _MAX_DECODE_BYTES:
        return None
    if base64.b32encode(raw).decode("ascii").rstrip("=") != norm:
        return None
    if not _printable_ascii(raw):
        return None
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return None


# --------------------------------------------------- F428: JSFuck decoding
# JSFuck is a JS-execution encoding: arbitrary JS written with only the
# characters []()!+- (unary minus included). Salt Labs vs Manus (2026-10-03)
# showed it used for prompt-injection in the wild; the wave-341 attack lane
# showed a JSFuck-encoded slack token missing every DLP seam while the
# plain/base64/hex/base32 forms all block.
#
# A static decoder is safe here because it never executes: it is a strict,
# bounded recursive-descent evaluator for the JSFuck construction set that
# real encoders emit (literals ![]/!![]/+/-, string coercion, indexing,
# the "constructor"/"toString" member ladder, and calls of the safe
# primitive constructors String/Number/Boolean). Anything outside that set
# — notably Function() (arbitrary code) — fails closed: the run is not a
# decodable payload and is ignored, exactly like a base64 run that fails
# round-trip validation. The decoded text must additionally be
# mostly-printable ASCII and differ from the input before it becomes a
# variant, so the false-positive surface stays where it already was: the
# credential regexes themselves. A run that merely LOOKS like JSFuck but
# decodes to innocent text (or fails to decode) never blocks.


class _JSFuckFail(Exception):
    """Strict-decode failure: the run is not decodable JSFuck."""


_JSFuck_UNDEF = ("undef", None)

# V8 Function.prototype.toString forms for the callable surface the
# decoder supports. The artifact was node-verified (V8); a non-V8 form
# simply fails closed (no variant), it never mis-decodes.
_JSFUCK_FUNC_SOURCE = {
    "filter": "function filter() { [native code] }",
    "flat": "function flat() { [native code] }",
    "map": "function map() { [native code] }",
    "fill": "function fill() { [native code] }",
    "find": "function find() { [native code] }",
    "includes": "function includes() { [native code] }",
    "indexOf": "function indexOf() { [native code] }",
    "join": "function join() { [native code] }",
    "sort": "function sort() { [native code] }",
    "reverse": "function reverse() { [native code] }",
    "slice": "function slice() { [native code] }",
    "entries": "function entries() { [native code] }",
    "keys": "function keys() { [native code] }",
    "values": "function values() { [native code] }",
    "String": "function String() { [native code] }",
    "Number": "function Number() { [native code] }",
    "Boolean": "function Boolean() { [native code] }",
    "Array": "function Array() { [native code] }",
    "Function": "function Function() { [native code] }",
}

_JSFUCK_ARR_MEMBERS = set(_JSFUCK_FUNC_SOURCE) | {"constructor", "length"}


def _jsfuck_truthy(v):
    k = v[0]
    if k == "undef":
        return False
    if k == "bool":
        return v[1]
    if k == "num":
        return v[1] != 0 and v[1] == v[1]  # nonzero and not NaN
    if k == "str":
        return len(v[1]) > 0
    return True  # arrays and functions are truthy


def _jsfuck_primitive(v):
    k = v[0]
    if k in ("undef", "bool", "num", "str"):
        return v
    if k == "arr":
        # Array.prototype.toString: join(",").
        return ("str", ",".join(_jsfuck_to_string(e) for e in v[1]))
    if k == "func":
        try:
            return ("str", _JSFUCK_FUNC_SOURCE[v[1]])
        except KeyError:
            raise _JSFuckFail("unknown function %r" % (v[1],))
    raise _JSFuckFail("uncoercible %r" % (k,))


def _jsfuck_to_number(v):
    v = _jsfuck_primitive(v)
    k = v[0]
    if k == "undef":
        return float("nan")
    if k == "bool":
        return 1.0 if v[1] else 0.0
    if k == "num":
        return v[1]
    s = v[1].strip()
    if s == "":
        return 0.0
    if s in ("Infinity", "+Infinity"):
        return float("inf")
    if s == "-Infinity":
        return float("-inf")
    try:
        if (s[:2].lower() == "0x" and len(s) > 2
                and all(c in "0123456789abcdefABCDEF" for c in s[2:])):
            return float(int(s, 16))
        return float(s)
    except ValueError:
        return float("nan")


def _jsfuck_to_string(v):
    v = _jsfuck_primitive(v)
    k = v[0]
    if k == "undef":
        return "undefined"
    if k == "bool":
        return "true" if v[1] else "false"
    if k == "num":
        n = v[1]
        if n != n:
            return "NaN"
        if n == float("inf"):
            return "Infinity"
        if n == float("-inf"):
            return "-Infinity"
        if n == int(n) and abs(n) < 1e21:
            return str(int(n))
        return repr(n)
    return v[1]


def _jsfuck_num_to_string_radix(n, radix):
    """Number.prototype.toString(radix), integer n, radix 2..36."""
    if n != n:
        return "NaN"
    if n == float("inf"):
        return "Infinity"
    if n == float("-inf"):
        return "-Infinity"
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    neg = n < 0
    n = int(abs(n))
    if n == 0:
        return "0"
    out = ""
    while n:
        out = digits[n % radix] + out
        n //= radix
    return ("-" if neg else "") + out


class _JSFuckParser:
    """Strict recursive-descent evaluator for the JSFuck subset.

    Grammar (fully parenthesized, encoder-emitted):
      expr    := unary (("+" | "-") unary)*
      unary   := ("!" | "+" | "-")* postfix
      postfix := primary (("[" expr "]") | call)*
      primary := "[]" | "(" expr ")"
      call    := "(" (expr ("," expr)*)? ")"
    """

    def __init__(self, text, max_steps=2000000, max_depth=600):
        self.t = text
        self.n = len(text)
        self.i = 0
        self.steps = 0
        self.max_steps = max_steps
        self.max_depth = max_depth

    def _step(self):
        self.steps += 1
        if self.steps > self.max_steps:
            raise _JSFuckFail("step budget")

    def peek(self):
        return self.t[self.i] if self.i < self.n else ""

    def parse(self, depth=0):
        if depth > self.max_depth:
            raise _JSFuckFail("depth")
        v = self._parse_add(depth + 1)
        if self.i != self.n:
            raise _JSFuckFail("trailing input")
        return v

    def _parse_add(self, depth):
        self._step()
        v = self._parse_unary(depth)
        while self.peek() in ("+", "-"):
            op = self.t[self.i]
            self.i += 1
            rhs = self._parse_unary(depth)
            v = self._apply_add(v, rhs, op)
        return v

    def _parse_unary(self, depth):
        self._step()
        ch = self.peek()
        if ch == "!":
            self.i += 1
            return ("bool", not _jsfuck_truthy(self._parse_unary(depth)))
        if ch == "+":
            self.i += 1
            return ("num", _jsfuck_to_number(self._parse_unary(depth)))
        if ch == "-":
            self.i += 1
            return ("num", -_jsfuck_to_number(self._parse_unary(depth)))
        return self._parse_postfix(depth)

    def _parse_postfix(self, depth):
        self._step()
        v = self._parse_primary(depth)
        while True:
            if self.peek() == "[":
                self.i += 1
                idx = self._parse_add(depth + 1)
                if self.peek() != "]":
                    raise _JSFuckFail("unclosed [")
                self.i += 1
                v = self._index(v, idx)
            elif self.peek() == "(" and v[0] in ("func", "method"):
                v = self._call(v, depth + 1)
            else:
                return v

    def _parse_primary(self, depth):
        self._step()
        ch = self.peek()
        if ch == "[":
            # Array literal: [] or [expr (, expr)*]. Elements are needed
            # for correct ToPrimitive (join) and indexed access.
            self.i += 1
            elems = []
            if self.peek() != "]":
                elems.append(self._parse_add(depth + 1))
                while self.peek() == ",":
                    self.i += 1
                    elems.append(self._parse_add(depth + 1))
            if self.peek() != "]":
                raise _JSFuckFail("unclosed array")
            self.i += 1
            return ("arr", elems)
        if ch == "(":
            self.i += 1
            if self.peek() == ")":
                raise _JSFuckFail("empty parens")
            v = self._parse_add(depth + 1)
            if self.peek() != ")":
                raise _JSFuckFail("unclosed (")
            self.i += 1
            return v
        raise _JSFuckFail("unexpected char")

    def _apply_add(self, a, b, op):
        pa, pb = _jsfuck_primitive(a), _jsfuck_primitive(b)
        if pa[0] == "str" or pb[0] == "str":
            if op == "-":
                return ("num", float("nan"))
            return ("str", _jsfuck_to_string(pa) + _jsfuck_to_string(pb))
        na, nb = _jsfuck_to_number(pa), _jsfuck_to_number(pb)
        return ("num", na + nb if op == "+" else na - nb)

    def _index(self, v, idx):
        k = v[0]
        key = _jsfuck_to_string(_jsfuck_primitive(idx))
        if k == "str":
            try:
                n = int(key)
            except ValueError:
                n = None
            if n is not None and 0 <= n < len(v[1]):
                return ("str", v[1][n])
            if key == "length":
                return ("num", float(len(v[1])))
            if key == "constructor":
                return ("func", "String")
            return _JSFuck_UNDEF
        if k == "arr":
            if key in _JSFUCK_ARR_MEMBERS:
                if key == "length":
                    return ("num", float(len(v[1])))
                if key == "constructor":
                    return ("func", "Array")
                return ("func", key)
            try:
                n = int(key)
            except ValueError:
                return _JSFuck_UNDEF
            if 0 <= n < len(v[1]):
                return v[1][n]
            return _JSFuck_UNDEF
        if k == "num":
            if key == "constructor":
                return ("func", "Number")
            if key == "toString":
                return ("method", (v, "num_toString"))
            return _JSFuck_UNDEF
        if k == "bool":
            if key == "constructor":
                return ("func", "Boolean")
            return _JSFuck_UNDEF
        if k == "func":
            if key == "length":
                return ("num", 1.0)
            if key == "name":
                return ("str", v[1])
            if key == "constructor":
                return ("func", "Function")
            return _JSFuck_UNDEF
        return _JSFuck_UNDEF

    def _call(self, v, depth):
        self.i += 1  # consume '('
        args = []
        if self.peek() != ")":
            args.append(self._parse_add(depth + 1))
            while self.peek() == ",":
                self.i += 1
                args.append(self._parse_add(depth + 1))
        if self.peek() != ")":
            raise _JSFuckFail("unclosed call")
        self.i += 1
        if v[0] == "method":
            obj, mname = v[1]
            if mname == "num_toString":
                n = _jsfuck_to_number(obj)
                radix = 10
                if args:
                    r = _jsfuck_to_number(args[0])
                    if r != int(r) or not 2 <= r <= 36:
                        raise _JSFuckFail("bad radix")
                    radix = int(r)
                return ("str", _jsfuck_num_to_string_radix(n, radix))
            raise _JSFuckFail("unsafe method")
        name = v[1]
        if name == "String":
            a = args[0] if args else _JSFuck_UNDEF
            return ("str", _jsfuck_to_string(_jsfuck_primitive(a)))
        if name == "Number":
            a = args[0] if args else _JSFuck_UNDEF
            return ("num", _jsfuck_to_number(a))
        if name == "Boolean":
            a = args[0] if args else _JSFuck_UNDEF
            return ("bool", _jsfuck_truthy(a))
        if name == "Array":
            return ("arr", list(args))
        # Function() (arbitrary code) and anything else: refuse.
        raise _JSFuckFail("unsafe call")


def _try_jsfuck_decode(run):
    """Strict static JSFuck decode of one alphabet run.

    Returns the decoded ASCII string, or None when the run is not
    decodable JSFuck (strict-eval failure), decodes to non-text, or is
    unchanged. Never executes; bounded by run length, step budget, and
    recursion depth.
    """
    if len(run) > _MAX_JSFUCK_BYTES:
        return None
    try:
        value = _JSFuckParser(run).parse()
        decoded = _jsfuck_to_string(_jsfuck_primitive(value))
    except _JSFuckFail:
        return None
    except RecursionError:
        return None
    if not decoded or decoded == run:
        return None
    if len(decoded) > _MAX_DECODE_BYTES:
        return None
    try:
        raw = decoded.encode("ascii")
    except UnicodeEncodeError:
        return None
    if not _printable_ascii(raw):
        return None
    return decoded


_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_OCT_DIGITS = frozenset("01234567")
# F436: the semicolon is optional (legacy lenient form, mirroring
# html.unescape); the strict form is matched first by alternation
# order in _ENTITY_RUN, so &#65; still decodes identically.
_ENTITY_ONE = re.compile(r"&#([xX][0-9a-fA-F]{1,6}|[0-9]{1,7});?")

# F440: bounded named-entity table for the double-decode layer. Only the
# five named entities that can compose into entity runs (amp/lt/gt/quot/
# apos) are decoded -- the full HTML named-entity table is deliberately
# NOT swallowed (e.g. ``&Lt;`` -> U+226A stays out). Case variants mirror
# html.unescape exactly: amp/AMP, lt/LT, gt/GT, quot/QUOT decode (both
# semicolon and legacy no-semicolon forms); apos is lowercase-only and
# semicolon-only (it is not an HTML5 legacy no-semicolon name).
_NAMED_ENTITIES = (
    ("quot", '"'),
    ("QUOT", '"'),
    ("apos", "'"),
    ("amp", "&"),
    ("AMP", "&"),
    ("lt", "<"),
    ("LT", "<"),
    ("gt", ">"),
    ("GT", ">"),
)
_NAMED_ENTITY_MAP = {name: ch for name, ch in _NAMED_ENTITIES}

# html.unescape legacy no-semicolon forms exist only for these 8 names;
# apos is not a legacy name ("&apos" without ';' stays literal).
_LEGACY_NOSEMI = frozenset(("amp", "AMP", "lt", "LT",
                            "gt", "GT", "quot", "QUOT"))


def _decode_entity_refs_once(text):
    """One left-to-right entity-decode pass (F440 helper).

    Decodes numeric entities per _ENTITY_ONE and the bounded named
    table (exact html.unescape case variants, longest-prefix legacy
    rule: ``&amp;``/``&amp`` -> ``&``, ``&AMP;`` -> ``&``,
    ``&amplify`` -> ``&lify``; ``&Lt;`` is NOT in the table and stays
    literal; ``&apos`` without ``;`` stays literal since apos is not an
    HTML5 legacy no-semicolon name). Returns (decoded_text, match_count),
    or None when a matched entity is undecodable (out-of-range /
    surrogate code point) or the match budget is exceeded -- fail closed,
    no variant. Unmatched text (including stray '&') passes through
    literally. Static; never executes.
    """
    out = []
    i = 0
    n = len(text)
    count = 0
    while i < n:
        c = text[i]
        if c != "&":
            out.append(c)
            i += 1
            continue
        # Numeric first, mirroring the real parser's alternation order.
        m = _ENTITY_ONE.match(text, i)
        if m is not None:
            body = m.group(1)
            cp = int(body[1:], 16) if body[0] in "xX" else int(body, 10)
            ch = _safe_chr(cp)
            if ch is None:
                return None
            out.append(ch)
            i = m.end()
            count += 1
        else:
            # Bounded named entity: scan the letter run (names are at
            # most 4 letters), longest table-name prefix wins; a
            # trailing ';' is consumed when present.
            j = i + 1
            while j < n and j - i - 1 < 4 and text[j].isalpha() and text[j].isascii():
                j += 1
            word = text[i + 1:j]
            name = None
            for cand_len in range(min(4, len(word)), 1, -1):
                if word[:cand_len] in _NAMED_ENTITY_MAP:
                    name = word[:cand_len]
                    break
            if name is None:
                out.append(c)
                i += 1
                continue
            # html.unescape legacy no-semicolon forms exist only for the
            # 8 legacy names (amp/AMP/lt/LT/gt/GT/quot/QUOT); apos is NOT
            # a legacy name, so "&apos" (no ';') stays literal.
            has_semi = i + 1 + len(name) < n and text[i + 1 + len(name)] == ";"
            if not has_semi and name not in _LEGACY_NOSEMI:
                out.append(c)
                i += 1
                continue
            out.append(_NAMED_ENTITY_MAP[name])
            i = i + 1 + len(name)
            if has_semi:
                i += 1
            count += 1
        if count > _MAX_WHOLETEXT_ITEMS:
            return None
    return "".join(out), count


def _try_double_entity_decode(text):
    """Whole-text bounded named+numeric entity double-decode (F440).

    Closes double-HTML-entity encoding: wrapping every credential char's
    numeric entity in a SECOND entity -- ``&amp;#xHH;`` (named),
    ``&amp#xHH;`` (no-semicolon named) -- evades the entity sub-layer:
    _ENTITY_RUN never matches named entities and the inner ``&#xHH;``
    never materializes within the 2-layer decode budget, while
    html.unescape applied twice (a real parser stack) recovers the
    credential.

    Mirrors html.unescape applied twice, restricted to the bounded
    named table (amp/AMP, lt/LT, gt/GT, quot/QUOT, apos -- exact
    html.unescape case variants, longest-prefix legacy rule) plus
    numeric entities per _ENTITY_ONE. One variant, so
    entity+base64 stacks (``b64-stacked``) also close inside the 2-layer
    budget. Static; never executes; bounded by _MAX_WHOLETEXT_ITEMS
    matches per pass; undecodable code points fail closed (no variant).
    Returns the decoded text, or None.
    """
    if "&" not in text:
        return None
    first = _decode_entity_refs_once(text)
    if first is None:
        return None
    decoded1, _ = first
    if decoded1 == text:
        return None
    second = _decode_entity_refs_once(decoded1)
    if second is None:
        return None
    decoded2, _ = second
    return _ascii_printable_or_none(decoded2)


def _safe_chr(cp):
    """chr(cp), or None for out-of-range / surrogate code points.

    Surrogates are rejected rather than pair-combined: credential rules
    are ASCII-only, so a non-BMP decode can never match -- rejecting is
    the strict, safe choice.
    """
    if 0 <= cp <= 0x10FFFF and not 0xD800 <= cp <= 0xDFFF:
        return chr(cp)
    return None


def _decode_one_escape(run, i):
    """Decode one backslash escape at run[i] == '\\\\'.

    Priority is deterministic: \\uXXXX / \\UXXXXXXXX, \\xXX, then CSS
    (1-6 hex + mandatory single space, so ``\\78 `` decodes as 0x78
    rather than octal ``\\7`` + ``8 ``), then octal (1-3 digits, Python
    semantics). Returns (char, next_index) or None when the escape is
    malformed -- the whole run is then ignored.
    """
    n = len(run)
    c = run[i + 1]
    if c == "u":
        h = run[i + 2:i + 6]
        if len(h) != 4 or any(ch not in _HEX_DIGITS for ch in h):
            return None
        ch = _safe_chr(int(h, 16))
        return (ch, i + 6) if ch is not None else None
    if c == "U":
        h = run[i + 2:i + 10]
        if len(h) != 8 or any(ch not in _HEX_DIGITS for ch in h):
            return None
        ch = _safe_chr(int(h, 16))
        return (ch, i + 10) if ch is not None else None
    if c == "x":
        h = run[i + 2:i + 4]
        if len(h) != 2 or any(ch not in _HEX_DIGITS for ch in h):
            return None
        ch = _safe_chr(int(h, 16))
        return (ch, i + 4) if ch is not None else None
    j = i + 1
    while j < n and j < i + 7 and run[j] in _HEX_DIGITS:
        j += 1
    if j > i + 1 and j < n and run[j] == " ":
        ch = _safe_chr(int(run[i + 1:j], 16))
        return (ch, j + 1) if ch is not None else None
    j = i + 1
    while j < n and j < i + 4 and run[j] in _OCT_DIGITS:
        j += 1
    if j == i + 1:
        return None
    ch = _safe_chr(int(run[i + 1:j], 8))
    return (ch, j) if ch is not None else None


def _ascii_printable_or_none(decoded):
    """Gate a decoded variant: ASCII, printable, length-bounded."""
    if not decoded or len(decoded) > _MAX_DECODE_BYTES:
        return None
    try:
        raw = decoded.encode("ascii")
    except UnicodeEncodeError:
        return None
    if not _printable_ascii(raw):
        return None
    return decoded


def _try_escape_decode(run):
    """Strict static decode of one backslash-escape run (F429).

    Returns the decoded string, or None when the run is not fully
    decodable, decodes to non-text, or is unchanged. Never evals.
    """
    if len(run) > 6 * _MAX_DECODE_BYTES:
        return None
    out = []
    i = 0
    n = len(run)
    while i < n:
        if run[i] != "\\" or i + 1 >= n:
            return None
        r = _decode_one_escape(run, i)
        if r is None:
            return None
        ch, i = r
        out.append(ch)
    return _ascii_printable_or_none("".join(out))


# F433: CSS whitespace that may terminate a space-free escape (CSS
# Syntax L3 4.3.7 -- one whitespace code point is consumed; CRLF counts
# as a single whitespace).
_CSS_WS = frozenset(" \t\n\r\f")


def _decode_one_escape_css_free(run, i):
    """Decode one backslash escape at run[i] == '\\\\' with space-free CSS.

    Second interpretation of an escape run (F433), alongside the F429
    priority in _decode_one_escape. Per CSS Syntax Level 3 4.3.7, a CSS
    escape is backslash + 1-6 hex digits; the escape ends at the first
    non-hex code point, which is NOT consumed (so ``\\\\78o`` is 'x'
    followed by literal 'o'), and a single following whitespace is
    consumed as part of the escape. There is deliberately NO octal
    fallback here: in a CSS context ``\\\\62`` is 0x62 ('b'), never
    octal -- the F429 octal interpretation is tried separately by
    _try_escape_decode, so a run decodes under whichever genuine
    encoding the attacker used. Returns (char, next_index) or None
    when malformed -- the whole run is then ignored. Never evals.
    """
    n = len(run)
    c = run[i + 1]
    if c == "u":
        h = run[i + 2:i + 6]
        if len(h) != 4 or any(ch not in _HEX_DIGITS for ch in h):
            return None
        ch = _safe_chr(int(h, 16))
        return (ch, i + 6) if ch is not None else None
    if c == "U":
        h = run[i + 2:i + 10]
        if len(h) != 8 or any(ch not in _HEX_DIGITS for ch in h):
            return None
        ch = _safe_chr(int(h, 16))
        return (ch, i + 10) if ch is not None else None
    if c == "x":
        h = run[i + 2:i + 4]
        if len(h) != 2 or any(ch not in _HEX_DIGITS for ch in h):
            return None
        ch = _safe_chr(int(h, 16))
        return (ch, i + 4) if ch is not None else None
    j = i + 1
    while j < n and j < i + 7 and run[j] in _HEX_DIGITS:
        j += 1
    if j == i + 1:
        return None
    if j < n and run[j] in _HEX_DIGITS:
        # 7+ hex digits: not a strict single escape; the whole run is
        # ignored rather than guessed at.
        return None
    ch = _safe_chr(int(run[i + 1:j], 16))
    if ch is None:
        return None
    if j < n and run[j] in _CSS_WS:
        # Consume one whitespace terminator (CRLF counts as one).
        if run[j] == "\r" and j + 1 < n and run[j + 1] == "\n":
            j += 1
        j += 1
    return ch, j


def _try_escape_decode_css_free(run):
    """Strict static decode of one escape run with space-free CSS (F433).

    Returns the decoded string, or None when the run is not fully
    decodable, decodes to non-text, or is unchanged. Never evals.
    """
    if len(run) > 6 * _MAX_DECODE_BYTES:
        return None
    out = []
    i = 0
    n = len(run)
    while i < n:
        if run[i] != "\\" or i + 1 >= n:
            return None
        r = _decode_one_escape_css_free(run, i)
        if r is None:
            return None
        ch, i = r
        out.append(ch)
    return _ascii_printable_or_none("".join(out))


def _try_entity_decode(run):
    """Strict static decode of one numeric-HTML-entity run (F429).

    Returns the decoded string, or None when any entity is malformed,
    out of range, a surrogate, or the decode is not ASCII text.
    """
    out = []
    pos = 0
    for m in _ENTITY_ONE.finditer(run):
        if m.start() != pos:
            return None
        body = m.group(1)
        cp = int(body[1:], 16) if body[0] in "xX" else int(body, 10)
        ch = _safe_chr(cp)
        if ch is None:
            return None
        out.append(ch)
        pos = m.end()
    if pos != len(run) or not out:
        return None
    return _ascii_printable_or_none("".join(out))


def _try_entity_decode_all(text):
    """Whole-text numeric-entity decode (F436): decode every numeric
    entity (strict &#..; / &#x..; and the legacy no-semicolon forms a
    real HTML parser recovers) in a single pass, returning one variant.

    Per-run decoding alone needs one decode layer per entity, so two
    single entities separated by base64 chunks (F436 residual b) --
    or a no-semicolon entity poisoning a base64 run (residual a) --
    cannot compose with the base64 layer inside the 2-layer budget.
    One whole-text variant keeps entity+base64 stacks closable in 2
    layers; undecodable entities are left for the per-run path.

    Returns the decoded text, or None when the text holds no entities
    or any entity is malformed, out of range, a surrogate, or the
    decode is not ASCII text (fail closed: no variant). Bounded by
    _MAX_WHOLETEXT_ITEMS entities; static; never executes.
    """
    if "&#" not in text:
        return None
    out = []
    pos = 0
    n = 0
    for m in _ENTITY_ONE.finditer(text):
        body = m.group(1)
        cp = int(body[1:], 16) if body[0] in "xX" else int(body, 10)
        ch = _safe_chr(cp)
        if ch is None:
            return None
        out.append(text[pos:m.start()])
        out.append(ch)
        pos = m.end()
        n += 1
        if n > _MAX_WHOLETEXT_ITEMS:
            return None
    if n == 0:
        return None
    out.append(text[pos:])
    return _ascii_printable_or_none("".join(out))


def _try_entity_nul_decode_all(text):
    """Whole-text entity+NUL composition decode (F438): strip NUL
    bytes, then decode every numeric HTML entity in one pass.

    The F438 shape (`&#xHH;\\x00&#xHH;\\x00...`) defeats each
    existing layer on its own: per-run decoding decodes each
    entity+NUL pair as its own single variant (spreading the
    8-candidate budget), and the F436 whole-text entity pass alone
    leaves the NUL bytes in place, so the ASCII-printable gate
    rejects the result -- the fully-decoded + NUL-stripped form is
    unreachable within the depth-2 composition budget. Stripping
    NULs first is the honest decode order (a real chain is
    html.unescape then a control-strip), and it costs one decode
    layer, leaving the depth-2 design bound intact: after stripping,
    the entities still decode under the same bounded
    _MAX_WHOLETEXT_ITEMS budget. Malformed references stay literal
    (faithful to html.unescape, which only decodes valid
    references); out-of-range / surrogate / non-ASCII decodes fail
    closed to None (no variant).

    Returns the decoded text, or None when the text holds no NULs,
    no entities, or any matched entity decode fails. Static; never
    executes.
    """
    if "&#" not in text or "\x00" not in text:
        return None
    return _try_entity_decode_all(text.replace("\x00", ""))


def _try_escape_decode_all(text):
    """Whole-text backslash-escape decode (F436): decode every escape
    run under one interpretation in a single pass, returning one
    variant per interpretation (F429 priority via _try_escape_decode,
    space-free CSS via _try_escape_decode_css_free -- the same two
    interpretations the per-run path tries).

    Per-run decoding alone needs one decode layer per escape run, so
    two single escape fragments separated by base64 chunks (the escape
    analogue of F436 residual b) cannot compose with the base64 layer
    inside the 2-layer budget. One whole-text variant per
    interpretation keeps escape+base64 stacks closable in 2 layers.

    Returns a list of 0-2 decoded variants (an interpretation is
    skipped when any run fails under it -- fail closed, the per-run
    path still covers individually-decodable runs). Bounded by
    _MAX_WHOLETEXT_ITEMS runs; static; never executes.
    """
    if "\\" not in text:
        return []
    runs = list(_ESC_RUN.finditer(text))[:_MAX_WHOLETEXT_ITEMS + 1]
    if not runs or len(runs) > _MAX_WHOLETEXT_ITEMS:
        return []
    variants = []
    for decode in (_try_escape_decode, _try_escape_decode_css_free):
        out = []
        pos = 0
        ok = True
        for m in runs:
            decoded = decode(m.group(0))
            if decoded is None:
                ok = False
                break
            out.append(text[pos:m.start()])
            out.append(decoded)
            pos = m.end()
        if not ok:
            continue
        out.append(text[pos:])
        gated = _ascii_printable_or_none("".join(out))
        if gated is not None and gated != text:
            variants.append(gated)
    return variants


def _try_bslash_unescape_all(text):
    """Escaped-backslash productions (F441): collapse doubled
    backslashes, then decode the exposed escapes.

    Models the first pass of a real double-``unicode_escape`` parser
    stack: ``\\\\uXXXX`` resolves to ``\\uXXXX`` (escaped-backslash
    collapse), which the second pass decodes to the char. Returns up
    to three variants: the pure collapse (the existing escape-run
    layer supplies the second pass -- composes in 2 layers), plus the
    collapse decoded under each whole-text escape interpretation
    (keeps URL-stacked double-backslash shapes inside the 2-layer
    decode budget: URL layer first, this production second).

    Strictly reduces the backslash count on every application, so a
    re-application reaches a fixpoint (pinned -- no decode loop).
    Returns [] when no doubled backslash occurs, the pair count
    exceeds _MAX_WHOLETEXT_ITEMS, or the collapse is not ASCII text
    (fail closed). Bounded, static, never executes.
    """
    if "\\\\" not in text:
        return []
    if text.count("\\\\") > _MAX_WHOLETEXT_ITEMS:
        return []
    collapsed = _ascii_printable_or_none(text.replace("\\\\", "\\"))
    if collapsed is None:
        return []
    variants = []
    if collapsed != text:
        variants.append(collapsed)
    for v in _try_escape_decode_all(collapsed):
        variants.append(v)
    return variants


def _try_utf16_null_decode(run):
    """Decode one UTF-16 null-interleaved run (F429) by stripping NULs."""
    return _ascii_printable_or_none(run.replace("\x00", ""))


def _normalize_confusables(text):
    """Whole-string confusable normalization variant (F429, F431, F435).

    NFKC folds fullwidth and compatibility confusables to ASCII;
    zero-width joiners are stripped; then the bounded static
    Cyrillic-homoglyph map (F431) and the bounded static
    Greek/Cherokee-homoglyph map (F435) fold lookalikes NFKC does
    not cover (U+043E and kin, U+03BF and kin). Returns the
    normalized string, or None when it is unchanged. This is a
    VARIANT for the decode layer -- the original text is still
    scanned as-is.
    """
    norm = unicodedata.normalize("NFKC", text)
    if _ZERO_WIDTH_RUN.search(norm):
        norm = _ZERO_WIDTH_RUN.sub("", norm)
    folded = norm.translate(_CYRILLIC_FOLD)
    if folded != norm:
        norm = folded
    folded = norm.translate(_GREEK_CHEROKEE_FOLD)
    if folded != norm:
        norm = folded
    return norm if norm != text else None


def _normalize_bidi(text):
    """Whole-string bidi-control normalization variant (F431).

    Strips every bidi-override control (U+202A-U+202E, U+2066-U+2069)
    and reverses right-to-left-governed runs (RLO, RLE) to visual
    order, approximating what a renderer displays: an override/embed/
    isolate opens a frame at the current position, PDF/PDI closes the
    innermost frame (reversing it when it is RTL-governed), unclosed
    frames close at end of string, unmatched pops are dropped. Beyond
    _MAX_BIDI_CONTROLS controls the variant degrades to strip-only
    (still deterministic). Returns the normalized string, or None when
    there is nothing to normalize. A VARIANT -- the original text is
    still scanned as-is.
    """
    if not any(c in _BIDI_ALL for c in text):
        return None
    if sum(1 for c in text if c in _BIDI_ALL) > _MAX_BIDI_CONTROLS:
        stripped = "".join(c for c in text if c not in _BIDI_ALL)
        return stripped if stripped != text else None
    out = []
    stack = []  # (reversing, out_start_index) frames
    for c in text:
        if c in _BIDI_REVERSING:
            stack.append((True, len(out)))
        elif c == _BIDI_LRO or c in _BIDI_EMBED or c in _BIDI_ISOLATE:
            stack.append((False, len(out)))
        elif c in _BIDI_POP:
            if stack:
                reversing, start = stack.pop()
                if reversing:
                    out[start:] = out[start:][::-1]
        else:
            out.append(c)
    for reversing, start in reversed(stack):
        if reversing:
            out[start:] = out[start:][::-1]
    norm = "".join(out)
    return norm if norm != text else None


class _JSExprFail(Exception):
    """A JS-expression run is not strictly decodable (fail closed)."""


_JS_EXPR_START = re.compile(r"['\"`\[]|String\.fromCharCode|Array(\(|\.of)|\(")
_JS_EXPR_MAX_PARTS = 64        # bound on '+' operands per expression
_JS_EXPR_MAX_CODEPOINTS = 512  # bound on fromCharCode argument count
_JS_EXPR_MAX_DEPTH = 8         # bound on parenthesization depth
_JS_EXPR_MAX_REPEAT = 64       # bound on .repeat(n)
_JS_EXPR_MAX_FILL = 64         # bound on Array(N) element count (F443)
_JS_EXPR_MAX_LITERAL = 4096    # bound on one string literal
_JS_EXPR_MAX_RUN = 100000      # bound on expression run length
_ASCII_DIGITS = frozenset("0123456789")
_JS_IDENT_START = frozenset(
    "_$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_JS_IDENT_CONT = frozenset(
    "_$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


def _js_skip_ws(text, i):
    n = len(text)
    while i < n and text[i] in " \t\n\r":
        i += 1
    return i


def _js_parse_string(text, i):
    """Parse a '...', "...", or `...` literal at text[i].

    Returns (value, next_index). Template literals containing ${...}
    fail closed (undecodable). Never evals.
    """
    quote = text[i]
    i += 1
    n = len(text)
    out = []
    while True:
        if i >= n:
            raise _JSExprFail("unterminated string")
        c = text[i]
        if c == quote:
            return "".join(out), i + 1
        if quote == "`" and c == "$" and i + 1 < n and text[i + 1] == "{":
            raise _JSExprFail("interpolation")
        if c == "\\":
            if i + 1 >= n:
                raise _JSExprFail("bad escape")
            e = text[i + 1]
            if e in "xuU":
                r = _decode_one_escape(text, i)
                if r is None:
                    raise _JSExprFail("bad escape")
                ch, i = r
                out.append(ch)
                continue
            out.append({"n": "\n", "t": "\t", "r": "\r", "b": "\b",
                        "f": "\f", "v": "\v", "0": "\0"}.get(e, e))
            i += 2
            continue
        if ord(c) < 0x20 and c not in "\t\n\r":
            raise _JSExprFail("control char")
        out.append(c)
        i += 1
        if len(out) > _JS_EXPR_MAX_LITERAL:
            raise _JSExprFail("literal too long")


def _js_parse_number(text, i):
    """Parse a decimal or 0x integer literal at text[i] (ASCII only)."""
    n = len(text)
    if text.startswith(("0x", "0X"), i):
        j = i + 2
        k = j
        while k < n and text[k] in _HEX_DIGITS:
            k += 1
        if k == j:
            raise _JSExprFail("bad hex number")
        if k - j > 8:  # int() digit-limit safety: fail closed, not loud
            raise _JSExprFail("number too big")
        val = int(text[j:k], 16)
        if val > 0x10FFFF:
            raise _JSExprFail("number too big")
        return val, k
    else:
        j = i
        while j < n and text[j] in _ASCII_DIGITS:
            j += 1
        if j == i:
            raise _JSExprFail("not a number")
        if j - i > 7:  # 0x10FFFF needs 7 decimal digits at most
            raise _JSExprFail("number too big")
        val = int(text[i:j])
    if val > 0x10FFFF:
        raise _JSExprFail("number too big")
    return val, j


def _js_parse_fromcharcode(text, i):
    """Parse String.fromCharCode(n, ...) at text[i]; returns (value, idx)."""
    i += len("String.fromCharCode")
    i = _js_skip_ws(text, i)
    if i >= len(text) or text[i] != "(":
        raise _JSExprFail("fromCharCode without paren")
    i += 1
    out = []
    i = _js_skip_ws(text, i)
    if i < len(text) and text[i] == ")":
        return "", i + 1
    while True:
        val, i = _js_parse_number(text, i)
        ch = _safe_chr(val)
        if ch is None:
            raise _JSExprFail("bad codepoint")
        out.append(ch)
        if len(out) > _JS_EXPR_MAX_CODEPOINTS:
            raise _JSExprFail("too many codepoints")
        i = _js_skip_ws(text, i)
        if i < len(text) and text[i] == ",":
            i = _js_skip_ws(text, i + 1)
            continue
        if i < len(text) and text[i] == ")":
            return "".join(out), i + 1
        raise _JSExprFail("bad fromCharCode args")


class _JSArr:
    """Internal: a parsed JS array-literal value (elements are str).

    F434: array values only survive when immediately consumed by .join();
    a bare (unjoined) array is not obfuscation-shaped and decodes to
    nothing -- _try_js_expr_decode returns None for _JSArr values.
    """

    __slots__ = ("elements",)

    def __init__(self, elements):
        self.elements = elements


def _js_parse_array(text, i, depth, state):
    """Parse '[' element (, element)* ']' at text[i] (F434).

    Elements are additive string expressions; nested array literals fail
    closed. Returns (_JSArr, next_index). Element count is charged to the
    expression part budget; the joined output is charged to
    _MAX_DECODE_BYTES in _js_apply_method.
    """
    if state.get("in_array"):
        raise _JSExprFail("nested array")
    state["in_array"] = True
    try:
        i += 1
        elements = []
        i = _js_skip_ws(text, i)
        if i < len(text) and text[i] == "]":
            return _JSArr(elements), i + 1
        while True:
            elem, i = _js_parse_additive(text, i, depth, state)
            if isinstance(elem, _JSArr):
                raise _JSExprFail("nested array")
            elements.append(elem)
            state["parts"] += 1
            if state["parts"] > _JS_EXPR_MAX_PARTS:
                raise _JSExprFail("too many parts")
            i = _js_skip_ws(text, i)
            if i < len(text) and text[i] == ",":
                i = _js_skip_ws(text, i + 1)
                continue
            if i < len(text) and text[i] == "]":
                return _JSArr(elements), i + 1
            raise _JSExprFail("bad array")
    finally:
        state["in_array"] = False


def _js_parse_additive(text, i, depth, state):
    """Parse expr ('+' expr)* at text[i]; returns (value, end_index)."""
    val, i = _js_parse_primary(text, i, depth, state)
    while True:
        j = _js_skip_ws(text, i)
        if j >= len(text) or text[j] != "+":
            return val, i
        rhs, i = _js_parse_primary(text, j + 1, depth, state)
        if isinstance(val, _JSArr) or isinstance(rhs, _JSArr):
            raise _JSExprFail("array in additive")  # F434: no JS '+' on arrays
        state["parts"] += 1
        if state["parts"] > _JS_EXPR_MAX_PARTS:
            raise _JSExprFail("too many parts")
        if len(val) + len(rhs) > _MAX_DECODE_BYTES:
            raise _JSExprFail("concat too long")
        val = val + rhs
        state["ops"] += 1


def _js_parse_ident(text, i):
    """Parse a JS identifier at text[i] (ASCII only); returns (name, next).

    Fail closed on anything else -- never evals.
    """
    n = len(text)
    if i >= n or text[i] not in _JS_IDENT_START:
        raise _JSExprFail("not an identifier")
    j = i + 1
    while j < n and text[j] in _JS_IDENT_CONT:
        j += 1
    return text[i:j], j


def _js_expect(text, i, ch):
    """Skip whitespace, then require the literal char *ch*; returns next."""
    i = _js_skip_ws(text, i)
    if i >= len(text) or text[i] != ch:
        raise _JSExprFail("expected %r" % (ch,))
    return i + 1


def _js_parse_array_of(text, i, state):
    """Parse 'Array.of(arg, ...)' at text[i] (F446).

    Returns (_JSArr, next_index). Every argument must be a string
    literal -- numeric args (Array.of(2) is the 1-element array [2]
    in JS, NOT the Array(N) hole form), nested-array args, and
    additive ('a'+'b') args fail closed (documented scope boundary:
    they are rejected, never mis-decoded). Zero args is the empty
    array. The 'of' name is ident-boundary-checked
    (Array.off / Array.ofx fail closed); whitespace is tolerated around the dot,
    the name, and the parens, exactly as the engine allows. Nested
    calls inside array literals fail closed, same as Array(N) (F443).
    Element count is charged to the part budget; the joined output is
    charged to _MAX_DECODE_BYTES in _js_apply_method. Never evals.
    """
    n = len(text)
    if state.get("in_array"):
        raise _JSExprFail("Array inside array literal")
    j = _js_skip_ws(text, i + len("Array"))
    if j >= n or text[j] != ".":
        raise _JSExprFail("Array without dot")
    k = _js_skip_ws(text, j + 1)
    if not text.startswith("of", k):
        raise _JSExprFail("Array not of")
    k += 2
    if k < n and text[k] in _JS_IDENT_CONT:
        raise _JSExprFail("Array.ofx is not of")
    k = _js_skip_ws(text, k)
    if k >= n or text[k] != "(":
        raise _JSExprFail("Array.of without paren")
    k = _js_skip_ws(text, k + 1)
    elements = []
    if k < n and text[k] == ")":
        return _JSArr(elements), k + 1
    while True:
        if k >= n or text[k] not in "'\"`":
            raise _JSExprFail("Array.of arg not a string literal")
        frag, k = _js_parse_string(text, k)
        elements.append(frag)
        state["parts"] += 1
        if state["parts"] > _JS_EXPR_MAX_PARTS:
            raise _JSExprFail("too many parts")
        k = _js_skip_ws(text, k)
        if k >= n:
            raise _JSExprFail("unterminated Array.of")
        if text[k] == ",":
            k = _js_skip_ws(text, k + 1)
            continue
        if text[k] == ")":
            return _JSArr(elements), k + 1
        raise _JSExprFail("bad Array.of args")


def _js_parse_array_constructor(text, i, state):
    """Parse 'Array()' / 'Array(N)' / 'Array.of(...)' at text[i].

    The '.of' factory form dispatches to _js_parse_array_of (F446);
    the plain form is the F443 single-integer constructor. Returns
    (_JSArr, next_index). N is a decimal or 0x integer literal
    0.._JS_EXPR_MAX_FILL; the zero-arg form is an empty array.
    Elements start as the empty string: real Array(N) is sparse, but
    holes join exactly as "" does, so modeling them as "" is
    byte-identical through .join/.fill/.filter(Boolean). A string or
    multi-arg call (JS: single string arg means ONE element '2', which
    this bound does not model) fails closed, as do nested calls inside
    array literals. The result only survives when consumed by .join();
    a bare Array(N) decodes to nothing (not obfuscation-shaped).
    Never evals.
    """
    n = len(text)
    j = _js_skip_ws(text, i + len("Array"))
    if j < n and text[j] == ".":
        return _js_parse_array_of(text, i, state)
    if state.get("in_array"):
        raise _JSExprFail("Array inside array literal")
    if j >= n or text[j] != "(":
        raise _JSExprFail("Array without paren")
    j = _js_skip_ws(text, j + 1)
    if j < n and text[j] == ")":
        count = 0
        j += 1
    else:
        count, j = _js_parse_number(text, j)
        j = _js_skip_ws(text, j)
        if j >= n or text[j] != ")":
            raise _JSExprFail("bad Array args")
        j += 1
    if count > _JS_EXPR_MAX_FILL:
        raise _JSExprFail("Array too big")
    state["parts"] += count
    if state["parts"] > _JS_EXPR_MAX_PARTS:
        raise _JSExprFail("too many parts")
    return _JSArr([""] * count), j


def _js_parse_reduce_params(text, i):
    """Parse '(p0, p1)' at text[i]; returns (p0, p1, next_index)."""
    i = _js_expect(text, i, "(")
    p0, i = _js_parse_ident(text, _js_skip_ws(text, i))
    i = _js_expect(text, i, ",")
    p1, i = _js_parse_ident(text, _js_skip_ws(text, i))
    i = _js_expect(text, i, ")")
    if p0 == p1:
        raise _JSExprFail("duplicate reduce params")
    return p0, p1, i


def _js_parse_reduce_body(text, i, p0, p1):
    """Parse 'idA + idB' at text[i] (ws-tolerant); returns (idA, idB, next).

    idA/idB must each be one of the callback params (any order); the
    accumulator/currentValue binding is applied at fold time, so
    (x,y)=>y+x assembles in reverse -- exactly as the JS engine does.
    """
    i = _js_skip_ws(text, i)
    idA, i = _js_parse_ident(text, i)
    i = _js_expect(text, i, "+")
    idB, i = _js_parse_ident(text, _js_skip_ws(text, i))
    if idA not in (p0, p1) or idB not in (p0, p1):
        raise _JSExprFail("reduce body not param assembly")
    return idA, idB, i


def _js_parse_return_body(text, i, p0, p1):
    """Parse 'return idA + idB ;' at text[i]; returns (idA, idB, next)."""
    n = len(text)
    i = _js_skip_ws(text, i)
    if not text.startswith("return", i):
        raise _JSExprFail("expected return")
    if i + 6 < n and text[i + 6] in _JS_IDENT_CONT:
        raise _JSExprFail("expected return")
    idA, idB, i = _js_parse_reduce_body(text, i + 6, p0, p1)
    i = _js_skip_ws(text, i)
    if i < n and text[i] == ";":
        i += 1
    return idA, idB, i


def _js_parse_reduce_callback(text, i):
    """Parse a .reduce/.reduceRight callback at text[i].

    Recognized (F437) -- all strictly static, never evaluated:
      (p0,p1)=>pA+pB
      (p0,p1)=>{return pA+pB;}
      function(p0,p1){return pA+pB;}
    Returns (p0, p1, idA, idB, next_index); anything else fails closed.
    """
    n = len(text)
    if text.startswith("function", i):
        i += len("function")
        if i < n and text[i] in _JS_IDENT_CONT:
            raise _JSExprFail("bad function callback")
        p0, p1, i = _js_parse_reduce_params(text, i)
        i = _js_expect(text, i, "{")
        idA, idB, i = _js_parse_return_body(text, i, p0, p1)
        i = _js_expect(text, i, "}")
        return p0, p1, idA, idB, i
    # Arrow form: parenthesized params are required (single bare params
    # cannot name both accumulator and currentValue).
    p0, p1, i = _js_parse_reduce_params(text, i)
    i = _js_skip_ws(text, i)
    if not text.startswith("=>", i):
        raise _JSExprFail("bad arrow callback")
    i += 2
    j = _js_skip_ws(text, i)
    if j < n and text[j] == "{":
        idA, idB, i = _js_parse_return_body(text, j + 1, p0, p1)
        i = _js_expect(text, i, "}")
        return p0, p1, idA, idB, i
    idA, idB, i = _js_parse_reduce_body(text, i, p0, p1)
    return p0, p1, idA, idB, i


def _js_parse_return_body_single(text, i, p):
    """Parse 'return <p> ;' at text[i]; returns (name, name, next)."""
    n = len(text)
    i = _js_skip_ws(text, i)
    if not text.startswith("return", i):
        raise _JSExprFail("expected return")
    if i + 6 < n and text[i + 6] in _JS_IDENT_CONT:
        raise _JSExprFail("expected return")
    q, i = _js_parse_ident(text, _js_skip_ws(text, i + 6))
    if q != p:
        raise _JSExprFail("not identity return")
    i = _js_skip_ws(text, i)
    if i < n and text[i] == ";":
        i += 1
    return q, q, i


def _js_parse_map_callback(text, i):
    """Parse an identity .map callback at text[i]; returns next_index.

    Recognized (F437/F448 family): (s)=>s | s=>s | function(s){return s;}
    | s=>{return s;} (F448 -- block-body identity: a single return of
    the parameter, no other statements). The callback must return its
    own single parameter unchanged; the elements pass through
    untouched. Anything else fails closed.
    """
    n = len(text)
    if text.startswith("function", i):
        i += len("function")
        if i < n and text[i] in _JS_IDENT_CONT:
            raise _JSExprFail("bad map callback")
        i = _js_expect(text, i, "(")
        p, i = _js_parse_ident(text, _js_skip_ws(text, i))
        i = _js_expect(text, i, ")")
        i = _js_expect(text, i, "{")
        q, _, i = _js_parse_return_body_single(text, i, p)
        i = _js_expect(text, i, "}")
        return i
    j = _js_skip_ws(text, i)
    if j < n and text[j] == "(":
        p, i = _js_parse_ident(text, _js_skip_ws(text, j + 1))
        i = _js_expect(text, i, ")")
    else:
        p, i = _js_parse_ident(text, j)
    i = _js_skip_ws(text, i)
    if not text.startswith("=>", i):
        raise _JSExprFail("bad map callback")
    i = _js_skip_ws(text, i + 2)
    if i < n and text[i] == "{":
        # F448: block-body identity s=>{return s;} -- single return of
        # the parameter, no other statements. s=>{var y=1; return s;}
        # fails closed (not a bare return), as does s=>{return (s);}
        # (parenthesized return) and s=>{return s;;} (extra semicolon).
        i = _js_expect(text, i, "{")
        _, _, i = _js_parse_return_body_single(text, i, p)
        i = _js_expect(text, i, "}")
        return i
    q, i = _js_parse_ident(text, i)
    if q != p:
        raise _JSExprFail("map callback not identity")
    return i


def _js_parse_truthy_body(text, i, p):
    """Parse an F447 truthiness-test .filter body; returns (True, next).

    p is the single declared parameter. Recognized:
      p!==''    -- strict neq against the empty-string literal
      !!p       -- double negation
      p.length>0
      p         -- bare identity (truthiness over parsed strings)
    Parsed array elements are always string literals, whose only falsy
    value is "", so every form above drops exactly the falsy elements
    -- provably equivalent to .filter(Boolean). Anything else fails
    closed: loose !=, !== against a non-empty literal, length!=0 or
    length>=1, other member access, single negation (!p drops the
    truthy elements, not a bypass), block-body arrows. Never evals.
    """
    n = len(text)
    i = _js_skip_ws(text, i)
    if text.startswith("!!", i):
        q, j = _js_parse_ident(text, _js_skip_ws(text, i + 2))
        if q != p:
            raise _JSExprFail("not a truthiness test")
        return True, j
    q, j = _js_parse_ident(text, i)
    if q != p:
        raise _JSExprFail("not a truthiness test")
    j = _js_skip_ws(text, j)
    if text.startswith("!==", j):
        # Strict neq against the empty-string literal only.
        k = _js_skip_ws(text, j + 3)
        if k >= n or text[k] not in ("'", '"'):
            raise _JSExprFail("not a truthiness test")
        if k + 1 >= n or text[k + 1] != text[k]:
            raise _JSExprFail("not a truthiness test")
        return True, k + 2
    if j < n and text[j] == ".":
        m, j = _js_parse_ident(text, _js_skip_ws(text, j + 1))
        if m != "length":
            raise _JSExprFail("not a truthiness test")
        j = _js_skip_ws(text, j)
        if j >= n or text[j] != ">":
            raise _JSExprFail("not a truthiness test")
        j = _js_skip_ws(text, j + 1)
        if j >= n or text[j] != "0":
            raise _JSExprFail("not a truthiness test")
        if j + 1 < n and text[j + 1] in "0123456789":
            raise _JSExprFail("not a truthiness test")  # >01 is >1
        return True, j + 1
    # Bare identity: truthiness over parsed strings.
    return True, j


def _js_parse_filter_callback(text, i):
    """Parse a constant-true, Boolean, or truthiness .filter callback.

    Recognized (F437/F443/F447 family): ()=>true | (s)=>true |
    function(){return true;} | function(s){return true;} |
    Boolean (F443 -- bare identifier only, never Boolean(...) which is
    a call, not a function reference) |
    s=>s!=='' | s=>!!s | s=>s.length>0 | s=>s |
    function(s){return s;} (F447 -- truthiness predicates).

    Returns (drop_falsy, next_index): drop_falsy is True for the bare
    Boolean predicate and the F447 truthiness forms. JS Boolean(x)
    coerces to boolean, so .filter(Boolean) drops every falsy element;
    array elements here are always parsed string literals, so exactly
    the empty string is dropped -- and every F447 form is provably
    equivalent to that same test. Anything else fails closed.
    Never evals.
    """
    n = len(text)
    j = _js_skip_ws(text, i)
    if text.startswith("Boolean", j):
        k = j + len("Boolean")
        if k >= n or text[k] not in _JS_IDENT_CONT:
            if k < n and text[k] == "(":
                raise _JSExprFail("Boolean() is not a predicate")
            return True, k
    if text.startswith("function", i):
        i += len("function")
        if i < n and text[i] in _JS_IDENT_CONT:
            raise _JSExprFail("bad filter callback")
        i = _js_expect(text, i, "(")
        i = _js_skip_ws(text, i)
        param = None
        if i < n and text[i] in _JS_IDENT_START:
            param, i = _js_parse_ident(text, i)
        i = _js_expect(text, i, ")")
        i = _js_expect(text, i, "{")
        i = _js_skip_ws(text, i)
        if not text.startswith("return", i):
            raise _JSExprFail("expected return")
        if i + 6 < n and text[i + 6] in _JS_IDENT_CONT:
            raise _JSExprFail("expected return")
        i = _js_skip_ws(text, i + 6)
        if text.startswith("true", i) and (i + 4 >= n
                                           or text[i + 4] not in _JS_IDENT_CONT):
            i += 4
            i = _js_skip_ws(text, i)
            if i < n and text[i] == ";":
                i += 1
            i = _js_expect(text, i, "}")
            return False, i
        # F447: function(s){return s;} -- the bare param is a truthiness
        # test over parsed strings (only falsy value is ""). Free
        # variables (no declared param) fail closed.
        if param is None:
            raise _JSExprFail("filter predicate needs a param")
        q, i = _js_parse_ident(text, i)
        if q != param:
            raise _JSExprFail("not a truthiness predicate")
        i = _js_skip_ws(text, i)
        if i < n and text[i] == ";":
            i += 1
        i = _js_expect(text, i, "}")
        return True, i
    # Arrow form: zero, one-parenthesized, or one-bare params.
    j = _js_skip_ws(text, i)
    param = None
    if j < n and text[j] == "(":
        k = _js_skip_ws(text, j + 1)
        if k < n and text[k] in _JS_IDENT_START:
            param, k = _js_parse_ident(text, k)
        i = _js_expect(text, k, ")")
    elif j < n and text[j] in _JS_IDENT_START:
        # F447: bare single param s=>...
        param, i = _js_parse_ident(text, j)
    i = _js_skip_ws(text, i)
    if not text.startswith("=>", i):
        raise _JSExprFail("bad filter callback")
    i = _js_skip_ws(text, i + 2)
    if text.startswith("true", i) and (i + 4 >= n
                                       or text[i + 4] not in _JS_IDENT_CONT):
        return False, i + 4
    # F447: truthiness predicates -- require exactly one declared param
    # (an unbound body identifier would be a ReferenceError in node).
    if param is None:
        raise _JSExprFail("filter predicate needs a param")
    return _js_parse_truthy_body(text, i, param)


def _js_apply_method(text, j, name, value, depth, state):
    """Apply .concat(...) / .repeat(...) / .join(...) / .reduce(...) /
    .reduceRight(...) / .map(...) / .filter(...) / .fill(...) with text[j] == '('.

    .join/.reduce/.reduceRight/.map/.filter/.fill require an array-literal
    or Array(N) value (F434/F437/F443); .concat/.repeat require a string
    value. Anything else fails closed -- never evals.
    """
    i = j + 1
    if name == "join":
        # F434: ['a','b'].join(sep) -- the separator defaults to ",".
        if not isinstance(value, _JSArr):
            raise _JSExprFail("join on non-array")
        i = _js_skip_ws(text, i)
        if i < len(text) and text[i] == ")":
            sep = ","
            i += 1
        else:
            sep, i = _js_parse_additive(text, i, depth, state)
            if isinstance(sep, _JSArr):
                raise _JSExprFail("bad join separator")
            i = _js_skip_ws(text, i)
            if i >= len(text) or text[i] != ")":
                raise _JSExprFail("bad join")
            i += 1
        result = sep.join(value.elements)
        if len(result) > _MAX_DECODE_BYTES:
            raise _JSExprFail("join too long")
        state["ops"] += 1
        return result, i
    if name in ("reduce", "reduceRight"):
        # F437: ['a','b'].reduce((a,b)=>a+b) -- bounded static fold of
        # string fragments. The callback must be exactly param-assembly
        # (idA + idB over the two params, any order); the JS
        # accumulator/currentValue binding is applied per step, so
        # (x,y)=>y+x assembles in reverse -- exactly as the engine does.
        if not isinstance(value, _JSArr):
            raise _JSExprFail("reduce on non-array")
        i = _js_skip_ws(text, i)
        p0, p1, idA, idB, i = _js_parse_reduce_callback(text, i)
        i = _js_skip_ws(text, i)
        if i < len(text) and text[i] == ",":
            # Optional initial value: an additive string expression; the
            # fold starts with it over every element (JS stringifies a
            # numeric init, which _js_parse_additive already does).
            init, i = _js_parse_additive(text, i + 1, depth, state)
            if isinstance(init, _JSArr):
                raise _JSExprFail("bad reduce init")
            acc = init
            elems = (value.elements if name == "reduce"
                     else value.elements[::-1])
        else:
            if not value.elements:
                raise _JSExprFail("reduce of empty array")  # JS throws
            if name == "reduce":
                acc = value.elements[0]
                elems = value.elements[1:]
            else:
                acc = value.elements[-1]
                elems = value.elements[-2::-1]
        for cur in elems:
            first = acc if idA == p0 else cur
            second = acc if idB == p0 else cur
            acc = first + second
            state["ops"] += 1
            if len(acc) > _MAX_DECODE_BYTES:
                raise _JSExprFail("reduce too long")
        i = _js_skip_ws(text, i)
        if i >= len(text) or text[i] != ")":
            raise _JSExprFail("bad reduce")
        state["ops"] += 1
        return acc, i + 1
    if name == "map":
        # F437 family: ['a','b'].map(s=>s) -- identity callbacks pass the
        # array through untouched for a later .join(); anything but the
        # identity transform fails closed.
        if not isinstance(value, _JSArr):
            raise _JSExprFail("map on non-array")
        i = _js_parse_map_callback(text, _js_skip_ws(text, i))
        i = _js_skip_ws(text, i)
        if i >= len(text) or text[i] != ")":
            raise _JSExprFail("bad map")
        state["ops"] += 1
        return _JSArr(list(value.elements)), i + 1
    if name == "filter":
        # F437 family: ['a','b'].filter(()=>true) -- constant-true keeps
        # every element; (F443) .filter(Boolean) drops every falsy
        # element -- for parsed string elements, exactly the empty
        # string. Any other predicate fails closed.
        if not isinstance(value, _JSArr):
            raise _JSExprFail("filter on non-array")
        drop_falsy, i = _js_parse_filter_callback(text, _js_skip_ws(text, i))
        i = _js_skip_ws(text, i)
        if i >= len(text) or text[i] != ")":
            raise _JSExprFail("bad filter")
        elements = list(value.elements)
        if drop_falsy:
            elements = [e for e in elements if e != ""]
        state["ops"] += 1
        return _JSArr(elements), i + 1
    if name == "fill":
        # F443: Array(N).fill(x) -- every element becomes x. Only the
        # single-arg form is modeled; start/end args fail closed
        # (attacker shapes use none).
        if not isinstance(value, _JSArr):
            raise _JSExprFail("fill on non-array")
        i = _js_skip_ws(text, i)
        frag, i = _js_parse_additive(text, i, depth, state)
        if isinstance(frag, _JSArr):
            raise _JSExprFail("bad fill value")
        i = _js_skip_ws(text, i)
        if i < len(text) and text[i] == ",":
            raise _JSExprFail("fill start/end unsupported")
        if i >= len(text) or text[i] != ")":
            raise _JSExprFail("bad fill")
        i += 1
        elements = [frag] * len(value.elements)
        if len("".join(elements)) > _MAX_DECODE_BYTES:
            raise _JSExprFail("fill too long")
        state["ops"] += 1
        return _JSArr(elements), i
    if isinstance(value, _JSArr):
        raise _JSExprFail("method on unjoined array")
    if name == "repeat":
        i = _js_skip_ws(text, i)
        count, i = _js_parse_number(text, i)
        i = _js_skip_ws(text, i)
        if i >= len(text) or text[i] != ")":
            raise _JSExprFail("bad repeat")
        if count > _JS_EXPR_MAX_REPEAT:
            raise _JSExprFail("repeat too big")
        result = value * count
        if len(result) > _MAX_DECODE_BYTES:
            raise _JSExprFail("repeat too long")
        state["ops"] += 1
        return result, i + 1
    parts = []
    i = _js_skip_ws(text, i)
    if i < len(text) and text[i] == ")":
        state["ops"] += 1
        return value, i + 1
    while True:
        arg, i = _js_parse_additive(text, i, depth, state)
        parts.append(arg)
        state["parts"] += 1
        if state["parts"] > _JS_EXPR_MAX_PARTS:
            raise _JSExprFail("too many parts")
        i = _js_skip_ws(text, i)
        if i < len(text) and text[i] == ",":
            i = _js_skip_ws(text, i + 1)
            continue
        if i < len(text) and text[i] == ")":
            result = value + "".join(parts)
            if len(result) > _MAX_DECODE_BYTES:
                raise _JSExprFail("concat too long")
            state["ops"] += 1
            return result, i + 1
        raise _JSExprFail("bad concat")


def _js_parse_postfix(text, i, value, depth, state):
    """Consume chained .concat(...) / .repeat(...) / .join(...) /
    .reduce(...) / .reduceRight(...) / .map(...) / .filter(...) /
    .fill(...) on *value*."""
    while True:
        j = _js_skip_ws(text, i)
        if j >= len(text) or text[j] != ".":
            return value, i
        for name in ("concat", "repeat", "join", "reduce", "reduceRight",
                     "map", "filter", "fill"):
            if text.startswith(name, j + 1):
                k = _js_skip_ws(text, j + 1 + len(name))
                if k < len(text) and text[k] == "(":
                    value, i = _js_apply_method(text, k, name, value,
                                                depth, state)
                    break
        else:
            return value, i


def _js_parse_primary(text, i, depth, state):
    """Parse one primary (literal / fromCharCode / parens / number / array)."""
    i = _js_skip_ws(text, i)
    if i >= len(text):
        raise _JSExprFail("empty")
    c = text[i]
    if c in "'\"`":
        val, i = _js_parse_string(text, i)
        return _js_parse_postfix(text, i, val, depth, state)
    if text.startswith("String.fromCharCode", i):
        val, i = _js_parse_fromcharcode(text, i)
        state["ops"] += 1  # the call itself is obfuscation-shaped
        return _js_parse_postfix(text, i, val, depth, state)
    if c == "(":
        if depth >= _JS_EXPR_MAX_DEPTH:
            raise _JSExprFail("too deep")
        val, i = _js_parse_additive(text, i + 1, depth + 1, state)
        i = _js_skip_ws(text, i)
        if i >= len(text) or text[i] != ")":
            raise _JSExprFail("unbalanced paren")
        return _js_parse_postfix(text, i + 1, val, depth, state)
    if c == "[":
        val, i = _js_parse_array(text, i, depth, state)
        state["ops"] += 1  # an array literal is obfuscation-shaped
        return _js_parse_postfix(text, i, val, depth, state)
    if text.startswith("Array", i):
        # F443: Array(N) constructor; F446: Array.of(...) factory.
        # startswith alone admits Arrayfoo, which the constructor
        # parse then fails closed (no paren / no .of).
        val, i = _js_parse_array_constructor(text, i, state)
        state["ops"] += 1  # an Array(N)/Array.of construction is obfuscation-shaped
        return _js_parse_postfix(text, i, val, depth, state)
    if c in _ASCII_DIGITS:
        num, i = _js_parse_number(text, i)
        return str(num), i
    raise _JSExprFail("not a primary")


def _try_js_expr_decode(text, start):
    """Strict static decode of one JS string expression (F430).

    Returns (decoded, end_index), or None when the run at *start* is not
    a decodable expression. Handles quoted-string '+' concatenation,
    template literals (no ${...}), String.fromCharCode(...),
    .concat(...) / .repeat(...) postfix calls, array-literal .join(sep)
    (F434), (F437) .reduce(...) / .reduceRight(...) array-assembly
    plus identity .map(...) / constant-true .filter(...) passthroughs,
    and (F443) Array(N).fill(x) construction plus .filter(Boolean)
    truthiness filtering, and (F446) the Array.of('frag', ...) fragment-
    list factory (string-literal args only; numeric/nested/additive args
    fail closed). Bounded by part, depth, codepoint, repeat, and output budgets; never
    evals; undecodable runs are ignored. A bare string literal (or an
    unjoined array literal) with no operator or call is not rewritten
    (not obfuscation-shaped).
    """
    if len(text) - start > _JS_EXPR_MAX_RUN:
        return None
    state = {"ops": 0, "parts": 0}
    try:
        val, end = _js_parse_additive(text, start, 0, state)
    except _JSExprFail:
        return None
    except RecursionError:
        return None
    if state["ops"] == 0:
        return None
    if isinstance(val, _JSArr):
        return None  # F434: bare unjoined array is not obfuscation-shaped
    decoded = _ascii_printable_or_none(val)
    if decoded is None or decoded == text[start:end]:
        return None
    return decoded, end


def _try_js_expr_decode_all(text):
    """Whole-text JS string-expression scan (F444).

    Decodes every strictly-decodable JS expression in *text* in one
    left-to-right pass, producing a single variant: at each
    ``_JS_EXPR_START`` match at/after the current position, attempt
    :func:`_try_js_expr_decode`; on success splice the decoded value
    in and continue past the decoded span, otherwise copy the span
    verbatim (fail closed). Matches inside an already-decoded span
    are skipped.

    This closes the F444 budget-starvation class: ``_decode_layer``
    enumerates per-match JS-expression decodes positionally
    (``[:_MAX_CANDIDATES]``) over a 2-layer budget, so attacker junk
    expressions ahead of the real one consume the enumeration window
    and the layers. One whole-text variant decodes junk and real
    expression alike in a single layer, so no positional window can
    starve the real expression out.

    Bounded: at most ``_MAX_WHOLETEXT_ITEMS`` decode attempts per
    scan (each attempt is ops-bounded inside
    :func:`_try_js_expr_decode`); beyond the bound the remainder is
    copied verbatim and the per-match path still tries. No new
    regexes (reuses ``_JS_EXPR_START``). Static, never executes.
    Returns None when nothing decoded.
    """
    out = []
    pos = 0
    attempts = 0
    for m in _JS_EXPR_START.finditer(text):
        s = m.start()
        if s < pos:
            continue  # inside an already-decoded span
        if attempts >= _MAX_WHOLETEXT_ITEMS:
            break
        attempts += 1
        r = _try_js_expr_decode(text, s)
        if r is None:
            continue  # fail closed: copy verbatim below
        decoded, end = r
        if end <= s:
            continue  # defensive: never retreat
        out.append(text[pos:s])
        out.append(decoded)
        pos = end
    out.append(text[pos:])
    whole = "".join(out)
    return whole if whole != text else None


def _decode_layer(text):
    """One decode layer: return decoded variants of *text* (deduped)."""
    variants = []
    def _add(variant):
        if variant != text and variant not in variants:
            variants.append(variant)

    # URL-encoding layer (whole-string: %XX sequences / '+' separators).
    for dec in (unquote(text), unquote_plus(text)):
        _add(dec)
        if len(variants) >= _MAX_CANDIDATES:
            return variants
    # Confusable-normalization layer (whole-string, F429): NFKC folds
    # fullwidth/compatibility confusables; zero-width joiners stripped.
    norm = _normalize_confusables(text)
    if norm is not None:
        _add(norm)
        if len(variants) >= _MAX_CANDIDATES:
            return variants
    # Bidi-override normalization (whole-string, F431): strip bidi
    # controls, reverse RTL-governed runs to visual order.
    bidi = _normalize_bidi(text)
    if bidi is not None:
        _add(bidi)
        if len(variants) >= _MAX_CANDIDATES:
            return variants
    # Hex runs embedded anywhere in the text.
    for m in list(_HEX_RUN.finditer(text))[:_MAX_CANDIDATES]:
        decoded = _try_hex_decode(m.group(0))
        if decoded is not None:
            _add(text[:m.start()] + decoded + text[m.end():])
    # Base64 / base64url runs embedded anywhere in the text.
    for m in list(_B64_RUN.finditer(text))[:_MAX_CANDIDATES]:
        decoded = _try_b64_decode(m.group(0))
        if decoded is not None:
            _add(text[:m.start()] + decoded + text[m.end():])
    # Short base64/base64url runs (F445): strict-decode with the
    # credential-shape gate -- undecodable or innocent runs are
    # ignored, so this cannot starve the candidate budget.
    for variant in _b64_short_variants(text):
        _add(variant)
        if len(variants) >= _MAX_CANDIDATES:
            return variants
    # Base32 runs embedded anywhere in the text (F8).
    for m in list(_B32_RUN.finditer(text))[:_MAX_CANDIDATES]:
        decoded = _try_b32_decode(m.group(0))
        if decoded is not None:
            _add(text[:m.start()] + decoded + text[m.end():])
    # Short base32 runs (F445): same credential-shape-gated contract.
    for variant in _b32_short_variants(text):
        _add(variant)
        if len(variants) >= _MAX_CANDIDATES:
            return variants
    # JSFuck runs embedded anywhere in the text (F428): strict static
    # decode, never executed; undecodable runs are ignored.
    for m in list(_JSFUCK_RUN.finditer(text))[:_MAX_CANDIDATES]:
        decoded = _try_jsfuck_decode(m.group(0))
        if decoded is not None:
            _add(text[:m.start()] + decoded + text[m.end():])
    # Whole-text JS-expression scan (F444): one variant decoding every
    # strictly-decodable JS expression left-to-right, so junk
    # quoted-concat prefixes cannot starve the real expression out of
    # the positional per-match enumeration window (8) x 2-layer
    # budget. Additive: the per-match loop below is unchanged. The
    # variant composes with the other layers inside the 2-layer
    # budget exactly like the whole-text entity/escape productions.
    decoded = _try_js_expr_decode_all(text)
    if decoded is not None:
        _add(decoded)
        if len(variants) >= _MAX_CANDIDATES:
            return variants
    # JS string-expression runs (F430/F434/F437): strict static decode of
    # quoted '+' concatenation, template literals, String.fromCharCode,
    # .concat/.repeat postfix calls, array-literal .join(sep) (F434),
    # and .reduce/.reduceRight assembly + identity .map / constant-true
    # .filter passthroughs (F437); undecodable runs are ignored.
    for m in list(_JS_EXPR_START.finditer(text))[:_MAX_CANDIDATES]:
        r = _try_js_expr_decode(text, m.start())
        if r is not None:
            decoded, end = r
            _add(text[:m.start()] + decoded + text[end:])
    # Escaped-backslash productions (F441): collapse doubled
    # backslashes and decode the exposed escapes -- models the first
    # pass of a real double-unicode_escape parser stack. This whole-
    # text production MUST precede the per-run escape layers below:
    # on double-backslash text the per-run layers decode inside-out
    # (matching the inner escape from the second backslash), leaving
    # stray backslashes -- the F441 miss mechanism -- and their junk
    # variants would otherwise starve the _MAX_CANDIDATES budget.
    # The pure collapse composes with the escape-run layer in 2
    # layers; the collapse+decode variants keep URL-stacked
    # double-backslash shapes inside the budget. Strictly reduces
    # backslashes -- fixpoint, no loop.
    for decoded in _try_bslash_unescape_all(text):
        _add(decoded)
        if len(variants) >= _MAX_CANDIDATES:
            return variants
    # Backslash-escape runs (F429): strict static \uXXXX / \xXX /
    # octal / CSS-escape decode; undecodable runs are ignored.
    for m in list(_ESC_RUN.finditer(text))[:_MAX_CANDIDATES]:
        decoded = _try_escape_decode(m.group(0))
        if decoded is not None:
            _add(text[:m.start()] + decoded + text[m.end():])
    # Backslash-escape runs, space-free CSS interpretation (F433): the
    # same runs decoded per CSS Syntax L3 4.3.7 (a non-hex code point
    # terminates the escape without being consumed; no octal fallback).
    # A run decodes under whichever genuine encoding the attacker used;
    # undecodable runs are ignored.
    for m in list(_ESC_RUN.finditer(text))[:_MAX_CANDIDATES]:
        decoded = _try_escape_decode_css_free(m.group(0))
        if decoded is not None:
            _add(text[:m.start()] + decoded + text[m.end():])
    # Numeric HTML-entity runs (F429): strict &#x..; / &#..; decode.
    for m in list(_ENTITY_RUN.finditer(text))[:_MAX_CANDIDATES]:
        decoded = _try_entity_decode(m.group(0))
        if decoded is not None:
            _add(text[:m.start()] + decoded + text[m.end():])
    # Whole-text numeric-entity decode (F436): one variant decoding
    # every entity (strict and legacy no-semicolon forms) at once, so
    # entity+base64 stacks -- a no-semicolon entity or two spaced
    # single entities poisoning a base64 run -- compose with the
    # base64 layer inside the 2-layer budget.
    decoded = _try_entity_decode_all(text)
    if decoded is not None:
        _add(decoded)
        if len(variants) >= _MAX_CANDIDATES:
            return variants
    # Whole-text entity+NUL composition (F438): strip NUL bytes, then
    # decode every entity at once, so entity+NUL-interleave stacks
    # compose inside the 2-layer budget.
    decoded = _try_entity_nul_decode_all(text)
    if decoded is not None:
        _add(decoded)
        if len(variants) >= _MAX_CANDIDATES:
            return variants
    # Whole-text bounded named+numeric double entity decode (F440): one
    # variant mirroring html.unescape x2 over the bounded named table
    # (amp/lt/gt/quot/apos) plus numeric entities, so double-encoded
    # entities (named-wrapped, no-semicolon named-wrapped) and their
    # base64 stacks close inside the 2-layer budget.
    decoded = _try_double_entity_decode(text)
    if decoded is not None:
        _add(decoded)
        if len(variants) >= _MAX_CANDIDATES:
            return variants
    # Whole-text backslash-escape decode (F436): one variant per
    # escape-run interpretation, so spaced single escape fragments
    # poisoning a base64 run compose with the base64 layer inside the
    # 2-layer budget.
    for decoded in _try_escape_decode_all(text):
        _add(decoded)
        if len(variants) >= _MAX_CANDIDATES:
            return variants
    # UTF-16 null-interleaved runs (F429): strip the NUL bytes.
    for m in list(_UTF16N_RUN.finditer(text))[:_MAX_CANDIDATES]:
        decoded = _try_utf16_null_decode(m.group(0))
        if decoded is not None:
            _add(text[:m.start()] + decoded + text[m.end():])
    return variants


def _decoded_variants(text, max_layers=2):
    """All distinct decoded variants of *text* up to *max_layers* deep."""
    seen = {text}
    out = []
    frontier = [text]
    for _ in range(max_layers):
        nxt = []
        for t in frontier:
            for v in _decode_layer(t):
                if v not in seen:
                    seen.add(v)
                    out.append(v)
                    nxt.append(v)
        if not nxt:
            break
        frontier = nxt
    return out


def _match_credential_rules(text):
    for rule_id, rx in _CREDENTIAL_RULES:
        if rx.search(text):
            return rule_id
    return None


def _match_credential_forms(text):
    """Match the credential rules against *text* in its deterministic
    form variants (F8): as-is, whitespace-stripped, and reversed.

    These are precise transforms of a known-format credential — a match
    on any form means the text genuinely carries credential-shaped
    material, so the false-positive surface is the regexes themselves,
    not the transforms.
    """
    for candidate in (text, _WS_RUN.sub("", text), text[::-1]):
        rule = _match_credential_rules(candidate)
        if rule:
            return rule
    return None


def _find_credential_strict(text):
    """Credential regexes over *text* and its decoded variants (F2/F8).

    No entropy tripwire: this is the precise half of the check, used for
    the per-field scan and for the cross-param joined buffer.
    """
    rule = _match_credential_forms(text)
    if rule:
        return rule
    for variant in _decoded_variants(text):
        rule = _match_credential_forms(variant)
        if rule:
            return rule
    # F439: bounded base64 decode-until-fixpoint (max _MAX_B64_ROUNDS
    # rounds). Checked directly, not fed back into the layer pipeline,
    # so depth-4+ base64 stacks stay a documented non-goal.
    for variant in _b64_fixpoint_variants(text):
        rule = _match_credential_forms(variant)
        if rule:
            return rule
    return None


# ------------------------------------------------------------------ scanning

def find_credential(text):
    """Return the id of the first blocking credential rule matching *text*,
    or None. Also fires the entropy tripwire for unknown key formats.

    Encoding-aware (F2/F8/F428/F429/F430/F431): before giving up, decodes likely encodings
    (base64/base64url, base32, hex, URL-encoding, JSFuck, JS string
    expressions (F444: whole-text scan defeats junk-prefix budget
    starvation), backslash
    escapes, numeric HTML entities, double HTML-entity encoding (F440),
    UTF-16 null-interleave, confusable
    normalization incl. the Cyrillic-homoglyph map, bidi-override
    normalization -- bounded, 2 layers), short base64/base32 runs when
    the strict decode is credential-shaped (F445), plus a bounded base64
    decode-until-fixpoint pass (F439: max 3 rounds; depth-4+ base64
    stacks are a documented non-goal), and
    re-runs the credential rules on each decoded variant, in
    whitespace-stripped and reversed form as well. The entropy tripwire
    runs on the original text only (documented boundary, see module
    docstring).
    """
    rule = _find_credential_strict(text)
    if rule:
        return rule
    # Entropy tripwire: a long high-entropy token sitting near a
    # credential keyword (matched in normalized space: synonyms, spaced
    # forms, leetspeak — F16) is treated as an unknown key format.
    if _tripwire_hit(text):
        return "dlp-entropy-tripwire"
    return None


def _try_ascii_leaf(value):
    """Decode a non-string arg leaf to ASCII text, or None.

    F128 (wave-63): non-string leaves are scannable credential
    carriers — a bytes blob, or a JSON-native int array (the canonical
    byte encoding, like base64), holding a credential-shaped string is
    still that credential. Only strict ASCII decodes yield a variant
    (printable-gated, length-gated): the strict credential rules run on
    decoded leaves exactly as they do on str leaves, and the entropy
    tripwire stays on the original text (documented F2/F8 boundary).
    """
    raw = None
    if isinstance(value, (bytes, bytearray)):
        if len(value) < 8:
            return None
        raw = bytes(value)
    elif isinstance(value, (list, tuple)):
        if len(value) < 8:
            return None
        if not all(isinstance(i, int) and not isinstance(i, bool)
                   and 0 <= i <= 255 for i in value):
            return None
        raw = bytes(value)
    else:
        return None
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not all(c.isprintable() or c in " \t\n\r" for c in text):
        return None
    return text


def _collect_strings(value, out):
    """Recursively collect every string leaf of an arg mapping.

    F128: also collects ASCII-decoded forms of bytes/bytearray leaves
    and all-int (0-255) list/tuple leaves. Dict KEYS are deliberately
    NOT collected here: this feed joins into one buffer, and key
    fragments glued onto adjacent values poison alignment-sensitive
    decoding (wave-63: keys "a"/"b" glued onto b64 halves broke the
    cross-field reassembly). Keys are scanned individually, not joined
    (see find_credential_cross_field). Used by the cross-field
    (strict-rules-only) scan, so decoded leaves never reach the
    entropy tripwire.
    """
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, (bytes, bytearray)):
        decoded = _try_ascii_leaf(value)
        if decoded is not None:
            out.append(decoded)
    elif isinstance(value, dict):
        for v in value.values():
            _collect_strings(v, out)
    elif isinstance(value, (list, tuple)):
        decoded = _try_ascii_leaf(value)
        if decoded is not None:
            out.append(decoded)
        for v in value:
            _collect_strings(v, out)


def _collect_keys(value, out):
    """Recursively collect every dict key of an arg mapping.

    F128: keys are scanned INDIVIDUALLY (never joined into the
    cross-field buffer — see _collect_strings). A credential-shaped
    string as an object key is still the credential.
    """
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                out.append(k)
            elif isinstance(k, (bytes, bytearray)):
                decoded = _try_ascii_leaf(k)
                if decoded is not None:
                    out.append(decoded)
            _collect_keys(v, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _collect_keys(v, out)


def find_credential_cross_field(args):
    """Scan the concatenation of ALL string param values (F8).

    Catches a credential chunked across params, where every chunk is
    innocent alone. Uses the strict (regex + decodings) half only — never
    the entropy tripwire — so joining fields cannot manufacture a
    heuristic hit; only a genuine known-format credential spanning the
    join blocks.

    F128: dict keys are strict-scanned individually (a credential as an
    object key is still the credential); keys never enter the joined
    buffer (glue poisoning — see _collect_strings).
    """
    parts = []
    _collect_strings(args or {}, parts)
    joined = "".join(parts)
    if joined:
        hit = _find_credential_strict(joined)
        if hit:
            return hit
    keys = []
    _collect_keys(args or {}, keys)
    for k in keys:
        hit = _find_credential_strict(k)
        if hit:
            return hit
    return None


def scrub_pii(text):
    """Redact PII in *text*. Returns (redacted_text, [rule_ids])."""
    hits = []

    def _replace(rule_id, rx, s):
        def _sub(m):
            hits.append(rule_id)
            return "[REDACTED:%s]" % rule_id
        return rx.sub(_sub, s)

    # F171: linear-time guards. The pii-email/phone/card regexes
    # backtrack quadratically on long runs of word characters with no
    # possible match (e.g. 60KB of 'd's: ~7s; 263KB: minutes), and
    # scrub_pii runs inside executor.call() BEFORE the F33 byte-cap
    # projection — an agent-controlled payload burned governor CPU
    # before the cap could deny it. Each rule only runs when its
    # trigger characters are present (a match is impossible
    # otherwise), so the whole scrub stays linear in the input length.
    # The triggers are necessary conditions of the patterns, never
    # sufficient ones: redaction behavior is unchanged.
    has_digit = any(ch.isdigit() for ch in text)  # O(n), early exit
    _triggers_ok = {
        "pii-ssn": "-" in text and has_digit,
        "pii-email": "@" in text,
        "pii-phone": has_digit,
    }
    out = text
    for rule_id, rx in _PII_RULES:
        if _triggers_ok.get(rule_id, True):
            out = _replace(rule_id, rx, out)

    def _card_sub(m):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            hits.append("pii-card")
            return "[REDACTED:pii-card]"
        return m.group(0)

    # F171: the card pattern needs a digit to match; skip the regex
    # (and its per-candidate Luhn check) when there is none.
    if has_digit:
        out = _CARD_RE.sub(_card_sub, out)
    return out, sorted(set(hits))


def _summarize_content(value):
    raw = value if isinstance(value, str) else str(value)
    data = raw.encode("utf-8", "replace")
    return {"bytes": len(data),
            "sha256_prefix": hashlib.sha256(data).hexdigest()[:16]}


# Fields that stay readable in logs/approvals because they are the
# audit-relevant routing of the action (who/where), never its payload.
_AUDIT_FIELDS = {
    "send_email": {"to"},
    "http_post": {"url"},
    "read_file": {"path"},
    "write_file": {"path"},
    "delete_file": {"path"},
    "api_call": {"endpoint"},
}

# Payload fields whose values are summarized to {bytes, sha256} rather than
# stored verbatim: they can carry arbitrary secret material.
_SUMMARY_FIELDS = {
    "write_file": {"content"},
    "send_email": {"body"},
    "http_post": {"payload"},
}


def scan_value(text):
    """Scan one string: returns (blocked, rule_id, redacted, [pii_hits])."""
    rule = find_credential(text)
    if rule:
        return True, rule, "[BLOCKED:%s]" % rule, []
    redacted, hits = scrub_pii(text)
    return False, None, redacted, hits


def scan_tool_args(tool, args):
    """Scan a tool's argument mapping.

    Returns ``(blocked, blocking_rule, redacted_args, redactions)`` where
    ``redacted_args`` is safe to store in logs/approvals and ``redactions``
    lists every rule that fired (blocking rule first, then PII rules, then
    ``field:<tool>.<name>`` markers for summarized fields).
    """
    audit = _AUDIT_FIELDS.get(tool, set())
    summary = _SUMMARY_FIELDS.get(tool, set())
    redacted = {}
    redactions = []
    blocked = False
    blocking_rule = None
    for name, value in (args or {}).items():
        if name in summary:
            redacted[name] = _summarize_content(value)
            redactions.append("field:%s.%s" % (tool, name))
            # The summarized value is still scanned for the blocking rules
            # using the ORIGINAL value, so a secret triggers the block even
            # though only the summary is stored.
            raw = value if isinstance(value, str) else str(value)
            rule = find_credential(raw)
            if rule and not blocked:
                blocked, blocking_rule = True, rule
                redactions.insert(0, blocking_rule)
            continue
        if isinstance(value, str):
            if name in audit:
                # Audit fields (recipients, URLs, paths) stay readable: they
                # are the routing envelope the reviewer must see, and
                # subject/body redaction already covers the payload. Only
                # credential patterns in them still block (a secret pasted
                # into "to" is still a leak).
                rule = find_credential(value)
                if rule and not blocked:
                    blocked, blocking_rule = True, rule
                    redactions.insert(0, blocking_rule)
                redacted[name] = value
            else:
                is_blocked, rule, clean, hits = scan_value(value)
                redacted[name] = clean
                if is_blocked and not blocked:
                    blocked, blocking_rule = True, rule
                    redactions.insert(0, blocking_rule)
                redactions.extend(h for h in hits if h not in redactions)
        elif isinstance(value, dict):
            sub_blocked, sub_rule, sub_red, sub_hits = scan_tool_args(
                tool, {str(k): v for k, v in value.items()})
            redacted[name] = sub_red
            if sub_blocked and not blocked:
                blocked, blocking_rule = True, sub_rule
                redactions.insert(0, blocking_rule)
            redactions.extend(h for h in sub_hits if h not in redactions)
        elif isinstance(value, (bytes, bytearray)):
            # F128: a bytes/bytearray field value is a scannable
            # credential carrier — strict rules on the ASCII-decoded
            # form (the entropy tripwire stays on the original str
            # text, per the documented F2/F8 boundary). The stored
            # redaction keeps the original value untouched.
            redacted[name] = value
            decoded = _try_ascii_leaf(value)
            if decoded is not None:
                rule = _find_credential_strict(decoded)
                if rule and not blocked:
                    blocked, blocking_rule = True, rule
                    redactions.insert(0, blocking_rule)
        else:
            redacted[name] = value
    # F8: a credential chunked across params is innocent per-field. Scan
    # the joined buffer of all string values as well (strict rules only).
    if not blocked:
        rule = find_credential_cross_field(args)
        if rule:
            blocked, blocking_rule = True, rule
            redactions.insert(0, blocking_rule)
    return blocked, blocking_rule, redacted, redactions
