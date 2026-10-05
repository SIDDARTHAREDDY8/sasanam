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
String.fromCharCode, and .concat()/.repeat() -- never eval; undecodable
runs are ignored and bare literals are not rewritten.

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
_ENTITY_RUN = re.compile(r"(?:&#[xX][0-9a-fA-F]{1,6};|&#[0-9]{1,7};)+")
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
_WS_RUN = re.compile(r"\s+")
_MAX_DECODE_BYTES = 4096  # bound on any single decoded blob
_MAX_JSFUCK_BYTES = 100000  # bound on a JSFuck run (artifact: 34635)
_MAX_CANDIDATES = 8       # bound on decode attempts per layer


def _printable_ascii(data, min_ratio=0.9):
    if not data:
        return False
    good = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return good / len(data) >= min_ratio


def _try_b64_decode(run):
    """Strict base64/base64url decode with round-trip validation.

    Returns the decoded ASCII string, or None when the run is not really
    base64 (wrong alphabet after normalization, bad padding, no round-trip,
    or decodes to binary rather than text).
    """
    norm = run.replace("-", "+").replace("_", "/").rstrip("=")
    if len(norm) < 24:
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


def _try_b32_decode(run):
    """Strict base32 decode with round-trip validation (F8).

    Same contract as the base64 path: the run must be a genuine base32
    encoding (strict alphabet, valid padding, exact round-trip) that
    decodes to mostly-printable ASCII. Without the round-trip check,
    arbitrary uppercase/digit runs would "decode" to garbage bytes.
    """
    norm = run.rstrip("=")
    if len(norm) < 24:
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
_ENTITY_ONE = re.compile(r"&#([xX][0-9a-fA-F]{1,6}|[0-9]{1,7});")


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


def _try_utf16_null_decode(run):
    """Decode one UTF-16 null-interleaved run (F429) by stripping NULs."""
    return _ascii_printable_or_none(run.replace("\x00", ""))


def _normalize_confusables(text):
    """Whole-string confusable normalization variant (F429, F431).

    NFKC folds fullwidth and compatibility confusables to ASCII;
    zero-width joiners are stripped; then the bounded static
    Cyrillic-homoglyph map (F431) folds lookalikes NFKC does not
    cover (U+043E and kin). Returns the normalized string, or None
    when it is unchanged. This is a VARIANT for the decode layer --
    the original text is still scanned as-is.
    """
    norm = unicodedata.normalize("NFKC", text)
    if _ZERO_WIDTH_RUN.search(norm):
        norm = _ZERO_WIDTH_RUN.sub("", norm)
    folded = norm.translate(_CYRILLIC_FOLD)
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


_JS_EXPR_START = re.compile(r"['\"`]|String\.fromCharCode|\(")
_JS_EXPR_MAX_PARTS = 64        # bound on '+' operands per expression
_JS_EXPR_MAX_CODEPOINTS = 512  # bound on fromCharCode argument count
_JS_EXPR_MAX_DEPTH = 8         # bound on parenthesization depth
_JS_EXPR_MAX_REPEAT = 64       # bound on .repeat(n)
_JS_EXPR_MAX_LITERAL = 4096    # bound on one string literal
_JS_EXPR_MAX_RUN = 100000      # bound on expression run length
_ASCII_DIGITS = frozenset("0123456789")


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


def _js_parse_additive(text, i, depth, state):
    """Parse expr ('+' expr)* at text[i]; returns (value, end_index)."""
    val, i = _js_parse_primary(text, i, depth, state)
    while True:
        j = _js_skip_ws(text, i)
        if j >= len(text) or text[j] != "+":
            return val, i
        rhs, i = _js_parse_primary(text, j + 1, depth, state)
        state["parts"] += 1
        if state["parts"] > _JS_EXPR_MAX_PARTS:
            raise _JSExprFail("too many parts")
        if len(val) + len(rhs) > _MAX_DECODE_BYTES:
            raise _JSExprFail("concat too long")
        val = val + rhs
        state["ops"] += 1


def _js_apply_method(text, j, name, value, depth, state):
    """Apply .concat(...) / .repeat(...) with text[j] == '('."""
    i = j + 1
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
    """Consume chained .concat(...) / .repeat(...) calls on *value*."""
    while True:
        j = _js_skip_ws(text, i)
        if j >= len(text) or text[j] != ".":
            return value, i
        for name in ("concat", "repeat"):
            if text.startswith(name, j + 1):
                k = _js_skip_ws(text, j + 1 + len(name))
                if k < len(text) and text[k] == "(":
                    value, i = _js_apply_method(text, k, name, value,
                                                depth, state)
                    break
        else:
            return value, i


def _js_parse_primary(text, i, depth, state):
    """Parse one primary (literal / fromCharCode / parens / number)."""
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
    if c in _ASCII_DIGITS:
        num, i = _js_parse_number(text, i)
        return str(num), i
    raise _JSExprFail("not a primary")


def _try_js_expr_decode(text, start):
    """Strict static decode of one JS string expression (F430).

    Returns (decoded, end_index), or None when the run at *start* is not
    a decodable expression. Handles quoted-string '+' concatenation,
    template literals (no ${...}), String.fromCharCode(...), and
    .concat(...) / .repeat(...) postfix calls. Bounded by part, depth,
    codepoint, repeat, and output budgets; never evals; undecodable
    runs are ignored. A bare string literal with no operator or call is
    not rewritten (not obfuscation-shaped).
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
    decoded = _ascii_printable_or_none(val)
    if decoded is None or decoded == text[start:end]:
        return None
    return decoded, end


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
    # Base32 runs embedded anywhere in the text (F8).
    for m in list(_B32_RUN.finditer(text))[:_MAX_CANDIDATES]:
        decoded = _try_b32_decode(m.group(0))
        if decoded is not None:
            _add(text[:m.start()] + decoded + text[m.end():])
    # JSFuck runs embedded anywhere in the text (F428): strict static
    # decode, never executed; undecodable runs are ignored.
    for m in list(_JSFUCK_RUN.finditer(text))[:_MAX_CANDIDATES]:
        decoded = _try_jsfuck_decode(m.group(0))
        if decoded is not None:
            _add(text[:m.start()] + decoded + text[m.end():])
    # JS string-expression runs (F430): strict static decode of quoted
    # '+' concatenation, template literals, String.fromCharCode, and
    # .concat/.repeat postfix calls; undecodable runs are ignored.
    for m in list(_JS_EXPR_START.finditer(text))[:_MAX_CANDIDATES]:
        r = _try_js_expr_decode(text, m.start())
        if r is not None:
            decoded, end = r
            _add(text[:m.start()] + decoded + text[end:])
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
    return None


# ------------------------------------------------------------------ scanning

def find_credential(text):
    """Return the id of the first blocking credential rule matching *text*,
    or None. Also fires the entropy tripwire for unknown key formats.

    Encoding-aware (F2/F8/F428/F429/F430/F431): before giving up, decodes likely encodings
    (base64/base64url, base32, hex, URL-encoding, JSFuck, JS string
    expressions, backslash
    escapes, numeric HTML entities, UTF-16 null-interleave, confusable
    normalization incl. the Cyrillic-homoglyph map, bidi-override
    normalization -- bounded, 2 layers) and
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
