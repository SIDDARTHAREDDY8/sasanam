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

ENCODING-AWARE MATCHING (F2, extended F8). The credential patterns above
are syntactic, so an attacker can smuggle a credential past them with one
encoding step (hex, base64, base32, URL-encoding). ``find_credential``
therefore decodes likely encodings BEFORE pattern matching, bounded to 2
layers: each layer finds candidate encoded runs, decodes only those that
validate (base64/base32 round-trip / even-length hex / percent-decoding
that changes the text) AND decode to mostly-printable ASCII, then re-runs
the credential rules on the decoded variants. Innocent base64-looking text
(random tokens, hashes) decodes to binary and is rejected by the printable
check, so it is never blocked; text whose DECODED form matches a credential
regex is blocked because the decoded content genuinely contains a
credential-shaped string.

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
from urllib.parse import unquote, unquote_plus

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

_PII_RULES = [
    # (rule_id, compiled regex) -- a match is REDACTED in logs/approvals.
    ("pii-ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("pii-email",
     re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("pii-phone",
     re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
]

_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

# F16: the entropy tripwire's keyword list is matched in a NORMALIZED
# space — lowercase, leet-speak folded, and every whitespace RUN replaced
# by a \x00 boundary marker (no whitespace survives, but word edges do,
# so "deploy password" still has a boundary while "private key" and
# "privatekey" both match). Synonyms ("credentials"), spaced forms
# ("private key"), and leet ("p4ssw0rd" -> "password") all trip it. The
# window / token / entropy half still runs on the ORIGINAL text (match
# positions are mapped back), so the precise-credential regexes and the
# entropy behavior are untouched.
_TRIP_KEYWORDS = re.compile(
    r"\b(password|passwd|passcode|pwd|secret|credentials?|creds|token|"
    r"api[_\-\x00]?key|private[_\-\x00]?key|key|access|auth|login|"
    r"aws_secret|client_secret)\b")

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
        for token in re.findall(r"[A-Za-z0-9_+/=-]{20,}", window):
            if _shannon_entropy(token) > 4.3:
                return True
    return False


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
# F2: decode likely encodings BEFORE credential pattern matching, bounded to
# 2 layers. Every candidate must VALIDATE (strict decode + round-trip for
# base64, even-length for hex) and decode to mostly-printable ASCII;
# otherwise it is not a hidden credential, it is a random token/hash, and it
# is ignored. This keeps innocent base64-looking text unblocked.

_B64_RUN = re.compile(r"[A-Za-z0-9+/\-_]{24,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")
_B32_RUN = re.compile(r"[A-Z2-7]{24,}={0,6}")
_WS_RUN = re.compile(r"\s+")
_MAX_DECODE_BYTES = 4096  # bound on any single decoded blob
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
    return raw.decode("ascii")


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
    return raw.decode("ascii")


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
    return raw.decode("ascii")


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

    Encoding-aware (F2/F8): before giving up, decodes likely encodings
    (base64/base64url, base32, hex, URL-encoding — bounded, 2 layers) and
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


def _collect_strings(value, out):
    """Recursively collect every string leaf of an arg mapping."""
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _collect_strings(v, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _collect_strings(v, out)


def find_credential_cross_field(args):
    """Scan the concatenation of ALL string param values (F8).

    Catches a credential chunked across params, where every chunk is
    innocent alone. Uses the strict (regex + decodings) half only — never
    the entropy tripwire — so joining fields cannot manufacture a
    heuristic hit; only a genuine known-format credential spanning the
    join blocks.
    """
    parts = []
    _collect_strings(args or {}, parts)
    joined = "".join(parts)
    if not joined:
        return None
    return _find_credential_strict(joined)


def scrub_pii(text):
    """Redact PII in *text*. Returns (redacted_text, [rule_ids])."""
    hits = []

    def _replace(rule_id, rx, s):
        def _sub(m):
            hits.append(rule_id)
            return "[REDACTED:%s]" % rule_id
        return rx.sub(_sub, s)

    out = text
    for rule_id, rx in _PII_RULES:
        out = _replace(rule_id, rx, out)

    def _card_sub(m):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            hits.append("pii-card")
            return "[REDACTED:pii-card]"
        return m.group(0)

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
