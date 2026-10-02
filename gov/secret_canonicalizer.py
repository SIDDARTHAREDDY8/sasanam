"""Gitleaks-contract secret canonicalizer: the single detection seam for
the F306 emission family (triad guard records, shield-run records,
GuardChain plugin records, and future emission sites).

Mechanism provenance: the rule-engine contract is adapted from
``gitleaks/gitleaks`` (MIT, (c) 2019 Zachary Rice -- license verified
from raw LICENSE bytes by the wave-282 prospecting lane; the upstream
project is feature-complete and shifting to Betterleaks, so the rule
set below is PINNED 2026-10-02 and vendored here rather than tracked).
No gitleaks code is vendored: the contract (``id`` / ``regex`` /
``secretGroup`` / ``keywords`` / layered allowlists / ``stdin``
streaming / decode layers / composite proximity) is reimplemented
clean-room in stdlib-only Python. This is the MIT-clean alternative to
the trufflehog contract noted in wave-281, and the second independent
confirmation of the F306 fix direction (detect -> canonicalize -> emit;
secret bytes physically cannot cross the audit-log write).

Contract summary:

* ``keywords`` cheap prefilter -- a rule only runs its regex when one
  of its lowercase keywords occurs in the text (latency; gitleaks'
  ``keywords`` field).
* ``secretGroup`` -- every rule regex carries a named ``(?P<secret>...)``
  group naming the secret span, separating the match from the secret.
  Structured findings carry ``secret_digest`` (sha256 of the secret
  span), never the raw bytes.
* Decode layers -- base64 / hex / percent-encoded layers are scanned up
  to ``MAX_DECODE_DEPTH`` (gitleaks' ``--max-decode-depth``); findings
  are tagged with ``encoding`` and the decoded bytes never leave the
  engine.
* Composite proximity -- the generic high-entropy rule only fires when
  a credential keyword is adjacent to the token (proximity-bounded),
  so far-apart entropy is silent.
* ``stdin`` streaming seam -- :class:`Scanner` scans chunked input with
  an overlap buffer: a secret split across chunk boundaries is caught
  exactly once, with absolute offsets.
* Reporter redaction invariant -- :func:`scan` returns structured
  findings; :func:`sanitize` returns text with secret spans replaced by
  kind-preserving ``[REDACTED:<kind>]`` placeholders. Nothing that
  leaves this module carries raw secret bytes.
* Fingerprint + allowlist exception registry -- :class:`ExceptionRegistry`
  holds governed, auditable, expiring exceptions keyed by stable
  finding fingerprints (gitleaks' ``.gitleaksignore`` Fingerprint
  analog).
* Fail-closed on rule errors -- a malformed rule refuses at
  construction (:class:`RuleError`); the engine never half-initializes.

The emission funnels (``gov/tool_guardrails.py`` F306,
``gov/guardrail_evidence.py`` F310, ``gov/guard_plugins.py`` F311)
route their detection through :func:`credential_material_present`;
they keep their own placeholder conventions. The elicitation ban in
``gov/elicitation_contract.py`` is intentionally untouched (its
fail-closed false-positive discipline is a separate contract).
"""

import base64
import binascii
import hashlib
import json
import math
import os
import re
import time
from dataclasses import dataclass, replace

__all__ = [
    "RuleError",
    "Rule",
    "SecretFinding",
    "ExceptionRegistry",
    "Scanner",
    "compile_rules",
    "get_rule",
    "RULES",
    "scan",
    "sanitize",
    "credential_material_present",
    "scan_stream",
    "MAX_DECODE_DEPTH",
    "RULESET_PIN",
]

#: The rule set is pinned, not tracked: upstream gitleaks is
#: feature-complete / security-patches-only (shifting to Betterleaks),
#: so this snapshot is vendored and reviewed in-tree. Bumping the pin
#: means re-running the full red-first battery below.
RULESET_PIN = "gitleaks-rule-contract/2026-10-02/curated-v1"

#: Maximum decode-layer depth (gitleaks --max-decode-depth analog).
MAX_DECODE_DEPTH = 2

#: Streaming overlap: a secret span longer than this cannot be caught
#: when split across chunks (documented bound; PEM blocks and tokens
#: are far shorter).
_STREAM_OVERLAP = 4096


class RuleError(ValueError):
    """A rule is malformed, unknown, or the engine was asked to do
    something the contract refuses. Fail-closed: raised at
    construction, never swallowed."""


@dataclass(frozen=True)
class Rule:
    """One detection rule: the gitleaks ``id`` / ``regex`` /
    ``secretGroup`` / ``keywords`` contract.

    ``secret_group`` names the regex group capturing the secret span
    (the gitleaks ``secretGroup`` analog). ``entropy_min`` is an
    optional Shannon-entropy floor (bits/char) applied to the secret
    span. ``proximity_window`` is an optional composite filter: the
    secret is only reported when one of the rule's keywords occurs
    within that many characters before the secret's start.
    """
    id: str
    kind: str
    pattern: "re.Pattern"
    keywords: tuple
    tags: tuple
    entropy_min: float = None
    proximity_window: int = None

    def __repr__(self):
        return "Rule(%r)" % (self.id,)


# ---------------------------------------------------------------------------
# Pinned rule set (curated v1, 2026-10-02)
# ---------------------------------------------------------------------------
#
# Each regex carries a named (?P<secret>...) group -- the secretGroup
# analog. Keywords are lowercase substrings; a rule only runs when one
# occurs in the text (cheap prefilter). Generic rules are
# keyword-adjacent by construction (composite proximity).
#
# These are synthetic-shape detectors for well-known credential
# formats, reimplemented clean-room for this engine's shapes -- the
# pin records the contract version, not a vendored file.

_PINNED_RULES = (
    dict(id="aws-access-key", kind="aws-access-key",
         regex=r"(?P<secret>AKIA[0-9A-Z]{16})",
         keywords=("akia",), tags=("aws",)),
    dict(id="aws-secret-access-key", kind="aws-secret",
         regex=r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?"
               r"(?P<secret>[A-Za-z0-9/+=]{40})['\"]?",
         keywords=("aws",), tags=("aws",)),
    dict(id="github-pat", kind="github-token",
         regex=r"(?P<secret>ghp_[A-Za-z0-9]{36,})",
         keywords=("ghp_",), tags=("github",)),
    dict(id="github-oauth", kind="github-token",
         regex=r"(?P<secret>gho_[A-Za-z0-9]{36,})",
         keywords=("gho_",), tags=("github",)),
    dict(id="gitlab-pat", kind="gitlab-token",
         regex=r"(?P<secret>glpat-[A-Za-z0-9\-_]{20,})",
         keywords=("glpat",), tags=("gitlab",)),
    dict(id="slack-token", kind="slack-token",
         regex=r"(?P<secret>xox[baprs]-[A-Za-z0-9\-]{10,})",
         keywords=("xox",), tags=("slack",)),
    dict(id="stripe-secret", kind="stripe-key",
         regex=r"(?P<secret>sk_live_[A-Za-z0-9]{16,})",
         keywords=("sk_live",), tags=("stripe",)),
    dict(id="openai-key", kind="openai-key",
         regex=r"(?P<secret>sk-[A-Za-z0-9]{20,})",
         keywords=("sk-",), tags=("openai",), entropy_min=3.5),
    dict(id="google-api-key", kind="google-api-key",
         regex=r"(?P<secret>AIza[0-9A-Za-z\-_]{35})",
         keywords=("aiza",), tags=("google",)),
    dict(id="jwt", kind="jwt",
         regex=r"(?P<secret>eyJ[A-Za-z0-9\-_]{10,}\."
               r"[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,})",
         keywords=("eyj",), tags=("token",)),
    dict(id="sendgrid-key", kind="sendgrid-key",
         regex=r"(?P<secret>SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})",
         keywords=("sg.",), tags=("sendgrid",)),
    dict(id="square-token", kind="square-token",
         regex=r"(?P<secret>sq0atp-[0-9A-Za-z\-_]{22})",
         keywords=("sq0atp",), tags=("square",)),
    dict(id="npm-token", kind="npm-token",
         regex=r"(?P<secret>npm_[A-Za-z0-9]{36,})",
         keywords=("npm_",), tags=("npm",)),
    dict(id="pypi-token", kind="pypi-token",
         regex=r"(?P<secret>pypi-[A-Za-z0-9\-_]{40,})",
         keywords=("pypi-",), tags=("pypi",)),
    dict(id="twilio-key", kind="twilio-key",
         regex=r"(?P<secret>SK[0-9a-fA-F]{32})",
         keywords=("sk",), tags=("twilio",)),
    dict(id="telegram-bot-token", kind="telegram-token",
         regex=r"(?P<secret>[0-9]{5,12}:[A-Za-z0-9_\-]{35})",
         keywords=(), tags=("telegram",)),
    dict(id="discord-token", kind="discord-token",
         regex=r"(?P<secret>[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27})",
         keywords=(), tags=("discord",)),
    dict(id="facebook-token", kind="facebook-token",
         regex=r"(?P<secret>EAACEdEose0cBA[0-9A-Za-z]+)",
         keywords=("eaac",), tags=("facebook",)),
    dict(id="private-key", kind="private-key",
         regex=r"(?P<secret>-----BEGIN (?:[A-Z0-9 ]* )?PRIVATE KEY-----"
               r"[\s\S]{1,8192}?-----END (?:[A-Z0-9 ]* )?PRIVATE KEY-----)",
         keywords=("private",), tags=("key",)),
    dict(id="generic-password", kind="password",
         regex=r"(?i)(?:password|passwd)\s*[:=]\s*['\"]?"
               r"(?P<secret>[A-Za-z0-9\-._~+/=]{4,200})['\"]?",
         keywords=("password", "passwd"), tags=("generic",)),
    dict(id="generic-api-key", kind="api-key",
         regex=r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?"
               r"(?P<secret>[A-Za-z0-9\-._~+/=]{8,200})['\"]?",
         keywords=("api_key", "apikey", "api-key"), tags=("generic",)),
    dict(id="generic-secret", kind="secret",
         regex=r"(?i)(?:secret|client_secret)\s*[:=]\s*['\"]?"
               r"(?P<secret>[A-Za-z0-9\-._~+/=]{8,200})['\"]?",
         keywords=("secret",), tags=("generic",)),
    dict(id="generic-token", kind="token",
         regex=r"(?i)(?:access_token|auth_token|token)\s*[:=]\s*['\"]?"
               r"(?P<secret>[A-Za-z0-9\-._~+/=]{8,200})['\"]?",
         keywords=("token",), tags=("generic",)),
    dict(id="bearer-token", kind="bearer-token",
         regex=r"(?i)\bbearer\s+(?P<secret>[A-Za-z0-9\-._~+/=]{10,200})",
         keywords=("bearer",), tags=("generic",)),
    dict(id="connection-string-password", kind="password",
         regex=r"(?i)(?:password|pwd)=(?P<secret>[^;\s'\"]{4,200})",
         keywords=("password=", "pwd="), tags=("generic",)),
    dict(id="basic-auth-url", kind="url-credential",
         regex=r"(?i)[a-z][a-z0-9+.\-]*://[^/\s:]+:"
               r"(?P<secret>[^/\s@]{1,200})@",
         keywords=("://",), tags=("generic",)),
    # Composite rule: high-entropy token with a credential keyword inside
    # a proximity window BEFORE the token (true composite semantics:
    # keyword + entropy + proximity). A lone high-entropy string with
    # no nearby keyword is silent -- this is the rule that keeps the
    # generic detector from firing on UUIDs, digests, and prose.
    dict(id="composite-keyword-entropy", kind="high-entropy-token",
         regex=r"(?P<secret>[A-Za-z0-9\-._~+/=]{16,200})",
         keywords=("password", "passwd", "secret", "api_key", "apikey",
                   "api-key", "token"),
         tags=("generic", "composite"), entropy_min=4.0,
         proximity_window=80),
)


def _validate_rule_dict(d, seen):
    if not isinstance(d, dict):
        raise RuleError("rule must be a dict, got %r" % type(d).__name__)
    allowed = {"id", "kind", "regex", "keywords", "tags", "entropy_min",
               "proximity_window"}
    unknown = set(d) - allowed
    if unknown:
        raise RuleError("rule %r: unknown keys %r"
                        % (d.get("id"), sorted(unknown)))
    rid = d.get("id")
    if not isinstance(rid, str) or not rid:
        raise RuleError("rule id must be a non-empty string, got %r" % (rid,))
    if rid in seen:
        raise RuleError("duplicate rule id %r" % (rid,))
    seen.add(rid)
    kind = d.get("kind")
    if not isinstance(kind, str) or not kind:
        raise RuleError("rule %r: kind must be a non-empty string" % (rid,))
    regex_src = d.get("regex")
    if not isinstance(regex_src, str) or not regex_src:
        raise RuleError("rule %r: regex must be a non-empty string" % (rid,))
    try:
        pattern = re.compile(regex_src)
    except re.error as exc:
        raise RuleError("rule %r: regex does not compile: %s"
                        % (rid, exc)) from exc
    if "secret" not in pattern.groupindex:
        raise RuleError(
            "rule %r: regex must carry a named (?P<secret>...) group "
            "(the secretGroup analog)" % (rid,))
    keywords = d.get("keywords", ())
    if not isinstance(keywords, (tuple, list)) or any(
            not isinstance(k, str) or not k for k in keywords):
        raise RuleError("rule %r: keywords must be non-empty strings" % (rid,))
    keywords = tuple(k.lower() for k in keywords)
    tags = tuple(d.get("tags", ()))
    if any(not isinstance(t, str) for t in tags):
        raise RuleError("rule %r: tags must be strings" % (rid,))
    entropy_min = d.get("entropy_min")
    if entropy_min is not None and not isinstance(entropy_min, (int, float)):
        raise RuleError("rule %r: entropy_min must be a number" % (rid,))
    proximity_window = d.get("proximity_window")
    if proximity_window is not None and not isinstance(
            proximity_window, int):
        raise RuleError("rule %r: proximity_window must be an int" % (rid,))
    return Rule(id=rid, kind=kind, pattern=pattern, keywords=keywords,
                tags=tags,
                entropy_min=(None if entropy_min is None
                             else float(entropy_min)),
                proximity_window=proximity_window)


def compile_rules(rule_dicts):
    """Compile rule dicts into :class:`Rule` objects, fail-closed.

    Raises :class:`RuleError` on any malformed rule (bad regex, missing
    ``secret`` group, duplicate id, unknown keys). The engine never
    half-initializes: either every rule compiles or none are used.
    """
    if not isinstance(rule_dicts, (tuple, list)):
        raise RuleError("rules must be a tuple/list, got %r"
                        % type(rule_dicts).__name__)
    seen = set()
    rules = tuple(_validate_rule_dict(d, seen) for d in rule_dicts)
    if not rules:
        raise RuleError("rule set must not be empty")
    return rules


#: The pinned engine rule set, compiled at import. A malformed pinned
#: rule is an import-time RuleError -- loud, never a silent gap.
RULES = compile_rules(_PINNED_RULES)

_RULES_BY_ID = {r.id: r for r in RULES}


def get_rule(rule_id):
    """Return the compiled :class:`Rule` for ``rule_id``; refuse
    unknown ids fail-closed."""
    try:
        return _RULES_BY_ID[rule_id]
    except KeyError:
        raise RuleError("unknown rule id %r" % (rule_id,)) from None


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def _shannon_entropy(text):
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass(frozen=True)
class SecretFinding:
    """A structured detection: the gitleaks finding analog.

    ``detector`` is the rule id, ``kind`` the coarse credential kind,
    ``secret_digest`` the sha256 of the secret span (the secret's
    identity -- the raw bytes never appear here), ``fingerprint`` the
    stable exception-registry key, ``offset``/``length`` the secret
    span in the scanned text, ``span_offset``/``span_length`` the span
    to redact (for decode-layer findings this is the whole ENCODED
    span in the original text -- redacting the decoded-local span
    would corrupt the text and leak decodable fragments),
    ``location`` the caller-supplied provenance label, ``encoding``
    the decode layer (``""`` for the plain layer), ``tags`` the rule's
    tag tuple. ``entropy`` is the secret span's Shannon entropy
    (bits/char).

    Every field is safe to log: repr() can never carry raw secret
    bytes (the reporter redaction invariant).
    """
    detector: str
    kind: str
    secret_digest: str
    fingerprint: str
    offset: int
    length: int
    span_offset: int
    span_length: int
    location: str
    encoding: str
    entropy: float
    tags: tuple

    def to_dict(self):
        return {
            "detector": self.detector,
            "kind": self.kind,
            "secret_digest": self.secret_digest,
            "fingerprint": self.fingerprint,
            "offset": self.offset,
            "length": self.length,
            "location": self.location,
            "encoding": self.encoding,
            "entropy": round(self.entropy, 3),
            "tags": sorted(self.tags),
        }


def _fingerprint(detector, secret_digest, location):
    return hashlib.sha256(
        b"secret-canonicalizer-v1\x00" + detector.encode("utf-8") +
        b"\x00" + secret_digest.encode("ascii") +
        b"\x00" + location.encode("utf-8")).hexdigest()


def _secret_digest(secret):
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _rule_hits(rule, text, *, location, encoding, base_offset=0,
               span_offset=None, span_length=None):
    """Yield findings for one rule on one text layer.

    ``span_offset``/``span_length`` override the redact span (used by
    decode layers: the encoded span in the original text)."""
    out = []
    text_lower = text.lower() if rule.proximity_window else None
    for m in rule.pattern.finditer(text):
        start, end = m.span("secret")
        secret = text[start:end]
        if not secret:
            continue
        entropy = _shannon_entropy(secret)
        if rule.entropy_min is not None and entropy < rule.entropy_min:
            continue
        if rule.proximity_window:
            window = text_lower[max(0, start - rule.proximity_window):start]
            if not any(k in window for k in rule.keywords):
                continue
        digest = _secret_digest(secret)
        out.append(SecretFinding(
            detector=rule.id, kind=rule.kind,
            secret_digest=digest,
            fingerprint=_fingerprint(rule.id, digest, location),
            offset=base_offset + start, length=end - start,
            span_offset=(base_offset + start if span_offset is None
                         else span_offset),
            span_length=(end - start if span_length is None
                         else span_length),
            location=location, encoding=encoding, entropy=entropy,
            tags=rule.tags))
    return out


# ---------------------------------------------------------------------------
# Decode layers (gitleaks --max-decode-depth semantics)
# ---------------------------------------------------------------------------

_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX_CANDIDATE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
# Percent: the whole word-ish span around the %XX sequence (a lone "%3D"
# decodes to "=" alone, which is useless -- the span carries the context).
_PCT_CANDIDATE = re.compile(
    r"[A-Za-z0-9_.~+\-]*%[0-9A-Fa-f]{2}"
    r"(?:[A-Za-z0-9_.~+\-]|%[0-9A-Fa-f]{2})*")


def _is_mostly_printable(data):
    if not data:
        return False
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data) >= 0.6


def _decode_layers(text, depth=0):
    """Yield (decoded_text, encoding, enc_offset, enc_len) for each
    decodeable span, up to MAX_DECODE_DEPTH. The decoded bytes never
    leave this module except as digests inside findings. Nested layers
    keep the OUTERMOST encoded span (that is what gets redacted)."""
    if depth >= MAX_DECODE_DEPTH:
        return
    spans = []
    for m in _B64_CANDIDATE.finditer(text):
        cand = m.group(0)
        decoded = _try_b64(cand)
        if decoded is None:
            # LOW-2 hardening: a maximal base64-alphabet run can merge
            # adjacent junk with an encoded secret; retry 4-char-aligned
            # suffixes of the run's tail before abandoning it.
            decoded, cut = _try_b64_suffixes(cand)
            if decoded is not None:
                spans.append((decoded, "base64", m.start() + cut,
                              len(cand) - cut))
            continue
        spans.append((decoded, "base64", m.start(), len(cand)))
    for m in _HEX_CANDIDATE.finditer(text):
        cand = m.group(0)
        if len(cand) % 2:
            continue
        try:
            raw = bytes.fromhex(cand)
        except ValueError:
            continue
        if _is_mostly_printable(raw):
            spans.append((raw.decode("utf-8", errors="replace"),
                          "hex", m.start(), len(cand)))
    for m in _PCT_CANDIDATE.finditer(text):
        cand = m.group(0)
        try:
            out = []
            i = 0
            while i < len(cand):
                if cand[i] == "%" and i + 2 < len(cand):
                    out.append(bytes([int(cand[i + 1:i + 3], 16)]))
                    i += 3
                else:
                    out.append(cand[i].encode("utf-8", errors="replace"))
                    i += 1
            raw = b"".join(out)
        except ValueError:
            continue
        if _is_mostly_printable(raw):
            spans.append((raw.decode("utf-8", errors="replace"),
                          "percent", m.start(), len(cand)))
    for decoded, encoding, enc_offset, enc_len in spans:
        yield decoded, encoding, enc_offset, enc_len
        # Recurse one layer deeper (nested encoding evasion); the
        # redact span stays the outermost encoded span.
        for deeper, enc2, _inner_off, _inner_len in _decode_layers(
                decoded, depth + 1):
            yield deeper, encoding + "+" + enc2, enc_offset, enc_len


def _try_b64(cand):
    """Decode a base64 candidate; None when not decodeable/printable."""
    if len(cand) % 4:
        return None
    try:
        raw = base64.b64decode(cand, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not _is_mostly_printable(raw):
        return None
    return raw.decode("utf-8", errors="replace")


def _try_b64_suffixes(cand):
    """Bounded retry: 4-char-aligned suffixes of the run's last 1024
    chars. Returns (decoded, cut) or (None, 0)."""
    tail_start = max(0, len(cand) - 1024)
    # Align to a 4-char boundary relative to the run start.
    first = tail_start + (-tail_start % 4)
    for cut in range(first, len(cand), 4):
        sub = cand[cut:]
        sub = sub[:len(sub) - len(sub) % 4]
        if len(sub) < 20:
            continue
        decoded = _try_b64(sub)
        if decoded is not None:
            return decoded, cut
    return None, 0


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def _rules_for(text_lower):
    """The keywords cheap prefilter: a rule runs only when one of its
    keywords occurs in the text (rules with no keywords always run)."""
    return [r for r in RULES
            if not r.keywords or any(k in text_lower for k in r.keywords)]


def _dedupe(findings):
    """Drop findings whose secret span is contained in an already-kept
    finding's span (longer / earlier-rule wins; deterministic)."""
    ordered = sorted(findings,
                     key=lambda f: (f.offset, -(f.length), f.detector))
    kept = []
    for f in ordered:
        contained = False
        for k in kept:
            if (k.offset <= f.offset
                    and f.offset + f.length <= k.offset + k.length):
                contained = True
                break
        if not contained:
            kept.append(f)
    return kept


def scan(text, *, location=""):
    """Scan ``text`` for credential-shaped material.

    Returns a tuple of :class:`SecretFinding` (deterministic order:
    offset, then longest span, then rule id). Findings carry digests,
    never raw secret bytes. ``location`` labels provenance for
    fingerprinting (e.g. ``"guardrail-run/input_shield"``).
    """
    if not isinstance(text, str):
        text = "" if text is None else str(text)
    if not text:
        return ()
    findings = []
    # Plain layer: the redact span is the secret span itself.
    for rule in _rules_for(text.lower()):
        findings.extend(_rule_hits(rule, text, location=location,
                                   encoding=""))
    # Decode layers: the redact span is the whole ENCODED span in the
    # original text (never the decoded-local span).
    for decoded, encoding, enc_offset, enc_len in _decode_layers(text):
        loc = location + "+%s@%d" % (encoding, enc_offset)
        for rule in _rules_for(decoded.lower()):
            findings.extend(_rule_hits(rule, decoded, location=loc,
                                       encoding=encoding,
                                       base_offset=enc_offset,
                                       span_offset=enc_offset,
                                       span_length=enc_len))
    return tuple(_dedupe(findings))


def credential_material_present(text):
    """True when ``text`` carries credential-shaped material.

    The single detection seam for the F306 emission family: every
    evidence-emission funnel routes through this predicate. (The
    elicitation ban in ``gov/elicitation_contract.py`` keeps its own
    narrower contract by design.)
    """
    return bool(scan(text))


def sanitize(text, *, location=""):
    """Withhold secret spans from ``text``.

    Returns ``(sanitized_text, findings)``: each secret span is
    replaced by a kind-preserving ``[REDACTED:<kind>]`` placeholder
    (redaction is marked, never silent elision); the findings are the
    structured evidence. For decode-layer findings the whole encoded
    span is redacted, so no decodable fragment survives. The verdict
    the caller computed is untouched. Overlapping spans are replaced
    right-to-left without double-redaction.
    """
    findings = scan(text, location=location)
    if not findings:
        return text, findings
    spans = sorted(((f.span_offset, f.span_offset + f.span_length, f.kind)
                    for f in findings), reverse=True)
    out = text
    cut = len(text)
    for start, end, kind in spans:
        if start >= cut:
            continue  # already covered by a span to its right
        end = min(end, cut)
        out = out[:start] + "[REDACTED:%s]" % kind + out[end:]
        cut = start
    return out, findings


# ---------------------------------------------------------------------------
# Streaming seam (gitleaks `stdin` mode analog)
# ---------------------------------------------------------------------------

class Scanner:
    """Chunked scanning with an overlap buffer.

    A secret split across chunk boundaries is caught exactly once with
    absolute offsets. The overlap bound is documented:
    ``_STREAM_OVERLAP`` (4096 chars); a single secret span longer than
    the overlap cannot be caught when split -- PEM blocks and tokens
    are far shorter.
    """

    def __init__(self, *, location=""):
        self._location = location
        self._tail = ""
        self._consumed = 0

    def feed(self, chunk):
        """Scan one chunk; returns findings fully settled in this feed
        (findings touching the overlap tail are deferred to the next
        feed or :meth:`finish`). Offsets are absolute in the stream."""
        if not isinstance(chunk, str):
            chunk = str(chunk)
        data = self._tail + chunk
        base = self._consumed - len(self._tail)  # absolute offset of data[0]
        settled_cut = len(data) - _STREAM_OVERLAP
        out = []
        if settled_cut > 0:
            # All scan() offsets are relative to ``data``: plain-layer
            # findings directly, decode-layer findings via their encoded
            # span's offset within ``data`` (the finding's redact span
            # is the encoded span). The settled-region test and the
            # absolute rebase are uniform across layers.
            for f in scan(data, location=self._location):
                if f.offset + f.length <= settled_cut:
                    out.append(replace(f, offset=base + f.offset,
                                       span_offset=base + f.span_offset))
        self._tail = (data[-_STREAM_OVERLAP:]
                      if len(data) > _STREAM_OVERLAP else data)
        self._consumed += len(chunk)
        return out

    def finish(self):
        """Flush the overlap tail; returns any findings completing
        there (never duplicates of already-reported findings: the tail
        is disjoint from every earlier settled region). Offsets are
        absolute in the stream."""
        if not self._tail:
            return []
        base = self._consumed - len(self._tail)
        out = [replace(f, offset=base + f.offset,
                       span_offset=base + f.span_offset)
               for f in scan(self._tail, location=self._location)]
        self._tail = ""
        return out


def scan_stream(chunks, *, location=""):
    """Scan an iterable of text chunks (the ``stdin`` streaming seam);
    returns the full finding tuple."""
    scanner = Scanner(location=location)
    out = []
    for chunk in chunks:
        out.extend(scanner.feed(chunk))
    out.extend(scanner.finish())
    return tuple(out)


# ---------------------------------------------------------------------------
# Fingerprint + allowlist exception registry
# ---------------------------------------------------------------------------

_FP_RE = re.compile(r"^[0-9a-f]{64}$")


class ExceptionRegistry:
    """Governed exceptions keyed by finding fingerprint (gitleaks'
    ``.gitleaksignore`` Fingerprint analog).

    An exception suppresses exactly one (rule, secret, location)
    finding. Registrations are auditable (each returns an audit dict
    with ``reason`` and ``approver``) and may expire. This registry is
    deployment-owned state; persistence is a plain JSON file with
    atomic writes.
    """

    def __init__(self):
        self._exceptions = {}

    def register(self, *, fingerprint, reason, approver, expires_at=None):
        """Register an exception. ``expires_at`` is an epoch float or
        None (no expiry). Returns an audit dict. Refuses malformed
        input fail-closed."""
        if not isinstance(fingerprint, str) or not _FP_RE.match(fingerprint):
            raise RuleError("fingerprint must be a 64-hex sha256, got %r"
                            % (fingerprint,))
        if not isinstance(reason, str) or not reason.strip():
            raise RuleError("reason must be a non-empty string")
        if not isinstance(approver, str) or not approver.strip():
            raise RuleError("approver must be a non-empty string")
        if expires_at is not None and not isinstance(expires_at, (int, float)):
            raise RuleError("expires_at must be an epoch number or None")
        self._exceptions[fingerprint] = {
            "reason": reason.strip(),
            "approver": approver.strip(),
            "expires_at": expires_at,
            "registered_at": time.time(),
        }
        return {
            "event": "secret-exception-registered",
            "fingerprint": fingerprint,
            "reason": reason.strip(),
            "approver": approver.strip(),
            "expires_at": expires_at,
        }

    def is_allowed(self, fingerprint, *, now=None):
        """True when the fingerprint is registered and unexpired."""
        entry = self._exceptions.get(fingerprint)
        if entry is None:
            return False
        expires_at = entry["expires_at"]
        if expires_at is not None:
            now = time.time() if now is None else now
            if now >= expires_at:
                return False
        return True

    def suppress(self, findings, *, now=None):
        """Split ``findings`` into ``(kept, suppressed)`` by the
        registry. Deterministic; never mutates the input."""
        kept, suppressed = [], []
        for f in findings:
            (suppressed if self.is_allowed(f.fingerprint, now=now)
             else kept).append(f)
        return tuple(kept), tuple(suppressed)

    def revoke(self, fingerprint):
        """Revoke an exception; returns True when one existed."""
        return self._exceptions.pop(fingerprint, None) is not None

    def to_dict(self):
        return {fp: dict(entry)
                for fp, entry in sorted(self._exceptions.items())}

    def save(self, path):
        """Atomic JSON persistence (tmp file + rename)."""
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"ruleset_pin": RULESET_PIN,
                       "exceptions": self.to_dict()},
                      fh, sort_keys=True, indent=2)
            fh.write("\n")
        os.replace(tmp, path)

    @classmethod
    def load(cls, path):
        """Load a registry; refuses malformed files and pin mismatches
        fail-closed (exceptions are only meaningful against the rule
        set that produced their fingerprints)."""
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict) or "exceptions" not in data:
            raise RuleError("exception registry file is malformed: %r"
                            % (path,))
        if data.get("ruleset_pin") != RULESET_PIN:
            raise RuleError(
                "exception registry pin %r does not match engine pin %r: "
                "refusing to apply exceptions across rule-set versions"
                % (data.get("ruleset_pin"), RULESET_PIN))
        reg = cls()
        for fp, entry in data["exceptions"].items():
            if not _FP_RE.match(fp) or not isinstance(entry, dict):
                raise RuleError("exception registry entry malformed: %r"
                                % (fp,))
            reg._exceptions[fp] = {
                "reason": str(entry.get("reason", "")),
                "approver": str(entry.get("approver", "")),
                "expires_at": entry.get("expires_at"),
                "registered_at": entry.get("registered_at", 0),
            }
        return reg
