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

Field-level policy (see ``scan_tool_args``): some fields are audit-relevant
and stay readable (email recipients, URLs, file paths); payloads and file
contents are summarized to ``{bytes, sha256}`` so secret material never
reaches the log at all.
"""

import hashlib
import math
import re

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

_CRED_KEYWORDS = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|token|"
    r"aws_secret|client_secret|private[_-]?key)\b")


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


# ------------------------------------------------------------------ scanning

def find_credential(text):
    """Return the id of the first blocking credential rule matching *text*,
    or None. Also fires the entropy tripwire for unknown key formats."""
    for rule_id, rx in _CREDENTIAL_RULES:
        if rx.search(text):
            return rule_id
    # Entropy tripwire: a long high-entropy token sitting near a credential
    # keyword is treated as an unknown key format.
    for m in _CRED_KEYWORDS.finditer(text):
        window = text[max(0, m.start() - 10):m.end() + 80]
        for token in re.findall(r"[A-Za-z0-9_+/=-]{20,}", window):
            if _shannon_entropy(token) > 4.3:
                return "dlp-entropy-tripwire"
    return None


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
    return blocked, blocking_rule, redacted, redactions
