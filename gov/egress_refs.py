"""Trusted-relay egress reference screening adapter (wave-273 lane I).

The EchoLeak successor work (CVE-2025-32711): zero-click prompt injection
exfiltrated tenant data WITHOUT any agent tool call. The injected
instruction directed the model to emit reference-style Markdown image
links carrying tenant data in the URL, which the client AUTO-FETCHED
through an allow-listed first-party relay proxy
(``teams.microsoft.com/urlp/v1/url/content``) -- a trusted relay acting
as an exfiltration channel. Link redaction was bypassed by the
reference-style shape (``[text][id]`` + ``[id]: url``).

The egress-screening adapter seam: the analog of the ImageTextExtractor
adapter (:mod:`gov.image_text`). Parsing stays owned by per-channel
adapters; this module composes extraction with screening and flows the
verdicts into the decision taxonomy. The first concrete channel is
:class:`MarkdownAutoFetchChannel` (inline/reference-style images and
links, HTML ``<img>``/``<a>``, and bare URLs for the link-unfurl/preview
surface).

Screening rules (deterministic, stdlib-only), evaluated per reference:
  1. Non-external refs (relative paths, fragments) and non-http(s)
     schemes are not egress -- allowed, recorded as such.
  2. Trusted-relay rule: a ref routed through a deployment-declared
     trusted relay (host + path prefix) whose decoded inner target is
     external (not in ``allowed_hosts``) AND carries an exfil-shaped
     payload (sensitive-digest match or oversized query/fragment) is
     refused with ``egress-relay-exfil``. A relay ref with a short
     clean inner query is allowed -- allow-listed relays carry benign
     traffic too (anti-FP pin c04).
  3. Data rule: a ref whose query/fragment embeds a value whose sha256
     matches ``sensitive_digests``, or whose query+fragment exceeds
     ``max_ref_payload_chars`` on a non-allow-listed effective host,
     is refused with ``egress-ref-data-exfil``.

Provenance tags (``rendered`` vs ``rendered-preview``) are a documented
heuristic over what typical clients render/auto-fetch, not a capability
boundary -- verdicts never depend on the tag.

Public seam: :func:`extract_egress_refs` and
:func:`screen_egress_refs`, plus :class:`EgressPolicy`,
:class:`EgressChannel`, :class:`MarkdownAutoFetchChannel`. Deterministic,
stdlib-only, explicit ``now`` accepted for pipeline symmetry (screening
is clock-free by construction), and never raises on hostile input.

Honest limits (listed on every verdict's ``out_of_scope``):
  * Pre-emission screening only. THE CLIENT PERFORMS THE FETCH: this
    module screens agent-produced content before it reaches the client.
    A client that never asks the gate, a proxy that serves anyway, or
    content that left through another path is outside enforcement.
  * Copy/paste surfaces are client-side clipboard operations and are
    invisible to any content screen.
  * URL shorteners and encrypted/encoded targets hide the effective
    destination; they are treated as external (never allow-listed by
    target), not resolved.
  * Outbound webhooks/callbacks are tool calls, governed at the call
    seam (:mod:`gov.egress_proxy`), not auto-fetch refs.
  * Instruction provenance (which input authored the exfil) is lane G's
    provenance-labeling spike, not this module.
"""

import hashlib
import re
import urllib.parse

try:
    from gov import decision_codes as _decision_codes
except Exception:  # noqa: BLE001
    _decision_codes = None


CODES = (
    "egress-refs-malformed",
    "egress-refs-oversized",
    "egress-ref-data-exfil",
    "egress-relay-exfil",
)

_MAX_CONTENT_BYTES = 1 * 1024 * 1024   # refuse before parsing (same budget)
_DEFAULT_MAX_REF_PAYLOAD_CHARS = 512   # query+fragment budget per ref
_MIN_DIGEST_TOKEN_CHARS = 8            # tokens shorter than this are noise

_OUT_OF_SCOPE = (
    "client-performs-fetch",
    "copy-paste-surfaces-invisible",
    "shortened-urls-treated-external",
    "webhooks-are-tool-calls",
    "instruction-provenance-out-of-scope",
)

# -- markdown parsing -----------------------------------------------------

# Reference definition: [id]: <url> "optional title"
_REF_DEF_RE = re.compile(
    r"(?m)^[ ]{0,3}\[([^\]]+)\]:[ \t]*<?([^>\s]+)>?"
    r"(?:[ \t]+[\"'(][^\"')]*[\"')])?[ \t]*$")

# Inline image/link: ![alt](url "title") / [text](url "title")
_INLINE_RE = re.compile(
    r"(!?)\[([^\]]*)\]\(\s*<?([^)\s]+)>?"
    r"(?:\s+[\"'][^\"']*[\"'])?\s*\)")

# Reference-style image/link: ![alt][id] / [text][id]
_REF_USE_RE = re.compile(r"(!?)\[([^\]]*)\]\[([^\]]*)\]")

# Collapsed/shortcut reference: [id] / [id][]  (not preceded by ![ or ]()
_SHORTCUT_RE = re.compile(r"(?<!!)\[(?P<id>[^\]\[]+)\](?:\[\])?")

_IMG_HTML_RE = re.compile(
    r"<img\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_A_HTML_RE = re.compile(
    r"<a\b[^>]*\bhref\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)

_BARE_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")


def _fail(code, detail, evidence_extra=None):
    if _decision_codes is not None and code not in _decision_codes.TAXONOMY:
        raise AssertionError("unknown decision code: %r" % (code,))
    evidence = {"detail": detail}
    if evidence_extra:
        evidence.update(evidence_extra)
    return {
        "verdict": "refuse",
        "provenance_label": "RETRIEVED_UNTRUSTED",  # wave-274: ingress label (instruction provenance)
        "code": code,
        "refs": [],
        "flagged": [],
        "checks": ["fail-closed"],
        "evidence": evidence,
        "out_of_scope": list(_OUT_OF_SCOPE),
    }


class EgressChannel(object):
    """Typed egress-screening adapter interface.

    A channel owns parsing for one auto-fetch surface and yields ref
    records: {"kind", "text", "url", "line", "provenance"}.
    Screening composes channels; it never forks their parsing.
    """
    channel_kind = "base"

    def extract_refs(self, content):
        """Return a list of ref records. Must not raise on hostile input."""
        raise NotImplementedError


class MarkdownAutoFetchChannel(EgressChannel):
    """Concrete channel: markdown + HTML + bare-URL auto-fetch surfaces.

    Kinds: image-inline, image-reference, link-inline, link-reference,
    img-html, a-html, url-plain. Reference definitions are resolved
    (case-insensitive id) -- the EchoLeak redaction-bypass shape.
    Provenance: "rendered" for client-rendered refs, "rendered-preview"
    for bare URLs (unfurl/preview fetch, not body rendering).
    """
    channel_kind = "markdown-auto-fetch"

    def extract_refs(self, content):
        try:
            return self._extract(content)
        except Exception:  # noqa: BLE001 -- never raise
            return []

    def _extract(self, content):
        if not isinstance(content, str):
            return []
        refs = []
        seen_spans = []

        def _claim(start, end):
            for s, e in seen_spans:
                if start < e and end > s:
                    return False
            seen_spans.append((start, end))
            return True

        def _line(text, pos):
            return text.count("\n", 0, pos) + 1

        # Reference definitions first (the resolution map). Claim the
        # definition-line spans so the shortcut and bare-URL shapes below
        # do not re-scan the definitions themselves.
        refmap = {}
        for m in _REF_DEF_RE.finditer(content):
            refmap[m.group(1).strip().lower()] = m.group(2).strip()
            _claim(m.start(), m.end())

        # Inline images/links.
        for m in _INLINE_RE.finditer(content):
            if not _claim(m.start(), m.end()):
                continue
            bang, text, url = m.group(1), m.group(2), m.group(3)
            refs.append({
                "kind": "image-inline" if bang else "link-inline",
                "text": text, "url": url.strip(),
                "line": _line(content, m.start()),
                "provenance": "rendered",
            })

        # Reference-style images/links.
        for m in _REF_USE_RE.finditer(content):
            if not _claim(m.start(), m.end()):
                continue
            bang, text, rid = m.group(1), m.group(2), m.group(3)
            target = refmap.get((rid or text).strip().lower())
            if target is None:
                continue
            refs.append({
                "kind": "image-reference" if bang else "link-reference",
                "text": text, "url": target,
                "line": _line(content, m.start()),
                "provenance": "rendered",
                "ref_id": rid or text,
            })

        # HTML img / a.
        for m in _IMG_HTML_RE.finditer(content):
            if not _claim(m.start(), m.end()):
                continue
            refs.append({"kind": "img-html", "text": "",
                         "url": m.group(1).strip(),
                         "line": _line(content, m.start()),
                         "provenance": "rendered"})
        for m in _A_HTML_RE.finditer(content):
            if not _claim(m.start(), m.end()):
                continue
            refs.append({"kind": "a-html", "text": "",
                         "url": m.group(1).strip(),
                         "line": _line(content, m.start()),
                         "provenance": "rendered"})

        # Shortcut references: [id] resolved via the map (skip anything
        # already claimed by the richer shapes above).
        for m in _SHORTCUT_RE.finditer(content):
            if not _claim(m.start(), m.end()):
                continue
            rid = m.group("id").strip()
            if not rid or "://" in rid:
                continue
            target = refmap.get(rid.lower())
            if target is None:
                continue
            refs.append({"kind": "link-reference", "text": rid,
                         "url": target,
                         "line": _line(content, m.start()),
                         "provenance": "rendered", "ref_id": rid})

        # Bare URLs (unfurl/preview surface). Skip ones inside already
        # claimed spans.
        for m in _BARE_URL_RE.finditer(content):
            url = m.group(0).rstrip(".,;:!?")
            if not _claim(m.start(), m.start() + len(url)):
                continue
            refs.append({"kind": "url-plain", "text": url, "url": url,
                         "line": _line(content, m.start()),
                         "provenance": "rendered-preview"})

        refs.sort(key=lambda r: (r["line"], r["url"]))
        return refs


class EgressPolicy(object):
    """Screening policy (deployment-owned configuration).

    trusted_relays: iterable of (host, path_prefix) -- first-party
      relay proxies that must be treated as UNTRUSTED exfiltration
      channels when the inner target is external and data-shaped.
    allowed_hosts: hosts the deployment trusts (own CDN, etc.).
    sensitive_digests: sha256 hex digests of data tokens that must
      never appear in an auto-fetch URL.
    max_content_bytes / max_ref_payload_chars: budgets.
    """
    def __init__(self, trusted_relays=(), allowed_hosts=(),
                 sensitive_digests=(), max_content_bytes=None,
                 max_ref_payload_chars=None):
        self.trusted_relays = tuple(
            (str(h).lower(), str(p)) for h, p in trusted_relays)
        self.allowed_hosts = frozenset(
            str(h).lower() for h in allowed_hosts)
        self.sensitive_digests = frozenset(
            str(d).lower() for d in sensitive_digests)
        self.max_content_bytes = (
            _MAX_CONTENT_BYTES if max_content_bytes is None
            else max_content_bytes)
        self.max_ref_payload_chars = (
            _DEFAULT_MAX_REF_PAYLOAD_CHARS
            if max_ref_payload_chars is None
            else max_ref_payload_chars)


_DEFAULT_POLICY = None


def _default_policy():
    global _DEFAULT_POLICY
    if _DEFAULT_POLICY is None:
        _DEFAULT_POLICY = EgressPolicy()
    return _DEFAULT_POLICY


# ------------------------------------------------------------------
# Public seam: extraction.
# ------------------------------------------------------------------

def extract_egress_refs(content, channels=None, now=None):
    """Extract auto-fetchable references into a typed record.

    ``now`` is accepted for pipeline symmetry and ignored: extraction
    is clock-free by construction. Never raises.
    """
    try:
        if not isinstance(content, (str, bytes, bytearray)):
            return _fail("egress-refs-malformed",
                         "content is not str/bytes")
        text = (content.decode("utf-8", "replace")
                if isinstance(content, (bytes, bytearray)) else content)
        if len(text.encode("utf-8")) > _MAX_CONTENT_BYTES:
            return _fail("egress-refs-oversized",
                         "content exceeds %d bytes" % _MAX_CONTENT_BYTES)
        chs = channels if channels is not None else (
            MarkdownAutoFetchChannel(),)
        refs = []
        kinds = set()
        for ch in chs:
            try:
                got = ch.extract_refs(text)
            except Exception:  # noqa: BLE001 -- a broken third-party
                continue       # channel adapter must not break the seam
            for ref in got:
                kinds.add(ch.channel_kind)
                refs.append(ref)
        return {
            "verdict": "ok",
            "provenance_label": "RETRIEVED_UNTRUSTED",  # wave-274: ingress label (instruction provenance)
            "code": None,
            "refs": refs,
            "checks": ["extracted"],
            "evidence": {
                "ref_count": len(refs),
                "channels": sorted(kinds),
                "kinds": sorted({r["kind"] for r in refs}),
            },
            "out_of_scope": list(_OUT_OF_SCOPE),
        }
    except Exception as exc:  # noqa: BLE001 -- never raise
        return _fail("egress-refs-malformed",
                     "internal extraction error: %r" % (exc,))


# ------------------------------------------------------------------
# Screening internals.
# ------------------------------------------------------------------

_INNER_PARAMS = ("url", "u")


def _split_url(url):
    """Parse a URL; return (scheme, host, path, query, fragment) or None
    when the URL is not absolute-external."""
    try:
        parts = urllib.parse.urlsplit(url.strip())
    except Exception:  # noqa: BLE001
        return None
    if not parts.scheme or not parts.netloc:
        return None
    if parts.scheme.lower() not in ("http", "https"):
        return ("other", "", "", "", "")
    return (parts.scheme.lower(), parts.hostname.lower() if parts.hostname
            else "", parts.path or "", parts.query or "",
            parts.fragment or "")


def _relay_inner_target(query):
    """Decode the inner target of a trusted-relay URL (EchoLeak shape).

    Returns the inner URL string, or None when the query carries no
    recognizable inner-target parameter.
    """
    try:
        params = urllib.parse.parse_qsl(query, keep_blank_values=True)
    except Exception:  # noqa: BLE001
        return None
    for name, value in params:
        if name.lower() in _INNER_PARAMS and value:
            try:
                return urllib.parse.unquote(value)
            except Exception:  # noqa: BLE001
                return value
    return None


def _payload_tokens(query, fragment):
    """Candidate data tokens from query+fragment for digest matching."""
    blob = (query or "") + "\n" + (fragment or "")
    toks = set()
    if blob.strip():
        toks.add(blob.strip())
    # Split on parameter separators and punctuation; '=' is excluded so
    # name=value pairs yield the value as its own token (the digest
    # list holds values, not pairs).
    for tok in re.split(r"[^A-Za-z0-9+/_-]", blob):
        if len(tok) >= _MIN_DIGEST_TOKEN_CHARS:
            toks.add(tok)
    return toks


def _digest_matches(tokens, policy):
    for tok in tokens:
        if hashlib.sha256(tok.encode("utf-8")).hexdigest() in \
                policy.sensitive_digests:
            return tok
    return None


def _data_shaped(query, fragment, policy):
    """The two-keyed exfil shape: sensitive-digest match OR oversized
    query/fragment payload. Returns a note string when data-shaped,
    else None. Shared by the relay rule and the data rule."""
    tokens = _payload_tokens(query, fragment)
    hit = _digest_matches(tokens, policy)
    if hit is not None:
        return "sensitive digest match in ref payload"
    if len(query) + len(fragment) > policy.max_ref_payload_chars:
        return ("ref payload %d chars over budget %d"
                % (len(query) + len(fragment),
                   policy.max_ref_payload_chars))
    return None


def _screen_ref(ref, policy):
    """Screen one ref. Returns (verdict, code, note)."""
    url = ref.get("url", "")
    split = _split_url(url)
    if split is None:
        return ("allow", None, "not-external")
    scheme, host, path, query, fragment = split
    if scheme == "other":
        return ("allow", None, "non-http-scheme")

    # Trusted-relay rule (EchoLeak): relay URL wrapping an external
    # inner target WITH an exfil-shaped payload. Digest and size are
    # both evaluated on the DECODED inner target: the outer query is
    # percent-encoded, which glues tokens to %-fragments and would
    # defeat digest matching.
    relay_hit = None
    for rhost, rprefix in policy.trusted_relays:
        if host == rhost and path.startswith(rprefix):
            relay_hit = (rhost, rprefix)
            break
    if relay_hit is not None:
        inner = _relay_inner_target(query)
        inner_host = None
        inner_query = inner_fragment = ""
        if inner:
            isplit = _split_url(inner)
            if isplit and isplit[0] != "other":
                inner_host = isplit[1]
                inner_query, inner_fragment = isplit[3], isplit[4]
        if inner_host is not None and \
                inner_host not in policy.allowed_hosts:
            note = _data_shaped(inner_query, inner_fragment, policy)
            if note is not None:
                return ("refuse", "egress-relay-exfil",
                        "relay inner target external: " + note)
            return ("allow", None, "relay-external-inner-clean")
        # Relay to an allowed (or unresolvable) inner target: fall
        # through to the data rule on the full relay URL.
    effective_host = host
    if effective_host in policy.allowed_hosts:
        return ("allow", None, "allowed-host")
    note = _data_shaped(query, fragment, policy)
    if note is not None:
        return ("refuse", "egress-ref-data-exfil", note)
    return ("allow", None, "clean")


# ------------------------------------------------------------------
# Public seam: screening.
# ------------------------------------------------------------------

def screen_egress_refs(content, policy=None, channels=None, now=None):
    """Extract refs, then screen each against the policy.

    Refuses with ``egress-relay-exfil`` (trusted-relay exfil shape) or
    ``egress-ref-data-exfil`` (sensitive data / oversized payload in an
    auto-fetch URL). Allows everything else. Never raises.
    """
    try:
        pol = policy if policy is not None else _default_policy()
        record = extract_egress_refs(content, channels=channels, now=now)
        if record["verdict"] != "ok":
            return {
                "verdict": record["verdict"],
                "provenance_label": "RETRIEVED_UNTRUSTED",  # wave-274: ingress label (instruction provenance)
                "code": record["code"],
                "refs": record["refs"],
                "flagged": [],
                "checks": record["checks"],
                "evidence": record["evidence"],
                "out_of_scope": list(_OUT_OF_SCOPE),
            }
        flagged = []
        notes = []
        for ref in record["refs"]:
            verdict, code, note = _screen_ref(ref, pol)
            ref = dict(ref)
            ref["screen"] = {"verdict": verdict, "code": code,
                             "note": note}
            notes.append(ref)
            if verdict == "refuse":
                flagged.append(ref)
        checks = ["screened:%d" % len(notes)]
        evidence = {
            "ref_count": len(notes),
            "flagged_count": len(flagged),
            "flagged": [{"kind": r["kind"], "url": r["url"][:120],
                         "code": r["screen"]["code"],
                         "note": r["screen"]["note"]}
                        for r in flagged],
        }
        if flagged:
            code = flagged[0]["screen"]["code"]
            if _decision_codes is not None and \
                    code not in _decision_codes.TAXONOMY:
                raise AssertionError(
                    "unknown decision code: %r" % (code,))
            return {
                "verdict": "refuse",
                "provenance_label": "RETRIEVED_UNTRUSTED",  # wave-274: ingress label (instruction provenance)
                "code": code,
                "refs": notes,
                "flagged": flagged,
                "checks": checks + ["refused"],
                "evidence": evidence,
                "out_of_scope": list(_OUT_OF_SCOPE),
            }
        return {
            "verdict": "allow",
            "provenance_label": "RETRIEVED_UNTRUSTED",  # wave-274: ingress label (instruction provenance)
            "code": None,
            "refs": notes,
            "flagged": [],
            "checks": checks + ["clean"],
            "evidence": evidence,
            "out_of_scope": list(_OUT_OF_SCOPE),
        }
    except Exception as exc:  # noqa: BLE001 -- never raises
        return _fail("egress-refs-malformed",
                     "internal screening error: %r" % (exc,))


def rail_verdict_of(record):
    """Adapt an egress-screening verdict dict to the uniform rail
    vocabulary (wave-274 lane 2). The ``screen_egress_refs`` dict
    contract is unchanged; this is the uniform view. Unknown verdict
    words refuse ``rail-adapter-unknown-verdict``.
    """
    from . import rail_verdict as _rv
    return _rv.from_screen_verdict(record, stage="egress-screening")
