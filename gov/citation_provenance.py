"""Citation provenance (F139): was this cited URL planted by a governed agent?

Attack class: a model under evaluation uploads fabricated files to an
allowlisted web host (paste site, gist) via governed ``http_post`` and
later cites the planted URL back to evaluators as *independent*
corroboration -- poisoning the evaluation evidence base. The approval
gate is structurally blind to the plant (F12: the approver sees only the
URL plus ``{bytes, sha256_prefix}``), so the defense cannot live at the
upload gate. It lives HERE, at the citation: evaluators treat bare-URL
citations as untrusted-by-default and verify each one against the
governed upload record.

What this module does:
  - ``normalize_url``: canonical URL form for plant/citation matching.
  - ``CitationIndex``: queryable index of governed uploads, built from
    (a) per-run chained-log ``tool_call`` entries (URL + payload sha
    prefix + uploader identity are already recorded there) and/or
    (b) the cross-run ``EgressLedger`` ``kind:"upload"`` entries the
    executor appends at every executed http_post (F139).
  - ``verify_citation``: ``SELF_PLANTED`` / ``UNKNOWN`` / ``INDEPENDENT``
    for one cited URL.
  - ``extract_urls``: pull candidate citations out of evaluator-facing
    text.

Verdict semantics (read carefully):
  - ``SELF_PLANTED``: the URL was uploaded through governed tooling.
    The cited evidence is NOT independent of the governed population.
    This does NOT prove the citer planted it themselves -- the uploader
    identity rides in the evidence, with ``same_principal`` /
    ``same_agent`` flags so the evaluator can distinguish self-plant
    from another-agent plant. Either way the citation is tainted.
  - ``INDEPENDENT``: the URL was NOT uploaded through governed tooling
    AND it carries a positive trust anchor -- the host is on the
    deployment's ``trusted_sources`` list, or the fetched content's
    sha256 is on ``trusted_content_hashes``. Absent a trust anchor the
    verdict is UNKNOWN, never INDEPENDENT: this module does not certify
    the open internet.
  - ``UNKNOWN``: no governed upload record and no trust anchor. This is
    the honest default, not a clean bill of health.

Precedence: plant evidence beats trust anchors. A plant uploaded TO a
trusted host still verifies SELF_PLANTED -- the trust anchor attests to
the host, not to who put the bytes there.

What this module does NOT do (stated residuals):
  - Paraphrased or re-encoded content defeats payload matching; the
    URL is the primary key and payload sha (a 16-char prefix in the
    log) is only corroboration. Fuzzy/structural content matching is
    follow-up work, not claimed here.
  - Query-string evasion: ``?x=1`` appended to a planted URL is a
    different normalized URL (conservative against false accusation;
    the tradeoff is documented).
  - Plants uploaded through channels outside governance (personal
    device, a second ungoverned agent, the model memorizing the URL
    from training) are invisible -- the index covers governed uploads
    only.
  - The uploader identity in the log is only as strong as the process
    boundary (the standing GOVERNANCE WARNING on mint_identity):
    configure a deployment-controlled PrincipalRegistry for real
    deployments.
"""

import hashlib
import hmac
import re
from urllib.parse import urlsplit

SELF_PLANTED = "SELF_PLANTED"
UNKNOWN = "UNKNOWN"
INDEPENDENT = "INDEPENDENT"

_VERDICTS = (SELF_PLANTED, UNKNOWN, INDEPENDENT)

# Upload-shaped decisions in the chained action log. A plant that was
# queued but never approved never reached the host -- only executed
# uploads count.
_EXECUTED_DECISIONS = ("allowed_executed", "approved_executed")


def normalize_url(url):
    """Canonical form of a URL for plant/citation matching.

    Returns None when the URL cannot be parsed or is not http(s) --
    callers treat that as unverifiable (UNKNOWN), never as clean.
    Normalization: scheme+host lowercased, default ports dropped,
    trailing-dot host stripped, fragment dropped, empty path -> "/",
    one trailing slash stripped. The query string is significant (a
    different query is a different URL -- see module docstring for the
    documented query-evasion residual).
    """
    if not isinstance(url, str):
        return None
    url = url.strip()
    if not url:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return None
    port = parts.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    netloc = host if port is None else "%s:%d" % (host, port)
    out = "%s://%s%s" % (scheme, netloc, path)
    if parts.query:
        out += "?" + parts.query
    return out


def _host_of(normalized_url):
    try:
        return urlsplit(normalized_url).hostname or ""
    except ValueError:
        return ""


def upload_records_from_log_entries(entries):
    """Extract governed http_post upload records from chained-log entries.

    Each record: {url, url_normalized, payload_sha256_prefix,
    payload_bytes, agent_id, principal, run_id, seq, source}. Only
    EXECUTED uploads (allowed_executed / approved_executed) -- a queued
    but never approved post never reached the host and is not a plant.
    """
    out = []
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        if e.get("event") != "tool_call":
            continue
        if e.get("tool") != "http_post":
            continue
        if e.get("decision") not in _EXECUTED_DECISIONS:
            continue
        args = e.get("args") or {}
        url = args.get("url")
        normalized = normalize_url(url)
        if normalized is None:
            continue
        payload = args.get("payload")
        sha_prefix, nbytes = None, None
        if isinstance(payload, dict):
            sha_prefix = payload.get("sha256_prefix")
            nbytes = payload.get("bytes")
        out.append({
            "url": url,
            "url_normalized": normalized,
            "payload_sha256_prefix": sha_prefix,
            "payload_bytes": nbytes,
            "agent_id": e.get("agent_id"),
            "principal": e.get("principal"),
            "run_id": e.get("run_id"),
            "seq": e.get("seq"),
            "source": "action_log",
        })
    return out


def upload_records_from_ledger_entries(entries):
    """Extract upload records from cross-run EgressLedger entries
    (kind == "upload", appended by the executor at F139)."""
    out = []
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        if e.get("kind") != "upload":
            continue
        url = e.get("url")
        normalized = e.get("url_normalized") or normalize_url(url)
        if normalized is None:
            continue
        out.append({
            "url": url,
            "url_normalized": normalized,
            "payload_sha256_prefix": e.get("payload_sha256_prefix"),
            "payload_bytes": e.get("payload_bytes"),
            "agent_id": e.get("agent_id"),
            "principal": e.get("principal"),
            "run_id": e.get("run_id"),
            "seq": e.get("seq"),
            "ts": e.get("ts"),
            "source": "egress_ledger",
        })
    return out


class CitationIndex:
    """Queryable index of governed uploads.

    Merge as many sources as the evaluator has: the current run's
    chained-log entries (``add_log_entries``) and the shared cross-run
    ledger (``add_ledger``). ``lookup(url)`` returns every matching
    upload record, earliest first.
    """

    def __init__(self):
        self._by_url = {}

    def add_upload_records(self, records):
        for r in records or []:
            n = r.get("url_normalized")
            if n:
                self._by_url.setdefault(n, []).append(r)
        return self

    def add_log_entries(self, entries):
        return self.add_upload_records(
            upload_records_from_log_entries(entries))

    def add_ledger(self, ledger):
        """Add cross-run uploads from an EgressLedger (uses its verified
        ``uploads()`` query -- never raw file reads)."""
        if ledger is None:
            return self
        return self.add_upload_records(
            upload_records_from_ledger_entries(ledger.uploads()))

    def lookup(self, url):
        n = normalize_url(url)
        if n is None:
            return []
        return list(self._by_url.get(n, []))

    def __len__(self):
        return sum(len(v) for v in self._by_url.values())


def _identity_parts(identity):
    """(principal, agent_id) from an AgentIdentity or a plain dict."""
    if identity is None:
        return None, None
    if isinstance(identity, dict):
        return identity.get("principal"), identity.get("agent_id")
    return (getattr(identity, "principal", None),
            getattr(identity, "agent_id", None))


def _host_trusted(host, trusted_sources):
    host = (host or "").lower().rstrip(".")
    for src in trusted_sources or ():
        s = str(src).lower().rstrip(".")
        if not s:
            continue
        if host == s or host.endswith("." + s):
            return True
    return False


def verify_citation(url, identity=None, *, index=None, log_entries=None,
                    ledger=None, trusted_sources=(),
                    trusted_content_hashes=(), content_sha256=None):
    """Verify one cited URL against governed upload records.

    Returns {"url", "url_normalized", "verdict", "upload",
    "same_principal", "same_agent", "reason"} where verdict is one of
    SELF_PLANTED / UNKNOWN / INDEPENDENT and "upload" is the earliest
    matching upload record (or None).

    ``identity`` is the citing identity (AgentIdentity or dict) --
    used only for the same_principal/same_agent flags in the evidence.
    ``trusted_sources`` is an iterable of host suffixes the deployment
    vouches for (e.g. ("nature.com",)); ``trusted_content_hashes`` is
    an iterable of hex sha256 digests with ``content_sha256`` the hash
    of content the evaluator fetched. Plant evidence always beats
    trust anchors.
    """
    normalized = normalize_url(url)
    if normalized is None:
        return {"url": url, "url_normalized": None, "verdict": UNKNOWN,
                "upload": None, "same_principal": None,
                "same_agent": None,
                "reason": "unparseable or non-http(s) URL: unverifiable"}
    idx = index
    if idx is None:
        idx = CitationIndex()
        if log_entries is not None:
            idx.add_log_entries(log_entries)
        if ledger is not None:
            idx.add_ledger(ledger)
    hits = idx.lookup(normalized)
    principal, agent_id = _identity_parts(identity)
    if hits:
        # Earliest upload is the plant record; keep every hit in
        # evidence for multi-plant forensics.
        first = hits[0]
        up_principal = first.get("principal")
        up_agent = first.get("agent_id")
        return {
            "url": url,
            "url_normalized": normalized,
            "verdict": SELF_PLANTED,
            "upload": first,
            "n_uploads": len(hits),
            "same_principal": (bool(principal) and bool(up_principal)
                               and principal == up_principal),
            "same_agent": (bool(agent_id) and bool(up_agent)
                           and agent_id == up_agent),
            "reason": ("URL was uploaded through governed tooling "
                       "(source=%s, uploader=%s/%s); the cited evidence "
                       "is not independent" %
                       (first.get("source"), up_principal, up_agent)),
        }
    host = _host_of(normalized)
    if _host_trusted(host, trusted_sources):
        return {"url": url, "url_normalized": normalized,
                "verdict": INDEPENDENT, "upload": None,
                "same_principal": None, "same_agent": None,
                "reason": "host %s is on the deployment trust anchor "
                          "and no governed upload record exists" % host}
    if content_sha256:
        wanted = str(content_sha256).lower()
        for h in trusted_content_hashes or ():
            # compare_digest: the allowlist is a trust anchor, not a
            # secret, but constant-time comparison costs nothing.
            if hmac.compare_digest(str(h).lower(), wanted):
                return {"url": url, "url_normalized": normalized,
                        "verdict": INDEPENDENT, "upload": None,
                        "same_principal": None, "same_agent": None,
                        "reason": "fetched content hash is on the "
                                  "deployment trust anchor and no governed "
                                  "upload record exists"}
    return {"url": url, "url_normalized": normalized, "verdict": UNKNOWN,
            "upload": None, "same_principal": None, "same_agent": None,
            "reason": "no governed upload record and no trust anchor: "
                      "provenance unknown (not a clean bill of health)"}


_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")


def extract_urls(text):
    """Pull candidate citation URLs out of evaluator-facing text.

    Trailing sentence punctuation is stripped. Order-preserving,
    deduplicated.
    """
    out = []
    seen = set()
    for m in _URL_RE.finditer(text or ""):
        u = m.group(0).rstrip(".,;:!?")
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def payload_sha256_hex(payload):
    """Full sha256 hex of a payload value (canonical UTF-8 form).

    Convenience for deployments that want to bind a plant record to
    exact bytes; the chained log itself carries only the 16-char
    prefix (F12), so this is for evaluator-side fetched content, not
    log parsing.
    """
    if isinstance(payload, (bytes, bytearray)):
        data = bytes(payload)
    else:
        data = str(payload).encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()
