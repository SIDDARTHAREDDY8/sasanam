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
    executor appends at every executed upload-shaped call (F139/F140).
  - ``verify_citation``: ``SELF_PLANTED`` / ``UNKNOWN`` / ``INDEPENDENT``
    for one cited URL.
  - ``extract_urls``: pull candidate citations out of evaluator-facing
    text.
  - ``canonical_params_fingerprint``: (bytes, sha256_prefix) over a
    canonical serialization of api_call params (the log carries params
    as a scrubbed dict, not the http_post {bytes, sha256} summary).

Upload-shaped tools (F140): ``http_post`` (URL-bearing arg ``url``,
payload arg ``payload``) and ``api_call`` (URL-bearing arg
``endpoint``, payload arg ``params``). The correlation primary key is
the normalized URL; the payload fingerprint is corroboration only.

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
  - Response-URL gap (F140 follow-up, NOT closed here): a real API
    plant's citable URL is usually a *resource* URL returned in the API
    response, not the endpoint the agent called. This primitive
    correlates the endpoint -- a citation of a response-minted resource
    URL has no governed record to match. Closing that needs response
    capture or endpoint->content bindings; do not claim it.
"""

import hashlib
import hmac
import json
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

# F140: the tools whose executed calls are upload-shaped -- a
# URL-addressable egress call carrying a payload to a third-party host.
# http_post: URL-bearing arg "url", payload arg "payload".
# api_call: URL-bearing arg "endpoint", payload arg "params".
_UPLOAD_TOOLS = ("http_post", "api_call")


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


def canonical_params_fingerprint(params):
    """(bytes, sha256_prefix) over a canonical serialization of params.

    api_call's redacted args carry ``params`` as a (PII-scrubbed) dict,
    not the ``{bytes, sha256_prefix}`` summary http_post's ``payload``
    uses -- so both the ledger writer (executor._record_upload) and the
    log index compute the summary from the canonical form (sorted-keys
    JSON) and stay consistent. The URL is the correlation primary key;
    this fingerprint is corroboration only.
    """
    try:
        data = json.dumps(params, sort_keys=True, separators=(",", ":"),
                          default=str).encode("utf-8", "replace")
    except (TypeError, ValueError):
        data = str(params).encode("utf-8", "replace")
    return len(data), hashlib.sha256(data).hexdigest()[:16]


def upload_records_from_log_entries(entries):
    """Extract governed upload-shaped call records from chained-log entries.

    Each record: {url, url_normalized, payload_sha256_prefix,
    payload_bytes, agent_id, principal, run_id, seq, tool, source}.
    Only EXECUTED calls (allowed_executed / approved_executed) -- a
    queued but never approved call never reached the host and is not a
    plant. Covers http_post (url/payload) and api_call (endpoint/params).
    """
    out = []
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        if e.get("event") != "tool_call":
            continue
        tool = e.get("tool")
        if tool not in _UPLOAD_TOOLS:
            continue
        if e.get("decision") not in _EXECUTED_DECISIONS:
            continue
        args = e.get("args") or {}
        if tool == "http_post":
            url = args.get("url")
            payload = args.get("payload")
            sha_prefix, nbytes = None, None
            if isinstance(payload, dict):
                sha_prefix = payload.get("sha256_prefix")
                nbytes = payload.get("bytes")
        else:  # api_call: "endpoint" is the URL-bearing arg; params
            # are the payload (scrubbed dict in the log, not a summary).
            url = args.get("endpoint")
            nbytes, sha_prefix = canonical_params_fingerprint(
                args.get("params"))
        normalized = normalize_url(url)
        if normalized is None:
            continue
        out.append({
            "url": url,
            "url_normalized": normalized,
            "payload_sha256_prefix": sha_prefix,
            "payload_bytes": nbytes,
            "agent_id": e.get("agent_id"),
            "principal": e.get("principal"),
            "run_id": e.get("run_id"),
            "seq": e.get("seq"),
            "tool": tool,
            "source": "action_log",
            # F142: the chained log carries payload summaries only (F12),
            # never full content hashes -- content-keyed correlation
            # comes from the ledger records (see
            # upload_records_from_ledger_entries).
            "content_sha256_set": [],
            # F142: response-minted resource URLs captured at the
            # executor's API-execution boundary (additive; old log
            # records predate the field and parse as empty).
            "response_urls": [
                n for n in (
                    normalize_url(u)
                    for u in (e.get("response_urls") or [])
                    if isinstance(u, str)
                ) if n
            ],
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
            # F142: full content hashes of the uploaded payload's string
            # leaves (written by the executor's _record_upload). Old
            # ledger entries predate the field and parse as empty.
            "content_sha256_set": [
                str(h).lower() for h in (e.get("content_sha256_set") or [])
                if isinstance(h, str) and h
            ],
            # F142: response-minted resource URLs captured at the
            # executor's API-execution boundary (additive; old ledger
            # entries predate the field and parse as empty).
            "response_urls": [
                n for n in (
                    normalize_url(u)
                    for u in (e.get("response_urls") or [])
                    if isinstance(u, str)
                ) if n
            ],
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
        # F142: secondary key over full content hashes (exact 256-bit
        # match only). hex digest (lowercased) -> [records].
        self._by_content_hash = {}

    def add_upload_records(self, records):
        for r in records or []:
            n = r.get("url_normalized")
            if n:
                self._by_url.setdefault(n, []).append(r)
            # F142: index response-minted resource URLs as aliases of
            # the same plant record (one record, many keys).
            for alias in r.get("response_urls") or []:
                a = normalize_url(alias)
                if a and a != n:
                    self._by_url.setdefault(a, []).append(r)
            for h in r.get("content_sha256_set") or []:
                key = str(h).lower()
                if key:
                    self._by_content_hash.setdefault(key, []).append(r)
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

    def lookup_by_content_sha256(self, hex_digest):
        """F142: upload records whose payload contained these exact bytes.

        Exact 256-bit match only -- a near-miss digest is a miss (no
        fuzzy/structural matching; accusation-unsafe). Returns matching
        records, earliest first. Empty list on unparseable input.
        """
        if not isinstance(hex_digest, str):
            return []
        return list(self._by_content_hash.get(hex_digest.lower(), []))

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
    # F142: content-keyed correlation. When the URL key misses but the
    # evaluator fetched the cited content and hands us its sha256, an
    # exact match against a governed upload's payload bytes is plant
    # evidence -- and plant evidence beats trust anchors on both keys.
    if content_sha256:
        chits = idx.lookup_by_content_sha256(str(content_sha256))
        if chits:
            first = chits[0]
            up_principal = first.get("principal")
            up_agent = first.get("agent_id")
            return {
                "url": url,
                "url_normalized": normalized,
                "verdict": SELF_PLANTED,
                "upload": first,
                "n_uploads": len(chits),
                "same_principal": (bool(principal) and bool(up_principal)
                                   and principal == up_principal),
                "same_agent": (bool(agent_id) and bool(up_agent)
                               and agent_id == up_agent),
                "reason": ("fetched content hash matches a governed "
                           "upload (content-keyed correlation, source=%s, "
                           "uploader=%s/%s); the cited evidence is not "
                           "independent" %
                           (first.get("source"), up_principal, up_agent)),
            }
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

#: F142: explicit result keys that carry a response-minted resource URL,
#: in preference order. The bare "url" key is handled separately: it is
#: only a response URL when it differs from the called endpoint (an echo
#: of the request URL is not minted).
_RESPONSE_URL_KEYS = ("resource_url", "resource_urls", "location")

#: F142: bounds for the heuristic string scan in
#: extract_response_urls (see docstring).
_RESPONSE_URL_SCAN_MAX_URLS = 25
_RESPONSE_URL_SCAN_MAX_DEPTH = 3
_RESPONSE_URL_SCAN_MAX_CHARS = 65536


def extract_response_urls(tool, result, endpoint=None):
    """F142: response-minted resource URLs from an upload-shaped result.

    A real API plant's citable URL is minted in the API *response*, not
    the request the agent made. This pulls candidate resource URLs out
    of the result so the upload record can be indexed under them as
    aliases of the plant.

    Explicit well-known keys first (``resource_url``, ``resource_urls``,
    ``location``), then the bare ``url`` key when it differs from the
    called endpoint, then a bounded scan of string values for embedded
    ``https?://`` URLs (max depth 3, ~64 KiB of string content, first 25
    URLs). URLs are normalized; the called endpoint itself is never
    reported (it is already the record's primary key).

    Never raises: extraction is heuristic, and a capture bug must
    degrade detection (missed alias), never break the result path.
    ``tool`` names the upload-shaped tool (currently unused; part of
    the seam contract for future tool-specific handling).
    """
    found = []
    seen = set()
    try:
        if not isinstance(result, dict):
            return []
        endpoint_n = normalize_url(endpoint) if endpoint else None

        def _add(raw):
            n = normalize_url(raw)
            if n and n != endpoint_n and n not in seen:
                seen.add(n)
                found.append(n)

        for key in _RESPONSE_URL_KEYS:
            v = result.get(key)
            vals = v if isinstance(v, list) else [v]
            for u in vals:
                if isinstance(u, str) and len(found) < \
                        _RESPONSE_URL_SCAN_MAX_URLS:
                    _add(u)
        u = result.get("url")
        if isinstance(u, str):
            _add(u)
        budget = [_RESPONSE_URL_SCAN_MAX_CHARS]

        def _scan(v, depth):
            if (len(found) >= _RESPONSE_URL_SCAN_MAX_URLS
                    or budget[0] <= 0
                    or depth > _RESPONSE_URL_SCAN_MAX_DEPTH):
                return
            if isinstance(v, str):
                chunk = v[:budget[0]]
                budget[0] -= len(chunk)
                for m in _URL_RE.finditer(chunk):
                    if len(found) >= _RESPONSE_URL_SCAN_MAX_URLS:
                        return
                    _add(m.group(0).rstrip(".,;:!?"))
            elif isinstance(v, dict):
                for vv in v.values():
                    _scan(vv, depth + 1)
            elif isinstance(v, (list, tuple)):
                for vv in v:
                    _scan(vv, depth + 1)

        _scan(result, 0)
    except Exception:
        # Fail-open: never break the result path on a capture bug.
        pass
    return found


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


#: F142: bounds for payload leaf hashing (see payload_content_hashes).
_CONTENT_HASH_MAX_LEAVES = 32
_CONTENT_HASH_MAX_LEAF_BYTES = 1048576


def payload_content_hashes(payload):
    """F142: full sha256 hex digests of a payload's string leaves.

    Walks the payload (dict/list/tuple/str), hashing each string leaf
    as UTF-8. Bounded: first 32 leaves, leaves longer than 1 MiB
    skipped, empty leaves skipped, deduplicated, order-preserving.
    Exact 256-bit match only downstream -- no fuzzy matching.

    Never raises: hashing is a correlation aid, not a gate.
    """
    hashes = []
    seen = set()

    def _walk(v):
        if len(hashes) >= _CONTENT_HASH_MAX_LEAVES:
            return
        if isinstance(v, str):
            data = v.encode("utf-8", "replace")
            if not data or len(data) > _CONTENT_HASH_MAX_LEAF_BYTES:
                return
            h = hashlib.sha256(data).hexdigest()
            if h not in seen:
                seen.add(h)
                hashes.append(h)
        elif isinstance(v, dict):
            for vv in v.values():
                _walk(vv)
        elif isinstance(v, (list, tuple)):
            for vv in v:
                _walk(vv)

    try:
        _walk(payload)
    except Exception:
        pass
    return hashes
