"""MCP adapter: a governed wrapper around an MCP client session.

``GovernedMCPClient`` wraps an ``mcp.ClientSession`` (or any object with
the same ``call_tool`` / ``list_tools`` coroutine interface). The only
tool-invocation path it exposes is its own ``call_tool`` coroutine:

1. the requested ``name`` is resolved through the binding's tool map
   (unregistered names -> :class:`UnregisteredToolError`, fail closed);
2. the executor mediates the call (identity, role, DLP, rate guards,
   policy, audit log);
3. only on ``"executed"`` is the underlying session's ``call_tool``
   invoked; denials and queued approvals raise *without ever touching*
   the session.

The raw session is stored name-mangled (``_GovernedMCPClient__session``)
and **no public accessor, property, or method exposes it**. ``dir()``
on the client shows no ``session`` attribute.

Execution model
---------------
The executor authorizes and logs, then the real MCP server executes --
a deliberate **split authorization/execution** boundary (the executor
cannot host arbitrary server implementations). The executor's
simulated result is *not* returned; the server's ``CallToolResult`` is.
What the executor *does* guarantee: nothing reaches the server unless
the full governance pipeline allowed it, and every attempt -- allowed,
denied, or queued -- is in the tamper-evident log.

Residual limitation: code that already holds its own reference to the
raw session can call ``session.call_tool`` directly. In-process Python
cannot prevent that; the deployment rule is to never hand the raw
session to agent code -- only the governed client.

P2 metadata guard
-----------------
Tool *descriptions* are untrusted model input, not trusted config: a
malicious server can inject instructions into them, shadow trusted
tool names, or rug-pull a description after approval. Accordingly
:meth:`GovernedMCPClient.list_tools` is mediated, not a passthrough --
every entry is shape-checked, scanned for instruction-like content
(:func:`scan_tool_description`), and pinned by a canonical
``name + description + inputSchema`` hash (:func:`metadata_hash`).
:meth:`GovernedMCPClient.call_tool` re-validates the listing
immediately before dispatch so a swap between listing and call raises
:class:`MetadataChangedError` instead of executing. All listing
decisions are audit-logged; failures are fail-closed.

K-012 server provenance
-----------------------
Bind-time supply-chain provenance (OWASP LLM03 / ASI04): the client
optionally records a deployer-declared ``server_id``, a
``pinned_tools`` ``{name: metadata_hash}`` allowlist, and/or an ed25519
``server_public_key``. Every listing re-verifies provenance *before*
the P2 content scan: a swapped server identity, a tampered/unsigned
manifest, a missing or drifted pinned tool, or an advertised tool
outside the pin set raises :class:`ServerProvenanceError` -- the
session is never touched. Without these options the client keeps the
P2 dynamic behavior (scan + pin at first sight).
"""

from .core import AdapterError, GovernedBinding

import asyncio
import hashlib
import inspect
import json
import re
import time
import unicodedata
from collections import deque

from gov.ed25519 import sign as _ed25519_sign
from gov.ed25519 import verify as _ed25519_verify


class MetadataPoisoningError(AdapterError):
    """Tool metadata failed the P2 instruction-content scan.

    Carries ``tool_name`` and ``reason`` (a short machine-readable code
    such as ``"delimiter_tag"`` or ``"duplicate_tool_name"``).
    """

    def __init__(self, tool_name, reason):
        self.tool_name = tool_name
        self.reason = reason
        super().__init__(
            "MCP tool %r failed metadata safety scan (reason=%s); "
            "refusing to expose it." % (tool_name, reason)
        )


class MetadataChangedError(AdapterError):
    """A tool's pinned metadata changed between observations (rug pull).

    Carries ``tool_name`` plus ``expected_hash`` / ``observed_hash``.
    """

    def __init__(self, tool_name, expected_hash, observed_hash):
        self.tool_name = tool_name
        self.expected_hash = expected_hash
        self.observed_hash = observed_hash
        super().__init__(
            "MCP tool %r metadata changed after pinning "
            "(expected=%s observed=%s); refusing to call."
            % (tool_name, expected_hash[:16], observed_hash[:16])
        )


class ServerProvenanceError(AdapterError):
    """K-012: tool/MCP-server provenance check failed (fail closed).

    Carries ``tool_name`` (``"<server>"`` for server-level failures)
    and a machine-readable ``reason`` such as ``"server_id_mismatch"``,
    ``"pinned_tool_changed"``, ``"unpinned_tool_advertised"``, or
    ``"manifest_signature_invalid"``.
    """

    def __init__(self, tool_name, reason):
        self.tool_name = tool_name
        self.reason = reason
        super().__init__(
            "MCP server provenance check failed for %r (reason=%s); "
            "refusing." % (tool_name, reason)
        )


class ListingChurnError(AdapterError):
    """A server's tool-listing churn exceeded the rate limit.

    B5 pressure ratchet (F109 follow-up): the listing is REFUSED,
    fail-closed and loud -- never silently mediated. Carries
    ``server_id`` and ``reason`` (``"listing_churn_rate_limited"``).
    """

    def __init__(self, server_id, reason="listing_churn_rate_limited",
                 changes_in_window=0, window_s=0):
        self.server_id = server_id
        self.reason = reason
        self.changes_in_window = changes_in_window
        self.window_s = window_s
        super().__init__(
            "MCP server %r redefined its tool listing %d times in "
            "%ds (reason=%s); refusing to mediate the listing."
            % (server_id, changes_in_window, window_s, reason)
        )


class ListingChurnGuard:
    """Per-server listing-churn rate limiter + tool-count anomaly flags.

    B5 pressure-ratchet follow-up to F109 (wave-36): with tier-1 flags
    firing on any key-tool description, an adversary who can influence
    an MCP server's listing can flood the approval queue with
    plausible flagged descriptions (alert fatigue) to bury the real
    malicious tool. This guard bounds that pressure at the listing
    gate:

    * CHANGE-RATE LIMIT (fail-closed): more than ``max_changes``
      listings whose tool set or metadata hashes differ from the
      previous listing within ``window_s`` seconds -> the listing is
      REFUSED with :class:`ListingChurnError`. A server redefining
      its tool surface that fast is compromised or broken; refusing
      to mediate is the safe default, and the refusal is loud
      (audit-logged ``mcp_listing_churn_limited``), not silent.
      Identical re-listings (the normal ``call_tool`` pre-dispatch
      re-fetch) are NOT change events.
    * TOOL-COUNT ANOMALY (flag, not fatal): a listing whose tool
      count jumps (>= ``count_growth_factor`` x the max previously
      seen, or +``count_growth_abs`` absolute) returns
      ``tool_count_anomaly: True`` for audit annotation -- a sudden
      tool-flood is the queue-flooding shape even under the rate
      limit.

    Wave-37 review decision (open item from wave-36): SPLIT
    accounting, documented here as the design -- not just the status
    quo.

    * The CHANGE-RATE LIMIT keeps ATTACK-PRESSURE accounting: every
      presented listing counts, including ones the content scan later
      rejects. Rationale: the scanner is a heuristic; an adaptive
      adversary gets unlimited free probes against it unless
      rejections burn the budget. A server redefining its surface
      with hostile listings 6 times in 10 minutes is compromised or
      broken whether or not the scan caught each one -- refusing is
      the safe default, and each probe is audit-logged.
    * The TOOL-COUNT ANOMALY baseline is VALIDATED-ONLY: only fully
      accepted listings move ``accepted_max_count`` (via
      :meth:`note_accepted`, called after the accept audit lands).
      Rationale: counting rejected listings polluted the baseline --
      one giant scan-rejected listing permanently suppressed anomaly
      flags on later accepted floods (smaller than the rejected
      giant), a concrete detection-suppression exploit against the
      guard's own purpose. The anomaly measures accepted-surface
      behavior; rejected listings exert no queue pressure.

    State is per ``server_id``. Pure apart from the clock: pass
    ``now=`` a callable for deterministic tests; production uses
    ``time.monotonic``.
    """

    def __init__(self, *, max_changes=5, window_s=600.0,
                 count_growth_factor=2.0, count_growth_abs=10,
                 now=None):
        if max_changes < 1:
            raise ValueError("max_changes must be >= 1")
        if window_s <= 0:
            raise ValueError("window_s must be > 0")
        self._max_changes = max_changes
        self._window_s = float(window_s)
        self._growth_factor = float(count_growth_factor)
        self._growth_abs = int(count_growth_abs)
        self._now = now if now is not None else time.monotonic
        self._servers = {}

    def _state(self, server_id):
        st = self._servers.get(server_id)
        if st is None:
            st = {"last_hashes": None, "changes": deque(),
                  "accepted_max_count": 0}
            self._servers[server_id] = st
        return st

    def observe(self, server_id, tool_hashes):
        """Account one listing for ``server_id``.

        ``tool_hashes``: ``{tool_name: metadata_hash}`` of the live
        listing. Returns ``{"listing_changed": bool,
        "tool_count_anomaly": bool, "changes_in_window": int}``.
        Raises :class:`ListingChurnError` when the change-rate limit
        trips (the listing must then be refused, not mediated).

        Attack-pressure accounting (wave-37 decision): the change-rate
        state (``last_hashes``, ``changes``) commits for EVERY
        presented listing, including ones the content scan later
        rejects -- rejections still burn the probing budget. The
        tool-count anomaly compares against ``accepted_max_count``,
        which only :meth:`note_accepted` moves: rejected listings
        never pollute the validated baseline.
        """
        now = float(self._now())
        st = self._state(server_id)
        cutoff = now - self._window_s
        while st["changes"] and st["changes"][0] <= cutoff:
            st["changes"].popleft()

        hashes = dict(tool_hashes or {})
        count = len(hashes)
        changed = (st["last_hashes"] is not None
                   and hashes != st["last_hashes"])
        base = st["accepted_max_count"]
        anomaly = (base > 0 and count > base
                   and (count >= base * self._growth_factor
                        or count - base >= self._growth_abs))
        st["last_hashes"] = hashes

        if changed:
            st["changes"].append(now)
            if len(st["changes"]) > self._max_changes:
                raise ListingChurnError(
                    server_id,
                    changes_in_window=len(st["changes"]),
                    window_s=self._window_s)
        return {"listing_changed": changed,
                "tool_count_anomaly": anomaly,
                "changes_in_window": len(st["changes"])}

    def note_accepted(self, server_id, tool_count):
        """Record a FULLY VALIDATED listing for ``server_id``.

        Called by the client only after the listing passed provenance,
        the content scan, rug-pull checks, pin commit, AND the accept
        audit landed. Moves the validated-only tool-count baseline;
        rejected listings never reach this call, so they cannot
        inflate the baseline and suppress later anomaly flags
        (wave-37 review).
        """
        if not isinstance(tool_count, int) or tool_count < 0:
            raise ValueError("tool_count must be a non-negative int")
        st = self._state(server_id)
        st["accepted_max_count"] = max(st["accepted_max_count"],
                                      tool_count)


# F102 (Wave-27): paraphrase-hardened secret-exfil detection.
#
# The F100 closure enumerated closed verb lists and closed material
# regexes with verb-before-material windows; the wave-27 red team
# showed 19/23 natural paraphrases evade (verb synonyms, "deployment
# key" morphology, passive/inflected verbs, distance padding beyond
# the windows, "secrets folder" phrasing, nbsp separators).
# Enumerating a longer verb list loses by construction -- natural
# language has open classes on both sides -- so the sensitive_path /
# exfiltration entries below are *material-centric*: secret-material
# mention + read/exfil context, decoupled from verb position and form:
#   * verb STEMS, not base forms: a fixed inflection map folds
#     uploaded/pasted/sent/... to upload/paste/send on a matching
#     copy, so inflection is a closed class per stem and passive voice
#     ("should be uploaded", "was already pasted") matches with no
#     verb-before-material ordering requirement;
#   * order-independent co-occurrence within the description: no
#     60/80-char windows, so distance padding cannot separate the verb
#     from the material;
#   * morphological material coverage: deploy(?:ment)?[ _-]?keys? and
#     "secrets folder|directory" phrasing; NFKC + Unicode-whitespace
#     folding on the matching copy closes the nbsp-separator class
#     (and Cf format chars are stripped, F84 precedent -- the original
#     description is untouched; only the matching copy is normalized).
# The verb-STEM inventory itself is still finite -- a genuinely novel
# disclosure stem ("whisper the deploy key") still evades; that
# residual is documented in F102 rather than papered over with a
# longer list.
# Fail-closed scoping (the 8 FP pins must hold): the READ branch is
# suppressed only when a secrets-MANAGEMENT verb directly governs the
# key material ("Fetch the deploy key from the vault and rotate it"
# is rotation-workflow prose, not exfiltration). The EXFIL branch has
# NO such carve-out: an explicit disclosure verb fires regardless of
# destination ("upload the deploy key to the vault for safekeeping"
# fires by design -- documented F102 precision observation).
# Documented residual: "read the deploy key and rotate the logs"
# (management verb governing something other than the key) still
# fires, but "read the deploy key and rotate it" is accepted -- the
# carve-out requires the management verb's object to be the key
# itself, so the laundering surface is one ambiguous rotation-workflow
# phrasing, and any disclosure verb still fires via the EXFIL branch.
_F102_VERB_INFLECTIONS = {
    # inflected form -> stem (closed per-stem inflection class)
    "reads": "read", "reading": "read",
    "opens": "open", "opened": "open", "opening": "open",
    "includes": "include", "included": "include", "including": "include",
    "displays": "display", "displayed": "display",
    "displaying": "display",
    "prints": "print", "printed": "print", "printing": "print",
    "shows": "show", "showed": "show", "shown": "show",
    "showing": "show",
    "fetches": "fetch", "fetched": "fetch", "fetching": "fetch",
    "gets": "get", "got": "get", "gotten": "get", "getting": "get",
    "copies": "copy", "copied": "copy", "copying": "copy",
    "extracts": "extract", "extracted": "extract",
    "extracting": "extract",
    "reveals": "reveal", "revealed": "reveal", "revealing": "reveal",
    "outputs": "output", "outputted": "output", "outputting": "output",
    "dumps": "dump", "dumped": "dump", "dumping": "dump",
    "lists": "list", "listed": "list", "listing": "list",
    "sends": "send", "sent": "send", "sending": "send",
    "uploads": "upload", "uploaded": "upload", "uploading": "upload",
    "exfiltrates": "exfiltrate", "exfiltrated": "exfiltrate",
    "exfiltrating": "exfiltrate",
    "forwards": "forward", "forwarded": "forward",
    "forwarding": "forward",
    "leaks": "leak", "leaked": "leak", "leaking": "leak",
    "pastes": "paste", "pasted": "paste", "pasting": "paste",
    "discloses": "disclose", "disclosed": "disclose",
    "disclosing": "disclose",
    "shares": "share", "shared": "share", "sharing": "share",
    "posts": "post", "posted": "post", "posting": "post",
    "publishes": "publish", "published": "publish",
    "publishing": "publish",
    # secrets-management verbs (fail-closed scoping only, never
    # detection verbs)
    "rotates": "rotate", "rotated": "rotate", "rotating": "rotate",
    "rotation": "rotate",
    "stores": "store", "stored": "store", "storing": "store",
    "revokes": "revoke", "revoked": "revoke", "revoking": "revoke",
    "provisions": "provision", "provisioned": "provision",
    "provisioning": "provision",
}
_F102_READ_STEMS = frozenset([
    "read", "cat", "open", "include", "display", "print", "show",
    "fetch", "get", "copy", "extract", "reveal", "output", "dump",
    "list",
])
_F102_EXFIL_STEMS = frozenset([
    "send", "upload", "exfiltrate", "forward", "leak", "paste",
    "disclose", "share", "post", "publish",
])
_F102_MANAGEMENT_STEMS = frozenset(["rotate", "store", "revoke",
                                    "provision"])

_F102_INFLECTION_RE = re.compile(
    r"\b(" + "|".join(sorted(_F102_VERB_INFLECTIONS, key=len,
                             reverse=True)) + r")\b")

# Path-shaped secret material (READ branch pairs with these only --
# "Read a secret from the vault" must stay clean, so bare "secret"
# is exfil-branch material, never read-branch material).
_F102_PATH_MATERIAL_RE = re.compile(
    r"~/\.ssh|id_rsa|\.pem\b"
    r"|deploy(?:ment)?[ _-]?keys?\b"
    r"|/run/secrets/|secrets?/"
    r"|secrets?\s+(?:folder|director(?:y|ies))\b")
# Any secret material (EXFIL branch).
_F102_SECRET_MATERIAL_RE = re.compile(
    r"~/\.ssh|id_rsa|\.pem\b"
    r"|deploy(?:ment)?[ _-]?keys?\b"
    r"|/run/secrets/|secrets?/"
    r"|secrets?\s+(?:folder|director(?:y|ies))\b"
    r"|\bprivate\s+key\b|\bpassword\b|\bapi[ _-]?key\b"
    r"|\bsecret\b|\bcredential\b|\btoken\b")


def _f102_normalize(text):
    """Matching-copy normalization for the F102 predicates.

    NFKC (homoglyph folding, F82 precedent), Cf format-char stripping
    (F84 precedent), Unicode-whitespace folding (closes the nbsp
    separator class), lowercasing, then verb-stem folding. The caller's
    original string is never modified.
    """
    t = unicodedata.normalize("NFKC", text)
    t = "".join(ch for ch in t if unicodedata.category(ch) != "Cf")
    t = re.sub(r"\s", " ", t)
    t = t.lower()
    return _F102_INFLECTION_RE.sub(
        lambda m: _F102_VERB_INFLECTIONS[m.group(1)], t)


def _f102_stem_present(stems, text):
    return re.search(r"\b(?:" + "|".join(sorted(stems)) + r")\b",
                    text) is not None


# A secrets-management verb directly governing the key material --
# "rotate it" / "rotate the deploy key" / "deploy key ... rotated".
# "rotate the logs" does NOT match: the object must be the key.
_F102_MGMT_GOVERNS_KEY_RE = re.compile(
    r"\b(?:rotate|store|revoke|provision)\b"
    r".{0,20}\b(?:it|them|the\s+deploy(?:ment)?[ _-]?keys?"
    r"|the\s+keys?)\b"
    r"|"
    r"\bdeploy(?:ment)?[ _-]?keys?\b"
    r".{0,30}\b(?:rotate|store|revoke|provision)\b"
    r".{0,20}\b(?:it|them|the\s+keys?|the\s+deploy)\b")


# F109 (Wave-33): the F104 carve-outs are DEAD AS SUPPRESSION. The
# benign contexts were a much smaller class than English disclosure
# verbs, but the suppression concept was incoherent by construction:
# every carve-out was a single ordinary word matched
# position-independently anywhere in the description and vetoed ONLY
# by the finite 10-stem _F102_EXFIL_STEMS -- the exact finiteness the
# tier existed to escape. 150/150 laundering (30 novel verbs x 5
# appended tokens) through both scanner entry points proved patching
# cannot converge (workstreams/redteam/F109_REDESIGN.md §1). Option
# A+C landed here:
#   * DETECTION ALWAYS FIRES: tier-1 material mentioned -> flag, full
#     stop. No carve-out, no veto, no finite inventory in the accept
#     path. An adversary appending "document the incident" buys
#     exactly nothing.
#   * FRAMING IS TRIAGE METADATA, never suppression: management /
#     documentation / audit framing still exists as ANALYSIS, but it
#     only re-keys the flag's reason (high_signal_material ->
#     high_signal_material_benign_framing) for routing, review-lane
#     priority, and audit annotation. See _f109_framing_tag for the
#     cry-wolf guardrails.
#   * Honest tools are handled OUTSIDE the scanner: the
#     deployer-controlled exact-hash description allowlist on
#     GovernedMCPClient (metadata_hash of name+description+inputSchema
#     -- nothing for the adversary to satisfy by word choice) plus
#     approval routing. Previously-clean honest controls
#     ("Rotates the deploy key via the vault") now FLAG, by design.
# The mgmt regex above STAYS for the F102 READ-branch suppression
# (_f102_sensitive_path): separate, narrower, documented decision --
# the READ branch is a stem-gated predicate with its own FP analysis,
# not the verb-independent tier.
_F102_TIER1_MATERIAL_RE = re.compile(
    r"deploy(?:ment)?[ _-]?keys?\b"
    r"|/run/secrets/|secrets?/"
    r"|secrets?\s+(?:folder|director(?:y|ies))\b")

# F109 framing-tag detectors (triage metadata ONLY -- these NEVER
# suppress detection; see _f109_framing_tag). Renamed out of the F104
# carve-out names to mark the semantic break: presence of these
# tokens no longer vetoes the tier, it only routes the flag.
_F109_FRAMING_MGMT_RE = _F102_MGMT_GOVERNS_KEY_RE
_F109_FRAMING_DOC_RE = re.compile(r"\bdocument\w*\b|\brunbooks?\b")
_F109_FRAMING_AUDIT_RE = re.compile(
    r"\baudit\s+logs?\b|\baudited\b|\baudit\s+trails?\b")


def _f109_framing_tag(description):
    """Triage-only framing tag for tier-1 flags, or None.

    Returns "management" / "documentation" / "audit" ("+"-joined when
    several match). Called only for descriptions that ALREADY flagged:
    the tag annotates the flag for routing, never decides it.

    TRIAGE METADATA, NEVER SUPPRESSION (F109 cry-wolf guardrails --
    named, not documented away):
    * The tag NEVER gates execution: a flagged description is refused
      regardless of the tag. ``scan_tool_description`` re-keys the
      reason only; the refusal is identical.
    * Review ordering must be independent of the tag, and the tag
      should be blinded from first-pass review UI: the adversary can
      add framing tokens for free, so "benign_framing" is a
      "please-deprioritize" signal they control (cry-wolf inversion).
    * Queue flooding via plausible flagged key-tool descriptions was a
      B5 pressure-ratchet residual: SOLVED wave-36 by
      ``ListingChurnGuard`` (per-server listing-churn rate limits +
      tool-count anomaly flags), enforced default-on in
      ``GovernedMCPClient._validate_and_pin`` -- a churning server's
      listing is refused fail-closed (``mcp_listing_churn_limited``)
      before its flood reaches the approval queue.
    """
    if not isinstance(description, str) or not description:
        return None
    t = _f102_normalize(description)
    tags = []
    if _F109_FRAMING_MGMT_RE.search(t):
        tags.append("management")
    if _F109_FRAMING_DOC_RE.search(t):
        tags.append("documentation")
    if _F109_FRAMING_AUDIT_RE.search(t):
        tags.append("audit")
    return "+".join(tags) if tags else None


def _f102_high_signal_material(description):
    """F104 tier-1, F109-hardened: high-signal material ALWAYS flags.

    Drops the verb requirement for deploy-key / secrets-directory
    material: ANY mention flags -- the benign-context suppression is
    deleted outright (F109), not narrowed. The framing analysis
    survives only as triage metadata: scan_tool_description re-keys
    the reason to "high_signal_material_benign_framing" when framing
    tokens are present; the flag itself is unconditional.
    Registered AFTER the verb-stem branches so known shapes keep
    their existing reason strings.
    """
    if not isinstance(description, str) or not description:
        return False
    t = _f102_normalize(description)
    return bool(_F102_TIER1_MATERIAL_RE.search(t))


def _f102_sensitive_path(description):
    """F102 READ branch: read-stem + path material, order-independent.

    Returns True (flag) on co-occurrence anywhere in the description,
    suppressed only when a management verb governs the key itself.
    """
    if not isinstance(description, str) or not description:
        return False
    t = _f102_normalize(description)
    if not (_f102_stem_present(_F102_READ_STEMS, t)
            and _F102_PATH_MATERIAL_RE.search(t)):
        return False
    if _F102_MGMT_GOVERNS_KEY_RE.search(t):
        return False
    return True


def _f102_exfiltration(description):
    """F102 EXFIL branch: disclosure-stem + secret material.

    No management carve-out: an explicit disclosure verb fires
    regardless of destination (fail closed).
    """
    if not isinstance(description, str) or not description:
        return False
    t = _f102_normalize(description)
    return bool(_f102_stem_present(_F102_EXFIL_STEMS, t)
                and _F102_SECRET_MATERIAL_RE.search(t))


# P2: instruction-like content patterns for tool descriptions. They
# target *imperative / system-style framing* and *exfiltration of
# sensitive material*, not ordinary descriptive prose ("Reads a file
# and returns its contents" matches none of these). Kept deliberately
# narrow: a secrets-manager tool saying "Read a secret from the vault"
# must NOT trip the scanner -- only exfiltration verbs
# (send/upload/leak/...) paired with secret material do.
#
# Entries are (reason, pattern) where pattern is either a compiled
# regex (``.search(description)``) or -- for the F102/F104 secret-exfil
# entries -- a predicate ``f(description) -> bool``. The secret-exfil
# entries need stem-normalization and order-independent co-occurrence
# (F102) and verb-independent material detection (F104), which single
# regexes cannot express cleanly.
_INSTRUCTION_PATTERNS = (
    # <IMPORTANT>...</IMPORTANT>, [SYSTEM], <instruction> -- prompt-
    # injection delimiter tags borrowed from chat markup.
    ("delimiter_tag",
     re.compile(r"[<\[]\s*(important|system|instruction|developer)\s*[>\]]",
                re.IGNORECASE)),
    # "ignore all previous instructions", "disregard the above rules".
    ("instruction_override",
     re.compile(r"\b(ignore|disregard)\b.{0,40}\b(previous\s+)?"
                r"(instructions?|rules?|guidance|orders?|directives?)\b",
                re.IGNORECASE)),
    # "before any other action, do X" -- priority hijack phrasing.
    ("priority_hijack",
     re.compile(r"\bbefore\s+(any|all|every)\s+(other\s+)?actions?\b",
                re.IGNORECASE)),
    # "do not tell the user", "without informing the operator".
    ("secrecy",
     re.compile(r"\bdo\s+not\s+(tell|inform|mention|disclose|reveal)\b"
                r".{0,60}\b(user|operator|human)\b",
                re.IGNORECASE)),
    # "Read ~/.ssh/id_rsa", "cat the private key". F100 (GitLost):
    # natural deploy-key / secrets-directory phrasing is unambiguous
    # secret exfiltration. F102: regex enumeration (closed verb lists,
    # closed material lists, verb-before-material windows) fell to
    # one-paraphrase -- the entry is now the material-centric
    # _f102_sensitive_path predicate (stem-normalized, order-
    # independent, morphological material coverage). Reason string
    # unchanged.
    ("sensitive_path", _f102_sensitive_path),
    # "send the password to ...", "leak the API key". F100: "send the
    # deploy key to ..." is the same exfil shape. F102: now the
    # _f102_exfiltration predicate -- disclosure-stem + secret
    # material, no management carve-out (fail closed). Reason string
    # unchanged.
    ("exfiltration", _f102_exfiltration),
    # F104: high-signal material tier -- deploy-key / secrets-directory
    # mention flags with no verb requirement (novel disclosure/read
    # verbs are an open class). F109 (A+C): the benign-context
    # suppression is deleted outright -- framing survives only as the
    # "high_signal_material_benign_framing" reason tag (triage
    # metadata, never suppression). Registered last so known shapes
    # keep their reason strings.
    ("high_signal_material", _f102_high_signal_material),
    # "bypass safety policy", "circumvent the approval guardrail".
    ("safety_override",
     re.compile(r"\b(override|bypass|circumvent)\b.{0,40}\b(safety|policy|"
                r"guardrail|restriction|approval)\b",
                re.IGNORECASE)),
    # "act as root", "pretend to be the system".
    ("role_reassignment",
     re.compile(r"\b(act\s+as|pretend\s+to\s+be)\b", re.IGNORECASE)),
)


def scan_tool_description(tool_name, description):
    """Scan one tool description for instruction-like content.

    Returns ``None`` when clean. Raises :class:`MetadataPoisoningError`
    (fail closed) on the first matching pattern or on a present but
    non-string description. An *absent* (``None``) description is clean:
    with no text there is no instruction content to scan, and many
    legitimate MCP tools omit descriptions.
    """
    if description is None:
        return None
    if not isinstance(description, str):
        raise MetadataPoisoningError(tool_name, "non_string_description")
    for reason, pattern in _INSTRUCTION_PATTERNS:
        # F102: the sensitive_path / exfiltration entries are
        # predicates (stem-normalized, order-independent
        # co-occurrence); every other entry is a compiled regex.
        if callable(pattern):
            matched = pattern(description)
        else:
            matched = pattern.search(description)
        if matched:
            # F109 (A+C): framing is triage metadata, never
            # suppression. The tier always fires on tier-1 material;
            # when benign framing is present the reason is re-keyed
            # for routing only -- the refusal is identical.
            if (reason == "high_signal_material"
                    and _f109_framing_tag(description)):
                reason = "high_signal_material_benign_framing"
            raise MetadataPoisoningError(tool_name, reason)
    return None


def _entry_name(entry):
    if isinstance(entry, dict):
        return entry.get("name")
    return getattr(entry, "name", None)


def _entry_description(entry):
    if isinstance(entry, dict):
        return entry.get("description")
    return getattr(entry, "description", None)


def _entry_schema(entry):
    if isinstance(entry, dict):
        return entry.get("inputSchema", entry.get("input_schema"))
    return getattr(entry, "inputSchema",
                    getattr(entry, "input_schema", None))


def _canonical_metadata(name, description, schema):
    """Deterministic canonical form of one tool's pinned metadata."""
    return json.dumps(
        {
            "name": name,
            "description": description,
            "inputSchema": schema,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def metadata_hash(name, description=None, schema=None):
    """Hex digest pinning a tool's ``name + description + inputSchema``.

    Either ``metadata_hash(name, description, schema)`` or
    ``metadata_hash(entry)`` where ``entry`` is a listing entry (dict
    or tool object with ``name``/``description``/``inputSchema``).
    """
    if not isinstance(name, str):
        entry = name
        name = _entry_name(entry)
        description = _entry_description(entry)
        schema = _entry_schema(entry)
    return hashlib.sha256(
        _canonical_metadata(name, description, schema).encode("utf-8")
    ).hexdigest()


class GovernedMCPClient:
    """Mediated façade over an MCP client session.

    ``GovernedMCPClient(binding, session)``

    * ``binding`` -- the :class:`GovernedBinding` used for mediation.
    * ``session`` -- the underlying MCP ``ClientSession`` (or test
      double). Stored privately; never exposed.
    * ``server_id`` (K-012) -- deployer-declared identity of the
      expected MCP server, e.g. ``"notes-svc-prod"``. Recorded at
      bind, audit-logged with every listing, and cross-checked against
      the session's advertised identity when the session exposes one.
    * ``pinned_tools`` (K-012) -- ``{tool_name: metadata_hash}`` of the
      deployer-approved tool definitions. Every listing must contain
      exactly these tools with matching hashes; absence, drift, or an
      extra advertised tool fails closed.
    * ``server_public_key`` (K-012) -- 32-byte ed25519 public key. When
      given, the session must serve a signed manifest via
      ``get_server_manifest() -> (manifest_bytes, signature)``; the
      signature is verified on every listing and the manifest's
      ``server_id`` must match ``server_id`` when that is also given.
    * ``description_allowlist`` (F109) -- a set of ``metadata_hash``
      digests (``name + description + inputSchema``) for deployer-
      approved honest tool descriptions. An entry whose hash is in
      the allowlist skips the P2 content scan in ``_validate_and_pin``
      (the accept decision is audit-logged, fail-closed on log
      failure). Hashes, not regexes: there is nothing for an
      adversary to satisfy by word choice, and any byte of metadata
      drift misses the hash and re-enters the scan. This is the
      deployer-controlled honest-path counterpart to the F109
      detection-always-fires tier: previously-clean honest rotation
      prose now flags unless allowlisted (or approval-routed).
    * ``listing_churn_guard`` (B5, F109 follow-up) -- a
      :class:`ListingChurnGuard`. Default-constructed when omitted
      (default-on): per-server listing-churn rate limiting and
      tool-count anomaly flags, enforced in ``_validate_and_pin``.
    * ``artifact_pinset`` (wave-80) -- a
      ``gov.load_gate.ArtifactPinset``. When attached, the two MCP
      artifact load points go through the digest gate (fail closed,
      no TOFU):
        - the signed server manifest: ``manifest_bytes`` are verified
          against pin ``mcp:manifest:<server_id>`` in
          ``_fetch_and_verify_manifest`` (in ADDITION to the ed25519
          signature — a valid signature over attacker-substituted
          bytes is the Plugin4Shell shape);
        - every tool-definition entry: the canonical ``name +
          description + inputSchema`` bytes are verified against pin
          ``mcp:tool:<server_id>:<name>`` in ``_validate_and_pin``
          before the entry's metadata hash is committed.
      Mismatch or a missing pin raises ``ArtifactRefused`` (loud,
      audit-logged ``mcp_artifact_refused``). Omitted (None) keeps
      the legacy behavior — the wave-80 documented residual on this
      seam (the K-012 ``pinned_tools`` / manifest-signature checks
      still apply).
    """

    def __init__(self, binding, session, server_id=None, pinned_tools=None,
                 server_public_key=None, description_allowlist=None,
                 listing_churn_guard=None, artifact_pinset=None):
        if not isinstance(binding, GovernedBinding):
            raise TypeError("binding must be a GovernedBinding, got %r"
                            % type(binding).__name__)
        if session is None:
            raise TypeError("session must not be None")
        call_tool = getattr(session, "call_tool", None)
        if not callable(call_tool):
            raise TypeError(
                "session must expose a callable 'call_tool', got %r"
                % type(session).__name__)
        if server_id is not None and not isinstance(server_id, str):
            raise TypeError("server_id must be a string, got %r"
                            % type(server_id).__name__)
        if pinned_tools is not None:
            if not isinstance(pinned_tools, dict):
                raise TypeError("pinned_tools must be a {name: hash} dict")
            for name, digest in pinned_tools.items():
                if not isinstance(name, str) or not name:
                    raise ValueError(
                        "pinned_tools keys must be non-empty strings")
                if not isinstance(digest, str) or not digest:
                    raise ValueError(
                        "pinned_tools[%r] must be a non-empty hash string"
                        % (name,))
        if server_public_key is not None and not (
                isinstance(server_public_key, (bytes, bytearray))
                and len(server_public_key) == 32):
            raise ValueError("server_public_key must be 32 bytes")
        if description_allowlist is not None:
            if not isinstance(description_allowlist,
                              (set, frozenset, list, tuple)):
                raise TypeError(
                    "description_allowlist must be a set of hash strings, "
                    "got %r" % type(description_allowlist).__name__)
            for digest in description_allowlist:
                if not isinstance(digest, str) or not digest:
                    raise ValueError(
                        "description_allowlist entries must be non-empty "
                        "hash strings")
        self._binding = binding
        self.__session = session  # name-mangled: no public path to it
        # P2: pinned metadata hashes, {tool_name: hex digest}, from the
        # last fully-validated listing. Replaced atomically only after
        # a complete listing scans clean (no partial pin state).
        self._metadata_pins = {}
        # K-012: bind-time provenance. The deployer pins are the
        # allowlist: the live listing must match them exactly.
        self._server_id = server_id
        self._deployer_pins = dict(pinned_tools or {})
        self._server_public_key = (bytes(server_public_key)
                                   if server_public_key is not None else None)
        # F109: exact-hash description allowlist, deployer-controlled.
        # Stored as a frozenset of metadata_hash digests; checked in
        # _validate_and_pin before the P2 content scan.
        self._description_allowlist = frozenset(description_allowlist or ())
        # B5 (F109 follow-up): per-server listing-churn rate limiter.
        # Default-on: a deployment that wants it off passes an
        # explicitly permissive guard; the default posture refuses
        # churned listings fail-closed.
        if listing_churn_guard is not None and not isinstance(
                listing_churn_guard, ListingChurnGuard):
            raise TypeError("listing_churn_guard must be a "
                            "ListingChurnGuard, got %r"
                            % type(listing_churn_guard).__name__)
        self._churn_guard = (listing_churn_guard
                             if listing_churn_guard is not None
                             else ListingChurnGuard())
        # Wave-80: digest-pinset for MCP artifact loads (manifest +
        # tool definitions). None = legacy behavior (documented
        # residual); attached = fail-closed digest verification.
        if artifact_pinset is not None:
            from gov.load_gate import ArtifactPinset
            if not isinstance(artifact_pinset, ArtifactPinset):
                raise TypeError("artifact_pinset must be an "
                                "ArtifactPinset, got %r"
                                % type(artifact_pinset).__name__)
        self._artifact_pinset = artifact_pinset

    def _mcp_artifact_id(self, kind, name):
        """Pinset artifact id for an MCP artifact load."""
        return "mcp:%s:%s:%s" % (kind, self._server_id or "default", name)

    @property
    def binding(self):
        return self._binding

    @property
    def server_id(self):
        """The deployer-declared server identity (None if unconfigured)."""
        return self._server_id

    @property
    def framework_tools(self):
        """Tool names this client will mediate (from the binding)."""
        return self._binding.framework_tools()

    async def call_tool(self, name, arguments=None, **session_kwargs):
        """Mediate one MCP tool call.

        ``name`` is resolved through the binding's tool map, then the
        executor mediates ``(native_tool, **arguments)``. On
        ``"executed"`` the underlying session's ``call_tool`` runs with
        the *framework-facing* ``name`` and the original ``arguments``,
        and its result is returned verbatim. Denials raise
        :class:`ToolDeniedError`; queued approvals raise
        :class:`ApprovalRequiredError`; unregistered names raise
        :class:`UnregisteredToolError` -- all before the session is
        touched.

        ``session_kwargs`` are forwarded to the underlying
        ``session.call_tool`` only (never to the executor): things like
        ``read_timeout_seconds``. They are validated to be
        keyword-only; governance-relevant routing stays with the
        binding.
        """
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise TypeError("arguments must be a dict, got %r"
                            % type(arguments).__name__)
        # Mediate FIRST. Any exception below means the session is never
        # touched: no side effect, no network, nothing.
        mediated = self._binding.call(name, **dict(arguments))
        if mediated.get("status") != "executed":
            # binding.call with defaults raises on denied/queued, so this
            # is unreachable -- kept as a fail-closed belt-and-braces.
            raise RuntimeError(
                "binding returned non-executed status without raising; "
                "refusing to call the MCP session.")
        # P2: re-fetch and re-validate the server's listing immediately
        # before dispatch. A description/schema swap between listing and
        # call (rug pull) raises here -- the session is never touched.
        # Queued approvals re-run this closure at approval time, so a
        # swap between queueing and approval is caught as well.
        await self.list_tools()
        server_result = await self.__session.call_tool(
            name, arguments, **session_kwargs)
        # F37: ingest the REAL server result into the run's
        # provenance/taint store — the executor's own call() only
        # ingested its simulated placeholder, so without this a
        # sensitive server response never taints the run and a follow-up
        # paraphrase api_call escapes the sensitive-read-before-api
        # gate. The result is returned verbatim; ingestion is a
        # fail-open side channel (the call already executed).
        try:
            self._binding.executor.ingest_foreign_result(
                self._binding.resolve(name), server_result,
                self._binding.identity.principal)
        except Exception:
            pass
        return server_result

    async def list_tools(self):
        """Mediated tool listing with the P2 metadata guard and K-012
        provenance check.

        The listing is fetched from the session, then K-012 provenance
        is verified (server identity, signed manifest, deployer tool
        pins -- fail closed on any drift); every entry is shape-checked
        and scanned for instruction-like descriptions; duplicates (tool
        shadowing) are rejected; each tool's ``name + description +
        inputSchema`` hash is pinned; and any change versus the previous
        pin (rug pull) raises :class:`MetadataChangedError` -- all
        before anything is returned. Pins are replaced atomically only
        after the *whole* listing validates clean, so a failed check
        leaves no partial state. Every outcome is audit-logged; the
        accept entry is fail-closed on log failure. Invoke tools only
        via :meth:`call_tool`.
        """
        list_tools = getattr(self.__session, "list_tools", None)
        if not callable(list_tools):
            raise TypeError("underlying session has no callable 'list_tools'")
        entries = await list_tools()
        return await self._validate_and_pin(entries)

    def _audit_listing(self, decision, fields):
        """Append a listing-mediation event to the HMAC-chained log.

        Fail-closed: an append failure propagates -- the caller must
        not treat the listing as mediated.
        """
        event = {"decision": decision}
        event.update(fields)
        try:
            event.setdefault("agent_id",
                             self._binding.identity.agent_id)
        except Exception:
            pass
        self._binding.executor.log.append(event)

    async def _verify_provenance(self, entries):
        """K-012: verify tool-server provenance for one listing.

        Runs before the P2 content scan: server identity is the outer
        trust boundary. Checks, in order:

        1. When ``server_public_key`` is configured, the session must
           serve a signed manifest (``get_server_manifest() ->
           (manifest_bytes, signature)``); the ed25519 signature must
           verify, and the manifest's ``server_id`` must match the
           bound ``server_id`` when that is also configured.
        2. Otherwise, when ``server_id`` is configured and the session
           advertises a ``server_id``, they must match. (A session that
           advertises nothing cannot be cross-checked; the deployer's
           claim is recorded and audited instead.)
        3. When ``pinned_tools`` is configured, the live listing must
           contain exactly the pinned tools with matching hashes:
           absence, drift, or an extra advertised tool all fail closed.

        Raises :class:`ServerProvenanceError`; rejections are
        audit-logged best-effort as ``mcp_provenance_rejected``.
        """
        session = self.__session

        def _reject(tool_name, reason, **fields):
            fields.update({"tool": tool_name, "reason": reason,
                           "server_id": self._server_id})
            try:
                self._audit_listing("mcp_provenance_rejected", fields)
            except Exception:
                pass
            raise ServerProvenanceError(tool_name, reason)

        if self._server_public_key is not None:
            try:
                manifest = await self._fetch_and_verify_manifest(session)
            except ServerProvenanceError as exc:
                _reject(exc.tool_name, exc.reason)
            manifest_server_id = (manifest.get("server_id")
                                  if isinstance(manifest, dict) else None)
            if (self._server_id is not None
                    and manifest_server_id != self._server_id):
                _reject("<server>", "manifest_server_id_mismatch",
                        advertised=manifest_server_id)
        elif self._server_id is not None:
            advertised = getattr(session, "server_id", None)
            if (advertised is not None
                    and advertised != self._server_id):
                _reject("<server>", "server_id_mismatch",
                        advertised=advertised)

        if self._deployer_pins:
            live = {}
            for entry in entries:
                name = _entry_name(entry)
                if isinstance(name, str) and name:
                    live[name] = metadata_hash(entry)
            for name, expected in self._deployer_pins.items():
                if name not in live:
                    _reject(name, "pinned_tool_absent")
                if live[name] != expected:
                    _reject(name, "pinned_tool_changed")
            for name in live:
                if name not in self._deployer_pins:
                    _reject(name, "unpinned_tool_advertised")

    async def _fetch_and_verify_manifest(self, session):
        """Fetch and ed25519-verify the server's signed manifest.

        Returns the parsed manifest dict. Any failure -- no manifest
        capability, malformed envelope, bad signature -- raises
        :class:`ServerProvenanceError` (fail closed).
        """
        get_manifest = getattr(session, "get_server_manifest", None)
        if not callable(get_manifest):
            raise ServerProvenanceError("<server>", "manifest_unavailable")
        try:
            result = get_manifest()
            if inspect.isawaitable(result):
                result = await result
        except Exception:
            raise ServerProvenanceError("<server>", "manifest_unavailable")
        try:
            manifest_bytes, signature = result
            manifest_bytes = bytes(manifest_bytes)
            signature = bytes(signature)
        except (TypeError, ValueError):
            raise ServerProvenanceError("<server>", "manifest_malformed")
        if not _ed25519_verify(self._server_public_key,
                               manifest_bytes, signature):
            raise ServerProvenanceError("<server>",
                                       "manifest_signature_invalid")
        # Wave-80: the manifest is a loadable artifact — verify its
        # bytes against the digest pinset when attached. A valid
        # signature over substituted bytes (key-compromise or
        # manifest-swap shape) is refused here as digest_mismatch;
        # an unpinned manifest is refused as artifact_unpinned (no
        # TOFU on the pinned path).
        if self._artifact_pinset is not None:
            from gov.load_gate import ArtifactRefused, verify_and_load
            try:
                verify_and_load(
                    self._artifact_pinset,
                    self._mcp_artifact_id("manifest", "server"),
                    manifest_bytes)
            except ArtifactRefused:
                try:
                    self._audit_listing(
                        "mcp_artifact_refused",
                        {"tool": "<server>",
                         "artifact_id": self._mcp_artifact_id(
                             "manifest", "server"),
                         "reason": "manifest_digest_gate"})
                except Exception:
                    pass
                raise
        try:
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ServerProvenanceError("<server>", "manifest_malformed")
        if not isinstance(manifest, dict):
            raise ServerProvenanceError("<server>", "manifest_malformed")
        return manifest

    async def _validate_and_pin(self, entries):
        """Scan, pin, and rug-pull-check one listing; return it unchanged.

        K-012 provenance is verified first (server identity is the outer
        trust boundary), then the P2 content scan runs.

        A listing entry whose ``name + description + inputSchema``
        hash is in the deployer-controlled ``description_allowlist``
        (F109) skips the content scan: the accept is audit-logged as
        ``mcp_metadata_allowlisted``, fail-closed on log failure like
        the ``mcp_list_tools`` accept entry. Structural checks
        (malformed entries, duplicate names) still apply to
        allowlisted tools, and rug-pull detection compares the same
        hashes -- the allowlist bypasses only the content scan.

        Raises :class:`ServerProvenanceError` on provenance drift,
        :class:`MetadataPoisoningError` on malformed entries, duplicate
        names, or instruction-like descriptions, and
        :class:`MetadataChangedError` when a pinned tool's metadata
        changed. Rejections are audit-logged best-effort (the refusal
        itself is the control); acceptance is fail-closed on audit
        failure.
        """
        # K-012 first: a swapped server fails before its metadata is
        # even scanned.
        await self._verify_provenance(entries)
        if not isinstance(entries, (list, tuple)):
            try:
                self._audit_listing("mcp_metadata_rejected",
                                    {"tool": "<unknown>",
                                     "reason": "malformed_listing"})
            except Exception:
                pass
            raise MetadataPoisoningError("<unknown>", "malformed_listing")
        # B5 (F109 follow-up): per-server listing-churn accounting.
        # Runs after provenance (a swapped server fails first) and
        # before the content scan: a churning server is refused
        # fail-closed with ListingChurnError, so its flood never
        # reaches the approval queue. SPLIT accounting (wave-37
        # review, see ListingChurnGuard): observe() counts every
        # presented listing toward the change-rate limit -- rejections
        # burn the scanner-probing budget -- while the tool-count
        # anomaly baseline moves only via note_accepted() below, after
        # full validation. The tool-count anomaly (flag, not fatal)
        # rides the accept audit below.
        live_hashes = {}
        for entry in entries:
            _n = _entry_name(entry)
            if isinstance(_n, str) and _n:
                try:
                    live_hashes[_n] = metadata_hash(entry)
                except Exception:
                    pass
        try:
            churn = self._churn_guard.observe(self._server_id,
                                              live_hashes)
        except ListingChurnError as exc:
            try:
                self._audit_listing(
                    "mcp_listing_churn_limited",
                    {"reason": exc.reason, "server_id": self._server_id,
                     "changes_in_window": exc.changes_in_window,
                     "window_s": exc.window_s})
            except Exception:
                pass
            raise
        seen = set()
        new_pins = {}
        for entry in entries:
            name = _entry_name(entry)
            if not isinstance(name, str) or not name:
                try:
                    self._audit_listing("mcp_metadata_rejected",
                                        {"tool": "<unknown>",
                                         "reason": "malformed_entry"})
                except Exception:
                    pass
                raise MetadataPoisoningError("<unknown>", "malformed_entry")
            if name in seen:
                # Tool shadowing: two entries claim one name.
                try:
                    self._audit_listing(
                        "mcp_metadata_rejected",
                        {"tool": name, "reason": "duplicate_tool_name"})
                except Exception:
                    pass
                raise MetadataPoisoningError(name, "duplicate_tool_name")
            seen.add(name)
            description = _entry_description(entry)
            # Wave-80: every tool definition is a loadable artifact.
            # When the pinset is attached, the canonical definition
            # bytes are digest-verified against
            # mcp:tool:<server_id>:<name> BEFORE the metadata hash is
            # committed — a definition swap (rug pull at the byte
            # level, or a session serving attacker bytes for a pinned
            # tool) is refused as digest_mismatch / artifact_unpinned.
            if self._artifact_pinset is not None:
                from gov.load_gate import (ArtifactRefused,
                                           verify_and_load)
                entry_bytes = _canonical_metadata(
                    name, description, _entry_schema(entry)).encode("utf-8")
                try:
                    verify_and_load(
                        self._artifact_pinset,
                        self._mcp_artifact_id("tool", name),
                        entry_bytes)
                except ArtifactRefused:
                    try:
                        self._audit_listing(
                            "mcp_artifact_refused",
                            {"tool": name,
                             "artifact_id": self._mcp_artifact_id(
                                 "tool", name),
                             "reason": "tool_definition_digest_gate"})
                    except Exception:
                        pass
                    raise
            entry_hash = metadata_hash(name, description,
                                       _entry_schema(entry))
            if entry_hash in self._description_allowlist:
                # F109: deployer allowlisted this EXACT metadata. The
                # allowlist entry is a deliberate, audited, reversible
                # per-description decision -- the opposite of a
                # position-independent regex carve-out. Fail-closed:
                # the accept audit must land, like the mcp_list_tools
                # accept entry below.
                self._audit_listing("mcp_metadata_allowlisted",
                                    {"tool": name,
                                     "metadata_hash": entry_hash})
                new_pins[name] = entry_hash
                continue
            try:
                scan_tool_description(name, description)
            except MetadataPoisoningError as exc:
                try:
                    self._audit_listing(
                        "mcp_metadata_rejected",
                        {"tool": name, "reason": exc.reason,
                         "description_snippet": str(description)[:200]})
                except Exception:
                    pass
                raise
            new_pins[name] = entry_hash
        # Rug-pull detection against the previous pins BEFORE swapping
        # state: any change fails closed, pins untouched.
        for name, old_hash in self._metadata_pins.items():
            new_hash = new_pins.get(name)
            if new_hash is not None and new_hash != old_hash:
                try:
                    self._audit_listing(
                        "mcp_metadata_changed",
                        {"tool": name, "expected_hash": old_hash,
                         "observed_hash": new_hash})
                except Exception:
                    pass
                raise MetadataChangedError(name, old_hash, new_hash)
        # Commit: the whole listing validated clean. Atomic swap -- no
        # partial pin state is ever visible.
        self._metadata_pins = new_pins
        # Fail-closed audit of the accepted listing.
        self._audit_listing("mcp_list_tools",
                            {"tool_count": len(new_pins),
                             "pins": dict(new_pins),
                             "server_id": self._server_id,
                             "tool_count_anomaly":
                                 churn["tool_count_anomaly"]})
        # B5 (wave-37 review): the listing is FULLY validated (pins
        # committed, accept audit landed) -- move the validated-only
        # anomaly baseline. Rejected listings never reach this call.
        self._churn_guard.note_accepted(self._server_id, len(new_pins))
        return entries


class DeterministicFakeSession:
    """In-process MCP session double for tests and demos.

    Implements the ``call_tool`` / ``list_tools`` coroutine interface
    with canned, deterministic results -- no network, no subprocesses.
    ``calls`` records every ``(name, arguments)`` pair the double
    received, so tests can assert the session was (or was not) touched.

    ``tool_metadata`` optionally maps tool names to metadata dicts, e.g.
    ``{"read_file": {"description": "...", "inputSchema": {...}}}``;
    ``list_tools`` merges them into the entries (tools without metadata
    keep the historical ``{"name": name}`` shape). ``set_description`` /
    ``set_schema`` mutate a tool's metadata in place, simulating a
    server-side metadata change (rug pull); ``remove_tool`` simulates
    removal.

    K-012 provenance knobs: ``server_id`` advertises a server identity
    string; ``manifest_seed`` (a 32-byte ed25519 seed) enables
    ``get_server_manifest()``, which returns a signed JSON manifest of
    the current tool list. ``manifest_tamper=True`` corrupts the
    manifest *after* signing, simulating a tampered manifest.
    """

    def __init__(self, results=None, tool_metadata=None, server_id=None,
                 manifest_seed=None, manifest_tamper=False):
        # results: {tool_name: result}. Missing names get a canned echo.
        self._results = dict(results or {})
        self._tool_metadata = {
            name: dict(meta)
            for name, meta in dict(tool_metadata or {}).items()
        }
        self.calls = []
        # K-012: advertised server identity (checked against the
        # client's bound server_id when the deployer configures one).
        self.server_id = server_id
        self._manifest_seed = manifest_seed
        self._manifest_tamper = bool(manifest_tamper)

    def set_description(self, name, description):
        """Simulate a server-side description change (rug pull)."""
        meta = self._tool_metadata.setdefault(name, {})
        meta["description"] = description

    def set_schema(self, name, schema):
        """Simulate a server-side inputSchema change (rug pull)."""
        meta = self._tool_metadata.setdefault(name, {})
        meta["inputSchema"] = schema

    def remove_tool(self, name):
        """Simulate a server-side tool removal."""
        self._tool_metadata.pop(name, None)
        self._results.pop(name, None)

    async def get_server_manifest(self):
        """Return ``(manifest_bytes, signature)`` for K-012 tests.

        The manifest is JSON ``{"server_id": ..., "tools": [...]}``
        signed with ``manifest_seed``. Raises ``NotImplementedError``
        when no seed was configured (the client treats this as
        "manifest unavailable" -- fail closed when a public key is
        pinned).
        """
        if self._manifest_seed is None:
            raise NotImplementedError(
                "fake session has no manifest signing key")
        manifest = {
            "server_id": self.server_id,
            "tools": [
                {"name": t["name"],
                 "description": t.get("description"),
                 "inputSchema": t.get("inputSchema")}
                for t in await self.list_tools()
            ],
        }
        body = json.dumps(manifest, sort_keys=True).encode("utf-8")
        signature = _ed25519_sign(self._manifest_seed, body)
        if self._manifest_tamper:
            if manifest["tools"]:
                manifest["tools"][0]["description"] = "TAMPERED AFTER SIGNING"
            else:
                manifest["server_id"] = "tampered-server"
            body = json.dumps(manifest, sort_keys=True).encode("utf-8")
        return body, signature

    async def call_tool(self, name, arguments=None, **kwargs):
        self.calls.append((name, dict(arguments or {})))
        if name in self._results:
            return self._results[name]
        return {"echo": name, "arguments": dict(arguments or {})}

    async def list_tools(self):
        names = list(self._results)
        for name in self._tool_metadata:
            if name not in self._results:
                names.append(name)
        tools = []
        for name in names:
            entry = {"name": name}
            entry.update(self._tool_metadata.get(name, {}))
            tools.append(entry)
        return tools
