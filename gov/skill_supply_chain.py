"""Continuous skill/MCP bundle supply-chain verification (wave-267 feature lane).

The TUF half and the in-toto half, as a pair (the wave-266 prospectus's
top-6 build #4: "TUF + in-toto pair"; license posture: TUF spec is CSL
1.0 which expressly permits implementations without attribution, in-toto
spec is Apache-2.0/MIT -- pattern-adapted here, nothing vendored,
stdlib-only, $0 spend).

This is the EVENT-DRIVEN lifecycle half of skill-bundle verification:
re-verify a bundle's custody chain on EVERY lifecycle transition
(publish -> fetch -> install -> update), not just at publish time.

Composition (never duplication):

* ``gov.bundle_refresh`` (wave-206): the PULL-based repository metadata
  refresh (root chaining, per-role byte caps, write-through cache).
  This module consumes a trusted chain state and verifies per-event
  transitions; it does not reimplement the refresh loop.
* ``gov.skill_admission`` (W248-2): the BUILD-time in-toto layout /
  step / link gate ("the skill that was authorized is the skill that
  was built"). This module's lifecycle layouts verify the INSTALLED
  bundle's transitions (fetch -> install -> update), not the build
  steps.
* ``gov.skill_update``: install-time record checks (pin, digest,
  version). This module adds delegation authority and link-chain
  custody around those checks.
* ``gov.artifact_rules``: the general six-rule firewall engine. This
  module COMPOSES it for per-transition (materials, products) checks
  and never reimplements a rule.

TUF half -- delegation-aware targets authority
---------------------------------------------

``verify_delegated_authority`` answers: "is this skill bundle version
authorized by a delegation that covers its path, under the deployment's
root trust, at the pinned evaluation time?" The pieces, adapted from
the TUF spec's delegation semantics:

* The delegation document is sealed under the ROOT role's threshold
  (opaque declared key IDs, distinct-key counting -- the same
  discipline as ``gov.bundle_refresh``).
* Delegations are searched IN ORDER; each carries ``paths`` scoping
  (fnmatch) and ``terminating``. The FIRST path-matching delegation
  is authoritative for its namespace: its threshold verdict is final
  and the search never falls through to a later, broader delegation
  (the terminating behavior, applied uniformly -- a weak outer
  delegation cannot launder a failed inner one). ``terminating`` is
  validated and recorded; it governs multi-level delegation when
  supported. Revocation is by absence: a delegation
  name present in the caller's trusted state but missing from the new
  document refuses loudly, never silently.
* Expiry is evaluated against ONE pinned ``eval_start`` for the whole
  pass (TUF section "fix time": ``expires <= eval_start`` is frozen).
  There is no per-check ``now()`` -- that is the anti-TOCTOU steal.
* Version monotonicity against caller-kept trusted state: a delegation
  document older than trusted refuses as rollback.

in-toto half -- lifecycle layouts and chained link records
----------------------------------------------------------

``verify_lifecycle`` answers: "did this bundle's bytes travel an
unbroken, authorized, rule-checked custody chain across its lifecycle?"
A signed layout declares the ordered transitions; each transition
declares its authorized signers and its artifact rules. Each lifecycle
event produces a link-like record ``{transition, materials, products,
byproducts, prev_digest}`` where ``prev_digest`` is the sha256 of the
previous link's canonical bytes (genesis: 64 zeros). Verification, in
fixed order:

1. layout shape -> layout authority signature threshold
2. layout expiry at the pinned ``eval_start``
3. per transition, in layout order: link presence -> link signer
   authorization + threshold -> prev-link chain -> artifact rules over
   (materials, products) via ``gov.artifact_rules`` (the terminal
   ``DISALLOW *`` is mandatory there, so leftovers always refuse)

``MATCH`` rules with caller-pinned digests hash-bind each transition's
materials to the previous transition's products -- that is the
cross-transition custody check the F193 vacuous-proof class needs.

Every refusal is machine-coded (domain ``supplychain``). Every verdict
report carries honest coverage: ``checked[]`` (what ran) and
``out_of_scope[]`` (what this module explicitly does not prove).

Honest boundaries (stated, not absorbed):

* Transport trust: fetching wires is deployment-owned; this module
  verifies what it is handed.
* Clock trust: ``eval_start`` is caller-supplied. Expiry/freeze checks
  are only as good as it -- a lying clock defeats freeze protection
  exactly as it defeats TUF.
* Key custody: ``root_trust`` / ``keys`` are deployment-supplied;
  rotation ceremony design is out of scope (see module docstring of
  ``gov.bundle_refresh`` for the refresh-side story).
* Link self-reporting: a single lying signer is caught only by
  CROSS-transition inconsistency (MATCH digest mismatch) or by
  thresholds >= 2 with independent observers. One signature proves one
  keyholder signed a claim, not that the claim is true.
* Content policy: artifact rules check presence/identity/accounting,
  never whether an artifact's contents are good -- that stays in the
  policy layer.
* Initial root bootstrap is out-of-band (TUF's own assumption).
"""

import base64
import binascii
import fnmatch
import hashlib
import json
import math
from datetime import datetime, timezone

from .artifact_rules import ArtifactRuleError, load_rules, verify_artifacts
from .bundle_refresh import tuf_canonical_json
from .dsse_envelope import pae
from .signing import Ed25519Verifier

__all__ = [
    "CODES",
    "SupplyChainError",
    "seal_document",
    "verify_delegated_authority",
    "verify_lifecycle",
    "to_evidence",
]

# ---------------------------------------------------------------------------
# Machine codes (domain ``supplychain``; also registered in
# gov/decision_codes.py, alphabetical there)
# ---------------------------------------------------------------------------

CODES = (
    "supplychain-delegation-path-unauthorized",
    "supplychain-delegation-revoked",
    "supplychain-delegation-signature-invalid",
    "supplychain-eval-start-invalid",
    "supplychain-frozen",
    "supplychain-layout-expired",
    "supplychain-layout-signature-invalid",
    "supplychain-link-chain-broken",
    "supplychain-link-unauthorized",
    "supplychain-malformed",
    "supplychain-rollback",
    "supplychain-snapshot-mismatch",
    "supplychain-transition-rules-failed",
)

_PAYLOAD_TYPES = {
    "delegations": "application/vnd.sasanam.supplychain-delegations+json",
    "layout": "application/vnd.sasanam.supplychain-layout+json",
    "link": "application/vnd.sasanam.supplychain-link+json",
}

_GENESIS_DIGEST = "0" * 64

_HEX64 = set("0123456789abcdef")


class SupplyChainError(ValueError):
    """Loud, machine-coded refusal. ``code`` is always one of CODES."""

    def __init__(self, code, detail=""):
        if code not in CODES:
            raise ValueError("unknown supplychain code %r" % (code,))
        super(SupplyChainError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Shape checking helpers (fail-closed, loud)
# ---------------------------------------------------------------------------

def _fail(code, detail):
    raise SupplyChainError(code, detail)


def _check_hex64(value, where):
    if not isinstance(value, str) or len(value) != 64 \
            or any(c not in _HEX64 for c in value):
        _fail("supplychain-malformed",
              "%s: expected 64 lowercase hex chars, got %r" % (where, value))
    return value


def _check_nonneg_int(value, where):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail("supplychain-malformed",
              "%s: expected non-negative int, got %r" % (where, value))
    return value


def _check_version(value, where):
    _check_nonneg_int(value, where)
    if value < 1:
        _fail("supplychain-malformed",
              "%s: version must be >= 1, got %r" % (where, value))
    return value


def _parse_expiry(value, where):
    """Strict ISO-8601 UTC ``...Z`` expiry -> epoch float. Malformed
    expiry is an authoring error, refused loudly (never treated as
    "no expiry")."""
    if not isinstance(value, str):
        _fail("supplychain-malformed",
              "%s: expires must be a str, got %s"
              % (where, type(value).__name__))
    text = value.strip()
    if not text.endswith("Z"):
        _fail("supplychain-malformed",
              "%s: expires must be UTC '...Z', got %r" % (where, value))
    try:
        dt = datetime.strptime(text[:-1], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        _fail("supplychain-malformed",
              "%s: bad expires timestamp %r" % (where, value))
    return dt.replace(tzinfo=timezone.utc).timestamp()


def _check_eval_start(eval_start):
    """The pinned evaluation start: one time for the whole pass. Must
    be a non-negative epoch number -- a missing or non-numeric start
    would make every expiry check meaningless."""
    if isinstance(eval_start, bool) \
            or not isinstance(eval_start, (int, float)) \
            or eval_start != eval_start \
            or not math.isfinite(eval_start) \
            or eval_start < 0:
        _fail("supplychain-eval-start-invalid",
              "eval_start must be a non-negative epoch number, got %r"
              % (eval_start,))
    return float(eval_start)


def _check_key_entry(kid, entry, where):
    if not isinstance(entry, dict):
        _fail("supplychain-malformed",
              "%s: key entry for %r must be a dict" % (where, kid))
    if entry.get("keytype") != "ed25519":
        _fail("supplychain-malformed",
              "%s: key %r: only ed25519 keys supported" % (where, kid))
    public = (entry.get("keyval") or {}).get("public")
    if not isinstance(public, str):
        _fail("supplychain-malformed",
              "%s: key %r: keyval.public must be a hex str" % (where, kid))
    try:
        raw = bytes.fromhex(public)
    except (TypeError, ValueError):
        _fail("supplychain-malformed",
              "%s: key %r: keyval.public is not hex" % (where, kid))
    if len(raw) != 32:
        _fail("supplychain-malformed",
              "%s: key %r: public key must be 32 bytes" % (where, kid))
    return raw


def _check_role_info(info, where):
    if not isinstance(info, dict):
        _fail("supplychain-malformed", "%s: role info must be a dict"
              % where)
    keyids = info.get("keyids")
    threshold = info.get("threshold")
    if not isinstance(keyids, list) or not keyids \
            or any(not isinstance(k, str) or not k for k in keyids):
        _fail("supplychain-malformed",
              "%s: keyids must be a non-empty list of str" % where)
    _check_nonneg_int(threshold, where + ".threshold")
    if threshold < 1 or threshold > len(keyids):
        _fail("supplychain-malformed",
              "%s: threshold must be in [1, len(keyids)]" % where)
    if len(set(keyids)) != len(keyids):
        _fail("supplychain-malformed",
              "%s: duplicate keyids" % where)
    return {"keyids": list(keyids), "threshold": threshold}

# ---------------------------------------------------------------------------
# Sealed envelopes (same discipline as gov.bundle_refresh: DSSE PAE over
# canonical JSON, opaque declared key IDs, distinct-key threshold
# counting -- re-expressed here because bundle_refresh.seal_role is
# pinned to its four repository roles)
# ---------------------------------------------------------------------------

def seal_document(kind, doc, signers):
    """Seal ``doc`` as a signed ``kind`` envelope; returns wire bytes.

    ``kind`` is one of "delegations", "layout", "link". ``signers`` is
    an iterable of ``(declared_key_id, signer)`` tuples. The declared
    (opaque, producer-chosen) key ID goes in the envelope; it is never
    re-derived from the key.
    """
    if kind not in _PAYLOAD_TYPES:
        raise ValueError("unknown document kind %r" % (kind,))
    if not isinstance(doc, dict):
        raise ValueError("doc must be a dict")
    payload = tuf_canonical_json(doc)
    pae_bytes = pae(_PAYLOAD_TYPES[kind], payload)
    sigs = []
    for keyid, signer in signers:
        if not isinstance(keyid, str) or not keyid:
            raise ValueError("declared keyid must be a non-empty str")
        sigs.append({"keyid": keyid,
                     "sig": bytes(signer.sign(pae_bytes)).hex()})
    if not sigs:
        raise ValueError("seal_document requires at least one signer")
    envelope = {
        "payload": base64.b64encode(payload).decode("ascii"),
        "payloadType": _PAYLOAD_TYPES[kind],
        "signatures": sigs,
    }
    return tuf_canonical_json(envelope)


def _parse_envelope(kind, wire, where, code):
    if not isinstance(wire, (bytes, bytearray)):
        _fail("supplychain-malformed",
              "%s: wire must be bytes, got %s"
              % (where, type(wire).__name__))
    try:
        envelope = json.loads(bytes(wire).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        _fail("supplychain-malformed",
              "%s: envelope is not valid JSON: %s" % (where, exc))
    if not isinstance(envelope, dict):
        _fail("supplychain-malformed", "%s: envelope must be a dict"
              % where)
    if envelope.get("payloadType") != _PAYLOAD_TYPES[kind]:
        _fail(code, "%s: wrong payloadType %r (expected %r)"
              % (where, envelope.get("payloadType"),
                 _PAYLOAD_TYPES[kind]))
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        _fail("supplychain-malformed",
              "%s: bad base64 payload: %s" % (where, exc))
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        _fail("supplychain-malformed",
              "%s: payload is not valid JSON: %s" % (where, exc))
    if not isinstance(doc, dict):
        _fail("supplychain-malformed", "%s: payload must be a dict"
              % where)
    sigs = envelope.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        _fail(code, "%s: envelope carries no signatures" % where)
    return doc, payload, sigs


def _threshold_verify(kind, doc, payload, sigs, keys, role_info, where,
                      code):
    """True when distinct declared key IDs listed in the role meet the
    threshold with verifying signatures. Unknown key IDs never
    attribute, even when the underlying key would verify; no ID is ever
    re-derived."""
    pae_bytes = pae(_PAYLOAD_TYPES[kind], payload)
    seen = set()
    for entry in sigs:
        if not isinstance(entry, dict):
            continue
        kid = entry.get("keyid")
        if not isinstance(kid, str) or kid in seen:
            continue
        if kid not in role_info["keyids"]:
            continue
        keyinfo = keys.get(kid)
        if not isinstance(keyinfo, dict):
            continue
        try:
            public = _check_key_entry(kid, keyinfo, where)
            sig = bytes.fromhex(entry.get("sig", ""))
        except (SupplyChainError, TypeError, ValueError):
            continue
        if len(sig) != 64:
            continue
        # Ed25519Verifier.verify returns exact True/False and never
        # raises (wave-243 contract, pinned by unit test): no
        # try/except here -- a raising verifier would be a bug we want
        # loud, not a key silently uncounted.
        if Ed25519Verifier(public, key_id=kid).verify(pae_bytes, sig):
            seen.add(kid)
    if len(seen) < role_info["threshold"]:
        _fail(code, "%s: threshold not met: %d of %d distinct key(s) "
                    "verified" % (where, len(seen), role_info["threshold"]))
    return sorted(seen)


def _check_frozen(expires_epoch, eval_start, where):
    """Expiry is exclusive and evaluated against the PINNED eval_start
    only -- never a per-check now(). ``expires <= eval_start`` is
    frozen (stale), refused fail-closed."""
    if expires_epoch <= eval_start:
        _fail("supplychain-frozen",
              "%s: metadata expired (expires=%s <= eval_start=%s)"
              % (where, expires_epoch, eval_start))

# ---------------------------------------------------------------------------
# TUF half: delegation-aware targets authority
# ---------------------------------------------------------------------------

def _check_root_trust(root_trust):
    if not isinstance(root_trust, dict):
        _fail("supplychain-malformed", "root_trust must be a dict")
    keys = root_trust.get("keys")
    if not isinstance(keys, dict) or not keys:
        _fail("supplychain-malformed", "root_trust.keys must be a "
                                       "non-empty dict")
    for kid, entry in keys.items():
        if not isinstance(kid, str) or not kid:
            _fail("supplychain-malformed",
                  "root_trust.keys: key id must be a non-empty str")
        _check_key_entry(kid, entry, "root_trust.keys")
    root = _check_role_info(root_trust.get("root"), "root_trust.root")
    for kid in root["keyids"]:
        if kid not in keys:
            _fail("supplychain-malformed",
                  "root_trust: root keyid %r has no key entry" % (kid,))
    return {"keys": keys, "root": root}


def _check_delegation_entry(entry, index):
    where = "delegations[%d]" % index
    if not isinstance(entry, dict):
        _fail("supplychain-malformed", "%s: must be a dict" % where)
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        _fail("supplychain-malformed", "%s: name must be a non-empty str"
              % where)
    role = _check_role_info({"keyids": entry.get("keyids"),
                             "threshold": entry.get("threshold")}, where)
    paths = entry.get("paths")
    if not isinstance(paths, list) or not paths \
            or any(not isinstance(p, str) or not p for p in paths):
        _fail("supplychain-malformed",
              "%s: paths must be a non-empty list of str" % where)
    terminating = entry.get("terminating", False)
    if not isinstance(terminating, bool):
        _fail("supplychain-malformed",
              "%s: terminating must be a bool" % where)
    return {"name": name, "keyids": role["keyids"],
            "threshold": role["threshold"], "paths": list(paths),
            "terminating": terminating}


def _check_authz_doc(doc):
    if not isinstance(doc.get("skill"), str) or not doc["skill"]:
        _fail("supplychain-malformed",
              "authorization: skill must be a non-empty str")
    _check_version(doc.get("version"), "authorization.version")
    _check_hex64(doc.get("digest"), "authorization.digest")
    _parse_expiry(doc.get("expires"), "authorization.expires")
    if set(doc) - {"skill", "version", "digest", "expires"}:
        _fail("supplychain-malformed",
              "authorization: unknown keys %r"
              % (sorted(set(doc) - {"skill", "version", "digest",
                                    "expires"}),))


def verify_delegated_authority(delegation_wire, authz_wire, skill_path,
                               root_trust, eval_start, trusted=None,
                               parent_pin=None):
    """Verify that ``skill_path`` at its claimed version/digest is
    authorized by a delegation covering its path.

    ``delegation_wire``: sealed delegation document
    ``{"version": int, "expires": "...Z", "delegations": [...]}``,
    sealed under the root role threshold.
    ``authz_wire``: sealed authorization statement
    ``{"skill": path, "version": int, "digest": hex, "expires": "...Z"}``,
    sealed under the covering delegation's threshold.
    ``root_trust``: ``{"keys": {kid: keyinfo}, "root": {keyids,
    threshold}}`` -- deployment-supplied, out-of-band bootstrap.
    ``eval_start``: pinned evaluation-start epoch; every expiry check
    in this pass uses it and nothing else.
    ``trusted`` (optional): caller-kept ``{"delegations_version": int,
    "delegations": {name: version}}`` for rollback/revocation checks.
    ``parent_pin`` (optional): expected sha256 hex of the delegation
    wire (snapshot binding); a mismatch is mix-and-match, refused.

    Check order (fixed): malformed -> eval-start -> binding ->
    delegation signature -> frozen -> rollback -> revocation ->
    path authorization (first path-match is authoritative).
    Returns a verdict report; raises SupplyChainError loudly.
    """
    checked = []
    if not isinstance(skill_path, str) or not skill_path:
        _fail("supplychain-malformed", "skill_path must be a non-empty str")
    eval_start = _check_eval_start(eval_start)
    checked.append("shape")
    trust = _check_root_trust(root_trust)
    checked.append("root-trust-shape")

    if not isinstance(delegation_wire, (bytes, bytearray)):
        _fail("supplychain-malformed",
              "delegation wire must be bytes, got %s"
              % type(delegation_wire).__name__)
    if parent_pin is not None:
        _check_hex64(parent_pin, "parent_pin")
        actual = hashlib.sha256(bytes(delegation_wire)).hexdigest()
        if actual != parent_pin:
            _fail("supplychain-snapshot-mismatch",
                  "delegation wire digest %s != pinned %s (mix-and-match)"
                  % (actual, parent_pin))
        checked.append("snapshot-binding")

    deleg_doc, deleg_payload, deleg_sigs = _parse_envelope(
        "delegations", delegation_wire, "delegations",
        "supplychain-delegation-signature-invalid")
    checked.append("envelope-shape")
    if set(deleg_doc) - {"version", "expires", "delegations"}:
        _fail("supplychain-malformed",
              "delegations: unknown keys %r"
              % (sorted(set(deleg_doc) - {"version", "expires",
                                          "delegations"}),))
    version = _check_version(deleg_doc.get("version"),
                             "delegations.version")
    expires = _parse_expiry(deleg_doc.get("expires"),
                            "delegations.expires")
    delegations_raw = deleg_doc.get("delegations")
    if not isinstance(delegations_raw, list) or not delegations_raw:
        _fail("supplychain-malformed",
              "delegations.delegations must be a non-empty list")
    delegations = [_check_delegation_entry(e, i)
                   for i, e in enumerate(delegations_raw)]
    names = [d["name"] for d in delegations]
    if len(set(names)) != len(names):
        _fail("supplychain-malformed", "delegations: duplicate names")
    for d in delegations:
        for kid in d["keyids"]:
            if kid not in trust["keys"]:
                _fail("supplychain-malformed",
                      "delegation %r: keyid %r has no key entry"
                      % (d["name"], kid))
    _threshold_verify("delegations", deleg_doc, deleg_payload, deleg_sigs,
                      trust["keys"], trust["root"], "delegations",
                      "supplychain-delegation-signature-invalid")
    checked.append("root-threshold(%d-of-%d)"
                   % (trust["root"]["threshold"],
                      len(trust["root"]["keyids"])))
    _check_frozen(expires, eval_start, "delegations")
    checked.append("expiry@eval_start")

    if trusted is not None:
        if not isinstance(trusted, dict):
            _fail("supplychain-malformed", "trusted must be a dict")
        tv = trusted.get("delegations_version")
        if tv is not None:
            _check_version(tv, "trusted.delegations_version")
            if version < tv:
                _fail("supplychain-rollback",
                      "delegations version %d < trusted %d"
                      % (version, tv))
            checked.append("rollback(version %d >= trusted %d)"
                           % (version, tv))
        known = trusted.get("delegations")
        if "delegations" in trusted and not isinstance(known, dict):
            _fail("supplychain-malformed",
                  "trusted.delegations must be a dict of name->version")
        if isinstance(known, dict):
            for name in known:
                if name not in names:
                    _fail("supplychain-delegation-revoked",
                          "delegation %r was trusted and is now absent "
                          "(revocation by absence is loud)" % (name,))
            checked.append("revocation-by-absence")

    authz_doc, authz_payload, authz_sigs = _parse_envelope(
        "link", authz_wire, "authorization",
        "supplychain-delegation-signature-invalid")
    # NOTE: the authorization statement reuses the "link" envelope
    # kind (a signed claim record); it is NOT a lifecycle link.
    _check_authz_doc(authz_doc)
    checked.append("authorization-shape")
    if authz_doc["skill"] != skill_path:
        _fail("supplychain-malformed",
              "authorization skill %r != requested %r"
              % (authz_doc["skill"], skill_path))
    _check_frozen(_parse_expiry(authz_doc["expires"],
                                "authorization.expires"),
                  eval_start, "authorization")
    checked.append("authorization-expiry@eval_start")

    covering = None
    for delegation in delegations:
        if not any(fnmatch.fnmatchcase(skill_path, pattern)
                   for pattern in delegation["paths"]):
            continue
        # The first path-matching delegation is AUTHORITATIVE for its
        # namespace (the terminating behavior, applied uniformly): its
        # threshold verdict is final. A failed threshold under the
        # covering delegation is a hard signature failure -- the
        # search never falls through to a later, broader delegation,
        # which would let a weak outer delegation launder a failed
        # inner one.
        role = {"keyids": delegation["keyids"],
                "threshold": delegation["threshold"]}
        _threshold_verify("link", authz_doc, authz_payload, authz_sigs,
                          trust["keys"], role,
                          "authorization[%s]" % delegation["name"],
                          "supplychain-delegation-signature-invalid")
        covering = delegation
        checked.append("delegation[%s]: path-scope + threshold(%d-of-%d)"
                       % (delegation["name"], role["threshold"],
                          len(role["keyids"])))
        break
    if covering is None:
        _fail("supplychain-delegation-path-unauthorized",
              "no delegation covers skill path %r" % (skill_path,))

    report = {
        "ok": True,
        "kind": "delegated-authority",
        "skill": skill_path,
        "version": authz_doc["version"],
        "digest": authz_doc["digest"],
        "delegation": covering["name"],
        "delegation_version": version,
        "eval_start": eval_start,
        "checked": checked,
        "out_of_scope": list(_OUT_OF_SCOPE),
    }
    report["evidence_digest"] = _report_digest(report)
    return report

# ---------------------------------------------------------------------------
# Shared honest-coverage footer + evidence digest
# ---------------------------------------------------------------------------

_OUT_OF_SCOPE = (
    "transport trust: fetching wires is deployment-owned; only handed "
    "bytes are verified",
    "clock trust: eval_start is caller-supplied; freeze/expiry checks "
    "are only as good as it",
    "key custody: root_trust/keys are deployment-supplied and "
    "out-of-band bootstrapped; rotation ceremony is out of scope",
    "link self-reporting: a single lying signer is caught only by "
    "cross-transition MATCH inconsistency; use thresholds >= 2 with "
    "independent observers for real assurance",
    "content policy: artifact rules check presence/identity/accounting, "
    "never whether an artifact's contents are good",
)


def _report_digest(report):
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def to_evidence(report):
    """The verdict as a canonical digest-linked record for attachment
    to evidence bundles / decision packets. The record digest binds the
    full report transitively through evidence_digest (which covers the
    canonical report bytes, including checked[] and out_of_scope[])."""
    if not isinstance(report, dict) or report.get("ok") is not True:
        _fail("supplychain-malformed",
              "to_evidence: report must be a successful verdict dict")
    evidence_digest = report.get("evidence_digest")
    if not isinstance(evidence_digest, str) or not evidence_digest:
        _fail("supplychain-malformed",
              "to_evidence: report carries no evidence_digest")
    record = {
        "kind": "supplychain-verdict",
        "subject": report.get("skill") or report.get("bundle"),
        "verdict": "authorized" if report.get("kind")
                   == "delegated-authority" else "chain-verified",
        "evidence_digest": evidence_digest,
    }
    record["record_digest"] = _report_digest(record)
    return record


# ---------------------------------------------------------------------------
# in-toto half: lifecycle layouts and chained link records
# ---------------------------------------------------------------------------

def _check_transition_spec(spec, index, keys):
    where = "transitions[%d]" % index
    if not isinstance(spec, dict):
        _fail("supplychain-malformed", "%s: must be a dict" % where)
    name = spec.get("name")
    if not isinstance(name, str) or not name:
        _fail("supplychain-malformed", "%s: name must be a non-empty str"
              % where)
    raw_signers = spec.get("signers")
    if not isinstance(raw_signers, dict):
        raw_signers = {}
    signers = _check_role_info({"keyids": raw_signers.get("keyids"),
                                "threshold": raw_signers.get("threshold")},
                               where + ".signers")
    for kid in signers["keyids"]:
        if kid not in keys:
            _fail("supplychain-malformed",
                  "%s: signer keyid %r has no key entry" % (where, kid))
    materials = spec.get("expected_materials")
    products = spec.get("expected_products")
    if not isinstance(materials, list) or not isinstance(products, list):
        _fail("supplychain-malformed",
              "%s: expected_materials/products must be lists" % where)
    # One queue, one terminal: the module concatenates the two lists
    # (materials rules first) and appends the single terminal DISALLOW
    # itself. A layout that smuggles its own DISALLOW is refused, so
    # the "no implicit ALLOW *" discipline stays explicit and exactly
    # once per transition.
    for side, rules in (("expected_materials", materials),
                        ("expected_products", products)):
        for rule in rules:
            if isinstance(rule, (tuple, list)) and rule \
                    and rule[0] == "DISALLOW":
                _fail("supplychain-malformed",
                      "%s: %s must not contain DISALLOW -- the module "
                      "appends the single terminal DISALLOW" % (where, side))
    try:
        combined_rules = load_rules(list(materials) + list(products)
                                    + [("DISALLOW",)])
    except ArtifactRuleError as exc:
        _fail("supplychain-malformed",
              "%s: bad rule set: %s" % (where, exc))
    if set(spec) - {"name", "signers", "expected_materials",
                    "expected_products"}:
        _fail("supplychain-malformed",
              "%s: unknown keys %r"
              % (where, sorted(set(spec) - {"name", "signers",
                                            "expected_materials",
                                            "expected_products"})))
    return {"name": name, "signers": signers, "rules": combined_rules,
            "declared_materials": len(materials),
            "declared_products": len(products)}


def _check_link_doc(doc, transition_name):
    for field in ("materials", "products"):
        value = doc.get(field)
        if not isinstance(value, dict):
            _fail("supplychain-malformed",
                  "link[%s]: %s must be a dict of name -> digest"
                  % (transition_name, field))
        for name, digest in value.items():
            if not isinstance(name, str) or not name:
                _fail("supplychain-malformed",
                      "link[%s]: %s: bad artifact name %r"
                      % (transition_name, field, name))
            _check_hex64(digest, "link[%s]: %s[%r]"
                         % (transition_name, field, name))
    byproducts = doc.get("byproducts", {})
    if not isinstance(byproducts, dict):
        _fail("supplychain-malformed",
              "link[%s]: byproducts must be a dict" % transition_name)
    _check_hex64(doc.get("prev_digest"),
                 "link[%s]: prev_digest" % transition_name)
    if doc.get("transition") != transition_name:
        _fail("supplychain-malformed",
              "link transition %r != expected %r"
              % (doc.get("transition"), transition_name))
    if set(doc) - {"transition", "materials", "products", "byproducts",
                   "prev_digest"}:
        _fail("supplychain-malformed",
              "link[%s]: unknown keys %r"
              % (transition_name, sorted(set(doc) - {"transition",
                                                     "materials",
                                                     "products",
                                                     "byproducts",
                                                     "prev_digest"})))


def verify_lifecycle(layout_wire, link_wires, keys, eval_start):
    """Verify a skill bundle's lifecycle custody chain.

    ``layout_wire``: sealed layout ``{"bundle": path, "version": int,
    "expires": "...Z", "authority": {"keyids": [...], "threshold": n},
    "transitions": [{"name": str, "signers": {"keyids": [...],
    "threshold": n}, "expected_materials": [rules...],
    "expected_products": [rules...]}]}``. Rule lists use the
    ``gov.artifact_rules`` grammar (lists, not tuples -- JSON-safe).
    The module concatenates a transition's two lists (materials rules
    first) over the transition's single (materials, products) queue
    and appends the ONE terminal DISALLOW itself; a layout that
    includes its own DISALLOW is refused as malformed, so the "no
    implicit ALLOW *" discipline is explicit and exactly-once.
    ``link_wires``: sealed link records in layout order, each
    ``{"transition": name, "materials": {name: digest}, "products":
    {name: digest}, "byproducts": {...}, "prev_digest": hex}`` sealed
    under the transition's signer threshold. The first link's
    ``prev_digest`` must be the genesis marker (64 zeros); every later
    link's must equal the sha256 of the previous link's canonical
    bytes.
    ``keys``: ``{kid: keyinfo}`` -- deployment-supplied.
    ``eval_start``: pinned evaluation-start epoch for the layout
    expiry check.

    Check order (fixed): malformed -> eval-start -> layout shape ->
    layout authority signature -> layout expiry -> per transition in
    layout order (link presence -> signer threshold -> prev-link chain
    -> artifact rules over the combined (materials, products) queue,
    materials rules first). Returns a verdict report;
    raises SupplyChainError loudly.
    """
    checked = []
    eval_start = _check_eval_start(eval_start)
    checked.append("shape")
    if not isinstance(keys, dict) or not keys:
        _fail("supplychain-malformed", "keys must be a non-empty dict")
    for kid, entry in keys.items():
        if not isinstance(kid, str) or not kid:
            _fail("supplychain-malformed",
                  "keys: key id must be a non-empty str")
        _check_key_entry(kid, entry, "keys")
    checked.append("keys-shape")
    if not isinstance(link_wires, (list, tuple)):
        _fail("supplychain-malformed", "link_wires must be a list")

    layout_doc, layout_payload, layout_sigs = _parse_envelope(
        "layout", layout_wire, "layout",
        "supplychain-layout-signature-invalid")
    checked.append("layout-envelope-shape")
    if not isinstance(layout_doc.get("bundle"), str) \
            or not layout_doc["bundle"]:
        _fail("supplychain-malformed", "layout: bundle must be a "
                                       "non-empty str")
    _check_version(layout_doc.get("version"), "layout.version")
    layout_expires = _parse_expiry(layout_doc.get("expires"),
                                   "layout.expires")
    authority = _check_role_info(layout_doc.get("authority"),
                                 "layout.authority")
    for kid in authority["keyids"]:
        if kid not in keys:
            _fail("supplychain-malformed",
                  "layout: authority keyid %r has no key entry" % (kid,))
    transitions_raw = layout_doc.get("transitions")
    if not isinstance(transitions_raw, list) or not transitions_raw:
        _fail("supplychain-malformed",
              "layout: transitions must be a non-empty list")
    transitions = [_check_transition_spec(t, i, keys)
                   for i, t in enumerate(transitions_raw)]
    tnames = [t["name"] for t in transitions]
    if len(set(tnames)) != len(tnames):
        _fail("supplychain-malformed", "layout: duplicate transition "
                                       "names")
    if set(layout_doc) - {"bundle", "version", "expires", "authority",
                          "transitions"}:
        _fail("supplychain-malformed",
              "layout: unknown keys %r"
              % (sorted(set(layout_doc) - {"bundle", "version",
                                           "expires", "authority",
                                           "transitions"}),))
    _threshold_verify("layout", layout_doc, layout_payload, layout_sigs,
                      keys, authority, "layout",
                      "supplychain-layout-signature-invalid")
    checked.append("layout-authority-threshold(%d-of-%d)"
                   % (authority["threshold"], len(authority["keyids"])))
    if layout_expires <= eval_start:
        _fail("supplychain-layout-expired",
              "layout expired (expires=%s <= eval_start=%s)"
              % (layout_expires, eval_start))
    checked.append("layout-expiry@eval_start")

    if len(link_wires) != len(transitions):
        _fail("supplychain-malformed",
              "expected %d link(s) in layout order, got %d"
              % (len(transitions), len(link_wires)))
    checked.append("link-count(%d)" % len(transitions))

    transition_reports = []
    prev_digest = _GENESIS_DIGEST
    for spec, wire in zip(transitions, link_wires):
        tname = spec["name"]
        doc, payload, sigs = _parse_envelope(
            "link", wire, "link[%s]" % tname,
            "supplychain-link-unauthorized")
        _check_link_doc(doc, tname)
        checked.append("link[%s]: shape" % tname)
        _threshold_verify("link", doc, payload, sigs, keys,
                          spec["signers"], "link[%s]" % tname,
                          "supplychain-link-unauthorized")
        checked.append("link[%s]: signer-threshold(%d-of-%d)"
                       % (tname, spec["signers"]["threshold"],
                          len(spec["signers"]["keyids"])))
        if doc["prev_digest"] != prev_digest:
            _fail("supplychain-link-chain-broken",
                  "link[%s]: prev_digest %s != expected %s"
                  % (tname, doc["prev_digest"], prev_digest))
        checked.append("link[%s]: prev-link-chain" % tname)
        try:
            audit = verify_artifacts(doc["materials"], doc["products"],
                                     spec["rules"],
                                     context="link[%s]" % tname)
        except ArtifactRuleError as exc:
            _fail("supplychain-transition-rules-failed",
                  "link[%s]: artifact rules: %s" % (tname, exc))
        checked.append("link[%s]: artifact-rules(%d, digest %s)"
                       % (tname, len(spec["rules"]),
                          audit["rule_set_digest"][:12]))
        link_digest = hashlib.sha256(payload).hexdigest()
        transition_reports.append({"transition": tname,
                                   "link_digest": link_digest})
        prev_digest = link_digest

    report = {
        "ok": True,
        "kind": "lifecycle",
        "bundle": layout_doc["bundle"],
        "layout_version": layout_doc["version"],
        "eval_start": eval_start,
        "transitions": transition_reports,
        "checked": checked,
        "out_of_scope": list(_OUT_OF_SCOPE),
    }
    report["evidence_digest"] = _report_digest(report)
    return report
