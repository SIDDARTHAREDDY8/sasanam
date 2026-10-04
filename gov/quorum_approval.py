"""m-of-n operation approval, Control-Groups shape (open reimplementation).

The problem (wave-319 threshold-custody prospectus, direction-brief item 2):
sensitive *governance operations* -- root-key ceremonies, evidence-anchor
signing, policy overrides -- need distributed *authority*, not just secret
*recovery*. Shamir secret sharing gives recovery: reconstructing a split key
on one device is a single point of failure. The closer pattern is Vault's
Control Groups: m-of-n human approvals *per operation*, the request paused
until quorum, fully audited. Vault's Control Groups are Enterprise-gated;
OpenBao's status is unverified. This module is the open reimplementation.

What this module provides:

* ``QuorumPolicy``: a named policy binding an operation class to m-of-n
  named approvers. Approvers are workload-identity-bound: each carries a
  ``spiffe://`` identity and a pinned Ed25519 public key (the deployment
  binds keys to verified workload-identity documents at registration time;
  see ``gov/workload_identity.py``).
* ``attest`` / ``deny``: signed, replay-resistant attestations over
  (operation_digest, policy_id, policy_version, nonce). ``deny`` is a
  signed dissent -- the D1-core one-deny veto discipline: a single
  eligible dissenter fails the quorum closed.
* ``QuorumCollector``: accumulates attestations for one operation. The
  operation becomes executable only when m *distinct named approvers*
  have valid attestations. Distinctness is by named approver slot, never
  by keyid -- two signatures from the same keyid (or the same name twice)
  count once (the wave-319 redteam's latent observation, pinned as a
  standing regression). Fewer than m fails closed with coded refusals.
* ``QuorumPolicy`` versioning + change log (the evidence-schema-2.0 CC8.1
  pattern): the operation digest binds the policy version; a policy change
  without a version bump refuses.
* ``QuorumGate``: opt-in enforcement for registered sensitive operations.
  Unregistered operations are advisory-absent -- the gate never gates what
  it does not own, so existing flows cannot break.

Layering (wave-317 HE-2): quorum approval authorizes the *operation*, but
downstream trust layers (provenance sink, policy engine) still apply.
Quorum approval is necessary, never sufficient -- approval alone is not
declassification.

Signature primitive: Ed25519 via the repo's own RFC 8032 implementation
(``gov.ed25519``). ``verify`` is bool-returning -- the return is always
checked with ``is True`` / ``is False`` (the wave-243 lesson).

HONEST RESIDUALS (never claimed away):

* The nonce store is per-``QuorumCollector`` instance, in memory.
  Deployments must persist it -- a restarted collector forgets seen nonces.
* Clock is caller-supplied (``now`` / ``issued_at``); no clock-skew
  allowance. Deployments with skewed clocks fail closed.
* The module does not re-verify workload-identity documents at collect
  time: it trusts the policy's pinned keys. Key-to-document binding is a
  deployment registration-time responsibility.
* ``attest`` signs for whoever holds the seed -- it does not check policy
  membership. Membership is enforced at ``collect`` (fail-closed there).
* This wave is advisory-first at the approval queue: ``queue()`` records
  ``quorum_state`` MAC-bound but never gates on it. Enforcement lives in
  ``QuorumGate`` for explicitly registered sensitive operations only.

Design notes (deliberate deviations from the letter of the spec):
* The policy version is bound by the attestation *signature* (the signed
  body carries both ``operation_digest`` and ``policy_version``), not by
  hashing the version into ``operation_digest`` itself. The digest names
  the operation; the signature binds operation+version together. The
  fail-closed effect is identical (a version mismatch refuses).
* Attestations carry a bounded TTL (default 3600s, max 3600s). The spec
  asked for replay resistance via nonce+digest+version; a validity window
  is the standard companion (K8s bound-token pattern: expiry is the
  revocation mechanism). This is a deliberate addition, not spec creep
  by accident -- it is pinned by ``quorum-attestation-expired`` and the
  battery's expired-attestation probe.

$0 spend. Synthetic/local testing.
"""

from __future__ import annotations

import hashlib
import json
import time

from . import ed25519 as _ed

SCHEMA = "quorum-approval/v1"

# Attestation validity bound (K8s bound-token pattern: expiry is the
# revocation mechanism; there is no attestation revocation list).
MAX_TTL_SECONDS = 3600
DEFAULT_TTL_SECONDS = 3600

__all__ = [
    "SCHEMA",
    "MAX_TTL_SECONDS",
    "DEFAULT_TTL_SECONDS",
    "PolicyRefusal",
    "AttestationRefusal",
    "QuorumPolicy",
    "register_policy",
    "reset_registry",
    "operation_digest",
    "attest",
    "deny",
    "QuorumCollector",
    "QuorumGate",
]


class PolicyRefusal(Exception):
    """A coded quorum-policy failure. ``code`` is the machine code."""

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("[%s] %s" % (code, detail) if detail else
                         "[%s]" % (code,))


class AttestationRefusal(Exception):
    """A coded attestation failure. ``code`` is the machine code."""

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("[%s] %s" % (code, detail) if detail else
                         "[%s]" % (code,))


def _refuse_policy(code, detail=""):
    raise PolicyRefusal(code, detail)


def _refuse_att(code, detail=""):
    raise AttestationRefusal(code, detail)


def _canonical_bytes(obj):
    """Canonical JSON bytes: sort_keys, no whitespace, ASCII. The exact
    bytes every signer and verifier must hash. Refuses (never silently
    degrades) on unserializable input."""
    try:
        return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _refuse_att("quorum-malformed",
                    "attestation not JSON-serializable: %s" % (exc,))


def operation_digest(descriptor):
    """sha256 hex of the canonical operation descriptor. The descriptor
    is deployment-defined and treated opaquely; the digest is what
    attestations bind to."""
    if not isinstance(descriptor, dict):
        _refuse_att("quorum-malformed",
                    "operation descriptor must be a mapping")
    return hashlib.sha256(_canonical_bytes(descriptor)).hexdigest()


def _check_approver_entry(entry, where):
    if not isinstance(entry, dict):
        _refuse_policy("quorum-malformed",
                       "%s: approver must be a mapping" % (where,))
    name = entry.get("name")
    if not isinstance(name, str) or not name.strip():
        _refuse_policy("quorum-malformed",
                       "%s: approver name must be a non-empty str" % (where,))
    spiffe_id = entry.get("spiffe_id")
    if (not isinstance(spiffe_id, str) or not spiffe_id.startswith(
            "spiffe://")):
        _refuse_policy("quorum-malformed",
                       "%s: spiffe_id must start with 'spiffe://'" % (where,))
    pub = entry.get("public_key")
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
        _refuse_policy("quorum-malformed",
                       "%s: public_key must be 32 bytes" % (where,))
    return {"name": name.strip(),
            "spiffe_id": spiffe_id,
            "public_key": bytes(pub)}


class QuorumPolicy:
    """An immutable, versioned m-of-n approver policy."""

    def __init__(self, policy_id, version, m, approvers, change_log):
        self.policy_id = policy_id
        self.version = version
        self.m = m
        self.approvers = tuple(approvers)
        self.change_log = tuple(change_log)
        self._by_name = {a["name"]: a for a in self.approvers}

    def approver(self, name):
        return self._by_name.get(name)

    def approver_names(self):
        return tuple(a["name"] for a in self.approvers)


# Module-level registry: policy_id -> QuorumPolicy. The registry is what
# makes version monotonicity enforceable. Deployments with multiple
# processes must share one registry (deployment responsibility -- same
# trust model as the HMAC log key).
_POLICY_REGISTRY = {}


def reset_registry():
    """Clear the policy registry. Test support -- deployments must never
    call this outside tests."""
    _POLICY_REGISTRY.clear()


def register_policy(cfg):
    """Validate and register a quorum policy. Fail-closed at load:

    * m < 1, empty approvers, duplicate names, key reuse across names,
      m > n (unreachable quorum -- D1-core L7), malformed entries: refuse.
    * version must strictly exceed the registered version for the same
      policy_id; a changed approver set at the same version refuses
      (quorum-policy-version-invalid).
    """
    if not isinstance(cfg, dict):
        _refuse_policy("quorum-malformed", "policy cfg must be a mapping")
    policy_id = cfg.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id.strip():
        _refuse_policy("quorum-malformed",
                       "policy_id must be a non-empty str")
    policy_id = policy_id.strip()
    version = cfg.get("version")
    if (isinstance(version, bool) or not isinstance(version, int)
            or version < 1):
        _refuse_policy("quorum-malformed",
                       "version must be an int >= 1")
    m = cfg.get("m")
    if isinstance(m, bool) or not isinstance(m, int) or m < 1:
        _refuse_policy("quorum-malformed", "m must be an int >= 1")
    raw_approvers = cfg.get("approvers")
    if not isinstance(raw_approvers, (list, tuple)) or not raw_approvers:
        _refuse_policy("quorum-malformed",
                       "approvers must be a non-empty list")
    approvers = [_check_approver_entry(a, "approvers[%d]" % i)
                 for i, a in enumerate(raw_approvers)]
    names = [a["name"] for a in approvers]
    if len(set(names)) != len(names):
        _refuse_policy("quorum-malformed",
                       "approver names must be unique -- duplicates would "
                       "let one human fill two quorum slots")
    keys = [a["public_key"] for a in approvers]
    if len(set(keys)) != len(keys):
        _refuse_policy("quorum-key-reuse",
                       "the same public key under two names would let one "
                       "key fill two quorum slots -- refused at load")
    if m > len(approvers):
        _refuse_policy("quorum-unreachable",
                       "m (%d) exceeds n (%d): the quorum is unreachable -- "
                       "silent starvation -- failing closed at load" % (
                           m, len(approvers)))
    change_log = cfg.get("change_log")
    if not isinstance(change_log, (list, tuple)) or not change_log:
        _refuse_policy("quorum-malformed",
                       "change_log must be a non-empty list (CC8.1: every "
                       "policy version lands with a change-log entry)")
    for i, entry in enumerate(change_log):
        # Every entry -- head and history -- must be well-formed (CC8.1:
        # the trail is the evidence; a malformed history entry fails
        # closed, not silently).
        if not isinstance(entry, dict):
            _refuse_policy("quorum-malformed",
                           "change_log[%d] must be a mapping" % (i,))
        if (not isinstance(entry.get("version"), int)
                or isinstance(entry.get("version"), bool)):
            _refuse_policy("quorum-malformed",
                           "change_log[%d].version must be an int" % (i,))
        for f in ("change", "author"):
            if (not isinstance(entry.get(f), str) or not entry.get(f)):
                _refuse_policy("quorum-malformed",
                               "change_log[%d].%s must be a non-empty str"
                               % (i, f))
        if (not isinstance(entry.get("changed_at"), int)
                or isinstance(entry.get("changed_at"), bool)):
            _refuse_policy("quorum-malformed",
                           "change_log[%d].changed_at must be an int"
                           % (i,))
    if change_log[-1]["version"] != version:
        _refuse_policy("quorum-malformed",
                       "change_log head must carry this version %d "
                       "(got %d)" % (version, change_log[-1]["version"]))
    existing = _POLICY_REGISTRY.get(policy_id)
    if existing is not None:
        if version <= existing.version:
            _refuse_policy("quorum-policy-version-invalid",
                           "version %d does not exceed registered version "
                           "%d for %r" % (version, existing.version,
                                           policy_id))
        # A version bump with an identical approver set is a no-op bump;
        # allowed (the change log explains why). A *changed* set at the
        # same version is impossible here (version strictly increased),
        # so the silent-swap class is closed by monotonicity itself.
    policy = QuorumPolicy(policy_id, version, m, approvers,
                          [dict(e) for e in change_log])
    _POLICY_REGISTRY[policy_id] = policy
    return policy


def _attestation_body(approver_name, spiffe_id, op_digest, policy,
                      nonce, issued_at, ttl_seconds, kind, reason):
    return {
        "schema": SCHEMA,
        "kind": kind,  # "approve" or "deny"
        "approver": approver_name,
        "spiffe_id": spiffe_id,
        "operation_digest": op_digest,
        "policy_id": policy.policy_id,
        "policy_version": policy.version,
        "nonce": nonce,
        "issued_at": issued_at,
        "ttl_seconds": ttl_seconds,
        "reason": reason,
    }


def _sign_attestation(seed, body):
    sig = _ed.sign(bytes(seed), _canonical_bytes(body))
    att = dict(body)
    att["signature"] = bytes(sig).hex()
    return att


def _mint_attestation(seed, approver_name, op_digest, policy, nonce, kind,
                      reason, issued_at, ttl_seconds, spiffe_id):
    """Shared attestation minter: validates, builds the body, signs once."""
    if not isinstance(nonce, str) or not nonce:
        _refuse_att("quorum-malformed", "nonce must be a non-empty str")
    if issued_at is None:
        issued_at = int(time.time())
    if (isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int)
            or not 1 <= ttl_seconds <= MAX_TTL_SECONDS):
        _refuse_att("quorum-malformed",
                    "ttl_seconds must be an int in [1, %d]" % (
                        MAX_TTL_SECONDS,))
    entry = policy.approver(approver_name)
    sid = spiffe_id if spiffe_id is not None else (
        entry["spiffe_id"] if entry else "spiffe://unknown/%s" % approver_name)
    body = _attestation_body(approver_name, sid, op_digest, policy, nonce,
                             issued_at, ttl_seconds, kind, reason)
    return _sign_attestation(seed, body)


def attest(seed, approver_name, op_digest, policy, nonce, issued_at=None,
           ttl_seconds=DEFAULT_TTL_SECONDS, spiffe_id=None):
    """Mint a signed approval attestation. Signs for whoever holds the
    seed -- policy membership is enforced at ``collect``, not here."""
    return _mint_attestation(seed, approver_name, op_digest, policy, nonce,
                             "approve", "", issued_at, ttl_seconds,
                             spiffe_id)


def deny(seed, approver_name, op_digest, policy, nonce, reason,
         issued_at=None, ttl_seconds=DEFAULT_TTL_SECONDS, spiffe_id=None):
    """Mint a signed *dissent* attestation. A single eligible deny vetoes
    the quorum (D1-core §4.3)."""
    if not isinstance(reason, str) or not reason.strip():
        _refuse_att("quorum-malformed", "deny reason must be non-empty")
    # Single sign: the kind and reason are part of the signed body from
    # the start (no intermediate approve signature to discard).
    return _mint_attestation(seed, approver_name, op_digest, policy, nonce,
                             "deny", reason.strip(), issued_at, ttl_seconds,
                             spiffe_id)


_REQUIRED_ATTESTATION_FIELDS = (
    "schema", "kind", "approver", "spiffe_id", "operation_digest",
    "policy_id", "policy_version", "nonce", "issued_at", "ttl_seconds",
    "reason", "signature",
)


def _verify_attestation_shape(att):
    if not isinstance(att, dict):
        _refuse_att("quorum-malformed", "attestation must be a mapping")
    for field in _REQUIRED_ATTESTATION_FIELDS:
        if field not in att:
            _refuse_att("quorum-malformed",
                        "attestation missing field %r" % (field,))
    if att.get("schema") != SCHEMA:
        _refuse_att("quorum-malformed",
                    "attestation schema %r != %r" % (att.get("schema"),
                                                     SCHEMA))
    if att.get("kind") not in ("approve", "deny"):
        _refuse_att("quorum-malformed",
                    "attestation kind must be approve/deny")
    # Type checks: fail-closed on wrong types (never a bare TypeError
    # downstream -- e.g. an unhashable approver name in dict.get()).
    for field in ("approver", "spiffe_id", "operation_digest",
                  "policy_id", "nonce"):
        v = att.get(field)
        if not isinstance(v, str) or not v:
            _refuse_att("quorum-malformed",
                        "attestation field %r must be a non-empty str" % (
                            field,))
    for field in ("policy_version", "issued_at", "ttl_seconds"):
        v = att.get(field)
        if isinstance(v, bool) or not isinstance(v, int):
            _refuse_att("quorum-malformed",
                        "attestation field %r must be an int" % (field,))
    try:
        sig = bytes.fromhex(att["signature"])
    except (ValueError, TypeError):
        _refuse_att("quorum-malformed", "signature must be hex")
    if len(sig) != 64:
        _refuse_att("quorum-signature-invalid",
                    "signature is %d bytes, want 64" % len(sig))
    return sig


class QuorumCollector:
    """Accumulates attestations for one operation under one policy.

    The collector is bound to (policy, operation_digest) at construction;
    attestations for any other digest refuse ``quorum-operation-mismatch``.
    Distinctness is by named approver slot: a second attestation from an
    already-counted name is recorded but never counted twice.
    """

    def __init__(self, policy, operation_digest, now=None):
        if not isinstance(operation_digest, str) or not operation_digest:
            _refuse_att("quorum-malformed",
                        "operation_digest must be a non-empty str")
        self._policy = policy
        self._digest = operation_digest
        self._now = now  # caller-supplied clock; None -> time.time() at use
        self._seen_nonces = set()
        self._counted = {}  # approver name -> attestation
        self._denials = {}  # approver name -> attestation
        self._records = []  # every collect() outcome, for audit

    def _now_s(self):
        return int(time.time()) if self._now is None else self._now

    @property
    def policy(self):
        return self._policy

    @property
    def operation_digest(self):
        return self._digest

    def collect(self, att):
        """Validate and record one attestation. Returns an acceptance
        record. Raises ``AttestationRefusal`` (coded) on any failure --
        nothing unverified is ever counted."""
        sig = _verify_attestation_shape(att)
        name = att["approver"]
        entry = self._policy.approver(name)
        if entry is None:
            _refuse_att("quorum-unknown-approver",
                        "%r is not an eligible approver" % (name,))
        if att["policy_id"] != self._policy.policy_id:
            _refuse_att("quorum-operation-mismatch",
                        "attestation policy %r != collector policy %r" % (
                            att["policy_id"], self._policy.policy_id))
        if att["policy_version"] != self._policy.version:
            _refuse_att("quorum-policy-version-invalid",
                        "attestation version %r != policy version %r" % (
                            att["policy_version"], self._policy.version))
        if att["operation_digest"] != self._digest:
            _refuse_att("quorum-operation-mismatch",
                        "attestation is bound to a different operation")
        nonce = att["nonce"]  # non-empty str per the shape check
        if nonce in self._seen_nonces:
            _refuse_att("quorum-replay-refused",
                        "nonce %r already seen for this operation" % (nonce,))
        issued_at = att["issued_at"]  # int per the shape check
        ttl = att["ttl_seconds"]  # int per the shape check
        if issued_at + ttl <= self._now_s():
            _refuse_att("quorum-attestation-expired",
                        "attestation validity window has passed")
        body = {k: v for k, v in att.items() if k != "signature"}
        # The wave-243 lesson: verify() returns a bool -- check it.
        if _ed.verify(entry["public_key"], _canonical_bytes(body),
                      sig) is not True:
            _refuse_att("quorum-signature-invalid",
                        "signature does not verify for %r" % (name,))
        self._seen_nonces.add(nonce)
        kind = att["kind"]
        if kind == "deny":
            self._denials[name] = att
            rec = {"accepted": True, "kind": "deny", "approver": name,
                   "counted": False}
        elif name in self._counted:
            # Distinctness by named slot: recorded, never double-counted.
            # The informational code is quorum-duplicate-approver (per the
            # spec); the refusal code for execution attempts is
            # quorum-insufficient.
            rec = {"accepted": True, "kind": "approve", "approver": name,
                   "counted": False, "code": "quorum-duplicate-approver",
                   "note": "already counted; recorded, not double-counted"}
        else:
            self._counted[name] = att
            rec = {"accepted": True, "kind": "approve", "approver": name,
                   "counted": True}
        self._records.append(rec)
        return rec

    def evaluate(self):
        """The quorum verdict. Deny veto first, then the m-of-n count."""
        if self._denials:
            return {"executable": False,
                    "code": "quorum-deny-veto",
                    "counted": len(self._counted),
                    "m": self._policy.m,
                    "n": len(self._policy.approvers),
                    "approvers": sorted(self._counted),
                    "denied_by": sorted(self._denials)}
        counted = len(self._counted)
        if counted >= self._policy.m:
            return {"executable": True,
                    "code": None,
                    "counted": counted,
                    "m": self._policy.m,
                    "n": len(self._policy.approvers),
                    "approvers": sorted(self._counted),
                    "denied_by": []}
        return {"executable": False,
                "code": "quorum-insufficient",
                "counted": counted,
                "m": self._policy.m,
                "n": len(self._policy.approvers),
                "approvers": sorted(self._counted),
                "denied_by": []}

    def records(self):
        return tuple(self._records)


class QuorumGate:
    """Opt-in enforcement for registered sensitive operations.

    The gate never gates what it does not own: ``check`` on an
    unregistered operation returns advisory-absent and allows. Only
    operations explicitly registered via ``register_sensitive`` are
    subject to the m-of-n rule.
    """

    def __init__(self):
        self._policies = {}
        self._collectors = {}

    def register_sensitive(self, operation_id, policy):
        if not isinstance(operation_id, str) or not operation_id.strip():
            _refuse_policy("quorum-malformed",
                           "operation_id must be a non-empty str")
        if not isinstance(policy, QuorumPolicy):
            _refuse_policy("quorum-malformed",
                           "policy must be a QuorumPolicy")
        self._policies[operation_id.strip()] = policy
        # A re-registration resets collection state -- fail-closed, never
        # carry attestations across a policy swap.
        self._collectors.pop(operation_id.strip(), None)

    def collector_for(self, operation_id):
        try:
            return self._collectors[operation_id]
        except KeyError:
            raise KeyError(
                "no collector for %r: check() the operation first or "
                "register it via register_sensitive" % (operation_id,))

    def check(self, operation_id, context):
        """Evaluate the gate for one operation. ``context`` carries the
        operation ``digest`` the caller is acting on."""
        policy = self._policies.get(operation_id)
        if policy is None:
            return {"mode": "absent", "allowed": True, "code": None}
        digest = (context or {}).get("digest")
        if not isinstance(digest, str) or not digest:
            return {"mode": "enforcing", "allowed": False,
                    "code": "quorum-malformed",
                    "detail": "check context must carry the operation digest"}
        col = self._collectors.get(operation_id)
        if col is None:
            col = QuorumCollector(policy, digest)
            self._collectors[operation_id] = col
        elif col.operation_digest != digest:
            return {"mode": "enforcing", "allowed": False,
                    "code": "quorum-operation-mismatch",
                    "detail": "collector is bound to a different operation"}
        v = col.evaluate()
        return {"mode": "enforcing",
                "allowed": v["executable"],
                "code": v["code"],
                "counted": v["counted"],
                "m": v["m"],
                "denied_by": v["denied_by"]}
