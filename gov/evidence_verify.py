#!/usr/bin/env python3
"""Standalone evidence-bundle v1 verifier (standard library only).

Verifies a bundle directory produced by ``gov/evidence_bundle.py``
WITHOUT the repository installed and WITHOUT trusting the deployer.
Usage::

    python3 evidence-verify <bundle-dir> [--pin-operator-pubkey HEX ...]
                                         [--format text|json]

Exit codes: 0 = VERIFIED (pinned operator key) · 1 = FAILED ·
2 = SELF_CONSISTENT (unpinned: internally intact, authorship NOT
established) · 3 = usage / config error.

Checks (V1-V13, see docs/evidence-bundle-spec.md):
  V1  bundle digest recomputes over the file tree
  V2  required transport files present
  V3  VERSION pins bundle + schema versions
  V4  evidence.json hashes to manifest.export_sha256 (and is canonical)
  V5  key envelope well-formed: 32-byte pubkeys, key_id == sha256(pub)[:16]
  V6  pinned operator key: envelope pubkey matches an out-of-band pin
      (full 32-byte public key, not a key id); F151: V7 does not run
      against the wrong operator's keys
  V7  Ed25519 manifest signature over the domain-separated signed body
      (window, chain_verified, checkpoints_digest, inclusion
      presence/coverage, receipt binding — F173); seal key == envelope
      operator key
  V8  checkpoint signatures (single-key or A5 k-of-n roster threshold)
      + Merkle roots recomputed from the slice; inclusion bundles
      verified per entry; embedded checkpoints cross-checked
  V9  slice seqs contiguous, prev_hash-linked; inclusion bundles verified
      against V8-verified heads; reduced coverage explicit
  V10 manifest completeness: all nine payload sections present; entry
      counts and coverage math consistent; no out-of-window seq refs
  V11 policy-version consistency: payload policy values equal the
      slice's policy_loaded events; policy_change_events complete
  V12 receipt chains onto the window tip; receipt.json bundle-presence/
      unavailable_reason equals the operator-signed manifest receipt
      binding (F173); receipt inclusion bundle verified; V12b with
      --log checks receipt existence in source log
  V13 citation/approval cross-consistency: accepted citations have no
      self-planted; verdict counts sum; approval shapes match vocabulary
  V14 deterministic bundle ID (v1 extension, non-normative)
  V15 provenance block well-formed (v1 extension, non-normative)
  V16 retention schema valid (v1 extension, non-normative)

WHAT THIS DOES NOT PROVE (normative, spec §7 — printed on every run):
recorded events only, not unrecorded ones; integrity is not truth;
key custody is claimed, not proven; timestamps are operator
wall-clock; unpinned bundles prove self-consistency only; UNKNOWN is
not clean; retention/operator fields are assertions; single-tenant
scope; no auditor or regulator has accepted this format; no live
Rekor/Sigstore anchoring in v1.

$0 spend. No network. Pure Python, no dependencies.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys

# ---------------------------------------------------------------------------
# Vendored cryptography (marked sections — do not hand-edit; canonical
# sources live in the repo: gov/ed25519.py, gov/merkle.py, gov/log.py).
# ---------------------------------------------------------------------------

# --- begin vendored gov/ed25519.py (verbatim) ---
"""Ed25519 digital signatures: vendored pure-Python RFC 8032.

P2 (crypto workstream): public-key signatures for the audit log, so an
external auditor can verify entries and checkpoints WITHOUT holding the
shared HMAC key (cf. ``gov/keys.py``: HMAC gives no non-repudiation
between key holders).

Implementation status -- read before deploying:
* Faithful RFC 8032 sections 5.1.5-5.1.7; validated byte-exact against
  the RFC 8032 section 7.1 TEST 1 and TEST 2 vectors (see
  ``tests/test_crypto_gov.py``). This is the standard wire format, so
  signatures verify across implementations.
* Pure Python: NOT constant-time. CPython bigint operations leak timing
  to a local side-channel attacker. The threat model for the audit-log
  use covers a run-dir writer and a network auditor, not a local
  side-channel observer; where local side channels are in scope,
  replace this module with a constant-time backend (e.g. libsodium via
  PyNaCl) behind the same function signatures -- no wire-format change.
* Deterministic nonces per RFC 8032 section 5.1.6 (no RNG at sign
  time); key generation uses :mod:`secrets`.

``verify`` never raises on malformed inputs: malformed is False, never
an exception (fail-closed for verifiers).
"""

import hashlib
import secrets

_Q = (1 << 255) - 19
_L = (1 << 252) + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)  # sqrt(-1) mod _Q


def _inv(x):
    return pow(x, _Q - 2, _Q)


def _xrecover(y):
    xx = (y * y - 1) * _inv((_D * y * y + 1) % _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x & 1:
        x = _Q - x
    return x


_BY = (4 * _inv(5)) % _Q
_BX = _xrecover(_BY)
# Base point B in extended coordinates (X, Y, Z, T).
_B = (_BX, _BY, 1, (_BX * _BY) % _Q)
_IDENTITY = (0, 1, 1, 0)


def _add(P, Q):
    """Complete Edwards addition (Hisil et al.), valid for all inputs."""
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = ((Y1 - X1) * (Y2 - X2)) % _Q
    B = ((Y1 + X1) * (Y2 + X2)) % _Q
    C = (T1 * ((2 * _D) % _Q) * T2) % _Q
    Dd = ((2 * Z1) * Z2) % _Q
    E = (B - A) % _Q
    F = (Dd - C) % _Q
    G = (Dd + C) % _Q
    H = (B + A) % _Q
    return ((E * F) % _Q, (G * H) % _Q, (F * G) % _Q, (E * H) % _Q)


def _scalarmult(P, e):
    e %= _L
    Q = _IDENTITY
    for i in range(255, -1, -1):
        Q = _add(Q, Q)
        if (e >> i) & 1:
            Q = _add(Q, P)
    return Q


def _encode_point(P):
    X, Y, Z, _T = P
    zinv = _inv(Z)
    x = (X * zinv) % _Q
    y = (Y * zinv) % _Q
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode_point(s):
    if len(s) != 32:
        raise ValueError("encoded point must be 32 bytes")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    if y >= _Q:
        raise ValueError("y coordinate out of range")
    x = _xrecover(y)
    if (x & 1) != (s[31] >> 7):
        x = _Q - x
    if ((-x * x + y * y - 1 - _D * x * x * y * y) % _Q) != 0:
        raise ValueError("point not on curve")
    return (x, y, 1, (x * y) % _Q)


def _clamp(a):
    a &= ~7            # clear lowest three bits (cofactor multiple)
    a &= ~(1 << 255)   # clear highest bit
    a |= (1 << 254)    # set second-highest bit
    return a


def generate_seed():
    """Generate a fresh 32-byte Ed25519 seed (secret key material)."""
    return secrets.token_bytes(32)


def publickey(seed):
    """Derive the 32-byte public key from a 32-byte seed (RFC 8032 5.1.5)."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(bytes(seed)).digest()
    a = _clamp(int.from_bytes(h[:32], "little"))
    return _encode_point(_scalarmult(_B, a))


def sign(seed, msg):
    """Sign ``msg`` deterministically (RFC 8032 5.1.6). Returns 64 bytes."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    seed = bytes(seed)
    if not isinstance(msg, (bytes, bytearray)):
        raise TypeError("msg must be bytes")
    msg = bytes(msg)
    h = hashlib.sha512(seed).digest()
    a = _clamp(int.from_bytes(h[:32], "little"))
    prefix = h[32:]
    A = _encode_point(_scalarmult(_B, a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(),
                       "little") % _L
    R = _encode_point(_scalarmult(_B, r))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(),
                       "little") % _L
    S = (r + k * a) % _L
    return R + S.to_bytes(32, "little")


def verify(pub, msg, sig):
    """Verify an Ed25519 signature (RFC 8032 5.1.7).

    Returns True/False; never raises on malformed inputs (fail-closed
    for verifiers: malformed is False, never an exception).
    """
    if (not isinstance(pub, (bytes, bytearray)) or len(pub) != 32
            or not isinstance(sig, (bytes, bytearray)) or len(sig) != 64):
        return False
    if not isinstance(msg, (bytes, bytearray)):
        return False
    pub, sig, msg = bytes(pub), bytes(sig), bytes(msg)
    try:
        A = _decode_point(pub)
        R = _decode_point(sig[:32])
    except ValueError:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(),
                       "little") % _L
    lhs = _scalarmult(_B, s)
    rhs = _add(R, _scalarmult(A, k))
    return _encode_point(lhs) == _encode_point(rhs)


# ---------------------------------------------------------------------------
# RFC 8032, section 7.1, test vectors for Ed25519 (pages 23-24). Private and
# public keys are 32 octets; signatures 64 octets; hex-encoded in the RFC.
RFC8032_VECTORS = (
    {  # TEST 1 -- empty message
        "sk": "9d61b19deffd5a60ba844af492ec2cc4"
              "4449c5697b326919703bac031cae7f60",
        "pk": "d75a980182b10ab7d54bfed3c964073a"
              "0ee172f3daa62325af021a68f707511a",
        "msg": "",
        "sig": "e5564300c360ac729086e2cc806e828a"
               "84877f1eb8e5d974d873e06522490155"
               "5fb8821590a33bacc61e39701cf9b46b"
               "d25bf5f0595bbe24655141438e7a100b",
    },
    {  # TEST 2 -- 1-byte message 0x72
        "sk": "4ccd089b28ff96da9db6c346ec114e0f"
              "5b8a319f35aba624da8cf6ed4fb8a6fb",
        "pk": "3d4017c3e843895a92b70aa74d1b7ebc"
              "9c982ccf2ec4968cc0cd55f12af4660c",
        "msg": "72",
        "sig": "92a009a9f0d4cab8720e820b5f642540"
               "a2b27b5416503f8fb3762223ebdb69da"
               "085ac1e43e15996e458f3613d0f11d8c"
               "387b2eaeb4302aeeb00d291612bb0c00",
    },
)


def rfc8032_selftest():
    """Validate against the RFC 8032 vectors: pubkey derivation, byte-exact
    deterministic signatures, and verification."""
    for i, v in enumerate(RFC8032_VECTORS, 1):
        sk = bytes.fromhex(v["sk"])
        pk = bytes.fromhex(v["pk"])
        msg = bytes.fromhex(v["msg"])
        sig = bytes.fromhex(v["sig"])
        assert publickey(sk) == pk, "TEST %d: pubkey mismatch" % i
        assert sign(sk, msg) == sig, "TEST %d: signature mismatch" % i
        assert verify(pk, msg, sig), "TEST %d: verify failed" % i
    return True
# --- end vendored gov/ed25519.py ---

# --- begin vendored gov/merkle.py primitives ---
_MERKLE_LEAF_DOMAIN = b"gov-merkle-leaf/v1\x00"
_MERKLE_NODE_DOMAIN = b"gov-merkle-node/v1\x00"


def _mk_leaf_hash(leaf_input):
    return hashlib.sha256(_MERKLE_LEAF_DOMAIN + leaf_input).digest()


def _mk_node_hash(left, right):
    return hashlib.sha256(_MERKLE_NODE_DOMAIN + left + right).digest()


def _mk_largest_pow2_lt(n):
    p = 1
    while 2 * p < n:
        p *= 2
    return p


def mk_verify_inclusion(leaf_input, root, leaf_index, proof, tree_size):
    """Verify a leaf's inclusion under ``root``.

    Faithful to gov/merkle.py::verify_inclusion: the proof list is
    ordered root-level-first and consumed top-down; the recursion
    mirrors inclusion_proof's largest-power-of-two split. Returns
    True/False; never raises on malformed inputs.
    """
    leaf = _mk_leaf_hash(leaf_input)
    if (not isinstance(leaf, (bytes, bytearray)) or len(leaf) != 32
            or not isinstance(root, (bytes, bytearray))
            or len(root) != 32):
        return False
    if not isinstance(leaf_index, int) or not isinstance(tree_size, int):
        return False
    if not (0 <= leaf_index < tree_size):
        return False
    try:
        proof = [bytes(p) for p in proof]
    except TypeError:
        return False
    if any(len(p) != 32 for p in proof):
        return False
    h = bytes(leaf)
    pos = 0

    def rec(m, n):
        nonlocal h, pos
        if n == 1:
            return True
        if pos >= len(proof):
            return False
        k = _mk_largest_pow2_lt(n)
        sib = proof[pos]
        pos += 1
        if m < k:
            if not rec(m, k):
                return False
            h = _mk_node_hash(h, sib)
        else:
            if not rec(m - k, n - k):
                return False
            h = _mk_node_hash(sib, h)
        return True

    if not rec(leaf_index, tree_size):
        return False
    if pos != len(proof):
        return False
    return h == bytes(root)


# --- end vendored gov/merkle.py ---

# --- begin vendored gov/log.py leaf/checkpoint conventions ---
_SIG_ENVELOPE_FIELDS = frozenset({"ed_sig", "sig_key_id",
                                  "sig_key_version"})
_CHECKPOINT_SIG_DOMAIN = b"gov-checkpoint-sig/v1\x00"
_SINGLE_ROSTER_MARK = "single:1-of-1:"


def _canonical_entry(entry):
    """Canonical bytes for one log entry (excludes chain hash + sig
    envelope), ``default=str`` exactly like gov.log._canonical."""
    payload = {k: v for k, v in entry.items()
               if k != "hash" and k not in _SIG_ENVELOPE_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _leaf_input(entry):
    return (_canonical_entry(entry) + b"\x00"
            + str(entry["hash"]).encode("utf-8"))


_ENTRY_SIG_DOMAIN = b"gov-entry-sig/v1\x00"
# Wave-183: distinct domain for version-bound entry signatures; kept
# byte-identical with gov/log.py::_ENTRY_SIG_DOMAIN_V2.
_ENTRY_SIG_DOMAIN_V2 = b"gov-entry-sig/v2\x00"


def _entry_sig_body(entry):
    """Bytes a per-entry Ed25519 signature covers: canonical content
    (sig fields excluded) plus the chain hash, domain-separated.
    Vendored from gov/log.py::_entry_sig_body (wave-179 lane A): the
    offline entry-signature check (V9d) recomputes byte-identical
    bodies from the transported slice. NOTE: this module's
    _canonical_entry returns bytes (unlike gov.log._canonical's str),
    so no .encode() here.

    Wave-183: when the envelope carries ``sig_key_version`` the version
    is bound into the signed bytes under the v2 domain (byte-identical
    with gov/log.py). Entries without a version keep the byte-identical
    v1 body.
    """
    version = entry.get("sig_key_version")
    core = _canonical_entry(entry) + b"\x00"
    tail = str(entry["hash"]).encode("utf-8")
    if isinstance(version, bool) or not isinstance(version, int):
        return _ENTRY_SIG_DOMAIN + core + tail
    return (_ENTRY_SIG_DOMAIN_V2 + core
            + str(version).encode("utf-8") + b"\x00" + tail)


def _checkpoint_sig_body(seq, entry_hash, merkle_root_hex, key_epoch,
                         threshold, roster_hash, ts):
    # F202: ts is bound into the signed body (mirrors gov/log.py).
    if not isinstance(ts, str) or not ts:
        raise TypeError(
            "checkpoint ts must be a non-empty string for the sig body")
    return (_CHECKPOINT_SIG_DOMAIN
            + ("%d|%s|%s|%s|%d|%s|%s"
               % (seq, entry_hash, merkle_root_hex, key_epoch,
                  threshold, roster_hash, ts)).encode("utf-8"))


# --- end vendored gov/log.py ---

# --- begin vendored gov/signing.py threshold primitives (adapted) ---
# Vendored from gov/signing.py::verify_roster / verify_threshold (A5).
# Adapted only for the standalone context: uses this module's vendored
# ``verify`` and ``canonical``. The roster trust root comes from the
# bundle's checkpoint_keys envelope / --pin-checkpoint-key-ids (see V8);
# v1 does not ship an offline root out-of-band, so root authorization
# for threshold rosters is noted explicitly (see _verify_threshold_head).
_ROSTER_VERSION = 1
_ROSTER_ROLE = "checkpoint-signer"


def _roster_hash(roster):
    body = {k: v for k, v in roster.items() if k != "sig"}
    return hashlib.sha256(canonical(body)).hexdigest()


def _verify_roster(roster, trusted_root_pub):
    """Verify a roster against a trusted root public key.

    Returns (ok, error). Never raises on malformed input.
    """
    try:
        if not isinstance(roster, dict):
            return False, "roster is not an object"
        if roster.get("roster_version") != _ROSTER_VERSION:
            return False, "unsupported roster_version %r" % (
                roster.get("roster_version"),)
        if roster.get("role") != _ROSTER_ROLE:
            return False, "roster role %r is not %r (role separation)" % (
                roster.get("role"), _ROSTER_ROLE)
        threshold = roster.get("threshold")
        keys = roster.get("keys")
        if not isinstance(keys, dict) or not keys:
            return False, "roster has no keys"
        if (not isinstance(threshold, int) or isinstance(threshold, bool)
                or not (1 <= threshold <= len(keys))):
            return False, "bad threshold %r for %d keys" % (
                threshold, len(keys))
        for kid, pubhex in keys.items():
            try:
                pub = bytes.fromhex(pubhex)
            except (TypeError, ValueError):
                return False, "bad pubkey hex for %r" % (kid,)
            if len(pub) != 32:
                return False, "bad pubkey length for %r" % (kid,)
            if hashlib.sha256(pub).hexdigest()[:16] != kid:
                return False, "key id %r does not match its pubkey" % (kid,)
        if not isinstance(trusted_root_pub, (bytes, bytearray)) \
                or len(trusted_root_pub) != 32:
            return False, "trusted root pubkey malformed"
        if roster.get("root_key_id") != \
                hashlib.sha256(bytes(trusted_root_pub)).hexdigest()[:16]:
            return False, "roster root_key_id does not match trusted root"
        sig = bytes.fromhex(roster.get("sig", ""))
        body = {k: v for k, v in roster.items() if k != "sig"}
        if not verify(bytes(trusted_root_pub), canonical(body), sig):
            return False, "roster signature invalid (not root-signed)"
        return True, None
    except (TypeError, ValueError, KeyError) as e:
        return False, "malformed roster: %s" % (e,)


def _verify_threshold(data, sig_entries, roster, trusted_root_pub):
    """Verify k-of-n checkpoint signatures (A5).

    Returns (ok, error). Steps: (1) the roster must verify under the
    trusted offline root; (2) at least ``threshold`` DISTINCT roster key
    ids must carry valid Ed25519 signatures over ``data``.
    """
    ok, err = _verify_roster(roster, trusted_root_pub)
    if not ok:
        return False, "roster rejected: %s" % (err,)
    if not isinstance(data, (bytes, bytearray)):
        return False, "data must be bytes"
    data = bytes(data)
    roster_keys = roster["keys"]
    threshold = roster["threshold"]
    good = set()
    try:
        entries = list(sig_entries)
    except TypeError:
        return False, "sig_entries malformed"
    for entry in entries:
        try:
            kid = entry["key_id"]
            sig = bytes.fromhex(entry["sig"])
        except (KeyError, TypeError, ValueError):
            continue  # malformed entry: contributes nothing
        if kid in good or kid not in roster_keys:
            continue  # duplicate or unknown: no double-count
        pub = bytes.fromhex(roster_keys[kid])
        if verify(pub, data, sig):
            good.add(kid)
    if len(good) >= threshold:
        return True, None
    return False, "only %d/%d valid distinct signatures" % (
        len(good), threshold)


# --- end vendored gov/signing.py ---

# ---------------------------------------------------------------------------
# Verifier proper (stdlib only).
# ---------------------------------------------------------------------------

BUNDLE_VERSION = "evidence-bundle/1.1"
EVIDENCE_SCHEMA_VERSION = "evidence-schema/1.0"
SIGN_DOMAIN = b"evidence-bundle/v2\x00"

#: Last bundle version whose signed claim does NOT bind inclusion
#: coverage or the receipt (F173). The V1 gate fails these closed;
#: see evals/f173_legacy_binding_decision.md. Kept as a module
#: constant (not derived from gov.evidence_bundle) because this file
#: is shipped standalone to auditors.
LEGACY_BUNDLE_VERSION = "evidence-bundle/1.0"

REQUIRED_FILES = (
    "VERSION",
    "evidence.json",
    "manifest.json",
    "log_slice.jsonl",
    "checkpoints.jsonl",
    "receipt.json",
    "keys/operator_ed25519.json",
    "keys/checkpoint_keys.json",
    "VERIFY.txt",
    "BUNDLE_DIGEST.sha256",
)

PROVENANCE_KINDS = {"log", "operator_supplied", "operator_must_supply",
                    "key_provider", "sar_manifest"}

# The nine payload sections (§4.1). The spec text says "seven sections"
# but enumerates nine; the implementation follows the enumeration.
PAYLOAD_SECTIONS = ("bundle_meta", "log_slice", "policy", "decisions",
                    "approvals", "citations", "benchmark", "kms_attestation",
                    "retention_manifest")

# Declared gov.approvals event vocabulary (mirrors
# gov/evidence_bundle.py::APPROVAL_EVENTS). V13 flags unknown names.
APPROVAL_EVENTS = (
    "approval_decision",
    "approval_decision_attempt",
    "approval_late_decision",
    "approval_break_glass",
    "approval_batch_abort",
    "ticket_consumed",
    "quorum_opened",
    "post_review_resolved",
)

HONESTY_FOOTER = (
    "WHAT THIS DOES NOT PROVE (normative, docs/evidence-bundle-spec.md §7): "
    "the bundle attests to RECORDED events, not unrecorded ones — off-log "
    "actions remain invisible; integrity is not truth — a verified bundle "
    "can contain a true record of a bad decision; key custody is asserted by "
    "the operator, not cryptographically proven; timestamps are operator "
    "wall-clock with no independent timestamp authority in v1; an unpinned "
    "bundle proves self-consistency only, never authorship; UNKNOWN "
    "citations are not clean citations; retention and operator-supplied "
    "fields are assertions — presence and schema checked, truth not "
    "verified; safeguard thresholds and taxonomy are provisional and "
    "project-defined, not externally validated; approval-queue MACs are "
    "not independently re-authenticated by third parties; "
    "single-tenant scope; no auditor or regulator has accepted "
    "this format; live Rekor/Sigstore anchoring is out of scope for v1 "
    "(test-double only)."
)

# List form for the JSON output contract (spec §4.3: "what_this_does_not_prove": [...]).
HONESTY_FOOTER_LIST = [
    "Recorded events only — off-log actions remain invisible.",
    "Integrity is not truth — a verified bundle can record a bad decision.",
    "Key custody is asserted by the operator, not cryptographically proven.",
    "Timestamps are operator wall-clock; no independent timestamp authority.",
    "Unpinned bundles prove self-consistency only, never authorship.",
    "UNKNOWN citations are not clean citations.",
    "Retention and operator-supplied fields are assertions (schema checked, truth not).",
    "Safeguard thresholds and taxonomy are provisional/project-defined.",
    "Approval-queue MACs are not independently re-authenticated by third parties.",
    "Single-tenant scope.",
    "No auditor or regulator has accepted this format.",
    "Live Rekor/Sigstore anchoring is out of scope for v1 (test-double only).",
]


def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), default=str).encode("utf-8")


class Check:
    def __init__(self, check_id, name):
        self.id = check_id      # "V1".."V16" per docs/evidence-bundle-spec.md
        self.name = name
        self.status = "pass"    # pass | fail | not_applicable
        self.detail = ""

    def fail(self, detail):
        self.status = "fail"
        self.detail = detail
        return self

    def na(self, detail):
        self.status = "not_applicable"
        self.detail = detail
        return self

    def ok(self, detail=""):
        self.status = "pass"
        self.detail = detail
        return self

    def as_dict(self):
        return {"id": self.id, "name": self.name,
                "ok": self.status == "pass",
                "status": self.status, "detail": self.detail}


def _read(bundle_dir, rel):
    with open(os.path.join(bundle_dir, rel), "rb") as f:
        return f.read()


def _load_json(bundle_dir, rel):
    return json.loads(_read(bundle_dir, rel).decode("utf-8"))


def compute_bundle_digest(bundle_dir):
    """Recompute BUNDLE_DIGEST over the file tree (same algorithm as
    gov.safeguard_bundle.compute_bundle_digest)."""
    h = hashlib.sha256()
    paths = []
    for root, _dirs, files in os.walk(bundle_dir):
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, bundle_dir)
            if rel == "BUNDLE_DIGEST.sha256":
                continue
            paths.append(rel)
    for rel in sorted(paths):
        with open(os.path.join(bundle_dir, rel), "rb") as f:
            content = f.read()
        h.update(rel.encode("utf-8") + b"\x00" + content + b"\x00")
    return h.hexdigest()


# -- individual checks ------------------------------------------------------

def v1_version_gate(ctx):
    c = Check("V1", "V1 version gate")
    try:
        text = _read(ctx.dir, "VERSION").decode("utf-8")
    except OSError as e:
        return c.fail("cannot read VERSION: %s" % e)
    lines = text.splitlines()
    if lines[:1] == [LEGACY_BUNDLE_VERSION]:
        # F173 decision (evals/f173_legacy_binding_decision.md): 1.0
        # bundles have no cryptographic binding of inclusion coverage
        # or the receipt, so no unsigned alteration of those fields can
        # fail — accepting them (even labeled) would preserve the exact
        # downgrade F173 closes. Fail closed with the remedy named.
        return c.fail(
            "legacy bundle %r: inclusion coverage and receipt binding "
            "are not cryptographically bound in this format version "
            "(F173) — refusing to verify; re-seal with the current "
            "builder" % LEGACY_BUNDLE_VERSION)
    if len(lines) < 2 or lines[0] != BUNDLE_VERSION:
        return c.fail("VERSION[0] %r != %r" % (lines[:1], BUNDLE_VERSION))
    if lines[1] != "schema: " + EVIDENCE_SCHEMA_VERSION:
        return c.fail("VERSION[1] %r != 'schema: %s'"
                      % (lines[1:2], EVIDENCE_SCHEMA_VERSION))
    return c.ok("bundle %s, schema %s"
                % (BUNDLE_VERSION, EVIDENCE_SCHEMA_VERSION))


def v2_required_files(ctx):
    c = Check("V2", "V2 required files")
    missing = [r for r in REQUIRED_FILES
               if not os.path.isfile(os.path.join(ctx.dir, r))]
    if missing:
        return c.fail("missing: %s" % ", ".join(missing))
    return c.ok("all %d required files present" % len(REQUIRED_FILES))


def v3_transport_digest(ctx):
    c = Check("V3", "V3 transport digest")
    try:
        stored = _read(ctx.dir, "BUNDLE_DIGEST.sha256").decode(
            "utf-8").strip()
    except OSError as e:
        return c.fail("cannot read BUNDLE_DIGEST.sha256: %s" % e)
    recomputed = compute_bundle_digest(ctx.dir)
    if stored != recomputed:
        return c.fail("digest mismatch: stored %s recomputed %s"
                      % (stored, recomputed))
    ctx.bundle_digest = stored
    return c.ok("digest %s recomputes over %d files"
                % (stored[:16], ctx.file_count))


def v4_payload_digest(ctx):
    c = Check("V4", "V4 payload digest")
    try:
        data = _read(ctx.dir, "evidence.json")
    except OSError as e:
        return c.fail("cannot read evidence.json: %s" % e)
    if not data.endswith(b"\n"):
        return c.fail("evidence.json has no trailing newline")
    body = data[:-1]
    try:
        payload = json.loads(body.decode("utf-8"))
    except ValueError as e:
        return c.fail("evidence.json is not JSON: %s" % e)
    if hashlib.sha256(body).hexdigest() != ctx.manifest["export_sha256"]:
        return c.fail("sha256(evidence.json) != manifest.export_sha256")
    if canonical(payload) != body:
        return c.fail("evidence.json is not in canonical form "
                      "(rewritten or re-encoded)")
    ctx.payload = payload
    return c.ok("evidence.json hashes to export_sha256 and is canonical")


def v5_key_envelope(ctx):
    c = Check("V5", "V5 key envelope")
    env = ctx.operator_envelope
    try:
        pub = bytes.fromhex(env["public_key_hex"])
    except (KeyError, ValueError, TypeError):
        return c.fail("operator envelope public_key_hex malformed")
    if len(pub) != 32:
        return c.fail("operator envelope public key is not 32 bytes")
    if env.get("key_id") != hashlib.sha256(pub).hexdigest()[:16]:
        return c.fail("operator envelope key_id does not match "
                      "sha256(pub)[:16]: the envelope mislabels its key")
    cp_keys = ctx.cp_envelope
    if not isinstance(cp_keys, list) or not cp_keys:
        return c.fail("checkpoint_keys envelope is not a non-empty list")
    for i, kenv in enumerate(cp_keys):
        try:
            cpub = bytes.fromhex(kenv["public_key_hex"])
        except (KeyError, ValueError, TypeError):
            return c.fail("checkpoint_keys[%d] public_key_hex malformed"
                          % i)
        if len(cpub) != 32:
            return c.fail("checkpoint_keys[%d] public key is not 32 "
                          "bytes" % i)
        if kenv.get("key_id") != hashlib.sha256(cpub).hexdigest()[:16]:
            return c.fail("checkpoint_keys[%d] key_id does not match "
                          "sha256(pub)[:16]" % i)
    return c.ok("operator + %d checkpoint key envelopes well-formed "
                "(32-byte pubkeys, key_id == sha256(pub)[:16])"
                % len(cp_keys))


def v6_authorship_pin(ctx):
    c = Check("V6", "V6 authorship pin")
    env = ctx.operator_envelope
    pub_hex = env.get("public_key_hex", "")
    ctx.pin_ok = False
    if not ctx.pins:
        return c.na("no --pin-operator-pubkey given: authorship NOT "
                    "established; best possible verdict is "
                    "SELF_CONSISTENT")
    if pub_hex.lower() not in {p.lower() for p in ctx.pins}:
        # F151 rule: V7 must not run against the wrong operator's keys.
        ctx.pin_failed = True
        return c.fail("operator envelope pubkey does not match any "
                      "pinned key: authorship NOT established")
    ctx.pin_ok = True
    ctx.authorship_key_id = env.get("key_id")
    return c.ok("operator pubkey matches a pinned key (full 32-byte "
                "public key, not a key id)")


def _signed_claim(manifest):
    """Reconstruct the operator-signed claim.

    Must build byte-identical canonical bytes to
    ``gov.evidence_bundle.EvidenceBundle.signed_body`` (the builder).
    F173: besides window/chain_verified/checkpoints_digest, the claim
    binds the per-entry inclusion-bundle presence vector, the
    inclusion_coverage counts, and the receipt's bundle-presence/reason
    — so unsigned alteration of any of those fails V7.
    Wave-179 lane A: the claim additionally binds audit_entry_signing
    (the window's per-entry Ed25519 key ids and signed/total counts)
    when the manifest carries it. Manifests sealed before that block
    existed keep the old claim shape (backward compatible: the field
    is included iff present).
    """
    ic = manifest.get("inclusion_coverage") or {}
    presence = []
    for b in manifest.get("inclusion_bundles") or []:
        presence.append({
            "seq": b.get("seq"),
            "bundle_present": b.get("bundle") is not None,
            "unavailable_reason": b.get("unavailable_reason"),
        })
    r = manifest.get("receipt")
    receipt = (None if r is None else
               {"bundle_present": r.get("bundle") is not None,
                "unavailable_reason": r.get("unavailable_reason")})
    claim = {
        "window": manifest["window"],
        "chain_verified": manifest["chain_verified"],
        "checkpoints_digest": manifest["checkpoints_digest"],
        "inclusion": {
            "coverage": {"entries": ic.get("entries"),
                         "with_bundle": ic.get("with_bundle")},
            "presence": presence,
        },
        "receipt": receipt,
    }
    if "audit_entry_signing" in manifest:
        claim["audit_entry_signing"] = manifest["audit_entry_signing"]
    return claim


def v7_operator_signature(ctx):
    c = Check("V7", "V7 operator signature")
    if getattr(ctx, "pin_failed", False):
        # F151: do not verify a signature against the wrong operator's
        # keys — the pin failure already failed the bundle.
        return c.na("skipped: V6 pin failed (F151 rule — V7 does not run "
                    "against the wrong operator's keys)")
    env = ctx.operator_envelope
    try:
        pub = bytes.fromhex(env["public_key_hex"])
    except (KeyError, ValueError, TypeError):
        return c.fail("operator envelope public_key_hex malformed")
    if len(pub) != 32:
        return c.fail("operator envelope public key is not 32 bytes")
    if env.get("key_id") != hashlib.sha256(pub).hexdigest()[:16]:
        return c.fail("operator envelope key_id does not match "
                      "sha256(pub)[:16]")
    seal = ctx.manifest.get("signing") or {}
    if seal.get("scheme") != "ed25519":
        return c.fail("manifest signing scheme %r != ed25519"
                      % (seal.get("scheme"),))
    if seal.get("key_id") != env.get("key_id"):
        return c.fail("seal key_id %r != envelope key_id %r: the bundle "
                      "ships a key that did not sign it"
                      % (seal.get("key_id"), env.get("key_id")))
    if seal.get("domain") != "evidence-bundle/v2":
        return c.fail("manifest signing domain %r != 'evidence-bundle/v2': "
                      "the signature is not over the v2 claim (F173 "
                      "inclusion/receipt binding)" % (seal.get("domain"),))
    claim = _signed_claim(ctx.manifest)
    body = (SIGN_DOMAIN
            + bytes.fromhex(ctx.manifest["export_sha256"])
            + canonical(claim))
    try:
        sig = bytes.fromhex(seal["signature_hex"])
    except (KeyError, ValueError, TypeError):
        return c.fail("signature_hex malformed")
    if not verify(pub, body, sig):
        return c.fail("Ed25519 signature over the domain-separated "
                      "signed body does NOT verify")
    return c.ok("signature verifies; claim (window, chain_verified, "
                "checkpoints_digest, inclusion presence/coverage, "
                "receipt binding) bound")


def _verify_one_head(head, cp_keys, roster=None, pinned_cp_key_ids=None):
    """Verify one signed checkpoint head (single-key or A5 threshold).

    Returns (error_string, note_string); error is None when the head
    verifies. ``roster`` is the A5 roster dict (from the bundle's
    ``keys/checkpoint_roster.json``); required for threshold heads.
    """
    for f in ("seq", "hash", "merkle_root", "key_epoch", "threshold",
              "roster_hash", "sigs", "ts"):
        if f not in head:
            return "checkpoint head missing field %r" % f, None
    threshold = head["threshold"]
    roster_hash = head["roster_hash"]
    try:
        body = _checkpoint_sig_body(head["seq"], head["hash"],
                                    head["merkle_root"], head["key_epoch"],
                                    threshold, roster_hash, head["ts"])
    except (KeyError, TypeError, ValueError):
        return "checkpoint sig body malformed (ts binding)", None
    if threshold == 1 and roster_hash.startswith(_SINGLE_ROSTER_MARK):
        # Single-key branch.
        expect_kid = roster_hash[len(_SINGLE_ROSTER_MARK):]
        sigs = head["sigs"] or []
        if not sigs or sigs[0].get("key_id") != expect_kid:
            return "checkpoint sig key_id does not match roster", None
        kid = sigs[0]["key_id"]
        pubs = {k["key_id"]: k["public_key_hex"] for k in cp_keys}
        if kid not in pubs:
            return ("checkpoint signer %r not in checkpoint_keys "
                    "envelope" % kid), None
        pub = bytes.fromhex(pubs[kid])
        try:
            sig = bytes.fromhex(sigs[0]["sig"])
        except (KeyError, ValueError, TypeError):
            return "checkpoint sig malformed", None
        if not verify(pub, body, sig):
            return ("checkpoint seq %d signature does NOT verify"
                    % head["seq"]), None
        return None, None
    # Threshold (A5 k-of-n) branch.
    if roster is None:
        return ("threshold checkpoint (k=%r) but no "
                "keys/checkpoint_roster.json in the bundle" % (threshold,)), \
            None
    if _roster_hash(roster) != roster_hash:
        return ("roster_hash mismatch: the shipped roster is not the "
                "signer set the checkpoint binds"), None
    # Structural roster validation (well-formedness; the offline-root
    # signature is checked below only when the root is pinned).
    ok, err = _verify_roster_structure(roster)
    if not ok:
        return "roster rejected: %s" % err, None
    if pinned_cp_key_ids is not None:
        if set(roster["keys"]) != set(pinned_cp_key_ids):
            return ("roster key ids do not match "
                    "--pin-checkpoint-key-ids exactly"), None
    # k-of-n over the roster's keys.
    roster_pubs = roster["keys"]
    good = set()
    sigs = head["sigs"] or []
    if not isinstance(sigs, list):
        return "threshold checkpoint sigs is not a list", None
    for entry in sigs:
        try:
            kid = entry["key_id"]
            sig = bytes.fromhex(entry["sig"])
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
        if kid in good or kid not in roster_pubs:
            continue
        if verify(bytes.fromhex(roster_pubs[kid]), body, sig):
            good.add(kid)
    if len(good) < threshold:
        return ("threshold checkpoint seq %d: only %d/%d valid distinct "
                "signatures" % (head["seq"], len(good), threshold)), None
    note = None
    # Offline-root authorization: v1 has no out-of-band root pinning, so
    # the roster's root signature cannot be independently verified. The
    # roster is authorized by the operator's manifest signature (via
    # checkpoints_digest -> roster_hash); this is stated, not hidden.
    root_kid = roster.get("root_key_id")
    if pinned_cp_key_ids is not None and root_kid in pinned_cp_key_ids:
        # The root key id was pinned; try to verify the roster signature
        # if its pubkey is available in the envelope.
        pubs = {k["key_id"]: k["public_key_hex"] for k in cp_keys}
        if root_kid in pubs:
            ok, err = _verify_roster(
                roster, bytes.fromhex(pubs[root_kid]))
            if not ok:
                return "roster root signature: %s" % err, None
            note = "roster root signature verified (root pinned)"
        else:
            note = ("roster root %r pinned but its pubkey is not in the "
                    "checkpoint_keys envelope: root signature not "
                    "independently verified" % root_kid)
    else:
        note = ("roster root signature not independently verified (no "
                "offline root pinned); roster authorized via the "
                "operator's manifest signature")
    return None, note


def _verify_roster_structure(roster):
    """Well-formedness checks for an A5 roster (no root-signature check).

    Returns (ok, error). Never raises on malformed input.
    """
    try:
        if not isinstance(roster, dict):
            return False, "roster is not an object"
        if roster.get("roster_version") != _ROSTER_VERSION:
            return False, "unsupported roster_version %r" % (
                roster.get("roster_version"),)
        if roster.get("role") != _ROSTER_ROLE:
            return False, "roster role %r is not %r" % (
                roster.get("role"), _ROSTER_ROLE)
        threshold = roster.get("threshold")
        keys = roster.get("keys")
        if not isinstance(keys, dict) or not keys:
            return False, "roster has no keys"
        if (not isinstance(threshold, int) or isinstance(threshold, bool)
                or not (1 <= threshold <= len(keys))):
            return False, "bad threshold %r for %d keys" % (
                threshold, len(keys))
        for kid, pubhex in keys.items():
            try:
                pub = bytes.fromhex(pubhex)
            except (TypeError, ValueError):
                return False, "bad pubkey hex for %r" % (kid,)
            if len(pub) != 32:
                return False, "bad pubkey length for %r" % (kid,)
            if hashlib.sha256(pub).hexdigest()[:16] != kid:
                return False, "key id %r does not match its pubkey" % (kid,)
        return True, None
    except (TypeError, ValueError, KeyError) as e:
        return False, "malformed roster: %s" % (e,)


def _verify_bundle_entry(bundle, slice_by_seq, heads, cp_keys,
                         check_head_membership=True, roster=None,
                         pinned_cp_key_ids=None):
    """Verify one inclusion bundle against the slice and heads."""
    if not isinstance(bundle, dict) or bundle.get("kind") != "inclusion":
        return "not an inclusion bundle"
    entry = bundle.get("entry") or {}
    seq = entry.get("seq")
    if not isinstance(seq, int):
        return "bundle entry has no seq"
    if bundle.get("index") != seq - 1:
        return "bundle index %r != seq-1" % (bundle.get("index"),)
    if seq not in slice_by_seq:
        return "bundle entry seq %d not in the transported slice" % seq
    s_entry = slice_by_seq[seq]
    if s_entry.get("hash") != entry.get("hash"):
        return ("bundle entry hash %r != slice hash %r"
                % (entry.get("hash"), s_entry.get("hash")))
    if _canonical_entry(entry) != _canonical_entry(s_entry):
        return "bundle entry content differs from the slice entry"
    cp = bundle.get("checkpoint") or {}
    if check_head_membership:
        match = [h for h in heads
                 if h.get("seq") == cp.get("seq")
                 and h.get("hash") == cp.get("hash")
                 and h.get("merkle_root") == cp.get("merkle_root")]
        if not match:
            return ("bundle checkpoint (seq %r) is not one of the "
                    "transported heads" % (cp.get("seq"),))
    else:
        # The receipt's checkpoint is newer than every window head: it
        # cannot be in checkpoints.jsonl, so its signature is verified
        # directly instead.
        err, _note = _verify_one_head(cp, cp_keys, roster,
                                      pinned_cp_key_ids)
        if err:
            return "receipt checkpoint: %s" % err
    try:
        proof = [bytes.fromhex(p) for p in bundle["proof"]]
        root = bytes.fromhex(cp["merkle_root"])
    except (KeyError, ValueError, TypeError):
        return "bundle proof/root malformed"
    try:
        tree_size = int(bundle["tree_size"])
    except (KeyError, ValueError, TypeError):
        return "bundle tree_size malformed"
    if not mk_verify_inclusion(_leaf_input(entry), root, seq - 1, proof,
                               tree_size):
        return "Merkle inclusion proof does NOT verify"
    return None


def v8_checkpoint_signatures(ctx):
    c = Check("V8", "V8 checkpoint signatures")
    try:
        heads = [_h for _h in
                 (json.loads(line) for line in
                  _read(ctx.dir, "checkpoints.jsonl").decode(
                      "utf-8").splitlines() if line.strip())]
    except (OSError, ValueError) as e:
        return c.fail("cannot read checkpoints.jsonl: %s" % e)
    cp_keys = ctx.cp_envelope
    if not isinstance(cp_keys, list):
        return c.fail("checkpoint_keys envelope is not a list")
    # The manifest's embedded checkpoints must be the heads the signed
    # checkpoints_digest commits to; otherwise the embedded copy is an
    # unsigned claim a consumer could mistake for authoritative.
    embedded = ctx.manifest.get("checkpoints")
    if not isinstance(embedded, list):
        return c.fail("manifest checkpoints is not a list")
    if hashlib.sha256(canonical(embedded)).hexdigest() \
            != ctx.manifest.get("checkpoints_digest"):
        return c.fail("manifest checkpoints do not hash to the signed "
                      "checkpoints_digest")
    if embedded != heads:
        return c.fail("manifest checkpoints != checkpoints.jsonl heads")
    # A5 roster (threshold heads only): the bundle ships it as
    # keys/checkpoint_roster.json; the roster_hash in each threshold head
    # must be its content hash.
    roster = None
    roster_path = os.path.join(ctx.dir, "keys", "checkpoint_roster.json")
    if os.path.isfile(roster_path):
        try:
            with open(roster_path, "rb") as f:
                roster = json.loads(f.read().decode("utf-8"))
        except (OSError, ValueError) as e:
            return c.fail("cannot read keys/checkpoint_roster.json: "
                          "%s" % e)
    pinned_cp = getattr(ctx, "pinned_cp_key_ids", None)
    notes = []
    for head in heads:
        err, note = _verify_one_head(head, cp_keys, roster, pinned_cp)
        if err is not None:
            return c.fail(err)
        if note:
            notes.append(note)
    # Merkle roots recomputed from the slice.
    slice_entries = ctx.slice_entries
    for head in heads:
        n = head["seq"]
        # Tree over entries 1..n: recompute from the slice only when the
        # slice covers 1..n; otherwise the root is attested by the
        # checkpoint signature alone (still verified above).
        if ctx.slice_from != 1 or ctx.slice_to < n:
            continue
        leaves = [_mk_leaf_hash(_leaf_input(e))
                  for e in slice_entries[:n]]
        if _recompute_root(leaves) != head["merkle_root"]:
            return c.fail("checkpoint seq %d merkle_root does not "
                          "recompute from the slice" % n)
    ctx.heads = heads
    ctx.roster = roster  # for V9/V12 inclusion-bundle verification
    detail = "%d checkpoint heads verified (Ed25519; threshold via A5)" \
        % len(heads)
    if notes:
        detail += "; " + "; ".join(sorted(set(notes)))
    return c.ok(detail)


def _recompute_root(leaves):
    """Merkle root hex over leaf hashes (RFC 6962 shape, largest-pow2
    split). Thin wrapper over the bytes recursion."""
    return _recompute_root_bytes(list(leaves)).hex()


def _recompute_root_bytes(nodes):
    while len(nodes) > 1:
        k = _mk_largest_pow2_lt(len(nodes))
        left = _recompute_root_bytes(nodes[:k])
        right = _recompute_root_bytes(nodes[k:])
        return _mk_node_hash(left, right)
    return nodes[0]


def v9_slice_integrity(ctx):
    c = Check("V9", "V9 log-slice integrity and inclusion")
    entries = ctx.slice_entries
    w = ctx.manifest["window"]
    seqs = [e.get("seq") for e in entries]
    if seqs != list(range(w["from_seq"], w["to_seq"] + 1)):
        return c.fail("slice seqs are not the contiguous window "
                      "%d..%d" % (w["from_seq"], w["to_seq"]))
    # V9a: the transported slice must equal the source log's entries.
    # (The bundle carries no source-log copy; the transported slice is
    #  the claim. Byte-equality against the source log is V12b's job
    #  when --log is given. Here we verify internal consistency.)
    for prev, cur in zip(entries, entries[1:]):
        if cur.get("prev_hash") != prev.get("hash"):
            return c.fail("chain break between seq %d and %d"
                          % (prev["seq"], cur["seq"]))
    if w["from_seq"] == 1:
        if entries[0].get("prev_hash") != "GENESIS":
            return c.fail("first entry prev_hash != GENESIS")
        anchor = "anchored at GENESIS"
    else:
        anchor = ("window starts at seq %d: first entry anchored by "
                  "inclusion bundles, not by genesis"
                  % w["from_seq"])
    # V9b: slice tip equals the window tip.
    if entries[-1].get("hash") != w["tip_hash"]:
        return c.fail("slice tip hash != manifest window tip_hash")
    # V9c: every entry's inclusion bundle verifies against a
    # V8-verified checkpoint head.
    bundles = ctx.manifest.get("inclusion_bundles") or []
    slice_by_seq = {e["seq"]: e for e in entries}
    cp_keys = ctx.cp_envelope
    verified = 0
    for b in bundles:
        seq = b.get("seq")
        bundle = b.get("bundle")
        if bundle is None:
            continue  # reduced coverage: counted below, not a failure
        err = _verify_bundle_entry(bundle, slice_by_seq, ctx.heads,
                                   cp_keys,
                                   roster=getattr(ctx, "roster", None),
                                   pinned_cp_key_ids=getattr(
                                       ctx, "pinned_cp_key_ids", None))
        if err:
            return c.fail("inclusion bundle seq %d: %s" % (seq, err))
        verified += 1
    # Reduced coverage is explicit, never silent: every entry without a
    # bundle must carry an unavailable_reason, and the manifest counts
    # must match the payload coverage.
    cov = (ctx.payload.get("log_slice") or {}).get("coverage") or []
    missing = [e for e in cov if not e.get("has_bundle")]
    for e in missing:
        if not e.get("unavailable_reason"):
            return c.fail("seq %d has no bundle and no reason"
                          % e.get("seq"))
    ic = ctx.manifest.get("inclusion_coverage") or {}
    if ic.get("with_bundle") != verified or \
            ic.get("entries") != len(entries):
        return c.fail("manifest inclusion_coverage counts do not match "
                      "the verified bundles")
    return c.ok("%d entries contiguous and hash-linked (%s); %d "
                "inclusion bundles verified, %d reduced-coverage "
                "entries with explicit reasons"
                % (len(entries), anchor, verified, len(missing)))


def v9d_entry_signatures(ctx):
    """V9d: per-entry Ed25519 audit signatures (wave-179 lane A).

    The manifest's audit_entry_signing block (bound into the
    operator-signed claim, so V7 already pins it) names the window's
    entry-signing key ids and the signed/total counts. Every slice
    entry carrying ed_sig/sig_key_id is verified here against the
    shipped checkpoint_keys envelope -- offline, with the auditor's
    pinned keys only, no shared HMAC secret.

    Wave-183: the block may additionally carry ``keyset`` (a
    sasanam-keyset/v1 document). When present, every signed entry's
    key version is resolved through it and entries signed by a
    *revoked* version fail loudly -- the compromise story for
    evidence. The keyset's own authorization signatures (rotation
    lineage, revocation records) are the online auditor's job
    (``gov.keyset.Keyset.verify``); inside the bundle the keyset rides
    in the operator-signed claim, so the standalone verifier trusts
    the operator's attestation here exactly as it trusts the key_ids
    list -- no crypto is duplicated in this module.

    Fail-closed notes: stripping ed_sig from entries does NOT break
    Merkle inclusion (the leaf deliberately excludes the sig envelope
    so re-signing never changes tree roots) -- the bound
    signed_entries count is what catches a strip. A forged ed_sig, an
    entry signed by a key the manifest does not bind, or a key missing
    from the envelope all fail loudly. HMAC-only windows (no block /
    zero signed) pass as not-applicable: absence of signatures is
    honest, not a failure.
    """
    c = Check("V9d", "V9d per-entry Ed25519 audit signatures")
    bound = ctx.manifest.get("audit_entry_signing") or {}
    entries = ctx.slice_entries
    signed = [e for e in entries
              if isinstance(e.get("ed_sig"), str)
              and isinstance(e.get("sig_key_id"), str)]
    if len(signed) != bound.get("signed_entries", 0):
        return c.fail("manifest audit_entry_signing.signed_entries=%r "
                      "!= slice entries carrying ed_sig (%d): signatures "
                      "stripped or injected"
                      % (bound.get("signed_entries"), len(signed)))
    if not signed:
        return c.na("no per-entry ed_sig in slice (HMAC-only window): "
                    "absence of signatures is honest, not a failure")
    bound_kids = bound.get("key_ids") or []
    if not bound_kids:
        return c.fail("slice carries entry signatures but the manifest "
                      "binds no audit_entry_signing key_ids")
    ks_map, ks_err = _v9d_keyset_statuses(bound)
    if ks_err is not None:
        return c.fail(ks_err)
    pubs = {}
    for kenv in ctx.cp_envelope or []:
        try:
            pubs[kenv["key_id"]] = bytes.fromhex(
                kenv["public_key_hex"])
        except (KeyError, ValueError, TypeError):
            continue  # V5 already validated the envelope itself
    for e in signed:
        kid = e["sig_key_id"]
        if kid not in bound_kids:
            return c.fail("entry seq %d signed by key %r not bound in "
                          "manifest audit_entry_signing"
                          % (e.get("seq"), kid))
        pub = pubs.get(kid)
        if pub is None:
            return c.fail("entry seq %d: signing key %r not in the "
                          "checkpoint_keys envelope"
                          % (e.get("seq"), kid))
        try:
            sig = bytes.fromhex(e["ed_sig"])
        except ValueError:
            return c.fail("entry seq %d: ed_sig is not hex"
                          % e.get("seq"))
        # Wave-183: _entry_sig_body dispatches on sig_key_version, so a
        # versioned entry verifies under the v2 body -- tampering with
        # or stripping the version changes the verified bytes and fails
        # here (no silent downgrade to the legacy body).
        if len(sig) != 64 or not verify(pub, _entry_sig_body(e), sig):
            return c.fail("entry seq %d: ed_sig does not verify"
                          % e.get("seq"))
        if ks_map is not None:
            by_ver, by_kid = ks_map
            ver = e.get("sig_key_version")
            if isinstance(ver, int) and not isinstance(ver, bool):
                status = by_ver.get(ver)
                if status is None:
                    return c.fail("entry seq %d names key version %r "
                                  "unknown to the bound keyset"
                                  % (e.get("seq"), ver))
            else:
                # Legacy entry (no version bound): resolve by key id.
                status = by_kid.get(kid)
                if status is None:
                    return c.fail("entry seq %d signed by key %r unknown "
                                  "to the bound keyset" % (e.get("seq"),
                                                           kid))
            if status == "revoked":
                return c.fail("entry seq %d signed by REVOKED key version "
                              "(keyset revocation enforced)"
                              % e.get("seq"))
    n = len(signed)
    note = ("%d entry signatures verified against manifest-bound "
            "keys (no shared secret needed)" % n)
    if ks_map is not None:
        note += "; keyset revocation enforced"
    return c.ok(note)


def _v9d_keyset_statuses(bound):
    """Wave-183: optional keyset revocation map for V9d.

    Reads ``audit_entry_signing.keyset`` (a sasanam-keyset/v1 document
    embedded by the bundle producer). Returns ``((by_version,
    by_key_id), None)`` mapping versions/key ids to their status
    strings, ``(None, None)`` when no keyset is bound (yesterday's
    behavior, unchanged), or ``(None, error)`` on a malformed keyset
    (fail-closed: a bundle that claims a keyset carries a usable one).

    Deliberately a light parse, not a re-implementation of
    ``gov.keyset``: the keyset's rotation/revocation authorization
    signatures are verified by the online auditor
    (``gov.keyset.Keyset.verify``). In here the keyset is attested by
    the operator's claim signature (V7), the same trust basis as the
    key_ids list.
    """
    doc = bound.get("keyset")
    if doc is None:
        return None, None
    if not isinstance(doc, dict):
        return None, ("manifest audit_entry_signing.keyset is not a "
                      "mapping")
    if doc.get("format") != "sasanam-keyset/v1":
        return None, ("manifest audit_entry_signing.keyset has unsupported "
                      "format %r" % (doc.get("format"),))
    versions = doc.get("versions")
    if not isinstance(versions, list) or not versions:
        return None, ("manifest audit_entry_signing.keyset carries no "
                      "versions")
    by_ver, by_kid = {}, {}
    for v in versions:
        if not isinstance(v, dict):
            return None, "keyset version entry is not a mapping"
        ver, kid, status = (v.get("version"), v.get("key_id"),
                            v.get("status"))
        if (isinstance(ver, bool) or not isinstance(ver, int)
                or not isinstance(kid, str)
                or status not in ("active", "verify-only", "revoked")):
            return None, "keyset version entry malformed"
        by_ver[ver] = status
        by_kid[kid] = status
    return (by_ver, by_kid), None


def v10_manifest_completeness(ctx):
    c = Check("V10", "V10 manifest completeness")
    p = ctx.payload
    w = ctx.manifest["window"]
    # All nine payload sections must be present.
    for section in PAYLOAD_SECTIONS:
        if section not in p:
            return c.fail("payload section %r missing" % section)
    # Every entry's coverage is accounted for.
    entries = ctx.slice_entries
    if w["entry_count"] != len(entries):
        return c.fail("window entry_count %r != slice length %d"
                      % (w["entry_count"], len(entries)))
    cov = (p.get("log_slice") or {}).get("coverage") or []
    if len(cov) != len(entries):
        return c.fail("payload coverage length %d != slice length %d"
                      % (len(cov), len(entries)))
    ic = ctx.manifest.get("inclusion_coverage") or {}
    if ic.get("entries") != len(entries):
        return c.fail("inclusion_coverage.entries %r != slice length "
                      "%d" % (ic.get("entries"), len(entries)))
    # No section may reference sequences outside the window.
    lo, hi = w["from_seq"], w["to_seq"]
    bad = []
    for path, seq in _payload_seq_refs(p):
        if not (isinstance(seq, int) and lo <= seq <= hi):
            bad.append("%s references seq %r (window %d..%d)"
                       % (path, seq, lo, hi))
    if bad:
        return c.fail("; ".join(bad[:5]))
    return c.ok("all 9 payload sections present; entry counts agree "
                "(%d); no section references sequences outside %d..%d"
                % (len(entries), lo, hi))


def _payload_seq_refs(payload):
    """Yield (path, seq) for every sequence number a payload section
    claims. Used by V10 to ensure no section references sequences
    outside the transported window.
    """
    def emit(node, path):
        if isinstance(node, dict):
            if isinstance(node.get("seq"), int) and "seq" in node:
                yield (path, node["seq"])
            for k, v in node.items():
                for item in emit(v, "%s.%s" % (path, k)):
                    yield item
        elif isinstance(node, list):
            for i, v in enumerate(node):
                for item in emit(v, "%s[%d]" % (path, i)):
                    yield item
    for section in ("policy", "decisions", "approvals", "citations"):
        node = payload.get(section)
        if node is not None:
            for item in emit(node, section):
                yield item


def v11_policy_consistency(ctx):
    c = Check("V11", "V11 policy-version consistency")
    p = ctx.payload.get("policy") or {}
    val = (p.get("policy_version") or {}).get("value")
    phash = (p.get("policy_hash") or {}).get("value")
    pinned = (p.get("pinned") or {}).get("value")
    if val is None and phash is None and pinned is None:
        return c.na("no policy_loaded record in the window: policy is "
                    "operator_must_supply-null (unattested, not a "
                    "failure)")
    # The manifest's stated policy must equal the slice's latest
    # policy_loaded (or a policy_pin event's stated values).
    loaded = [e for e in ctx.slice_entries
              if e.get("event") == "policy_loaded"]
    if not loaded:
        return c.fail("payload states policy values but the slice has "
                      "no policy_loaded record: the claim is unattested")
    latest = loaded[-1]
    problems = []
    # Spec §4.1.1 item 3: the builder renders a policy_loaded event with
    # no policy_version field as "unversioned" (never null, never guessed).
    # The verifier must apply the same rendering rule when comparing, or
    # a genuine bundle from an unversioned-policy log can never verify.
    want_ver = latest.get("policy_version", "unversioned")
    if val != want_ver:
        problems.append("policy_version %r != latest policy_loaded %r"
                        % (val, want_ver))
    if phash != latest.get("policy_hash"):
        problems.append("policy_hash mismatch against latest "
                        "policy_loaded")
    if pinned != latest.get("pinned"):
        problems.append("pinned %r != latest policy_loaded %r"
                        % (pinned, latest.get("pinned")))
    # Every policy_pin_mismatch / policy_pin_absent in the slice must
    # appear in the payload's policy_change_events.
    change_seqs = {ev.get("seq")
                   for ev in (p.get("policy_change_events") or [])}
    for e in ctx.slice_entries:
        if e.get("event") in ("policy_pin_mismatch", "policy_pin_absent") \
                and e.get("seq") not in change_seqs:
            problems.append("slice %s seq %d missing from "
                            "policy_change_events"
                            % (e.get("event"), e.get("seq")))
    if problems:
        return c.fail("; ".join(problems[:5]))
    return c.ok("payload policy == latest policy_loaded "
                "(version=%r); %d policy-change events accounted for"
                % (val, len(change_seqs)))


def v14_bundle_id(ctx):
    # v1 extension (beyond the spec's V1–V13): the deterministic EVB-…
    # bundle identity recomputes from the payload. This binds the
    # bundle_id to the payload bytes the operator signed.
    c = Check("V14", "V14 bundle id (v1 extension)")
    bid = (ctx.payload.get("bundle_meta") or {}).get("bundle_id")
    if not isinstance(bid, str) or not bid.startswith("EVB-"):
        return c.fail("bundle_id %r is not EVB-<hex>" % (bid,))
    probe = json.loads(json.dumps(ctx.payload))
    probe["bundle_meta"]["bundle_id"] = None
    expect = "EVB-" + hashlib.sha256(canonical(probe)).hexdigest()[:16]
    if bid != expect:
        return c.fail("bundle_id %r != recomputed %r" % (bid, expect))
    ctx.bundle_id = bid
    return c.ok("bundle_id %s recomputes deterministically" % bid)


def v15_provenance(ctx):
    # v1 extension (beyond the spec's V1–V13): every value field in the
    # payload must carry a provenance envelope, and operator_must_supply
    # fields must be null. This enforces the §2 honesty contract that
    # the normative checks assume.
    c = Check("V15", "V15 provenance (v1 extension)")
    bad = []

    def walk(node, path):
        if isinstance(node, dict):
            if "value" in node:
                prov = node.get("provenance")
                if not isinstance(prov, dict) or prov.get("kind") \
                        not in PROVENANCE_KINDS:
                    bad.append("%s: value without valid provenance"
                               % path)
                if node.get("operator_must_supply") is True and \
                        node.get("value") is not None:
                    bad.append("%s: operator_must_supply but value "
                               "is not null" % path)
            for k, v in node.items():
                if k == "provenance":
                    continue
                walk(v, "%s.%s" % (path, k))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, "%s[%d]" % (path, i))

    walk(ctx.payload, "payload")
    if bad:
        return c.fail("; ".join(bad[:5]))
    return c.ok("every value field carries provenance; "
                "operator_must_supply fields are null")


def v16_retention(ctx):
    # v1 extension (beyond the spec's V1–V13): retention-manifest schema.
    # Required by §7 item 7 ("the verifier checks their presence and
    # schema, not their truth").
    c = Check("V16", "V16 retention schema (v1 extension)")
    rm = ctx.payload.get("retention_manifest") or {}
    val = rm.get("value")
    if val is None:
        return c.na("retention manifest absent: operator_must_supply "
                    "(absence is honest, not a failure)")
    if not isinstance(val, dict):
        return c.fail("retention_manifest value is not a dict")
    for field, typ in (("retention_policy", str),
                       ("window_coverage", str),
                       ("archive_locations", list)):
        if field not in val or not isinstance(val[field], typ):
            return c.fail("retention field %r missing or not %s"
                          % (field, typ.__name__))
    if not all(isinstance(x, str) for x in val["archive_locations"]):
        return c.fail("archive_locations must be strings")
    return c.ok("retention schema valid (presence + schema only; "
                "truth not checked)")


# Wave-175 lane 1 (countersigned invocation receipts, R7 #7 Sigil shape).
# v1 extension (beyond the spec's normative thirteen): every
# ``invocation_receipt`` entry in the slice carries an executor
# countersignature over the executed invocation. The check re-verifies
# each receipt's Ed25519 signature against the pubkey carried in the
# receipt itself (self-consistency), and against --pin-receipt-pubkey
# pins when given (authorship). Standalone: uses only this file's
# vendored Ed25519 + the receipt's documented canonicalization
# (domain b"agent-governance/invocation-receipt/v1." + RFC 8785-style
# canonical JSON of the receipt minus "signature") — never imports
# gov.invocation_receipts, so the verifier stays install-free.
_RECEIPT_SIGNING_DOMAIN = b"agent-governance/invocation-receipt/v1."
_RECEIPT_AUDIENCE = "agent-governance-executor"


def _receipt_b64u_decode(text):
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _verify_receipt_standalone(receipt):
    """(ok, reason) — self-contained receipt verification for the bundle
    verifier. Mirrors gov.invocation_receipts.verify_receipt exactly;
    never raises on hostile input."""
    try:
        if not isinstance(receipt, dict):
            return False, "receipt is not a dict"
        body = {k: v for k, v in receipt.items() if k != "signature"}
        if receipt.get("receipt_version") != 1:
            return False, "unsupported receipt_version %r" % (
                receipt.get("receipt_version"),)
        for section in ("holder", "action", "policy", "outcome",
                        "authority"):
            if not isinstance(body.get(section), dict):
                return False, "missing section %r" % section
        if (not isinstance(body.get("challenge"), str)
                or not body["challenge"]):
            return False, "missing challenge"
        if body.get("audience") != _RECEIPT_AUDIENCE:
            return False, "audience mismatch"
        auth = body["authority"]
        pub = bytes.fromhex(auth.get("pubkey") or "")
        if len(pub) != 32:
            return False, "authority.pubkey not 32 bytes"
        if auth.get("kid") != hashlib.sha256(pub).digest()[:16].hex():
            return False, "authority.kid does not match pubkey"
        sig = _receipt_b64u_decode(receipt.get("signature") or "")
        signing_input = (_RECEIPT_SIGNING_DOMAIN
                         + json.dumps(body, sort_keys=True,
                                      separators=(",", ":"),
                                      ensure_ascii=True,
                                      default=str).encode("utf-8"))
        if not verify(pub, signing_input, sig):
            return False, "Ed25519 countersignature does not verify"
        return True, "ok"
    except (ValueError, TypeError, KeyError, AttributeError) as e:
        return False, "malformed receipt (%s: %s)" % (type(e).__name__, e)


def _verify_receipt_pinned_standalone(receipt, pinned_pubkey_hex):
    """_verify_receipt_standalone + authorship: the countersigning key
    must equal the out-of-band pinned operator key (full 32-byte pubkey
    hex, not a key id — same pin semantics as the evidence bundle's V6).
    Stdlib-only, like _verify_receipt_standalone."""
    ok, reason = _verify_receipt_standalone(receipt)
    if not ok:
        return False, reason
    try:
        pinned = bytes.fromhex((pinned_pubkey_hex or "").strip())
    except (ValueError, TypeError):
        return False, "pinned key not hex"
    if len(pinned) != 32:
        return False, "pinned key not 32 bytes"
    claimed = bytes.fromhex(receipt["authority"]["pubkey"])
    if not hmac.compare_digest(claimed, pinned):
        return False, "countersigning key is not the pinned operator key"
    return True, "ok"


def v17_invocation_receipts(ctx):
    c = Check("V17", "V17 invocation receipts (v1 extension)")
    entries = [e for e in ctx.slice_entries
               if e.get("event") == "invocation_receipt"]
    if not entries:
        return c.na("no invocation_receipt entries in the window: receipts "
                    "are an opt-in evidence extension (absence is honest, "
                    "not a failure)")
    bad = []
    for e in entries:
        ok, reason = _verify_receipt_standalone(e.get("receipt"))
        if not ok:
            bad.append("seq %s: %s" % (e.get("seq"), reason))
    pins = [p.lower() for p in (getattr(ctx, "receipt_pins", None) or [])]
    if pins:
        for e in entries:
            receipt = e.get("receipt")
            if not any(_verify_receipt_pinned_standalone(receipt, pin)[0]
                       for pin in pins):
                bad.append("seq %s: countersigning key is not a pinned "
                           "receipt key" % (e.get("seq"),))
    if bad:
        return c.fail("; ".join(bad[:5]))
    if pins:
        return c.ok("%d invocation receipts countersigned by pinned "
                    "key(s)" % len(entries))
    return c.ok("%d invocation receipts countersigned "
                "(self-consistent; authorship NOT established — no "
                "--pin-receipt-pubkey)" % len(entries))


def v12_receipt(ctx):
    c = Check("V12", "V12 export receipt")
    try:
        receipt = _load_json(ctx.dir, "receipt.json")
    except (OSError, ValueError) as e:
        return c.fail("cannot read receipt.json: %s" % e)
    entry = receipt.get("entry") or {}
    w = ctx.manifest["window"]
    for f in ("seq", "hash", "prev_hash"):
        if f not in entry:
            return c.fail("receipt entry missing %r" % f)
    if entry.get("prev_hash") != w["tip_hash"]:
        return c.fail("receipt prev_hash != window tip_hash: the "
                      "receipt does not chain onto the slice tip")
    if entry.get("seq") != w["to_seq"] + 1:
        return c.fail("receipt seq %r != window to_seq+1 %r"
                      % (entry.get("seq"), w["to_seq"] + 1))
    if entry.get("export_sha256") != ctx.manifest["export_sha256"]:
        return c.fail("receipt entry export_sha256 != manifest "
                      "export_sha256: the receipt is not for this bundle")
    # F173: the transported receipt.json's bundle-presence/reason must
    # match the operator-signed manifest receipt binding (whose
    # presence/reason rides in the V7-signed claim). A no-key attacker
    # who strips receipt.json's inclusion bundle (or fabricates its
    # unavailable_reason) fails here even though the entry itself is
    # untouched. Deliberately NOT a full-entry equality check: the
    # receipt binding is content-addressed (tip + digest + seq, checked
    # above), not bundle-instance-addressed — a genuine receipt entry
    # for the same export (same tip/digest/seq, e.g. re-minted at a
    # different wall-clock second) replays harmlessly (control B2).
    # Timestamps are operator wall-clock, not a v1 security property.
    signed_receipt = ctx.manifest.get("receipt")
    if not isinstance(signed_receipt, dict):
        return c.fail("manifest carries no signed receipt binding")
    if (receipt.get("bundle") is not None) != \
            (signed_receipt.get("bundle") is not None):
        return c.fail("receipt.json bundle-presence does not match the "
                      "operator-signed manifest receipt binding: the "
                      "transported receipt was altered after sealing")
    if receipt.get("unavailable_reason") != \
            signed_receipt.get("unavailable_reason"):
        return c.fail("receipt.json unavailable_reason does not match "
                      "the operator-signed manifest receipt binding: "
                      "the transported receipt was altered after sealing")
    bundle = receipt.get("bundle")
    detail = "receipt chains onto the slice tip"
    if bundle is None:
        reason = receipt.get("unavailable_reason")
        if not reason:
            return c.fail("receipt has no inclusion bundle and no "
                          "reason")
        detail += "; bundle unavailable (%s)" % reason
    else:
        # Verify the receipt's own inclusion bundle (its checkpoint is
        # newer than the window heads, so membership is not required —
        # its signature is verified directly).
        slice_by_seq = {e["seq"]: e for e in ctx.slice_entries}
        slice_by_seq[entry["seq"]] = entry
        err = _verify_bundle_entry(bundle, slice_by_seq, ctx.heads,
                                   ctx.cp_envelope,
                                   check_head_membership=False,
                                   roster=getattr(ctx, "roster", None),
                                   pinned_cp_key_ids=getattr(
                                       ctx, "pinned_cp_key_ids", None))
        if err:
            return c.fail("receipt inclusion bundle: %s" % err)
        detail += "; its inclusion bundle verifies"
    # V12b: with --log, the auditor's copy of the source log is
    # re-verified (hash-linkage; HMAC re-verification needs the log key,
    # which the auditor does not have) and the receipt entry must exist
    # in it with matching bytes.
    if getattr(ctx, "source_log", None):
        err = _v12b_source_log(ctx, entry)
        if err:
            return c.fail("V12b source log: %s" % err)
        detail += "; V12b: receipt found in the auditor's source-log copy"
    return c.ok(detail)


def _v12b_source_log(ctx, receipt_entry):
    """V12b: verify the receipt against the auditor's --log copy.

    Returns an error string, or None. Checks hash-linkage of the log
    copy (not HMACs — the auditor does not hold the log key) and that
    the receipt entry exists at its seq with matching hash/prev_hash
    and export_sha256.
    """
    try:
        with open(ctx.source_log, "rb") as f:
            lines = [ln for ln in f.read().decode("utf-8").splitlines()
                     if ln.strip()]
    except (OSError, ValueError) as e:
        return "cannot read --log %s: %s" % (ctx.source_log, e)
    try:
        entries = [json.loads(ln) for ln in lines]
    except ValueError as e:
        return "source log is not JSONL: %s" % e
    prev = None
    for e in entries:
        if not isinstance(e, dict) or "seq" not in e or "hash" not in e:
            return "source log has a malformed entry"
        if prev is not None and e.get("prev_hash") != prev.get("hash"):
            return ("source log hash-linkage breaks between seq %r and "
                    "%r" % (prev.get("seq"), e.get("seq")))
        prev = e
    match = [e for e in entries if e.get("seq") == receipt_entry["seq"]]
    if not match:
        return ("receipt seq %r not present in the source-log copy"
                % receipt_entry["seq"])
    src = match[0]
    for f in ("hash", "prev_hash", "export_sha256"):
        if src.get(f) != receipt_entry.get(f):
            return ("source-log receipt entry field %r does not match "
                    "receipt.json" % f)
    return None


def v13_citation_approval(ctx):
    c = Check("V13", "V13 citation/approval cross-consistency")
    cit = ctx.payload.get("citations") or {}
    problems = []
    # An accepted citation record cannot have self-planted citations.
    for chk in (cit.get("citation_checks") or []):
        if chk.get("accepted") is True and \
                (chk.get("n_self_planted") or 0) > 0:
            problems.append("citation check seq %r accepted with "
                            "n_self_planted=%r"
                            % (chk.get("seq"), chk.get("n_self_planted")))
    # Verdict counts must sum to the citation count.
    counts = cit.get("verdict_counts") or {}
    if counts:
        total = sum(v for v in counts.values()
                    if isinstance(v, int) and not isinstance(v, bool))
        n_cit = None
        for chk in (cit.get("citation_checks") or []):
            if isinstance(chk.get("n_citations"), int):
                n_cit = (n_cit or 0) + chk["n_citations"]
        # n_citations is per-check; compare against the sum of the
        # verdict counts only when both are present.
        if n_cit is not None and total != n_cit:
            problems.append("verdict_counts sum %d != n_citations sum "
                            "%d" % (total, n_cit))
    # Approval section: declared gov.approvals vocabulary only; unknown
    # event names are flagged, not coerced. Also flag approval-like
    # events in the slice that the payload silently dropped.
    appr = ctx.payload.get("approvals") or {}
    for key in appr:
        if key == "_honesty_note":
            continue
        if key not in APPROVAL_EVENTS:
            problems.append("approvals section uses undeclared event "
                            "name %r" % key)
    slice_events = {e.get("event") for e in ctx.slice_entries}
    for ev in slice_events:
        if ev and "approv" in ev and ev not in APPROVAL_EVENTS \
                and ev not in appr:
            problems.append("slice has approval-like event %r not in "
                            "the declared vocabulary and not "
                            "represented in the payload" % ev)
    if problems:
        return c.fail("; ".join(problems[:5]))
    return c.ok("citation verdicts consistent; approval vocabulary "
                "exact (%d declared events)" % len(APPROVAL_EVENTS))


class Ctx:
    pass


def _run_checks_v4_v17(ctx, run, checks):
    """V4–V16 in spec order. Returns False when V4 fails (remaining
    checks are meaningless without the payload); True otherwise. Any
    unexpected exception propagates to verify_bundle's outer guard.
    F151: if V6 fails (wrong pin), V7 does not run against the wrong
    keys — v7_operator_signature returns not_applicable in that case.
    """
    run(v4_payload_digest)
    if any(c.status == "fail" for c in checks[-1:]):
        return False
    run(v5_key_envelope)
    run(v6_authorship_pin)
    run(v7_operator_signature)
    run(v8_checkpoint_signatures)
    run(v9_slice_integrity)
    run(v9d_entry_signatures)
    run(v10_manifest_completeness)
    run(v11_policy_consistency)
    run(v12_receipt)
    run(v13_citation_approval)
    # v1 extensions (beyond the spec's normative thirteen).
    run(v14_bundle_id)
    run(v15_provenance)
    run(v16_retention)
    run(v17_invocation_receipts)
    return True


# F174: the operator_id disclaimer is the fix — the verifier must never
# let key pinning be mistaken for verification of the claimed name.
CLAIMED_OPERATOR_DISCLAIMER = ("operator-supplied, not independently "
                               "verified")


def _claimed_operator(ctx):
    """F174: render bundle_meta.operator_id, always labeled.

    The value is an operator assertion (payload provenance honestly
    records ``operator_supplied``); the disclaimer rides with it in
    both text and JSON summaries so an auditor skimming the verdict
    cannot mistake the pinned key_id for verification of the name.
    """
    payload = getattr(ctx, "payload", None) or {}
    op_id = (payload.get("bundle_meta") or {}).get("operator_id") or {}
    return {
        "value": op_id.get("value"),
        "disclaimer": CLAIMED_OPERATOR_DISCLAIMER,
    }


def _discovery_snapshot(ctx):
    """H5 (wave-117): render the discovery snapshot, if present.

    The section is OPTIONAL (not in PAYLOAD_SECTIONS): old bundles
    without it stay V10-green. Returns the snapshot dict verbatim
    (already inside the signed payload) or None.
    """
    payload = getattr(ctx, "payload", None) or {}
    return payload.get("discovery")


def verify_bundle(bundle_dir, pins=(), pinned_cp_key_ids=None,
                   source_log=None, receipt_pins=()):
    """Run V1–V17. Returns (exit_code, checks, summary_dict)."""
    ctx = Ctx()
    ctx.dir = bundle_dir
    ctx.pins = list(pins)
    ctx.pinned_cp_key_ids = (list(pinned_cp_key_ids)
                             if pinned_cp_key_ids else None)
    ctx.source_log = source_log
    ctx.receipt_pins = list(receipt_pins)
    ctx.pin_failed = False
    checks = []

    def run(fn):
        c = fn(ctx)
        checks.append(c)
        return c

    # V1/V2 first: without the digest and the files, nothing else is
    # meaningful.
    if not os.path.isdir(bundle_dir):
        c = Check("V0", "bundle dir")
        c.fail("not a directory: %r" % (bundle_dir,))
        return 3, [c], {}
    ctx.file_count = sum(len(files) for _r, _d, files
                         in os.walk(bundle_dir))
    run(v1_version_gate)
    run(v2_required_files)
    run(v3_transport_digest)
    if any(c.status == "fail" for c in checks):
        return 1, checks, {}
    # Load manifest + envelopes before the checks that need them.
    try:
        ctx.manifest = _load_json(bundle_dir, "manifest.json")
        ctx.operator_envelope = _load_json(
            bundle_dir, "keys/operator_ed25519.json")
        ctx.cp_envelope = _load_json(
            bundle_dir, "keys/checkpoint_keys.json")
    except (OSError, ValueError) as e:
        c = Check("V0", "load manifest/envelopes")
        c.fail("cannot parse: %s" % e)
        checks.append(c)
        return 1, checks, {}
    # Load the slice.
    try:
        raw = _read(bundle_dir, "log_slice.jsonl").decode("utf-8")
        ctx.slice_entries = [json.loads(line) for line in raw.splitlines()
                             if line.strip()]
    except (OSError, ValueError) as e:
        c = Check("V0", "load slice")
        checks.append(c.fail("cannot parse log_slice.jsonl: %s" % e))
        return 1, checks, {}
    w = ctx.manifest.get("window")
    if not isinstance(w, dict):
        w = {}
    ctx.slice_from = w.get("from_seq")
    ctx.slice_to = w.get("to_seq")
    ctx.heads = []  # filled by V8; V12 tolerates V8 having failed

    # V4-V16 run under one outer guard: hostile bundle data must FAIL
    # cleanly (a named check, exit 1), never crash with a traceback.
    try:
        _run_checks_v4_v17(ctx, run, checks)
    except Exception as e:  # hostile/malformed bundle: fail, don't crash
        c = Check("V0", "bundle fatal")
        c.fail("unexpected error while verifying bundle: %r" % (e,))
        checks.append(c)
        return 1, checks, {}

    failed = [c for c in checks if c.status == "fail"]
    if failed:
        code = 1
        verdict = "FAILED"
    elif not pins:
        code = 2
        verdict = "SELF_CONSISTENT"
    else:
        code = 0
        verdict = "VERIFIED"
    v6 = next((c for c in checks if c.id == "V6"), None)
    pin_ok = getattr(ctx, "pin_ok", False)
    summary = {
        "verdict": verdict,
        "exit_code": code,
        "bundle_id": getattr(ctx, "bundle_id", None),
        "bundle_digest": getattr(ctx, "bundle_digest", None),
        "authorship": {
            "pinned": pin_ok,
            "key_id": getattr(ctx, "authorship_key_id", None) if pin_ok else None,
        },
        # F174: the claimed operator name, always with its disclaimer.
        "claimed_operator": _claimed_operator(ctx),
        # H5: the discovery snapshot, when the bundle carries one.
        "discovery": _discovery_snapshot(ctx),
        "checks": [c.as_dict() for c in checks],
        "failures": [{"id": c.id, "name": c.name, "detail": c.detail}
                     for c in failed],
        "coverage": {
            "entries": len(getattr(ctx, "slice_entries", []) or []),
            "with_inclusion_bundle": sum(
                1 for b in (ctx.manifest.get("inclusion_bundles") or [])
                if b.get("bundle")),
        },
        "what_this_does_not_prove": HONESTY_FOOTER_LIST,
    }
    return code, checks, summary


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Verify an evidence-bundle v1 directory (stdlib only).")
    ap.add_argument("bundle_dir", help="bundle directory to verify")
    ap.add_argument("--pin-operator-pubkey", action="append", default=[],
                    help="operator Ed25519 public key hex (full 32-byte "
                         "key, out-of-band). Repeatable. Without a pin "
                         "the best verdict is SELF_CONSISTENT.")
    ap.add_argument("--pin-checkpoint-key-ids", action="append", default=[],
                    help="expected checkpoint signer key ids (key_id == "
                         "sha256(pub)[:16]). Repeatable; the envelope / "
                         "roster set must match exactly.")
    ap.add_argument("--pin-receipt-pubkey", action="append", default=[],
                    help="invocation-receipt countersigning Ed25519 public "
                         "key hex (full 32-byte key, out-of-band). "
                         "Repeatable. V17 checks authorship against these; "
                         "without a pin V17 is self-consistency only.")
    ap.add_argument("--log", default=None, metavar="PATH",
                    help="auditor's copy of the source audit log: V12b "
                         "re-verifies the receipt against it.")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        # argparse usage errors exit 2; the bundle contract reserves
        # exit 3 for all usage/config errors.
        return 3 if e.code != 0 else 0
    for p in args.pin_operator_pubkey:
        try:
            raw = bytes.fromhex(p)
        except ValueError:
            print("error: --pin-operator-pubkey is not hex", file=sys.stderr)
            return 3
        if len(raw) != 32:
            print("error: --pin-operator-pubkey is not 32 bytes",
                  file=sys.stderr)
            return 3
    for kid in args.pin_checkpoint_key_ids:
        if len(kid) != 16:
            print("error: --pin-checkpoint-key-ids entries must be "
                  "16-hex-char key ids", file=sys.stderr)
            return 3
        try:
            bytes.fromhex(kid)
        except ValueError:
            print("error: --pin-checkpoint-key-ids entries must be hex",
                  file=sys.stderr)
            return 3
    for p in args.pin_receipt_pubkey:
        try:
            raw = bytes.fromhex(p)
        except ValueError:
            print("error: --pin-receipt-pubkey is not hex", file=sys.stderr)
            return 3
        if len(raw) != 32:
            print("error: --pin-receipt-pubkey is not 32 bytes",
                  file=sys.stderr)
            return 3
    code, checks, summary = verify_bundle(
        args.bundle_dir, pins=args.pin_operator_pubkey,
        pinned_cp_key_ids=args.pin_checkpoint_key_ids or None,
        source_log=args.log, receipt_pins=args.pin_receipt_pubkey)
    if args.format == "json":
        payload = summary or {
            "verdict": "FAILED",
            "exit_code": code,
            "authorship": {"pinned": False, "key_id": None},
            "claimed_operator": {"value": None,
                                 "disclaimer":
                                 CLAIMED_OPERATOR_DISCLAIMER},
            "checks": [c.as_dict() for c in checks],
            "failures": [{"id": c.id, "name": c.name, "detail": c.detail}
                         for c in checks if c.status == "fail"],
            "coverage": {"entries": 0, "with_inclusion_bundle": 0},
            "discovery": None,
            "what_this_does_not_prove": HONESTY_FOOTER_LIST,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for c in checks:
            mark = {"pass": "PASS", "fail": "FAIL",
                    "not_applicable": "N/A"}[c.status]
            line = "[%s] %s %s" % (mark, c.id, c.name)
            if c.detail:
                line += " — %s" % c.detail
            print(line)
        print()
        if summary:
            print("verdict: %s (exit %d)" % (summary["verdict"],
                                             summary["exit_code"]))
            auth = summary["authorship"]
            if auth.get("pinned"):
                print("authorship: pinned operator %s" % auth.get("key_id"))
            else:
                print("authorship: unpinned (self-consistency only)")
            # F174: the claimed name is rendered WITH its disclaimer —
            # disclosure, not rejection.
            cop = summary.get("claimed_operator") or {}
            cval = cop.get("value")
            print("claimed operator: %s (%s)"
                  % (cval if cval is not None else "(not supplied)",
                     cop.get("disclaimer",
                             CLAIMED_OPERATOR_DISCLAIMER)))
            # H5 (wave-117): the discovery snapshot, loud when nonzero
            # candidates, quiet for the zero control, absent when the
            # bundle was built without a discovery ledger.
            disc = summary.get("discovery") or {}
            if disc:
                n = disc.get("unregistered_candidate_count") or 0
                kinds = ", ".join(disc.get("candidate_kinds") or [])
                inv = disc.get("inventoried_count") or 0
                if n:
                    print("discovery: %d unregistered candidates at "
                          "export time (kinds: %s; inventoried: %d) -- "
                          "UNREGISTERED AGENTS PRESENT"
                          % (n, kinds or "(none listed)", inv))
                else:
                    print("discovery: no unregistered candidates at "
                          "export time (inventoried: %d)" % inv)
            if summary["failures"]:
                print("failures:")
                for f in summary["failures"]:
                    print("  - %s %s: %s" % (f["id"], f["name"],
                                             f["detail"]))
        else:
            print("verdict: FAILED (exit %d)" % code)
        print()
        print("Verify procedure: docs/evidence-bundle-spec.md §4.3 "
              "(V1–V13).")
        print()
        print("WHAT THIS PROVES: the transported log slice is internally "
              "consistent and bound to the operator's signed manifest; "
              "every transported entry is anchored by a checkpoint the "
              "operator's keys signed.")
        print()
        print(HONESTY_FOOTER)
    return code


if __name__ == "__main__":
    sys.exit(main())
