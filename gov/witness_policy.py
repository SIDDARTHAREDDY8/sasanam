"""Signed witness-policy artifact (open reimplementation).

Wave-322 lane 2 (wave-321 witness/monitor prospectus, direction-brief
item 1 -- the greenfield that blocks everything): no deployed standard
ships the witness set as a signed artifact (Sigstore's TrustedRoot has
no witness-key field; witness-network.org lists are unsigned). This
module defines Sasanam's own format, borrowing the grammar:

* Sigsum's policy-file shape for the witness list (entries = vkeys +
  operator identity + validity window);
* TUF-style role/key/threshold semantics for the signature envelope
  (the policy is signed by threshold-authorized policy signers; the
  AUTHORITY is the auditor's pinned trust anchor, never the document);
* witness-network ``logs/v0`` line grammar for log/witness identity
  (the ``name+hex(keyID)+base64(sigtype||pubkey)`` vkey, validated by
  ``gov/checkpoint_note.py`` -- the keyID must recompute from the key
  material).

What it provides:

* :func:`seal_policy` -- threshold-sign a policy body (canonical JSON
  bytes). Sealing is fail-closed on shape: a malformed body cannot be
  sealed.
* :func:`verify_policy_document` -- full verification against the
  trust anchor. Returns the verified policy dict; raises
  :class:`WitnessPolicyError` (coded) on any failure. Never returns
  soft False (the witness_consistency contract).
* :func:`check_policy_update` -- verifies a new document AND enforces
  TUF N+1 version monotonicity plus policy_id continuity: the
  stale-policy replay defense. A key DROP requires a threshold-signed
  strictly-newer version -- the threshold signature IS the drop
  authorization; there is no separate drop ceremony.
* :func:`active_witnesses` -- the quorum-eligible set right now
  (validity window covers ``now``, status qualified/usable).
* :func:`verifier_inputs` -- ``{operator_vkeys, witness_vkeys,
  quorum_k, policy_id, policy_version}``: the exact inputs for
  ``gov.witness_consistency.require_cosignatures``. A client holding
  only the policy artifact verifies a fresh checkpoint with zero log
  calls.

Key rotation composes by construction: unknown signature keyids are
IGNORED (MUST-ignore, the C2SP rotation rule); a KNOWN signer's bad
signature refuses ``witness-policy-signature-invalid`` (forgery
signal, never ignored -- the witness_consistency cosignature rule).
Rotation ADDS keys in a newer signed version; it never silently drops
one.

The module loads ``checkpoint_note`` and ``ed25519`` by file path (the
checkpoint_note zero-network pattern): no top-level ``gov`` imports,
so the offline verifier's import closure stays socket-free. Stdlib
only. $0 spend, synthetic/local testing.

HONEST RESIDUALS (never claimed away):

* Cross-restart replay protection needs the auditor's persisted
  last-seen-version watermark (TUF-adapted); within a run the caller
  holds the verified policy object. The crossing ceremony is the
  freshness channel for the offline case.
* ``max_checkpoint_staleness_seconds`` is carried by the policy but
  ENFORCED by the monitor lane via
  ``witness_consistency.check_freshness``; this module does not
  re-implement freshness.
* ``readonly``/``retired`` witnesses are kept for audit but never
  counted toward quorum -- only ``qualified``/``usable`` count.
* Clock is caller-supplied (``now``); no skew allowance. A future
  ``issued_at`` is ACCEPTED (pre-provisioned successor, the
  trustroot.proto contract); expiry still fails closed.
"""

from __future__ import annotations

import importlib.util
import json
import os
import time

SCHEMA = "witness-policy/v1"

# Decision codes (registered in gov/decision_codes.py, domain 'witness').
# witness-policy-malformed is the pre-existing witness_consistency config
# code, reused here with the same meaning (shape violations).
WITNESS_POLICY_MALFORMED = "witness-policy-malformed"
WITNESS_POLICY_UNKNOWN_FIELD = "witness-policy-unknown-field"
WITNESS_POLICY_EXPIRED = "witness-policy-expired"
WITNESS_POLICY_THRESHOLD_INVALID = "witness-policy-threshold-invalid"
WITNESS_POLICY_DUPLICATE_WITNESS = "witness-policy-duplicate-witness"
WITNESS_POLICY_KEY_UNVERIFIABLE = "witness-policy-key-unverifiable"
WITNESS_POLICY_SIGNATURE_INVALID = "witness-policy-signature-invalid"
WITNESS_POLICY_THRESHOLD_UNMET = "witness-policy-threshold-unmet"
WITNESS_POLICY_VERSION_ROLLBACK = "witness-policy-version-rollback"
WITNESS_POLICY_ID_MISMATCH = "witness-policy-id-mismatch"

__all__ = [
    "SCHEMA",
    "WitnessPolicyError",
    "seal_policy",
    "verify_policy_document",
    "check_policy_update",
    "active_witnesses",
    "verifier_inputs",
    "canonical_policy_bytes",
]


class WitnessPolicyError(Exception):
    """A coded witness-policy failure. ``code`` is the machine code."""

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("[%s] %s" % (code, detail) if detail else
                         "[%s]" % (code,))


def _refuse(code, detail=""):
    raise WitnessPolicyError(code, detail)


# ---------------------------------------------------------------------------
# Zero-network dependency loading (the checkpoint_note pattern).
# ---------------------------------------------------------------------------

_cn = None
_ed = None


def _deps():
    """Load checkpoint_note + ed25519 from sibling files. No top-level
    gov imports: the offline verifier loads this module by file path."""
    global _cn, _ed
    if _cn is None or _ed is None:
        base = os.path.dirname(os.path.abspath(__file__))
        try:
            cspec = importlib.util.spec_from_file_location(
                "sasanam_standalone_checkpoint_note_witpol",
                os.path.join(base, "checkpoint_note.py"))
            cn = importlib.util.module_from_spec(cspec)
            cspec.loader.exec_module(cn)
            espec = importlib.util.spec_from_file_location(
                "sasanam_standalone_ed25519_witpol",
                os.path.join(base, "ed25519.py"))
            ed = importlib.util.module_from_spec(espec)
            espec.loader.exec_module(ed)
        except Exception as exc:  # noqa: BLE001
            _refuse(WITNESS_POLICY_MALFORMED,
                    "cannot load checkpoint_note/ed25519: %s" % (exc,))
        _cn, _ed = cn, ed
    return _cn, _ed


def canonical_policy_bytes(policy):
    """Canonical JSON bytes: sort_keys, no whitespace, ASCII. The exact
    bytes every policy signer and verifier hashes. Key order in the
    presented dict is irrelevant; any value change breaks signatures."""
    try:
        return json.dumps(policy, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _refuse(WITNESS_POLICY_MALFORMED,
                "policy not JSON-serializable: %s" % (exc,))


# ---------------------------------------------------------------------------
# Shape checking (fail closed on shape drift).
# ---------------------------------------------------------------------------

_POLICY_FIELDS = frozenset([
    "schema", "policy_id", "version", "issued_at", "expires_at",
    "threshold", "log", "witnesses", "policy_signers", "policy_threshold",
    "max_checkpoint_staleness_seconds",
])

_WITNESS_FIELDS = frozenset([
    "name", "vkey", "operator", "contact", "not_before", "not_after",
    "status",
])

_LOG_FIELDS = frozenset(["name", "vkey"])

_SIGNER_FIELDS = frozenset(["key_id", "public_key"])

_WITNESS_STATUSES = frozenset(["qualified", "usable", "readonly",
                               "retired"])

# Statuses that count toward the cosignature quorum.
_QUORUM_STATUSES = frozenset(["qualified", "usable"])


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _no_unknown(obj, allowed, where):
    extra = set(obj) - allowed
    if extra:
        _refuse(WITNESS_POLICY_UNKNOWN_FIELD,
                "%s: unknown field(s) %s -- fail closed on shape drift"
                % (where, sorted(extra, key=repr)))


def _nonempty_str(obj, field, where):
    v = obj.get(field)
    if not isinstance(v, str) or not v.strip():
        _refuse(WITNESS_POLICY_MALFORMED,
                "%s: %r must be a non-empty str" % (where, field))
    return v.strip()


def _checked_vkey(vkey, where):
    """A vkey string whose keyID recomputes from the key material."""
    cn, _ed = _deps()
    if not isinstance(vkey, str) or not vkey:
        _refuse(WITNESS_POLICY_KEY_UNVERIFIABLE,
                "%s: vkey must be a non-empty str" % (where,))
    try:
        parsed = cn.parse_vkey(vkey)
    except (ValueError, TypeError) as exc:
        _refuse(WITNESS_POLICY_KEY_UNVERIFIABLE,
                "%s: vkey does not parse / keyID does not recompute: %s"
                % (where, exc))
    return parsed


def _checked_log(obj, where):
    if not isinstance(obj, dict):
        _refuse(WITNESS_POLICY_MALFORMED,
                "%s: log must be a mapping" % (where,))
    _no_unknown(obj, _LOG_FIELDS, where)
    name = _nonempty_str(obj, "name", where)
    parsed = _checked_vkey(obj.get("vkey"), where + ".vkey")
    if parsed["name"] != name:
        _refuse(WITNESS_POLICY_MALFORMED,
                "%s: vkey name %r != entry name %r" % (
                    where, parsed["name"], name))
    return {"name": name, "vkey": obj["vkey"], "parsed": parsed}


def _checked_witness(entry, where):
    if not isinstance(entry, dict):
        _refuse(WITNESS_POLICY_MALFORMED,
                "%s: witness must be a mapping" % (where,))
    _no_unknown(entry, _WITNESS_FIELDS, where)
    name = _nonempty_str(entry, "name", where)
    parsed = _checked_vkey(entry.get("vkey"), where + ".vkey")
    if parsed["name"] != name:
        _refuse(WITNESS_POLICY_MALFORMED,
                "%s: vkey name %r != entry name %r -- the vkey name is "
                "the signed-note key identity; a mismatch misleads "
                "audits" % (where, parsed["name"], name))
    operator = _nonempty_str(entry, "operator", where)
    contact = _nonempty_str(entry, "contact", where)
    not_before = entry.get("not_before")
    not_after = entry.get("not_after")
    if not _is_int(not_before) or not _is_int(not_after):
        _refuse(WITNESS_POLICY_MALFORMED,
                "%s: not_before/not_after must be ints" % (where,))
    if not_before > not_after:
        _refuse(WITNESS_POLICY_MALFORMED,
                "%s: not_before (%d) > not_after (%d)" % (
                    where, not_before, not_after))
    status = entry.get("status")
    if status not in _WITNESS_STATUSES:
        _refuse(WITNESS_POLICY_MALFORMED,
                "%s: status %r not in %s" % (
                    where, status, sorted(_WITNESS_STATUSES)))
    return {"name": name, "vkey": entry["vkey"], "operator": operator,
            "contact": contact, "not_before": not_before,
            "not_after": not_after, "status": status, "parsed": parsed}


def _checked_policy_signer(entry, where):
    if not isinstance(entry, dict):
        _refuse(WITNESS_POLICY_MALFORMED,
                "%s: policy signer must be a mapping" % (where,))
    _no_unknown(entry, _SIGNER_FIELDS, where)
    key_id = entry.get("key_id")
    public_key = entry.get("public_key")
    for label, v in (("key_id", key_id), ("public_key", public_key)):
        if not isinstance(v, str):
            _refuse(WITNESS_POLICY_MALFORMED,
                    "%s: %s must be a hex str" % (where, label))
        try:
            raw = bytes.fromhex(v)
        except ValueError:
            _refuse(WITNESS_POLICY_MALFORMED,
                    "%s: %s is not hex" % (where, label))
        if len(raw) != 32:
            _refuse(WITNESS_POLICY_MALFORMED,
                    "%s: %s must be 32 bytes" % (where, label))
    return {"key_id": key_id.lower(), "public_key": public_key.lower()}


def _check_policy_body(body):
    """Validate the policy body shape. Returns a normalized dict."""
    if not isinstance(body, dict):
        _refuse(WITNESS_POLICY_MALFORMED, "policy must be a mapping")
    _no_unknown(body, _POLICY_FIELDS, "policy")
    if body.get("schema") != SCHEMA:
        _refuse(WITNESS_POLICY_MALFORMED,
                "policy schema %r != %r" % (body.get("schema"), SCHEMA))
    policy_id = _nonempty_str(body, "policy_id", "policy")
    version = body.get("version")
    if not _is_int(version) or version < 1:
        _refuse(WITNESS_POLICY_MALFORMED,
                "policy version must be an int >= 1")
    issued_at = body.get("issued_at")
    expires_at = body.get("expires_at")
    if not _is_int(issued_at) or not _is_int(expires_at):
        _refuse(WITNESS_POLICY_MALFORMED,
                "issued_at/expires_at must be ints")
    if expires_at <= issued_at:
        _refuse(WITNESS_POLICY_MALFORMED,
                "expires_at (%d) must exceed issued_at (%d)" % (
                    expires_at, issued_at))
    witnesses = body.get("witnesses")
    if not isinstance(witnesses, (list, tuple)) or not witnesses:
        _refuse(WITNESS_POLICY_MALFORMED,
                "witnesses must be a non-empty list")
    # Structural pass first: names must be present and unique before
    # any deep validation (so a duplicated name is named as such,
    # not masked by a later per-entry check).
    names = []
    for i, e in enumerate(witnesses):
        if not isinstance(e, dict):
            _refuse(WITNESS_POLICY_MALFORMED,
                    "witnesses[%d] must be a mapping" % (i,))
        n = e.get("name")
        if not isinstance(n, str) or not n.strip():
            _refuse(WITNESS_POLICY_MALFORMED,
                    "witnesses[%d].name must be a non-empty str" % (i,))
        names.append(n.strip())
    if len(set(names)) != len(names):
        _refuse(WITNESS_POLICY_DUPLICATE_WITNESS,
                "witness names must be unique -- duplicates would let one "
                "operator fill two quorum slots")
    checked_wit = [_checked_witness(e, "witnesses[%d]" % i)
                   for i, e in enumerate(witnesses)]
    vkeys = [w["vkey"] for w in checked_wit]
    if len(set(vkeys)) != len(vkeys):
        _refuse(WITNESS_POLICY_DUPLICATE_WITNESS,
                "witness vkey strings must be unique")
    # Compare KEY MATERIAL, not vkey strings: the vkey embeds the
    # name, so the same 32-byte key under two names yields different
    # strings but one operator filling two quorum slots.
    pubkeys = [w["parsed"]["public_key"] for w in checked_wit]
    if len(set(pubkeys)) != len(pubkeys):
        _refuse(WITNESS_POLICY_DUPLICATE_WITNESS,
                "witness keys must be unique -- the same key under two "
                "names would let one key fill two quorum slots")
    threshold = body.get("threshold")
    if not _is_int(threshold) or not 1 <= threshold <= len(checked_wit):
        _refuse(WITNESS_POLICY_THRESHOLD_INVALID,
                "threshold must satisfy 1 <= k <= n (%d witnesses)"
                % len(checked_wit))
    log = _checked_log(body.get("log"), "log")
    raw_signers = body.get("policy_signers")
    if not isinstance(raw_signers, (list, tuple)) or not raw_signers:
        _refuse(WITNESS_POLICY_MALFORMED,
                "policy_signers must be a non-empty list")
    signers = [_checked_policy_signer(e, "policy_signers[%d]" % i)
               for i, e in enumerate(raw_signers)]
    sids = [s["key_id"] for s in signers]
    if len(set(sids)) != len(sids):
        _refuse(WITNESS_POLICY_MALFORMED,
                "policy_signers key_ids must be unique")
    policy_threshold = body.get("policy_threshold")
    if (not _is_int(policy_threshold)
            or not 1 <= policy_threshold <= len(signers)):
        _refuse(WITNESS_POLICY_THRESHOLD_INVALID,
                "policy_threshold must satisfy 1 <= t <= %d signers"
                % len(signers))
    staleness = body.get("max_checkpoint_staleness_seconds")
    if not _is_int(staleness) or staleness < 1:
        _refuse(WITNESS_POLICY_MALFORMED,
                "max_checkpoint_staleness_seconds must be an int >= 1")
    return {"policy_id": policy_id, "version": version,
            "issued_at": issued_at, "expires_at": expires_at,
            "threshold": threshold, "log": log, "witnesses": checked_wit,
            "policy_signers": signers, "policy_threshold": policy_threshold,
            "max_checkpoint_staleness_seconds": staleness}


def _check_trust_anchor(anchor):
    if not isinstance(anchor, dict):
        _refuse(WITNESS_POLICY_MALFORMED,
                "trust_anchor must be a mapping")
    raw = anchor.get("policy_signers")
    if not isinstance(raw, (list, tuple)) or not raw:
        _refuse(WITNESS_POLICY_MALFORMED,
                "trust_anchor.policy_signers must be a non-empty list")
    signers = [_checked_policy_signer(e, "trust_anchor.policy_signers[%d]" % i)
               for i, e in enumerate(raw)]
    threshold = anchor.get("policy_threshold")
    if (not _is_int(threshold) or not 1 <= threshold <= len(signers)):
        _refuse(WITNESS_POLICY_THRESHOLD_INVALID,
                "trust_anchor.policy_threshold must satisfy 1 <= t <= %d"
                % len(signers))
    return {"policy_signers": signers, "policy_threshold": threshold}


def _now_s(now):
    if now is None:
        return int(time.time())
    if not _is_int(now):
        _refuse(WITNESS_POLICY_MALFORMED, "now must be an int")
    return now


# ---------------------------------------------------------------------------
# Sealing + verification.
# ---------------------------------------------------------------------------

def _checked_seal_signer(signer, where):
    pub = getattr(signer, "public_key", None)
    if callable(pub):
        pub = pub()
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
        _refuse(WITNESS_POLICY_MALFORMED,
                "%s: signer public_key must be 32 bytes" % (where,))
    sign = getattr(signer, "sign", None)
    if not callable(sign):
        _refuse(WITNESS_POLICY_MALFORMED,
                "%s: signer must expose sign(bytes)" % (where,))
    return bytes(pub), sign


def seal_policy(body, signers):
    """Threshold-sign a policy body. The body is shape-checked first:
    a malformed policy cannot be sealed. Returns the envelope
    ``{"policy": <normalized body>, "signatures": [...]}``.

    ``signers`` are objects with ``.public_key`` (32 bytes) and
    ``.sign(bytes)`` (the ``gov.signing`` signer interface). Sealing
    takes whatever signers are presented; :func:`verify_policy_document`
    enforces the threshold.
    """
    checked = _check_policy_body(body)
    if not isinstance(signers, (list, tuple)) or not signers:
        _refuse(WITNESS_POLICY_MALFORMED,
                "signers must be a non-empty list")
    seen = set()
    sigs = []
    msg = canonical_policy_bytes(_public_body(checked))
    for i, s in enumerate(signers):
        pub, sign = _checked_seal_signer(s, "signers[%d]" % i)
        if pub.hex() in seen:
            continue  # one signature per key; duplicates add nothing
        seen.add(pub.hex())
        try:
            sig = sign(msg)
        except WitnessPolicyError:
            raise
        except Exception as exc:  # noqa: BLE001
            _refuse(WITNESS_POLICY_MALFORMED,
                    "signers[%d].sign failed: %s" % (i, exc))
        if not isinstance(sig, (bytes, bytearray)) or len(sig) != 64:
            _refuse(WITNESS_POLICY_MALFORMED,
                    "signers[%d].sign must return 64 bytes" % (i,))
        sigs.append({"keyid": pub.hex(), "sig": bytes(sig).hex()})
    # The envelope carries the normalized body (no "parsed" internals).
    return {"policy": _public_body(checked), "signatures": sigs}


def _public_body(checked):
    """The normalized body without internal parse artifacts."""
    body = {
        "schema": SCHEMA,
        "policy_id": checked["policy_id"],
        "version": checked["version"],
        "issued_at": checked["issued_at"],
        "expires_at": checked["expires_at"],
        "threshold": checked["threshold"],
        "log": {"name": checked["log"]["name"],
                "vkey": checked["log"]["vkey"]},
        "witnesses": [{
            "name": w["name"], "vkey": w["vkey"],
            "operator": w["operator"], "contact": w["contact"],
            "not_before": w["not_before"], "not_after": w["not_after"],
            "status": w["status"]} for w in checked["witnesses"]],
        "policy_signers": checked["policy_signers"],
        "policy_threshold": checked["policy_threshold"],
        "max_checkpoint_staleness_seconds":
            checked["max_checkpoint_staleness_seconds"],
    }
    return body


def _check_envelope(doc):
    if not isinstance(doc, dict):
        _refuse(WITNESS_POLICY_MALFORMED,
                "policy document must be a mapping")
    _no_unknown(doc, frozenset(["policy", "signatures"]), "document")
    if "policy" not in doc or "signatures" not in doc:
        _refuse(WITNESS_POLICY_MALFORMED,
                "document must carry policy + signatures")
    sigs = doc["signatures"]
    if not isinstance(sigs, (list, tuple)) or not sigs:
        _refuse(WITNESS_POLICY_MALFORMED,
                "signatures must be a non-empty list")
    for i, s in enumerate(sigs):
        where = "signatures[%d]" % i
        if not isinstance(s, dict):
            _refuse(WITNESS_POLICY_MALFORMED,
                    "%s must be a mapping" % (where,))
        _no_unknown(s, frozenset(["keyid", "sig"]), where)
        for field in ("keyid", "sig"):
            v = s.get(field)
            if not isinstance(v, str):
                _refuse(WITNESS_POLICY_MALFORMED,
                        "%s.%s must be a hex str" % (where, field))
            try:
                raw = bytes.fromhex(v)
            except ValueError:
                _refuse(WITNESS_POLICY_MALFORMED,
                        "%s.%s is not hex" % (where, field))
            if field == "keyid" and len(raw) != 32:
                _refuse(WITNESS_POLICY_MALFORMED,
                        "%s.keyid must be 32 bytes" % (where,))
            if field == "sig" and len(raw) != 64:
                _refuse(WITNESS_POLICY_MALFORMED,
                        "%s.sig must be 64 bytes" % (where,))
    return list(sigs)


def verify_policy_document(doc, trust_anchor, now=None):
    """Verify a sealed policy document against the trust anchor.

    Checks, in order: envelope shape; body shape (unknown fields
    refuse); expiry; the threshold/window/witness rules; then the
    signatures -- each against the TRUST ANCHOR's authorized signers
    (never the document's declared list). Unknown keyids are ignored
    (MUST-ignore, the rotation rule); a KNOWN signer's bad signature
    refuses ``witness-policy-signature-invalid``; fewer than the
    anchor's threshold valid signatures refuses
    ``witness-policy-threshold-unmet``.

    Returns the verified policy dict. Raises
    :class:`WitnessPolicyError` (coded) on any failure -- never a soft
    False.
    """
    _cn, ed = _deps()
    sigs = _check_envelope(doc)
    checked = _check_policy_body(doc["policy"])
    anchor = _check_trust_anchor(trust_anchor)
    now_s = _now_s(now)
    if now_s > checked["expires_at"]:
        _refuse(WITNESS_POLICY_EXPIRED,
                "policy v%d expired at %d (now %d)" % (
                    checked["version"], checked["expires_at"], now_s))
    # A future issued_at is ACCEPTED: pre-provisioned successor (the
    # trustroot.proto contract). Expiry is the only time bound enforced.
    msg = canonical_policy_bytes(_public_body(checked))
    authorized = {s["key_id"]: bytes.fromhex(s["public_key"])
                  for s in anchor["policy_signers"]}
    valid_from = set()
    for s in sigs:
        keyid = s["keyid"].lower()
        pub = authorized.get(keyid)
        if pub is None:
            continue  # MUST-ignore: unknown keyids compose with rotation
        sig = bytes.fromhex(s["sig"])
        # The wave-243 lesson: verify() returns a bool -- check it.
        if ed.verify(pub, msg, sig) is not True:
            _refuse(WITNESS_POLICY_SIGNATURE_INVALID,
                    "signature from authorized signer %s... does not "
                    "verify -- forgery signal" % (keyid[:8],))
        valid_from.add(keyid)
    if len(valid_from) < anchor["policy_threshold"]:
        _refuse(WITNESS_POLICY_THRESHOLD_UNMET,
                "%d valid authorized signature(s), need %d" % (
                    len(valid_from), anchor["policy_threshold"]))
    return _public_body(checked)


def check_policy_update(old_policy, new_doc, trust_anchor, now=None):
    """Verify a new policy document and enforce the update rules.

    * the new document verifies (same rules as
      :func:`verify_policy_document`);
    * ``new.policy_id == old.policy_id`` (no policy-family swap);
    * ``new.version > old.version`` (TUF N+1 rollback protection).

    A key DROP inside the new document is authorized by the
    threshold-signed strictly-newer version itself -- that signature IS
    the drop authorization; there is no separate drop ceremony. A drop
    at the same (or older) version refuses
    ``witness-policy-version-rollback``. Dropping below
    ``threshold <= n`` is refused by the new document's own shape
    check. Returns the verified new policy dict.
    """
    if not isinstance(old_policy, dict):
        _refuse(WITNESS_POLICY_MALFORMED,
                "old_policy must be a verified policy dict")
    for field in ("policy_id", "version"):
        if field not in old_policy:
            _refuse(WITNESS_POLICY_MALFORMED,
                    "old_policy missing %r" % (field,))
    new = verify_policy_document(new_doc, trust_anchor, now)
    if new["policy_id"] != old_policy["policy_id"]:
        _refuse(WITNESS_POLICY_ID_MISMATCH,
                "new policy_id %r != old %r" % (
                    new["policy_id"], old_policy["policy_id"]))
    if not _is_int(old_policy["version"]):
        _refuse(WITNESS_POLICY_MALFORMED,
                "old_policy version must be an int")
    if new["version"] <= old_policy["version"]:
        _refuse(WITNESS_POLICY_VERSION_ROLLBACK,
                "new version %d does not exceed old version %d" % (
                    new["version"], old_policy["version"]))
    return new


# ---------------------------------------------------------------------------
# Downstream consumption.
# ---------------------------------------------------------------------------

def active_witnesses(policy, now=None):
    """The quorum-eligible witness set right now: ``{name: vkey}`` for
    witnesses whose validity window covers ``now`` and whose status is
    ``qualified`` or ``usable``. ``readonly``/``retired`` entries are
    kept for audit but never counted toward quorum."""
    if not isinstance(policy, dict) or not isinstance(
            policy.get("witnesses"), list):
        _refuse(WITNESS_POLICY_MALFORMED,
                "policy must be a verified policy dict")
    now_s = _now_s(now)
    out = {}
    for w in policy["witnesses"]:
        if not isinstance(w, dict):
            _refuse(WITNESS_POLICY_MALFORMED,
                    "witness entry must be a mapping")
        if (w.get("status") in _QUORUM_STATUSES
                and _is_int(w.get("not_before"))
                and _is_int(w.get("not_after"))
                and w["not_before"] <= now_s <= w["not_after"]
                and isinstance(w.get("name"), str)
                and isinstance(w.get("vkey"), str)):
            out[w["name"]] = w["vkey"]
    return out


def verifier_inputs(policy, now=None):
    """The exact inputs for
    ``gov.witness_consistency.require_cosignatures`` derived from a
    verified policy: ``{operator_vkeys, witness_vkeys, quorum_k,
    policy_id, policy_version}``. ``policy_version`` binds the version
    into every downstream verification; replay protection across
    restarts additionally needs the auditor's persisted
    last-seen-version watermark (see module docstring)."""
    if not isinstance(policy, dict):
        _refuse(WITNESS_POLICY_MALFORMED,
                "policy must be a verified policy dict")
    log = policy.get("log")
    if not isinstance(log, dict) or not log.get("vkey"):
        _refuse(WITNESS_POLICY_MALFORMED,
                "policy log vkey missing")
    threshold = policy.get("threshold")
    if not _is_int(threshold):
        _refuse(WITNESS_POLICY_MALFORMED,
                "policy threshold must be an int")
    policy_id = policy.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id:
        _refuse(WITNESS_POLICY_MALFORMED,
                "policy policy_id must be a non-empty str")
    version = policy.get("version")
    if not _is_int(version):
        _refuse(WITNESS_POLICY_MALFORMED,
                "policy version must be an int")
    return {"operator_vkeys": [log["vkey"]],
            "witness_vkeys": active_witnesses(policy, now),
            "quorum_k": threshold,
            "policy_id": policy_id,
            "policy_version": version}
