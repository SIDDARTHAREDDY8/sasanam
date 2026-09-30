"""Wave-244 treeship advisory probes (W244-6, red-first).

Attacker shapes from treeship's published security advisories, verified
2026-09-30 against the zerkerlabs/treeship repo-level advisory API.
(They are repo advisories, not global GHSAs: the global advisory API
404s them by design. Lesson applied: IDs fetched, never carried on
trust after the wave-243 Harbor fabrication incident.)
- GHSA-w356-2hw3-x2v2 (high): agent-card verification could accept a
  trusted party's key as another agent's; revocations forgeable/hidden.
- GHSA-qhv9-h5vq-hw6r (medium): Rekor anchoring never succeeded;
  verify --max-unwitnessed trusted unsigned local records.
- GHSA-29hj-wmwv-7hx8 (medium): package verify accepted fabricated
  sealed sets without checking signatures.
- GHSA-pmp9-x698-fh4v (high): keystore documented as AES-256-GCM was a
  broken SHA-256-CTR+HMAC construction (claimed-vs-actual crypto).
- GHSA-p367-33qm-pwv7 (high): package verify could report a rewritten
  receipt as verified.

A. Advisory-bound verifier inputs (NEW: gov/advisory_binding):
  advisory-unscoped-pin-asserted -- an unscoped agent_cert pin grades
      asserted; presenting it as verification evidence refuses
      pin-scope-insufficient (re-pin with agent scope required).
  advisory-stale-snapshot-refused -- an advisory snapshot older than
      its freshness bound refuses chain-source-stale: explicit stale,
      never a silent pass.
  advisory-flagged-package-refused -- a package whose signature
      VERIFIES but which the advisory flags refuses
      package-advisory-flagged. A signature proves who signed, never
      that the package is safe.
  advisory-threshold-unmet-refused -- an advisory signed 1-of-3 below
      the advisory signature threshold refuses registry-threshold-unmet
      (its flags are untrusted).
  advisory-supersession-newest-wins -- v2 (flagged, supersedes v1's
      allow) is the effective advisory; the older allow never
      resurrects.

B. Conformance pins (existing verifier seams; already held on the
   pristine base):
  ghsa-w356-wrong-key-as-agent -- a card self-reporting agent://x
      while the attested peer names agent://y refuses
      channel-peer-mismatch: a trusted party's key is never accepted
      as another agent's.
  ghsa-29hj-fabricated-sealed-set -- a fabricated sealed set with
      recomputed digests but no valid signature refuses
      package-signature-invalid; it is never accepted.
  ghsa-pmp9-claimed-vs-actual-crypto -- a digest whose length does not
      match the claimed hash refuses signer-digest-length-mismatch;
      P-521 paired with SHA-256 refuses signer-hash-downshift-refused.
      Measured, never trusted on the claim.
  ghsa-p367-rewritten-receipt -- package bytes rewritten after signing
      refuse package-digest-mismatch; a rewritten receipt is never
      reported verified.
  ghsa-qhv9-unwitnessed-not-verified -- an absence bundle with no
      close record refuses absence-epoch-not-closed: unclosed (and
      therefore unwitnessed) epochs verify nothing.

Stdlib only (+ in-repo gov.ed25519 for the advisory signatures).
Deterministic: fixed keys, fixed timestamps. No in-repo git
subprocesses.
"""

import base64
import copy
import hashlib
import json
import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_ADVISORY = False
try:
    from gov import advisory_binding as _ab
    HAVE_ADVISORY = all(hasattr(_ab, n) for n in (
        "grade_agent_pin", "assert_pin_for_verification",
        "bind_advisory_input", "supersede", "check_package",
        "AdvisoryBindingError"))
except ImportError:
    _ab = None

HAVE_REGISTRY = False
try:
    from gov import registry_acceptance as _rg
    HAVE_REGISTRY = all(hasattr(_rg, n) for n in (
        "accept_package", "canonical_manifest_bytes",
        "RegistryAcceptanceError"))
except ImportError:
    _rg = None

HAVE_CHANNEL = False
try:
    from gov import attested_channel as _ch
    HAVE_CHANNEL = all(hasattr(_ch, n) for n in (
        "ChannelAdmission", "AttestedChannelError"))
except ImportError:
    _ch = None

HAVE_SIGNER = False
try:
    from gov import signer_interop as _si
    HAVE_SIGNER = all(hasattr(_si, n) for n in (
        "sign_digest_paired", "SignerInteropError"))
except ImportError:
    _si = None

HAVE_ABSENCE = False
try:
    from gov import absence_epoch as _ae
    HAVE_ABSENCE = all(hasattr(_ae, n) for n in (
        "open_epoch", "observe_absence", "verify_absence",
        "AbsenceEpochError"))
except ImportError:
    _ae = None

HAVE_ED25519 = False
try:
    from gov import ed25519 as _e
    HAVE_ED25519 = all(hasattr(_e, n) for n in (
        "generate_seed", "publickey", "sign", "verify"))
except ImportError:
    _e = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

T_FETCH = 1727731200
T_NOW = T_FETCH + 1800            # 30 min later: within the 1h bound
T_STALE = T_FETCH + 7200          # 2h later: past the bound

_SEEDS = [bytes([0xA0 + i]) * 32 for i in range(4)]
_PUBS = None


def _pubs():
    global _PUBS
    if _PUBS is None:
        _PUBS = [_e.publickey(s) for s in _SEEDS]
    return _PUBS


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


# ---------------------------------------------------------------------------
# Advisory fixtures
# ---------------------------------------------------------------------------

def _policy(**over):
    policy = {
        "advisory_policy_input": "advisory-policy-v1",
        "freshness_seconds": 3600,
        "signature_threshold": 3,
        "trusted_keys": [_b64(p) for p in _pubs()],
    }
    policy.update(over)
    return policy


def _snapshot(version, flags, n_sigs=3, **over):
    body = {
        "advisory_id": "GHSA-w356-2hw3-x2v2",
        "version": version,
        "issuer": "zerkerlabs/treeship",
        "fetched_at": T_FETCH,
        "flags": flags,
    }
    body.update(over)
    canon = _canonical_bytes(body)
    sigs = []
    for i in range(n_sigs):
        sigs.append({"key": _b64(_pubs()[i]),
                     "sig": _b64(_e.sign(_SEEDS[i], canon))})
    return {
        "advisory_id": body["advisory_id"],
        "version": version,
        "issuer": body["issuer"],
        "fetched_at": body["fetched_at"],
        "flags": flags,
        "canonical_bytes": canon,
        "digest": hashlib.sha256(canon).hexdigest(),
        "signatures": sigs,
    }


def _run_probe(name, fn, have, pin=False):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, ("PIN" if pin else "HELD"), note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _expect_refusal(fn, exc_class, code):
    try:
        fn()
    except exc_class as exc:
        assert exc.code == code, "code %r, expected %r" % (exc.code, code)
        return "refused %s" % code
    raise AssertionError("no refusal; expected %s" % code)


# ---------------------------------------------------------------------------
# A. Advisory-bound verifier inputs (need gov/advisory_binding)
# ---------------------------------------------------------------------------

def _probe_unscoped_pin():
    unscoped = {"kind": "agent_cert"}
    scoped = {"kind": "agent_cert", "agent": "agent://deployer"}
    assert _ab.grade_agent_pin(unscoped) == "asserted", \
        "unscoped pin must grade asserted, never key-bound"
    assert _ab.grade_agent_pin(scoped) == "key-bound", \
        "agent-scoped pin must grade key-bound"
    note = _expect_refusal(
        lambda: _ab.assert_pin_for_verification(unscoped),
        _ab.AdvisoryBindingError, "pin-scope-insufficient")
    assert _ab.assert_pin_for_verification(scoped) == "key-bound"
    return "unscoped->asserted, scoped->key-bound; %s" % note


def _probe_stale_snapshot():
    pinned = _ab.bind_advisory_input(_policy(), _snapshot(2, {}), T_NOW)
    # fresh at bind time; stale at check time -> explicit stale, never silent
    return _expect_refusal(
        lambda: _ab.check_package(pinned, "pkg-1", T_STALE),
        _ab.AdvisoryBindingError, "chain-source-stale")


def _probe_flagged_package():
    # The advisory flags pkg-evil even though its (hypothetical) package
    # signature verifies: signature proves who signed, not safety.
    snap = _snapshot(2, {"pkg-evil": "flagged", "pkg-good": "allow"})
    pinned = _ab.bind_advisory_input(_policy(), snap, T_NOW)
    note = _expect_refusal(
        lambda: _ab.check_package(pinned, "pkg-evil", T_NOW),
        _ab.AdvisoryBindingError, "package-advisory-flagged")
    res = _ab.check_package(pinned, "pkg-good", T_NOW)
    assert res["verdict"] == "advisory-clear", "got %r" % (res,)
    assert res["advisory_policy_input"] == "advisory-policy-v1", \
        "verdict must name its pinned advisory policy input"
    return "%s; unflagged package advisory-clear" % note


def _probe_threshold():
    # 1 valid advisory signature against a threshold-3 policy.
    snap = _snapshot(2, {}, n_sigs=1)
    pinned = _ab.bind_advisory_input(_policy(), snap, T_NOW)
    return _expect_refusal(
        lambda: _ab.check_package(pinned, "pkg-1", T_NOW),
        _ab.AdvisoryBindingError, "registry-threshold-unmet")


def _probe_supersession():
    v1 = _ab.bind_advisory_input(
        _policy(), _snapshot(1, {"pkg-x": "allow"}), T_NOW)
    v2 = _ab.bind_advisory_input(
        _policy(), _snapshot(2, {"pkg-x": "flagged"}), T_NOW)
    effective = _ab.supersede([v1, v2])
    assert effective["version"] == 2, \
        "newest advisory must win, got version %r" % (effective.get("version"),)
    # The older allow never resurrects: the effective (v2) advisory flags.
    return _expect_refusal(
        lambda: _ab.check_package(effective, "pkg-x", T_NOW),
        _ab.AdvisoryBindingError, "package-advisory-flagged")


# ---------------------------------------------------------------------------
# B. Conformance pins (existing seams)
# ---------------------------------------------------------------------------

def _probe_wrong_key_as_agent():
    # GHSA-w356 shape: a trusted party's key presented as another agent.
    # The daemon-vouched peer names agent://intruder while the emitter
    # self-reports agent://deployer.
    adm = _ch.ChannelAdmission()
    claim = {"principal": "agent://deployer", "ts_emit": T_NOW,
             "seq": 0, "payload": {"op": "read"}}
    peer = {"uid": 1000, "gid": 1000, "pid": 42, "exe": "/usr/bin/agent",
            "principal": "agent://intruder"}
    return _expect_refusal(
        lambda: adm.admit(claim, peer, "daemon", T_NOW),
        _ch.AttestedChannelError, "channel-peer-mismatch")


def _probe_fabricated_sealed_set():
    # GHSA-29hj shape: internally consistent sealed set (recomputed
    # digests), fabricated ids, NO valid signature -> never accept.
    package_bytes = b"fabricated-package-bytes"
    payload = {"name": "skill-pack", "version": "9.9.9",
               "digest": hashlib.sha256(package_bytes).hexdigest(),
               "issued_at": T_FETCH, "valid_until": T_FETCH + 3600,
               "sealed": ["art_invented_1", "art_invented_2"]}
    body = _rg.canonical_manifest_bytes(payload)
    # Sign with an UNTRUSTED key (not in the policy trust list).
    rogue = bytes([0xFF]) * 32
    rogue_pub = _e.publickey(rogue)
    manifest = {"payload": payload,
                "signatures": [{"key": _b64(rogue_pub),
                                "sig": _b64(_e.sign(rogue, body))}]}
    policy = {"threshold": 1,
              "trusted_keys": [_b64(p) for p in _pubs()]}
    return _expect_refusal(
        lambda: _rg.accept_package(manifest, package_bytes, policy,
                                   now=T_NOW),
        _rg.RegistryAcceptanceError, "package-signature-invalid")


def _probe_claimed_vs_actual_crypto():
    # GHSA-pmp9 shape: the claim says sha256; the measured digest is
    # 48 bytes. Refused on the measurement, never on the claim.
    note1 = _expect_refusal(
        lambda: _si.sign_digest_paired(b"\x00" * 48, "sha256", "P-256"),
        _si.SignerInteropError, "signer-digest-length-mismatch")
    # The upstream bug shape: P-521 with SHA-256 is refused loudly,
    # never silently downshifted.
    note2 = _expect_refusal(
        lambda: _si.sign_digest_paired(b"\x00" * 32, "sha256", "P-521"),
        _si.SignerInteropError, "signer-hash-downshift-refused")
    return "%s; %s" % (note1, note2)


def _probe_rewritten_receipt():
    # GHSA-p367 shape: package bytes rewritten after signing are never
    # reported verified.
    package_bytes = b"original-package-bytes"
    digest = hashlib.sha256(package_bytes).hexdigest()
    payload = {"name": "skill-pack", "version": "1.0.0",
               "digest": digest,
               "issued_at": T_FETCH, "valid_until": T_FETCH + 3600}
    body = _rg.canonical_manifest_bytes(payload)
    manifest = {"payload": payload,
                "signatures": [{"key": _b64(_pubs()[0]),
                                "sig": _b64(_e.sign(_SEEDS[0], body))}]}
    policy = {"threshold": 1,
              "trusted_keys": [_b64(p) for p in _pubs()]}
    # The signature verifies over the manifest; the REWRITTEN bytes no
    # longer digest to the signed digest -> refused, never verified.
    return _expect_refusal(
        lambda: _rg.accept_package(manifest, b"rewritten-bytes", policy,
                                   now=T_NOW),
        _rg.RegistryAcceptanceError, "package-digest-mismatch")


def _probe_unwitnessed_not_verified():
    # GHSA-qhv9 shape: an anchoring claim with no witness is never
    # reported verified. An absence bundle with observations but no
    # close record refuses: unclosed epochs verify nothing.
    beacon_seed = bytes([0xB0]) * 32
    observer_seed = bytes([0xB1]) * 32
    epoch = T_FETCH // _ae.EPOCH_SECONDS
    beacon = _ae.open_epoch(beacon_seed, epoch,
                            prev_root="00" * 32,
                            opened_at=epoch * _ae.EPOCH_SECONDS)
    observed_at = epoch * _ae.EPOCH_SECONDS + 10
    _ae.observe_absence(observer_seed, beacon, "scope-a", observed_at)
    bundle = {"beacons": [beacon], "closes": [], "ledgers": {}}
    observer_pub = _ae.pub_of(observer_seed)
    return _expect_refusal(
        lambda: _ae.verify_absence(bundle, epoch, "scope-a",
                                   observer_pub),
        _ae.AbsenceEpochError, "absence-epoch-not-closed")


_PROBES = [
    # (name, fn, have-flag-name, is_conformance_pin)
    ("advisory-unscoped-pin-asserted", _probe_unscoped_pin,
     "HAVE_ADVISORY", False),
    ("advisory-stale-snapshot-refused", _probe_stale_snapshot,
     "HAVE_ADVISORY", False),
    ("advisory-flagged-package-refused", _probe_flagged_package,
     "HAVE_ADVISORY", False),
    ("advisory-threshold-unmet-refused", _probe_threshold,
     "HAVE_ADVISORY", False),
    ("advisory-supersession-newest-wins", _probe_supersession,
     "HAVE_ADVISORY", False),
    ("ghsa-w356-wrong-key-as-agent", _probe_wrong_key_as_agent,
     "HAVE_CHANNEL", True),
    ("ghsa-29hj-fabricated-sealed-set", _probe_fabricated_sealed_set,
     "HAVE_REGISTRY", True),
    ("ghsa-pmp9-claimed-vs-actual-crypto",
     _probe_claimed_vs_actual_crypto, "HAVE_SIGNER", True),
    ("ghsa-p367-rewritten-receipt", _probe_rewritten_receipt,
     "HAVE_REGISTRY", True),
    ("ghsa-qhv9-unwitnessed-not-verified",
     _probe_unwitnessed_not_verified, "HAVE_ABSENCE", True),
]


def main():
    # NOTE (wave-244 merge): this battery spawns no nested green-check
    # subprocesses, so there is nothing to skip here -- the probes must
    # always run. An earlier revision returned early on GOV_SKIP_GREEN=1,
    # which made the whole battery a vacuous pass when run depth-1.
    if not HAVE_ED25519:
        print("ERROR: gov.ed25519 unavailable")
        return 1
    flags = {"HAVE_ADVISORY": HAVE_ADVISORY,
             "HAVE_REGISTRY": HAVE_REGISTRY,
             "HAVE_CHANNEL": HAVE_CHANNEL,
             "HAVE_SIGNER": HAVE_SIGNER,
             "HAVE_ABSENCE": HAVE_ABSENCE}
    results = []
    for name, fn, flag, pin in _PROBES:
        results.append(_run_probe(name, fn, flags[flag], pin=pin))
    held = sum(1 for _, s, _ in results if s in ("HELD", "PIN"))
    total = len(results)
    for name, status, note in results:
        print("%-42s %-6s %s" % (name, status, note.split("\n")[0]))
    print("w244_treeship_advisory: %d/%d HELD-or-PIN" % (held, total))
    return 0 if held == total else 2


if __name__ == "__main__":
    sys.exit(main())
