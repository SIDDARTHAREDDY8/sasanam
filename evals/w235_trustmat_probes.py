#!/usr/bin/env python3
"""Wave-235 lane A: trust-material externality (treeship TS-2026-004 pressure).

Attack shapes at the public seams (break-first, red-first on base):
* trust keys resolve from an EXTERNAL trust root only: a packet signed by
  an attacker key carried INSIDE the record (its own authority block, an
  embedded keys bundle) is refused ``untrusted-key`` when the verifier is
  given an external TrustRoot pinned to the real key -- record-carried key
  material is never trusted;
* key ids are pinned to KEY MATERIAL (sha256 of the raw key bytes), not
  labels: the same kid label bound to different material refuses
  ``trust-key-repointed``;
* unsigned fields are never consulted: a verifier asked to rely on a field
  outside the signature-covered body (e.g. an approval-use limit) refuses
  ``unsigned-field-ignored`` -- fail closed, never silent accept;
* control: the externally-pinned legitimate key still verifies, and the
  legacy path (trust_root=None) is byte-identical in behavior.

Seams under test:
* gov/trust_material.py -- TrustRoot.bind_authority, pin_key_id,
  assert_signature_covered, TrustMaterialError codes.
* gov/decision_packet.py -- verify_decision_packet(..., trust_root=,
  relied_claims=) (additive keyword-only seams).

Method (diagnosing-bugs): deterministic, minimal, against pushed
wave-234 HEAD 0390dcbd2e65a7d7b15f8c1b0c89efe1807f63d7.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent)
is expected GAP for every probe.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g235a
  TMPDIR=/var/tmp/g235a ~/workspace/.gov-venv/bin/python evals/w235_trustmat_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import copy
import hashlib
import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import decision_packet as dp  # noqa: E402
from gov import decision_bom as bom_mod  # noqa: E402

HAVE_NEW_API = False
try:
    from gov import trust_material as _tm
    HAVE_NEW_API = all(hasattr(_tm, n) for n in (
        "TrustRoot", "TrustMaterialError", "pin_key_id",
        "assert_signature_covered"))
except ImportError:
    _tm = None

SEED_REAL = bytes.fromhex("11" * 32)
SEED_ATTACKER = bytes.fromhex("22" * 32)

PROBE_NAMES = [
    "trustmat-pinned-key-verifies",
    "trustmat-attacker-key-in-package-refused",
    "trustmat-repointed-kid-refused",
    "trustmat-unsigned-limit-refused",
    "trustmat-covered-claim-accepted",
    "trustmat-legacy-path-unchanged",
    "trustmat-pin-is-material-bound",
    "trustmat-record-keys-bundle-ignored",
]


def _minimal_bom(**over):
    kw = dict(policy_id="default", policy_version="unversioned",
              policy_digest="ab" * 32,
              evidence_head_digest="GENESIS",
              principal={"agent_id": None, "role": None,
                         "principal": None, "run_id": None})
    kw.update(over)
    return bom_mod.build_bom(**kw)


def _packet(seed):
    body = dp.build_decision_packet(
        decision="allow", boundary_declared=False, authority_proof=None,
        evidence_head_digest="GENESIS", policy_id="default",
        policy_version="unversioned",
        issued_at="2026-09-30T00:00:00+00:00",
        bill_of_materials=_minimal_bom())
    return dp.sign_packet(body, seed)


def _authority(packet):
    return packet["authority"]["kid"], packet["authority"]["pubkey"]


def _rec(results, name, verdict, detail=""):
    results[name] = verdict if not detail else "%s\n  %s" % (verdict, detail)


def _p1_pinned_key_verifies(results):
    try:
        pkt = _packet(SEED_REAL)
        kid, pub = _authority(pkt)
        root = _tm.TrustRoot({kid: bytes.fromhex(pub)})
        ok, reason = dp.verify_decision_packet(pkt, trust_root=root)
        assert ok is True, "pinned key must verify: %s" % (reason,)
        _rec(results, PROBE_NAMES[0], "HELD",
             "kid=%s... verifies under the external root" % kid[:12])
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[0], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[0], "ERROR", traceback.format_exc(limit=2))


def _p2_attacker_key_refused(results):
    try:
        # The attacker mints a packet with their own key, embedding their
        # own authority block -- and a keys bundle inside the record,
        # mimicking a package-carried keys.json (treeship TS-2026-004).
        pkt = _packet(SEED_ATTACKER)
        pkt = copy.deepcopy(pkt)
        pkt["keys"] = {"executor-signing-key": pkt["authority"]["pubkey"]}
        kid_real, pub_real = _authority(_packet(SEED_REAL))
        root = _tm.TrustRoot({kid_real: bytes.fromhex(pub_real)})
        ok, reason = dp.verify_decision_packet(pkt, trust_root=root)
        assert ok is False, "attacker key must not verify under the root"
        assert "untrusted-key" in reason, \
            "want the named untrusted-key refusal, got: %s" % (reason,)
        _rec(results, PROBE_NAMES[1], "HELD",
             "record-carried key refused: %s" % reason[:120])
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[1], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[1], "ERROR", traceback.format_exc(limit=2))


def _p3_repointed_kid_refused(results):
    try:
        # Same kid label, different key material: the label was re-pointed
        # to attacker material (keys.json key-id re-pointing). Probed at
        # the TrustRoot seam, where the binding decision is made.
        real = _packet(SEED_REAL)
        kid_real, _pub_real = _authority(real)
        attacker = _packet(SEED_ATTACKER)
        _kid_att, pub_att = _authority(attacker)
        root = _tm.TrustRoot(
            {kid_real: bytes.fromhex(_authority(real)[1])})
        try:
            root.bind_authority(kid_real, bytes.fromhex(pub_att))
            _rec(results, PROBE_NAMES[2], "BREAK",
                 "re-pointed material bound silently")
            return
        except _tm.TrustMaterialError as exc:
            assert exc.code == "trust-key-repointed", \
                "want trust-key-repointed, got %r" % (exc.code,)
        _rec(results, PROBE_NAMES[2], "HELD",
             "label re-pointed to new material refused as trust-key-repointed")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[2], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[2], "ERROR", traceback.format_exc(limit=2))


def _p4_unsigned_limit_refused(results):
    try:
        pkt = _packet(SEED_REAL)
        # The verifier is asked to rely on an approval-use limit that has
        # no signature-covered source: fail closed, never silent accept.
        ok, reason = dp.verify_decision_packet(
            pkt, relied_claims={"approval_use_limit": 3})
        assert ok is False, "unsigned reliance must not verify"
        assert "unsigned-field-ignored" in reason, \
            "want the named unsigned-field-ignored refusal, got: %s" % (
                reason,)
        _rec(results, PROBE_NAMES[3], "HELD",
             "unsigned approval_use_limit refused: %s" % reason[:120])
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[3], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[3], "ERROR", traceback.format_exc(limit=2))


def _p5_covered_claim_accepted(results):
    try:
        # Control: a relied claim WITH a signature-covered source is
        # resolved from the covered body and verified normally.
        pkt = _packet(SEED_REAL)
        ok, reason = dp.verify_decision_packet(
            pkt, relied_claims={"decision": "allow"})
        assert ok is True, "covered claim must verify: %s" % (reason,)
        ok2, reason2 = dp.verify_decision_packet(
            pkt, relied_claims={"decision": "deny"})
        assert ok2 is False, "a claim disagreeing with the covered body " \
            "must refuse: %s" % (reason2,)
        assert "unsigned-field-ignored" not in reason2
        _rec(results, PROBE_NAMES[4], "HELD",
             "covered relied claim resolved from the signed body")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[4], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[4], "ERROR", traceback.format_exc(limit=2))


def _p6_legacy_path_unchanged(results):
    try:
        # Honest residual: external-root enforcement is opt-in. Without
        # trust_root, verification keeps the exact legacy semantics (an
        # attacker-minted packet still verifies -- the deployment owns the
        # root-pinning decision).
        pkt = _packet(SEED_ATTACKER)
        ok, reason = dp.verify_decision_packet(pkt)
        assert ok is True, \
            "legacy path must be unchanged without trust_root: %s" % (reason,)
        _rec(results, PROBE_NAMES[5], "HELD",
             "trust_root=None keeps legacy semantics (residual documented)")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[5], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[5], "ERROR", traceback.format_exc(limit=2))


def _p7_pin_is_material_bound(results):
    try:
        # The pin is a function of the key MATERIAL only: same material ->
        # same pin; different material -> different pin; labels play no
        # role (a label cannot be re-pointed to keep the pin).
        real_pub = bytes.fromhex(_authority(_packet(SEED_REAL))[1])
        att_pub = bytes.fromhex(_authority(_packet(SEED_ATTACKER))[1])
        assert _tm.pin_key_id(real_pub) == _tm.pin_key_id(real_pub)
        assert _tm.pin_key_id(real_pub) != _tm.pin_key_id(att_pub)
        assert _tm.pin_key_id(real_pub) == hashlib.sha256(real_pub).hexdigest()
        assert len(_tm.pin_key_id(real_pub)) == 64
        # Malformed material is a construction error, never a product code.
        try:
            _tm.pin_key_id(b"short")
            _rec(results, PROBE_NAMES[6], "BREAK",
                 "malformed material pinned silently")
            return
        except _tm.TrustMaterialError as exc:
            assert exc.code == "trust-material-malformed", exc.code
        _rec(results, PROBE_NAMES[6], "HELD",
             "pin = sha256(material); malformed refused at construction")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[6], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[6], "ERROR", traceback.format_exc(limit=2))


def _p8_record_keys_bundle_ignored(results):
    try:
        # The TrustRoot NEVER consults key material carried inside the
        # record: a record shipping its own keys bundle (keys.json) with
        # the attacker's kid cannot bootstrap trust.
        real = _packet(SEED_REAL)
        kid_real, pub_real = _authority(real)
        attacker = _packet(SEED_ATTACKER)
        kid_att, pub_att = _authority(attacker)
        root = _tm.TrustRoot({kid_real: bytes.fromhex(pub_real)})
        record = {"authority": {"kid": kid_att, "pubkey": pub_att},
                  "keys": {kid_att: pub_att}}  # embedded keys.json
        try:
            root.bind_authority(record["authority"]["kid"],
                                bytes.fromhex(record["authority"]["pubkey"]))
            _rec(results, PROBE_NAMES[7], "BREAK",
                 "embedded bundle bootstrapped trust")
            return
        except _tm.TrustMaterialError as exc:
            assert exc.code == "untrusted-key", \
                "want untrusted-key, got %r" % (exc.code,)
        _rec(results, PROBE_NAMES[7], "HELD",
             "embedded keys bundle never consulted; untrusted-key refused")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[7], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[7], "ERROR", traceback.format_exc(limit=2))


def _run_all():
    results = {}
    if not HAVE_NEW_API:
        for name in PROBE_NAMES:
            _rec(results, name, "GAP", "trust_material module absent")
        return results
    _p1_pinned_key_verifies(results)
    _p2_attacker_key_refused(results)
    _p3_repointed_kid_refused(results)
    _p4_unsigned_limit_refused(results)
    _p5_covered_claim_accepted(results)
    _p6_legacy_path_unchanged(results)
    _p7_pin_is_material_bound(results)
    _p8_record_keys_bundle_ignored(results)
    return results


def main():
    t0 = time.time()
    results = _run_all()

    def _v(name):
        return results.get(name, "ERROR: missing").split("\n")[0]
    held = sum(1 for name in PROBE_NAMES if _v(name) == "HELD")
    gap = sum(1 for name in PROBE_NAMES if _v(name).startswith("GAP"))
    brk = sum(1 for name in PROBE_NAMES if _v(name).startswith("BREAK"))
    err = sum(1 for name in PROBE_NAMES if _v(name).startswith("ERROR"))
    for name in PROBE_NAMES:
        verdict = results.get(name, "ERROR: missing")
        first = verdict.split("\n")[0]
        print("%-42s %s" % (name, first))
        if "\n" in verdict:
            print(verdict.split("\n", 1)[1])
    print("summary: %d HELD / %d GAP / %d BREAK / %d ERROR (%.1fs)"
          % (held, gap, brk, err, time.time() - t0))
    # Exit 0 only when every probe HELD. Genuine red (module absent) is
    # exit 2: the absence is the expected pre-implementation state, not a
    # passing suite.
    if not HAVE_NEW_API:
        return 2
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
