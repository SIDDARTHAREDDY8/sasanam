"""Wave-248 Lane 3 red-first probes: per-record DSSE evidence envelope.

Blamejs/pki 0.7.6 (Sept 2026) fixed the envelope-shape bug class our
F195 worried about: its Sigstore bundle verifier accepted
multi-signature DSSE envelopes while only verifying the first (the
second signature rode through unverified), and bounded neither
transparency-log entries nor verification material (unbounded tlog =
work-multiplier DoS).

Two red-first pins from that shape:
  (a) a two-signature envelope where the second is forged must REFUSE
      (``dsse-envelope-multi-signature``), never verify-first-only;
  (b) a bundle of 10,001 record envelopes must be refused with
      ``evidence-envelope-record-limit`` BEFORE any signature
      verification runs (work does not scale with entry count).

On the pristine wave-247 base these probes FAIL: gov/evidence_envelope
does not exist and the offline bundle has no per-record DSSE envelope
layer. They go green when the lane lands.

Stdlib only. No in-repo git subprocesses.
"""

import base64
import copy
import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

RESULTS = []


def check(name, fn):
    try:
        fn()
    except AssertionError as exc:
        RESULTS.append((name, "FAIL", str(exc)[:200]))
    except Exception as exc:  # noqa: BLE001 - probe harness reports
        RESULTS.append((name, "ERROR", "%s: %s" % (
            type(exc).__name__, str(exc)[:200])))
    else:
        RESULTS.append((name, "PASS", ""))


def _import():
    from gov import evidence_envelope as ee  # noqa: PLC0415
    from gov import ed25519 as ed  # noqa: PLC0415
    return ee, ed


def _keys():
    from gov import ed25519 as ed  # noqa: PLC0415
    seed = ed.generate_seed()
    pub = ed.publickey(seed)
    return seed, pub


def _record(seq=1):
    return {"seq": seq, "decision": "deny", "reason": "probe"}


# ---------------------------------------------------------------- probes

def p_roundtrip():
    ee, _ = _import()
    seed, pub = _keys()
    env = ee.seal_record(_record(), seed, key_id="probe-key")
    assert isinstance(env, dict), "seal_record must return a dict"
    assert env["payloadType"] == ee.PAYLOAD_TYPE_AUDIT_ENTRY
    assert len(env["signatures"]) == 1, "exactly one signature"
    opened = ee.open_record(env, pub)
    assert opened == _record(), "round-trip must preserve the record"


def p_multisig_second_forged_refused():
    """Blamejs pin (a): two signatures, second forged -> REFUSE."""
    ee, ed = _import()
    seed, pub = _keys()
    env = ee.seal_record(_record(), seed, key_id="probe-key")
    other_seed = ed.generate_seed()
    forged = copy.deepcopy(env)
    forged["signatures"].append({
        "keyid": "attacker",
        "sig": ed.sign(other_seed, b"forged-bytes-not-pae").hex(),
    })
    try:
        ee.open_record(forged, pub)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", "") or str(exc)
        assert "dsse-envelope-multi-signature" in code, \
            "must refuse multi-signature, got: %s" % (code,)
    else:
        raise AssertionError("two-signature envelope was ACCEPTED")


def p_wrong_payload_type_refused():
    ee, _ = _import()
    seed, pub = _keys()
    env = ee.seal_record(_record(), seed, key_id="probe-key")
    wrong = copy.deepcopy(env)
    wrong["payloadType"] = \
        "application/vnd.sasanam.decision-packet+json"
    try:
        ee.open_record(wrong, pub)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", "") or str(exc)
        assert "payload-type-refused" in code or \
            "payloadtype-mismatch" in code or \
            "transplant" in code, \
            "must refuse wrong payloadType, got: %s" % (code,)
    else:
        raise AssertionError("wrong payloadType was ACCEPTED")


def p_tampered_payload_refused():
    ee, _ = _import()
    seed, pub = _keys()
    env = ee.seal_record(_record(), seed, key_id="probe-key")
    tampered = copy.deepcopy(env)
    raw = json.loads(base64.b64decode(tampered["payload"]))
    raw["decision"] = "allow"
    tampered["payload"] = base64.b64encode(
        json.dumps(raw).encode()).decode("ascii")
    try:
        ee.open_record(tampered, pub)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", "") or str(exc)
        assert "dsse-signature-invalid" in code or \
            "malformed" in code, \
            "must refuse tampered payload, got: %s" % (code,)
    else:
        raise AssertionError("tampered payload was ACCEPTED")


def p_oversized_record_refused():
    ee, _ = _import()
    seed, _ = _keys()
    big = {"seq": 1, "blob": "x" * (ee.MAX_RECORD_BYTES + 1)}
    try:
        ee.seal_record(big, seed)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", "") or str(exc)
        assert "evidence-envelope-record-too-large" in code, \
            "must refuse oversized record, got: %s" % (code,)
    else:
        raise AssertionError("oversized record was SEALED")


def p_bundle_record_limit_before_crypto():
    """Blamejs pin (b): 10,001 envelopes refused before any verify."""
    ee, _ = _import()
    seed, pub = _keys()
    envs = [ee.seal_record(_record(seq=i), seed) for i in range(10)]
    # Corrupt every signature so any per-record verify would fail loudly
    # with dsse-signature-invalid -- if the count check runs first we
    # must see evidence-envelope-record-limit instead.
    for env in envs:
        env["signatures"][0]["sig"] = "ab" * 64
    oversized = envs * 1001  # 10,010 envelopes
    assert len(oversized) > ee.MAX_RECORDS_PER_BUNDLE
    try:
        ee.open_records(oversized, pub)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", "") or str(exc)
        assert "evidence-envelope-record-limit" in code, \
            "must refuse oversized bundle before crypto, got: %s" % (code,)
    else:
        raise AssertionError("oversized bundle was ACCEPTED")


def p_malformed_envelope_refused():
    ee, _ = _import()
    _, pub = _keys()
    for bad in (None, [], "nope", {}, {"payloadType": "x"}):
        try:
            ee.open_record(bad, pub)
        except Exception:  # noqa: BLE001
            pass
        else:
            raise AssertionError(
                "malformed envelope accepted: %r" % (bad,))


def p_manifest_roundtrip():
    ee, _ = _import()
    seed, pub = _keys()
    manifest = {"bundle_id": "b1", "record_count": 3}
    env = ee.seal_manifest(manifest, seed)
    assert env["payloadType"] == ee.PAYLOAD_TYPE_BUNDLE_MANIFEST
    assert ee.open_manifest(env, pub) == manifest


PROBES = [
    ("roundtrip", p_roundtrip),
    ("multisig-second-forged-refused", p_multisig_second_forged_refused),
    ("wrong-payload-type-refused", p_wrong_payload_type_refused),
    ("tampered-payload-refused", p_tampered_payload_refused),
    ("oversized-record-refused", p_oversized_record_refused),
    ("bundle-record-limit-before-crypto",
     p_bundle_record_limit_before_crypto),
    ("malformed-envelope-refused", p_malformed_envelope_refused),
    ("manifest-roundtrip", p_manifest_roundtrip),
]


def main():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("GREEN CHECKS SKIPPED (GOV_SKIP_GREEN=1)")
        return 0
    for name, fn in PROBES:
        check(name, fn)
    held = sum(1 for _, s, _ in RESULTS if s == "PASS")
    gaps = sum(1 for _, s, _ in RESULTS if s != "PASS")
    for name, status, detail in RESULTS:
        print("%-38s %s %s" % (name, status, detail))
    print("HELD %d/%d  GAP %d/%d" % (held, len(RESULTS), gaps,
                                    len(RESULTS)))
    return 0 if gaps == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
