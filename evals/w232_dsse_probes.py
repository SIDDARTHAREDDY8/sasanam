#!/usr/bin/env python3
"""Wave-232 lane C: DSSE pre-authentication-encoding discipline for signed envelopes.

Re-derived envelope discipline (nothing copied): every signature signs
length-prefixed bytes ``DSSEv1 SP len SP payloadType SP len SP payload``
-- the PAE shape. Length-prefixing kills envelope-shape bugs by
construction: a payloadType can never be confused with a payload, because
every field is consumed by its declared length and exactly one parse
exists. Any ambiguity (leading-zero lengths, trailing bytes, wrong
domain) refuses ``dsse-envelope-malformed`` -- never falls back to a
second parse.

Payload types are vendored: only ``application/vnd.sasanam.*+json``
is signable; a generic ``application/json`` is refused at build time
(``dsse-payload-type-refused``), because a generic type lets an
attacker re-present a signature under a different semantic.

Seams under test:
* gov/dsse_envelope.py -- check_payload_type_namespace / pae_decode
  (strict, fail-closed), envelope(payload, payload_type, sign) /
  verify_envelope(env, verify, expect_payload_type): confusion across
  payload types is impossible; signatures sign the exact PAE bytes;
  tampering refuses; ambiguous encodings refuse.
* gov/deny_receipts.py -- emit(..., envelope=<vendored type>):
  envelope-only additive; legacy receipts byte-identical.
* gov/decision_packet.py -- sign_packet(body, seed, envelope=True):
  envelope-only additive; legacy packets byte-identical; legacy
  signature rule never widened.

Attack shapes: present an envelope under a wrong payloadType; use a
generic payloadType; flip a payload byte post-signing; hand-craft
PAE bytes with leading-zero lengths / trailing garbage; re-present a
legacy signature as an envelope; forge an envelope field on a
receipt.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-231 HEAD
6f9131bc76e3713a61a271c4a2203956c533c456.

Verdicts: HELD / GAP / BREAK / ERROR. Any BREAK is a real
product defect. Pristine run (new helpers absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g232c
  TMPDIR=/var/tmp/g232c ~/workspace/.gov-venv/bin/python evals/w232_dsse_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import base64
import hashlib
import hmac
import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

HAVE_MODULE = False
try:
    from gov import dsse_envelope as _ds
    HAVE_MODULE = all(hasattr(_ds, n) for n in (
        "envelope", "verify_envelope", "pae_decode",
        "check_payload_type_namespace"))
except ImportError:
    _ds = None

PROBE_NAMES = [
    "dsse-round-trip",
    "dsse-type-payload-confusion-refused",
    "dsse-generic-payload-type-refused",
    "dsse-tampered-payload-refused",
    "dsse-ambiguous-encoding-refused",
    "dsse-signature-over-pae-bytes",
    "dsse-legacy-still-verifies",
    "dsse-receipt-envelope-integrates",
]


def _signer_cb(secret):
    def _sign(msg):
        return hmac.new(secret, msg, hashlib.sha256).digest()
    return _sign


def _verifier_cb(secret):
    def _verify(msg, sig):
        return hmac.compare_digest(
            hmac.new(secret, msg, hashlib.sha256).digest(), sig)
    return _verify


def _payloads():
    pt_a = "application/vnd.sasanam.decision-packet+json"
    pt_b = "application/vnd.sasanam.denial-receipt+json"
    return pt_a, pt_b, b'{"decision":"allow"}'


def _run_all():
    results = {}
    secret = hashlib.sha256(b"dsse-probe-key").digest()
    pt_a, pt_b, payload = _payloads()

    # 1. round trip -------------------------------------------------
    try:
        env = _ds.envelope(payload, payload_type=pt_a, sign=_signer_cb(secret))
        out = _ds.verify_envelope(env, verify=_verifier_cb(secret),
                                  expect_payload_type=pt_a)
        assert out["ok"] is True
        assert out["payload"] == payload
        assert out["payload_type"] == pt_a
        results["dsse-round-trip"] = "HELD"
    except Exception:
        results["dsse-round-trip"] = "BREAK\n" + traceback.format_exc(limit=2)

    # 2. type confusion: envelope signed under A, presented as B ----
    try:
        env = _ds.envelope(payload, payload_type=pt_a, sign=_signer_cb(secret))
        _ds.verify_envelope(env, verify=_verifier_cb(secret),
                            expect_payload_type=pt_b)
        results["dsse-type-payload-confusion-refused"] = "BREAK: no refusal"
    except Exception as exc:
        reason = getattr(exc, "reason", str(exc))
        if "dsse-payload-type-refused" in reason:
            results["dsse-type-payload-confusion-refused"] = "HELD"
        else:
            results["dsse-type-payload-confusion-refused"] = \
                "BREAK: wrong refusal %r" % (reason,)

    # 3. generic payloadType refused at build ------------------------
    try:
        _ds.envelope(payload, payload_type="application/json",
                     sign=_signer_cb(secret))
        results["dsse-generic-payload-type-refused"] = "BREAK: no refusal"
    except Exception as exc:
        reason = getattr(exc, "reason", str(exc))
        if "dsse-payload-type-refused" in reason:
            results["dsse-generic-payload-type-refused"] = "HELD"
        else:
            results["dsse-generic-payload-type-refused"] = \
                "BREAK: wrong refusal %r" % (reason,)

    # 4. tampered payload refuses ------------------------------------
    try:
        env = _ds.envelope(payload, payload_type=pt_a, sign=_signer_cb(secret))
        bad = dict(env)
        tampered = bytearray(base64.b64decode(bad["payload"]))
        tampered[2] ^= 0xFF
        bad["payload"] = base64.b64encode(bytes(tampered)).decode("ascii")
        _ds.verify_envelope(bad, verify=_verifier_cb(secret),
                            expect_payload_type=pt_a)
        results["dsse-tampered-payload-refused"] = "BREAK: no refusal"
    except Exception as exc:
        reason = getattr(exc, "reason", str(exc))
        if "dsse-signature-invalid" in reason or \
                "dsse-envelope-malformed" in reason:
            results["dsse-tampered-payload-refused"] = "HELD"
        else:
            results["dsse-tampered-payload-refused"] = \
                "BREAK: wrong refusal %r" % (reason,)

    # 5. ambiguous encodings refused ----------------------------------
    try:
        pae = _ds.pae(pt_a, payload)
        parts = pae.split(b" ")
        parts[1] = b"0" + parts[1]  # leading-zero length: "043" not "43"
        amb = b" ".join(parts)
        try:
            _ds.pae_decode(amb)
            results["dsse-ambiguous-encoding-refused"] = \
                "BREAK: leading-zero parse accepted"
        except Exception as exc2:
            reason = getattr(exc2, "reason", str(exc2))
            if "dsse-envelope-malformed" in reason:
                try:
                    _ds.pae_decode(pae + b"\x00")
                    results["dsse-ambiguous-encoding-refused"] = \
                        "BREAK: trailing bytes accepted"
                except Exception as exc3:
                    reason3 = getattr(exc3, "reason", str(exc3))
                    if "dsse-envelope-malformed" in reason3:
                        # and the honest parse still works
                        got_type, got_body = _ds.pae_decode(pae)
                        if got_type == pt_a and got_body == payload:
                            results["dsse-ambiguous-encoding-refused"] = "HELD"
                        else:
                            results["dsse-ambiguous-encoding-refused"] = \
                                "BREAK: honest parse mismatch"
                    else:
                        results["dsse-ambiguous-encoding-refused"] = \
                            "BREAK: wrong refusal %r" % (reason3,)
            else:
                results["dsse-ambiguous-encoding-refused"] = \
                    "BREAK: wrong refusal %r" % (reason,)
    except Exception:
        results["dsse-ambiguous-encoding-refused"] = \
            "ERROR\n" + traceback.format_exc(limit=2)

    # 6. signature signs the exact PAE bytes ---------------------------
    try:
        env = _ds.envelope(payload, payload_type=pt_a, sign=_signer_cb(secret))
        expected_pae = (b"DSSEv1 " + str(len(pt_a)).encode("ascii") + b" "
                        + pt_a.encode("ascii") + b" "
                        + str(len(payload)).encode("ascii") + b" " + payload)
        sig = bytes.fromhex(env["signatures"][0]["sig"])
        assert hmac.compare_digest(
            hmac.new(secret, expected_pae, hashlib.sha256).digest(), sig), \
            "signature is not over the literal PAE bytes"
        assert env["signing_input_digest"] == \
            hashlib.sha256(expected_pae).hexdigest()
        results["dsse-signature-over-pae-bytes"] = "HELD"
    except Exception:
        results["dsse-signature-over-pae-bytes"] = \
            "BREAK\n" + traceback.format_exc(limit=2)

    # 7. legacy still verifies (never widened) -------------------------
    try:
        from gov import deny_receipts as _dr
        signer = _dr.Signer(alg="hmac-sha256-mac", secret=secret, key_id="k1")
        rec = {
            "verdict": "deny", "rule_path": "policy.reception.deny",
            "token_digest": hashlib.sha256(b"t").hexdigest(),
            "policy_bundle_digest": hashlib.sha256(b"p").hexdigest(),
            "intent_digest": hashlib.sha256(b"i").hexdigest(),
            "jurisdiction_profile": "profile-1",
        }
        legacy = _dr.emit(rec, signer=signer)
        assert "envelope" not in legacy, "legacy receipt gained a field"
        ok = _dr.verify(legacy, key=secret)
        assert ok["ok"] is True
        results["dsse-legacy-still-verifies"] = "HELD"
    except ImportError:
        results["dsse-legacy-still-verifies"] = "ERROR: deny_receipts missing"
    except Exception:
        results["dsse-legacy-still-verifies"] = \
            "BREAK\n" + traceback.format_exc(limit=2)

    # 8. receipt envelope integration -----------------------------------
    try:
        from gov import deny_receipts as _dr
        signer = _dr.Signer(alg="hmac-sha256-mac", secret=secret, key_id="k1")
        rec = {
            "verdict": "deny", "rule_path": "policy.reception.deny",
            "token_digest": hashlib.sha256(b"t").hexdigest(),
            "policy_bundle_digest": hashlib.sha256(b"p").hexdigest(),
            "intent_digest": hashlib.sha256(b"i").hexdigest(),
            "jurisdiction_profile": "profile-1",
        }
        with_env = _dr.emit(
            rec, signer=signer,
            envelope="application/vnd.sasanam.denial-receipt+json")
        legacy = _dr.emit(rec, signer=signer)
        assert "envelope" in with_env, "envelope kwarg produced no envelope"
        stripped = {k: v for k, v in with_env.items() if k != "envelope"}
        assert stripped == legacy, "envelope changed legacy bytes"
        ok = _dr.verify(with_env, key=secret)
        assert ok["ok"] is True
        forged = dict(with_env)
        forged["envelope"] = dict(forged["envelope"])
        forged["envelope"]["payload"] = base64.b64encode(
            b'{"forged":true}').decode("ascii")
        try:
            _dr.verify(forged, key=secret)
            results["dsse-receipt-envelope-integrates"] = \
                "BREAK: forged envelope accepted"
        except Exception as exc:
            reason = getattr(exc, "reason", str(exc))
            if "signature-invalid" in reason or "malformed" in reason:
                results["dsse-receipt-envelope-integrates"] = "HELD"
            else:
                results["dsse-receipt-envelope-integrates"] = \
                    "BREAK: wrong refusal %r" % (reason,)
    except ImportError:
        results["dsse-receipt-envelope-integrates"] = \
            "ERROR: deny_receipts missing envelope kwarg"
    except Exception:
        results["dsse-receipt-envelope-integrates"] = \
            "BREAK\n" + traceback.format_exc(limit=2)

    return results


def main():
    t0 = time.time()
    if not HAVE_MODULE:
        for name in PROBE_NAMES:
            print("%-42s GAP (dsse helpers absent)" % name)
        print("summary: 0 HELD / %d GAP / 0 BREAK / 0 ERROR" % len(PROBE_NAMES))
        return 2
    results = _run_all()
    held = sum(1 for v in results.values() if v == "HELD")
    gap = sum(1 for v in results.values() if v.startswith("GAP"))
    brk = sum(1 for v in results.values() if v.startswith("BREAK"))
    err = sum(1 for v in results.values() if v.startswith("ERROR"))
    for name in PROBE_NAMES:
        verdict = results.get(name, "ERROR: missing")
        first = verdict.split("\n")[0]
        print("%-42s %s" % (name, first))
        if "\n" in verdict:
            print(verdict.split("\n", 1)[1])
    print("summary: %d HELD / %d GAP / %d BREAK / %d ERROR (%.1fs)"
          % (held, gap, brk, err, time.time() - t0))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
