"""Break-first red battery for gov/vsa_packet.py (wave-315 lane 2).

Every probe asserts a refusal (or the happy-path acceptance) at the public
seams ``issue_decision_vsa`` / ``consume_vsa``. Probe 1 runs the REAL
offline-verification pipeline (``gov.evidence_verify_offline.verify``) to
produce the report the VSA wraps -- the happy path is end-to-end, not a
hand-built fixture.

Result contract: each probe prints ``HELD`` (refusal/acceptance as designed),
``BREAK`` (the attack succeeded -- a real finding), or ``ERROR`` (harness
fault). Exit 0 iff no BREAK and no ERROR.

Depth-1 green check honoring GOV_SKIP_GREEN; no in-repo git subprocesses;
deterministic (fixed seeds, fixed clock); stdlib only.
"""

import base64
import calendar
import hashlib
import json
import os
import sys
import traceback
from datetime import datetime, timedelta, timezone

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from gov import ed25519
from gov import evidence_verify_offline as v
from gov import vsa_packet as vp
from gov import decision_codes as dc

# -- fixed test material ----------------------------------------------------
SEED_A = "aa" * 32  # packet-signing key for the (pinned) verifier
SEED_B = "bb" * 32  # an untrusted signer's key
NOW = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
NOW_EPOCH = calendar.timegm(NOW.timetuple())
EV_SEED = "11" * 32   # evidence-signing key inside the offline bundle
TSA_SEED = "22" * 32
ANCHOR_SEED = ("02eb4cee77eb9c934286078d60f8960f6a038a6c9b04906d940ed521de3fa3b6")
BUNDLE_BYTES = b'{"evidence":"w315-vsa-probe"}\n'
PREDICATE_TYPE = "https://sasanam.dev/evidence-predicate/v1"
DECISION_DIGEST = hashlib.sha256(b"decision-packet-w315").hexdigest()
OTHER_DIGEST = hashlib.sha256(b"a-different-decision").hexdigest()
MAX_AGE = 86400 * 30


def _signer(seed_hex):
    seed = bytes.fromhex(seed_hex)
    pub = ed25519.publickey(seed)
    keyid = hashlib.sha256(pub).hexdigest()[:16]

    class _S(object):
        def keyid(self):
            return keyid

        def pubkey_hex(self):
            return pub.hex()

        def sign(self, msg):
            return ed25519.sign(seed, msg)

    return _S()


def _seal(payload, ptype, signers):
    msg = v.pae(ptype, payload)
    return {
        "payload": base64.b64encode(payload).decode("ascii"),
        "payloadType": ptype,
        "signatures": [
            {"keyid": s.keyid(),
             "sig": base64.b64encode(s.sign(msg)).decode("ascii")}
            for s in signers
        ],
    }


def _policy_doc(ev, tsa, expires):
    return {
        "version": "sasanam-verification-policy/v1",
        "policy_id": "w315-vsa-probe-policy",
        "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "required_predicate_type": PREDICATE_TYPE,
        "required_predicate_claims": ["window"],
        "evidence_signing": {
            "threshold": 1,
            "keys": [{"keyid": s.keyid(), "pubkey_hex": s.pubkey_hex()}
                     for s in ev],
        },
        "observer_timestamps": {"min": 0, "max_age_hours": 168},
        "timestamp_authorities": [
            {"authority_id": s.keyid(), "pubkey_hex": s.pubkey_hex(),
             "valid_for": {
                 "not_before": (NOW - timedelta(days=30))
                 .strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "not_after": (NOW + timedelta(days=30))
                 .strftime("%Y-%m-%dT%H:%M:%SZ")}}
            for s in tsa
        ],
    }


def _real_report():
    """Run the real offline pipeline; return its VALID report."""
    ev = _signer(EV_SEED)
    stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact.bin",
                     "digest": {"sha256": hashlib.sha256(BUNDLE_BYTES)
                                .hexdigest()}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {"window": "2026-10-03T00:00:00Z"},
    }
    payload = v.canonical(stmt)
    policy = _policy_doc([ev], [_signer(TSA_SEED)], NOW + timedelta(days=10))
    vb = v.build_verification_bundle(
        _seal(payload, v.ENVELOPE_PAYLOAD_TYPE, [ev]),
        _seal(v.canonical(policy), v.POLICY_PAYLOAD_TYPE,
              [_signer(ANCHOR_SEED)]))
    return v.verify(BUNDLE_BYTES, vb, time_source=v.FixedClock("t", NOW))


def _pubkey_hex(seed_hex):
    return ed25519.publickey(bytes.fromhex(seed_hex)).hex()


def _expected(**over):
    exp = {
        "subject_digest": DECISION_DIGEST,
        "resource_uri": vp.DECISION_URI_SCHEME + DECISION_DIGEST,
        "verifier_id": v.VERIFIER_ID,
        "required_level": "SLSA_BUILD_LEVEL_1",
        "signer_registry": {v.VERIFIER_ID: [_pubkey_hex(SEED_A)]},
        "now": NOW_EPOCH + 3600,
        "max_age_seconds": MAX_AGE,
    }
    exp.update(over)
    return exp


def _issue(report=None, levels=None, seed=SEED_A, digest=DECISION_DIGEST):
    signer = vp.packet_key_signer(seed)
    return vp.issue_decision_vsa(
        decision_digest=digest,
        report=_real_report() if report is None else report,
        verified_levels=(["SLSA_BUILD_LEVEL_1"] if levels is None else levels),
        signer=signer)


def _decode(env):
    return json.loads(base64.b64decode(env["payload"]))


def _reseal_statement(env, statement, seed=SEED_A):
    payload = vp._canonical(statement)
    return vp._dsse().seal(payload, vp.VSA_PAYLOAD_TYPE,
                           [vp.packet_key_signer(seed)])


# -- probe harness ------------------------------------------------------------
PROBES = []


def probe(name):
    def deco(fn):
        PROBES.append((name, fn))
        return fn
    return deco


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _expect_refusal(code, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except vp.VSAPacketError as exc:
        if exc.code == code:
            return _held("refused %s" % code)
        return _break("refused %s, expected %s" % (exc.code, code))
    except Exception as exc:  # noqa: BLE001 -- harness fault surface
        return ("ERROR", "%r" % (exc,))
    return _break("accepted; expected refusal %s" % code)


@probe("01-happy-path-real-pipeline")
def p01():
    report = _real_report()
    assert report["status"] == "VALID" and report["verificationResult"] == "PASSED"
    env = _issue(report)
    out = vp.consume_vsa(env, expected=_expected())
    assert out["ok"] is True
    assert out["subject_digest"] == DECISION_DIGEST
    assert out["verifier"]["id"] == v.VERIFIER_ID
    return _held("real pipeline report -> issue -> consume ok")


@probe("02-determinism")
def p02():
    report = _real_report()
    if _issue(report) != _issue(report):
        return _break("issue is not deterministic")
    return _held("byte-identical envelopes")


@probe("03-swapped-decision-digest")
def p03():
    env = _issue(digest=OTHER_DIGEST)  # VSA minted for a DIFFERENT decision
    return _expect_refusal("vsa-packet-subject-mismatch",
                           vp.consume_vsa, env, expected=_expected())


@probe("04-cross-decision-replay")
def p04():
    env = _issue()
    exp = _expected(resource_uri=vp.DECISION_URI_SCHEME + OTHER_DIGEST)
    return _expect_refusal("vsa-packet-resource-mismatch",
                           vp.consume_vsa, env, expected=exp)


@probe("05-untrusted-verifier-key")
def p05():
    env = _issue(seed=SEED_B)  # signed by a key the registry never pinned
    return _expect_refusal("vsa-packet-signer-unpinned",
                           vp.consume_vsa, env, expected=_expected())


@probe("06-verifier-keyid-cross")
def p06():
    # the key IS pinned -- but under a different verifier id than the
    # statement's verifier.id claims. Pair check must still refuse.
    env = _issue()
    exp = _expected(
        signer_registry={"test-verifier-a": [_pubkey_hex(SEED_A)],
                         "test-verifier-b": [_pubkey_hex(SEED_B)]},
        verifier_id="test-verifier-a")
    return _expect_refusal("vsa-packet-verifier-mismatch",
                           vp.consume_vsa, env, expected=exp)


@probe("07-issue-over-invalid-report")
def p07():
    bad = dict(_real_report(), status="INVALID", verificationResult="FAILED")
    try:
        _issue(bad)
    except ValueError:
        return _held("issuer refused non-VALID report")
    return _break("minted a VSA over an INVALID report")


@probe("08-issue-over-failed-result")
def p08():
    bad = dict(_real_report(), verificationResult="FAILED")
    try:
        _issue(bad)
    except ValueError:
        return _held("issuer refused non-PASSED result")
    return _break("minted a PASSED VSA over FAILED evidence")


@probe("09-truncated-attestations")
def p09():
    env = _issue()
    stmt = _decode(env)
    stmt["predicate"]["inputAttestations"] = []  # attacker strips pins
    tampered = dict(env)
    tampered["payload"] = base64.b64encode(
        vp._canonical(stmt)).decode("ascii")
    return _expect_refusal("vsa-packet-signature-invalid",
                           vp.consume_vsa, tampered, expected=_expected())


@probe("10-forged-signature")
def p10():
    env = _issue()
    sig = bytearray.fromhex(env["signatures"][0]["sig"])
    sig[0] ^= 0xFF
    forged = dict(env)
    forged["signatures"] = [dict(env["signatures"][0], sig=bytes(sig).hex())]
    return _expect_refusal("vsa-packet-signature-invalid",
                           vp.consume_vsa, forged, expected=_expected())


@probe("11-wrong-predicate-type")
def p11():
    env = _issue()
    stmt = _decode(env)
    stmt["predicateType"] = "https://example.com/not-a-vsa"
    resealed = _reseal_statement(env, stmt)  # insider with the key
    return _expect_refusal("vsa-packet-predicate-mismatch",
                           vp.consume_vsa, resealed, expected=_expected())


@probe("12-hand-sealed-failed-result")
def p12():
    env = _issue()
    stmt = _decode(env)
    stmt["predicate"]["verificationResult"] = "FAILED"
    resealed = _reseal_statement(env, stmt)
    return _expect_refusal("vsa-packet-result-not-passed",
                           vp.consume_vsa, resealed, expected=_expected())


@probe("13-missing-required-level")
def p13():
    env = _issue(levels=["SLSA_BUILD_LEVEL_1"])
    exp = _expected(required_level="SLSA_BUILD_LEVEL_3")
    return _expect_refusal("vsa-packet-levels-missing",
                           vp.consume_vsa, env, expected=exp)


@probe("14-expired-window")
def p14():
    env = _issue()
    exp = _expected(now=NOW_EPOCH + MAX_AGE + 86400)
    return _expect_refusal("vsa-packet-window-invalid",
                           vp.consume_vsa, env, expected=exp)


@probe("15-future-timeverified")
def p15():
    env = _issue()
    exp = _expected(now=NOW_EPOCH - 86400)  # before timeVerified
    return _expect_refusal("vsa-packet-window-invalid",
                           vp.consume_vsa, env, expected=exp)


@probe("16-decision-packet-transplant")
def p16():
    env = _issue()
    transplant = dict(env)
    transplant["payloadType"] = \
        "application/vnd.sasanam.decision-packet.v1+json"
    return _expect_refusal("vsa-packet-malformed",
                           vp.consume_vsa, transplant, expected=_expected())


@probe("17-double-signature")
def p17():
    env = _issue()
    doubled = dict(env)
    doubled["signatures"] = env["signatures"] * 2
    return _expect_refusal("vsa-packet-malformed",
                           vp.consume_vsa, doubled, expected=_expected())


@probe("18-hostile-shapes")
def p18():
    bad_inputs = [
        None, [], "string", {},
        {"payload": "e30=", "payloadType": vp.VSA_PAYLOAD_TYPE},
        {"payload": "!!!", "payloadType": vp.VSA_PAYLOAD_TYPE,
         "signatures": []},
        {"payload": base64.b64encode(b"not json").decode(),
         "payloadType": vp.VSA_PAYLOAD_TYPE,
         "signatures": [{"keyid": "x", "sig": "00" * 64}]},
    ]
    for bad in bad_inputs:
        verdict, detail = _expect_refusal(
            "vsa-packet-malformed", vp.consume_vsa, bad,
            expected=_expected())
        if verdict != "HELD":
            return (verdict, "shape %r: %s" % (bad, detail))
    return _held("8 hostile shapes refused malformed")


@probe("19-passed-is-not-allow")
def p19():
    out = vp.consume_vsa(_issue(), expected=_expected())
    for forbidden in ("verdict", "allow", "decision", "authorized"):
        if forbidden in out:
            return _break("consumer returns %r -- PASSED became a verdict"
                          % forbidden)
    return _held("consumer returns claims only; no authorization verdict")


@probe("20-pin-and-footer")
def p20():
    codes = set(dc.TAXONOMY)  # keys are the code strings
    missing = [c for c in vp._VERDICTS if c not in codes]
    if missing:
        return _break("codes missing from TAXONOMY: %s" % missing)
    if len(dc.TAXONOMY) != 2131:
        return _break("TAXONOMY len %d, expected 2131" % len(dc.TAXONOMY))
    from gov import guac_graph
    if guac_graph.TAXONOMY_PIN != 2131:


        return _break("TAXONOMY_PIN is %r" % (guac_graph.TAXONOMY_PIN,))
    return _held("10 codes registered; pin 2131")


def green_check():
    """Depth-1 green check: adjacent seams still green. Honors
    GOV_SKIP_GREEN (the wave-173 convention)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green_check: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    env = dict(os.environ, GOV_SKIP_GREEN="1",
               GOV_DEPLOYMENT_MODE="staging")
    suites = ["tests.test_vsa_packet", "tests.test_evidence_verify_offline",
              "tests.test_decision_packet", "tests.test_bundle_vsa"]
    ok = True
    for suite in suites:
        try:
            r = subprocess.run(
                [sys.executable, "-m", "unittest", suite],
                cwd=REPO, env=env, capture_output=True, text=True,
                timeout=300)
        except Exception as exc:  # noqa: BLE001
            print("green_check: %s ERROR %r" % (suite, exc))
            ok = False
            continue
        status = "OK" if r.returncode == 0 else "FAIL"
        print("green_check: %s %s" % (suite, status))
        if r.returncode != 0:
            ok = False
            print(r.stderr[-2000:])
    return ok


def main():
    held = broke = errors = 0
    for name, fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception:  # noqa: BLE001
            verdict, detail = "ERROR", traceback.format_exc(limit=3)
        print("%-42s %s %s" % (name, verdict, detail))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            broke += 1
        else:
            errors += 1
    print("probes: %d held / %d BREAK / %d errors" % (held, broke, errors))
    print("green_check:", "OK" if green_check() else "FAIL")
    return 0 if (broke == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
