#!/usr/bin/env python3
"""Wave-318 Lane 3 battery: trust-root refresh (gov/trust_root_refresh.py).

The offline verifier's trust root was a static compiled-in document: no
rotation story, no freshness signal, no expiry semantics. This battery
proves the versioned trust-root chain end-to-end at the public seams,
RED-FIRST: it is written before the wiring exists and must FAIL on the
open tree.

Probe map (public seams only -- verify() / consume_vsa()):
  chain-rotated-root-verifies: rotation ceremony (signed by the old
      root) adopts v2; a bundle whose policy is sealed by the v2 key
      verifies under trust_chain=[v1, v2] with a fresh signal.
  chain-pre-rotation-bundle-under-old-root: a bundle sealed under v1
      still verifies against the v1-only chain (rotation never
      retroactively invalidates).
  chain-expired-root-fails-closed: tip validity window ends before the
      bundle time -> coded trust-root-expired.
  chain-silent-swap-fails-closed: a v2 link with no rotation record ->
      coded trust-root-silent-swap (never silently adopted).
  chain-stale-freshness-fails-closed: freshness older than the window ->
      coded trust-root-stale-freshness.
  chain-expiry-at-timestamp-grace: CVE-2026-24122 -- the tip expired an
      hour ago but the bundle's observer timestamp is inside the window:
      still HELD (expiry is evaluated at the timestamp's time, not now).
  chain-mutual-exclusion: trust_root + trust_chain together -> loud
      InternalError (ambiguous anchor), never a silent preference.
  vsa-consume-with-chain-ok: consume_vsa with expected["trust_chain"]
      verifies the decision packet.
  vsa-consume-expired-chain-refused: VSA under an expired chain ->
      coded trust-root-expired at the VSA's timeVerified.
  vsa-consume-stale-freshness-refused: VSA with a stale freshness
      signal -> coded trust-root-stale-freshness.
  pin-taxonomy / footer-state: standard pins (1973; open none / next
      F406).
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import green_check  # noqa: E402  (shared fail-closed green checks)
import probe_lines  # noqa: E402  (canonical probe-line emission)

from gov import decision_codes as dc  # noqa: E402
from gov import evidence_verify_offline as v  # noqa: E402
from gov import trust_root_refresh as trr  # noqa: E402
from gov import vsa_packet as vp  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


FOOTER_NEXT = "F612"  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)


FOOTER_OPEN = "F595, F606, F608, F609, F610, F611"    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint



_results = []
PROBES = []


def probe(name):
    def deco(fn):
        PROBES.append((name, fn))
        return fn
    return deco


def _held(pid, note):
    _results.append({"probe_id": pid, "verdict": "HELD", "note": note})
    return "HELD", note


def _break(pid, note):
    _results.append({"probe_id": pid, "verdict": "BREAK", "note": note})
    return "BREAK", note


def _error(pid, note):
    _results.append({"probe_id": pid, "verdict": "ERROR", "note": note})
    return "ERROR", note


# ---------------------------------------------------------------------------
# Fixtures (the tests/test_evidence_verify_offline.py pattern).
# ---------------------------------------------------------------------------

import base64  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

from gov import ed25519  # noqa: E402

NOW = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
EV_SEED = "11" * 32
TSA_SEED = "22" * 32
NEW_SEED = "44" * 32  # rotation-target root key (test-local, not a secret)
# TEST-ONLY policy-anchor seed: seals test policies under v1. Synthetic
# placeholder; NEVER in the module (the module pins only the pubkey).
ANCHOR_SEED = "02eb4cee77eb9c934286078d60f8960f6a038a6c9b04906d940ed521de3fa3b6"
BUNDLE_BYTES = b'{\"evidence\":\"w318-trustroot-battery\"}\\n'
PREDICATE_TYPE = "https://sasanam.dev/evidence-predicate/v1"


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


def _policy_doc(ev, tsa, expires, min_ts=0, max_age_hours=168):
    return {
        "version": "sasanam-verification-policy/v1",
        "policy_id": "w318-trustroot-policy",
        "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "required_predicate_type": PREDICATE_TYPE,
        "required_predicate_claims": ["window"],
        "evidence_signing": {
            "threshold": 1,
            "keys": [{"keyid": s.keyid(), "pubkey_hex": s.pubkey_hex()}
                     for s in ev],
        },
        "observer_timestamps": {"min": min_ts,
                                "max_age_hours": max_age_hours},
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


def _bundle(policy_signer, ev_signer, tsa_signer, timestamps=(), min_ts=0,
            max_age_hours=168):
    ev = ev_signer
    stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact.bin",
                     "digest": {"sha256": hashlib.sha256(BUNDLE_BYTES)
                                .hexdigest()}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {"window": "2026-10-03T00:00:00Z"},
    }
    payload = v.canonical(stmt)
    policy = _policy_doc([ev], [tsa_signer], NOW + timedelta(days=10),
                         min_ts=min_ts, max_age_hours=max_age_hours)
    vb = {
        "version": v.BUNDLE_VERSION,
        "envelope": _seal(payload, v.ENVELOPE_PAYLOAD_TYPE, [ev]),
        "policy": _seal(v.canonical(policy), v.POLICY_PAYLOAD_TYPE,
                        [policy_signer]),
        "timestamps": list(timestamps),
    }
    return vb, BUNDLE_BYTES


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _genesis_v1(**kw):
    kw.setdefault("source_commit", "sasanam@c5c95ae3")
    kw.setdefault("review_date", _iso(NOW - timedelta(days=30)))
    return trr.genesis_entry(v.COMPILED_TRUST_ROOT, **kw)


def _v2_doc():
    s = _signer(NEW_SEED)
    return {"version": v.TRUST_ROOT_VERSION,
            "policy_keys": [{"keyid": s.keyid(),
                             "pubkey_hex": s.pubkey_hex()}]}


def _rotated_chain(v1):
    rec = trr.build_rotation_record(
        v1, _v2_doc(), source_commit="sasanam@w318",
        review_date=_iso(NOW - timedelta(days=1)),
        signers=[_signer(ANCHOR_SEED)])
    return trr.adopt_rotation([v1], rec, _v2_doc(),
                              now=NOW - timedelta(days=1))


def _fresh(tip, issued_at=NOW, seed=ANCHOR_SEED):
    return trr.build_freshness_statement(tip, issued_at=issued_at,
                                         signers=[_signer(seed)])


def _verify(vb, bb, chain, fresh, **kw):
    return v.verify(bb, vb, trust_chain=chain, chain_freshness=fresh,
                    time_source=v.FixedClock("t", NOW), **kw)


def _expect_code(pid, fn, code):
    try:
        fn()
    except v.VerificationError as exc:
        if exc.code == code:
            return _held(pid, "coded %s" % code)
        return _break(pid, "wrong code %r, want %r: %s"
                      % (exc.code, code, exc.detail))
    except v.InternalError as exc:
        return _error(pid, "InternalError: %s" % exc)
    return _break(pid, "no refusal raised")


# ---------------------------------------------------------------------------
# Chain probes at the verify() seam.
# ---------------------------------------------------------------------------

@probe("chain-rotated-root-verifies")
def _p_rotated():
    v1 = _genesis_v1()
    chain = _rotated_chain(v1)
    vb, bb = _bundle(_signer(NEW_SEED), _signer(EV_SEED),
                     _signer(TSA_SEED))
    rep = _verify(vb, bb, chain, _fresh(chain[-1], seed=NEW_SEED))
    if rep.get("status") == "VALID":
        return _held("chain-rotated-root-verifies",
                     "v2 bundle verifies after the rotation record")
    return _break("chain-rotated-root-verifies",
                  "unexpected report status %r" % rep.get("status"))


@probe("chain-pre-rotation-bundle-under-old-root")
def _p_prerotation():
    v1 = _genesis_v1()
    vb, bb = _bundle(_signer(ANCHOR_SEED), _signer(EV_SEED),
                     _signer(TSA_SEED))
    rep = _verify(vb, bb, [v1], _fresh(v1))
    if rep.get("status") == "VALID":
        return _held("chain-pre-rotation-bundle-under-old-root",
                     "v1 bundle verifies under the v1-only chain")
    return _break("chain-pre-rotation-bundle-under-old-root",
                  "unexpected report status %r" % rep.get("status"))


@probe("chain-expired-root-fails-closed")
def _p_expired():
    v1 = _genesis_v1(valid_until=_iso(NOW - timedelta(hours=1)))
    vb, bb = _bundle(_signer(ANCHOR_SEED), _signer(EV_SEED),
                     _signer(TSA_SEED))
    return _expect_code(
        "chain-expired-root-fails-closed",
        lambda: _verify(vb, bb, [v1], _fresh(v1)), "trust-root-expired")


@probe("chain-silent-swap-fails-closed")
def _p_silent_swap():
    v1 = _genesis_v1()
    v2 = trr.make_entry(_v2_doc(), chain_version=2,
                        source_commit="sasanam@evil",
                        review_date=_iso(NOW))
    vb, bb = _bundle(_signer(NEW_SEED), _signer(EV_SEED),
                     _signer(TSA_SEED))
    return _expect_code(
        "chain-silent-swap-fails-closed",
        lambda: _verify(vb, bb, [v1, v2], _fresh(v2, seed=NEW_SEED)),
        "trust-root-silent-swap")


@probe("chain-stale-freshness-fails-closed")
def _p_stale():
    v1 = _genesis_v1()
    vb, bb = _bundle(_signer(ANCHOR_SEED), _signer(EV_SEED),
                     _signer(TSA_SEED))
    return _expect_code(
        "chain-stale-freshness-fails-closed",
        lambda: _verify(vb, bb, [v1],
                        _fresh(v1, issued_at=NOW - timedelta(hours=48))),
        "trust-root-stale-freshness")


@probe("chain-expiry-at-timestamp-grace")
def _p_grace():
    # CVE-2026-24122: the tip expired an hour ago, but the bundle's
    # observer timestamp is inside the window -> HELD.
    ts_time = NOW - timedelta(hours=2)
    v1 = _genesis_v1(valid_from=_iso(NOW - timedelta(days=30)),
                     valid_until=_iso(NOW - timedelta(hours=1)))
    tsa = _signer(TSA_SEED)
    body = {"authority_id": tsa.keyid(),
            "time": _iso(ts_time),
            "evidence_digest": hashlib.sha256(BUNDLE_BYTES).hexdigest()}
    token = dict(body, sig=base64.b64encode(
        tsa.sign(v.canonical(body))).decode("ascii"))
    vb, bb = _bundle(_signer(ANCHOR_SEED), _signer(EV_SEED), tsa,
                     timestamps=[token], min_ts=1, max_age_hours=24 * 90)
    try:
        rep = _verify(vb, bb, [v1], _fresh(v1))
    except v.VerificationError as exc:
        return _break("chain-expiry-at-timestamp-grace",
                      "refused %s: %s" % (exc.code, exc.detail))
    if rep.get("status") == "VALID":
        return _held("chain-expiry-at-timestamp-grace",
                     "bundle timestamped inside the window verifies "
                     "after the root expired")
    return _break("chain-expiry-at-timestamp-grace",
                  "unexpected report status %r" % rep.get("status"))


@probe("chain-mutual-exclusion")
def _p_exclusion():
    v1 = _genesis_v1()
    vb, bb = _bundle(_signer(ANCHOR_SEED), _signer(EV_SEED),
                     _signer(TSA_SEED))
    try:
        v.verify(bb, vb, trust_root=v.COMPILED_TRUST_ROOT,
                 trust_chain=[v1], chain_freshness=_fresh(v1),
                 time_source=v.FixedClock("t", NOW))
    except v.InternalError:
        return _held("chain-mutual-exclusion",
                     "trust_root + trust_chain -> loud InternalError")
    except v.VerificationError as exc:
        return _break("chain-mutual-exclusion",
                      "wrong error class: %s" % exc.code)
    return _break("chain-mutual-exclusion", "no error raised")


# ---------------------------------------------------------------------------
# Chain probes at the consume_vsa() seam.
# ---------------------------------------------------------------------------

VSA_SEED = "dd" * 32
VSA_VERIFIER = "sasanam-offline-verifier"
VSA_TIME_VERIFIED = "2026-09-20T12:00:00Z"
VSA_NOW = 1790320800  # 2026-09-20T13:00:00Z, inside the consumer window


def _vsa_report(**over):
    rep = {
        "status": "VALID",
        "verificationResult": "PASSED",
        "verifier": {"id": VSA_VERIFIER, "version": "1.0.0"},
        "timeVerified": VSA_TIME_VERIFIED,
        "timeSource": {"name": "test-clock"},
        "resourceUri": "sha256:" + hashlib.sha256(b"vsa-decision")
        .hexdigest(),
        "policy": {
            "uri": "sasanam:policy/unit-test",
            "digest": {"sha256": hashlib.sha256(b"vsa-policy").hexdigest()},
            "expires": "2027-09-20T12:00:00Z",
        },
        "inputAttestations": [
            {"uri": "dsse-envelope",
             "digest": {"sha256": hashlib.sha256(b"vsa-report")
                        .hexdigest()}},
        ],
        "witness": None,
        "checks": [{"step": "x", "result": "pass", "detail": "y"}],
    }
    rep.update(over)
    return rep


def _vsa_envelope():
    signer = vp.packet_key_signer(VSA_SEED)
    digest = hashlib.sha256(b"vsa-decision").hexdigest()
    return vp.issue_decision_vsa(
        decision_digest=digest, report=_vsa_report(),
        verified_levels=["SLSA_BUILD_LEVEL_1"], signer=signer), digest


def _vsa_expected(chain, freshness, **over):
    exp = {
        "subject_digest": over.pop("digest"),
        "resource_uri": "sasanam:decision-packet/" + over.pop("digest2"),
        "verifier_id": VSA_VERIFIER,
        "required_level": "SLSA_BUILD_LEVEL_1",
        "signer_registry": {
            VSA_VERIFIER: [ed25519.publickey(bytes.fromhex(VSA_SEED))
                           .hex()]},
        "now": VSA_NOW,
        "max_age_seconds": 86400 * 30,
        "trust_chain": {"chain": chain, "freshness": freshness,
                        "max_age_seconds": 86400},
    }
    exp.update(over)
    return exp


def _vsa_chain(**kw):
    s = _signer(VSA_SEED)
    doc = {"version": v.TRUST_ROOT_VERSION,
           "policy_keys": [{"keyid": s.keyid(),
                            "pubkey_hex": s.pubkey_hex()}]}
    kw.setdefault("source_commit", "sasanam@c5c95ae3")
    kw.setdefault("review_date", "2026-09-01T00:00:00Z")
    kw.setdefault("valid_from", "2026-09-01T00:00:00Z")
    kw.setdefault("valid_until", "2026-12-01T00:00:00Z")
    return [trr.genesis_entry(doc, **kw)]


@probe("vsa-consume-with-chain-ok")
def _p_vsa_ok():
    env, digest = _vsa_envelope()
    chain = _vsa_chain()
    fresh = trr.build_freshness_statement(
        chain[0], issued_at=datetime.fromtimestamp(VSA_NOW, tz=timezone.utc),
        signers=[_signer(VSA_SEED)])
    exp = _vsa_expected(chain, fresh, digest=digest, digest2=digest)
    out = vp.consume_vsa(env, expected=exp)
    if out.get("ok") is True:
        return _held("vsa-consume-with-chain-ok",
                     "VSA consumed under a live trust root")
    return _break("vsa-consume-with-chain-ok", "not ok: %r" % (out,))


@probe("vsa-consume-expired-chain-refused")
def _p_vsa_expired():
    env, digest = _vsa_envelope()
    chain = _vsa_chain(valid_until="2026-09-19T00:00:00Z")
    fresh = trr.build_freshness_statement(
        chain[0], issued_at=datetime.fromtimestamp(VSA_NOW, tz=timezone.utc),
        signers=[_signer(VSA_SEED)])
    exp = _vsa_expected(chain, fresh, digest=digest, digest2=digest)
    try:
        vp.consume_vsa(env, expected=exp)
    except vp.VSAPacketError as exc:
        if exc.code == "trust-root-expired":
            return _held("vsa-consume-expired-chain-refused",
                         "coded trust-root-expired at timeVerified")
        return _break("vsa-consume-expired-chain-refused",
                      "wrong code %r" % exc.code)
    return _break("vsa-consume-expired-chain-refused", "no refusal")


@probe("vsa-consume-stale-freshness-refused")
def _p_vsa_stale():
    env, digest = _vsa_envelope()
    chain = _vsa_chain()
    fresh = trr.build_freshness_statement(
        chain[0],
        issued_at=datetime.fromtimestamp(VSA_NOW - 90000, tz=timezone.utc),
        signers=[_signer(VSA_SEED)])
    exp = _vsa_expected(chain, fresh, digest=digest, digest2=digest)
    try:
        vp.consume_vsa(env, expected=exp)
    except vp.VSAPacketError as exc:
        if exc.code == "trust-root-stale-freshness":
            return _held("vsa-consume-stale-freshness-refused",
                         "coded trust-root-stale-freshness")
        return _break("vsa-consume-stale-freshness-refused",
                      "wrong code %r" % exc.code)
    return _break("vsa-consume-stale-freshness-refused", "no refusal")


# ---------------------------------------------------------------------------
# Pins.
# ---------------------------------------------------------------------------

@probe("pin-taxonomy")
def _p_pin():
    n = len(dc.TAXONOMY)
    if n != TAXONOMY_PIN:
        return _break("pin-taxonomy",
                      "taxonomy %d, want %d" % (n, TAXONOMY_PIN))
    return _held("pin-taxonomy", "%d codes" % n)


@probe("footer-state")
def _p_footer():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    import re
    m = list(re.finditer(r"Next free finding: \*\*(F\d+)\*\*\. "
                         r"\*\*Open findings: ([^*]*)\*\*",
                         text))
    if not m:
        return _error("footer-state", "footer not found")
    last = m[-1]
    nxt, opens = last.group(1), last.group(2).strip().rstrip(".")
    if nxt != FOOTER_NEXT or opens != FOOTER_OPEN:
        return _break("footer-state",
                      "footer %s / %s, want %s / %s"
                      % (nxt, opens, FOOTER_NEXT, FOOTER_OPEN))
    return _held("footer-state",
                 "open %s / next %s" % (opens, nxt))


def green_check():
    """Depth-1 green check: adjacent seams still green. Honors
    GOV_SKIP_GREEN (the wave-173 convention)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green_check: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    env = dict(os.environ, GOV_SKIP_GREEN="1",
               GOV_DEPLOYMENT_MODE="staging")
    suites = ["tests.test_trust_root_refresh",
              "tests.test_evidence_verify_offline",
              "tests.test_vsa_packet",
              "tests.test_decision_codes"]
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
    probe_lines.emit_dicts(
        _results, verdict_key="verdict", pid_key="probe_id",
        note_key="note")
    print("probes: %d held / %d BREAK / %d errors" % (held, broke, errors))
    print("green_check:", "OK" if green_check() else "FAIL")
    return 0 if (broke == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
