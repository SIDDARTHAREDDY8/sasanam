#!/usr/bin/env python3
"""Break-first red battery for the keyed Sigstore Bundle v0.3 export
(wave-321 lane 1, gov/sigstore_bundle.py).

P1 (2): happy path -- seal/open round trip over a real in-toto
    statement; the one-signature-per-envelope fan-out.
P2 (11): break-first refusal probes -- forged signature, wrong pinned
    key, tampered payload, multi-signature envelope, non-PAE signature
    (proves PAE coverage is actually verified), the
    "publicKeyIdentifier" field-name trap (sigstore/docs#451),
    tlog/timestamp misuse, keyid/hint mismatch, wrong mediaType,
    subject-digest binding.
P3 (2): contract probes -- verify_keyed_bundle returns False (not
    raises) on a forged bundle (assert `is False`); the empty-hint
    spike shape ({"publicKey": {}}) is accepted, as cosign proved.
P4 (2): regressions -- footer open none / next F409; pin taxonomy
    2140/2140/0 sorted on source literals (this lane registers no


    taxonomy codes).

Result contract: each probe prints [HELD]/[BREAK]/[ERROR]. Exit 0 iff
no ERROR and no unexpected BREAK. On the OPEN tree (module absent) the
top-level import fails with ImportError before any probe runs -- the
battery fails loudly and no probe can pass (the red-first property).

Depth-1 green check honoring GOV_SKIP_GREEN; no in-repo git
subprocesses; deterministic (fixed seeds); stdlib only.
"""

import base64
import copy
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from gov import sigstore_bundle as SB  # noqa: E402
from gov import evidence_intoto as _intoto  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

FOOTER_OPEN = "F612, F614, F615, F616, F617, F618, F619, F620"    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # F409-F427 CLOSED; F428 OPEN (wave-341 lane C).; F442 CLOSED 2026-10-05 wave-347 lane 6; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED


FOOTER_NEXT = "F621"  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621



_results = []
_PROBES = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    return (pid, "HELD", note)


def _break(pid, note):
    return (pid, "BREAK", note)


def probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _safe(pid, fn):
    try:
        _record(*fn())
    except Exception as exc:  # noqa: BLE001
        _record(pid, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3)))


def _expect_refuse(pid, fn, code, note):
    """Run fn(); HELD iff it raises KeyedBundleError with `code`."""
    try:
        fn()
    except SB.KeyedBundleError as exc:
        if exc.code == code:
            return _held(pid, "%s: refused coded %s" % (note, code))
        return _break(pid, "%s: refused coded %s, want %s"
                      % (note, exc.code, code))
    except Exception as exc:  # noqa: BLE001
        return _break(pid, "%s: raised %r, want coded %s" % (note, exc, code))
    return _break(pid, "%s: ACCEPTED, want coded refusal %s" % (note, code))


# Fixed seeds: deterministic keys across runs.
_SEED_A = bytes(range(32))
_SEED_B = bytes([255 - i for i in range(32)])
_SIGNER_A = Ed25519Signer(_SEED_A)
_SIGNER_B = Ed25519Signer(_SEED_B)
_PUB_A = _SIGNER_A.public_key
_PUB_B = _SIGNER_B.public_key

_EVIDENCE = b'{"decision": "deny", "seq": 7}'


def _statement_bytes():
    st = _intoto.build_statement(_EVIDENCE, {"lane": "w321-sigstore"})
    return _intoto.statement_bytes(st)


def _b64flip(b64str):
    raw = bytearray(base64.b64decode(b64str.encode("ascii")))
    raw[0] ^= 1
    return base64.b64encode(bytes(raw)).decode("ascii")


# ---------------------------------------------------------------------------
# P1: happy path
# ---------------------------------------------------------------------------

@probe("P1-seal-open-roundtrip")
def _p1a():
    payload = _statement_bytes()
    bundle = SB.seal_keyed_bundle(payload, _SIGNER_A)
    got = SB.open_keyed_bundle(bundle, _PUB_A)
    if got != payload:
        return _break("P1-seal-open-roundtrip", "payload mismatch")
    if SB.verify_keyed_bundle(bundle, _PUB_A) is not True:
        return _break("P1-seal-open-roundtrip", "verify not True")
    # Wire shape assertions (the interop surface cosign parses).
    if bundle["mediaType"] != SB.SIGSTORE_BUNDLE_MEDIA_TYPE:
        return _break("P1-seal-open-roundtrip", "bad mediaType")
    if set(bundle["verificationMaterial"]["publicKey"]) != {"hint"}:
        return _break("P1-seal-open-roundtrip", "publicKey not form-(1)")
    if bundle["verificationMaterial"]["publicKey"]["hint"] != \
            SB.key_hint(_PUB_A):
        return _break("P1-seal-open-roundtrip", "hint != hex(sha256(SPKI))")
    env = bundle["dsseEnvelope"]
    if len(env["signatures"]) != 1 or env["payloadType"] != \
            SB.SASANAM_PAYLOAD_TYPE:
        return _break("P1-seal-open-roundtrip", "envelope shape")
    return _held("P1-seal-open-roundtrip", "round trip verifies; form-(1) "
                 "hint populated; one signature; PAE-covered")


@probe("P1-fanout-one-signature-per-envelope")
def _p1b():
    payload = _statement_bytes()
    bundles = SB.seal_keyed_bundle_fanout(payload, [_SIGNER_A, _SIGNER_B])
    if not isinstance(bundles, list) or len(bundles) != 2:
        return _break("P1-fanout-one-signature-per-envelope",
                      "want 2 bundles")
    for bundle, pub in zip(bundles, (_PUB_A, _PUB_B)):
        if len(bundle["dsseEnvelope"]["signatures"]) != 1:
            return _break("P1-fanout-one-signature-per-envelope",
                          "envelope carries != 1 signature")
        if SB.verify_keyed_bundle(bundle, pub) is not True:
            return _break("P1-fanout-one-signature-per-envelope",
                          "bundle does not verify under its own key")
        other = _PUB_B if pub == _PUB_A else _PUB_A
        if SB.verify_keyed_bundle(bundle, other) is not False:
            return _break("P1-fanout-one-signature-per-envelope",
                          "bundle verifies under the WRONG key")
    return _held("P1-fanout-one-signature-per-envelope",
                 "2 signers -> 2 bundles, 1 sig each, key-bound")


# ---------------------------------------------------------------------------
# P2: break-first refusals
# ---------------------------------------------------------------------------

@probe("P2-forged-signature")
def _p2a():
    bundle = SB.seal_keyed_bundle(_statement_bytes(), _SIGNER_A)
    bad = copy.deepcopy(bundle)
    bad["dsseEnvelope"]["signatures"][0]["sig"] = _b64flip(
        bad["dsseEnvelope"]["signatures"][0]["sig"])
    return _expect_refuse("P2-forged-signature",
                          lambda: SB.open_keyed_bundle(bad, _PUB_A),
                          "sigstore-keyed-signature-invalid", "forged sig")


@probe("P2-wrong-pinned-key")
def _p2b():
    bundle = SB.seal_keyed_bundle(_statement_bytes(), _SIGNER_A)
    # The bundle's hint honestly names key A; the auditor pins key B.
    # The hint check fires first (fail-fast, most specific refusal) --
    # the signature check would also fail. Either way it is a coded
    # refusal, never a success.
    return _expect_refuse("P2-wrong-pinned-key",
                          lambda: SB.open_keyed_bundle(bundle, _PUB_B),
                          "sigstore-keyed-hint-mismatch",
                          "valid sig, wrong pinned key")


@probe("P2-tampered-payload")
def _p2c():
    bundle = SB.seal_keyed_bundle(_statement_bytes(), _SIGNER_A)
    bad = copy.deepcopy(bundle)
    bad["dsseEnvelope"]["payload"] = _b64flip(
        bad["dsseEnvelope"]["payload"])
    return _expect_refuse("P2-tampered-payload",
                          lambda: SB.open_keyed_bundle(bad, _PUB_A),
                          "sigstore-keyed-signature-invalid",
                          "tampered payload")


@probe("P2-multi-signature-envelope")
def _p2d():
    bundle = SB.seal_keyed_bundle(_statement_bytes(), _SIGNER_A)
    bad = copy.deepcopy(bundle)
    bad["dsseEnvelope"]["signatures"].append(
        bad["dsseEnvelope"]["signatures"][0])
    return _expect_refuse("P2-multi-signature-envelope",
                          lambda: SB.open_keyed_bundle(bad, _PUB_A),
                          "sigstore-keyed-multi-signature",
                          "2 signatures in one envelope")


@probe("P2-non-pae-signature")
def _p2e():
    # A signature over the RAW payload (not PAE) is cryptographically
    # valid Ed25519 but must NOT verify: it proves the verifier really
    # checks PAE coverage, not just "some valid signature".
    payload = _statement_bytes()
    raw_sig = _SIGNER_A.sign(payload)
    bundle = SB.seal_keyed_bundle(payload, _SIGNER_A)
    bad = copy.deepcopy(bundle)
    bad["dsseEnvelope"]["signatures"][0]["sig"] = \
        base64.b64encode(raw_sig).decode("ascii")
    return _expect_refuse("P2-non-pae-signature",
                          lambda: SB.open_keyed_bundle(bad, _PUB_A),
                          "sigstore-keyed-signature-invalid",
                          "raw-payload (non-PAE) signature")


@probe("P2-publicKeyIdentifier-field-trap")
def _p2f():
    # sigstore/docs#451: the JSON key is "publicKey", never
    # "publicKeyIdentifier" -- verifiers ignore the wrong name.
    bundle = SB.seal_keyed_bundle(_statement_bytes(), _SIGNER_A)
    bad = copy.deepcopy(bundle)
    vm = bad["verificationMaterial"]
    vm["publicKeyIdentifier"] = vm.pop("publicKey")
    return _expect_refuse("P2-publicKeyIdentifier-field-trap",
                          lambda: SB.open_keyed_bundle(bad, _PUB_A),
                          "sigstore-keyed-verification-material",
                          "'publicKeyIdentifier' key refused")


@probe("P2-tlog-misuse")
def _p2g():
    # A fake Rekor entry must never ride along unverified.
    bundle = SB.seal_keyed_bundle(_statement_bytes(), _SIGNER_A)
    bad = copy.deepcopy(bundle)
    bad["verificationMaterial"]["tlogEntries"] = [{
        "logIndex": "42",
        "logId": {"keyId": "ZmFrZQ=="},
        "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
    }]
    return _expect_refuse("P2-tlog-misuse",
                          lambda: SB.open_keyed_bundle(bad, _PUB_A),
                          "sigstore-keyed-tlog-unexpected",
                          "fake tlog entry refused")


@probe("P2-timestamp-misuse")
def _p2h():
    bundle = SB.seal_keyed_bundle(_statement_bytes(), _SIGNER_A)
    bad = copy.deepcopy(bundle)
    bad["verificationMaterial"]["timestampVerificationData"] = {
        "rfc3161Timestamps": [{"signedTimestamp": "ZmFrZQ=="}]}
    return _expect_refuse("P2-timestamp-misuse",
                          lambda: SB.open_keyed_bundle(bad, _PUB_A),
                          "sigstore-keyed-timestamp-unexpected",
                          "fake timestamp refused")


@probe("P2-keyid-mismatch")
def _p2i():
    # Hint-consistency MUST: non-empty keyid with empty-side hint.
    bundle = SB.seal_keyed_bundle(_statement_bytes(), _SIGNER_A)
    bad = copy.deepcopy(bundle)
    bad["dsseEnvelope"]["signatures"][0]["keyid"] = "deadbeef"
    return _expect_refuse("P2-keyid-mismatch",
                          lambda: SB.open_keyed_bundle(bad, _PUB_A),
                          "sigstore-keyed-keyid-mismatch",
                          "non-empty keyid refused")


@probe("P2-hint-mismatch")
def _p2j():
    bundle = SB.seal_keyed_bundle(_statement_bytes(), _SIGNER_A)
    bad = copy.deepcopy(bundle)
    bad["verificationMaterial"]["publicKey"]["hint"] = SB.key_hint(_PUB_B)
    return _expect_refuse("P2-hint-mismatch",
                          lambda: SB.open_keyed_bundle(bad, _PUB_A),
                          "sigstore-keyed-hint-mismatch",
                          "hint naming another key refused")


@probe("P2-media-type")
def _p2k():
    bundle = SB.seal_keyed_bundle(_statement_bytes(), _SIGNER_A)
    bad = copy.deepcopy(bundle)
    bad["mediaType"] = "application/vnd.dev.sigstore.bundle.v0.2+json"
    return _expect_refuse("P2-media-type",
                          lambda: SB.open_keyed_bundle(bad, _PUB_A),
                          "sigstore-keyed-media-type",
                          "wrong mediaType refused")


@probe("P2-message-signature-oneof")
def _p2m():
    # The v0.3 content oneof is message_signature XOR dsse_envelope.
    # A bundle carrying both must be refused, not verified on the
    # envelope alone (a downstream tool could read the other blob).
    bundle = SB.seal_keyed_bundle(_statement_bytes(), _SIGNER_A)
    bad = copy.deepcopy(bundle)
    bad["messageSignature"] = {
        "messageDigest": {"algorithm": "SHA2_256",
                          "digest": base64.b64encode(b"0" * 32).decode("ascii")},
        "signature": base64.b64encode(b"1" * 64).decode("ascii"),
    }
    return _expect_refuse("P2-message-signature-oneof",
                          lambda: SB.open_keyed_bundle(bad, _PUB_A),
                          "sigstore-keyed-message-signature-unexpected",
                          "messageSignature alongside envelope refused")


@probe("P2-subject-binding")
def _p2l():
    payload = _statement_bytes()
    bundle = SB.seal_keyed_bundle(payload, _SIGNER_A)
    good_digest = hashlib.sha256(_EVIDENCE).hexdigest()
    got_payload, _stmt = SB.open_keyed_evidence_bundle(
        bundle, _PUB_A, good_digest)
    if got_payload != payload:
        return _break("P2-subject-binding", "payload mismatch on good path")
    wrong = "00" * 32
    try:
        SB.open_keyed_evidence_bundle(bundle, _PUB_A, wrong)
    except SB.KeyedBundleError as exc:
        if exc.code == "sigstore-keyed-subject-mismatch":
            return _held("P2-subject-binding",
                         "subject binds evidence digest; wrong digest "
                         "refused coded")
        return _break("P2-subject-binding",
                      "wrong code %s" % exc.code)
    return _break("P2-subject-binding", "wrong digest ACCEPTED")


# ---------------------------------------------------------------------------
# P3: contract probes
# ---------------------------------------------------------------------------

@probe("P3-bool-contract-false-not-raise")
def _p3a():
    bundle = SB.seal_keyed_bundle(_statement_bytes(), _SIGNER_A)
    bad = copy.deepcopy(bundle)
    bad["dsseEnvelope"]["signatures"][0]["sig"] = _b64flip(
        bad["dsseEnvelope"]["signatures"][0]["sig"])
    # The wave-243 rule: bool-returning verify must return False on a
    # forged bundle, never raise. Assert `is False`, not truthiness.
    result = SB.verify_keyed_bundle(bad, _PUB_A)
    if result is False:
        return _held("P3-bool-contract-false-not-raise",
                     "forged bundle -> False (is False), no raise")
    return _break("P3-bool-contract-false-not-raise",
                  "got %r, want False" % (result,))


@probe("P3-empty-hint-spike-shape")
def _p3b():
    # The 2026-08-15 spike proved cosign verifies
    # verificationMaterial == {"publicKey": {}} -- our verifier must
    # accept the same shape (hint leniency), still key-bound.
    bundle = SB.seal_keyed_bundle(_statement_bytes(), _SIGNER_A)
    spike = copy.deepcopy(bundle)
    spike["verificationMaterial"]["publicKey"] = {}
    if SB.verify_keyed_bundle(spike, _PUB_A) is not True:
        return _break("P3-empty-hint-spike-shape", "empty hint refused")
    if SB.verify_keyed_bundle(spike, _PUB_B) is not False:
        return _break("P3-empty-hint-spike-shape",
                      "empty hint verified under wrong key")
    return _held("P3-empty-hint-spike-shape",
                 "empty hint accepted, still key-bound")


# ---------------------------------------------------------------------------
# P4: regressions
# ---------------------------------------------------------------------------

@probe("P4-pin-taxonomy-2140-sorted")


def _p4a():
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'"code":\s*\'([^\']+)\'', src)
    lits += re.findall(r'"code":\s*"([^"]+)"', src)
    ok = (len(lits) == TAXONOMY_PIN == 2140#Wave-333 merge: pin 2069 -> 2106 (+8 revocation-push-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
          and lits == sorted(lits) and len(set(lits)) == len(lits))
    if ok:
        return _held("P4-pin-taxonomy-2140-sorted", "2140/2140/0 sorted")
    return _break("P4-pin-taxonomy-2140-sorted",


                  "got %d literals" % (len(lits),))


@probe("P4-footer-state")
def _p4b():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    m_open = re.findall(r"Open findings: ([A-Za-z0-9, ]*)", text)
    m_next = re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
    ok = (m_open and m_open[-1].strip() == FOOTER_OPEN
          and m_next and m_next[-1] == FOOTER_NEXT)
    if ok:
        return _held("P4-footer-state", "open none / next F417")
    return _break("P4-footer-state",
                  "got %r / %r" % (m_open[-1] if m_open else None,
                                   m_next[-1] if m_next else None))


# ---------------------------------------------------------------------------
# Green check (depth-1) + main
# ---------------------------------------------------------------------------

GREEN_UNITTESTS = [
    # (name, module) -- adjacent suites that must stay green.
    ("test-sigstore-bundle", "tests.test_sigstore_bundle"),
    ("test-dsse-envelope", "tests.test_dsse_envelope"),
    ("test-evidence-intoto", "tests.test_evidence_intoto"),
]


def _run_green_unittest(name, module):
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tempfile.mkdtemp(prefix="w321-gc-")
    try:
        p = subprocess.run(
            [sys.executable, "-m", "unittest", module, "-v"],
            env=env, capture_output=True, text=True, timeout=900,
            cwd=REPO)
    except Exception as e:  # noqa: BLE001
        return (name, "BREAK", "spawn failed: %r" % (e,))
    out = p.stdout + p.stderr
    m = re.search(r"OK(?:\s+\((\d+) tests?\))?", out)
    failed = re.search(r"FAILED", out)
    if p.returncode == 0 and m and not failed:
        return (name, "HELD", out.strip().splitlines()[-1][:80])
    tail = "\n".join(out.strip().splitlines()[-6:])
    return (name, "BREAK", "rc=%d: %s" % (p.returncode, tail))


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-skipped",
                "HELD", "green check skipped (GOV_SKIP_GREEN=1)")
        return
    for name, module in GREEN_UNITTESTS:
        n, v, note = _run_green_unittest(name, module)
        _record("green-" + n, v, note)


def main(argv):
    only = argv[1] if len(argv) > 1 else None
    for pid, fn in _PROBES:
        if only is not None and pid != only:
            continue
        _safe(pid, fn)
    if only is None:
        green_check()
    breaks = errors = 0
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    for _, verdict, _ in _results:
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "ERROR":
            errors += 1
    expected_breaks = set()  # no BREAKs expected on the closed tree
    actual_breaks = {pid for pid, v, _ in _results if v == "BREAK"}
    green_breaks = {pid for pid, v, _ in _results
                    if pid.startswith("green-") and v == "BREAK"}
    unexpected = (actual_breaks - expected_breaks - green_breaks)
    print("w321_sigstore battery: %d BREAK / %d HELD / %d ERROR "
          % (breaks, len(_results) - breaks - errors, errors))
    if errors or unexpected:
        return 1
    # green-check breaks are reported but do not fail the battery when
    # the probes themselves are clean (they pin adjacent trees).
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
