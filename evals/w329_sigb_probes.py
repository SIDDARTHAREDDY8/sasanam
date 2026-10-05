#!/usr/bin/env python3
"""Break-first audit battery for Sigstore-bundle distribution (wave-329 lane 2).

Context: the briefed keyed Sigstore Bundle v0.3 module (gov/sigstore_bundle.py,
wave-321) and the witness-backed variant (gov/evidence_sigstore.py, wave-311)
both already exist and pass their batteries. Per the reuse-over-duplication
order this lane does NOT build a third module. Instead it audits both against
the four 2026 Sigstore CVEs (wave-310 negative design rules) and the Bundle
v0.3 protobuf contract, and closes the genuine gap the audit finds:

  the witness-backed bundle's ``verificationMaterial.publicKey`` embeds
  ``{"rawBytes", "keyDetails"}`` where the Bundle proto's PublicKeyIdentifier
  allows ONLY ``hint``. Strict protobuf-JSON parsers (protojson default, as
  sigstore-go/cosign use) reject unknown fields -- the module's own interop
  purpose ("third-party verifiers consume evidence without the engine")
  fails at parse time for strict consumers. gov/sigstore_bundle.py already
  documents this deviation.

Probe groups:

S (7): spec-shape probes for the witness-backed bundle. S1/S2/S4/S5/S7 are
    written against the FIXED shape and BREAK on the base tree (red-first);
    S3/S6 are positive controls (HELD on base and after the fix).
K (6): keyed-module regression pins -- the four CVE analogues plus the
    keyid/hint discipline. All HELD on base.
W (6): witness-backed CVE analogues -- entry transplant binding
    (CVE-2026-22703), witness-time window (CVE-2026-24122), always-on content
    checks (CVE-2026-39395), crash-never-success (CVE-2026-44310). All HELD
    on base.
P (2): taxonomy pin 2083 (this lane registers no taxonomy codes -- the
    module's refusals are bundle-scoped codes by design) and footer
    open F415 / next F417 (wave-330 merge: F414 closed, F415/F416 filed).

Result contract: each probe prints [HELD]/[BREAK]/[ERROR]. Exit 0 iff no
ERROR and no unexpected BREAK. The S-group documents its expected BREAKs
on the base tree explicitly.

Depth-1 green check honoring GOV_SKIP_GREEN; no in-repo git subprocesses;
deterministic (fixed seeds); stdlib only.
"""

import base64
import copy
import hashlib
import inspect
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

from gov import evidence_sigstore as ES  # noqa: E402
from gov import sigstore_bundle as SB  # noqa: E402
from gov import evidence_dsse as _edsse  # noqa: E402
from gov import evidence_intoto as _intoto  # noqa: E402
from gov import dsse_envelope as _dsse  # noqa: E402
from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402

TAXONOMY_PIN = 2083  # Wave-328 merge: pin 2044 -> 2056 (+12). This lane adds no taxonomy codes.; Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*)

FOOTER_OPEN = "none"  # F417 CLOSED 2026-10-05 (wave-334 lane 1); no open findings.
FOOTER_NEXT = "F419"  # Next free finding number (F417 OPEN, F418 closed at wave-333 merge).

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


def _coded(pid, fn, codes, note):
    """HELD iff fn() raises EnvelopeError/KeyedBundleError with a code in codes."""
    try:
        fn()
    except (_dsse.EnvelopeError, SB.KeyedBundleError) as exc:
        code = getattr(exc, "code", None) or _reason_code(exc)
        if code in codes:
            return _held(pid, "%s: refused coded %s" % (note, code))
        return _break(pid, "%s: refused coded %s, want one of %s"
                      % (note, code, sorted(codes)))
    except Exception as exc:  # noqa: BLE001
        return _break(pid, "%s: raised %r, want coded refusal" % (note, exc))
    return _break(pid, "%s: ACCEPTED, want coded refusal" % note)


def _reason_code(exc):
    m = re.match(r"^([a-z0-9-]+):", str(exc))
    return m.group(1) if m else str(exc)


# Fixed seeds: deterministic keys across runs.
def _signers(n, base=41):
    return [Ed25519Signer(bytes([base + i]) * 32) for i in range(n)]


def _verifiers(signers):
    return [Ed25519Verifier(s.public_key, s.key_id) for s in signers]


def _witness(base=77):
    return Ed25519Signer(bytes([base]) * 32)


T0 = 1791528600
VALIDITY = (1791528000, 1791530000)
BUNDLE = b'{"bundle":"synthetic-test-bytes-329"}'
OTHER = b'{"bundle":"different-bytes-329"}'
CLAIMS = {"window": "2026-10-04", "tip": "ab" * 16, "decisions": 3}


def _seal(signers=None, witness=None, bundle_bytes=BUNDLE,
          integrated_time=T0, witness_log=None):
    signers = _signers(1) if signers is None else signers
    witness = _witness() if witness is None else witness
    stmt = _intoto.build_statement(bundle_bytes, CLAIMS)
    env = _intoto.seal_statement(stmt, signers)
    return ES.seal_sigstore_bundle(env, signers, witness,
                                   integrated_time=integrated_time,
                                   witness_log=witness_log)


def _open(bundle, bundle_bytes=BUNDLE, signers=None, witness=None,
          threshold=1, validity=VALIDITY, verifiers=None):
    signers = _signers(1) if signers is None else signers
    witness = _witness() if witness is None else witness
    verifiers = _verifiers(signers) if verifiers is None else verifiers
    return ES.open_sigstore_bundle(
        bundle, bundle_bytes, verifiers,
        Ed25519Verifier(witness.public_key, witness.key_id),
        threshold=threshold, witness_validity=validity)


# ---------------------------------------------------------------------------
# S: spec-shape probes (witness-backed bundle)
# ---------------------------------------------------------------------------

@probe("S1-publickey-form1")
def _s1():
    pid = "S1-publickey-form1"
    b = _seal()
    pk = b["verificationMaterial"]["publicKey"]
    unknown = set(pk) - {"hint"}
    if unknown:
        return _break(pid, "publicKey carries non-form-(1) fields %s "
                           "(Bundle proto PublicKeyIdentifier allows only "
                           "'hint'; strict protobuf-JSON parsers reject "
                           "unknown fields)" % sorted(unknown))
    return _held(pid, "publicKey is the form-(1) shape {hint}")


@probe("S2-hint-names-primary")
def _s2():
    pid = "S2-hint-names-primary"
    signers = _signers(1)
    b = _seal(signers=signers)
    hint = b["verificationMaterial"]["publicKey"].get("hint", "")
    want = SB.key_hint(signers[0].public_key)
    if hint != want:
        return _break(pid, "hint %r does not name the primary key "
                           "(want hex(sha256(DER(SPKI))) %r)" % (hint, want))
    return _held(pid, "hint names the primary key")


@probe("S3-roundtrip")
def _s3():
    pid = "S3-roundtrip"
    signers = _signers(1)
    b = _seal(signers=signers)
    got = _open(b, signers=signers)
    if got["statement"]["predicate"] != CLAIMS:
        return _break(pid, "round trip predicate mismatch")
    return _held(pid, "seal/open round trip verifies")


@probe("S4-hint-spoof-refused")
def _s4():
    pid = "S4-hint-spoof-refused"
    signers = _signers(1)
    b = _seal(signers=signers)
    # Attacker names a different key in the hint. The hint must never
    # decide, but it must not be allowed to LIE about the key either.
    b["verificationMaterial"]["publicKey"]["hint"] = "ff" * 32
    return _coded(pid, lambda: _open(b, signers=signers),
                  {"evidence-bundle-hint-mismatch"},
                  "spoofed hint")


@probe("S5-rawbytes-smuggled-refused")
def _s5():
    pid = "S5-rawbytes-smuggled-refused"
    signers = _signers(1)
    b = _seal(signers=signers)
    b["verificationMaterial"]["publicKey"]["rawBytes"] = base64.b64encode(
        signers[0].public_key).decode("ascii")
    return _coded(pid, lambda: _open(b, signers=signers),
                  {"evidence-bundle-verification-material"},
                  "rawBytes smuggled into form-(1) publicKey")


@probe("S6-verifier-order-independent")
def _s6():
    pid = "S6-verifier-order-independent"
    signers = _signers(2)
    b = _seal(signers=signers)
    # Primary (signers[0]) is NOT first in the verifier list: the
    # witness must still bind the actual primary key.
    verifiers = _verifiers(list(reversed(signers)))
    got = _open(b, signers=signers, verifiers=verifiers)
    if got["statement"]["predicate"] != CLAIMS:
        return _break(pid, "reordered verifiers broke verification")
    return _held(pid, "primary resolves from the authenticated set, "
                      "not verifier order")


@probe("S7-empty-hint-accepted")
def _s7():
    pid = "S7-empty-hint-accepted"
    # The spike-proven cosign shape: {"publicKey": {}} verifies. Our
    # witness-backed bundle must accept the empty hint too -- the key
    # is pinned out-of-band by the auditor.
    signers = _signers(1)
    b = _seal(signers=signers)
    b["verificationMaterial"]["publicKey"] = {}
    try:
        got = _open(b, signers=signers)
    except _dsse.EnvelopeError as exc:
        return _break(pid, "empty-hint bundle refused: %s" % exc)
    if got["statement"]["predicate"] != CLAIMS:
        return _break(pid, "empty-hint bundle verified but predicate wrong")
    return _held(pid, "empty hint accepted (key pinned out-of-band)")


# ---------------------------------------------------------------------------
# K: keyed-module regression pins (all HELD on base)
# ---------------------------------------------------------------------------

def _k_statement():
    st = _intoto.build_statement(b'{"k":"v"}', {"lane": "w329"})
    return _intoto.statement_bytes(st)


_KA = Ed25519Signer(bytes(range(32)))
_KB = Ed25519Signer(bytes([255 - i for i in range(32)]))


@probe("K1-forged-signature")
def _k1():
    pid = "K1-forged-signature"
    b = SB.seal_keyed_bundle(_k_statement(), _KA)
    b["dsseEnvelope"]["signatures"][0]["sig"] = base64.b64encode(
        b"\x00" * 64).decode("ascii")
    return _coded(pid, lambda: SB.open_keyed_bundle(b, _KA.public_key),
                  {"sigstore-keyed-signature-invalid"}, "forged signature")


@probe("K2-tampered-payload")
def _k2():
    pid = "K2-tampered-payload"
    b = SB.seal_keyed_bundle(_k_statement(), _KA)
    raw = bytearray(base64.b64decode(b["dsseEnvelope"]["payload"]))
    raw[10] ^= 1
    b["dsseEnvelope"]["payload"] = base64.b64encode(bytes(raw)).decode()
    return _coded(pid, lambda: SB.open_keyed_bundle(b, _KA.public_key),
                  {"sigstore-keyed-signature-invalid"}, "tampered payload")


@probe("K3-wrong-pinned-key")
def _k3():
    pid = "K3-wrong-pinned-key"
    b = SB.seal_keyed_bundle(_k_statement(), _KA)
    return _coded(pid, lambda: SB.open_keyed_bundle(b, _KB.public_key),
                  {"sigstore-keyed-signature-invalid",
                   "sigstore-keyed-hint-mismatch"}, "wrong pinned key")


@probe("K4-keyid-spoof-failclosed")
def _k4():
    pid = "K4-keyid-spoof-failclosed"
    # Valid signature under the pinned key, but a lying keyid. keyid is
    # an unauthenticated hint: it must never decide, and a non-empty
    # one is refused rather than ignored.
    b = SB.seal_keyed_bundle(_k_statement(), _KA)
    b["dsseEnvelope"]["signatures"][0]["keyid"] = "attacker-hint"
    return _coded(pid, lambda: SB.open_keyed_bundle(b, _KA.public_key),
                  {"sigstore-keyed-keyid-mismatch"}, "keyid spoof")


@probe("K5-bool-contract")
def _k5():
    pid = "K5-bool-contract"
    # CVE-2026-44310: a crash must never emit success. The bool API
    # returns False (never True, never raises-as-success) on garbage.
    bads = [None, "nope", b"\x00", {}, {"mediaType": "x"}]
    for bad in bads:
        try:
            r = SB.verify_keyed_bundle(bad, _KA.public_key)
        except Exception as exc:  # noqa: BLE001
            return _break(pid, "verify raised %r on %r" % (exc, bad))
        if r is not False:
            return _break(pid, "verify returned %r (not False) on %r"
                          % (r, bad))
    return _held(pid, "verify_keyed_bundle is False on all malformed input")


@probe("K6-payloadtype-transplant")
def _k6():
    pid = "K6-payloadtype-transplant"
    # A signature over PAE(other-type, payload) must not verify as our
    # payload type: the type is bound inside the PAE signature.
    other = SB.seal_keyed_bundle(_k_statement(), _KA,
                                 payload_type="application/vnd.other+json")
    b = SB.seal_keyed_bundle(_k_statement(), _KA)
    b["dsseEnvelope"]["signatures"] = other["dsseEnvelope"]["signatures"]
    return _coded(pid, lambda: SB.open_keyed_bundle(b, _KA.public_key),
                  {"sigstore-keyed-signature-invalid"},
                  "cross-payload-type signature transplant")


# ---------------------------------------------------------------------------
# W: witness-backed CVE analogues (all HELD on base)
# ---------------------------------------------------------------------------

@probe("W1-entry-transplant-unbound")
def _w1():
    pid = "W1-entry-transplant-unbound"
    # CVE-2026-22703: a valid witness entry for bundle A must not
    # validate bundle B. Never accept "a valid entry" alone.
    signers, witness = _signers(1), _witness()
    a = _seal(signers=signers, witness=witness, bundle_bytes=BUNDLE)
    b = _seal(signers=signers, witness=witness, bundle_bytes=OTHER)
    b["verificationMaterial"]["tlogEntries"] = copy.deepcopy(
        a["verificationMaterial"]["tlogEntries"])
    return _coded(pid, lambda: _open(b, bundle_bytes=OTHER,
                                     signers=signers, witness=witness),
                  {"evidence-bundle-witness-unbound"}, "entry transplant")


@probe("W2-witness-time-window")
def _w2():
    pid = "W2-witness-time-window"
    # CVE-2026-24122 analogue: issuing-side time is validated against
    # the caller-pinned window, never trusted blindly; the window is
    # REQUIRED (no silent downgrade).
    signers, witness = _signers(1), _witness()
    b = _seal(signers=signers, witness=witness, integrated_time=T0)
    r1 = _coded(pid + "-expired",
                lambda: _open(b, signers=signers, witness=witness,
                              validity=(T0 + 100, T0 + 200)),
                {"evidence-bundle-witness-expired"}, "outside window")
    if r1[1] != "HELD":
        return r1
    try:
        _open(b, signers=signers, witness=witness, validity=None)
    except _dsse.EnvelopeError:
        return _held(pid, "expired refused; missing window loud")
    except Exception as exc:  # noqa: BLE001
        return _break(pid, "missing window raised %r" % exc)
    return _break(pid, "missing witness_validity silently accepted")


@probe("W3-forged-set")
def _w3():
    pid = "W3-forged-set"
    signers, witness, other = _signers(1), _witness(), _witness(base=78)
    b = _seal(signers=signers, witness=witness)
    entry = b["verificationMaterial"]["tlogEntries"][0]
    body = base64.b64decode(entry["canonicalizedBody"])
    entry["inclusionPromise"] = {"signedEntryTimestamp": base64.b64encode(
        other.sign(body)).decode("ascii")}
    return _coded(pid, lambda: _open(b, signers=signers, witness=witness),
                  {"evidence-bundle-witness-signature-invalid"}, "forged SET")


@probe("W4-logid-binding")
def _w4():
    pid = "W4-logid-binding"
    signers, witness, other = _signers(1), _witness(), _witness(base=78)
    b = _seal(signers=signers, witness=witness)
    entry = b["verificationMaterial"]["tlogEntries"][0]
    entry["logId"] = {"keyId": base64.b64encode(
        hashlib.sha256(other.public_key).digest()).decode("ascii")}
    return _coded(pid, lambda: _open(b, signers=signers, witness=witness),
                  {"evidence-bundle-witness-unbound"}, "logId mismatch")


@probe("W5-content-checks-always-on")
def _w5():
    pid = "W5-content-checks-always-on"
    # CVE-2026-39395: predicate/content checks must be always-on, never
    # opt-in. The open path must expose no flag that skips them.
    params = inspect.signature(ES.open_sigstore_bundle).parameters
    skippers = [n for n in params
                if "skip" in n.lower() or "check_claims" in n.lower()
                or "insecure" in n.lower()]
    if skippers:
        return _break(pid, "skip-style parameters present: %s" % skippers)
    return _held(pid, "no content-check opt-out in the open signature")


@probe("W6-crash-never-success")
def _w6():
    pid = "W6-crash-never-success"
    # CVE-2026-44310: malformed input raises coded EnvelopeError; it
    # must never return a success-shaped dict.
    signers, witness = _signers(1), _witness()
    bads = [None, "x", b"\x00", {}, {"mediaType": "x"},
            {"mediaType": ES.SIGSTORE_BUNDLE_MEDIA_TYPE}]
    for bad in bads:
        try:
            r = _open(bad, signers=signers, witness=witness)
        except _dsse.EnvelopeError:
            continue
        except Exception as exc:  # noqa: BLE001
            return _break(pid, "uncoded %r on %r" % (exc, bad))
        return _break(pid, "returned success-shaped %r on %r" % (r, bad))
    return _held(pid, "all malformed inputs refuse coded")


# ---------------------------------------------------------------------------
# P: pin + footer regression probes
# ---------------------------------------------------------------------------

@probe("P1-pin-taxonomy-2083")
def _p1():
    pid = "P1-pin-taxonomy-2083"
    if TAXONOMY_PIN != 2083:
        return _break(pid, "battery pin drifted: %r" % TAXONOMY_PIN)
    lits = []
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        for line in fh:
            m = re.search(r'"code"\s*:\s*\'([^\']+)\'', line)
            if m:
                lits.append(m.group(1))
    if len(lits) != 2083 or len(set(lits)) != 2083 \
            or lits != sorted(lits):
        return _break(pid, "taxonomy not 2083/2083/0 sorted "
                           "(%d/%d)" % (len(lits), len(set(lits))))
    return _held(pid, "taxonomy 2083/2083/0 sorted")


@probe("P2-footer")
def _p2():
    pid = "P2-footer"
    # The footer is a single enormous last line; read it whole (a byte
    # window would cut it mid-line).
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    tail = lines[-1] if lines else ""
    m = re.search(r"Next free finding: \*\*(F\d+)\*\*\. "
                  r"\*\*Open findings: ([^*]*)\.\*\*", tail)
    if not m:
        return _break(pid, "footer not found")
    if m.group(1) != FOOTER_NEXT or FOOTER_OPEN not in m.group(2):
        return _break(pid, "footer is %s / %s, want %s / %s"
                      % (m.group(2), m.group(1), FOOTER_OPEN, FOOTER_NEXT))
    return _held(pid, "footer open %s / next %s" % (FOOTER_OPEN, FOOTER_NEXT))


# ---------------------------------------------------------------------------
# Runner + depth-1 green check
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: run the adjacent keyed-bundle battery with green checks
    skipped in the child (it has its own green check)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED",
                 "GOV_SKIP_GREEN=1 (depth-1: no recursive spawn)")]
    child = os.path.join(REPO, "evals", "w321_sigstore_probes.py")
    tmp = tempfile.mkdtemp(prefix="g329-sigb-green-")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmp)
    try:
        p = subprocess.run(
            [sys.executable, child], env=env, capture_output=True,
            text=True, timeout=600, cwd=REPO)
    except Exception as exc:  # noqa: BLE001
        return [("green-check", "ERROR", "child failed: %r" % exc)]
    out = (p.stdout or "") + (p.stderr or "")
    m = re.search(r"w321_sigstore battery: (\d+) BREAK / (\d+) HELD / "
                  r"(\d+) ERROR", out)
    if not m or p.returncode != 0:
        return [("green-check", "BREAK",
                 "w321 child rc=%d out=%s" % (p.returncode, out[-400:]))]
    br, he, er = int(m.group(1)), int(m.group(2)), int(m.group(3))
    # Under GOV_SKIP_GREEN=1 the child's own green check is skipped,
    # so the child reports (0,20,0) instead of its standalone (0,22,0).
    if (br, he, er) != (0, 20, 0):
        return [("green-check", "BREAK",
                 "w321 child tally (%d,%d,%d), want (0,20,0)"
                 % (br, he, er))]
    return [("green-check", "HELD",
             "w321_sigstore 0/20/0 (child green skipped under "
             "GOV_SKIP_GREEN=1)")]


def main(argv):
    for pid, fn in _PROBES:
        _safe(pid, fn)
    for pid, verdict, note in _green_check():
        _results.append((pid, verdict, note))

    n_break = n_held = n_err = 0
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note.split("\n")[0]))
        if verdict == "BREAK":
            n_break += 1
        elif verdict == "HELD":
            n_held += 1
        else:
            n_err += 1
    # S1/S2/S4/S5/S7 are the expected red-first BREAKs on the OPEN tree
    # (pre-fix shape). After the fix the expected set is empty.
    expected = set()
    try:
        with open(__file__, encoding="utf-8") as fh:
            src = fh.read()
    except Exception:  # noqa: BLE001
        src = ""
    m = re.search(r"_EXPECTED_BREAKS\s*=\s*\{([^}]*)\}", src)
    if m:
        expected = set(re.findall(r'"([^"]+)"', m.group(1)))
    got_break = {pid for pid, v, _ in _results if v == "BREAK"}
    print("w329_sigb battery: %d BREAK / %d HELD / %d ERROR "
          "(expected BREAKs: %s)" % (n_break, n_held, n_err,
                                     sorted(expected) or "none"))
    if got_break != expected or n_err:
        if got_break - expected:
            print("UNEXPECTED BREAKs: %s" % sorted(got_break - expected))
        if expected - got_break:
            print("MISSING expected BREAKs: %s"
                  % sorted(expected - got_break))
        return 1
    return 0


# Expected BREAKs on the OPEN (pre-fix) tree. The wave-329 fix flipped
# the S-group to HELD; the set is now empty (wave-306 lesson: update
# expected-BREAK lists after the closure, don't leave stale entries).
_EXPECTED_BREAKS = set()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
