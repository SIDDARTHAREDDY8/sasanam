"""Wave-243 cosign sign-side negative interop probes (W243-1, red-first).

BUILD verdict: cosign's sign-side SHA-256 hardcode (keys.go:163) is a
durable, indefinite constraint -- #5029 closed-unmerged (verified
2026-09-30T06:39:41Z), #5018 open/frozen, zero replacement fix PRs,
#5074 (Ed25519 sign-side fix champion) open and unmerged -- track, do
NOT depend on it. Sasanam pins the constraint itself, loudly, not in
silence. Patterns only; no upstream code is read, imported, or vendored.

Probes:
  cosign-p521-hardcode-loud-failure -- a P-521 signer hardcoded to
      SHA-256 (the upstream bug, re-derived) given a 64-byte
      SHA-512 digest fails LOUD with the Go crypto/ecdsa text
      "unexpected length of digest for hash function specified".
      Tripwire: this pins the bug; it flips when upstream fixes it.
  cosign-p256-control-success -- the same mimic on P-256/SHA-256
      signs fine (the test does not degenerate if the mimic is
      broken).
  sasanam-wrapper-pairs-withdigest-cryptosigneropts -- Sasanam's
      wrapper always pairs the WithDigest equivalent with the
      WithCryptoSignerOpts equivalent: P-521/SHA-512 signs and
      verifies.
  sasanam-wrapper-refuses-downshift -- P-521 with SHA-256 on the
      payload path refuses signer-hash-downshift-refused (loud),
      never silently downshifts; P-256/SHA-256 stays the accepted
      control.
  sasanam-wrapper-digest-length-loud -- a 64-byte digest presented
      with hash_name="sha256" refuses signer-digest-length-mismatch
      with the Go text; a 32-byte digest presented with sha256 on
      P-521 refuses signer-hash-downshift-refused (length is exact
      but the pairing is the bug shape).
  legacy-vs-bundle-divergence-pinned -- the mimic's legacy path
      (hash payload with SHA-256, sign) SUCCEEDS silently on P-521
      while the bundle path (WithDigest, 64-byte digest) fails
      loudly: the divergence is pinned so no Sasanam wrapper is
      ever allowed to hide behind the silent path.
  upstream-status-documented -- the module documents the upstream
      issue states as of 2026-09-30; a verifier must update the
      mimic when upstream moves.

Stdlib only (plus in-repo gov.ed25519, unused here -- the mimic is a
self-contained test-grade ECDSA; see gov/signer_interop.py for the
honest implementation-status note). Deterministic apart from fresh
key material (keys are never asserted byte-equal). No in-repo git
subprocesses. Depth-1 green checks honoring GOV_SKIP_GREEN.
"""

import hashlib
import io
import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NEW_API = False
try:
    from gov import signer_interop as _sx
    HAVE_NEW_API = all(hasattr(_sx, n) for n in (
        "MimicSignerVerifierKeypair", "sign_payload_paired",
        "sign_digest_paired", "verify_record", "SignerInteropError",
        "UPSTREAM_STATUS"))
except ImportError:
    _sx = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

GO_ERROR_TEXT = "unexpected length of digest for hash function specified"

PAYLOAD = b"w243-1 interop pin payload"
DIGEST64 = hashlib.sha512(PAYLOAD).digest()
assert len(DIGEST64) == 64


def _run_probe(name, fn):
    if not HAVE_NEW_API:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _expect_refusal(fn, code):
    """fn must raise SignerInteropError with .code == code; returns note."""
    try:
        fn()
    except _sx.SignerInteropError as exc:
        assert exc.code == code, "code %r, expected %r" % (exc.code, code)
        return "refused %s" % code
    raise AssertionError("no refusal; expected %s" % code)


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _probe_p521_hardcode_loud_failure():
    mimic = _sx.MimicSignerVerifierKeypair(curve="P-521")
    assert mimic.hardcoded_hash == "sha256", \
        "mimic must pin the upstream SHA-256 hardcode"
    try:
        mimic.sign_with_digest(DIGEST64)
    except _sx.SignerInteropError as exc:
        assert GO_ERROR_TEXT in str(exc), \
            "Go crypto/ecdsa text missing: %r" % (str(exc),)
        assert getattr(exc, "digest_len", None) == 64, \
            "error must carry the attempted 64-byte digest length"
        assert getattr(exc, "expected_len", None) == 32, \
            "error must carry the hardcoded 32-byte expectation"
        return "loud failure pins the bug (digest 64 vs hardcoded 32)"
    raise AssertionError("mimic did not reproduce the loud failure")


def _probe_p256_control_success():
    mimic = _sx.MimicSignerVerifierKeypair(curve="P-256")
    sig = mimic.sign_with_digest(hashlib.sha256(PAYLOAD).digest())
    assert mimic.verify_with_digest(
        hashlib.sha256(PAYLOAD).digest(), sig), "control did not verify"
    sig2 = mimic.sign_legacy(PAYLOAD)
    assert mimic.verify_legacy(PAYLOAD, sig2), "legacy control did not verify"
    return "P-256 control signs and verifies (mimic not degenerate)"


def _probe_wrapper_pairs_digest_with_opts():
    rec = _sx.sign_payload_paired(PAYLOAD, hash_name="sha512",
                                  curve="P-521")
    assert rec["curve"] == "P-521", rec
    assert rec["hash"] == "sha512", rec
    assert len(bytes.fromhex(rec["digest_hex"])) == 64, rec
    assert _sx.verify_record(rec) is True, "wrapper record did not verify"
    return "wrapper pairs digest with signer opts (P-521/SHA-512)"


def _probe_wrapper_refuses_downshift():
    note = _expect_refusal(
        lambda: _sx.sign_payload_paired(PAYLOAD, hash_name="sha256",
                                        curve="P-521"),
        "signer-hash-downshift-refused")
    # Control: P-256 with SHA-256 is the accepted pairing (no downshift).
    rec = _sx.sign_payload_paired(PAYLOAD, hash_name="sha256",
                                  curve="P-256")
    assert _sx.verify_record(rec) is True, "P-256/SHA-256 control failed"
    return "%s; P-256/SHA-256 control signs" % note


def _probe_wrapper_digest_length_loud():
    # 64-byte digest presented as sha256: the length gate fires first,
    # with the Go crypto/ecdsa text.
    try:
        _sx.sign_digest_paired(DIGEST64, hash_name="sha256",
                               curve="P-521")
    except _sx.SignerInteropError as exc:
        assert exc.code == "signer-digest-length-mismatch", \
            "code %r, expected signer-digest-length-mismatch" % (exc.code,)
        assert GO_ERROR_TEXT in str(exc), \
            "Go crypto/ecdsa text missing: %r" % (str(exc),)
        note1 = "refused signer-digest-length-mismatch (Go text)"
    else:
        raise AssertionError("no refusal for 64-byte digest as sha256")
    # 32-byte digest presented as sha256 on P-521: the length gate
    # passes (32 == 32) but the pairing gate refuses the downshift.
    note2 = _expect_refusal(
        lambda: _sx.sign_digest_paired(
            hashlib.sha256(PAYLOAD).digest(), hash_name="sha256",
            curve="P-521"),
        "signer-hash-downshift-refused")
    return "%s; %s (exact length, bug-shaped pairing)" % (note1, note2)


def _probe_legacy_vs_bundle_divergence():
    mimic = _sx.MimicSignerVerifierKeypair(curve="P-521")
    # Legacy path: silently weak -- succeeds, no error, sha256 on P-521.
    sig = mimic.sign_legacy(PAYLOAD)
    assert mimic.legacy_digest_hash == "sha256", "legacy must use sha256"
    assert mimic.verify_legacy(PAYLOAD, sig), "legacy sig did not verify"
    # Bundle path: fails loud.
    try:
        mimic.sign_with_digest(DIGEST64)
    except _sx.SignerInteropError as exc:
        assert GO_ERROR_TEXT in str(exc)
        return ("divergence pinned: legacy silently downshifts "
                "(sha256, verifies), bundle fails loud")
    raise AssertionError("divergence not pinned: bundle path did not fail")


def _probe_upstream_status_documented():
    status = _sx.UPSTREAM_STATUS
    for issue in ("#5029", "#5018", "#5074"):
        assert issue in status, "upstream issue %s undocumented" % issue
    assert "closed-unmerged" in status["#5029"], status["#5029"]
    assert "do not depend" in status["#5074"].lower() or \
        "track" in status["#5074"].lower(), status["#5074"]
    src = io.open(os.path.join(os.path.dirname(__file__), "..", "gov",
                               "signer_interop.py"),
                  encoding="utf-8").read()
    assert "keys.go:163" in src, "upstream bug location undocumented"
    return "upstream states documented (%s)" % ", ".join(
        "%s=%s" % kv for kv in sorted(status.items()))


_PROBES = {
    "cosign-p521-hardcode-loud-failure": _probe_p521_hardcode_loud_failure,
    "cosign-p256-control-success": _probe_p256_control_success,
    "sasanam-wrapper-pairs-withdigest-cryptosigneropts":
        _probe_wrapper_pairs_digest_with_opts,
    "sasanam-wrapper-refuses-downshift": _probe_wrapper_refuses_downshift,
    "sasanam-wrapper-digest-length-loud": _probe_wrapper_digest_length_loud,
    "legacy-vs-bundle-divergence-pinned":
        _probe_legacy_vs_bundle_divergence,
    "upstream-status-documented": _probe_upstream_status_documented,
}

PROBE_NAMES = list(_PROBES)


def _run_green_checks():
    """Adjacent-seam sanity: new refusal codes mapped, no regressions.

    Depth-1 only; honors GOV_SKIP_GREEN=1 (never spawns another
    battery's main).
    """
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    try:
        from gov import decision_codes as _dc
        for code in ("signer-digest-length-mismatch",
                     "signer-hash-downshift-refused"):
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-243 cosign sign-side interop probes (new API: %s)"
          % HAVE_NEW_API)
    results = []
    for name in PROBE_NAMES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for r in results if r[1] == "HELD")
    gap = sum(1 for r in results if r[1] == "GAP")
    bad = sum(1 for r in results if r[1] in ("BREAK", "ERROR"))
    for name, verdict, note in results:
        print("  [%s] %s: %s" % (verdict, name, note.split("\n")[0]))
    for note in _run_green_checks():
        print("  green: %s" % note)
    print("HELD=%d GAP=%d BREAK/ERROR=%d" % (held, gap, bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
