"""Scan-verdict digest-binding negative class (wave-216, lane C).

npm/PyPI attestation DIGEST-BINDING STEAL (idea only, no upstream source
vendored): "an attestation for one file must not verify for a different
file in the same release." The scan-verdict module already binds every
verdict to an exact ``scan_target_digest`` and refuses transplants
(``scan_verdict_target_mismatch``), but the *consumption* seam --
``ScanGate.check(scan_target_digest, ...)`` -- takes the digest as a
caller-supplied string. A deployment that hashes the CLAIMANT's digest
claim instead of the promoted bytes collapses the binding. This battery
pins the negative class:

  * same-name-different-digest replay          -> refused
  * verdict-reuse-across-versions              -> refused
  * digest-mismatch-at-consumption (claimed digest vs actual bytes)
                                               -> refused via check_bytes
  * bit-flipped bytes                          -> refused
  * non-bytes input to the bytes API           -> loud refusal, no coerce

Verdict vocabulary: HELD (attack refused), BREAK (attack admitted --
a genuine finding, file it), GAP (the defense does not exist yet in
the pristine tree -- the honest red before the fix).

Stdlib only. Deterministic: fixed seeds, fixed timestamps.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import sys
import traceback

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_RESULTS = []
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        def run():
            try:
                verdict, detail = fn()
            except Exception as e:  # noqa: BLE001 - battery must not die
                return (name, "ERROR", "%s: %s"
                        % (type(e).__name__, str(e)[:160]))
            if isinstance(verdict, tuple):
                verdict, detail = verdict
            assert verdict in ("HELD", "GAP", "BREAK"), verdict
            return (name, verdict, detail)
        _PROBE_FNS[name] = run
        return run
    return deco


# ------------------------------------------------------------------ helpers

_NOW = 1700000000
_SEED_A = bytes.fromhex("a1" * 32)
_SEED_B = bytes.fromhex("b2" * 32)

_BYTES_V1 = b"widget-1.0.0-tarball-bytes"
_BYTES_V2 = b"widget-2.0.0-tarball-bytes"
_DIGEST_V1 = "sha256:" + hashlib.sha256(_BYTES_V1).hexdigest()
_DIGEST_V2 = "sha256:" + hashlib.sha256(_BYTES_V2).hexdigest()
_RULESET = "sha256:" + "cc" * 32


def _signer(seed):
    from gov.signing import Ed25519Signer, Ed25519Verifier
    s = Ed25519Signer(seed)
    return s, [Ed25519Verifier(s.public_key)]


def _emit(sv, signer, *, name="trivy", target, verdict="pass",
          scanned_at=_NOW - 3600, expires_at=_NOW + 86400, now=_NOW):
    return sv.emit_scan_verdict(
        scanner_name=name, scanner_version="0.58.2",
        scan_target_digest=target, verdict=verdict,
        ruleset_digest=_RULESET, scanned_at=scanned_at,
        expires_at=expires_at, signer=signer, now=now)


def _gate(sv, verifiers, required=("trivy",)):
    policy = sv.ScanPolicy(required_scans=list(required))
    return sv.ScanGate(policy, {"trivy": verifiers})


# ------------------------------------------------------------------- probes

@_probe("replay_across_digests_refused")
def p_replay():
    """N1: same-name-different-digest replay. Attack: take a valid
    'pass' verdict bound to the digest of v1 bytes and present it to
    verify_scan_verdict for the digest of v2 bytes. Must refuse with
    scan_verdict_target_mismatch."""
    import gov.scan_verdicts as sv
    signer, verifiers = _signer(_SEED_A)
    env = _emit(sv, signer, target=_DIGEST_V1)
    try:
        sv.verify_scan_verdict(env, verifiers=verifiers,
                               scanner_name="trivy",
                               scan_target_digest=_DIGEST_V2, now=_NOW)
    except sv.ScanVerdictError as e:
        if "target_mismatch" in str(e):
            return ("HELD", "replay refused: %s" % str(e)[:100])
        return ("GAP", "refused but wrong code: %s" % str(e)[:100])
    return ("BREAK", "verdict for v1 digest verified for v2 digest")


@_probe("version_reuse_refused_at_gate")
def p_version_reuse():
    """N2: verdict-reuse-across-versions at the gate. Attack: present
    the v1-bound verdict to ScanGate.check for the v2 digest. Must
    refuse (scan_gate_refused / target_mismatch)."""
    import gov.scan_verdicts as sv
    signer, verifiers = _signer(_SEED_A)
    env = _emit(sv, signer, target=_DIGEST_V1)
    gate = _gate(sv, verifiers)
    try:
        gate.check(_DIGEST_V2, [env], now=_NOW)
    except sv.ScanVerdictError as e:
        if "mismatch" in str(e) or "refused" in str(e):
            return ("HELD", "gate refused: %s" % str(e)[:100])
        return ("GAP", "refused but wrong code: %s" % str(e)[:100])
    return ("BREAK", "gate admitted v1 verdict for v2 digest")


@_probe("bytes_binding_api_present")
def p_api_present():
    """N3: the bytes-binding consumption API exists. The pristine tree
    has no way to consult the gate against BYTES -- only against a
    caller-supplied digest string -- so this is GAP until the fix."""
    import gov.scan_verdicts as sv
    if hasattr(sv.ScanGate, "check_bytes"):
        return ("HELD", "ScanGate.check_bytes present")
    return ("GAP", "no bytes-binding API: digest context is always a "
                   "caller-supplied string")


@_probe("claimed_digest_vs_actual_bytes")
def p_claimed_vs_actual():
    """N4: digest-mismatch-at-consumption. Attack: the deployment
    hashes the CLAIMANT's manifest digest claim (D_claimed) instead of
    the promoted bytes (D_actual). check(D_claimed, [verdict for
    D_claimed]) passes -- the module cannot see the lie -- but
    check_bytes(actual_bytes, ...) with the same verdict must refuse,
    because the digest context comes from the bytes themselves."""
    import gov.scan_verdicts as sv
    signer, verifiers = _signer(_SEED_A)
    # The claimant says "these bytes are D_claimed" (the v1 digest);
    # the actual promoted bytes are v2.
    env = _emit(sv, signer, target=_DIGEST_V1)
    gate = _gate(sv, verifiers)
    claimed_ok = False
    try:
        gate.check(_DIGEST_V1, [env], now=_NOW)
        claimed_ok = True
    except sv.ScanVerdictError:
        claimed_ok = False
    if not hasattr(sv.ScanGate, "check_bytes"):
        return ("GAP", "no check_bytes: claimed-digest seam rests on "
                       "the caller hashing real bytes (a named verifier "
                       "assumption in claim bounds); check(claimed)=%s"
                % ("pass" if claimed_ok else "refused"))
    # Fixed tree: the same verdict against the ACTUAL bytes refuses.
    try:
        gate.check_bytes(_BYTES_V2, [env], now=_NOW)
    except sv.ScanVerdictError as e:
        if "mismatch" in str(e):
            return ("HELD", "check_bytes refused (claimed=%s): %s"
                    % ("pass" if claimed_ok else "refused", str(e)[:80]))
        return ("GAP", "refused but wrong code: %s" % str(e)[:100])
    return ("BREAK", "check_bytes admitted v1 verdict for v2 bytes")


@_probe("bitflip_refused")
def p_bitflip():
    """N5: one-bit flip in the promoted bytes changes the digest, so
    the verdict must refuse via check_bytes."""
    import gov.scan_verdicts as sv
    if not hasattr(sv.ScanGate, "check_bytes"):
        return ("GAP", "no check_bytes API")
    signer, verifiers = _signer(_SEED_A)
    env = _emit(sv, signer, target=_DIGEST_V1)
    gate = _gate(sv, verifiers)
    flipped = bytearray(_BYTES_V1)
    flipped[0] ^= 0x01
    try:
        gate.check_bytes(bytes(flipped), [env], now=_NOW)
    except sv.ScanVerdictError as e:
        if "mismatch" in str(e):
            return ("HELD", "bit-flipped bytes refused: %s" % str(e)[:80])
        return ("GAP", "refused but wrong code: %s" % str(e)[:100])
    return ("BREAK", "check_bytes admitted verdict for tampered bytes")


@_probe("check_bytes_happy_path")
def p_happy():
    """N6: check_bytes with the exact scanned bytes and a valid
    verdict admits (the API must not break the legitimate path)."""
    import gov.scan_verdicts as sv
    if not hasattr(sv.ScanGate, "check_bytes"):
        return ("GAP", "no check_bytes API")
    signer, verifiers = _signer(_SEED_A)
    env = _emit(sv, signer, target=_DIGEST_V1)
    gate = _gate(sv, verifiers)
    try:
        result = gate.check_bytes(_BYTES_V1, [env], now=_NOW)
    except sv.ScanVerdictError as e:
        return ("GAP", "legitimate path refused: %s" % str(e)[:100])
    if result.get("ok") is True and "trivy" in result.get("checked", []):
        return ("HELD", "exact bytes + valid verdict admitted")
    return ("GAP", "unexpected result shape: %r" % (result,))


@_probe("check_bytes_rejects_non_bytes")
def p_non_bytes():
    """N7: check_bytes must refuse non-bytes input LOUDLY, never
    coerce (str/None/int must not become a digest)."""
    import gov.scan_verdicts as sv
    if not hasattr(sv.ScanGate, "check_bytes"):
        return ("GAP", "no check_bytes API")
    signer, verifiers = _signer(_SEED_A)
    env = _emit(sv, signer, target=_DIGEST_V1)
    gate = _gate(sv, verifiers)
    bad_inputs = ["sha256:" + "aa" * 32, None, 12345, b""]
    refused = 0
    for bad in bad_inputs[0:3]:
        try:
            gate.check_bytes(bad, [env], now=_NOW)
        except (sv.ScanVerdictError, TypeError):
            refused += 1
        else:
            return ("BREAK", "check_bytes accepted non-bytes %r"
                    % (bad,))
    # b"" is bytes -- it hashes fine; the verdict (bound to v1) must
    # mismatch, not be coerced into matching.
    try:
        gate.check_bytes(b"", [env], now=_NOW)
    except sv.ScanVerdictError as e:
        if "mismatch" in str(e):
            refused += 1
        else:
            return ("GAP", "empty bytes refused, wrong code: %s"
                    % str(e)[:80])
    else:
        return ("BREAK", "check_bytes admitted verdict for empty bytes")
    if refused == 4:
        return ("HELD", "non-bytes refused loudly; empty bytes mismatch")
    return ("GAP", "only %d/4 refused" % refused)


@_probe("digest_of_bytes_pinned")
def p_digest_helper():
    """N8: the digest helper pins the canonical 'sha256:' + 64-hex
    shape over the exact bytes (stdlib hashlib, no third party)."""
    import gov.scan_verdicts as sv
    fn = getattr(sv, "digest_of_bytes", None)
    if fn is None:
        return ("GAP", "no digest_of_bytes helper")
    got = fn(_BYTES_V1)
    if got != _DIGEST_V1:
        return ("BREAK", "digest_of_bytes wrong: %r" % (got,))
    if fn(b"") != "sha256:" + hashlib.sha256(b"").hexdigest():
        return ("BREAK", "digest_of_bytes wrong on empty input")
    try:
        fn("not-bytes")
    except (sv.ScanVerdictError, TypeError):
        return ("HELD", "helper pins canonical digest shape, no coerce")
    return ("BREAK", "digest_of_bytes coerced a str")


@_probe("empty_digest_verdict_cannot_cover_nonempty")
def p_empty_cover():
    """N9: a verdict bound to sha256(b'') must not cover non-empty
    promoted bytes (the degenerate-digest shape)."""
    import gov.scan_verdicts as sv
    if not hasattr(sv.ScanGate, "check_bytes"):
        return ("GAP", "no check_bytes API")
    signer, verifiers = _signer(_SEED_A)
    empty_digest = "sha256:" + hashlib.sha256(b"").hexdigest()
    env = _emit(sv, signer, target=empty_digest)
    gate = _gate(sv, verifiers)
    try:
        gate.check_bytes(_BYTES_V1, [env], now=_NOW)
    except sv.ScanVerdictError as e:
        if "mismatch" in str(e):
            return ("HELD", "empty-digest verdict cannot cover bytes")
        return ("GAP", "refused but wrong code: %s" % str(e)[:100])
    return ("BREAK", "empty-digest verdict covered non-empty bytes")


@_probe("string_digest_api_unchanged")
def p_legacy_unchanged():
    """N10: the existing check(digest_str, ...) API is byte-identical
    in behavior -- the new API is purely additive (tighten-only)."""
    import gov.scan_verdicts as sv
    signer, verifiers = _signer(_SEED_A)
    env = _emit(sv, signer, target=_DIGEST_V1)
    gate = _gate(sv, verifiers)
    try:
        result = gate.check(_DIGEST_V1, [env], now=_NOW)
    except sv.ScanVerdictError as e:
        return ("GAP", "legacy string API regressed: %s" % str(e)[:100])
    if result.get("ok") is True:
        return ("HELD", "legacy check(digest_str) behavior unchanged")
    return ("GAP", "unexpected legacy result: %r" % (result,))


# ------------------------------------------------------------------ green

def _green_check():
    """Depth-1: run the adjacent wave-213 battery + unit suite once,
    with GOV_SKIP_GREEN=1 so nothing nests."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1, no nested suites)")]
    import subprocess
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    notes = []
    py = sys.executable
    for label, cmd in (
        ("w213-scan-gate-battery",
         [py, os.path.join(_REPO_ROOT, "evals",
                           "w213_scan_gate_probes.py")]),
        ("test_scan_verdicts",
         [py, os.path.join(_REPO_ROOT, "tests",
                           "test_scan_verdicts.py")]),
    ):
        try:
            r = subprocess.run(cmd, env=env, capture_output=True,
                               text=True, timeout=600, cwd=_REPO_ROOT)
        except Exception as e:  # noqa: BLE001
            notes.append((label, "ERROR", "%s" % e))
            continue
        tail = (r.stdout + r.stderr)[-400:]
        if r.returncode == 0:
            notes.append((label, "HELD", tail.strip().splitlines()[-1]
                          if tail.strip() else "exit 0"))
        else:
            notes.append((label, "ERROR", "exit %d: %s"
                          % (r.returncode, tail.strip().splitlines()[-1]
                             if tail.strip() else "")))
    return notes


# ------------------------------------------------------------------- main

def main():
    names = sorted(_PROBE_FNS)
    rows = [(_PROBE_FNS[n]()) for n in names]
    held = sum(1 for _, v, _ in rows if v == "HELD")
    gap = sum(1 for _, v, _ in rows if v == "GAP")
    brk = sum(1 for _, v, _ in rows if v == "BREAK")
    err = sum(1 for _, v, _ in rows if v == "ERROR")
    print("== w216 verdict-binding battery: %d probes ==" % len(rows))
    for name, verdict, detail in rows:
        print("[%s] %s: %s" % (verdict, name, detail))
    print("-- %d HELD / %d GAP / %d BREAK / %d ERROR" % (held, gap, brk,
                                                         err))
    # determinism: second pass must be verdict-identical
    rows2 = [(_PROBE_FNS[n]()) for n in names]
    det = all(a[1] == b[1] for a, b in zip(rows, rows2))
    print("-- determinism: %s" % ("PASS" if det else "FAIL"))
    for label, verdict, detail in _green_check():
        print("[%s] green %s: %s" % (verdict, label, detail))
    if brk or err or not det:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
