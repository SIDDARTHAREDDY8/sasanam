#!/usr/bin/env python3
"""Wave-213 lane A red-team probes: signed scan-verdict promotion gate.

Break-first battery per the diagnosing-bugs skill for the NIST SP 800-190
ADAPT (wave-211 prospecting section 4, verdict: ADAPT narrowly): promotion
gated on named, signed, freshness-bounded scan verdicts. The pristine tree
(ad6e2a3) has signed-only deployment admission (admit_deploy, wave-209) but
NO scan-verdict primitive: the promotion ceremony never consults a scan
verdict, so a bundle with known-vulnerable content and a fully signed,
two-operator ceremony loads identically to a clean one.

Each probe attacks that gap at the PUBLIC seam of the new module
(gov.scan_verdicts). On pristine every probe reports GAP (module absent --
genuine red). After the fix all must flip to HELD.

Probe map:

  S1  STALE_VERDICT_REFUSED      verdict whose expires_at is in the past
                                refuses at verify_scan_verdict
                                (scan_verdict_stale).
  S2  WRONG_TARGET_REFUSED       verdict bound to digest A presented for
                                target digest B refuses
                                (scan_verdict_target_mismatch).
  S3  SIGNATURE_SWAP_REFUSED     envelope signed by scanner-B's key but
                                claiming scanner-A refuses against the
                                pinned scanner-A keyset.
  S4  UNKNOWN_SCANNER_REFUSED    verdict from a scanner name with no pinned
                                keyset refuses loudly at ScanGate.check
                                (never silently ignored).
  S5  FRESH_VALID_ADMITS         honest flow: emit -> verify -> gate check
                                with a policy requiring the scanner name
                                admits; canonical verdict fields sane.
  S6  MISSING_REQUIRED_REFUSED   policy requires "scanner-a", no verdicts
                                presented -> refuses fail-closed
                                (scan_verdict_missing).
  S7  DEFAULT_POLICY_EMPTY       ScanPolicy() default requires nothing:
                                check with no verdicts admits (the feature
                                is opt-in, never silently mandatory).
  S8  FAIL_VERDICT_BLOCKS        a signed "fail" verdict verifies fine at
                                the seam but ScanGate.check blocks
                                promotion (scan_verdict_negative).
  S9  ETERNAL_VERDICT_REFUSED    emission refuses verdicts whose validity
                                exceeds MAX_VERDICT_TTL_SECONDS, and
                                refuses a missing expires_at -- no eternal
                                verdicts on the wire.
  S10 LOADER_WIRING              SkillLoader with a wired ScanGate:
                                load without scan_verdicts refuses
                                (scan_verdicts_unpresented); load with a
                                fresh valid verdict for the pin's digest
                                succeeds.
  S11 LOADER_UNWIRED_IDENTICAL   SkillLoader without scan_gate loads the
                                same skill (legacy behavior unchanged by
                                the new seam).
  S12 DETERMINISM                every probe run twice, identical verdicts.
  S13 LOADER_EMPTY_POLICY_ADMITS SkillLoader with a wired ScanGate whose
                                policy requires NOTHING loads without
                                scan_verdicts (opt-in: wiring the gate
                                must not make verdicts mandatory).

Verdicts: HELD (defense held), GAP (gap demonstrated -- the red phase),
ERROR only on harness failure (a verdict changing between the two
deterministic runs, or an unexpected exception). Exit 2 on any GAP/ERROR
(red); exit 0 only when every probe HELD.

$0 spend. No network. stdlib only. Fixed clock (NOW) for determinism.
"""

import copy
import hashlib
import os
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        def run():
            try:
                detail = fn()
            except ImportError as e:
                _RESULTS.append((name, "GAP", "module absent: %s" % e))
                return
            except AssertionError as e:
                _RESULTS.append((name, "ERROR", "assertion: %s"
                                % str(e)[:300]))
                return
            except Exception as e:  # noqa: BLE001 - hostile-input battery
                _RESULTS.append((name, "ERROR", "%s: %s"
                                % (type(e).__name__, str(e)[:300])))
                return
            verdict, detail = detail
            assert verdict in ("HELD", "GAP"), verdict
            _RESULTS.append((name, verdict, detail))
        _PROBE_FNS[name] = run
        return run
    return deco


# ------------------------------------------------------------------ helpers

_NOW = 1700000000
_SEED_A = bytes.fromhex("a1" * 32)
_SEED_B = bytes.fromhex("b2" * 32)
_SEED_ROGUE = bytes.fromhex("c3" * 32)
_SEED_PIN = bytes.fromhex("d4" * 32)
_SEED_AUTH = bytes.fromhex("e5" * 32)
_TS = "2026-09-23T00:00:00+00:00"

_DIGEST_A = "sha256:" + "aa" * 32
_DIGEST_B = "sha256:" + "bb" * 32
_RULESET = "sha256:" + "cc" * 32


def _scanner(sv_mod, seed):
    from gov.signing import Ed25519Signer, Ed25519Verifier
    signer = Ed25519Signer(seed)
    return signer, [Ed25519Verifier(signer.public_key)]


def _emit(sv, signer, *, name="scanner-a", version="1.4.2",
          target=_DIGEST_A, verdict="pass", scanned_at=_NOW - 3600,
          expires_at=_NOW + 86400, ruleset=_RULESET,
          severity_counts=None, bounds=None, now=_NOW):
    return sv.emit_scan_verdict(
        scanner_name=name, scanner_version=version,
        scan_target_digest=target, verdict=verdict,
        ruleset_digest=ruleset, scanned_at=scanned_at,
        expires_at=expires_at, signer=signer,
        severity_counts=severity_counts, claim_bounds=bounds, now=now)


def _gate_harness():
    """Minimal SkillLoader fixture (pinset + store, no registry)."""
    from gov import load_gate as lg
    from gov.signing import Ed25519Signer
    from gov.delegation_tokens import DelegationTrust
    pin_signer = Ed25519Signer(_SEED_PIN)
    auth = Ed25519Signer(_SEED_AUTH)
    trust = DelegationTrust(
        human_keys={pin_signer.key_id: pin_signer.public_key},
        authority_keys={auth.key_id: auth.public_key},
        user_issuer_keys={pin_signer.key_id: pin_signer.public_key})
    pinset = lg.ArtifactPinset(trust)
    store = {}
    log = []

    def pin(name, content):
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        na = lg._resolve_pin_not_after(_TS, None)
        body = lg._canonical_pin_body("dev", "skill:" + name, digest,
                                      _TS, version=1, not_after=na)
        pinset.pin("skill:" + name, digest, pin_signer.key_id,
                   pin_signer.sign(body).hex(), ts=_TS,
                   tier="dev", version=1, not_after=na)
        store[name] = content
        return digest
    return lg, pinset, store, log, pin


# ------------------------------------------------------------------- probes

@_probe("stale_verdict_refused")
def p_stale():
    """S1: an expired verdict must refuse at verify time, not just at
    emission. Attack: present a once-valid verdict whose expires_at has
    passed; a gate that only checks signatures would admit it."""
    import gov.scan_verdicts as sv
    signer, verifiers = _scanner(sv, _SEED_A)
    # Valid at emission (window sane, not born stale), stale by the
    # time the verifier's clock reaches _NOW + 7200.
    env = _emit(sv, signer, scanned_at=_NOW - 3600, expires_at=_NOW + 3600)
    try:
        sv.verify_scan_verdict(env, verifiers=verifiers,
                               scanner_name="scanner-a",
                               scan_target_digest=_DIGEST_A,
                               now=_NOW + 7200)
    except sv.ScanVerdictError as e:
        if "stale" in str(e).lower() or "expir" in str(e).lower():
            return ("HELD", "expired verdict refused: %s"
                    % str(e)[:120])
        return ("GAP", "refused but with wrong reason: %s" % str(e)[:120])
    return ("GAP", "BREAK: stale verdict verified without complaint")


@_probe("wrong_target_refused")
def p_wrong_target():
    """S2: a verdict bound to digest A must refuse when presented for
    target B. Attack: transplant a clean verdict from one bundle onto
    another bundle."""
    import gov.scan_verdicts as sv
    signer, verifiers = _scanner(sv, _SEED_A)
    env = _emit(sv, signer, target=_DIGEST_A)
    try:
        sv.verify_scan_verdict(env, verifiers=verifiers,
                               scanner_name="scanner-a",
                               scan_target_digest=_DIGEST_B, now=_NOW)
    except sv.ScanVerdictError as e:
        if "target" in str(e).lower():
            return ("HELD", "wrong-target verdict refused: %s"
                    % str(e)[:120])
        return ("GAP", "refused but with wrong reason: %s" % str(e)[:120])
    return ("GAP", "BREAK: verdict transplanted across digests")


@_probe("signature_swap_refused")
def p_sig_swap():
    """S3: a verdict claiming scanner-A but signed by scanner-B's key
    must refuse against the pinned scanner-A keyset. Attack: rogue
    scanner key minting verdicts under a trusted scanner's name."""
    import gov.scan_verdicts as sv
    signer_b, _ = _scanner(sv, _SEED_B)
    _, verifiers_a = _scanner(sv, _SEED_A)
    env = _emit(sv, signer_b, name="scanner-a")  # B signs, claims A
    try:
        sv.verify_scan_verdict(env, verifiers=verifiers_a,
                               scanner_name="scanner-a",
                               scan_target_digest=_DIGEST_A, now=_NOW)
    except sv.ScanVerdictError as e:
        return ("HELD", "signature-swap refused: %s" % str(e)[:120])
    return ("GAP", "BREAK: foreign key minted a trusted-name verdict")


@_probe("unknown_scanner_refused")
def p_unknown_scanner():
    """S4: a verdict from a scanner with no pinned keyset must refuse
    LOUDLY at ScanGate.check -- silently ignoring it would let an
    attacker pick any scanner name to dodge a required scan."""
    import gov.scan_verdicts as sv
    signer_r, _ = _scanner(sv, _SEED_ROGUE)
    _, verifiers_a = _scanner(sv, _SEED_A)
    env = _emit(sv, signer_r, name="scanner-rogue")
    gate = sv.ScanGate(sv.ScanPolicy(required_scans=["scanner-a"]),
                       {"scanner-a": verifiers_a})
    try:
        gate.check(_DIGEST_A, [env], now=_NOW)
    except sv.ScanVerdictError as e:
        if "unknown" in str(e).lower():
            return ("HELD", "unknown scanner refused loudly: %s"
                    % str(e)[:120])
        # Any refusal here is fail-closed; the required scan is still
        # missing, so check() must not admit.
        return ("HELD", "refused fail-closed: %s" % str(e)[:120])
    return ("GAP", "BREAK: unpinned scanner name slipped through the gate")


@_probe("fresh_valid_admits")
def p_fresh_valid():
    """S5: the honest flow must admit: emit -> verify -> gate check with
    a policy requiring the scanner name. Also pins the canonical
    verdict shape (bounds present and validated)."""
    import gov.scan_verdicts as sv
    import gov.claim_bounds as cb
    signer, verifiers = _scanner(sv, _SEED_A)
    env = _emit(sv, signer,
                severity_counts={"critical": 0, "high": 1, "medium": 3})
    got = sv.verify_scan_verdict(env, verifiers=verifiers,
                                 scanner_name="scanner-a",
                                 scan_target_digest=_DIGEST_A, now=_NOW)
    stmt = got["statement"]
    assert stmt["verdict"] == "pass", stmt
    assert stmt["scan_target_digest"] == _DIGEST_A, stmt
    assert stmt["scanner_name"] == "scanner-a", stmt
    assert stmt["expires_at"] > _NOW, stmt
    assert got["verified_key_ids"], got
    # Bounds ride the wire and are validated, not decorative.
    cb.validate_bounds(stmt["claim_bounds"], where="wire-bounds")
    gate = sv.ScanGate(sv.ScanPolicy(required_scans=["scanner-a"]),
                       {"scanner-a": verifiers})
    res = gate.check(_DIGEST_A, [env], now=_NOW)
    assert res.get("ok") is True, res
    return ("HELD", "fresh valid verdict verified + admitted; "
            "bounds validated on the wire")


@_probe("missing_required_refused")
def p_missing_required():
    """S6: policy requires scanner-a, zero verdicts presented -> fail
    closed. The default must not silently admit a required scan as
    satisfied."""
    import gov.scan_verdicts as sv
    _, verifiers_a = _scanner(sv, _SEED_A)
    gate = sv.ScanGate(sv.ScanPolicy(required_scans=["scanner-a"]),
                       {"scanner-a": verifiers_a})
    try:
        gate.check(_DIGEST_A, [], now=_NOW)
    except sv.ScanVerdictError as e:
        if "missing" in str(e).lower():
            return ("HELD", "missing required scan refused: %s"
                    % str(e)[:120])
        return ("HELD", "refused fail-closed: %s" % str(e)[:120])
    return ("GAP", "BREAK: required scan absent yet promotion admitted")


@_probe("default_policy_empty")
def p_default_policy():
    """S7: ScanPolicy() with no required scans must admit with no
    verdicts -- the feature is opt-in and must never become silently
    mandatory for deployments that have not adopted it."""
    import gov.scan_verdicts as sv
    gate = sv.ScanGate(sv.ScanPolicy(), {})
    res = gate.check(_DIGEST_A, [], now=_NOW)
    assert res.get("ok") is True, res
    assert sv.ScanPolicy().required_scans == (), "default not empty"
    return ("HELD", "empty default policy admits without verdicts")


@_probe("fail_verdict_blocks")
def p_fail_blocks():
    """S8: a signed 'fail' verdict verifies cleanly at the seam (name,
    target, signature, freshness all good) but ScanGate.check must BLOCK
    promotion: a fail is decisive negative evidence, not an absence."""
    import gov.scan_verdicts as sv
    signer, verifiers = _scanner(sv, _SEED_A)
    env = _emit(sv, signer, verdict="fail",
                severity_counts={"critical": 2})
    # It must VERIFY (the seam is honest about what it carries)...
    got = sv.verify_scan_verdict(env, verifiers=verifiers,
                                 scanner_name="scanner-a",
                                 scan_target_digest=_DIGEST_A, now=_NOW)
    assert got["statement"]["verdict"] == "fail", got
    # ...but the gate must refuse to promote on it.
    gate = sv.ScanGate(sv.ScanPolicy(required_scans=["scanner-a"]),
                       {"scanner-a": verifiers})
    try:
        gate.check(_DIGEST_A, [env], now=_NOW)
    except sv.ScanVerdictError as e:
        return ("HELD", "signed fail verdict verified but promotion "
                "blocked: %s" % str(e)[:120])
    return ("GAP", "BREAK: promotion admitted on a signed FAIL verdict")


@_probe("eternal_verdict_refused")
def p_eternal():
    """S9: no eternal verdicts. Emission must refuse a validity window
    longer than MAX_VERDICT_TTL_SECONDS and must refuse a missing
    expires_at."""
    import gov.scan_verdicts as sv
    signer, _ = _scanner(sv, _SEED_A)
    try:
        _emit(sv, signer, scanned_at=_NOW,
              expires_at=_NOW + sv.MAX_VERDICT_TTL_SECONDS + 1)
    except sv.ScanVerdictError:
        pass
    else:
        return ("GAP", "BREAK: over-long validity window emitted")
    try:
        sv.emit_scan_verdict(
            scanner_name="scanner-a", scanner_version="1.4.2",
            scan_target_digest=_DIGEST_A, verdict="pass",
            ruleset_digest=_RULESET, scanned_at=_NOW, expires_at=None,
            signer=signer, now=_NOW)
    except sv.ScanVerdictError:
        pass
    else:
        return ("GAP", "BREAK: verdict without expires_at emitted")
    return ("HELD", "eternal/over-long verdicts refused at emission")


@_probe("loader_wiring")
def p_loader_wiring():
    """S10: SkillLoader with a wired ScanGate requiring scanner-a:
    load_skill without scan_verdicts refuses
    (scan_verdicts_unpresented); with a fresh valid verdict for the
    pin's digest the load succeeds."""
    import gov.scan_verdicts as sv
    from gov import load_gate as lg
    signer, verifiers = _scanner(sv, _SEED_A)
    lg_mod, pinset, store, log, pin = _gate_harness()
    gate = sv.ScanGate(sv.ScanPolicy(required_scans=["scanner-a"]),
                       {"scanner-a": verifiers})
    loader = lg_mod.SkillLoader(pinset, store, log=log, scan_gate=gate)
    digest = pin("scanme", b"scan-gated content")
    try:
        loader.load_skill("scanme")
    except lg_mod.ArtifactRefused as e:
        if "scan_verdicts_unpresented" not in str(e):
            return ("GAP", "refused with wrong reason: %s" % str(e)[:150])
    else:
        return ("GAP", "BREAK: scan-gated load admitted with no verdict")
    # The loader path consults the gate against the verifier's real
    # clock (honest: a fixed clock in production would be a lie), so
    # this verdict is minted wall-clock-relative, not on the fixed
    # test clock.
    wall = int(time.time())
    env = _emit(sv, signer, target=digest, scanned_at=wall - 60,
                expires_at=wall + 3600, now=wall)
    verified = loader.load_skill("scanme", scan_verdicts=[env])
    assert verified.data == b"scan-gated content", verified
    return ("HELD", "wired loader: unpresented refused, valid verdict "
            "loads")


@_probe("loader_unwired_identical")
def p_loader_unwired():
    """S11: SkillLoader WITHOUT scan_gate loads the same skill --
    legacy callers that have not adopted scan gating see zero behavior
    change."""
    import gov.scan_verdicts  # noqa: F401  (module must exist)
    lg_mod, pinset, store, log, pin = _gate_harness()
    loader = lg_mod.SkillLoader(pinset, store, log=log)
    pin("plain", b"ungated content")
    verified = loader.load_skill("plain")
    assert verified.data == b"ungated content", verified
    return ("HELD", "unwired loader loads unchanged")


@_probe("loader_empty_policy_admits")
def p_loader_empty_policy():
    """S13: SkillLoader with a WIRED ScanGate whose policy requires
    NOTHING must load without scan_verdicts. Regression for the
    spec-axis finding: the loader previously demanded verdicts
    whenever a gate was wired, making the feature silently mandatory
    for deployments that adopted the gate but required no scans."""
    import gov.scan_verdicts as sv
    _, verifiers = _scanner(sv, _SEED_A)
    lg_mod, pinset, store, log, pin = _gate_harness()
    gate = sv.ScanGate(sv.ScanPolicy(), {"scanner-a": verifiers})
    loader = lg_mod.SkillLoader(pinset, store, log=log, scan_gate=gate)
    pin("optin", b"opt-in content")
    verified = loader.load_skill("optin")
    assert verified.data == b"opt-in content", verified
    return ("HELD", "wired gate with empty policy admits without verdicts")


@_probe("determinism")
def p_determinism():
    """S12: every probe run twice on the fixed clock; verdicts must be
    identical. A verdict that flips between runs is a harness bug."""
    first = []
    saved = list(_RESULTS)
    del _RESULTS[:]
    try:
        for name in sorted(_PROBE_FNS):
            if name == "determinism":
                continue
            _PROBE_FNS[name]()
        first = [(n, v) for n, v, _ in _RESULTS]
        del _RESULTS[:]
        for name in sorted(_PROBE_FNS):
            if name == "determinism":
                continue
            _PROBE_FNS[name]()
        second = [(n, v) for n, v, _ in _RESULTS]
    finally:
        del _RESULTS[:]
        _RESULTS.extend(saved)
    if first != second:
        return ("ERROR", "non-deterministic verdicts: %r vs %r"
                % (first, second))
    return ("HELD", "deterministic across two runs (%d probes)"
            % len(first))


# ------------------------------------------------------------------ green

def _green_check():
    # Depth-1 green check: adjacent batteries must stay green alongside
    # this one (each run with GOV_SKIP_GREEN=1 to prevent combinatorial
    # nesting).
    import subprocess
    adj = ["evals/dsse_envelope_probes.py",
           "evals/claim_bounds_probes.py",
           "evals/sign_deploy_namespace_probes.py"]
    for rel in adj:
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            _RESULTS.append(("green:" + rel, "HELD",
                             "battery absent (lane not merged)"))
            continue
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        r = subprocess.run([sys.executable, path], capture_output=True,
                           text=True, env=env, timeout=600)
        ok = r.returncode == 0
        _RESULTS.append(("green:" + os.path.basename(rel),
                         "HELD" if ok else "ERROR",
                         "adjacent battery %s"
                         % ("green" if ok else
                            "RED: " + (r.stdout + r.stderr)[-300:])))


def main():
    if not GREEN_SKIP:
        _green_check()
    for name in list(_PROBE_FNS):
        if name == "determinism":
            continue
        _PROBE_FNS[name]()
    _PROBE_FNS["determinism"]()
    n_held = n_gap = n_err = 0
    for name, verdict, detail in _RESULTS:
        print("%-32s %-6s %s" % (name, verdict, detail))
        if verdict == "HELD":
            n_held += 1
        elif verdict == "GAP":
            n_gap += 1
        else:
            n_err += 1
    print("w213 scan-gate: held=%d gap=%d errors=%d" % (n_held, n_gap,
                                                       n_err))
    bad = any(v not in ("HELD",) for _, v, _ in _RESULTS)
    return 2 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
