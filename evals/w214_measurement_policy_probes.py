#!/usr/bin/env python3
"""Red-first battery: named, versioned measurement policies (wave-214 lane C).

Tests gov/measurement_policy.py (the Keylime policy-discipline ADAPT):
a measurement policy is named, versioned data; attestation evaluation
binds (policy_name, version) explicitly; unknown / stale / wrong-key
policies fail closed; version roll-forward is explicit; downgrades are
refused. On pristine every probe reports GAP (module absent).

Verdicts: HELD (defense held), GAP (gap demonstrated -- the red phase),
BREAK (genuine break on the fixed tree: files as F208+), ERROR
(harness failure). Exit 1 on any BREAK/ERROR.

Ranked falsifiable hypotheses (diagnosing-bugs loop):
  H1 (rank 1): without an explicit policy registry, attestation
     evaluation "verifies against whatever the agent sent" -- the
     Keylime gap. Expected: GAP on pristine (no module), HELD when the
     unknown-policy and stale-policy probes refuse.
  H2 (rank 2): a policy swapped after activation could pass evaluation
     if the signature were only checked once. Expected: GAP on
     pristine, HELD when the mid-evaluation swap probes refuse.
  H3 (rank 3): version upgrades could happen implicitly ("just use the
     newest") or slide backwards silently. Expected: HELD when the
     explicit-version and downgrade probes refuse.
  H4 (rank 4): the policy must wrap, not replace, the synthetic
     verifiers. Expected: HELD when the TEE fixture verifies both
     standalone and through the policy seam, and mismatched
     measurements refuse.

$0 spend. No network. stdlib only.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import measurement_policy as mp
    from gov import ed25519 as _ed
    HAVE_MODULE = True
except ImportError as _e:  # noqa: F841 -- pristine tree
    HAVE_MODULE = False

_RESULTS = []
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        _PROBE_FNS[name] = fn
        return fn
    return deco


def _record(name, verdict, detail):
    _RESULTS.append((name, verdict, detail))


def _run_probe(name, fn):
    try:
        if not HAVE_MODULE:
            raise ImportError("gov.measurement_policy")
        verdict, detail = fn()
    except ImportError as e:
        verdict, detail = "BREAK", "module absent: %s" % (e,)
    except Exception as exc:  # noqa: BLE001
        verdict, detail = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    _record(name, verdict, detail)
    return verdict


# ---------------------------------------------------------------------------
# fixtures

_NOW = 1785000000
_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64
_DIGEST_C = "c" * 64


def _issuer():
    seed = _ed.generate_seed()
    return seed, _ed.publickey(seed)


def _body(name="gpu-fleet", version=1, digests=(("launch_image", _DIGEST_A),),
          not_before=_NOW - 3600, not_after=_NOW + 3600):
    return mp.make_policy_body(
        policy_name=name, version=version,
        required_measurements=list(digests),
        not_before=not_before, not_after=not_after, signer_kid="policy-ops")


def _registry(body, seed=None, now=_NOW):
    if seed is None:
        seed, pub = _issuer()
    else:
        pub = _ed.publickey(seed)
    sig = mp.sign_policy(seed, body)
    reg = mp.MeasurementPolicyRegistry(pub)
    reg.activate(body, sig, now=now)
    return reg, seed, pub


def _measured(*names):
    return {name: _DIGEST_A for name in names}


# ---------------------------------------------------------------------------
# probes

@_probe("unknown_policy_refused")
def p_unknown():
    seed, pub = _issuer()
    reg = mp.MeasurementPolicyRegistry(pub)
    try:
        reg.evaluate("gpu-fleet", 1, _measured("launch_image"), now=_NOW)
    except mp.MeasurementPolicyError as e:
        if e.code == "policy-unknown":
            return "HELD", "unknown policy refused with policy-unknown"
        return "BREAK", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "evaluation succeeded with no activated policy"


@_probe("wrong_key_policy_refused")
def p_wrong_key():
    body = _body()
    rogue_seed, _rogue_pub = _issuer()
    real_seed, real_pub = _issuer()
    sig = mp.sign_policy(rogue_seed, body)  # signed by the wrong key
    reg = mp.MeasurementPolicyRegistry(real_pub)
    try:
        reg.activate(body, sig, now=_NOW)
    except mp.MeasurementPolicyError as e:
        if e.code == "policy-signature-invalid":
            return "HELD", "wrong-key policy refused at activation"
        return "BREAK", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "policy signed by a foreign key activated"


@_probe("self_signed_policy_refused")
def p_self_signed():
    # The document carries an identity-only signer.kid, never a key.
    # A "self-signed" policy verifies False against the pinned key.
    body = _body()
    seed, _ = _issuer()
    pinned_seed, pinned_pub = _issuer()
    sig = mp.sign_policy(seed, body)
    reg = mp.MeasurementPolicyRegistry(pinned_pub)
    try:
        reg.activate(body, sig, now=_NOW)
    except mp.MeasurementPolicyError as e:
        if e.code == "policy-signature-invalid":
            return "HELD", "self-asserted key never becomes trust"
        return "BREAK", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "self-signed policy activated"


@_probe("stale_policy_activation_refused")
def p_stale_activate():
    seed, pub = _issuer()
    body = _body(not_before=_NOW - 7200, not_after=_NOW - 1)
    sig = mp.sign_policy(seed, body)
    reg = mp.MeasurementPolicyRegistry(pub)
    try:
        reg.activate(body, sig, now=_NOW)
    except mp.MeasurementPolicyError as e:
        if e.code == "policy-stale":
            return "HELD", "expired policy cannot activate"
        return "BREAK", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "already-expired policy activated"


@_probe("stale_policy_eval_refused")
def p_stale_eval():
    body = _body(not_after=_NOW + 60)
    reg, _, _ = _registry(body)
    # 60 seconds later the same (name, version) is stale.
    try:
        reg.evaluate("gpu-fleet", 1, _measured("launch_image"),
                     now=_NOW + 61)
    except mp.MeasurementPolicyError as e:
        if e.code == "policy-stale":
            return "HELD", "stale policy refused at evaluation"
        return "BREAK", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "expired policy evaluated successfully"


@_probe("no_implicit_upgrade")
def p_no_upgrade():
    # v1 with a short window and v2 both activated. After v1 expires,
    # evaluating v1 must refuse -- never "helpfully" use v2.
    seed, pub = _issuer()
    b1 = _body(version=1, not_after=_NOW + 60)
    b2 = _body(version=2, digests=(("launch_image", _DIGEST_B),),
               not_after=_NOW + 3600)
    reg = mp.MeasurementPolicyRegistry(pub)
    reg.activate(b1, mp.sign_policy(seed, b1), now=_NOW)
    reg.activate(b2, mp.sign_policy(seed, b2), now=_NOW)
    try:
        reg.evaluate("gpu-fleet", 1, _measured("launch_image"),
                     now=_NOW + 61)
    except mp.MeasurementPolicyError as e:
        if e.code == "policy-stale":
            return "HELD", "stale v1 refused even though v2 is valid"
        return "BREAK", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "stale v1 silently upgraded to v2"


@_probe("explicit_version_rollforward")
def p_explicit_roll():
    seed, pub = _issuer()
    reg = mp.MeasurementPolicyRegistry(pub)
    b1 = _body(version=1)
    b2 = _body(version=2, digests=(("launch_image", _DIGEST_B),))
    reg.activate(b1, mp.sign_policy(seed, b1), now=_NOW)
    reg.activate(b2, mp.sign_policy(seed, b2), now=_NOW)
    # Roll-forward is explicit: caller names v2, which matches v2 digests.
    out = reg.evaluate("gpu-fleet", 2, {"launch_image": _DIGEST_B},
                       now=_NOW)
    if out != ("gpu-fleet", 2):
        return "BREAK", "explicit v2 evaluation did not bind v2"
    # And the caller can still pin v1 while it is valid.
    out = reg.evaluate("gpu-fleet", 1, _measured("launch_image"),
                       now=_NOW)
    if out != ("gpu-fleet", 1):
        return "BREAK", "explicit v1 evaluation did not bind v1"
    return "HELD", "explicit version binding honored for v1 and v2"


@_probe("version_downgrade_refused")
def p_downgrade():
    seed, pub = _issuer()
    reg = mp.MeasurementPolicyRegistry(pub)
    b2 = _body(version=2)
    b1 = _body(version=1)
    reg.activate(b2, mp.sign_policy(seed, b2), now=_NOW)
    try:
        reg.activate(b1, mp.sign_policy(seed, b1), now=_NOW)
    except mp.MeasurementPolicyError as e:
        if e.code == "policy-version-downgrade":
            return "HELD", "version downgrade refused"
        return "BREAK", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "older policy version displaced v2"


@_probe("version_replay_refused")
def p_replay():
    seed, pub = _issuer()
    reg = mp.MeasurementPolicyRegistry(pub)
    b1 = _body(version=1)
    reg.activate(b1, mp.sign_policy(seed, b1), now=_NOW)
    # Re-activating the SAME version is not an upgrade path.
    b1b = _body(version=1, digests=(("launch_image", _DIGEST_C),))
    try:
        reg.activate(b1b, mp.sign_policy(seed, b1b), now=_NOW)
    except mp.MeasurementPolicyError as e:
        if e.code == "policy-version-downgrade":
            return "HELD", "same-version replay refused (floor holds)"
        return "BREAK", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "same-version policy with new digests replaced v1"


@_probe("mid_eval_swap_refused")
def p_swap_body():
    reg, _, _ = _registry(_body())
    # Attacker edits the stored policy after activation (digest swap).
    entry = reg._policies[("gpu-fleet", 1)]  # noqa: SLF001 -- white-box probe
    entry["body"]["required_measurements"][0]["expected_digest"] = \
        _DIGEST_C
    try:
        reg.evaluate("gpu-fleet", 1, {"launch_image": _DIGEST_C},
                     now=_NOW)
    except mp.MeasurementPolicyError as e:
        if e.code == "policy-signature-invalid":
            return "HELD", "post-activation body edit fails re-check"
        return "BREAK", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "swapped policy body evaluated as valid"


@_probe("mid_eval_sig_swap_refused")
def p_swap_sig():
    reg, _, _ = _registry(_body())
    entry = reg._policies[("gpu-fleet", 1)]  # noqa: SLF001 -- white-box probe
    entry["sig"] = b"\x00" * 64
    try:
        reg.evaluate("gpu-fleet", 1, _measured("launch_image"),
                     now=_NOW)
    except mp.MeasurementPolicyError as e:
        if e.code == "policy-signature-invalid":
            return "HELD", "post-activation sig corruption fails re-check"
        return "BREAK", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "corrupted stored signature evaluated as valid"


@_probe("measurement_mismatch_refused")
def p_mismatch():
    reg, _, _ = _registry(_body())
    try:
        reg.evaluate("gpu-fleet", 1, {"launch_image": _DIGEST_B},
                     now=_NOW)
    except mp.MeasurementPolicyError as e:
        if e.code == "measurement-mismatch":
            return "HELD", "digest mismatch refused"
        return "BREAK", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "wrong measurement digest accepted"


@_probe("measurement_missing_refused")
def p_missing():
    reg, _, _ = _registry(_body(digests=(("launch_image", _DIGEST_A),
                                          ("kernel", _DIGEST_B))))
    try:
        reg.evaluate("gpu-fleet", 1, {"launch_image": _DIGEST_A},
                     now=_NOW)
    except mp.MeasurementPolicyError as e:
        if e.code == "measurement-missing":
            return "HELD", "missing required component refused"
        return "BREAK", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "partial measurements accepted"


@_probe("measurement_unlisted_refused")
def p_unlisted():
    reg, _, _ = _registry(_body())
    try:
        reg.evaluate("gpu-fleet", 1,
                     {"launch_image": _DIGEST_A,
                      "mystery_module": _DIGEST_A}, now=_NOW)
    except mp.MeasurementPolicyError as e:
        if e.code == "measurement-unlisted":
            return "HELD", "unlisted measured component refused"
        return "BREAK", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "unlisted software component accepted silently"


@_probe("malformed_digest_refused")
def p_malformed():
    reg, _, _ = _registry(_body())
    try:
        reg.evaluate("gpu-fleet", 1, {"launch_image": "not-a-digest"},
                     now=_NOW)
    except mp.MeasurementPolicyError as e:
        if e.code == "measurement-mismatch":
            return "HELD", "malformed digest verifies False"
        return "BREAK", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "malformed digest accepted"


@_probe("valid_evaluation_held")
def p_valid():
    reg, _, _ = _registry(_body())
    out = reg.evaluate("gpu-fleet", 1, _measured("launch_image"),
                       now=_NOW)
    if out != ("gpu-fleet", 1):
        return "ERROR", "evaluation returned %r" % (out,)
    return "HELD", "matching measurements evaluate cleanly"


@_probe("tee_fixture_wrapped_by_policy")
def p_tee_wrap():
    # Policies WRAP the synthetic verifiers: the TEE fixture verifies
    # standalone (unchanged), and a policy binds its measurement.
    from gov import tee_attest as ta
    fx = ta.make_snp_fixture(policy=1, measurement=bytes(48),
                             tcb=b"\x00" * 8, chip_id=b"\x01" * 64,
                             salt=b"\x02" * 32)
    claims = ta.SevSnpVerifier(ark_pubkey=fx["ark_pubkey"],
                               enabled=True).verify({
        "report": fx["report"],
        "ask_cert": fx["ask_cert"],
        "vcek_cert": fx["vcek_cert"],
        "expected_policy": 1,
        "expected_measurement": fx["measurement"],
        "tcb_allowlist": [fx["tcb"]],
        "tee_pubkey": fx["tee_pubkey"],
        "salt": fx["salt"],
    })
    seed, pub = _issuer()
    body = mp.make_policy_body(
        policy_name="sev-snp-fleet", version=1,
        required_measurements=[("launch_image", claims["measurement"])],
        not_before=_NOW - 60, not_after=_NOW + 3600,
        signer_kid="policy-ops")
    reg = mp.MeasurementPolicyRegistry(pub)
    reg.activate(body, mp.sign_policy(seed, body), now=_NOW)
    # Evaluate through the policy seam with the attested measurement.
    out = reg.evaluate("sev-snp-fleet", 1,
                       {"launch_image": claims["measurement"]}, now=_NOW)
    if out != ("sev-snp-fleet", 1):
        return "BREAK", "TEE measurement not evaluable through the policy"
    # A tampered measurement refuses at the policy seam.
    try:
        reg.evaluate("sev-snp-fleet", 1, {"launch_image": _DIGEST_C},
                     now=_NOW)
    except mp.MeasurementPolicyError as e:
        if e.code == "measurement-mismatch":
            return "HELD", "TEE verifier intact; policy binds measurement"
        return "BREAK", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "tampered TEE measurement accepted by policy"


@_probe("strict_shape_lint")
def p_shape():
    seed, _ = _issuer()
    body = _body()
    sig = mp.sign_policy(seed, body)
    # Unknown fields are refused, never ignored. (The signature was
    # computed before the mutation; the shape lint must fire first.)
    body["extra_field"] = "smuggle"
    _, pub = _issuer()
    reg = mp.MeasurementPolicyRegistry(pub)
    try:
        reg.activate(dict(body), sig, now=_NOW)
    except mp.MeasurementPolicyError as e:
        if e.code == "policy-body-malformed":
            return "HELD", "unknown body fields refused"
        return "BREAK", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "extra field in policy body ignored silently"


def _green_check():
    # Depth-1 green check: the module's own unit tests stay green
    # alongside this battery (run with GOV_SKIP_GREEN=1 to prevent
    # combinatorial nesting).
    import subprocess
    path = os.path.join(REPO, "tests", "test_measurement_policy.py")
    if not os.path.exists(path):
        _record("green_test_measurement_policy", "HELD",
                "unit tests absent (lane not merged)")
        return
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    r = subprocess.run([sys.executable, "-m", "unittest",
                        "tests.test_measurement_policy", "-v"],
                       capture_output=True, text=True, env=env,
                       cwd=REPO, timeout=600)
    ok = r.returncode == 0
    _record("green_test_measurement_policy",
            "HELD" if ok else "ERROR",
            "unit tests %s" % ("green" if ok else
                               "RED: " + (r.stdout + r.stderr)[-300:]))


def main():
    order = sorted(_PROBE_FNS)
    first = {}
    for name in order:
        first[name] = _run_probe(name, _PROBE_FNS[name])
    # Determinism: re-run every probe, verdicts must be identical.
    for name in order:
        verdict = _run_probe(name + "determinism", _PROBE_FNS[name])
        got = verdict
        want = first[name]
        if got != want:
            _RESULTS[-1] = (name + "determinism", "ERROR",
                            "nondeterministic: %s then %s" % (want, got))
    if not GREEN_SKIP:
        _green_check()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    gap = sum(1 for _, v, _ in _RESULTS if v == "GAP")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("w214 measurement-policy: %d probes: %d HELD / %d GAP / %d BREAK / "
          "%d ERROR" % (len(_RESULTS), held, gap, brk, err))
    # D1: all GAP verdicts mapped to BREAK above (red-first); the gap
    # counter is now 0 (w215 dead-counter precedent).
    probe_lines.emit(_RESULTS)
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
