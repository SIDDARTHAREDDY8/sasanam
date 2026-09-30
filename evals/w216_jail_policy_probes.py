#!/usr/bin/env python3
"""Red-first battery: named, versioned jail policies (wave-216 lane B).

Tests gov/jail_policy.py (the gVisor taxonomy + sandboxexec/python
recipe ADAPT): a jail policy is named, versioned, Ed25519-signed data
describing a tool-call jail (ro rootfs + explicit rw mounts + network
none + no_new_privs + timeout + resource limits). Activation binds a
pinned issuer key; invocation conformance is audit-visible and
fail-closed; backend coverage gaps are named, never silently degraded.
On pristine every probe reports GAP (module absent).

Verdicts: HELD (defense held), GAP (gap demonstrated -- the red phase),
BREAK (genuine break on the fixed tree: files as F209+), ERROR
(harness failure). Exit 1 on any BREAK/ERROR.

Ranked falsifiable hypotheses (diagnosing-bugs loop):
  H1 (rank 1): without a policy seam, any invocation runs under
     whatever the caller asked for -- there is no declared jail to
     conform to. Expected: GAP on pristine (no module), HELD when
     unknown-policy and escape probes refuse.
  H2 (rank 2): a signed policy could be swapped after activation if
     the signature were only checked once. Expected: HELD when the
     post-activation swap probe refuses via signature re-check.
  H3 (rank 3): policy upgrades could slide backwards silently.
     Expected: HELD when the downgrade probe refuses.
  H4 (rank 4): a backend coverage gap (no seccomp/netns/pivot on the
     machine) could silently degrade the jail. Expected: HELD when the
     gap probe names the missing feature and refuses.
  H5 (rank 5): path-traversal in a requested writable dir
     ("/output/../etc") could escape the declared mounts. Expected:
     HELD when the escape probe refuses (normpath collapses it to
     "/etc", outside the mounts).

$0 spend. No network. stdlib only.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import jail_policy as jp
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
            raise ImportError("gov.jail_policy")
        verdict, detail = fn()
    except ImportError as e:
        verdict, detail = "GAP", "module absent: %s" % (e,)
    except Exception as exc:  # noqa: BLE001
        verdict, detail = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    _record(name, verdict, detail)
    return verdict


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

_NOW = 1785000000
_FULL_FEATURES = {"timeout", "rlimit", "netns", "pidns", "pivot_root",
                  "seccomp", "privdrop"}


def _issuer():
    seed = _ed.generate_seed()
    return seed, _ed.publickey(seed)


def _body(name="tool-python", version=1, dirs=("/output",),
          timeout_s=5, not_before=_NOW - 3600, not_after=_NOW + 3600):
    return jp.make_policy_body(
        policy_name=name, version=version, writable_dirs=list(dirs),
        timeout_s=timeout_s, not_before=not_before, not_after=not_after)


def _envelope(body, seed):
    norm = jp.validate_policy_body(body)
    return {"body": norm, "signature": jp.sign_policy(seed, body)}


def _registry(body=None, seed=None, now=_NOW, features=_FULL_FEATURES):
    if seed is None:
        seed, pub = _issuer()
    else:
        pub = _ed.publickey(seed)
    reg = jp.JailPolicyRegistry(pub)
    if body is None:
        body = _body()
    reg.activate(_envelope(body, seed), now=now, features=features)
    return reg, seed, pub


def _req(dirs=("/output",), network=False, timeout_s=5):
    return {"writable_dirs": list(dirs), "wants_network": network,
            "timeout_s": timeout_s}


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------

@_probe("unsigned_policy_refused")
def p_unsigned():
    seed, pub = _issuer()
    reg = jp.JailPolicyRegistry(pub)
    body = _body()
    try:
        reg.activate({"body": jp.validate_policy_body(body),
                      "signature": b"\x00" * 64},
                     now=_NOW, features=_FULL_FEATURES)
    except jp.JailPolicyError as e:
        if e.code == "policy-signature-invalid":
            return "HELD", "unsigned policy refused"
        return "GAP", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "unsigned policy activated"


@_probe("self_signed_policy_refused")
def p_self_signed():
    rogue_seed, _rogue_pub = _issuer()
    _real_seed, real_pub = _issuer()
    reg = jp.JailPolicyRegistry(real_pub)
    body = _body()
    try:
        reg.activate(_envelope(body, rogue_seed), now=_NOW,
                     features=_FULL_FEATURES)
    except jp.JailPolicyError as e:
        if e.code == "policy-signature-invalid":
            return "HELD", "rogue-signed policy refused"
        return "GAP", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "self-signed policy activated against pinned issuer"


@_probe("unknown_policy_name_refused")
def p_unknown():
    seed, pub = _issuer()
    reg = jp.JailPolicyRegistry(pub)
    try:
        reg.check("tool-python", 1, _req(), now=_NOW)
    except jp.JailPolicyError as e:
        if e.code == "policy-unknown":
            return "HELD", "unknown policy refused"
        return "GAP", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "invocation checked against unknown policy"


@_probe("version_downgrade_refused")
def p_downgrade():
    seed, pub = _issuer()
    reg = jp.JailPolicyRegistry(pub)
    v2 = _body(version=2)
    reg.activate(_envelope(v2, seed), now=_NOW, features=_FULL_FEATURES)
    v1 = _body(version=1)
    try:
        reg.activate(_envelope(v1, seed), now=_NOW,
                     features=_FULL_FEATURES)
    except jp.JailPolicyError as e:
        if e.code == "policy-version-downgrade":
            return "HELD", "downgrade refused"
        return "GAP", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "older version activated over newer"


@_probe("stale_policy_refused")
def p_stale():
    seed, pub = _issuer()
    reg = jp.JailPolicyRegistry(pub)
    body = _body(not_after=_NOW - 1)
    try:
        reg.activate(_envelope(body, seed), now=_NOW,
                     features=_FULL_FEATURES)
    except jp.JailPolicyError as e:
        if e.code == "policy-stale":
            return "HELD", "stale-at-birth policy refused"
        return "GAP", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "expired policy activated"


@_probe("malformed_manifest_refused")
def p_malformed():
    body = _body()
    del body["timeout_s"]
    try:
        jp.validate_policy_body(body)
    except jp.JailPolicyError as e:
        if e.code != "policy-body-malformed":
            return "GAP", "refused but wrong code: %s" % (e.code,)
    else:
        return "BREAK", "missing field accepted"
    body2 = _body()
    body2["surprise"] = 1
    try:
        jp.validate_policy_body(body2)
    except jp.JailPolicyError as e:
        if e.code == "policy-body-malformed":
            return "HELD", "missing and unknown fields both refused"
        return "GAP", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "unknown field silently ignored"


@_probe("writable_dir_escape_refused")
def p_escape():
    reg, _seed, _pub = _registry()
    # traversal attempt: normpath collapses to /etc, outside the mounts
    try:
        reg.check("tool-python", 1, _req(dirs=("/output/../etc",)), now=_NOW)
    except jp.JailPolicyError as e:
        if e.code != "invocation-writable-dir-mismatch":
            return "GAP", "refused but wrong code: %s" % (e.code,)
    else:
        return "BREAK", "traversal escape accepted"
    try:
        reg.check("tool-python", 1, _req(dirs=("/etc",)), now=_NOW)
    except jp.JailPolicyError as e:
        if e.code != "invocation-writable-dir-mismatch":
            return "GAP", "refused but wrong code: %s" % (e.code,)
    else:
        return "BREAK", "undeclared writable dir accepted"
    # a subdirectory of the declared mount is honestly inside it
    rep = reg.check("tool-python", 1, _req(dirs=("/output/sub",)), now=_NOW)
    if rep.get("conforms") is True:
        return "HELD", "escape refused; subdir of declared mount conforms"
    return "GAP", "subdir refused: %r" % (rep,)


@_probe("network_request_under_none_refused")
def p_network():
    reg, _seed, _pub = _registry()
    try:
        reg.check("tool-python", 1, _req(network=True), now=_NOW)
    except jp.JailPolicyError as e:
        if e.code == "invocation-network-request-refused":
            return "HELD", "network request under none refused"
        return "GAP", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "network request granted under network:none"


@_probe("timeout_exceeds_policy_refused")
def p_timeout():
    reg, _seed, _pub = _registry()
    try:
        reg.check("tool-python", 1, _req(timeout_s=600), now=_NOW)
    except jp.JailPolicyError as e:
        if e.code != "invocation-timeout-exceeds-policy":
            return "GAP", "refused but wrong code: %s" % (e.code,)
    else:
        return "BREAK", "over-budget timeout accepted"
    rep = reg.check("tool-python", 1, _req(timeout_s=3), now=_NOW)
    if rep.get("conforms") is True:
        return "HELD", "over-budget refused; shorter timeout conforms"
    return "GAP", "shorter timeout refused: %r" % (rep,)


@_probe("backend_coverage_gap_refused")
def p_gap():
    seed, pub = _issuer()
    reg = jp.JailPolicyRegistry(pub)
    body = _body()
    # machine without seccomp: the policy needs it -> named gap
    try:
        reg.activate(_envelope(body, seed), now=_NOW,
                     features=_FULL_FEATURES - {"seccomp"})
    except jp.JailPolicyError as e:
        if e.code != "policy-needs-unimplemented-feature":
            return "GAP", "refused but wrong code: %s" % (e.code,)
        if "seccomp" not in e.detail:
            return "GAP", "gap not named: %s" % (e.detail,)
    else:
        return "BREAK", "policy activated despite missing seccomp"
    # a kvm platform is refused at authoring (closed vocabulary)
    kvm = _body()
    kvm["platform"] = "kvm"
    try:
        jp.validate_policy_body(kvm)
    except jp.JailPolicyError as e:
        if e.code == "policy-body-malformed":
            return "HELD", "gap named (seccomp); kvm refused at authoring"
        return "GAP", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "kvm platform accepted"


@_probe("nonempty_capabilities_refused")
def p_caps():
    body = _body()
    body["capabilities"] = ["CAP_SYS_ADMIN"]
    try:
        jp.validate_policy_body(body)
    except jp.JailPolicyError as e:
        if e.code == "policy-body-malformed":
            return "HELD", "non-empty capabilities refused"
        return "GAP", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "capabilities silently accepted"


@_probe("unknown_syscall_profile_refused")
def p_profile():
    body = _body()
    body["syscall_profile"] = "selinux-targeted"
    try:
        jp.validate_policy_body(body)
    except jp.JailPolicyError as e:
        if e.code == "policy-body-malformed":
            return "HELD", "unknown syscall profile refused"
        return "GAP", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "unknown syscall profile accepted"


@_probe("signature_rechecked_after_swap")
def p_swap():
    reg, _seed, _pub = _registry()
    key = ("tool-python", 1)
    stored_body, stored_sig = reg._active[key]
    stored_body["timeout_s"] = 3600  # post-activation edit
    try:
        reg.check("tool-python", 1, _req(), now=_NOW)
    except jp.JailPolicyError as e:
        if e.code == "policy-signature-invalid":
            return "HELD", "post-activation edit caught by re-check"
        return "GAP", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "edited policy passed signature re-check"


@_probe("audit_report_visible")
def p_report():
    reg, _seed, _pub = _registry()
    body = reg.get("tool-python", 1, now=_NOW)
    rep = reg.check("tool-python", 1, _req(), now=_NOW)
    if rep.get("conforms") is not True:
        return "GAP", "conforming request did not conform"
    if rep.get("policy_digest") != jp.policy_digest(body):
        return "GAP", "report does not carry the policy digest pin"
    if sorted(rep.get("checked", ())) == []:
        return "GAP", "report names no checks"
    return "HELD", "conformance report carries digest + check list"


@_probe("wiring_kwargs_tighten")
def p_wiring():
    reg, _seed, _pub = _registry()
    body = reg.get("tool-python", 1, now=_NOW)
    kw = jp.to_sandbox_kwargs(body, {"/output": "/var/tmp/g-out"})
    for flag in ("require_netns", "require_pidns", "require_pivot_root",
                 "require_privdrop", "require_seccomp"):
        if kw.get(flag) is not True:
            return "GAP", "fail-closed twin %s not on" % (flag,)
    if kw.get("cage_mode") != "strict" or kw.get("timeout") != 5:
        return "GAP", "kwargs mismatch: %r" % (kw,)
    if kw.get("memory_bytes") != 256 << 20 or kw.get("cpu_seconds") != 10:
        return "GAP", "resource limits not mapped: %r" % (kw,)
    try:
        jp.to_sandbox_kwargs(body, {})  # unwired mount
    except jp.JailPolicyError as e:
        if e.code == "wiring-unmapped-mount":
            return "HELD", "tighten-only kwargs; unwired mount refused"
        return "GAP", "refused but wrong code: %s" % (e.code,)
    return "BREAK", "unwired mount silently accepted"


@_probe("legacy_sandbox_behavior_unchanged")
def p_legacy():
    from gov import sandbox as sb
    import inspect
    sig = inspect.signature(sb.Sandbox.__init__)
    defaults = {k: v.default for k, v in sig.parameters.items()
                if v.default is not inspect.Parameter.empty}
    pinned = {"timeout": sb.DEFAULT_TIMEOUT, "use_netns": True,
              "use_pidns": True, "use_pivot_root": False,
              "drop_privs": False, "use_seccomp": False,
              "require_netns": False, "require_pidns": False,
              "require_pivot_root": False, "require_privdrop": False,
              "require_seccomp": False, "cage_mode": "strict"}
    for key, want in pinned.items():
        if defaults.get(key) != want:
            return "GAP", "Sandbox default %s drifted: %r" % (key,
                                                             defaults.get(key))
    return "HELD", "Sandbox() defaults byte-identical (opt-in only)"


def _green_check():
    # Depth-1 green check: the module's own unit tests stay green
    # alongside this battery (run with GOV_SKIP_GREEN=1 to prevent
    # combinatorial nesting).
    import subprocess
    path = os.path.join(REPO, "tests", "test_jail_policy.py")
    if not os.path.exists(path):
        _record("green:test_jail_policy", "HELD",
                "unit tests absent (lane not merged)")
        return
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    r = subprocess.run([sys.executable, "-m", "unittest",
                        "tests.test_jail_policy", "-v"],
                       capture_output=True, text=True, env=env,
                       cwd=REPO, timeout=600)
    ok = r.returncode == 0
    _record("green:test_jail_policy",
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
        verdict = _run_probe(name + ":determinism", _PROBE_FNS[name])
        got = verdict
        want = first[name]
        if got != want:
            _RESULTS[-1] = (name + ":determinism", "ERROR",
                            "nondeterministic: %s then %s" % (want, got))
    if not GREEN_SKIP:
        _green_check()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    gap = sum(1 for _, v, _ in _RESULTS if v == "GAP")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("w216 jail-policy: %d probes: %d HELD / %d GAP / %d BREAK / "
          "%d ERROR" % (len(_RESULTS), held, gap, brk, err))
    for name, verdict, detail in _RESULTS:
        print("  [%s] %s: %s" % (verdict, name, detail))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
