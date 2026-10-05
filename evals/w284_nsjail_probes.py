"""Wave-284 red-first battery: nsjail-pattern declarative sandbox policy.

Probes the policy-as-data layer stolen from google/nsjail (STEAL pattern,
Apache-2.0): declarative sandbox policy documents, a Kafel-derived syscall
grammar compiled to a deterministic decision function, pin-and-diff
use-time guarantees, fail-closed-by-construction (no DEFAULT -> refusal),
and host-validation of declared isolation requirements (the wave-176/177
EPERM lesson).

Red-first contract: every probe must BREAK on the pristine base (the
``gov/sandbox_policy.py`` module does not exist there) and HELD on the
lane tree. Deterministic A==B (staging vs clean env produce identical
verdicts).
"""

import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

TAXONOMY_PIN = 2131  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).


_PROBES = []


def probe(fn):
    _PROBES.append((fn.__name__, fn))
    return fn


def _break(detail):
    return ("BREAK", detail)


def _held(detail):
    return ("HELD", detail)


def _import():
    from gov import sandbox_policy as sp  # noqa: F401
    return sp


def needs_module(fn):
    """On the pristine base the module is absent: that is a BREAK
    (red-first contract), not a harness ERROR."""
    def wrapper():
        try:
            sp = _import()
        except ImportError:
            return _break("gov.sandbox_policy absent (red on pristine base)")
        return fn(sp)
    wrapper.__name__ = fn.__name__
    return wrapper


GOOD_POLICY = {
    "policy_schema_version": 1,
    "policy_id": "tool-default",
    "namespaces": {"net": True, "pid": True, "user": False},
    "rlimits": {"cpu_seconds": 60, "address_space_bytes": 1 << 30},
    "budgets": {"max_wall_seconds": 120, "max_output_bytes": 1 << 20},
    "mounts": {"readonly": ["/usr"], "writable": [], "masked": []},
    "syscalls": {
        "default": "kill",
        "allow": ["read", "write", "exit_group"],
        "deny": ["execve", "execveat"],
        "rules": [
            "POLICY mem { DEFAULT KILL "
            "ALLOW { mmap((prot & 4) == 0) } "
            "DENY { } }"
        ],
    },
}


@probe
def taxonomy_pin():
    from gov import decision_codes
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        return _break("taxonomy pin: expected %d, got %d"
                      % (TAXONOMY_PIN, len(decision_codes.TAXONOMY)))
    return _held("taxonomy pin holds at %d" % TAXONOMY_PIN)


@probe
@needs_module
def policy_compiles_and_decides(sp):
    pol = sp.compile_policy(dict(GOOD_POLICY))
    if pol.decide("read", {}) != "allow":
        return _break("allowed syscall did not decide allow")
    if pol.decide("execve", {}) != "kill":
        return _break("denied syscall did not decide kill")
    if pol.decide("open", {}) != "kill":
        return _break("unknown syscall did not hit DEFAULT KILL")
    return _held("compiled policy decides allow/deny/kill correctly")


@probe
@needs_module
def kafel_arg_filter_semantics(sp):
    pol = sp.compile_policy(dict(GOOD_POLICY))
    # PROT_EXEC == 4; mmap with prot=3 (RW, no X) is allowed ...
    if pol.decide("mmap", {"prot": 3}) != "allow":
        return _break("mmap(prot=3) should allow: (prot & 4) == 0 holds")
    # ... and prot=5 (R+X) is killed.
    if pol.decide("mmap", {"prot": 5}) != "kill":
        return _break("mmap(prot=5) should kill: (prot & 4) == 0 fails")
    # A missing argument fails the filter closed (never silently allows).
    if pol.decide("mmap", {}) != "kill":
        return _break("mmap with missing arg must fail closed to kill")
    return _held("Kafel-derived arg filters enforce (prot & PROT_EXEC) == 0")


@probe
@needs_module
def no_default_refused_at_compile(sp):
    bad = dict(GOOD_POLICY)
    bad_syscalls = dict(bad["syscalls"])
    del bad_syscalls["default"]
    bad["syscalls"] = bad_syscalls
    try:
        sp.compile_policy(bad)
    except sp.SandboxPolicyInvalid as exc:
        if exc.code == "sandbox-policy-no-default":
            return _held("policy without DEFAULT refused at compile")
        return _break("wrong code: %r" % (exc.code,))
    return _break("policy without DEFAULT compiled: not fail-closed")


@probe
@needs_module
def malformed_grammar_refused(sp):
    bad = dict(GOOD_POLICY)
    bad_syscalls = dict(bad["syscalls"])
    bad_syscalls["rules"] = ["POLICY broken { ALLOW { mmap((prot & } }"]
    bad["syscalls"] = bad_syscalls
    try:
        sp.compile_policy(bad)
    except sp.SandboxPolicyInvalid as exc:
        if exc.code == "sandbox-policy-invalid":
            return _held("malformed syscall rule refused at compile")
        return _break("wrong code: %r" % (exc.code,))
    return _break("malformed syscall rule compiled: not fail-closed")


@probe
@needs_module
def unknown_namespace_refused(sp):
    bad = dict(GOOD_POLICY)
    bad_namespaces = dict(bad["namespaces"])
    bad_namespaces["bogus_ns"] = True
    bad["namespaces"] = bad_namespaces
    try:
        sp.compile_policy(bad)
    except sp.SandboxPolicyInvalid as exc:
        if exc.code == "sandbox-policy-invalid":
            return _held("unknown namespace refused at compile")
        return _break("wrong code: %r" % (exc.code,))
    return _break("unknown namespace accepted: not fail-closed")


@probe
@needs_module
def unpinned_policy_refused_loud(sp):
    pol = sp.compile_policy(dict(GOOD_POLICY))
    try:
        sp.check_policy_use(pol, {})
    except sp.SandboxPolicyRefused as exc:
        if exc.code == "sandbox-policy-unpinned":
            return _held("unpinned policy refused loud at use")
        return _break("wrong code: %r" % (exc.code,))
    return _break("unpinned policy passed check_policy_use")


@probe
@needs_module
def drifted_policy_refused_loud(sp):
    # Both drift directions must refuse; run both halves so the
    # subset half is not shadowed by an early return.
    pol = sp.compile_policy(dict(GOOD_POLICY))
    pins = {pol.policy_id: pol.digest}
    for label, new_allow in (
        ("superset", ["read", "write", "exit_group", "open"]),
        ("subset", ["read", "write"]),
    ):
        drifted = dict(GOOD_POLICY)
        drifted_syscalls = dict(drifted["syscalls"])
        drifted_syscalls["allow"] = new_allow
        drifted["syscalls"] = drifted_syscalls
        drifted_pol = sp.compile_policy(drifted)
        try:
            sp.check_policy_use(drifted_pol, pins)
        except sp.SandboxPolicyRefused as exc:
            if exc.code != "sandbox-policy-drift":
                return _break("%s drift: wrong code %r" % (label, exc.code))
        else:
            return _break("%s drift passed check_policy_use" % (label,))
    return _held("superset and subset drifts both refused loud at use")


@probe
@needs_module
def policy_diff_names_changes(sp):
    a = sp.compile_policy(dict(GOOD_POLICY))
    b_doc = dict(GOOD_POLICY)
    b_ns = dict(b_doc["namespaces"])
    b_ns["net"] = False
    b_doc["namespaces"] = b_ns
    b = sp.compile_policy(b_doc)
    diff = sp.policy_diff(a, b)
    if "namespaces.net" not in diff:
        return _break("policy_diff missed the namespaces.net change: %r"
                      % (diff,))
    return _held("policy_diff names the changed field path")


@probe
@needs_module
def host_mismatch_refused(sp):
    pol = sp.compile_policy(dict(GOOD_POLICY))
    pins = {pol.policy_id: pol.digest}
    # The policy requires net+pid isolation, but the host (this test env)
    # enforces neither: binding must refuse rather than run degraded.
    try:
        sp.bind(pol, pins, enforced_namespaces=set())
    except sp.SandboxPolicyRefused as exc:
        if exc.code == "sandbox-policy-host-mismatch":
            return _held("undeclared-under-enforcement binding refused")
        return _break("wrong code: %r" % (exc.code,))
    return _break("bind passed with zero enforced namespaces")


@probe
@needs_module
def kill_decisions_are_audited(sp):
    pol = sp.compile_policy(dict(GOOD_POLICY))
    pins = {pol.policy_id: pol.digest}
    binding = sp.bind(pol, pins, enforced_namespaces={"net", "pid"})
    seen = []
    sp.set_emit(seen.append)
    try:
        decision = binding.decide("execve", {})
    finally:
        sp.set_emit(None)
    if decision != "kill":
        return _break("binding.decide did not kill execve")
    if len(seen) != 1:
        return _break("expected exactly one audit event, got %d" % len(seen))
    event = seen[0]
    if event.get("policy_digest") != pol.digest:
        return _break("audit event carries the wrong policy digest")
    if event.get("decision") != "kill":
        return _break("audit event carries the wrong decision")
    if "syscall" not in event:
        return _break("audit event names no syscall")
    return _held("kill decisions emit digest-bound audit events")


@probe
@needs_module
def default_allow_policy_compiles(sp):
    doc = dict(GOOD_POLICY)
    doc_syscalls = dict(doc["syscalls"])
    doc_syscalls["default"] = "allow"
    doc_syscalls["rules"] = [
        "POLICY mem { DEFAULT ALLOW "
        "ALLOW { mmap((prot & 4) == 0) } "
        "DENY { execve } }"
    ]
    doc["syscalls"] = doc_syscalls
    pol = sp.compile_policy(doc)
    if pol.decide("some_random_syscall", {}) != "allow":
        return _break("DEFAULT ALLOW did not allow an unknown syscall")
    if pol.decide("execve", {}) != "kill":
        return _break("explicit DENY must still kill under DEFAULT ALLOW")
    return _held("DEFAULT ALLOW is honored; explicit deny still kills")


@probe
@needs_module
def digest_stable_across_key_order(sp):
    a = sp.compile_policy(dict(GOOD_POLICY))
    shuffled = {
        "syscalls": dict(GOOD_POLICY["syscalls"]),
        "policy_id": "tool-default",
        "mounts": dict(GOOD_POLICY["mounts"]),
        "budgets": dict(GOOD_POLICY["budgets"]),
        "rlimits": dict(GOOD_POLICY["rlimits"]),
        "namespaces": dict(GOOD_POLICY["namespaces"]),
        "policy_schema_version": 1,
    }
    b = sp.compile_policy(shuffled)
    if a.digest != b.digest:
        return _break("policy digest is not key-order stable")
    return _held("policy digest is canonical (key-order stable)")


@probe
@needs_module
def in_block_garbage_refused_loud(sp):
    # ALLOW{read} (no space), FOOBAR sections, and nested POLICY
    # blocks must refuse LOUD -- a policy that silently differs from
    # what a reviewer read is not a reviewable policy.
    bad_rules = [
        "POLICY x { DEFAULT KILL ALLOW{read} DENY { } }",
        "POLICY x { DEFAULT KILL FOOBAR { nonsense } }",
        "POLICY outer { DEFAULT ALLOW POLICY inner { DEFAULT KILL } }",
    ]
    for rules in bad_rules:
        doc = dict(GOOD_POLICY)
        doc_syscalls = dict(doc["syscalls"])
        doc_syscalls["rules"] = [rules]
        doc["syscalls"] = doc_syscalls
        try:
            sp.compile_policy(doc)
        except sp.SandboxPolicyInvalid as exc:
            if exc.code != "sandbox-policy-invalid":
                return _break("wrong code %r for %r" % (exc.code, rules))
            continue
        return _break("in-block garbage compiled silently: %r" % (rules,))
    return _held("in-block garbage refuses LOUD at compile")


@probe
def depth_one_green_check():
    if os.environ.get("GOV_SKIP_GREEN"):
        return _held("green check skipped (GOV_SKIP_GREEN=1)")
    root = os.path.join(os.path.dirname(__file__), "..")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmp = tempfile.mkdtemp(prefix="g284-")
    proc = subprocess.run(
        [sys.executable, os.path.join(root, "evals", "w282_redteam_probes.py")],
        cwd=root, env=dict(env, TMPDIR=tmp),
        capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        return _break("adjacent w282_redteam battery red: %s"
                      % (proc.stderr[-500:],))
    return _held("adjacent w282_redteam battery green")


def main():
    from gov import decision_codes  # noqa: F401  (pin probe imports it too)
    held = broken = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001 -- probe harness
            verdict, detail = ("ERROR", "%r" % (exc,))
        print("%-32s %s  %s" % (name, verdict, detail))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            broken += 1
        else:
            errors += 1
    print("w284_nsjail: %d BREAK / %d HELD / %d ERROR" % (broken, held, errors))
    sys.exit(0 if errors == 0 else 2)


if __name__ == "__main__":
    main()
