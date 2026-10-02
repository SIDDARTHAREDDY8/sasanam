"""Break-first battery: Landlock least-privilege filesystem tier (wave-266).

Probes the Landlock tier ADAPTED from the wave-265 NVIDIA OpenShell
teardown (prospectus §3.4: OpenShell enforces with the Landlock LSM;
``grep -ci landlock gov/sandbox.py`` was 0 — a concrete enforcement
gap). Pattern only, no vendored code; stdlib only.

Modes: ``GOV_LANDLOCK_UNDER_TEST=stub`` runs the probes against a plain
``Sandbox`` with every auto layer pinned OFF (red phase: attacks MUST
break — the tier does not exist). Default (module) runs them against
``Sandbox(use_landlock=True, require_landlock=True)`` with the same
pinned-off composition (green phase: attacks MUST be held). Pinning the
other layers off in BOTH modes isolates the verdict delta to the
Landlock tier alone; one extra probe checks the default auto-layer
composition still runs with the tier on.

When the kernel cannot enforce Landlock (``landlock_available()`` is
False), the attack probes report BASELINE (nothing to falsify) and the
fail-closed wiring probes take over instead.

Probes inapplicable to the mode report BASELINE (no claim either way).

Depth-1 green check honoring ``GOV_SKIP_GREEN``; no in-repo git
subprocesses; stdlib only.
"""

import errno
import inspect
import json
import os
import shutil
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

MODE = os.environ.get("GOV_LANDLOCK_UNDER_TEST", "module")

from gov import decision_codes  # noqa: E402
from gov import sandbox as sandbox_mod  # noqa: E402

HAVE_TIER = "use_landlock" in inspect.signature(
    sandbox_mod.Sandbox.__init__).parameters

TAXONOMY_PIN = 1723  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*)

EXPECTED_LANDLOCK_CODES = (
    "sandbox-landlock-unavailable",
    "sandbox-landlock-required",
    "sandbox-landlock-apply-failed",
)

# Composition pinned for falsification: every other layer is OFF in both
# modes, so a HELD/BREAK delta is attributable to the Landlock tier alone.
_PINNED_OFF = dict(use_netns=False, use_pidns=False, use_pivot_root=False,
                   drop_privs=False, use_seccomp=False)


def _sandbox():
    if MODE == "module" and HAVE_TIER:
        return sandbox_mod.Sandbox(use_landlock=True, require_landlock=True,
                                   **_PINNED_OFF)
    return sandbox_mod.Sandbox(**_PINNED_OFF)


def _jaildir(root):
    d = os.path.join(root, "jail")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "planted.txt"), "w") as fh:
        fh.write("planted-by-battery")
    return d


def _run_child(sb, code, cwd):
    """Run a snippet; return (result, payload-dict-or-None)."""
    result = sb.run_python(code, cwd=cwd)
    payload = None
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                payload = json.loads(line)
            except ValueError:
                pass
    return result, payload


def _verdict(name, ok, held_detail, broke_detail, error_detail=None):
    if ok is True:
        return {"name": name, "result": "HELD", "detail": held_detail}
    if ok is False:
        return {"name": name, "result": "BREAK", "detail": broke_detail}
    return {"name": name, "result": "ERROR",
            "detail": error_detail or "indeterminate"}


# Attack probes: in stub (red) mode these MUST break. A HELD verdict here
# means the red phase is masked (the attack failed for reasons unrelated to
# the tier) and main() fails the run instead of passing green silently.
_ATTACK_PROBES = frozenset({
    "p_secret_outside_unreadable",
    "p_write_outside_jail_denied",
    "p_jail_root_readonly",
    "p_ambient_home_unlistable",
})


def p_secret_outside_unreadable(ctx):
    """Attack: read a secret file planted OUTSIDE the jail."""
    if not ctx["available"] and MODE == "module":
        return {"name": "p_secret_outside_unreadable", "result": "BASELINE",
                "detail": "landlock unavailable on this kernel"}
    sb = _sandbox()
    code = (
        "import json\n"
        "secret = %r\n"
        "out = {}\n"
        "try:\n"
        "    out['data'] = open(secret).read()\n"
        "    out['leaked'] = True\n"
        "except OSError as e:\n"
        "    out['leaked'] = False\n"
        "    out['errno'] = e.errno\n"
        "print(json.dumps(out))\n" % ctx["secret_path"])
    _, payload = _run_child(sb, code, ctx["jail"])
    if payload is None:
        return {"name": "p_secret_outside_unreadable", "result": "ERROR",
                "detail": "child produced no payload"}
    if MODE == "stub":
        # Red phase: the attack MUST succeed without the tier.
        return _verdict(
            "p_secret_outside_unreadable", payload.get("leaked") is False,
            "UNEXPECTED: read failed without the tier (masking?)",
            "attack broke as expected (secret read: %r)"
            % (payload.get("data"),))
    held = payload.get("leaked") is False and payload.get("errno") == errno.EACCES
    return _verdict(
        "p_secret_outside_unreadable", held,
        "secret read denied with EACCES",
        "secret LEAKED despite require_landlock: %r" % (payload,))


def p_write_outside_jail_denied(ctx):
    """Attack: write a file OUTSIDE the jail via an absolute path."""
    if not ctx["available"] and MODE == "module":
        return {"name": "p_write_outside_jail_denied", "result": "BASELINE",
                "detail": "landlock unavailable on this kernel"}
    sb = _sandbox()
    evil = os.path.join(ctx["root"], "evil.txt")
    code = (
        "import json\n"
        "out = {}\n"
        "try:\n"
        "    open(%r, 'w').write('pwned')\n"
        "    out['wrote'] = True\n"
        "except OSError as e:\n"
        "    out['wrote'] = False\n"
        "    out['errno'] = e.errno\n"
        "print(json.dumps(out))\n" % evil)
    _, payload = _run_child(sb, code, ctx["jail"])
    if os.path.exists(evil):
        os.unlink(evil)
    if payload is None:
        return {"name": "p_write_outside_jail_denied", "result": "ERROR",
                "detail": "child produced no payload"}
    if MODE == "stub":
        return _verdict(
            "p_write_outside_jail_denied", payload.get("wrote") is False,
            "UNEXPECTED: write failed without the tier (masking?)",
            "attack broke as expected (outside file written)")
    held = payload.get("wrote") is False and payload.get("errno") == errno.EACCES
    return _verdict(
        "p_write_outside_jail_denied", held,
        "outside write denied with EACCES",
        "outside write SUCCEEDED despite require_landlock: %r" % (payload,))


def p_jail_root_readonly(ctx):
    """Attack: write into the jail ROOT (read-only by design)."""
    if not ctx["available"] and MODE == "module":
        return {"name": "p_jail_root_readonly", "result": "BASELINE",
                "detail": "landlock unavailable on this kernel"}
    sb = _sandbox()
    code = (
        "import json, os\n"
        "out = {}\n"
        "try:\n"
        "    open(os.path.join(os.getcwd(), 'evil.txt'), 'w').write('x')\n"
        "    out['wrote'] = True\n"
        "except OSError as e:\n"
        "    out['wrote'] = False\n"
        "    out['errno'] = e.errno\n"
        "print(json.dumps(out))\n")
    _, payload = _run_child(sb, code, ctx["jail"])
    planted_evil = os.path.join(ctx["jail"], "evil.txt")
    if os.path.exists(planted_evil):
        os.unlink(planted_evil)
    if payload is None:
        return {"name": "p_jail_root_readonly", "result": "ERROR",
                "detail": "child produced no payload"}
    if MODE == "stub":
        return _verdict(
            "p_jail_root_readonly", payload.get("wrote") is False,
            "UNEXPECTED: jail-root write failed without the tier",
            "attack broke as expected (jail root writable)")
    held = payload.get("wrote") is False and payload.get("errno") == errno.EACCES
    return _verdict(
        "p_jail_root_readonly", held,
        "jail-root write denied with EACCES",
        "jail-root write SUCCEEDED despite require_landlock: %r"
        % (payload,))


def p_ambient_home_unlistable(ctx):
    """Attack: list an ambient directory (/home) outside the allowlist."""
    if not ctx["available"] and MODE == "module":
        return {"name": "p_ambient_home_unlistable", "result": "BASELINE",
                "detail": "landlock unavailable on this kernel"}
    sb = _sandbox()
    code = (
        "import json\n"
        "out = {}\n"
        "try:\n"
        "    out['entries'] = __import__('os').listdir('/home')\n"
        "    out['listed'] = True\n"
        "except OSError as e:\n"
        "    out['listed'] = False\n"
        "    out['errno'] = e.errno\n"
        "print(json.dumps(out))\n")
    _, payload = _run_child(sb, code, ctx["jail"])
    if payload is None:
        return {"name": "p_ambient_home_unlistable", "result": "ERROR",
                "detail": "child produced no payload"}
    if MODE == "stub":
        return _verdict(
            "p_ambient_home_unlistable", payload.get("listed") is False,
            "UNEXPECTED: /home unlistable without the tier (masking?)",
            "attack broke as expected (/home listed: %r)"
            % (payload.get("entries"),))
    held = payload.get("listed") is False and payload.get("errno") == errno.EACCES
    return _verdict(
        "p_ambient_home_unlistable", held,
        "/home listing denied with EACCES",
        "/home LISTED despite require_landlock: %r" % (payload,))


def p_scratch_writable(ctx):
    """Control: the designated scratch subdir is read-write for the tool."""
    if MODE == "stub" or not HAVE_TIER:
        return {"name": "p_scratch_writable", "result": "BASELINE",
                "detail": "no scratch tier without the module"}
    if not ctx["available"]:
        return {"name": "p_scratch_writable", "result": "BASELINE",
                "detail": "landlock unavailable on this kernel"}
    sb = _sandbox()
    code = (
        "import json, os\n"
        "s = os.environ.get('GOV_SANDBOX_SCRATCH')\n"
        "out = {'scratch': s}\n"
        "try:\n"
        "    p = os.path.join(s, 'out.txt')\n"
        "    open(p, 'w').write('hello')\n"
        "    out['roundtrip'] = open(p).read() == 'hello'\n"
        "except OSError as e:\n"
        "    out['roundtrip'] = False\n"
        "    out['errno'] = e.errno\n"
        "print(json.dumps(out))\n")
    _, payload = _run_child(sb, code, ctx["jail"])
    ok = bool(payload) and payload.get("roundtrip") is True
    return _verdict(
        "p_scratch_writable", ok,
        "scratch roundtrip ok (%r)" % (payload.get("scratch"),),
        "scratch NOT writable: %r" % (payload,))


def p_jail_file_readable(ctx):
    """Control: files the parent staged in the jail stay readable."""
    sb = _sandbox()
    code = (
        "import json, os\n"
        "out = {}\n"
        "try:\n"
        "    out['data'] = open(os.path.join(os.getcwd(), 'planted.txt')).read()\n"
        "    out['read'] = True\n"
        "except OSError as e:\n"
        "    out['read'] = False\n"
        "    out['errno'] = e.errno\n"
        "print(json.dumps(out))\n")
    _, payload = _run_child(sb, code, ctx["jail"])
    ok = bool(payload) and payload.get("data") == "planted-by-battery"
    return _verdict(
        "p_jail_file_readable", ok,
        "staged jail file readable",
        "staged jail file NOT readable: %r" % (payload,))


def p_interpreter_runs(ctx):
    """Control: the interpreter still starts under the tier."""
    sb = _sandbox()
    result = sb.run_python("print('w266-ok')", cwd=ctx["jail"])
    ok = "w266-ok" in (result.stdout or "")
    return _verdict(
        "p_interpreter_runs", ok,
        "interpreter runs under the tier",
        "interpreter failed: rc=%s stderr=%r"
        % (result.returncode, (result.stderr or "")[-300:]))


def p_default_composition_runs(ctx):
    """Control: default auto-layer composition + landlock still runs."""
    if MODE == "stub" or not HAVE_TIER:
        return {"name": "p_default_composition_runs", "result": "BASELINE",
                "detail": "no tier in stub mode"}
    sb = sandbox_mod.Sandbox(use_landlock=True)
    result = sb.run_python("print('w266-compo-ok')", cwd=ctx["jail"])
    ok = "w266-compo-ok" in (result.stdout or "")
    return _verdict(
        "p_default_composition_runs", ok,
        "default composition runs with landlock on",
        "default composition failed: rc=%s stderr=%r"
        % (result.returncode, (result.stderr or "")[-300:]))


def p_landlock_ground_truth(ctx):
    """Ground truth: landlock_active matches the mode."""
    if not HAVE_TIER:
        return {"name": "p_landlock_ground_truth", "result": "BASELINE",
                "detail": "tier not implemented yet"}
    sb = _sandbox()
    result = sb.run_python("print('x')", cwd=ctx["jail"])
    if MODE == "stub":
        ok = result.landlock_active is False
        return _verdict(
            "p_landlock_ground_truth", ok,
            "stub reports landlock_active=False (honest)",
            "stub reports landlock_active=True: %r" % (result,))
    if not ctx["available"]:
        return {"name": "p_landlock_ground_truth", "result": "BASELINE",
                "detail": "landlock unavailable on this kernel"}
    ok = result.landlock_active is True
    return _verdict(
        "p_landlock_ground_truth", ok,
        "module reports landlock_active=True",
        "module reports landlock_active=%r" % (result.landlock_active,))


def p_require_refuses_when_unavailable(ctx):
    """Fail-closed wiring: required tier + unavailable kernel -> refusal."""
    if not HAVE_TIER:
        return {"name": "p_require_refuses_when_unavailable",
                "result": "BASELINE", "detail": "tier not implemented yet"}
    if ctx["available"]:
        return {"name": "p_require_refuses_when_unavailable",
                "result": "BASELINE",
                "detail": "kernel supports landlock; wiring covered by unit test"}
    sb = sandbox_mod.Sandbox(use_landlock=True, require_landlock=True,
                             **_PINNED_OFF)
    import contextlib as _contextlib
    import io as _io
    buf = _io.StringIO()
    try:
        with _contextlib.redirect_stderr(buf):
            sb.run_python("print('x')", cwd=ctx["jail"])
    except sandbox_mod.SandboxError:
        # The machine code rides the loud stderr refusal record
        # (_refuse_loud convention: [kind] in the stderr line).
        ok = "[sandbox-landlock-required]" in buf.getvalue()
        return _verdict(
            "p_require_refuses_when_unavailable", ok,
            "refused with [sandbox-landlock-required]",
            "refused but without the machine code: %r" % (buf.getvalue(),))
    return {"name": "p_require_refuses_when_unavailable", "result": "BREAK",
            "detail": "required tier unavailable yet the tool RAN"}


def p_unavailable_warns_without_require(ctx):
    """Graceful wiring: tier requested but not required + unavailable kernel.

    Runs with the remaining limits and records the machine-coded warning.
    """
    if not HAVE_TIER:
        return {"name": "p_unavailable_warns_without_require",
                "result": "BASELINE", "detail": "tier not implemented yet"}
    if ctx["available"]:
        return {"name": "p_unavailable_warns_without_require",
                "result": "BASELINE",
                "detail": "kernel supports landlock; wiring covered by unit test"}
    sb = sandbox_mod.Sandbox(use_landlock=True, **_PINNED_OFF)
    result = sb.run_python("print('w266-degraded-ok')", cwd=ctx["jail"])
    ok = ("w266-degraded-ok" in (result.stdout or "")
          and result.landlock_active is False
          and "sandbox-landlock-unavailable" in (result.note or ""))
    return _verdict(
        "p_unavailable_warns_without_require", ok,
        "ran degraded with machine-coded warning",
        "degraded run misbehaved: %r" % (result,))


def p_taxonomy_pin(ctx):
    """The three landlock decision codes exist and the pin moved +3."""
    import re as _re
    codes = decision_codes.TAXONOMY
    missing = [c for c in EXPECTED_LANDLOCK_CODES if c not in codes]
    src = open(os.path.join(REPO_ROOT, "gov", "decision_codes.py")).read()
    lits = [a or b for a, b in
            _re.findall(r'"code": \'([^\']+)\'|"code": "([^"]+)"', src)]
    dupes = [c for c in EXPECTED_LANDLOCK_CODES if lits.count(c) != 1]
    ok = (len(codes) == TAXONOMY_PIN and not missing and not dupes)
    return _verdict(
        "p_taxonomy_pin", ok,
        "len(TAXONOMY)=%d and all %d landlock codes present exactly once"
        % (TAXONOMY_PIN, len(EXPECTED_LANDLOCK_CODES)),
        "len(TAXONOMY)=%d (pin %d) missing=%r dupes=%r"
        % (len(codes), TAXONOMY_PIN, missing, dupes))


def p_deterministic(ctx):
    """The falsifying probes decide the same way twice."""
    first = (p_secret_outside_unreadable(ctx)["result"],
             p_write_outside_jail_denied(ctx)["result"])
    second = (p_secret_outside_unreadable(ctx)["result"],
              p_write_outside_jail_denied(ctx)["result"])
    ok = first == second
    return _verdict(
        "p_deterministic", ok,
        "repeat run identical: %r" % (first,),
        "nondeterministic: %r vs %r" % (first, second))


PROBES = (
    p_secret_outside_unreadable,
    p_write_outside_jail_denied,
    p_jail_root_readonly,
    p_ambient_home_unlistable,
    p_scratch_writable,
    p_jail_file_readable,
    p_interpreter_runs,
    p_default_composition_runs,
    p_landlock_ground_truth,
    p_require_refuses_when_unavailable,
    p_unavailable_warns_without_require,
    p_taxonomy_pin,
    p_deterministic,
)


def green_check():
    """Depth-1 green check: the adjacent sandbox battery + unit suite."""
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN"):
        print("green_check: skipped (GOV_SKIP_GREEN set)")
        return True
    ok = True
    targets = [
        ("w35_sandbox_probes.py",
         [sys.executable,
          os.path.join(REPO_ROOT, "evals", "w35_sandbox_probes.py")]),
        ("tests.test_sandbox",
         [sys.executable, "-m", "unittest", "tests.test_sandbox"]),
    ]
    for label, cmd in targets:
        if not os.path.exists(cmd[-1]) and cmd[1] != "-m":
            print("green_check: missing %s (skip)" % label)
            continue
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600, env=env,
            cwd=REPO_ROOT)
        print("green_check: %s exit=%d" % (label, proc.returncode))
        if proc.returncode != 0:
            ok = False
            print(proc.stdout[-2000:])
            print(proc.stderr[-2000:])
    return ok


def main():
    root = tempfile.mkdtemp(prefix="w266ll_", dir="/var/tmp")
    ctx = {
        "root": root,
        "jail": _jaildir(root),
        "available": getattr(sandbox_mod, "landlock_available",
                             lambda: False)(),
        "secret_path": None,
    }
    secret_path = os.path.join(root, "secret.txt")
    with open(secret_path, "w") as fh:
        fh.write("TOP-SECRET-BATTERY-VALUE")
    os.chmod(secret_path, 0o600)
    ctx["secret_path"] = secret_path
    print("mode=%s deployment=%s have_tier=%s landlock_available=%s" % (
        MODE, os.environ.get("GOV_DEPLOYMENT_MODE", "(unset)"),
        HAVE_TIER, ctx["available"]))
    results = []
    try:
        for probe in PROBES:
            try:
                results.append(probe(ctx))
            except Exception as exc:  # never let a probe crash the battery
                results.append({"name": probe.__name__, "result": "ERROR",
                                "detail": "probe crashed: %r" % (exc,)})
    finally:
        shutil.rmtree(root, ignore_errors=True)
    held = [r for r in results if r["result"] == "HELD"]
    broke = [r for r in results if r["result"] == "BREAK"]
    baseline = [r for r in results if r["result"] == "BASELINE"]
    errors = [r for r in results if r["result"] == "ERROR"]
    for r in results:
        print("%-36s %-8s %s" % (r["name"], r["result"], r["detail"]))
    print("HELD %d / BREAK %d / BASELINE %d / ERROR %d"
          % (len(held), len(broke), len(baseline), len(errors)))
    if MODE == "stub":
        # Red phase: the four attack probes must BREAK. An attack that is
        # HELD without the tier is masked, not a pass.
        masked = [r["name"] for r in results
                  if r["name"] in _ATTACK_PROBES and r["result"] != "BREAK"]
        if masked:
            print("RED PHASE MASKED (stub): attacks held without the tier: %s"
                  % ", ".join(sorted(masked)))
            return 1
    if not green_check():
        print("GREEN CHECK FAILED")
        return 2
    if broke or errors:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
