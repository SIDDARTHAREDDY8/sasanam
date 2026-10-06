"""Break-first battery: standalone Landlock jail API (wave-331 lane 3).

The Landlock tier itself landed in wave-266 inside gov/sandbox.py; wave-331
lane 3 moved it verbatim to gov/landlock_jail.py and added the standalone
API the w330 prospectus asked for: landlock_supported() and
restrict_fs(read_paths, write_paths, *, exec_paths=()) -- confining the
CURRENT process to caller-declared paths (the sandbox tier only offers the
fixed jail_root+scratch+system policy per tool call).

Red-first: every probe below was written against the refusal/enforcement
contract first. The S-group (static/refusal) probes fail on a stub that
silently allows; the E-group (enforcement) probes fork a child, confine
it, and check EACCES -- they run only when landlock_supported() is True
and report BASELINE otherwise (never a faked pass).

Probes inapplicable to the mode report BASELINE (no claim either way).

Depth-1 green check honoring GOV_SKIP_GREEN; no in-repo git
subprocesses; stdlib only.
"""

import errno
import os
import re
import shutil
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import landlock_jail as lj  # noqa: E402

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
FOOTER_OPEN = "F496, F497, F498, F499, F500, F501, F502"  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # F426-F427 CLOSED (wave-340 lane 1); F428 OPEN (wave-341 lane C).; F442 CLOSED 2026-10-05 wave-347 lane 6; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN


FOOTER_NEXT = "F503"  # Next free finding number.; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: next F480  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: next F496



PROBES = []


def probe(name):
    def deco(fn):
        PROBES.append((name, fn))
        return fn
    return deco


def _held(name, detail):
    return {"name": name, "result": "HELD", "detail": detail}


def _break(name, detail):
    return {"name": name, "result": "BREAK", "detail": detail}


def _baseline(name, detail):
    return {"name": name, "result": "BASELINE", "detail": detail}


def _error(name, detail):
    return {"name": name, "result": "ERROR", "detail": detail}


def _expect_landlock_error(name, code, fn, *args, **kwargs):
    """fn must raise LandlockError with the given coded refusal."""
    try:
        fn(*args, **kwargs)
    except lj.LandlockError as exc:
        if exc.code == code:
            return _held(name, "refused coded %s" % (code,))
        return _break(name, "wrong code %r, want %r" % (exc.code, code))
    except Exception as exc:  # noqa: BLE001
        return _error(name, "wrong exception type: %r" % (exc,))
    return _break(name, "no refusal -- silently allowed")


def _fork_confined_child(grant_fn):
    """Fork; child applies grants via restrict_fs then runs checks.

    grant_fn() runs in the child and must call lj.restrict_fs. Returns
    the child's exit code and its stderr text. The parent is never
    confined.
    """
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:  # child
        os.close(r)
        try:
            grant_fn()
        except lj.LandlockError as exc:
            os.write(w, ("GRANT-REFUSED %s\n" % (exc.code,)).encode())
            os._exit(10)
        except BaseException as exc:  # noqa: BLE001
            os.write(w, ("GRANT-ERR %r\n" % (exc,)).encode())
            os._exit(11)
        os.close(w)
        os._exit(0)
    os.close(w)
    out = b""
    while True:
        chunk = os.read(r, 4096)
        if not chunk:
            break
        out += chunk
    os.close(r)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), out.decode("utf-8",
                                                         "replace")


# ---------------------------------------------------------------------------
# S-group: static/refusal probes (no confinement needed).
# ---------------------------------------------------------------------------

@probe("S1-supported-probe-backed")
def _s1():
    name = "S1-supported-probe-backed"
    # landlock_supported() must agree with the empirical enforcement
    # probe, not just the ABI number: monkeypatch the enforcement probe
    # to fail and the answer must flip to False.
    if not lj.landlock_supported():
        return _baseline(name, "Landlock not enforceable on this kernel; "
                               "refusal probes take over")
    real = lj._landlock_enforcement_probe
    lj._landlock_enforcement_probe = lambda: False
    lj._LANDLOCK_AVAILABLE_CACHE["available"] = None
    try:
        if lj.landlock_supported() is False:
            return _held(name, "LSM-disabled silent bypass detected: "
                               "supported() is False when enforcement fails")
        return _break(name, "supported() True despite failed enforcement "
                            "probe -- silent bypass")
    finally:
        lj._landlock_enforcement_probe = real
        lj._LANDLOCK_AVAILABLE_CACHE["available"] = None


@probe("S2-unsupported-kernel-refuses-coded")
def _s2():
    name = "S2-unsupported-kernel-refuses-coded"
    real_avail = lj._LANDLOCK_AVAILABLE_CACHE["available"]
    real_abi = lj._LANDLOCK_ABI_CACHE["version"]
    lj._LANDLOCK_AVAILABLE_CACHE["available"] = False
    lj._LANDLOCK_ABI_CACHE["version"] = 0
    try:
        return _expect_landlock_error(
            name, "sandbox-landlock-unavailable",
            lj.restrict_fs, ["/tmp"], [])
    finally:
        lj._LANDLOCK_AVAILABLE_CACHE["available"] = real_avail
        lj._LANDLOCK_ABI_CACHE["version"] = real_abi


@probe("S3-relative-path-refused")
def _s3():
    return _expect_landlock_error(
        "S3-relative-path-refused", "sandbox-landlock-apply-failed",
        lj.restrict_fs, ["relative/path"], [])


@probe("S4-missing-path-refused")
def _s4():
    return _expect_landlock_error(
        "S4-missing-path-refused", "sandbox-landlock-apply-failed",
        lj.restrict_fs, ["/no/such/path/xyz-331"], [])


@probe("S5-ambiguous-overlap-refused")
def _s5():
    name = "S5-ambiguous-overlap-refused"
    if not lj.landlock_supported():
        return _baseline(name, "needs an enforcing kernel")
    with tempfile.TemporaryDirectory() as tmp:
        return _expect_landlock_error(
            name, "sandbox-landlock-apply-failed",
            lj.restrict_fs, [tmp], [tmp])


@probe("S6-non-sequence-refused")
def _s6():
    return _expect_landlock_error(
        "S6-non-sequence-refused", "sandbox-landlock-apply-failed",
        lj.restrict_fs, "/tmp", [])


@probe("S7-error-carries-code")
def _s7():
    name = "S7-error-carries-code"
    try:
        lj.restrict_fs(["relative"], [])
    except lj.LandlockError as exc:
        if exc.code and "sandbox-landlock-" in exc.code \
                and isinstance(exc, OSError):
            return _held(name, "coded OSError: %s" % (exc.code,))
        return _break(name, "error not coded: %r" % (exc,))
    except Exception as exc:  # noqa: BLE001
        return _error(name, "wrong exception: %r" % (exc,))
    return _break(name, "no refusal")


# ---------------------------------------------------------------------------
# E-group: enforcement probes (forked child confined; parent unaffected).
# ---------------------------------------------------------------------------

def _needs_kernel(name):
    if not lj.landlock_supported():
        return _baseline(name, "Landlock not enforceable on this kernel")
    return None


@probe("E1-read-write-split-enforced")
def _e1():
    name = "E1-read-write-split-enforced"
    base = _needs_kernel(name)
    if base:
        return base
    with tempfile.TemporaryDirectory() as tmp:
        ro = os.path.join(tmp, "ro")
        rw = os.path.join(tmp, "rw")
        os.makedirs(ro)
        os.makedirs(rw)
        with open(os.path.join(ro, "secret.txt"), "w") as fh:
            fh.write("s3cret")

        def grant():
            lj.restrict_fs([ro], [rw])

        # Confine this probe's child for the actual checks.
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            try:
                lj.restrict_fs([ro], [rw])
                checks = []
                # read inside ro: allowed
                checks.append(("read-ro",
                               open(os.path.join(ro, "secret.txt")).read()
                               == "s3cret"))
                # write inside ro: EACCES
                try:
                    open(os.path.join(ro, "w.txt"), "w")
                    checks.append(("write-ro", False))
                except OSError as e:
                    checks.append(("write-ro", e.errno == errno.EACCES))
                # write inside rw: allowed
                try:
                    with open(os.path.join(rw, "w.txt"), "w") as fh:
                        fh.write("ok")
                    checks.append(("write-rw", True))
                except OSError:
                    checks.append(("write-rw", False))
                # read outside the jail: EACCES
                try:
                    open("/etc/hostname")
                    checks.append(("outside", False))
                except OSError as e:
                    checks.append(("outside", e.errno == errno.EACCES))
                bad = [k for k, v in checks if not v]
                os.write(w, ("BAD:" + ",".join(bad)).encode())
                os._exit(0 if not bad else 1)
            except BaseException as e:  # noqa: BLE001
                os.write(w, ("ERR %r" % (e,)).encode())
                os._exit(2)
        os.close(w)
        out = b""
        while True:
            chunk = os.read(r, 4096)
            if not chunk:
                break
            out += chunk
        os.close(r)
        _, status = os.waitpid(pid, 0)
        ec = os.waitstatus_to_exitcode(status)
        if ec == 0:
            return _held(name, "read/write split enforced by the kernel")
        return _break(name, "enforcement gap: %s" % (out.decode(),))


@probe("E2-symlink-escape-denied")
def _e2():
    name = "E2-symlink-escape-denied"
    base = _needs_kernel(name)
    if base:
        return base
    with tempfile.TemporaryDirectory() as tmp:
        ro = os.path.join(tmp, "ro")
        os.makedirs(ro)
        os.symlink("/etc/hostname", os.path.join(ro, "evil-link"))
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            try:
                lj.restrict_fs([ro], [])
                try:
                    open(os.path.join(ro, "evil-link")).read()
                    os.write(w, b"ALLOWED")
                except OSError as e:
                    os.write(w, ("EACCES" if e.errno == errno.EACCES
                                 else "ERRNO-%d" % e.errno).encode())
                os._exit(0)
            except BaseException as e:  # noqa: BLE001
                os.write(w, ("ERR %r" % (e,)).encode())
                os._exit(2)
        os.close(w)
        out = b""
        while True:
            chunk = os.read(r, 4096)
            if not chunk:
                break
            out += chunk
        os.close(r)
        _, status = os.waitpid(pid, 0)
        if os.waitstatus_to_exitcode(status) != 0:
            return _error(name, "child failed: %s" % (out.decode(),))
        if out == b"EACCES":
            return _held(name, "symlink target outside the policy denied "
                               "(inode-pinned, target-path checked)")
        return _break(name, "symlink escape: %s" % (out.decode(),))


@probe("E3-parent-unaffected")
def _e3():
    name = "E3-parent-unaffected"
    base = _needs_kernel(name)
    if base:
        return base
    with tempfile.TemporaryDirectory() as tmp:
        def grant():
            lj.restrict_fs([tmp], [])
        code, _ = _fork_confined_child(grant)
        if code != 0:
            return _error(name, "grant child exited %d" % (code,))
        try:
            open("/etc/hostname").read()
        except OSError:
            return _break(name, "parent lost access after child confined "
                                "-- jail leaked to parent")
        return _held(name, "confinement is per-process; parent unaffected")


@probe("E4-narrowing-only")
def _e4():
    name = "E4-narrowing-only"
    base = _needs_kernel(name)
    if base:
        return base
    with tempfile.TemporaryDirectory() as tmp:
        a = os.path.join(tmp, "a")
        b = os.path.join(tmp, "b")
        os.makedirs(a)
        os.makedirs(b)
        with open(os.path.join(b, "f.txt"), "w") as fh:
            fh.write("x")
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            try:
                lj.restrict_fs([a], [])
                # Second layer tries to WIDEN to b: Landlock stacks, so
                # this can only narrow -- b must stay denied.
                lj.restrict_fs([a, b], [])
                try:
                    open(os.path.join(b, "f.txt")).read()
                    os.write(w, b"WIDENED")
                except OSError as e:
                    os.write(w, ("EACCES" if e.errno == errno.EACCES
                                 else "ERRNO-%d" % e.errno).encode())
                os._exit(0)
            except BaseException as e:  # noqa: BLE001
                os.write(w, ("ERR %r" % (e,)).encode())
                os._exit(2)
        os.close(w)
        out = b""
        while True:
            chunk = os.read(r, 4096)
            if not chunk:
                break
            out += chunk
        os.close(r)
        _, status = os.waitpid(pid, 0)
        if os.waitstatus_to_exitcode(status) != 0:
            return _error(name, "child failed: %s" % (out.decode(),))
        if out == b"EACCES":
            return _held(name, "second layer cannot widen the first "
                               "(stacking narrows only)")
        return _break(name, "jail widened: %s" % (out.decode(),))


@probe("E5-exec-gated")
def _e5():
    name = "E5-exec-gated"
    base = _needs_kernel(name)
    if base:
        return base
    with tempfile.TemporaryDirectory() as tmp:
        true_bin = shutil.which("true")
        if not true_bin:
            return _baseline(name, "no 'true' binary on PATH")
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            try:
                # No EXECUTE grant anywhere: exec must fail EACCES.
                lj.restrict_fs([tmp], [])
                try:
                    os.execv(true_bin, ["true"])
                    os.write(w, b"EXECED")
                except OSError as e:
                    os.write(w, ("EACCES" if e.errno == errno.EACCES
                                 else "ERRNO-%d" % e.errno).encode())
                os._exit(0)
            except BaseException as e:  # noqa: BLE001
                os.write(w, ("ERR %r" % (e,)).encode())
                os._exit(2)
        os.close(w)
        out = b""
        while True:
            chunk = os.read(r, 4096)
            if not chunk:
                break
            out += chunk
        os.close(r)
        _, status = os.waitpid(pid, 0)
        if os.waitstatus_to_exitcode(status) != 0:
            return _error(name, "child failed: %s" % (out.decode(),))
        if out == b"EACCES":
            return _held(name, "exec without an EXECUTE grant denied")
        return _break(name, "exec escape: %s" % (out.decode(),))


# ---------------------------------------------------------------------------
# P-group: pin + footer state.
# ---------------------------------------------------------------------------

@probe("P1-pin-taxonomy-2135")
def _p1():
    name = "P1-pin-taxonomy-2135"
    if TAXONOMY_PIN != 2135:
        return _break(name, "TAXONOMY_PIN is %r, want 2135"
                      % (TAXONOMY_PIN,))
    import re as _re
    lits = _re.findall(r'"code"\s*:\s*\'([^\']+)\'',
                       open(os.path.join(REPO_ROOT, "gov",
                                         "decision_codes.py"),
                            encoding="utf-8").read())
    if len(lits) != 2135 or len(set(lits)) != 2135 \
            or lits != sorted(lits):
        return _break(name, "taxonomy not 2135/2135/0 sorted "
                             "(got %d/%d)" % (len(lits), len(set(lits))))
    for code in ("sandbox-landlock-apply-failed",
                 "sandbox-landlock-required",
                 "sandbox-landlock-unavailable"):
        if code not in lits:
            return _break(name, "missing code %s" % (code,))
    return _held(name, "2135/2135/0 sorted; landlock codes present")


@probe("P2-footer-open-f433-f434-f435-next-f436")
def _p2():
    name = "P2-footer-open-f433-f434-f435-next-f436"
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ms = re.findall(r"Next free finding: \*\*(F\d+)\*\*\. "
                    r"\*\*Open findings: ([^*]+)\.\*\*", text)
    if not ms:
        return _break(name, "footer line not found")
    next_free, open_now = ms[-1]
    if next_free != FOOTER_NEXT or open_now != FOOTER_OPEN:
        return _break(name, "footer open %s / next %s, want open %s / next %s"
                      % (open_now, next_free, FOOTER_OPEN, FOOTER_NEXT))
    return _held(name, "footer open none / next F419")


# ---------------------------------------------------------------------------
# Green check (depth-1) + main.
# ---------------------------------------------------------------------------

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green_check: skipped (GOV_SKIP_GREEN=1)")
        return 0
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tempfile.mkdtemp(prefix="g331-green-")
    rc = 0
    for battery, label in (
            ("evals/w266_landlock_probes.py", "w266-landlock"),
            ("evals/w267_redteam_probes.py", "w267-redteam")):
        try:
            p = subprocess.run(
                [sys.executable, os.path.join(REPO_ROOT, battery)],
                env=env, capture_output=True, text=True, timeout=900)
            ok = (p.returncode == 0)
            print("green_check: %s %s (rc=%d)" % (label, "OK" if ok else
                                                  "FAIL", p.returncode))
            if not ok:
                rc = 1
        except Exception as exc:  # noqa: BLE001
            print("green_check: %s ERROR %r" % (label, exc))
            rc = 1
    return rc


def main(argv):
    results = []
    for name, fn in PROBES:
        try:
            results.append(fn())
        except Exception as exc:  # noqa: BLE001
            results.append({"name": name, "result": "ERROR",
                            "detail": "probe crashed: %r" % (exc,)})
    n_break = sum(1 for r in results if r["result"] == "BREAK")
    n_held = sum(1 for r in results if r["result"] == "HELD")
    n_err = sum(1 for r in results if r["result"] == "ERROR")
    n_base = sum(1 for r in results if r["result"] == "BASELINE")
    for r in results:
        print("[%s] %s: %s" % (r["result"], r["name"], r["detail"]))
    print("w331_landlock battery: %d BREAK / %d HELD / %d ERROR / %d "
          "BASELINE (%d BREAKs expected: none)"
          % (n_break, n_held, n_err, n_base, 0))
    if n_break or n_err:
        return 1
    return _green_check()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
