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

TAXONOMY_PIN = 2062 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emailed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emailed +4 manifest-* +7 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-revoked); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*); Wave-330 merge: pin 2058 -> 2058 (no new codes) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).

FOOTER_OPEN = "none"  # F409-F416 CLOSED; no open findings (wave-331 merge).
FOOTER_NEXT = "F417"

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

@probe("P1-pin-taxonomy-2062")
def _p1():
    name = "P1-pin-taxonomy-2062"
    if TAXONOMY_PIN != 2062:
        return _break(name, "TAXONOMY_PIN is %r, want 2062"
                      % (TAXONOMY_PIN,))
    import re as _re
    lits = _re.findall(r'"code"\s*:\s*\'([^\']+)\'',
                       open(os.path.join(REPO_ROOT, "gov",
                                         "decision_codes.py"),
                            encoding="utf-8").read())
    if len(lits) != 2062 or len(set(lits)) != 2062 \
            or lits != sorted(lits):
        return _break(name, "taxonomy not 2062/2062/0 sorted "
                             "(got %d/%d)" % (len(lits), len(set(lits))))
    for code in ("sandbox-landlock-apply-failed",
                 "sandbox-landlock-required",
                 "sandbox-landlock-unavailable"):
        if code not in lits:
            return _break(name, "missing code %s" % (code,))
    return _held(name, "2062/2062/0 sorted; landlock codes present")


@probe("P2-footer-open-none-next-f417")
def _p2():
    name = "P2-footer-open-none-next-f417"
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
    return _held(name, "footer open none / next F417")


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
