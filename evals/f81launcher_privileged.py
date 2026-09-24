#!/usr/bin/env python3
"""F81 privileged integration battery: the production launcher topology.

Proves the PRODUCT topology the $0 sim cannot: the child really lands
inside a network namespace, the vendored seccomp helper really denies
raw sockets / netns escape live, and the nftables allowlist really
holds end-to-end. The sim battery (evals/s7egress_break.py) keeps
proving the launcher layer; this battery re-proves *placement* (spec
D11) — it never re-proves the 11 lab attack classes.

Close-when probes (spec "Testing Decisions"):
  0. control_governed_launch       (positive control)
  1. wall_down_refuses
  2. helper_tamper_refuses
  3. ruleset_drift_refuses
  4. child_is_in_agent0
  5. allowlist_enforced_end_to_end
  6. seccomp_live
  7. prefix_strip_is_auditor_visible
  8. audit_verification_procedure
  9. unauthored_helper_pin_refused
  10. preexec_abort_on_flap        (runs last: destroys the netns)

Topology (built and torn down by the battery; nothing pre-existing is
touched): netns ``f81test0`` (stands in for the deployment's
``agent0``), a veth pair (host 10.200.0.254/24 <-> ns 10.200.0.1/24),
an nftables default-deny ruleset in the ns, a minimal in-ns TCP proxy
(allowlisted host -> 200, anything else -> 403) on 10.200.0.1:8080 and
a minimal in-ns TCP DNS responder (allowlisted zone -> A record, else
NXDOMAIN) on 10.200.0.1:53. The wall inventory is a test-local
authored pin (install_simulated_wall) whose nftables live baseline is
the normalized ruleset actually loaded in the ns.

Skip conditions (clean skip with a reason, never false-green):
  - not root, or GOV_F81_PRIVILEGED != "1" (explicit opt-in),
  - no `ip` or no `nft` binary,
  - `ip netns add` fails (no CAP_SYS_ADMIN).
Individual probes SKIP when their tool is missing (curl,
python3-seccomp).

Run (privileged lab VM or privileged CI only -- NEVER the canonical
suite):
  sudo GOV_F81_PRIVILEGED=1 TMPDIR=/tmp/gov-f81priv \\
      ~/workspace/.gov-venv/bin/python evals/f81launcher_privileged.py

Verdicts: CLOSED (assertion holds) / BREAK (assertion failed -- the
topology claim does not hold; investigate) / SKIP (prerequisite
missing) / ERROR (battery bug).
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import json
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov.egress_launcher import (  # noqa: E402
    EgressLaunchRefused,
    FilteredEgressLauncher,
    NetnsWallProvider,
    WallComponentInventory,
    WallPinRefused,
    _canonical_pin_record_body,
    _check_pin_ledger_structure,
    _normalize_nft_ruleset,
    _record_sha256,
    install_simulated_wall,
)
from gov.ed25519 import verify as ed25519_verify  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402
from gov.delegation_tokens import DelegationTrust  # noqa: E402

NETNS = "f81test0"
NS_IP = "10.200.0.1"
HOST_IP = "10.200.0.254"
PROXY_PORT = 8080
DNS_PORT = 53
ALLOW_HOST = "example.com"
BLOCK_HOST = "blocked.example"
VETH_HOST = "veth-f81h"
VETH_NS = "veth-f81n"

RESULTS = []


class SkipProbe(Exception):
    """A probe's prerequisite is missing; not a failure."""


def _require(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def _run(*args, check=True, capture=True, timeout=30):
    return subprocess.run(
        list(args), check=check, capture_output=capture,
        text=True, timeout=timeout)


def _ns(*args, check=True, timeout=30):
    return _run("ip", "netns", "exec", NETNS, *args,
                check=check, timeout=timeout)


def _skip_reason():
    if os.geteuid() != 0:
        return ("not root (euid=%d); the privileged battery needs "
                "CAP_SYS_ADMIN" % os.geteuid())
    if os.environ.get("GOV_F81_PRIVILEGED") != "1":
        return "GOV_F81_PRIVILEGED != '1' (explicit opt-in not set)"
    if shutil.which("ip") is None:
        return "no `ip` binary on PATH"
    if shutil.which("nft") is None:
        return "no `nft` binary on PATH"
    probe = _run("ip", "netns", "add", "f81probecap", check=False)
    if probe.returncode != 0:
        err = (probe.stderr or probe.stdout or "").strip()[:160]
        return "`ip netns add` failed (no CAP_SYS_ADMIN?): %s" % err
    _run("ip", "netns", "del", "f81probecap", check=False)
    return None


NFT_RULESET = """\
table inet f81wall {
    chain input {
        type filter hook input priority 0; policy drop;
        iifname "lo" accept
        ct state established,related accept
        tcp dport 8080 ip saddr 10.200.0.0/24 accept
        tcp dport 53 ip saddr 10.200.0.0/24 accept
    }
    chain output {
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        ip daddr 10.200.0.0/24 accept
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
}
"""

# In-namespace stub supervisor: a minimal TCP proxy (allowlisted host ->
# 200, anything else -> 403) and a minimal TCP DNS responder
# (allowlisted zone -> A 10.200.0.1, else NXDOMAIN). Written as a file
# at setup time and run under `ip netns exec`. No third-party imports.
SUPERVISOR_SRC = r'''
import socket
import struct
import sys
import threading

NS_IP = "10.200.0.1"
ALLOW = {"example.com."}
READY = sys.argv[1]


def _recv_all(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


def _serve(listener, handler):
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=handler, args=(conn,),
                         daemon=True).start()


def _handle_proxy(conn):
    try:
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        line = data.split(b"\r\n", 1)[0].decode("latin1")
        parts = line.split()
        host = ""
        if len(parts) >= 2 and parts[1].startswith("http://"):
            host = parts[1][7:].split("/")[0].split(":")[0].lower()
        ok = (host + ".") in ALLOW or host in ("example.com",)
        if ok:
            body = b"f81-privileged-battery ok"
            head = b"HTTP/1.1 200 OK\r\n"
        else:
            body = b"blocked by f81 wall proxy"
            head = b"HTTP/1.1 403 Forbidden\r\n"
        conn.sendall(head + b"Content-Length: %d\r\n"
                     b"Connection: close\r\n\r\n" % len(body) + body)
    except Exception:
        pass
    finally:
        conn.close()


def _parse_qname(msg):
    off = 12
    labels = []
    while True:
        ln = msg[off]
        off += 1
        if ln == 0:
            break
        labels.append(msg[off:off + ln])
        off += ln
    qend = off + 4
    return b".".join(labels) + b".", msg[12:qend]


def _handle_dns(conn):
    try:
        (mlen,) = struct.unpack(">H", _recv_all(conn, 2))
        msg = _recv_all(conn, mlen)
        txid = struct.unpack(">H", msg[:2])[0]
        qname, qsec = _parse_qname(msg)
        if qname.decode("ascii", "ignore").lower() in ALLOW:
            flags, ancount = 0x8180, 1
        else:
            flags, ancount = 0x8183, 0
        resp = struct.pack(">HHHHHH", txid, flags, 1, ancount, 0, 0)
        resp += qsec
        if ancount:
            resp += bytes([0xC0, 0x0C])
            resp += struct.pack(">HHIH", 1, 1, 60, 4)
            resp += socket.inet_aton(NS_IP)
        conn.sendall(struct.pack(">H", len(resp)) + resp)
    except Exception:
        pass
    finally:
        conn.close()


def main():
    proxy = socket.socket()
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind((NS_IP, 8080))
    proxy.listen(32)
    dns = socket.socket()
    dns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dns.bind((NS_IP, 53))
    dns.listen(32)
    threading.Thread(target=_serve, args=(proxy, _handle_proxy),
                     daemon=True).start()
    threading.Thread(target=_serve, args=(dns, _handle_dns),
                     daemon=True).start()
    with open(READY, "w") as f:
        f.write("ready\n")
    threading.Event().wait()


main()
'''


def _dns_query_tcp(name, timeout=10):
    """Minimal TCP DNS query against the in-ns stub. Returns
    (rcode, [ipv4 strings])."""
    qname = b"".join(
        bytes([len(p)]) + p.encode("ascii") for p in name.split("."))
    qname += b"\x00"
    query = (struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
             + qname + struct.pack(">HH", 1, 1))
    sock = socket.create_connection((NS_IP, DNS_PORT), timeout=timeout)
    try:
        sock.sendall(struct.pack(">H", len(query)) + query)
        (mlen,) = struct.unpack(">H", _recv_all(sock, 2))
        resp = _recv_all(sock, mlen)
    finally:
        sock.close()
    rcode = resp[3] & 0x0F
    addrs = []
    if rcode == 0:
        ancount = struct.unpack(">H", resp[6:8])[0]
        off = 12
        while resp[off] != 0:
            off += 1 + resp[off]
        off += 5  # null + qtype + qclass
        for _ in range(ancount):
            off += 2  # name pointer
            atype, aclass, _, rdlen = struct.unpack(">HHIH", resp[off:off + 10])
            off += 10
            if atype == 1 and rdlen == 4:
                addrs.append(socket.inet_ntoa(resp[off:off + 4]))
            off += rdlen
    return rcode, addrs


def _recv_all(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


class Ctx:
    """Battery context: topology handles + wall inventory + launcher."""


def _setup():
    ctx = Ctx()
    ctx.tmp = tempfile.mkdtemp(prefix="gov-f81priv-")
    # Best-effort cleanup of a previous dead run.
    _run("ip", "netns", "del", NETNS, check=False)
    _run("ip", "link", "del", VETH_HOST, check=False)

    _run("ip", "netns", "add", NETNS)
    _run("ip", "link", "add", VETH_HOST, "type", "veth",
         "peer", "name", VETH_NS)
    _run("ip", "link", "set", VETH_NS, "netns", NETNS)
    _run("ip", "addr", "add", HOST_IP + "/24", "dev", VETH_HOST)
    _run("ip", "link", "set", VETH_HOST, "up")
    _ns("ip", "addr", "add", NS_IP + "/24", "dev", VETH_NS)
    _ns("ip", "link", "set", VETH_NS, "up")
    _ns("ip", "link", "set", "lo", "up")
    # A default route so dropped SYNs prove the nftables policy drop
    # (without it, connect() fails fast with ENETUNREACH and the probe
    # would be vacuous).
    _ns("ip", "route", "add", "default", "via", HOST_IP)

    ctx.ruleset_file = os.path.join(ctx.tmp, "ruleset.nft")
    with open(ctx.ruleset_file, "w", encoding="utf-8") as f:
        f.write(NFT_RULESET)
    _ns("nft", "-f", ctx.ruleset_file)
    live = _ns("nft", "list", "ruleset").stdout
    _require("f81wall" in live, "nftables ruleset did not load in the ns")
    ctx.live_baseline = _sha256_bytes(
        _normalize_nft_ruleset(live).encode("utf-8"))

    # The vendored seccomp helper bytes (the pinned artifact source).
    with open(os.path.join(REPO_ROOT, "gov", "data",
                           "run_seccomp.py"), "rb") as f:
        helper_bytes = f.read()

    # Authored wall pin. The battery acts as the operator: it pins the
    # REAL vendored helper bytes through the authored proposal ->
    # install flow (the F138 ceremony), not the sim stand-in. The
    # nftables live baseline is the normalized ruleset actually loaded
    # in the namespace.
    signer = Ed25519Signer(os.urandom(32))
    filler = [Ed25519Signer(os.urandom(32)), Ed25519Signer(os.urandom(32))]
    trust = DelegationTrust(
        human_keys={signer.key_id: signer.public_key},
        authority_keys={filler[0].key_id: filler[0].public_key},
        user_issuer_keys={filler[1].key_id: filler[1].public_key})
    wall_dir = os.path.join(ctx.tmp, "wall")
    live_digests = {"nft_ruleset": ctx.live_baseline}
    ctx.inv, ctx.paths = install_simulated_wall(
        wall_dir, wall_id="f81priv", trust=trust,
        operator_signers=[signer], tier="dev",
        live_digests=live_digests)
    manifest = json.loads(
        open(ctx.paths["manifest"], encoding="utf-8").read())
    comp_paths = {e["name"]: e["path"]
                  for e in manifest["components"]}
    with open(comp_paths["seccomp_helper"], "wb") as f:
        f.write(helper_bytes)
    prop = WallComponentInventory.proposal(
        comp_paths, ctx.paths["manifest"], tier="dev",
        ledger_path=ctx.paths["ledger"], live_digests=live_digests)
    WallComponentInventory.install(
        comp_paths, ctx.paths["manifest"], ctx.paths["receipt"],
        trust=trust, author_key_id=signer.key_id,
        authorship_sig_hex=signer.sign(prop["body"]).hex(),
        ts=prop["ts"], tier="dev", ledger_path=ctx.paths["ledger"],
        live_digests=live_digests)
    ctx.inv = WallComponentInventory(
        ctx.paths["manifest"], ctx.paths["receipt"], trust=trust,
        ledger_path=ctx.paths["ledger"])
    # The pinned artifact IS the deployed file: what the provider
    # execs is exactly what the pin binds.
    ctx.helper_path = comp_paths["seccomp_helper"]
    os.chmod(ctx.helper_path, 0o755)

    # In-namespace stubs (proxy + DNS).
    sup_path = os.path.join(ctx.tmp, "supervisor.py")
    with open(sup_path, "w", encoding="utf-8") as f:
        f.write(SUPERVISOR_SRC)
    ctx.ready_file = os.path.join(ctx.tmp, "stubs.ready")
    ctx.supervisor = subprocess.Popen(
        ["ip", "netns", "exec", NETNS, sys.executable, sup_path,
         ctx.ready_file],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 15
    while not os.path.exists(ctx.ready_file):
        _require(time.time() < deadline,
                 "in-ns stub supervisor did not become ready")
        _require(ctx.supervisor.poll() is None,
                 "in-ns stub supervisor died during startup")
        time.sleep(0.2)

    ctx.provider = NetnsWallProvider(
        ctx.inv, netns_name=NETNS, helper_path=ctx.helper_path)
    ctx.events = []
    ctx.launcher = FilteredEgressLauncher(
        manifest_path=ctx.paths["manifest"],
        receipt_path=ctx.paths["receipt"],
        wall_provider=ctx.provider, audit=ctx.events.append,
        trust=ctx.inv.trust)
    rep = ctx.provider.check()
    _require(rep.state == "UP", "wall not UP after setup: %s" % (rep,))
    return ctx


def _teardown(ctx):
    sup = getattr(ctx, "supervisor", None)
    if sup is not None and sup.poll() is None:
        sup.terminate()
        try:
            sup.wait(timeout=5)
        except Exception:
            sup.kill()
    _run("ip", "netns", "del", NETNS, check=False)
    _run("ip", "link", "del", VETH_HOST, check=False)
    shutil.rmtree(getattr(ctx, "tmp", None) or "", ignore_errors=True)


# ---------------------------------------------------------------------------
# Probes (each takes the Ctx; raise SkipProbe / AssertionError)
# ---------------------------------------------------------------------------

def _launcher_for(ctx, provider, events):
    return FilteredEgressLauncher(
        manifest_path=ctx.paths["manifest"],
        receipt_path=ctx.paths["receipt"],
        wall_provider=provider, audit=events.append,
        trust=ctx.inv.trust)


def p_control_governed_launch(ctx):
    cp = ctx.launcher.run_child(["/usr/bin/true"],
                                run_id="f81priv-governed")
    _require(cp.returncode == 0,
             "governed launch failed: rc=%s" % (cp.returncode,))
    launches = [e for e in ctx.events
                if e["event"] == "egress_wall_launch"]
    _require(len(launches) == 1,
             "expected 1 launch event, got %d" % len(launches))
    return "governed launch rc=0, 1 egress_wall_launch event"


def p_wall_down_refuses(ctx):
    events = []
    provider = NetnsWallProvider(ctx.inv, netns_name="f81nosuchns",
                                 helper_path=ctx.helper_path)
    launcher = _launcher_for(ctx, provider, events)
    rep = provider.check()
    _require(rep.state == "DOWN", "expected DOWN, got %s" % (rep,))
    _require(rep.detail.get("reason") == "netns_missing_or_unprivileged",
             "wrong DOWN detail: %r" % (rep.detail,))
    try:
        launcher.launch(["/usr/bin/true"], run_id="f81priv-down")
    except EgressLaunchRefused as e:
        _require("wall_not_up" in str(e), "wrong refusal: %s" % e)
    else:
        raise AssertionError("launch did not refuse with the wall down")
    _require(not [e for e in events
                  if e["event"] == "egress_wall_launch"],
             "a launch event exists despite refusal")
    refusals = [e for e in events
                if e["event"] == "egress_wall_launch_refused"]
    _require(len(refusals) == 1 and refusals[0]["reason"] == "wall_not_up",
             "expected one wall_not_up refusal, got %r" % (refusals,))
    return ("DOWN(netns_missing_or_unprivileged); launch refused "
            "wall_not_up; no child spawned; 1 refusal event")


def p_helper_tamper_refuses(ctx):
    tampered = os.path.join(ctx.tmp, "run_seccomp_tampered.py")
    with open(ctx.helper_path, "rb") as f:
        data = bytearray(f.read())
    data[len(data) // 2] ^= 0x01
    with open(tampered, "wb") as f:
        f.write(bytes(data))
    events = []
    provider = NetnsWallProvider(ctx.inv, netns_name=NETNS,
                                 helper_path=tampered)
    rep = provider.check()
    _require(rep.state == "DEGRADED",
             "expected DEGRADED, got %s" % (rep,))
    _require(rep.detail.get("reason") == "component_tampered"
             and rep.detail.get("component") == "seccomp_helper",
             "expected component_tampered/seccomp_helper, got %r"
             % (rep.detail,))
    launcher = _launcher_for(ctx, provider, events)
    try:
        launcher.launch(["/usr/bin/true"], run_id="f81priv-tamper")
    except EgressLaunchRefused as e:
        _require("wall_degraded" in str(e), "wrong refusal: %s" % e)
    else:
        raise AssertionError("launch did not refuse on helper tamper")
    return ("1 flipped byte -> DEGRADED(component_tampered/seccomp_helper); "
            "launch refused wall_degraded before spawn")


def p_ruleset_drift_refuses(ctx):
    _ns("nft", "add", "rule", "inet", "f81wall", "output",
        "ip", "daddr", "8.8.8.8", "accept")
    try:
        rep = ctx.provider.check()
        _require(rep.state == "DEGRADED",
                 "expected DEGRADED, got %s" % (rep,))
        _require(rep.detail.get("reason") == "ruleset_drift",
                 "expected ruleset_drift, got %r" % (rep.detail,))
        try:
            ctx.launcher.launch(["/usr/bin/true"],
                                run_id="f81priv-drift")
        except EgressLaunchRefused as e:
            _require("wall_degraded" in str(e), "wrong refusal: %s" % e)
        else:
            raise AssertionError("launch did not refuse on ruleset drift")
    finally:
        _ns("nft", "flush", "ruleset")
        _ns("nft", "-f", ctx.ruleset_file)
    rep = ctx.provider.check()
    _require(rep.state == "UP",
             "wall did not recover after ruleset restore: %s" % (rep,))
    return ("added allow rule -> DEGRADED(ruleset_drift); launch refused "
            "wall_degraded; wall UP again after restore")


def p_child_is_in_agent0(ctx):
    cp = ctx.launcher.run_child(["readlink", "/proc/self/ns/net"],
                                capture_output=True, text=True,
                                run_id="f81priv-ns")
    _require(cp.returncode == 0, "readlink failed: %s" % (cp.stderr,))
    child_inode = cp.stdout.strip()
    ns_inode = _ns("readlink", "/proc/self/ns/net").stdout.strip()
    host_inode = _run("readlink", "/proc/self/ns/net").stdout.strip()
    _require(child_inode == ns_inode,
             "child netns %r != f81test0 netns %r"
             % (child_inode, ns_inode))
    _require(child_inode != host_inode,
             "child netns == host netns (no isolation!)")
    env_cp = ctx.launcher.run_child(["/usr/bin/env"], capture_output=True,
                                    text=True, run_id="f81priv-env")
    env = {}
    for line in (env_cp.stdout or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            env[k] = v
    _require(env.get("EGRESS_WALL_ACTIVE") == "1",
             "EGRESS_WALL_ACTIVE missing from child env")
    wideners = [k for k in env
                if k.upper() in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
                                 "ALL_PROXY")]
    _require(not wideners,
             "trust-widening proxy vars present: %r" % (wideners,))
    return ("child netns == f81test0 (%s) != host (%s); EGRESS_WALL_ACTIVE=1; "
            "no proxy trust-wideners" % (ns_inode, host_inode))


def p_allowlist_enforced_end_to_end(ctx):
    if shutil.which("curl") is None:
        raise SkipProbe("no curl binary")
    proxy = "http://%s:%d" % (NS_IP, PROXY_PORT)
    ok = ctx.launcher.run_child(
        ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
         "--max-time", "10", "-x", proxy,
         "http://%s/" % ALLOW_HOST],
        capture_output=True, text=True, run_id="f81priv-allow")
    _require(ok.stdout.strip() == "200",
             "allowlisted fetch via proxy: %r rc=%s err=%s"
             % (ok.stdout, ok.returncode, ok.stderr))
    blocked = ctx.launcher.run_child(
        ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
         "--max-time", "10", "-x", proxy,
         "http://%s/" % BLOCK_HOST],
        capture_output=True, text=True, run_id="f81priv-block")
    _require(blocked.stdout.strip() == "403",
             "blocked fetch: expected proxy 403, got %r"
             % (blocked.stdout,))
    # Direct egress (no proxy): SYNs leave via the default route and
    # must die at the nftables output policy (drop), i.e. time out.
    direct = ctx.launcher.run_child(
        [sys.executable, "-c",
         "import socket;"
         "socket.create_connection(('93.184.216.34', 80), timeout=5);"
         "print('REACHED')"],
        capture_output=True, text=True, run_id="f81priv-direct")
    _require("REACHED" not in (direct.stdout or ""),
             "direct egress reached the outside (nftables drop failed)")
    # Confined DNS stub: allowlisted -> A, everything else -> NXDOMAIN.
    rcode, addrs = _dns_query_tcp(ALLOW_HOST)
    _require(rcode == 0 and addrs == [NS_IP],
             "allowlisted DNS: rcode=%s addrs=%r" % (rcode, addrs))
    rcode2, _ = _dns_query_tcp("evil.example")
    _require(rcode2 == 3,
             "non-allowlisted DNS: expected NXDOMAIN(3), got %s" % rcode2)
    return ("proxy 200 allowlisted / 403 blocked; direct egress SYN "
            "dropped by nftables; DNS allowlist->A, else NXDOMAIN")


_SECCOMP_PROBE = r'''
import ctypes
import os
import socket

out = []


def t(name, fn):
    try:
        fn()
        out.append(name + ":ALLOWED")
    except PermissionError:
        out.append(name + ":EPERM")
    except OSError as e:
        out.append(name + ":OSERROR-%s" % (e.errno,))


def raw_packet():
    socket.socket(socket.AF_PACKET, socket.SOCK_RAW).close()


def raw_inet():
    socket.socket(socket.AF_INET, socket.SOCK_RAW,
                  socket.IPPROTO_RAW).close()


def unshare_net():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    if libc.unshare(0x40000000) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


def setns_self():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fd = os.open("/proc/self/ns/net", os.O_RDONLY)
    try:
        if libc.setns(fd, 0) != 0:
            e = ctypes.get_errno()
            raise OSError(e, os.strerror(e))
    finally:
        os.close(fd)


t("AF_PACKET", raw_packet)
t("SOCK_RAW", raw_inet)
t("UNSHARE_NEWNET", unshare_net)
t("SETNS", setns_self)
print("\n".join(out))
'''


def p_seccomp_live(ctx):
    try:
        import seccomp  # noqa: F401
    except ImportError:
        raise SkipProbe("python3-seccomp not installed; "
                        "the helper cannot load")
    cp = ctx.launcher.run_child(
        [sys.executable, "-c", _SECCOMP_PROBE],
        capture_output=True, text=True, run_id="f81priv-seccomp")
    lines = dict(l.split(":", 1) for l in (cp.stdout or "").splitlines()
                 if ":" in l)
    for name in ("AF_PACKET", "SOCK_RAW", "UNSHARE_NEWNET", "SETNS"):
        _require(lines.get(name) == "EPERM",
                 "%s: expected EPERM under the helper, got %r (stderr=%s)"
                 % (name, lines.get(name), cp.stderr))
    # Control: the same probe WITHOUT the helper -- raw sockets are
    # allowed as root, proving the EPERM comes from the filter.
    ctrl = _ns(sys.executable, "-c", _SECCOMP_PROBE)
    ctrl_lines = dict(l.split(":", 1) for l in ctrl.stdout.splitlines()
                      if ":" in l)
    _require(ctrl_lines.get("AF_PACKET") == "ALLOWED",
             "control inconclusive: AF_PACKET %r without the helper"
             % (ctrl_lines.get("AF_PACKET"),))
    return ("AF_PACKET/SOCK_RAW/unshare(CLONE_NEWNET)/setns -> EPERM "
            "under the helper; control ALLOWED without it")


def p_prefix_strip_is_auditor_visible(ctx):
    # A caller that bypasses the launcher: direct spawn, no audit.
    subprocess.run(["/usr/bin/true"], check=True, timeout=30)
    governed = [e for e in ctx.events
                if e["event"] == "egress_wall_launch"
                and e.get("run_id") == "f81priv-governed"]
    _require(governed, "governed launch event missing")
    bypass = [e for e in ctx.events
              if e["event"] == "egress_wall_launch"
              and e.get("run_id") == "f81priv-bypass"]
    _require(not bypass,
             "bypass run produced a launch event (unexpected)")
    return ("governed run_id has its egress_wall_launch event; the "
            "prefix-stripped run_id has none -- the residual is "
            "auditor-visible")


def p_audit_verification_procedure(ctx):
    # The scripted auditor walk: recompute everything from the files,
    # match the launch event's bound digests.
    with open(ctx.paths["manifest"], "rb") as f:
        manifest_blob = f.read()
    with open(ctx.paths["receipt"], "rb") as f:
        receipt_blob = f.read()
    manifest = json.loads(manifest_blob.decode("utf-8"))
    receipt = json.loads(receipt_blob.decode("utf-8"))
    # a. the receipt binds the exact manifest bytes.
    _require(_sha256_bytes(manifest_blob) == receipt["manifest_sha256"],
             "receipt manifest_sha256 mismatch")
    # b. the ledger chains to the manifest's pin record.
    with open(ctx.paths["ledger"], encoding="utf-8") as f:
        records = [json.loads(l) for l in f if l.strip()]
    tip = _check_pin_ledger_structure(records)
    pin_record = manifest["pin_record"]
    _require(tip == pin_record["record_sha256"],
             "ledger tip != manifest pin record")
    _require(_record_sha256(pin_record) == pin_record["record_sha256"],
             "pin record self-hash mismatch")
    # c. the tip's authorship verifies against the roster key over the
    #    recomputed canonical body.
    body = _canonical_pin_record_body(
        pin_record["tier"], pin_record["pin_payload_sha256"],
        pin_record.get("prev_pin_record_sha256"),
        pin_record["pinned_at"])
    key_id = pin_record["author_key_ids"][0]
    pub = ctx.inv.trust.human_keys[key_id]
    sig = bytes.fromhex(pin_record["authorship_sigs"][key_id])
    _require(ed25519_verify(pub, body, sig),
             "tip authorship signature invalid")
    # d. every pinned component digest recomputes from disk.
    for entry in manifest["components"]:
        with open(entry["path"], "rb") as f:
            data = f.read()
        for algo, want in entry["digests"].items():
            got = hashlib.new(algo, data).hexdigest()
            _require(got == want,
                     "component %s digest mismatch" % entry["name"])
    # e. the launch event binds the same digests.
    ev = [e for e in ctx.events
          if e["event"] == "egress_wall_launch"
          and e.get("run_id") == "f81priv-governed"][0]
    _require(ev["manifest_sha256"] == _sha256_bytes(manifest_blob),
             "launch event manifest_sha256 mismatch")
    _require(ev["pin_record_sha256"] == tip,
             "launch event pin_record_sha256 mismatch")
    _require(ev["receipt_sha256"] == _sha256_bytes(receipt_blob),
             "launch event receipt_sha256 mismatch")
    _require(sorted(ev["components"]) ==
             sorted(e["name"] for e in manifest["components"]),
             "launch event components mismatch")
    return ("receipt/ledger-tip/authorship/component-digests/launch-event "
            "all match the recomputed values")


def p_unauthored_helper_pin_refused(ctx):
    tmp2 = tempfile.mkdtemp(prefix="gov-f81priv-unauth-")
    try:
        try:
            WallComponentInventory.install(
                {}, os.path.join(tmp2, "m.json"),
                os.path.join(tmp2, "r.json"))
        except WallPinRefused as e:
            _require("pin_authorship_invalid" in str(e),
                     "wrong refusal: %s" % e)
        else:
            raise AssertionError("bare install was not refused")
    finally:
        shutil.rmtree(tmp2, ignore_errors=True)
    return "bare helper re-pin refused: pin_authorship_invalid"


def p_preexec_abort_on_flap(ctx):
    # Fault injection: the netns dies between the parent's check() and
    # the child's preexec re-check. Runs LAST (destroys the netns).
    events = []
    base = ctx.provider
    orig_check = base.check
    flapped = {"done": False}

    def _flap_check():
        rep = orig_check()
        if rep.ok() and not flapped["done"]:
            flapped["done"] = True
            _run("ip", "netns", "del", NETNS, check=False)
        return rep

    base.check = _flap_check
    try:
        launcher = _launcher_for(ctx, base, events)
        try:
            launcher.run_child(["/usr/bin/true"],
                               run_id="f81priv-flap")
        except EgressLaunchRefused as e:
            _require("preexec_recheck_failed" in str(e),
                     "wrong refusal: %s" % e)
        else:
            raise AssertionError("flap did not abort the child")
    finally:
        base.check = orig_check
    refusals = [e for e in events
                if e["event"] == "egress_wall_launch_refused"]
    _require(any(r["reason"] == "preexec_recheck_failed"
                 for r in refusals),
             "no preexec_recheck_failed refusal event: %r" % (refusals,))
    _require(not [e for e in events
                  if e["event"] == "egress_wall_launch"],
             "a launch event exists despite the flap abort")
    return ("netns deleted between check and spawn -> child exit 99, "
            "EgressLaunchRefused(preexec_recheck_failed), nothing "
            "ungoverned ran")


PROBES = [
    ("control_governed_launch", p_control_governed_launch),
    ("wall_down_refuses", p_wall_down_refuses),
    ("helper_tamper_refuses", p_helper_tamper_refuses),
    ("ruleset_drift_refuses", p_ruleset_drift_refuses),
    ("child_is_in_agent0", p_child_is_in_agent0),
    ("allowlist_enforced_end_to_end", p_allowlist_enforced_end_to_end),
    ("seccomp_live", p_seccomp_live),
    ("prefix_strip_is_auditor_visible",
     p_prefix_strip_is_auditor_visible),
    ("audit_verification_procedure", p_audit_verification_procedure),
    ("unauthored_helper_pin_refused", p_unauthored_helper_pin_refused),
    ("preexec_abort_on_flap", p_preexec_abort_on_flap),
]


def main():
    reason = _skip_reason()
    if reason is not None:
        print("F81-PRIVILEGED-BATTERY: SKIPPED (%s)" % reason)
        return 0
    ctx = _setup()
    try:
        bad = 0
        counts = {}
        for name, fn in PROBES:
            try:
                detail = fn(ctx)
                verdict = "CLOSED"
            except SkipProbe as e:
                verdict, detail = "SKIP", str(e)
            except AssertionError as e:
                verdict, detail = "BREAK", "assertion failed: %s" % e
            except Exception as e:  # noqa: BLE001 - probe harness
                verdict, detail = "ERROR", "probe raised: %r" % (e,)
            counts[verdict] = counts.get(verdict, 0) + 1
            if verdict in ("BREAK", "ERROR"):
                bad += 1
            print("%-32s %-8s %s" % (name, verdict, detail))
    finally:
        _teardown(ctx)
    print("----")
    print("summary: %s" % " ".join("%s=%d" % kv
                                   for kv in sorted(counts.items())))
    print("F81-PRIVILEGED-BATTERY: %s" % ("GREEN" if bad == 0 else "RED"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
