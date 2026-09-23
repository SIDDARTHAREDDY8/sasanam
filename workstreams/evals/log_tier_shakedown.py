"""Wave-60 Lane 1: SECCOMP_RET_LOG staging-tier shake-down harness.

The kernel refuses live seccomp installation in this environment
(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) -> EINVAL; see
workstreams/evals/SECCOMP_REPORT.md), so the LOG tier cannot be
exercised on the kernel here. This harness does the honest equivalent:

  1. Compiles the EXACT filtered-egress cage filter twice — once with
     default_action="kill" (the production tier) and once with
     default_action="log" (the staging tier). Same builder, same 160
     instructions; only the default RET differs.
  2. Runs representative synthetic workloads under `strace -f` and
     captures every syscall (name + scalar args for socket-family,
     prctl, ioctl).
  3. Replays every unique (nr, args) through gov.sandbox._bpf_decision
     against BOTH blobs:
       LOG blob  -> ALLOW (silent) | LOG (logged, executes) | EPERM
                    (errno tier: enforced even in staging)
       KILL blob -> ALLOW | KILL | EPERM
  4. Emits the denial inventory: every logged denial under LOG, its
     verdict under KILL, and the triage class.

A "logged denial" for a legitimate workload syscall is an over-denial
candidate (the classic seccomp failure mode: legit workload killed at
KILL tier). An attack shape hitting LOG is confirmed against the KILL
blob ("would die under KILL").

Deterministic, $0, synthetic/local only. No external network.
"""

import json
import os
import re
import shutil
import socket as _socket
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import gov.sandbox as S  # noqa: E402

_ALLOW = S._SECCOMP_RET_ALLOW
_KILL = S._SECCOMP_RET_KILL_PROCESS
_EPERM = S._SECCOMP_RET_ERRNO | S._EPERM
_LOG = S._SECCOMP_RET_LOG

_VERDICT_NAMES = {_ALLOW: "ALLOW", _KILL: "KILL", _EPERM: "EPERM",
                  _LOG: "LOG"}

# ---------------------------------------------------------------- workloads

W_BASELINE = ("baseline-file-fork", S._AUDIT_WORKLOAD)

W_THREADS = ("threads-queue", r"""
import queue, threading, time
q = queue.Queue()
def worker(n):
    for i in range(200):
        q.put((n, i))
    q.put(None)
ts = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
[t.start() for t in ts]
seen = 0
dones = 0
while dones < 4:
    item = q.get()
    if item is None:
        dones += 1
    else:
        seen += 1
[t.join() for t in ts]
ev = threading.Event()
ev.set(); ev.wait(0.01)
lk = threading.Lock()
with lk:
    pass
print("threads-ok", seen)
""")

W_TCP_CLIENT = ("tcp-client-proxy-leg", r"""
import socket, threading
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(1)
port = srv.getsockname()[1]
got = {}
def serve():
    c, _ = srv.accept()
    got["data"] = c.recv(64)
    c.sendall(b"proxied-ok")
    c.shutdown(socket.SHUT_RDWR)
    c.close()
t = threading.Thread(target=serve); t.start()
# The cage->proxy leg: AF_INET STREAM client, exactly the shape the
# filtered-egress profile exists to allow.
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC, 0)
c.connect(("127.0.0.1", port))
print("peer:", c.getpeername()[1] == port, "name:", c.getsockname()[1] > 0)
c.sendall(b"hello-proxy")
print("reply:", c.recv(64))
c.shutdown(socket.SHUT_RDWR)
c.close()
t.join(); srv.close()
ai = socket.getaddrinfo("localhost", port, socket.AF_INET, socket.SOCK_STREAM)
print("getaddrinfo-ok", bool(ai))
print("tcp-ok")
""")

W_UNIX_PAIR = ("unix-socketpair-msg", r"""
import socket
a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
a.sendmsg([b"ping"])
data, anc, flags, addr = b.recvmsg(64)
print("pair-ok", data == b"ping", anc == [])
a.close(); b.close()
print("unix-ok")
""")

W_SUBPROCESS = ("subprocess-exec", r"""
import subprocess
r1 = subprocess.run(["/bin/true"], capture_output=True)
r2 = subprocess.run(["/bin/echo", "hi"], capture_output=True, text=True)
print("sub-ok", r1.returncode == 0, r2.stdout.strip() == "hi")
""")

W_SSL_IMPORT = ("ssl-context", r"""
import ssl
ctx = ssl.create_default_context()
print("ssl-ok", ctx.protocol is not None)
""")

W_IO_MMAP = ("io-tempfile-mmap", r"""
import mmap, os, tempfile
fd, path = tempfile.mkstemp()
os.write(fd, b"z" * 4096)
m = mmap.mmap(fd, 4096, access=mmap.ACCESS_READ)
print("mmap-ok", m[:4] == b"zzzz")
m.close(); os.close(fd); os.unlink(path)
print("rnd-ok", len(os.urandom(32)) == 32)
""")

# Probe shapes: syscalls a *plausible* legitimate workload might make
# that the cage profile deliberately denies. These are not asserted as
# workload needs — each is triaged in SECCOMP_LOG_SHAKEDOWN.md.
W_PROBE_PRCTL = ("probe-prctl-setname", r"""
import ctypes
libc = ctypes.CDLL("libc.so.6", use_errno=True)
PR_SET_NAME = 15
# Libraries (gunicorn/uvicorn-style workers, some HTTP clients) name
# their threads via prctl(PR_SET_NAME). Probe, don't require.
rc = libc.prctl(PR_SET_NAME, b"w60probe", 0, 0, 0)
print("prctl-probe-rc", rc)
""")

W_PROBE_IOCTL = ("probe-ioctl-winsz", r"""
import ctypes, fcntl, os, struct, termios
libc = ctypes.CDLL("libc.so.6", use_errno=True)
r, w = os.pipe()
# TIOCGWINSZ on a non-tty: cosmetic terminal probing some CLIs do.
buf = struct.pack("HHHH", 0, 0, 0, 0)
try:
    rc = fcntl.ioctl(w, termios.TIOCGWINSZ, buf)
    print("ioctl-probe-rc", rc)
except OSError as e:
    print("ioctl-probe-errno", e.errno)
os.close(r); os.close(w)
""")

W_PROBE_DGRAM = ("probe-udp-dns-shape", r"""
import socket
# What a workload doing its OWN dns would attempt. The cage design
# says DNS belongs to the proxy, not the child — probe the shape.
for fam, proto in ((socket.AF_INET, 0), (socket.AF_INET6, 0)):
    try:
        s = socket.socket(fam, socket.SOCK_DGRAM, proto)
        print("dgram-created", fam)
        s.close()
    except OSError as e:
        print("dgram-errno", fam, e.errno)
# And IPv6 STREAM: proxy is v4-only; is the denial load-bearing?
try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
    print("inet6-stream-created")
    s.close()
except OSError as e:
    print("inet6-stream-errno", e.errno)
""")

WORKLOADS = [W_BASELINE, W_THREADS, W_TCP_CLIENT, W_UNIX_PAIR,
             W_SUBPROCESS, W_SSL_IMPORT, W_IO_MMAP,
             W_PROBE_PRCTL, W_PROBE_IOCTL, W_PROBE_DGRAM]

# ---------------------------------------------------------------- strace parse

_CALL_RE = re.compile(r"^(?:\d+\s+)?([a-z_][a-z0-9_]*)\((.*)\)\s+=\s+(-?\d+|0x[0-9a-fA-F]+|\?)")
_RESUMED_RE = re.compile(r"^(?:\d+\s+)?<\.\.\. ([a-z_][a-z0-9_]*) resumed>")

_DOMAIN = {"AF_UNIX": 1, "AF_INET": 2, "AF_INET6": 10, "AF_NETLINK": 16,
           "AF_PACKET": 17}
_PROTO = {"IPPROTO_IP": 0, "IPPROTO_TCP": 6, "IPPROTO_UDP": 17,
          "IPPROTO_SCTP": 132, "IPPROTO_DCCP": 33}


def _socktype_mask(text):
    t = 0
    for name, bit in (("SOCK_STREAM", 1), ("SOCK_DGRAM", 2), ("SOCK_RAW", 3),
                      ("SOCK_NONBLOCK", 0x800), ("SOCK_CLOEXEC", 0x80000)):
        if name in text:
            if name in ("SOCK_NONBLOCK", "SOCK_CLOEXEC"):
                t |= bit
            else:
                t |= bit
    return t


def _parse_call(name, argtext):
    """Return scalar args for the calls whose args the filter inspects."""
    args = ()
    parts = [p.strip() for p in argtext.split(",")]
    if name == "socket" and len(parts) >= 3:
        dom = _DOMAIN.get(parts[0].split("|")[0].strip(), -1)
        typ = _socktype_mask(parts[1])
        p3 = parts[2]
        proto = _PROTO.get(p3, None)
        if proto is None:
            m = re.match(r"(\d+)", p3)
            proto = int(m.group(1)) if m else -1
        args = (dom, typ, proto)
    elif name == "socketpair" and len(parts) >= 3:
        dom = _DOMAIN.get(parts[0].split("|")[0].strip(), -1)
        typ = _socktype_mask(parts[1])
        args = (dom, typ, 0)
    elif name == "prctl" and parts:
        m = re.match(r"([A-Z_][A-Z0-9_]+|\d+)", parts[0])
        if m:
            opt = m.group(1)
            pr_map = {"PR_SET_NAME": 15, "PR_GET_NAME": 16,
                      "PR_SET_NO_NEW_PRIVS": 38, "PR_SET_SECCOMP": 22,
                      "PR_SET_DUMPABLE": 4, "PR_SET_KEEPCAPS": 8}
            args = (pr_map.get(opt, int(opt) if opt.isdigit() else -1),)
    elif name == "ioctl" and len(parts) >= 2:
        m = re.match(r"([A-Z_][A-Z0-9_]+|0x[0-9a-fA-F]+|\d+)", parts[1])
        if m:
            req = m.group(1)
            _ioctl_map = {"TCGETS": 0x5401, "FIOCLEX": 0x5451,
                          "TIOCGWINSZ": 0x5413, "FIONREAD": 0x541B,
                          "TCSETSW": 0x5403, "TCSETS": 0x5402,
                          "TIOCSTI": 0x5412}
            args = (_ioctl_map.get(req, int(req, 16)
                                   if req.startswith("0x")
                                   else (int(req) if req.isdigit()
                                         else -1)),)
    return args


def trace_workload(code, workdir, label):
    workload = os.path.join(workdir, label + ".py")
    trace = os.path.join(workdir, label + ".trace")
    with open(workload, "w") as f:
        f.write(code)
    proc = subprocess.run(
        ["strace", "-f", "-q", "-o", trace, sys.executable, "-I", workload],
        capture_output=True, text=True, cwd=workdir, timeout=180)
    if proc.returncode != 0:
        raise RuntimeError("workload %s failed under strace (rc=%d): %s"
                           % (label, proc.returncode,
                              proc.stderr[-1500:]))
    calls = {}  # (name, args) -> count
    with open(trace, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            m = _RESUMED_RE.match(line)
            if m:
                calls.setdefault((m.group(1), ()), 0)
                calls[(m.group(1), ())] += 1
                continue
            m = _CALL_RE.match(line)
            if not m:
                continue
            name, argtext = m.group(1), m.group(2)
            if name in ("total",):
                continue
            args = _parse_call(name, argtext)
            key = (name, args)
            calls[key] = calls.get(key, 0) + 1
    return calls


# ---------------------------------------------------------------- replay

def main():
    if shutil.which("strace") is None:
        print("FATAL: strace not on PATH", file=sys.stderr)
        return 2
    numbers = S._syscall_numbers()
    if not numbers:
        print("FATAL: no syscall numbers on this arch", file=sys.stderr)
        return 2
    arch = S._AUDIT_ARCH[S._ARCH]
    kill_blob = S._build_cage_seccomp_filter(numbers, default_action="kill")
    log_blob = S._build_cage_seccomp_filter(numbers, default_action="log")
    print("kill_blob_insns=%d log_blob_insns=%d arch=%s"
          % (len(kill_blob) // 8, len(log_blob) // 8, S._ARCH))

    workdir = tempfile.mkdtemp(prefix="gov-log-shakedown-")
    inventory = []   # one row per unique (workload, name, args)
    try:
        for label, code in WORKLOADS:
            calls = trace_workload(code, workdir, label)
            for (name, args), count in sorted(calls.items()):
                nr = numbers.get(name)
                if nr is None:
                    inventory.append({"workload": label, "name": name,
                                      "args": list(args), "count": count,
                                      "log_verdict": "NO_NUMBER",
                                      "kill_verdict": "NO_NUMBER"})
                    continue
                lv = S._bpf_decision(log_blob, arch, nr, args)
                kv = S._bpf_decision(kill_blob, arch, nr, args)
                inventory.append({
                    "workload": label, "name": name, "args": list(args),
                    "count": count,
                    "log_verdict": _VERDICT_NAMES.get(lv, hex(lv)),
                    "kill_verdict": _VERDICT_NAMES.get(kv, hex(kv)),
                })
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    # Denial inventory: everything not ALLOW under the LOG blob.
    denials = [r for r in inventory if r["log_verdict"] != "ALLOW"]
    by_shape = {}
    for r in denials:
        key = (r["name"], tuple(r["args"]), r["log_verdict"],
               r["kill_verdict"])
        by_shape.setdefault(key, {"workloads": set(), "count": 0})
        by_shape[key]["workloads"].add(r["workload"])
        by_shape[key]["count"] += r["count"]

    print("\n=== LOG-tier denial inventory (%d unique shapes) ==="
          % len(by_shape))
    for (name, args, lv, kv), info in sorted(
            by_shape.items(), key=lambda kv_: (kv_[0][0], kv_[0][1])):
        print("%-16s args=%-28s LOG->%-5s KILL->%-5s n=%-6d in %s"
              % (name, args, lv, kv, info["count"],
                 ",".join(sorted(info["workloads"]))))

    allowed_n = sum(1 for r in inventory if r["log_verdict"] == "ALLOW")
    print("\nunique (workload,name,args) evaluated: %d; ALLOW: %d; "
          "non-ALLOW under LOG: %d"
          % (len(inventory), allowed_n, len(denials)))

    out = os.path.join(_HERE, "log_tier_shakedown_inventory.json")
    with open(out, "w") as f:
        json.dump({"inventory": inventory,
                   "note": "verdicts from _bpf_decision on the exact "
                           "compiled cage bytes (kill + log blobs)"},
                  f, indent=1, sort_keys=True)
    print("wrote", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
