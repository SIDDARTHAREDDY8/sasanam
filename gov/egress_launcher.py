"""S7-stream (wave-90): filtered-egress launcher — productizing the F81 lab wall.

F136: the GCP lab validated the wall (netns ``agent0`` + default-deny
nftables + confined dnsmasq + CONNECT proxy + seccomp-BPF: 17 STOPPED /
0 BREAK across 11 attack classes), but there was no launcher, no
component pinning, and no residual threat model. This module is the
product layer on top of that validated mechanism:

1. ``WallComponentInventory`` — install-time digest pinning of the
   wall's own components (nft ruleset, proxy allowlist, DNS filter
   config, DNS zone, proxy implementation artifact, seccomp config).
   Same primitive shape as the S5 tool-definition digest inventory
   (``gov/tool_continuity.py``): canonical bytes -> sha256/sha512
   digests -> install manifest + operator-held receipt. The launcher
   re-verifies every digest at startup under an interprocess lock and
   refuses to launch on ANY mismatch. Tamper = no launch.
2. ``FilteredEgressLauncher`` — every launch (a) verifies the receipt
   -> manifest -> components chain, (b) verifies the wall reports UP
   via a ``WallStateProvider``, (c) spawns the child through the
   provider with a child-side preexec re-assertion (shrinking the
   check->spawn TOCTOU to the preexec->exec window), (d) scrubs
   proxy-env trust-wideners from the child (the F81 Wiki lesson:
   ``NO_PROXY`` suffix trust), and (e) chains audit events. Any
   failure refuses: fail-closed, never degraded.
3. Localhost fixtures — ``SimulatedWallProvider`` + ``FakePacketFilter``
   + ``StubProxyServer`` + ``StubDnsServer`` model the lab wall on
   loopback so the break battery runs at $0 with no real network and
   no privileges.

Honest boundaries (full text: ``docs/egress_wall_threat_model.md``):
the localhost fixtures model the wall's *mechanism* (allowlist
enforcement, digest pinning, fail-closed startup); they do NOT re-prove
the netns/nftables topology — the GCP lab did that (``evals/FINDINGS.md``
F81). Host root, TCB compromise (proxy/DNS), covert channels through
allowlisted destinations, and DNS answers inside the allowlist remain
documented residuals. A green battery here closes the *launcher* gap
(F136), not the universe.
"""

import fcntl
import hashlib
import json
import os
import select
import socket
import struct
import subprocess
import threading
import time

# ---------------------------------------------------------------------------
# Errors — every refusal names itself (fail-closed, never degraded).
# ---------------------------------------------------------------------------


class EgressLaunchRefused(RuntimeError):
    """The launcher refused to spawn. ``reason`` is one of:

    - ``receipt_unverifiable``  — receipt missing/unparseable, or the
      manifest's digest does not match the receipt (manifest tampered).
    - ``component_tampered``    — a pinned wall component's digest (or
      symlink target) drifted since install. ``component`` names it.
    - ``no_common_algorithm``   — manifest and verifier share no digest
      algorithm; refusing is safer than downgrading silently.
    - ``wall_not_up`` / ``wall_degraded`` — the wall provider does not
      report UP (wall down, partial wall, running-ruleset drift).
    - ``lock_unavailable``      — could not take the verify+spawn lock;
      launching unlocked would reopen the check->spawn race.
    - ``preexec_recheck_failed`` — the wall flapped between the parent
      check and the child preexec; the child aborted before exec
      (exit 99) and nothing ungoverned ran.
    """


# ---------------------------------------------------------------------------
# Digest agility — pins may carry several algorithms; the verifier uses
# the strongest algorithm present in BOTH the manifest and its own
# supported set. All listed digests must match (a mismatch in a weaker
# algorithm is still evidence of tamper, not a downgrade signal).
# ---------------------------------------------------------------------------

_ALGO_STRENGTH = {"sha256": 1, "sha512": 2}
DEFAULT_ALGOS = ("sha256", "sha512")


def _digest_bytes(data, algo):
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()


def component_digests(data, algos=DEFAULT_ALGOS):
    """Digest map for raw component bytes (follows symlinks: caller
    reads the bytes; what matters is content, plus recorded realpath)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return {a: _digest_bytes(data, a) for a in algos}


def negotiate_algo(manifest_algos, supported_algos=DEFAULT_ALGOS):
    """Strongest algorithm in both sets, or None."""
    common = set(manifest_algos or ()) & set(supported_algos or ())
    if not common:
        return None
    return max(common, key=lambda a: _ALGO_STRENGTH.get(a, 0))


MANIFEST_FORMAT = "egress-wall-pins/1"
RECEIPT_FORMAT = "egress-wall-receipt/1"

# The wall's pinned components. A deployment maps each name to the real
# artifact path (e.g. /etc/agent-wall/agent0.nft); the localhost
# fixtures map them into the sim dir (see install_simulated_wall).
WALL_COMPONENTS = (
    "nft_ruleset",      # default-deny ruleset (desired state)
    "proxy_allowlist",  # the entire outside world, host:port per line
    "dns_config",       # confined-resolver config (no-rebind etc.)
    "dns_zone",         # authoritative zone data for allowlisted names
    "proxy_impl",       # proxy implementation artifact / policy descriptor
    "seccomp_config",   # seccomp-BPF policy (blocked calls)
)


class WallComponentInventory:
    """Install-time pinning + startup verification of wall components.

    Install (operator, privileged, reviewed): ``install()`` digests each
    component file, writes the manifest, and writes the receipt — the
    operator-held trust anchor binding the manifest bytes. Verify
    (launcher, every launch): receipt -> manifest -> components.
    """

    def __init__(self, manifest_path, receipt_path,
                 supported_algos=DEFAULT_ALGOS):
        self.manifest_path = str(manifest_path)
        self.receipt_path = str(receipt_path)
        self.supported_algos = tuple(supported_algos)

    # -- install ------------------------------------------------------
    @staticmethod
    def install(component_paths, manifest_path, receipt_path,
                algos=DEFAULT_ALGOS):
        """Pin components. ``component_paths``: name -> filesystem path.

        Returns the manifest dict. Writes manifest JSON then the
        receipt (sha256 over the exact manifest bytes).
        """
        algos = tuple(algos)
        if not algos:
            raise ValueError("install requires at least one digest algo")
        entries = []
        for name in WALL_COMPONENTS:
            path = component_paths.get(name)
            if not path:
                raise ValueError("missing component path: %s" % name)
            st = os.lstat(path)
            is_link = os.path.islink(path)
            with open(path, "rb") as f:
                data = f.read()
            entries.append({
                "name": name,
                "path": os.path.abspath(path),
                "realpath": os.path.realpath(path),
                "is_symlink": bool(is_link),
                "size": len(data),
                "digests": component_digests(data, algos),
            })
        manifest = {
            "format": MANIFEST_FORMAT,
            "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                          time.gmtime()),
            "algos": list(algos),
            "components": entries,
        }
        blob = json.dumps(manifest, sort_keys=True, indent=2,
                          ensure_ascii=True).encode("utf-8")
        with open(manifest_path, "wb") as f:
            f.write(blob)
        receipt = {
            "format": RECEIPT_FORMAT,
            "manifest_sha256": _digest_bytes(blob, "sha256"),
            "installed_at": manifest["installed_at"],
        }
        with open(receipt_path, "w", encoding="utf-8") as f:
            json.dump(receipt, f, sort_keys=True, indent=2)
        return manifest

    # -- verify -------------------------------------------------------
    def _load_receipt(self):
        try:
            with open(self.receipt_path, "r", encoding="utf-8") as f:
                receipt = json.load(f)
        except (OSError, ValueError) as e:
            raise EgressLaunchRefused(
                "receipt_unverifiable: %s" % e)
        if not isinstance(receipt, dict) or \
                receipt.get("format") != RECEIPT_FORMAT:
            raise EgressLaunchRefused("receipt_unverifiable: bad format")
        return receipt

    def _load_manifest(self, receipt):
        try:
            with open(self.manifest_path, "rb") as f:
                blob = f.read()
        except OSError as e:
            raise EgressLaunchRefused(
                "receipt_unverifiable: manifest unreadable: %s" % e)
        if _digest_bytes(blob, "sha256") != receipt.get("manifest_sha256"):
            raise EgressLaunchRefused(
                "receipt_unverifiable: manifest digest != receipt "
                "(manifest tampered or replaced)")
        try:
            manifest = json.loads(blob.decode("utf-8"))
        except ValueError as e:
            raise EgressLaunchRefused(
                "receipt_unverifiable: manifest not JSON: %s" % e)
        if not isinstance(manifest, dict) or \
                manifest.get("format") != MANIFEST_FORMAT:
            raise EgressLaunchRefused(
                "receipt_unverifiable: bad manifest format")
        return manifest

    def verify(self):
        """Full chain verification. Returns (manifest, per-component
        digests). Raises EgressLaunchRefused on ANY failure."""
        receipt = self._load_receipt()
        manifest = self._load_manifest(receipt)
        algos = manifest.get("algos") or []
        if negotiate_algo(algos, self.supported_algos) is None:
            raise EgressLaunchRefused(
                "no_common_algorithm: manifest=%r supported=%r"
                % (algos, list(self.supported_algos)))
        checked = {}
        for entry in manifest.get("components", []):
            name = entry.get("name")
            path = entry.get("path")
            if not name or not path:
                raise EgressLaunchRefused(
                    "component_tampered: manifest entry malformed")
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except OSError:
                raise EgressLaunchRefused(
                    "component_tampered: %s absent (%s)" % (name, path))
            # Symlink-shape check: a symlink swapped to a different
            # target with identical bytes is still a deployment change
            # worth refusing on (defense in depth; the digest is the
            # primary signal).
            if os.path.realpath(path) != entry.get("realpath"):
                raise EgressLaunchRefused(
                    "component_tampered: %s symlink target changed "
                    "(%s -> %s)" % (name, entry.get("realpath"),
                                    os.path.realpath(path)))
            if os.path.islink(path) != bool(entry.get("is_symlink")):
                raise EgressLaunchRefused(
                    "component_tampered: %s symlink shape changed" % name)
            want = entry.get("digests") or {}
            for algo in algos:
                if algo not in self.supported_algos:
                    continue
                got = _digest_bytes(data, algo)
                if want.get(algo) != got:
                    raise EgressLaunchRefused(
                        "component_tampered: %s digest mismatch (%s)"
                        % (name, algo))
            checked[name] = {a: want.get(a) for a in algos
                             if a in self.supported_algos}
        return manifest, checked


# ---------------------------------------------------------------------------
# Wall state — UP / DOWN / DEGRADED, and the provider interface.
# ---------------------------------------------------------------------------

WALL_UP = "UP"
WALL_DOWN = "DOWN"
WALL_DEGRADED = "DEGRADED"


class WallStateReport:
    def __init__(self, state, detail=None):
        self.state = state
        self.detail = dict(detail or {})

    def ok(self):
        return self.state == WALL_UP

    def __repr__(self):
        return "WallStateReport(%s, %r)" % (self.state, self.detail)


class WallStateProvider:
    """How the launcher observes the wall. Production: netns/nftables/
    listener checks. Tests: the simulated provider below."""

    def check(self):
        """Return a WallStateReport. Must be cheap and side-effect free."""
        raise NotImplementedError

    def child_recheck(self):
        """Re-run inside the child preexec (after fork, before exec).
        Raise EgressLaunchRefused (or return False) to abort the child."""
        report = self.check()
        if not report.ok():
            raise EgressLaunchRefused(
                "preexec_recheck_failed: wall %s (%r)"
                % (report.state, report.detail))
        return True

    def describe(self):
        return {"provider": type(self).__name__}

    def child_env_extra(self):
        """Extra env vars injected into every launched child (e.g. the
        in-wall proxy endpoint). Production returns the well-known
        in-netns addresses; the sim reads endpoints.json."""
        return {}


# ---------------------------------------------------------------------------
# Localhost fixtures: the simulated wall.
#
# The sim models the LAB wall's mechanism on 127.0.0.1 with ephemeral
# ports (no privileges, no real netns):
#   - nft_state.txt        "running ruleset" (fake iptables state);
#                          symbolic ALLOW lines resolved via endpoints.json
#   - wall_up.flag         operator-set liveness marker
#   - StubDnsServer        confined resolver: authoritative for the
#                          pinned zone only, NXDOMAIN otherwise
#   - StubProxyServer      CONNECT + absolute-form proxy enforcing the
#                          pinned allowlist, resolving ONLY via the stub
#                          DNS (the lab's A5 bug fix, reproduced here)
# The sim does NOT model the IP-layer drop with real packets — the
# FakePacketFilter parses the pinned ruleset and answers would_drop()
# for any tuple; the real IP-layer enforcement was lab-validated.
# ---------------------------------------------------------------------------

SIM_PROXY_HOST = "127.0.0.1"
SIM_DNS_HOST = "127.0.0.1"

# Child-visible marker: the sim cannot put the child in a real netns,
# so the marker + scrubbed env + proxy-only routing is the sim's
# "inside the wall" notion. The battery asserts the marker is set and
# the env is scrubbed.
WALL_ACTIVE_ENV = "EGRESS_WALL_ACTIVE"
WALL_ID_ENV = "EGRESS_WALL_ID"

# Proxy-env names the launcher scrubs from the child (F81 Wiki lesson:
# a child-controlled NO_PROXY must never widen operator trust).
_PROXY_ENV_NAMES = ("http_proxy", "https_proxy", "all_proxy", "no_proxy",
                    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")

# Distinctive child exit code when the preexec re-assert aborts the
# child before exec: observable by the parent, never a real exit code
# of a launched workload.
PREEXEC_ABORT_CODE = 99


def install_simulated_wall(sim_dir, *, algos=DEFAULT_ALGOS,
                           wall_id="sim-wall-1"):
    """Create a simulated wall install: components + manifest + receipt.

    Returns (inventory, paths dict). The caller starts the stub servers
    (see SimulatedWallFixture) which write endpoints.json and
    wall_up.flag.
    """
    sim_dir = os.path.abspath(sim_dir)
    conf_dir = os.path.join(sim_dir, "conf")
    run_dir = os.path.join(sim_dir, "run")
    os.makedirs(conf_dir, exist_ok=True)
    os.makedirs(run_dir, exist_ok=True)

    def w(name, text):
        p = os.path.join(conf_dir, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    # The "running ruleset" is a separate file from the pinned desired
    # state: the launcher checks that the RUNNING wall matches the PIN.
    # Symbolic service names (wall:proxy / wall:dns) are resolved via
    # endpoints.json so ephemeral ports do not churn the digest.
    # Transport note: the lab wall allowed UDP+TCP/53; this fixture's
    # confined DNS speaks DNS-over-TCP (RFC 7766) because the build
    # environment's seccomp blocks the sendto() syscall. The modeled
    # mechanism (allowlisted answers only) is transport-independent.
    nft_ruleset = w("agent0.nft.sim",
                    "# simulated default-deny egress wall (desired state)\n"
                    "# production: nftables inside netns agent0; here the\n"
                    "# FakePacketFilter enforces the same semantics.\n"
                    "ALLOW tcp wall:dns   # confined DNS only (sim: TCP)\n"
                    "ALLOW tcp wall:proxy # egress proxy only\n"
                    "DROP  *              # everything else\n")
    with open(nft_ruleset, encoding="utf-8") as src:
        desired = src.read()
    with open(os.path.join(run_dir, "nft_state.txt"), "w",
              encoding="utf-8") as f:
        f.write(desired)

    allowlist = w("allowlist.txt",
                  "# the entire outside world (sim)\n"
                  "example.com:443\n"
                  "example.com:80\n")
    dns_config = w("dns_config.txt",
                   "# confined-resolver config (simulates dnsmasq.conf)\n"
                   "stop-dns-rebind\n"
                   "cache-size=0\n"
                   "forward-only-allowlisted\n")
    dns_zone = w("dns_hosts.txt",
                 "# authoritative zone: allowlisted names only.\n"
                 "# Everything else -> NXDOMAIN (no answer = no connect).\n"
                 "example.com 127.0.0.1\n")
    proxy_impl = w("proxy_impl.txt",
                   "# proxy enforcement-policy descriptor.\n"
                   "# PRODUCTION: pin the deployed proxy artifact bytes.\n"
                   "mode=CONNECT-and-absolute-form-only\n"
                   "resolver=confined-only\n"
                   "default=deny-with-log\n")
    seccomp_config = w("seccomp_config.txt",
                       "# seccomp-BPF policy descriptor (sim).\n"
                       "# PRODUCTION: pin the deployed BPF/profile bytes.\n"
                       "deny=socket(AF_PACKET) socket(SOCK_RAW) "
                       "unshare(CLONE_NEWNET) setns\n")

    manifest_path = os.path.join(sim_dir, "wall_pins.json")
    receipt_path = os.path.join(sim_dir, "wall_receipt.json")
    WallComponentInventory.install(
        {"nft_ruleset": nft_ruleset,
         "proxy_allowlist": allowlist,
         "dns_config": dns_config,
         "dns_zone": dns_zone,
         "proxy_impl": proxy_impl,
         "seccomp_config": seccomp_config},
        manifest_path, receipt_path, algos=algos)
    with open(os.path.join(sim_dir, "wall_id.txt"), "w",
              encoding="utf-8") as f:
        f.write(wall_id + "\n")
    paths = {"manifest": manifest_path, "receipt": receipt_path,
             "conf_dir": conf_dir, "run_dir": run_dir,
             "allowlist": allowlist, "nft_ruleset": nft_ruleset,
             "dns_zone": dns_zone, "wall_id": wall_id}
    return (WallComponentInventory(manifest_path, receipt_path), paths)


# ---------------------------------------------------------------------------
# FakePacketFilter — parses the pinned ruleset; answers would_drop().
# ---------------------------------------------------------------------------

class FakePacketFilter:
    """The sim's IP-layer model, parsed from the pinned ruleset text.

    In production this layer is nftables inside the netns (lab
    validated). Here the battery asserts the *model* drops exfil tuples;
    the proxy stub (real sockets) refuses them for real.
    """

    def __init__(self, ruleset_text, endpoints):
        self.rules = []  # (proto, host, port)
        eps = endpoints or {}
        sym = {"wall:proxy": (SIM_PROXY_HOST,
                              eps.get("proxy", [None, None])[1]),
               "wall:dns": (SIM_DNS_HOST,
                            eps.get("dns", [None, None])[1])}
        for line in ruleset_text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line.startswith("ALLOW"):
                continue
            parts = line.split()
            if len(parts) != 3:
                continue
            _, proto, target = parts
            if target in sym:
                host, port = sym[target]
            elif ":" in target:
                host, _, port = target.rpartition(":")
                port = int(port)
            else:
                continue
            self.rules.append((proto.lower(), host, port))

    def would_drop(self, host, port, proto="tcp"):
        for rproto, rhost, rport in self.rules:
            if rproto == proto.lower() and rhost == host \
                    and rport == port:
                return False
        return True


# ---------------------------------------------------------------------------
# StubDnsServer — confined resolver: pinned zone only, NXDOMAIN otherwise.
# ---------------------------------------------------------------------------

def _dns_encode_name(name):
    out = b""
    for part in name.rstrip(".").split("."):
        out += bytes([len(part)]) + part.encode("ascii")
    return out + b"\x00"


def _dns_decode_name(buf, off):
    parts = []
    while True:
        ln = buf[off]
        off += 1
        if ln == 0:
            break
        parts.append(buf[off:off + ln].decode("ascii", "replace"))
        off += ln
    return ".".join(parts), off


def dns_query(host, port, name, timeout=3.0):
    """Minimal DNS client: A query, returns IPv4 string or None.

    Transport note: DNS-over-TCP (RFC 7766) with the 2-byte length
    prefix. The lab used real dnsmasq over UDP; this environment's
    seccomp blocks the sendto() syscall, so the localhost fixture
    speaks TCP. The modeled mechanism — authoritative answers for the
    pinned zone only, NXDOMAIN otherwise, no-answer-means-no-connect —
    is transport-independent.
    """
    txid = os.urandom(2)
    q = (txid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         + _dns_encode_name(name) + b"\x00\x01\x00\x01")
    pkt = struct.pack(">H", len(q)) + q
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(pkt)
        hdr = b""
        while len(hdr) < 2:
            chunk = s.recv(2 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
        (rlen,) = struct.unpack(">H", hdr)
        data = b""
        while len(data) < rlen:
            chunk = s.recv(rlen - len(data))
            if not chunk:
                return None
            data += chunk
    except OSError:
        return None
    finally:
        s.close()
    if len(data) < 12 or data[0:2] != txid:
        return None
    ancount = struct.unpack(">H", data[6:8])[0]
    if ancount == 0:
        return None
    try:
        _, off = _dns_decode_name(data, 12)
    except (IndexError, struct.error):
        return None
    off += 4  # qtype+qclass
    try:
        while off + 10 <= len(data):
            if data[off] & 0xC0 == 0xC0:
                off += 2
            else:
                _, off = _dns_decode_name(data, off)
            atype, aclass, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            off += rdlen
            if atype == 1 and aclass == 1 and rdlen == 4:
                return socket.inet_ntoa(rdata)
    except (IndexError, struct.error):
        return None
    return None


class StubDnsServer(threading.Thread):
    """Authoritative DNS for the pinned zone file only (TCP transport;
    see dns_query for why the fixture uses DNS-over-TCP)."""

    def __init__(self, zone_path, log_path=None):
        super().__init__(daemon=True)
        self.zone_path = zone_path
        self.log_path = log_path
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((SIM_DNS_HOST, 0))
        self._sock.listen(32)
        self.port = self._sock.getsockname()[1]
        self._stop_event = threading.Event()

    def _zone(self):
        zone = {}
        try:
            with open(self.zone_path, encoding="utf-8") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) == 2:
                        zone[parts[0].lower().rstrip(".")] = parts[1]
        except OSError:
            pass
        return zone

    def _log(self, line):
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def run(self):
        self._sock.settimeout(0.2)
        while not self._stop_event.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._answer, args=(conn,),
                                 daemon=True)
            t.start()

    def _answer(self, conn):
        try:
            conn.settimeout(3.0)
            hdr = b""
            while len(hdr) < 2:
                chunk = conn.recv(2 - len(hdr))
                if not chunk:
                    return
                hdr += chunk
            (qlen,) = struct.unpack(">H", hdr)
            data = b""
            while len(data) < qlen:
                chunk = conn.recv(qlen - len(data))
                if not chunk:
                    return
                data += chunk
            if len(data) < 12:
                return
            txid = data[0:2]
            try:
                qname, _ = _dns_decode_name(data, 12)
            except (IndexError, struct.error):
                return
            ip = self._zone().get(qname.lower())
            if ip:
                flags = b"\x81\x80"
                ancount = b"\x00\x01"
                answer = (b"\xc0\x0c" + b"\x00\x01\x00\x01"
                          + b"\x00\x00\x00\x00" + b"\x00\x04"
                          + socket.inet_aton(ip))
                self._log("ALLOW-DNS %s -> %s" % (qname, ip))
            else:
                flags = b"\x81\x83"  # NXDOMAIN
                ancount = b"\x00\x00"
                answer = b""
                self._log("DENY-DNS %s NXDOMAIN" % qname)
            resp = (txid + flags + b"\x00\x01" + ancount
                    + b"\x00\x00\x00\x00" + data[12:] + answer)
            conn.sendall(struct.pack(">H", len(resp)) + resp)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop_event.set()
        try:
            self._sock.close()
        except OSError:
            pass
        # Join the accept loop: a thread blocked in accept() holds a
        # reference to the file description, so the port is only freed
        # once the thread observes the close/event and exits. Without
        # the join, an immediate rebind races the 0.2s accept timeout
        # and fails with EADDRINUSE (observed in the battery).
        self.join(timeout=5)


# ---------------------------------------------------------------------------
# StubProxyServer — CONNECT + absolute-form, pinned allowlist, confined
# resolver ONLY (the lab's A5 fix: never the host resolver).
# ---------------------------------------------------------------------------

class StubProxyServer(threading.Thread):
    def __init__(self, allowlist_path, dns_host, dns_port,
                 deny_log_path=None):
        super().__init__(daemon=True)
        self.allowlist_path = allowlist_path
        self.dns_host = dns_host
        self.dns_port = dns_port
        self.deny_log_path = deny_log_path
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((SIM_PROXY_HOST, 0))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(64)
        self._stop_event = threading.Event()

    def _allowlist(self):
        allowed = set()
        try:
            with open(self.allowlist_path, encoding="utf-8") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip().lower()
                    if line:
                        allowed.add(line)
        except OSError:
            pass
        return allowed

    def _deny(self, line):
        if self.deny_log_path:
            with open(self.deny_log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def _relay(self, a, b):
        a.setblocking(False)
        b.setblocking(False)
        pair = {a: b, b: a}
        try:
            while True:
                r, _, _ = select.select([a, b], [], [], 10.0)
                if not r:
                    break
                for s in r:
                    try:
                        data = s.recv(65536)
                    except OSError:
                        return
                    if not data:
                        return
                    try:
                        pair[s].sendall(data)
                    except OSError:
                        return
        finally:
            for s in (a, b):
                try:
                    s.close()
                except OSError:
                    pass

    def _handle(self, conn):
        try:
            conn.settimeout(5.0)
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                head += chunk
            try:
                request_line = head.split(b"\r\n", 1)[0].decode(
                    "ascii", "replace")
                method, target, _ = request_line.split(" ", 2)
            except ValueError:
                return
            method = method.upper()
            if method == "CONNECT":
                hostport = target
                path_suffix = b""
            elif target.startswith("http://"):
                rest = target[len("http://"):]
                hostport, _, suffix = rest.partition("/")
                path_suffix = b"/" + suffix.encode("ascii", "replace")
            else:
                conn.sendall(b"HTTP/1.1 400 bad request\r\n\r\n")
                self._deny("DENY-PROXY malformed %r" % target)
                return
            if ":" in hostport:
                host, _, port_s = hostport.rpartition(":")
            else:
                host, port_s = hostport, "80"
            try:
                port = int(port_s)
            except ValueError:
                port = -1
            key = "%s:%d" % (host.lower(), port)
            if key not in self._allowlist():
                conn.sendall(b"HTTP/1.1 403 denied by egress wall\r\n\r\n")
                self._deny("DENY-CONNECT %s" % key)
                return
            # Confined resolution ONLY — never the host resolver.
            ip = dns_query(self.dns_host, self.dns_port, host.lower())
            if not ip:
                conn.sendall(b"HTTP/1.1 502 no confined answer\r\n\r\n")
                self._deny("DENY-NOANSWER %s" % key)
                return
            try:
                up = socket.create_connection((ip, port), timeout=5.0)
            except OSError:
                conn.sendall(b"HTTP/1.1 502 upstream refused\r\n\r\n")
                self._deny("DENY-UPSTREAM %s" % key)
                return
            if method == "CONNECT":
                conn.sendall(b"HTTP/1.1 200 established\r\n\r\n")
                self._relay(conn, up)
            else:
                up.sendall(b"GET " + path_suffix + b" HTTP/1.0\r\n"
                            b"Host: " + host.encode("ascii", "replace")
                            + b"\r\n\r\n")
                self._relay(up, conn)
        except OSError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def run(self):
        self._sock.settimeout(0.2)
        while not self._stop_event.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle, args=(conn,),
                                 daemon=True)
            t.start()

    def stop(self):
        self._stop_event.set()
        try:
            self._sock.close()
        except OSError:
            pass
        # Join the accept loop: a thread blocked in accept() holds a
        # reference to the file description, so the port is only freed
        # once the thread observes the close/event and exits. Without
        # the join, an immediate rebind races the 0.2s accept timeout
        # and fails with EADDRINUSE (observed in the battery).
        self.join(timeout=5)


# ---------------------------------------------------------------------------
# SimulatedWallProvider — the launcher's view of the sim wall.
# ---------------------------------------------------------------------------

class SimulatedWallProvider(WallStateProvider):
    """Wall-state checks against the localhost fixture.

    UP requires ALL of: the operator liveness flag, the RUNNING ruleset
    digest matching the PINNED digest (live-wall drift detection), a TCP
    handshake to the proxy stub, and a confined-DNS probe answer.
    Anything less is DOWN/DEGRADED — and the launcher refuses either
    way (fail-closed); the distinction is diagnostic only.
    """

    def __init__(self, sim_dir, inventory, probe_name="example.com"):
        self.sim_dir = os.path.abspath(sim_dir)
        self.inventory = inventory
        self.probe_name = probe_name

    def _endpoints(self):
        p = os.path.join(self.sim_dir, "endpoints.json")
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _pinned_ruleset_digest(self, algo="sha256"):
        manifest, _ = self.inventory.verify()
        for e in manifest["components"]:
            if e["name"] == "nft_ruleset":
                return e["digests"][algo]
        return None

    def check(self):
        eps = self._endpoints()
        proxy_ep = eps.get("proxy")
        dns_ep = eps.get("dns")
        if not os.path.exists(os.path.join(self.sim_dir, "run",
                                            "wall_up.flag")):
            return WallStateReport(WALL_DOWN,
                                   {"missing": "wall_up.flag"})
        try:
            with open(os.path.join(self.sim_dir, "run",
                                   "nft_state.txt"), "rb") as f:
                running = f.read()
        except OSError:
            return WallStateReport(WALL_DOWN,
                                   {"missing": "run/nft_state.txt"})
        try:
            pinned = self._pinned_ruleset_digest()
        except EgressLaunchRefused as e:
            return WallStateReport(WALL_DOWN, {"pin_verify": str(e)})
        if pinned is None or _digest_bytes(running, "sha256") != pinned:
            return WallStateReport(WALL_DEGRADED,
                                   {"running_ruleset_drift": True})
        missing = []
        if not proxy_ep:
            missing.append("proxy endpoint")
        else:
            try:
                s = socket.create_connection(tuple(proxy_ep), timeout=2.0)
                s.close()
            except OSError:
                missing.append("proxy unreachable")
        if not dns_ep:
            missing.append("dns endpoint")
        else:
            ans = dns_query(dns_ep[0], dns_ep[1], self.probe_name,
                            timeout=2.0)
            if ans is None:
                missing.append("dns probe failed")
        if missing:
            return WallStateReport(WALL_DEGRADED, {"missing": missing})
        return WallStateReport(WALL_UP, {"proxy": proxy_ep, "dns": dns_ep})

    def describe(self):
        return {"provider": "SimulatedWallProvider",
                "sim_dir": self.sim_dir}

    def child_env_extra(self):
        eps = self._endpoints()
        extra = {}
        if eps.get("proxy"):
            extra["EGRESS_PROXY_ADDR"] = "%s:%d" % tuple(eps["proxy"])
        if eps.get("dns"):
            extra["EGRESS_DNS_ADDR"] = "%s:%d" % tuple(eps["dns"])
        return extra


class FlappingWallProvider(SimulatedWallProvider):
    """Test hook: first check() is UP, every later check is DOWN.

    Models the wall dying in the check->spawn window; the child-side
    preexec re-assert must catch it (exit 99, nothing exec'd).
    """

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._checks = 0

    def check(self):
        self._checks += 1
        if self._checks == 1:
            return WallStateReport(WALL_UP, {"flap": "first-check"})
        return WallStateReport(WALL_DOWN, {"flap": "wall died mid-launch"})


class SimulatedWallFixture:
    """Context manager: starts stub DNS + proxy + origin, writes
    endpoints.json and wall_up.flag. Yields self."""

    def __init__(self, sim_dir, inventory=None, origin_body=b"ok\n"):
        self.sim_dir = os.path.abspath(sim_dir)
        self.inventory = inventory
        self.origin_body = origin_body
        self.dns = None
        self.proxy = None
        self._origin_sock = None
        self._origin_thread = None
        self._origin_stop = threading.Event()
        self.proxy_port = None
        self.dns_port = None

    def __enter__(self):
        return self.start_fixed()

    def __exit__(self, *exc):
        self._origin_stop.set()
        for srv in (self.dns, self.proxy):
            if srv is not None:
                srv.stop()
        if self._origin_sock is not None:
            try:
                self._origin_sock.close()
            except OSError:
                pass
        # Same accept()-holds-the-port reason as StubDnsServer.stop:
        # join the origin thread so the port is deterministically free.
        if self._origin_thread is not None:
            self._origin_thread.join(timeout=5)
            self._origin_thread = None
        flag = os.path.join(self.sim_dir, "run", "wall_up.flag")
        try:
            os.remove(flag)
        except OSError:
            pass
        return False

    # -- the port problem, solved honestly ---------------------------
    # DNS maps names -> IPs, not ports; the allowlist pins host:port.
    # For the sim the origin MUST listen on the allowlisted port, so the
    # fixture binds fixed loopback ports chosen from a private range and
    # retries on collision. The pinned nft_state uses symbolic
    # wall:proxy / wall:dns names resolved via endpoints.json, so fixed
    # ports do not churn digests.

    FIXED_PROXY_PORT = 18443
    FIXED_DNS_PORT = 15353
    FIXED_ORIGIN_PORT = 18080

    def start_fixed(self):
        """Bind stubs on fixed ports; write endpoints.json + flag."""
        zone_path = os.path.join(self.sim_dir, "conf", "dns_hosts.txt")
        allow_path = os.path.join(self.sim_dir, "conf", "allowlist.txt")

        # DNS (TCP) fixed bind.
        dns = StubDnsServer.__new__(StubDnsServer)
        threading.Thread.__init__(dns, daemon=True)
        dns.zone_path = zone_path
        dns.log_path = os.path.join(self.sim_dir, "dns.log")
        dns._stop_event = threading.Event()
        for p in range(self.FIXED_DNS_PORT, self.FIXED_DNS_PORT + 50):
            try:
                dns._sock = socket.socket(socket.AF_INET,
                                          socket.SOCK_STREAM)
                dns._sock.setsockopt(socket.SOL_SOCKET,
                                     socket.SO_REUSEADDR, 1)
                dns._sock.bind((SIM_DNS_HOST, p))
                dns._sock.listen(32)
                dns.port = p
                break
            except OSError:
                continue
        else:
            raise RuntimeError("no free DNS port")
        dns.start()
        self.dns = dns

        # Origin on the allowlisted port (example.com:443 -> here is
        # impossible unprivileged; the sim allowlist uses :18080).
        allow_path_fixed = allow_path
        with open(allow_path_fixed, "w", encoding="utf-8") as f:
            f.write("# the entire outside world (sim)\n"
                    "example.com:%d\n" % self.FIXED_ORIGIN_PORT)
        # NOTE: rewriting the allowlist AFTER install changes its
        # digest -> the fixture re-pins (install-time action, operator).
        # See SimulatedWallFixture.repin_allowlist.
        self._origin_stop = threading.Event()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((SIM_PROXY_HOST, self.FIXED_ORIGIN_PORT))
        srv.listen(16)
        self._origin_sock = srv

        def serve():
            srv.settimeout(0.2)
            body = self.origin_body
            while not self._origin_stop.is_set():
                try:
                    c, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    c.settimeout(3.0)
                    c.recv(65536)
                    c.sendall(b"HTTP/1.0 200 ok\r\nContent-Length: "
                              + str(len(body)).encode("ascii") + b"\r\n\r\n"
                              + body)
                except OSError:
                    pass
                finally:
                    c.close()

        self._origin_thread = threading.Thread(target=serve, daemon=True)
        self._origin_thread.start()

        # Proxy on a fixed port.
        proxy = StubProxyServer.__new__(StubProxyServer)
        threading.Thread.__init__(proxy, daemon=True)
        proxy.allowlist_path = allow_path
        proxy.dns_host = SIM_DNS_HOST
        proxy.dns_port = dns.port
        proxy.deny_log_path = os.path.join(self.sim_dir,
                                           "proxy_deny.log")
        proxy._stop_event = threading.Event()
        for p in range(self.FIXED_PROXY_PORT, self.FIXED_PROXY_PORT + 50):
            try:
                proxy._sock = socket.socket(socket.AF_INET,
                                            socket.SOCK_STREAM)
                proxy._sock.setsockopt(socket.SOL_SOCKET,
                                       socket.SO_REUSEADDR, 1)
                proxy._sock.bind((SIM_PROXY_HOST, p))
                proxy.port = p
                proxy._sock.listen(64)
                break
            except OSError:
                continue
        else:
            raise RuntimeError("no free proxy port")
        proxy.start()
        self.proxy = proxy

        with open(os.path.join(self.sim_dir, "endpoints.json"), "w",
                  encoding="utf-8") as f:
            json.dump({"proxy": [SIM_PROXY_HOST, proxy.port],
                       "dns": [SIM_DNS_HOST, dns.port],
                       "origin": [SIM_PROXY_HOST,
                                  self.FIXED_ORIGIN_PORT]}, f)
        with open(os.path.join(self.sim_dir, "run", "wall_up.flag"),
                  "w", encoding="utf-8") as f:
            f.write("up\n")
        self.proxy_port = proxy.port
        self.dns_port = dns.port
        return self

    def provider(self):
        return SimulatedWallProvider(self.sim_dir, self.inventory)

    def packet_filter(self):
        with open(os.path.join(self.sim_dir, "run", "nft_state.txt"),
                  encoding="utf-8") as f:
            rules = f.read()
        with open(os.path.join(self.sim_dir, "endpoints.json"),
                  encoding="utf-8") as f:
            eps = json.load(f)
        return FakePacketFilter(rules, eps)


def repin_after_fixture_fixup(sim_dir, *, algos=DEFAULT_ALGOS):
    """Re-pin the manifest after the fixture rewrites the allowlist to
    the bound origin port. This is an INSTALL-TIME operator action (the
    allowlist content is deployment data); the battery calls it once
    per fresh sim dir before any launch, so digest verification still
    covers every later tamper."""
    sim_dir = os.path.abspath(sim_dir)
    conf = os.path.join(sim_dir, "conf")
    manifest_path = os.path.join(sim_dir, "wall_pins.json")
    receipt_path = os.path.join(sim_dir, "wall_receipt.json")
    WallComponentInventory.install(
        {"nft_ruleset": os.path.join(conf, "agent0.nft.sim"),
         "proxy_allowlist": os.path.join(conf, "allowlist.txt"),
         "dns_config": os.path.join(conf, "dns_config.txt"),
         "dns_zone": os.path.join(conf, "dns_hosts.txt"),
         "proxy_impl": os.path.join(conf, "proxy_impl.txt"),
         "seccomp_config": os.path.join(conf, "seccomp_config.txt")},
        manifest_path, receipt_path, algos=algos)
    return WallComponentInventory(manifest_path, receipt_path)


# ---------------------------------------------------------------------------
# The launcher.
# ---------------------------------------------------------------------------

class FilteredEgressLauncher:
    """Spawn processes behind the filtered-egress wall, fail-closed.

    Every launch: take the interprocess lock -> verify receipt ->
    manifest -> components -> wall state UP -> spawn with child-side
    preexec re-assert + scrubbed env. Any step failing raises
    EgressLaunchRefused and (when audit is set) chains a refusal event.
    """

    def __init__(self, *, manifest_path, receipt_path, wall_provider,
                 audit=None, lock_path=None,
                 supported_algos=DEFAULT_ALGOS):
        self.inventory = WallComponentInventory(
            manifest_path, receipt_path,
            supported_algos=supported_algos)
        self.wall = wall_provider
        self.audit = audit
        self.lock_path = (lock_path or str(manifest_path) + ".lock")
        self._wall_id = self._read_wall_id(manifest_path)

    @staticmethod
    def _read_wall_id(manifest_path):
        try:
            sib = os.path.join(os.path.dirname(os.path.abspath(
                manifest_path)), "wall_id.txt")
            with open(sib, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return "unknown"

    # -- audit -------------------------------------------------------
    def _emit(self, event):
        if self.audit is None:
            return
        try:
            self.audit(event)
        except Exception:
            pass  # audit failure must not open the wall; the
            # refusal/launch already happened — fail-closed stands.

    # -- verify (no spawn) -------------------------------------------
    def verify(self):
        """Run the receipt->manifest->components chain. Returns
        (manifest, checked). Raises EgressLaunchRefused."""
        return self.inventory.verify()

    # -- launch ------------------------------------------------------
    def _child_env(self, extra):
        env = {}
        if extra:
            env.update(extra)
        for name in _PROXY_ENV_NAMES:
            env.pop(name, None)
        env.update(self.wall.child_env_extra())
        env[WALL_ACTIVE_ENV] = "1"
        env[WALL_ID_ENV] = self._wall_id
        return env

    def _preexec(self):
        provider = self.wall

        def _child():
            try:
                provider.child_recheck()
            except Exception as e:  # noqa: BLE001 - child must die
                # loud, on any re-assert failure, before exec.
                try:
                    os.write(2, ("EGRESS-WALL preexec abort: %s\n"
                                 % e).encode("utf-8", "replace"))
                except OSError:
                    pass
                os._exit(PREEXEC_ABORT_CODE)
        return _child

    def launch(self, argv, *, env=None, **popen_kw):
        """Spawn argv behind the wall. Returns the Popen object.

        Raises EgressLaunchRefused (fail-closed) instead of spawning
        whenever the wall cannot be verified.
        """
        lock_fh = open(self.lock_path, "a+b")
        try:
            try:
                fcntl.flock(lock_fh.fileno(),
                            fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                self._emit({"event": "egress_wall_launch_refused",
                            "reason": "lock_unavailable",
                            "wall_id": self._wall_id})
                raise EgressLaunchRefused("lock_unavailable: another "
                                          "launch holds the wall lock")
            # 1. component chain, under the lock.
            try:
                manifest, checked = self.inventory.verify()
            except EgressLaunchRefused as e:
                self._emit({"event": "egress_wall_launch_refused",
                            "reason": str(e).split(":")[0],
                            "detail": str(e),
                            "wall_id": self._wall_id})
                raise
            # 2. wall state.
            report = self.wall.check()
            if not report.ok():
                reason = ("wall_not_up" if report.state == WALL_DOWN
                          else "wall_degraded")
                self._emit({"event": "egress_wall_launch_refused",
                            "reason": reason,
                            "wall_state": report.state,
                            "wall_detail": report.detail,
                            "wall_id": self._wall_id})
                raise EgressLaunchRefused(
                    "%s: %r" % (reason, report.detail))
            # 3. spawn with child-side re-assert.
            popen_kw = dict(popen_kw)
            popen_kw["env"] = self._child_env(env)
            popen_kw["preexec_fn"] = self._preexec()
            try:
                proc = subprocess.Popen(argv, **popen_kw)
            except OSError as e:
                self._emit({"event": "egress_wall_launch_refused",
                            "reason": "spawn_failed",
                            "detail": str(e),
                            "wall_id": self._wall_id})
                raise EgressLaunchRefused("spawn_failed: %s" % e)
            self._emit({"event": "egress_wall_launch",
                        "argv0": os.path.basename(str(argv[0])),
                        "wall_state": report.state,
                        "components": sorted(checked),
                        "wall_id": self._wall_id})
            return proc
        finally:
            try:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            lock_fh.close()

    def run_child(self, argv, *, env=None, **popen_kw):
        """launch() then wait; maps preexec-abort (exit 99) to
        EgressLaunchRefused so callers can treat a mid-launch wall
        death as a refusal, not a crash. ``capture_output=True`` is
        honored (translated to pipes for Popen)."""
        popen_kw = dict(popen_kw)
        capture = popen_kw.pop("capture_output", False)
        text = popen_kw.pop("text", False)
        if capture:
            popen_kw["stdout"] = subprocess.PIPE
            popen_kw["stderr"] = subprocess.PIPE
        if text:
            popen_kw["text"] = True
        proc = self.launch(argv, env=env, **popen_kw)
        if capture:
            out, err = proc.communicate(timeout=30)
            rc = proc.returncode
        else:
            rc = proc.wait()
            out = err = None
            try:
                out, err = proc.communicate(timeout=5)
            except Exception:
                pass
        if rc == PREEXEC_ABORT_CODE:
            self._emit({"event": "egress_wall_launch_refused",
                        "reason": "preexec_recheck_failed",
                        "wall_id": self._wall_id})
            raise EgressLaunchRefused(
                "preexec_recheck_failed: wall died between check and "
                "spawn; child aborted before exec")
        cp = subprocess.CompletedProcess(argv, rc, out, err)
        return cp

    # -- integration helper ------------------------------------------
    def popen_kwargs(self, env=None):
        """Env + preexec for embedding in another spawner (e.g.
        gov/sandbox.py's Popen call). The caller MUST still run
        verify()+check() first — this helper does not verify."""
        return {"env": self._child_env(env),
                "preexec_fn": self._preexec()}
