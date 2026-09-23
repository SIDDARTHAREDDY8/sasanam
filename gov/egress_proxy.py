"""F81 filtered-egress PROTOTYPE — CONNECT-tunneling egress proxy core (wave-57).

STATUS: MECHANISM-SHAPE PROTOTYPE. This module proves the *mechanism shape*
of the wave-56 proxy design (``workstreams/architect/F81_PROXY_EGRESS_DESIGN.md``):
CONNECT parsing, first-match-wins rule ordering with dst-deny above allow,
per-request resolution (no launch-time pinning), verdicts bound to the
active policy version, readiness semantics, and the emulated no-route
topology. It does NOT prove the topology.

HARD BOUNDARY (EPERM): real network namespaces cannot be exercised in this
environment — ``unshare(CLONE_NEWNET)`` / ``setns()`` return EPERM here, so
the veth-pair / child-netns / no-default-route topology from the design doc
is DEPLOYMENT-VERIFIED-ONLY. ``EmulatedCage`` below is a *model* of that
topology: it lets the mechanism-shape tests run, but its green tests imply
nothing about the real wall. F81 stays OPEN; prototype green != closure.

Squid-vs-bespoke decision (wave-57, on the auditability bar): BESPOKE.
The bar is "every verdict auditable, no opaque binary behavior in the
trust path." A packaged squid fails that bar for this component: ~1M LOC
of C plus an ACL/cache/TLS-bump config language is opaque surface in the
trust path, most of it dead config for our CONNECT-only shape but still a
CVE stream to track. The bespoke core is ~500 lines of stdlib Python whose
entire trust path (parse -> rule order -> dst-deny -> verdict) is readable
in one sitting. Honest cost admitted: bespoke userspace is our own bug
surface. Mitigations: radical minimalism (CONNECT only, no caching, no
TLS interception, strict config-as-data), the self-guarantees in
``PROXY_SELF_GUARANTEES`` below, and the design doc's section 6.4
requirement — an operator-owned upstream firewall layer at deployment —
which the bespoke choice does NOT remove. A deployment without that layer
has not implemented the design.

Stdlib only. No network calls on the default path: the default resolver
refuses (fail-closed) and the default connector refuses; tests inject
fakes over ``socket.socketpair()`` (AF_UNIX — no network interfaces).
"""

import hashlib
import ipaddress
import json
import os
import re
import select
import socket
import time

# ---------------------------------------------------------------------------
# Errors — every failure mode names itself loudly (fail-closed, never open).
# ---------------------------------------------------------------------------


class PolicyRefusedError(ValueError):
    """Policy-as-data confusion: unknown key, malformed entry, or a
    Wiki-shaped suffix wildcard. The launch/reload is refused BY NAME;
    nothing degrades into open egress."""


class ProxyNotReadyError(RuntimeError):
    """Readiness gate: the child is never forked while the proxy is not
    listening. Proxy-not-ready = no network, never fail-open."""


class PolicyVersionMismatch(RuntimeError):
    """The verdict logger's bound policy hash does not match the active
    policy (allowlist rotated without rotating the log binding, or vice
    versa). The proxy refuses to serve — no-network — until the operator
    reconciles the two. Silent version skew is worse than no network."""


class NoRouteError(OSError):
    """Emulated topology: the child has no route to this destination.
    In the real deployment this is enforced by the parent-owned veth with
    no default route; here it is a model (see HARD BOUNDARY above)."""


class CagePathError(ValueError):
    """The verdict log path resolves inside the child's jail view (or is
    not an absolute operator-owned path). Refused at construction."""


class ResolverUnavailableError(RuntimeError):
    """Per-request resolution failed or the resolver is unwired.
    Fail-closed: resolution timeout/unavailable -> refuse."""


class LogTamperedError(RuntimeError):
    """Verdict-chain verification failed: a line was modified, removed,
    or reordered. Evidence-grade integrity (the control does not depend
    on the log; the log must still not lie quietly)."""


class UpstreamDisabledError(RuntimeError):
    """The default upstream connector refuses: this prototype never opens
    real upstream TCP by default. Deployment wires the operator's
    upstream connector here."""


# ---------------------------------------------------------------------------
# Static dst-deny: evaluated ABOVE the allowlist, against the address the
# proxy actually connects to, and re-validated at connect time (the
# resolve->connect TOCTOU re-check in confirm_connected()). Static and
# never expiring: DNS-rebind into private space is closed regardless of
# any TTL, because this list does not come from DNS at all.
# ---------------------------------------------------------------------------

_DENY_NETS = (
    ipaddress.ip_network("127.0.0.0/8"),      # loopback (DeepSeek-harness shape)
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("10.0.0.0/8"),       # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),    # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),   # RFC1918
    ipaddress.ip_network("169.254.0.0/16"),   # link-local (incl. the veth itself)
    ipaddress.ip_network("100.64.0.0/10"),    # carrier-grade NAT
    ipaddress.ip_network("0.0.0.0/8"),        # "this network"
    ipaddress.ip_network("::/128"),           # unspecified
    ipaddress.ip_network("fc00::/7"),         # unique-local
    ipaddress.ip_network("fe80::/10"),        # link-local v6
    ipaddress.ip_network("ff00::/8"),         # multicast
)


def _unwrap(ip):
    """Unwrap IPv4-mapped IPv6 (``::ffff:127.0.0.1``) so the deny list
    cannot be dodged by address-family spelling."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def is_denied_ip(ip_str):
    """True if ``ip_str`` is in the static dst-deny space. Raises
    ValueError on unparsable input (fail-closed upstream)."""
    ip = _unwrap(ipaddress.ip_address(ip_str.strip()))
    return any(ip in net for net in _DENY_NETS)


def confirm_connected(ip_str):
    """Connect-time re-validation for the resolve->connect TOCTOU window
    (design doc section 6.2, ADR-admitted residual): after the upstream
    socket is connected, dst-deny the address actually reached. The
    dangerous rebind direction (-> private space) is closed here even if
    the answer flipped between the proxy's resolution and connect.
    Public->public flips are policy, not a boundary breach (documented,
    tested)."""
    return not is_denied_ip(ip_str)


# ---------------------------------------------------------------------------
# Policy: data, never code. Strict reader — unknown keys and malformed
# entries refuse the launch BY NAME (design doc section 8.5.3).
# ---------------------------------------------------------------------------

_KNOWN_KEYS = frozenset({
    "version", "allow", "operator_pinholes", "listen", "port",
    "client_subnet",
})

# Hostnames only. An IP literal in the allowlist would be a launch-time
# pin — the exact rotation failure the ADR rejected — so it is refused
# loudly rather than "supported".
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def _normalize_host(name):
    return name.strip().lower().rstrip(".")


def _check_allow_entry(entry, key):
    if not isinstance(entry, str) or not entry.strip():
        raise PolicyRefusedError(
            "%s entry must be a non-empty string, got %r" % (key, entry))
    norm = _normalize_host(entry)
    if norm.startswith("*."):
        # The Wiki shape: a trusted suffix must never implicitly trust
        # attacker-registered subdomains. Each allowed name is enumerated.
        raise PolicyRefusedError(
            "%s entry %r uses a suffix wildcard: refused (Wiki shape); "
            "enumerate each allowed FQDN explicitly" % (key, entry))
    try:
        ipaddress.ip_address(norm)
    except ValueError:
        pass
    else:
        raise PolicyRefusedError(
            "%s entry %r is an IP literal: refused (launch-time pin; "
            "the proxy resolves per request through the operator "
            "resolver)" % (key, entry))
    if not _HOST_RE.match(norm):
        raise PolicyRefusedError(
            "%s entry %r is not a valid hostname" % (key, entry))
    return norm


def canonical_policy_hash(data):
    """sha256 over the canonical (sorted-key, compact) serialization.
    The hash is the policy's version identity: every verdict line carries
    it, so post-incident analysis shows *what was allowed when*."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class EgressPolicy(object):
    """Parsed, validated egress policy. Immutable after parse."""

    def __init__(self, data):
        unknown = set(data) - _KNOWN_KEYS
        if unknown:
            raise PolicyRefusedError(
                "unknown policy keys refused: %s" % sorted(unknown))
        version = data.get("version")
        if not isinstance(version, str) or not version.strip():
            raise PolicyRefusedError("policy 'version' must be a non-empty string")
        allow = data.get("allow", [])
        pinholes = data.get("operator_pinholes", [])
        if not isinstance(allow, list) or not isinstance(pinholes, list):
            raise PolicyRefusedError("'allow' and 'operator_pinholes' must be lists")
        self.version = version.strip()
        # Exact-set membership. No wildcard semantics exist anywhere in
        # this module: subdomains are allowed only if enumerated.
        self.allow = frozenset(_check_allow_entry(e, "allow") for e in allow)
        self.operator_pinholes = frozenset(
            _check_allow_entry(e, "operator_pinholes") for e in pinholes)
        listen = data.get("listen")
        if not isinstance(listen, str):
            raise PolicyRefusedError("policy 'listen' must be an IP literal string")
        try:
            lip = ipaddress.ip_address(listen.strip())
        except ValueError:
            raise PolicyRefusedError("policy 'listen' is not an IP literal: %r" % listen)
        if lip.is_unspecified:
            # Set-up-safe: a wildcard bind would expose the proxy beyond
            # the veth. Refuse the launch instead of binding 0.0.0.0.
            raise PolicyRefusedError(
                "policy 'listen' must not be a wildcard (%r): the proxy "
                "listens ONLY on the veth address" % listen)
        self.listen = str(lip)
        port = data.get("port")
        if not isinstance(port, int) or isinstance(port, bool) \
                or not (1 <= port <= 65535):
            raise PolicyRefusedError("policy 'port' must be an int 1-65535")
        self.port = port
        try:
            self.client_subnet = ipaddress.ip_network(
                data.get("client_subnet", "169.254.240.0/30"), strict=False)
        except ValueError:
            raise PolicyRefusedError(
                "policy 'client_subnet' is not a valid network")
        self.policy_hash = canonical_policy_hash({
            "version": self.version,
            "allow": sorted(self.allow),
            "operator_pinholes": sorted(self.operator_pinholes),
            "listen": self.listen,
            "port": self.port,
            "client_subnet": str(self.client_subnet),
        })

    def __repr__(self):
        return ("EgressPolicy(version=%r, allow=%d, pinholes=%d, "
                "listen=%s:%d, hash=%.12s...)" % (
                    self.version, len(self.allow),
                    len(self.operator_pinholes), self.listen, self.port,
                    self.policy_hash))


def parse_policy(data):
    """Strict entry point: dict in, EgressPolicy out, or refused loudly."""
    if not isinstance(data, dict):
        raise PolicyRefusedError("policy must be a dict, got %r" % type(data))
    return EgressPolicy(data)


# ---------------------------------------------------------------------------
# Decision engine. First-match-wins, top to bottom — the security property
# IS the rule order (design doc section 5):
#   1. client check (only the child's veth subnet may ask)
#   2. method check (CONNECT only — no plaintext HTTP relay, nothing cached)
#   3. operator pinholes (explicit, ABOVE dst-deny, visible in the order)
#   4. dst-deny (static private/loopback/link-local — above the allowlist)
#   5. allowlist (exact enumerated FQDNs)
#   6. deny-all, logged
# ---------------------------------------------------------------------------

class Decision(object):
    __slots__ = ("verdict", "rule", "host", "port", "selected_ip", "client")

    def __init__(self, verdict, rule, host=None, port=None,
                 selected_ip=None, client=None):
        self.verdict = verdict      # "allow" | "deny"
        self.rule = rule            # which rule fired, for the verdict log
        self.host = host
        self.port = port
        self.selected_ip = selected_ip  # the answer we will connect to
        self.client = client

    def __repr__(self):
        return "Decision(%s by %s host=%r ip=%r)" % (
            self.verdict, self.rule, self.host, self.selected_ip)


def _parse_authority(authority):
    """Parse a CONNECT authority (``host:port``). Anything the parser
    cannot understand is a deny, never a guess.

    Grammar (strict, ASCII-only — the policy grammar in _HOST_RE is
    ASCII-only, so no legitimate request can contain anything else):
      host    = 1*63(ALPHA / DIGIT / "-" / ".")   ; unbracketed
              / "[" 1*(HEXDIG / ":" / ".") "]"    ; bracketed IPv6 literal
      port    = 1*5DIGIT                          ; ASCII digits only
    ``str.isdigit()`` is NOT sufficient: it accepts non-ASCII digits
    (superscripts, circled numbers) that ``int()`` rejects — wave-58
    fuzzing (F125) showed that gap crashes ``decide()``."""
    if not isinstance(authority, str):
        return None, None
    auth = authority.strip()
    if not auth or "@" in auth:
        # userinfo in a CONNECT authority is never legitimate here.
        return None, None
    if auth.startswith("["):
        # IPv6 literal "[::1]:443" — bracketed form only.
        m = re.match(r"^\[([0-9a-fA-F:.]+)\]:([0-9]+)$", auth)
        if not m:
            return None, None
        return m.group(1), m.group(2)
    if auth.count(":") != 1:
        return None, None
    host, _, port = auth.partition(":")
    host = host.strip()
    port = port.strip()
    if not host or not port.isascii() or not port.isdigit():
        return None, None
    if not _AUTHORITY_HOST_RE.match(host):
        return None, None
    return host, port


# Unbracketed authority host: ASCII letters/digits/hyphen/dot only.
# (Policy allow-entries are validated by _HOST_RE; anything outside this
# set can never match, so refusing it at parse is fail-closed and keeps
# garbage out of the operator resolver's query stream.)
_AUTHORITY_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")


def refuse_resolver(host):
    """Default resolver: refuses. Per-request resolution is operator-wired
    at deployment; the prototype never touches DNS (or the network) by
    default. Fail-closed: unwired resolver -> ResolverUnavailableError."""
    raise ResolverUnavailableError(
        "no operator resolver wired for %r (prototype default refuses)" % host)


def decide(policy, method, authority, client_addr, resolve=refuse_resolver):
    """One CONNECT decision. ``resolve`` is called PER REQUEST with the
    requested hostname — no launch-time pinning, no cache in this layer
    (deployment may cache with TTL + connect-time re-validation; the
    dangerous rebind direction is closed by the static dst-deny anyway)."""
    try:
        client_ip = ipaddress.ip_address(str(client_addr).strip())
    except ValueError:
        return Decision("deny", "client-check", client=str(client_addr))
    # Rule 1: client check.
    if client_ip not in policy.client_subnet:
        return Decision("deny", "client-check", client=str(client_addr))
    # Rule 2: method check.
    if method != "CONNECT":
        return Decision("deny", "method-check", client=str(client_addr))
    host_raw, port_raw = _parse_authority(authority)
    if host_raw is None:
        return Decision("deny", "malformed-authority", client=str(client_addr))
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        # Defense in depth: _parse_authority promises ASCII digits, but
        # decide() must never trust it — a parser-contract widening must
        # degrade to deny, never to an exception escaping serve_stream.
        return Decision("deny", "malformed-authority", client=str(client_addr))
    if not (1 <= port <= 65535):
        return Decision("deny", "malformed-authority", client=str(client_addr))
    host = _normalize_host(host_raw)
    # Rule 3: operator pinholes — explicit, above dst-deny, so the
    # exemption is visible in the rule order, never hidden in suffix logic.
    if host in policy.operator_pinholes:
        try:
            answers = resolve(host)
        except Exception:
            return Decision("deny", "pinhole-resolve-failed", host, port,
                            client=str(client_addr))
        if not answers:
            return Decision("deny", "pinhole-resolve-failed", host, port,
                            client=str(client_addr))
        return Decision("allow", "operator-pinhole", host, port,
                        selected_ip=str(answers[0]), client=str(client_addr))
    # Raw IP authorities are never allowlistable (hostname policy only).
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return Decision("deny", "ip-authority-not-allowlistable", host, port,
                        client=str(client_addr))
    # Rule 4: dst-deny — evaluated against the address we will connect to.
    try:
        answers = resolve(host)
    except Exception:
        return Decision("deny", "resolve-failed", host, port,
                        client=str(client_addr))
    if not answers:
        return Decision("deny", "resolve-failed", host, port,
                        client=str(client_addr))
    selected = str(answers[0]).strip()
    try:
        if is_denied_ip(selected):
            return Decision("deny", "dst-deny", host, port,
                            selected_ip=selected, client=str(client_addr))
    except ValueError:
        return Decision("deny", "resolve-failed", host, port,
                        client=str(client_addr))
    # Rule 5: allowlist — exact enumerated FQDNs, no suffix trust.
    if host in policy.allow:
        return Decision("allow", "allowlist", host, port,
                        selected_ip=selected, client=str(client_addr))
    # Rule 6: deny-all, logged.
    return Decision("deny", "deny-all", host, port, selected_ip=selected,
                    client=str(client_addr))


# ---------------------------------------------------------------------------
# Verdict log: operator-owned path OUTSIDE the cage, hash-bound to the
# active allowlist version. The log is evidence, not a control (design
# doc section 8.3): the control is the topology. Tampering breaks the
# chain loudly via verify().
#
# Deployment wiring: pass on_verdict=... to mirror each verdict dict into
# the canonical HMAC-chained audit log (gov/log.py ActionLog, the D1-core
# primitive). Key custody stays operator-owned; this module never sees keys.
# ---------------------------------------------------------------------------

def _utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class VerdictLogger(object):
    """Append-only JSONL verdict log with a prev-hash chain and the
    active policy's version+hash on every line."""

    def __init__(self, log_path, policy_hash, cage_roots=(), on_verdict=None):
        if not os.path.isabs(log_path):
            raise CagePathError(
                "verdict log path must be absolute (operator-owned): %r"
                % log_path)
        real = os.path.realpath(log_path)
        for root in cage_roots:
            rroot = os.path.realpath(root)
            if real == rroot or real.startswith(rroot + os.sep):
                raise CagePathError(
                    "verdict log path %r is inside the cage view %r: "
                    "refused — the log lives OUTSIDE the cage" % (log_path, root))
        # NOTE: the path comes ONLY from this constructor argument
        # (operator config). No environment variable, no client input is
        # ever consulted — a cage-side EGRESS_VERDICT_LOG=... is ignored
        # by construction (pinned by test).
        self.path = real
        self.policy_hash = policy_hash
        self._seq = 0
        self._prev = "GENESIS"
        self._on_verdict = on_verdict
        parent = os.path.dirname(real)
        if parent:
            os.makedirs(parent, exist_ok=True)
        if os.path.exists(real):
            self._resync()

    def _resync(self):
        ok, count, tip = self.verify_file(self.path)
        if not ok:
            raise LogTamperedError(
                "existing verdict log failed verification: refusing to "
                "append to a tampered log")
        self._seq = count
        self._prev = tip

    @staticmethod
    def _entry_hash(entry):
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def log(self, decision, policy_version, extra=None):
        """Append one verdict line. Returns the entry dict."""
        entry = {
            "seq": self._seq,
            "ts": _utcnow(),
            "client": decision.client,
            "host": decision.host,
            "port": decision.port,
            "resolved_ip": decision.selected_ip,
            "verdict": decision.verdict,
            "rule": decision.rule,
            "policy_version": policy_version,
            "policy_hash": self.policy_hash,
            "prev_hash": self._prev,
        }
        if extra:
            entry.update(extra)
        entry["entry_hash"] = self._entry_hash(entry)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        self._prev = entry["entry_hash"]
        self._seq += 1
        if self._on_verdict is not None:
            self._on_verdict(dict(entry))
        return entry

    @classmethod
    def verify_file(cls, path):
        """Re-verify the whole chain. Returns (ok, count, tip_hash);
        raises LogTamperedError on the first broken link."""
        prev = "GENESIS"
        count = 0
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    raise LogTamperedError("line %d: not JSON" % lineno)
                if entry.get("prev_hash") != prev:
                    raise LogTamperedError(
                        "line %d: prev_hash mismatch (log modified/reordered)"
                        % lineno)
                body = {k: v for k, v in entry.items() if k != "entry_hash"}
                if cls._entry_hash(body) != entry.get("entry_hash"):
                    raise LogTamperedError(
                        "line %d: entry_hash mismatch (line tampered)" % lineno)
                prev = entry["entry_hash"]
                count += 1
        return True, count, prev


# ---------------------------------------------------------------------------
# The proxy itself. Minimal: CONNECT allow/deny, no caching, no TLS
# interception (deliberate — design doc section 10), config-as-data.
#
# What the proxy ITSELF guarantees alone (proxy compromise containment,
# design doc section 6.4 — the operator-owned upstream firewall is OUT OF
# SCOPE here; this is what the code guarantees without it):
#   * one validated input: the CONNECT authority line. It is validated
#     (dst-deny + allowlist), never trusted. No other child-controlled
#     input reaches any decision.
#   * the upstream connector is called ONLY for allow-decisions, and only
#     with the (host, selected_ip, port) the engine decided on. Denied
#     requests never touch the connector (pinned by test).
#   * the connected address is re-validated (confirm_connected) before
#     any byte is relayed: a compromised-or-lying resolver cannot move a
#     private-space connection past the static dst-deny.
#   * no privileged operations exist in this module: no setuid, no
#     capabilities, no netns manipulation, no raw sockets. It runs
#     unprivileged; the veth/topology half is parent-owned and separate.
#   * malformed policy or version skew -> no network, never open.
# ---------------------------------------------------------------------------

PROXY_SELF_GUARANTEES = (
    "one validated input (CONNECT authority); validated, never trusted",
    "connector called only on allow, only with the decided (host, ip, port)",
    "connect-time re-validation of the reached address (TOCTOU re-check)",
    "no privileged operations in this module (no setuid/caps/netns/raw)",
    "malformed policy or version skew -> no-network, never fail-open",
)

_MAX_HEADER_BYTES = 8192  # F25 lesson: no unbounded reads on untrusted input
_RELAY_IDLE_TIMEOUT = 30.0


def refuse_connector(host, ip, port):
    """Default connector: refuses. The prototype never opens real upstream
    TCP by default (no network calls). Deployment injects the operator's
    connector. Returns (sock, connected_ip) on success."""
    raise UpstreamDisabledError(
        "upstream connector unwired (prototype default refuses)")


def tcp_connector(host, ip, port, timeout=10.0):
    """Deployment connector: real TCP to the decided address. Kept out of
    the default path so the prototype and its tests never touch the
    network. Returns (sock, connected_ip)."""
    sock = socket.create_connection((ip, port), timeout=timeout)
    return sock, ip


class EgressProxy(object):
    """The CONNECT-tunneling proxy core. Transport-agnostic: serve_stream
    handles one client session over any connected socket (tests use
    socketpair — AF_UNIX, no network)."""

    def __init__(self, policy, resolver=refuse_resolver,
                 connector=refuse_connector, logger=None):
        if not isinstance(policy, EgressPolicy):
            raise PolicyRefusedError("policy must be an EgressPolicy")
        self.policy = policy
        self.resolver = resolver
        self.connector = connector
        self.logger = logger
        self.ready = False  # readiness: no requests served until marked

    # -- readiness ------------------------------------------------------
    def mark_ready(self):
        """Called by the launcher AFTER the listen socket is live and
        liveness-checked. Before this, serve_stream refuses everything."""
        if self.logger is not None and \
                self.logger.policy_hash != self.policy.policy_hash:
            raise PolicyVersionMismatch(
                "verdict logger bound to policy %.12s... but active policy "
                "is %.12s...: refusing to serve (no-network)"
                % (self.logger.policy_hash, self.policy.policy_hash))
        self.ready = True

    def reload_policy(self, data):
        """Hot policy rotation. Malformed input is refused LOUDLY and the
        OLD policy keeps serving — the proxy never serves a half-parsed
        policy, and never serves with a version the verdict log cannot
        name (the logger is rebound to the new hash atomically)."""
        new_policy = parse_policy(data)  # raises PolicyRefusedError
        self.policy = new_policy
        if self.logger is not None:
            self.logger.policy_hash = new_policy.policy_hash
        return new_policy

    # -- session handling -----------------------------------------------
    def _read_request(self, sock):
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > _MAX_HEADER_BYTES:
                return None  # fail-closed: oversized headers refused
        if b"\r\n\r\n" not in buf:
            return None
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        lines = head.split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3:
            return None
        return parts[0].strip(), parts[1].strip()

    def _deny_response(self, sock, rule):
        body = ("HTTP/1.1 403 Forbidden\r\n"
                "X-Egress-Rule: %s\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n" % rule)
        try:
            sock.sendall(body.encode("latin-1"))
        except OSError:
            pass

    def serve_stream(self, sock, client_addr):
        """Handle one CONNECT session. Returns the Decision. Raises
        ProxyNotReadyError / PolicyVersionMismatch instead of serving
        when the proxy must not serve."""
        if self.logger is not None and \
                self.logger.policy_hash != self.policy.policy_hash:
            # Version skew discovered at request time (e.g. the operator
            # rebound the logger without reloading the policy): no-network.
            raise PolicyVersionMismatch(
                "policy/log version skew at request time: refusing")
        if not self.ready:
            dec = Decision("deny", "not-ready", client=str(client_addr))
            if self.logger is not None:
                self.logger.log(dec, self.policy.version)
            try:
                sock.sendall(b"HTTP/1.1 503 Proxy Not Ready\r\n"
                            b"Content-Length: 0\r\n"
                            b"Connection: close\r\n\r\n")
            except OSError:
                pass
            return dec
        parsed = self._read_request(sock)
        if parsed is None:
            dec = Decision("deny", "malformed-request",
                           client=str(client_addr))
            if self.logger is not None:
                self.logger.log(dec, self.policy.version)
            self._deny_response(sock, "malformed-request")
            return dec
        method, authority = parsed
        dec = decide(self.policy, method, authority, client_addr,
                     resolve=self.resolver)
        if dec.verdict != "allow":
            if self.logger is not None:
                self.logger.log(dec, self.policy.version)
            self._deny_response(sock, dec.rule)
            return dec
        # Allow path: connect ONLY to the decided address, then re-validate
        # what was actually reached before relaying a single byte.
        try:
            upstream, connected_ip = self.connector(
                dec.host, dec.selected_ip, dec.port)
        except Exception:
            dec2 = Decision("deny", "upstream-failed", dec.host, dec.port,
                            selected_ip=dec.selected_ip,
                            client=str(client_addr))
            if self.logger is not None:
                self.logger.log(dec2, self.policy.version)
            self._deny_response(sock, "upstream-failed")
            return dec2
        try:
            if not confirm_connected(connected_ip):
                # Resolve->connect TOCTOU: the answer flipped to private
                # space between our check and connect. Static dst-deny
                # holds regardless — close both ends, no bytes flow.
                dec2 = Decision("deny", "dst-deny-toctou", dec.host, dec.port,
                                selected_ip=connected_ip,
                                client=str(client_addr))
                if self.logger is not None:
                    self.logger.log(dec2, self.policy.version)
                self._deny_response(sock, "dst-deny-toctou")
                return dec2
            try:
                sock.sendall(b"HTTP/1.1 200 Connection Established\r\n"
                             b"Proxy-Agent: egress-proxy-prototype\r\n\r\n")
            except OSError:
                return dec
            up, down = self._relay(sock, upstream)
            if self.logger is not None:
                self.logger.log(dec, self.policy.version,
                                extra={"bytes_up": up, "bytes_down": down})
            return dec
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    @staticmethod
    def _relay(client, upstream):
        """Bidirectional byte relay until EOF/error or idle timeout.
        Destination-shaped wall: bytes tunnel opaquely (no TLS
        interception, deliberate)."""
        up = down = 0
        client.settimeout(_RELAY_IDLE_TIMEOUT)
        upstream.settimeout(_RELAY_IDLE_TIMEOUT)
        sockets = [client, upstream]
        try:
            while True:
                try:
                    r, _, _ = select.select(sockets, [], sockets,
                                            _RELAY_IDLE_TIMEOUT)
                except (OSError, ValueError):
                    break
                if not r:
                    break  # idle timeout: close, fail-closed
                for src in r:
                    dst = upstream if src is client else client
                    try:
                        data = src.recv(65536)
                    except OSError:
                        return up, down
                    if not data:
                        return up, down
                    try:
                        dst.sendall(data)
                    except OSError:
                        return up, down
                    if src is client:
                        up += len(data)
                    else:
                        down += len(data)
        finally:
            for s in sockets:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        return up, down


# ---------------------------------------------------------------------------
# Readiness gate (launcher side): the child is never forked until the
# proxy's listen socket is live. This is the defense-in-depth twin of the
# topological property (no route to race): even the *attempt* ordering is
# fail-closed.
# ---------------------------------------------------------------------------

class ReadinessGate(object):
    """Wraps an EgressProxy for the launcher. ``launch`` refuses to invoke
    the child callable unless the proxy is ready."""

    def __init__(self, proxy):
        self.proxy = proxy

    def wait_ready(self, timeout=5.0):
        """Poll the readiness flag (deployment: poll the listen socket).
        Returns True iff the proxy became ready in time."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proxy.ready:
                return True
            time.sleep(0.01)
        return self.proxy.ready

    def launch(self, child_fn, timeout=5.0):
        """Invoke ``child_fn`` only if the proxy is ready; otherwise raise
        ProxyNotReadyError WITHOUT invoking it. Proxy-not-ready therefore
        means no network AND no child — never fail-open, never a race."""
        if not self.wait_ready(timeout):
            raise ProxyNotReadyError(
                "proxy not ready within %.1fs: child not forked, no network"
                % timeout)
        return child_fn()


# ---------------------------------------------------------------------------
# Emulated topology. HARD BOUNDARY (repeated because it matters): this is a
# MODEL of the parent-owned veth topology (child netns, no default route,
# single link route to the proxy). In this EPERM environment the real
# topology cannot be constructed, so this model proves NOTHING about the
# wall itself — it only lets the mechanism-shape tests (ordering,
# readiness, verdicts) run against something shaped like the deployment.
# ---------------------------------------------------------------------------

class EmulatedCage(object):
    """Synthetic stand-in for the child network namespace. The ONLY
    reachable destination is the proxy's (address, port); everything else
    raises NoRouteError — modeling 'no default route, single link route
    to the proxy'. The real enforcement is topological and
    deployment-verified-only."""

    def __init__(self, proxy_addr, proxy):
        self.proxy_addr = proxy_addr  # (host, port) of the proxy's veth end
        self.proxy = proxy
        self.jail_root = "/emulated-cage/jail"  # the child's filesystem view

    def connect_proxy(self):
        """The single permitted route: a connected socketpair whose server
        end is handed to serve_stream with the child's veth address."""
        client, server = socket.socketpair()
        return client, server

    def connect_direct(self, host, port):
        """Any direct egress attempt: no route. Denied, never bypassed."""
        raise NoRouteError(
            "no route to %s:%d: child netns has no default route "
            "(emulated)" % (host, port))


class FilteredRun(object):
    """Honest status reporting for a filtered-egress run. The proxy being
    dead is reported as ``egress_filtered_unavailable`` — a distinct state,
    NEVER collapsed into ``network_isolated`` (design doc section 8.5.4)."""

    def __init__(self, cage, gate, firewall_state=None,
                 firewall_state_reason=None):
        self.cage = cage
        self.gate = gate
        self.proxy_dead = False
        # Lane-3 contract (docs/UPSTREAM_FIREWALL_CONTRACT.md §1): the
        # upstream firewall state is a first-class, always-present fact
        # in exactly {verified, degraded, absent}. Not wiring the §2
        # check IS the "absent" state — reported, never omitted, never
        # defaulted to verified. The reason string explains WHY absent.
        self.firewall_state = (
            "absent" if firewall_state is None else firewall_state)
        self.firewall_state_reason = (
            "no contract §2 check wired by the launcher"
            if firewall_state_reason is None else firewall_state_reason)

    def kill_proxy(self):
        """Emulate proxy death mid-run (design doc section 6.1)."""
        self.proxy_dead = True
        self.cage.proxy.ready = False

    def status(self):
        return {
            "egress_filtered": True,
            "egress_filtered_unavailable": self.proxy_dead,
            # Never collapsed: the run KNEW it wanted filtered egress.
            "network_isolated": False,
            # Lane-3 contract: absent/degraded is detectable, not silent.
            "upstream_firewall": self.firewall_state,
            "upstream_firewall_reason": self.firewall_state_reason,
            "allowlist_version": self.cage.proxy.policy.version,
            "allowlist_hash": self.cage.proxy.policy.policy_hash,
        }
