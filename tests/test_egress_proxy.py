"""Wave-57: F81 proxy prototype — mechanism-shape tests (break-first).

SYNTHETIC ONLY. No network calls: the transport runs over
``socket.socketpair()`` (AF_UNIX), resolution via injected fakes, upstream
via injected fake connectors. The emulated cage (``EmulatedCage``) is a
MODEL of the parent-owned veth topology — these green tests prove the
mechanism shape (ordering, resolution, verdicts, readiness, log binding),
not the wall. See gov/egress_proxy.py HARD BOUNDARY.

Break-first mapping (wave-56 five-part review residuals):
  readiness race ......... TestReadinessRace
  DNS-rebind / TOCTOU .... TestRebindToctou (static dst-deny holds regardless)
  verdict-log tampering .. TestVerdictLog
  proxy compromise ....... TestProxySelfGuarantees (what the proxy alone guarantees)
  policy-as-data ......... TestPolicyAsData (+ version-mismatch -> no-network)
"""

import json
import os
import socket
import sys
import tempfile
import threading
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.egress_proxy import (  # noqa: E402
    CagePathError,
    Decision,
    EgressPolicy,
    EgressProxy,
    EmulatedCage,
    FilteredRun,
    LogTamperedError,
    NoRouteError,
    PolicyRefusedError,
    PolicyVersionMismatch,
    ProxyNotReadyError,
    ReadinessGate,
    ResolverUnavailableError,
    VerdictLogger,
    confirm_connected,
    decide,
    is_denied_ip,
    parse_policy,
)

CLIENT = "169.254.240.2"      # inside the default client subnet
ROGUE_CLIENT = "10.99.99.99"  # outside it
PUBLIC_IP = "93.184.216.34"   # documentation/test-net stand-in (public)


def base_policy(**over):
    d = {
        "version": "wave57-001",
        "allow": ["example.com", "api.example.com"],
        "operator_pinholes": [],
        "listen": "169.254.240.1",
        "port": 3128,
        "client_subnet": "169.254.240.0/30",
    }
    d.update(over)
    return parse_policy(d)


def fake_resolver(mapping):
    """Injectable per-request resolver. ``mapping``: host -> [ip, ...].
    Counts calls so tests can prove no launch-time pinning."""
    calls = []

    def resolve(host):
        calls.append(host)
        if host not in mapping:
            raise ResolverUnavailableError("NXDOMAIN (fake): %s" % host)
        return list(mapping[host])

    resolve.calls = calls
    return resolve


class FakeConnector(object):
    """Injectable upstream connector. ``targets`` maps decided ip ->
    the ip it 'actually connected to' (models DNS rebind between
    resolve and connect). Unmapped -> connects to the decided ip."""

    def __init__(self, targets=None):
        self.targets = targets or {}
        self.calls = []
        self.peer = None  # other end of the fake upstream, for relay tests

    def __call__(self, host, ip, port):
        self.calls.append((host, ip, port))
        connected_ip = self.targets.get(ip, ip)
        a, b = socket.socketpair()
        self.peer = b
        return a, connected_ip


def run_session(proxy, request_bytes, client_addr=CLIENT, timeout=15,
                post_head=None):
    """Drive one CONNECT session over a socketpair. Returns
    (decision, raw_response_head, client_sock). ``post_head`` is called
    with the client socket after the response head is read but before
    joining the serve thread (lets tests close the client to end a
    relay promptly)."""
    client, server = socket.socketpair()
    client.settimeout(timeout)
    outcome = {}

    def target():
        try:
            outcome["decision"] = proxy.serve_stream(server, client_addr)
        except Exception as exc:  # noqa: BLE001
            outcome["error"] = exc
        finally:
            try:
                server.close()
            except OSError:
                pass

    t = threading.Thread(target=target, daemon=True)
    t.start()
    try:
        try:
            client.sendall(request_bytes)
        except OSError:
            pass  # server refused before reading (e.g. version skew)
        head = b""
        while b"\r\n\r\n" not in head:
            try:
                chunk = client.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            head += chunk
        if post_head is not None:
            try:
                post_head(client)
            except OSError:
                pass
    finally:
        pass
    t.join(timeout=timeout)
    if t.is_alive():
        client.close()
        raise AssertionError("serve_stream hung (would be a suite hang)")
    if "error" in outcome:
        raise outcome["error"]
    return outcome["decision"], head, client


def connect_req(authority, method="CONNECT"):
    return ("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n"
            % (method, authority, authority)).encode("latin-1")


def run_allow_session(proxy, request_bytes, client_addr=CLIENT, timeout=15):
    """run_session for the allow path: closes the client right after the
    200 head so the byte relay sees EOF and the serve thread terminates
    promptly (no 30s idle wait). Returns (decision, head)."""
    dec, head, client = run_session(
        proxy, request_bytes, client_addr=client_addr, timeout=timeout,
        post_head=lambda c: c.close())
    client.close()
    return dec, head


# ---------------------------------------------------------------------------
# Policy-as-data confusion: malformed input refused loudly, never degraded.
# ---------------------------------------------------------------------------

class TestPolicyAsData(unittest.TestCase):
    def test_unknown_key_refused_by_name(self):
        with self.assertRaises(PolicyRefusedError) as ctx:
            base_policy_extra = dict(version="v", allow=[],
                                     listen="169.254.240.1", port=3128,
                                     squid_mode=True)
            parse_policy(base_policy_extra)
        self.assertIn("squid_mode", str(ctx.exception))

    def test_suffix_wildcard_refused(self):
        with self.assertRaises(PolicyRefusedError) as ctx:
            base_policy(allow=["*.example.com"])
        self.assertIn("wildcard", str(ctx.exception))

    def test_ip_literal_allow_refused(self):
        # An IP in the allowlist would be a launch-time pin — refused.
        with self.assertRaises(PolicyRefusedError) as ctx:
            base_policy(allow=["93.184.216.34"])
        self.assertIn("IP literal", str(ctx.exception))

    def test_wildcard_listen_refused(self):
        # Set-up-safe: 0.0.0.0 would expose the proxy beyond the veth.
        with self.assertRaises(PolicyRefusedError) as ctx:
            base_policy(listen="0.0.0.0")
        self.assertIn("wildcard", str(ctx.exception))

    def test_non_dict_refused(self):
        with self.assertRaises(PolicyRefusedError):
            parse_policy(["not", "a", "dict"])

    def test_empty_version_refused(self):
        with self.assertRaises(PolicyRefusedError):
            base_policy(version="  ")

    def test_malformed_reload_keeps_old_policy(self):
        # Break: operator pushes a malformed edit. Required: refused
        # loudly, OLD policy keeps serving with the OLD hash on verdicts.
        tmp = tempfile.mkdtemp()
        policy = base_policy()
        logger = VerdictLogger(os.path.join(tmp, "v.jsonl"),
                               policy.policy_hash)
        proxy = EgressProxy(policy, resolver=fake_resolver(
            {"example.com": [PUBLIC_IP]}), connector=FakeConnector(),
            logger=logger)
        proxy.mark_ready()
        with self.assertRaises(PolicyRefusedError):
            proxy.reload_policy({"version": "v2", "allow": ["*.evil.com"],
                                 "listen": "169.254.240.1", "port": 3128})
        dec, head = run_allow_session(proxy, connect_req("example.com:443"))
        self.assertEqual(dec.verdict, "allow")
        self.assertEqual(dec.rule, "allowlist")
        with open(logger.path) as fh:
            entry = json.loads(fh.read().strip().splitlines()[-1])
        self.assertEqual(entry["policy_version"], "wave57-001")
        self.assertEqual(entry["policy_hash"], policy.policy_hash)

    def test_valid_reload_rotates_hash(self):
        tmp = tempfile.mkdtemp()
        policy = base_policy()
        logger = VerdictLogger(os.path.join(tmp, "v.jsonl"),
                               policy.policy_hash)
        proxy = EgressProxy(policy,
                            resolver=fake_resolver({"example.com": [PUBLIC_IP],
                                                    "new.example": [PUBLIC_IP]}),
                            connector=FakeConnector(), logger=logger)
        proxy.mark_ready()
        new = proxy.reload_policy({
            "version": "wave57-002", "allow": ["new.example"],
            "listen": "169.254.240.1", "port": 3128})
        self.assertNotEqual(new.policy_hash, policy.policy_hash)
        dec, head = run_allow_session(proxy, connect_req("new.example:443"))
        self.assertEqual(dec.verdict, "allow")
        with open(logger.path) as fh:
            entry = json.loads(fh.read().strip().splitlines()[-1])
        self.assertEqual(entry["policy_version"], "wave57-002")
        self.assertEqual(entry["policy_hash"], new.policy_hash)

    def test_version_mismatch_is_no_network(self):
        # Break: allowlist rotated without rebinding the verdict log
        # (or vice versa). Required: the proxy serves NOTHING — no 200
        # ever, connector never called — until the operator reconciles.
        tmp = tempfile.mkdtemp()
        p1 = base_policy()
        p2 = base_policy(version="wave57-002", allow=["other.example"])
        logger = VerdictLogger(os.path.join(tmp, "v.jsonl"), p1.policy_hash)
        connector = FakeConnector()
        proxy = EgressProxy(p1, resolver=fake_resolver(
            {"example.com": [PUBLIC_IP]}), connector=connector, logger=logger)
        proxy.mark_ready()
        proxy.policy = p2  # skew, bypassing reload_policy (operator error)
        with self.assertRaises(PolicyVersionMismatch):
            run_session(proxy, connect_req("example.com:443"))
        self.assertEqual(connector.calls, [])


# ---------------------------------------------------------------------------
# Ordering: dst-deny ABOVE allow. The security property is the rule order.
# ---------------------------------------------------------------------------

class TestOrdering(unittest.TestCase):
    DENIED_SPACES = ["10.0.0.5", "172.16.4.4", "192.168.1.9", "127.0.0.1",
                     "169.254.9.9", "100.64.0.7", "::1", "fc00::1",
                     "fe80::1", "::ffff:127.0.0.1"]

    def test_dst_deny_above_allow(self):
        # Break: an ALLOWED name whose current answer is private space
        # (DNS-rebind / operator DNS poison / stale record). Required:
        # refused at decide time by dst-deny, never reaching the allowlist.
        policy = base_policy()
        for ip in self.DENIED_SPACES:
            with self.subTest(ip=ip):
                resolver = fake_resolver({"example.com": [ip]})
                dec = decide(policy, "CONNECT", "example.com:443",
                             CLIENT, resolve=resolver)
                self.assertEqual(dec.verdict, "deny", ip)
                self.assertEqual(dec.rule, "dst-deny", ip)

    def test_is_denied_ip_unit(self):
        for ip in self.DENIED_SPACES:
            self.assertTrue(is_denied_ip(ip), ip)
        for ip in [PUBLIC_IP, "203.0.113.7", "8.8.8.8", "2001:db8::1"]:
            self.assertFalse(is_denied_ip(ip), ip)

    def test_pinhole_above_dst_deny_explicit(self):
        # The operator pinhole is an EXPLICIT exemption above dst-deny:
        # visible in the rule order, not hidden in suffix logic.
        policy = base_policy(operator_pinholes=["lifeline.ops"])
        resolver = fake_resolver({"lifeline.ops": ["10.9.9.9"],
                                  "example.com": ["10.0.0.1"]})
        dec = decide(policy, "CONNECT", "lifeline.ops:443", CLIENT,
                     resolve=resolver)
        self.assertEqual((dec.verdict, dec.rule), ("allow", "operator-pinhole"))
        dec2 = decide(policy, "CONNECT", "example.com:443", CLIENT,
                      resolve=resolver)
        self.assertEqual((dec2.verdict, dec2.rule), ("deny", "dst-deny"))

    def test_allow_exact_only_no_suffix_trust(self):
        # Wiki shape: no suffix-trust wildcards; subdomains allowed only
        # if enumerated.
        policy = base_policy()
        resolver = fake_resolver({
            "api.example.com": [PUBLIC_IP],
            "sub.api.example.com": [PUBLIC_IP],
            "notapi.example.com": [PUBLIC_IP],
            "api.example.com.evil.com": [PUBLIC_IP],
        })
        allowed = decide(policy, "CONNECT", "api.example.com:443",
                         CLIENT, resolve=resolver)
        self.assertEqual(allowed.verdict, "allow")
        for host in ("sub.api.example.com", "notapi.example.com",
                     "api.example.com.evil.com"):
            with self.subTest(host=host):
                dec = decide(policy, "CONNECT", "%s:443" % host, CLIENT,
                             resolve=resolver)
                self.assertEqual(dec.verdict, "deny", host)
                self.assertEqual(dec.rule, "deny-all", host)

    def test_raw_ip_authority_never_allowlistable(self):
        # Direct-IP CONNECT: hostname policy only; the resolver is not
        # even consulted.
        policy = base_policy()
        resolver = fake_resolver({})
        dec = decide(policy, "CONNECT", "93.184.216.34:443", CLIENT,
                     resolve=resolver)
        self.assertEqual((dec.verdict, dec.rule),
                         ("deny", "ip-authority-not-allowlistable"))
        self.assertEqual(resolver.calls, [])

    def test_method_check(self):
        policy = base_policy()
        connector = FakeConnector()
        proxy = EgressProxy(policy, resolver=fake_resolver({}),
                            connector=connector)
        proxy.mark_ready()
        dec, head, client = run_session(
            proxy, connect_req("http://example.com/", method="GET"))
        client.close()
        self.assertEqual((dec.verdict, dec.rule), ("deny", "method-check"))
        self.assertEqual(connector.calls, [])

    def test_client_check(self):
        policy = base_policy()
        connector = FakeConnector()
        proxy = EgressProxy(policy, resolver=fake_resolver(
            {"example.com": [PUBLIC_IP]}), connector=connector)
        proxy.mark_ready()
        dec, head, client = run_session(proxy, connect_req("example.com:443"),
                                        client_addr=ROGUE_CLIENT)
        client.close()
        self.assertEqual((dec.verdict, dec.rule), ("deny", "client-check"))
        self.assertEqual(connector.calls, [])

    def test_confused_deputy_authorities(self):
        # The only child-controlled input is the CONNECT authority line;
        # it is validated, never trusted.
        policy = base_policy()
        resolver = fake_resolver({"example.com": [PUBLIC_IP]})
        bad = ["user@example.com:443",       # userinfo
               "example.com:99999",          # port out of range
               "example.com:0",
               ":443",                       # empty host
               "example.com",                # no port
               "http://example.com/",        # absolute URI, not authority
               "", ]
        for auth in bad:
            with self.subTest(auth=auth):
                dec = decide(policy, "CONNECT", auth, CLIENT,
                             resolve=resolver)
                self.assertEqual(dec.verdict, "deny", auth)

    def test_per_request_resolution_no_pinning(self):
        # No launch-time pinning: the resolver is consulted per request.
        tmp = tempfile.mkdtemp()
        policy = base_policy()
        resolver = fake_resolver({"example.com": [PUBLIC_IP]})
        proxy = EgressProxy(policy, resolver=resolver,
                            connector=FakeConnector())
        proxy.mark_ready()
        for _ in range(2):
            dec, head, client = run_session(
                proxy, connect_req("example.com:443"),
                post_head=lambda c: c.close())  # end relay promptly
            client.close()
            self.assertEqual(dec.verdict, "allow")
        self.assertEqual(len(resolver.calls), 2)


# ---------------------------------------------------------------------------
# DNS-rebind / resolve->connect TOCTOU: the static dst-deny holds
# regardless, because it is re-validated against the CONNECTED address.
# ---------------------------------------------------------------------------

class TestRebindToctou(unittest.TestCase):
    def test_rebind_to_private_blocked_at_connect(self):
        # Break: authoritative DNS flips the answer between the proxy's
        # resolution and connect (ADR-admitted race). The proxy resolved
        # 93.184.216.34 (allow) but the connector reached 127.0.0.1.
        # Required: static dst-deny on the CONNECTED answer — no bytes flow.
        tmp = tempfile.mkdtemp()
        policy = base_policy()
        logger = VerdictLogger(os.path.join(tmp, "v.jsonl"),
                               policy.policy_hash)
        connector = FakeConnector(targets={PUBLIC_IP: "127.0.0.1"})
        proxy = EgressProxy(policy, resolver=fake_resolver(
            {"example.com": [PUBLIC_IP]}), connector=connector, logger=logger)
        proxy.mark_ready()
        dec, head, client = run_session(proxy, connect_req("example.com:443"))
        client.close()
        self.assertEqual((dec.verdict, dec.rule), ("deny", "dst-deny-toctou"))
        self.assertIn(b"403", head.split(b"\r\n")[0])
        self.assertIn(b"dst-deny-toctou", head)
        self.assertTrue(confirm_connected(PUBLIC_IP))
        self.assertFalse(confirm_connected("127.0.0.1"))

    def test_rebind_public_to_public_is_policy_not_breach(self):
        # Documented boundary: a public->public flip stays inside the
        # allowlist's public space. The security boundary (no private
        # egress) holds; which public IP is policy, not breach.
        policy = base_policy()
        connector = FakeConnector(targets={PUBLIC_IP: "203.0.113.7"})
        proxy = EgressProxy(policy, resolver=fake_resolver(
            {"example.com": [PUBLIC_IP]}), connector=connector)
        proxy.mark_ready()
        # Close the client right after the 200 so the relay sees EOF and
        # the serve thread terminates promptly (no 30s idle wait).
        dec, head, client = run_session(
            proxy, connect_req("example.com:443"),
            post_head=lambda c: c.close())
        self.assertEqual(dec.verdict, "allow")
        self.assertIn(b"200", head.split(b"\r\n")[0])


# ---------------------------------------------------------------------------
# Readiness race: proxy-not-ready = no network, never fail-open.
# ---------------------------------------------------------------------------

class TestReadinessRace(unittest.TestCase):
    def test_first_request_vs_not_ready_refused(self):
        tmp = tempfile.mkdtemp()
        policy = base_policy()
        logger = VerdictLogger(os.path.join(tmp, "v.jsonl"),
                               policy.policy_hash)
        connector = FakeConnector()
        proxy = EgressProxy(policy, resolver=fake_resolver(
            {"example.com": [PUBLIC_IP]}), connector=connector, logger=logger)
        # NOTE: mark_ready() deliberately NOT called — the race.
        dec, head, client = run_session(proxy, connect_req("example.com:443"))
        client.close()
        self.assertEqual((dec.verdict, dec.rule), ("deny", "not-ready"))
        self.assertIn(b"503", head.split(b"\r\n")[0])
        self.assertEqual(connector.calls, [])
        with open(logger.path) as fh:
            entry = json.loads(fh.read().strip())
        self.assertEqual(entry["rule"], "not-ready")

    def test_gate_never_forks_child_when_not_ready(self):
        policy = base_policy()
        proxy = EgressProxy(policy)  # not ready
        gate = ReadinessGate(proxy)
        forked = []
        with self.assertRaises(ProxyNotReadyError):
            gate.launch(lambda: forked.append(True), timeout=0.2)
        self.assertEqual(forked, [])

    def test_gate_launches_once_ready(self):
        policy = base_policy()
        proxy = EgressProxy(policy)
        proxy.mark_ready()
        gate = ReadinessGate(proxy)
        self.assertTrue(gate.launch(lambda: "child-ran", timeout=1.0)
                        == "child-ran")


# ---------------------------------------------------------------------------
# Verdict log: outside the cage, hash-bound, tamper-evident.
# ---------------------------------------------------------------------------

class TestVerdictLog(unittest.TestCase):
    def test_log_path_inside_cage_refused(self):
        policy = base_policy()
        with self.assertRaises(CagePathError):
            VerdictLogger("/emulated-cage/jail/verdicts.jsonl",
                          policy.policy_hash,
                          cage_roots=("/emulated-cage/jail",))

    def test_relative_log_path_refused(self):
        policy = base_policy()
        with self.assertRaises(CagePathError):
            VerdictLogger("verdicts.jsonl", policy.policy_hash)

    def test_sibling_prefix_not_confused(self):
        # "/tmp/.../jail-evil" is NOT inside "/tmp/.../jail": the prefix
        # check is sep-boundaried, not a raw string prefix.
        tmp = tempfile.mkdtemp()
        policy = base_policy()
        cage_root = os.path.join(tmp, "jail")
        os.makedirs(cage_root, exist_ok=True)
        sibling = os.path.join(tmp, "jail-evil", "v.jsonl")
        logger = VerdictLogger(sibling, policy.policy_hash,
                               cage_roots=(cage_root,))
        self.assertTrue(logger.path.endswith("v.jsonl"))
        with self.assertRaises(CagePathError):
            VerdictLogger(os.path.join(cage_root, "v.jsonl"),
                          policy.policy_hash, cage_roots=(cage_root,))

    def test_env_var_never_consulted(self):
        # Cage-side EGRESS_VERDICT_LOG=... is ignored by construction:
        # the path comes only from the constructor (operator config).
        tmp = tempfile.mkdtemp()
        policy = base_policy()
        os.environ["EGRESS_VERDICT_LOG"] = "/tmp/evil-cage-chosen.jsonl"
        try:
            logger = VerdictLogger(os.path.join(tmp, "v.jsonl"),
                                   policy.policy_hash)
        finally:
            del os.environ["EGRESS_VERDICT_LOG"]
        self.assertEqual(logger.path, os.path.join(tmp, "v.jsonl"))

    def test_verdict_lines_carry_policy_hash(self):
        # Registered probe redteam.f81.proxy_verdict_log_policy_hash,
        # synthetic half: rotating the allowlist changes the hash on
        # subsequent lines.
        tmp = tempfile.mkdtemp()
        p1 = base_policy()
        logger = VerdictLogger(os.path.join(tmp, "v.jsonl"), p1.policy_hash)
        proxy = EgressProxy(p1, resolver=fake_resolver(
            {"example.com": [PUBLIC_IP], "new.example": [PUBLIC_IP]}),
            connector=FakeConnector(), logger=logger)
        proxy.mark_ready()
        dec, head = run_allow_session(proxy, connect_req("example.com:443"))
        proxy.reload_policy({"version": "wave57-002", "allow": ["new.example"],
                             "listen": "169.254.240.1", "port": 3128})
        dec, head = run_allow_session(proxy, connect_req("new.example:443"))
        with open(logger.path) as fh:
            lines = [json.loads(l) for l in fh.read().strip().splitlines()]
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0]["policy_version"], "wave57-001")
        self.assertEqual(lines[0]["policy_hash"], p1.policy_hash)
        self.assertEqual(lines[1]["policy_version"], "wave57-002")
        self.assertNotEqual(lines[1]["policy_hash"], p1.policy_hash)
        ok, count, _tip = VerdictLogger.verify_file(logger.path)
        self.assertTrue(ok)
        self.assertEqual(count, 2)

    def test_tamper_breaks_chain_loudly(self):
        tmp = tempfile.mkdtemp()
        policy = base_policy()
        logger = VerdictLogger(os.path.join(tmp, "v.jsonl"),
                               policy.policy_hash)
        proxy = EgressProxy(policy, resolver=fake_resolver(
            {"example.com": [PUBLIC_IP]}), connector=FakeConnector(),
            logger=logger)
        proxy.mark_ready()
        for _ in range(2):
            dec, head = run_allow_session(proxy, connect_req("example.com:443"))
        # Break 1: flip a verdict byte in the middle of the file.
        with open(logger.path, "r+b") as fh:
            data = bytearray(fh.read())
        idx = data.find(b'"verdict": "allow"')
        self.assertNotEqual(idx, -1)
        data[idx + 12:idx + 17] = b"deny!"
        with open(logger.path, "wb") as fh:
            fh.write(bytes(data))
        with self.assertRaises(LogTamperedError):
            VerdictLogger.verify_file(logger.path)

    def test_line_deletion_breaks_chain(self):
        tmp = tempfile.mkdtemp()
        policy = base_policy()
        logger = VerdictLogger(os.path.join(tmp, "v.jsonl"),
                               policy.policy_hash)
        proxy = EgressProxy(policy, resolver=fake_resolver(
            {"example.com": [PUBLIC_IP]}), connector=FakeConnector(),
            logger=logger)
        proxy.mark_ready()
        for _ in range(3):
            dec, head = run_allow_session(proxy, connect_req("example.com:443"))
        with open(logger.path) as fh:
            lines = fh.read().strip().splitlines()
        with open(logger.path, "w") as fh:  # delete the middle line
            fh.write(lines[0] + "\n" + lines[2] + "\n")
        with self.assertRaises(LogTamperedError):
            VerdictLogger.verify_file(logger.path)

    def test_cage_cannot_forge_verdict(self):
        # Break: the cage speaks the verdict protocol down its own
        # client socket. Required: it is just a malformed CONNECT —
        # denied, logged as deny; no allow entry is forgeable.
        tmp = tempfile.mkdtemp()
        policy = base_policy()
        logger = VerdictLogger(os.path.join(tmp, "v.jsonl"),
                               policy.policy_hash)
        proxy = EgressProxy(policy, resolver=fake_resolver(
            {"example.com": [PUBLIC_IP]}), connector=FakeConnector(),
            logger=logger)
        proxy.mark_ready()
        for raw in (b"ALLOW evil.example:443 HTTP/1.1\r\n\r\n",
                    b"\xff\x00GARBAGE\r\n\r\n"):
            dec, head, c = run_session(proxy, raw)
            c.close()
            self.assertEqual(dec.verdict, "deny")
        with open(logger.path) as fh:
            entries = [json.loads(l) for l in fh.read().strip().splitlines()]
        self.assertTrue(entries)
        self.assertTrue(all(e["verdict"] == "deny" for e in entries))

    def test_on_verdict_hook_mirrors_to_audit_chain(self):
        # Deployment wiring: verdicts feed the HMAC-chained audit log
        # (gov/log.py ActionLog, D1-core primitive) via on_verdict.
        # Key custody stays operator-owned; this module never sees keys.
        tmp = tempfile.mkdtemp()
        policy = base_policy()
        mirrored = []
        logger = VerdictLogger(os.path.join(tmp, "v.jsonl"),
                               policy.policy_hash,
                               on_verdict=mirrored.append)
        proxy = EgressProxy(policy, resolver=fake_resolver(
            {"example.com": [PUBLIC_IP]}), connector=FakeConnector(),
            logger=logger)
        proxy.mark_ready()
        dec, head = run_allow_session(proxy, connect_req("example.com:443"))
        self.assertEqual(len(mirrored), 1)
        self.assertEqual(mirrored[0]["rule"], "allowlist")
        self.assertEqual(mirrored[0]["policy_hash"], policy.policy_hash)


# ---------------------------------------------------------------------------
# Proxy compromise containment: what the proxy ITSELF guarantees alone
# (the operator-owned upstream firewall is out of scope — this is the
# code's own blast-radius contract).
# ---------------------------------------------------------------------------

class TestProxySelfGuarantees(unittest.TestCase):
    def test_connector_never_called_on_any_deny(self):
        tmp = tempfile.mkdtemp()
        policy = base_policy()
        connector = FakeConnector()
        proxy = EgressProxy(policy, resolver=fake_resolver(
            {"example.com": ["10.0.0.9"]}),  # allowed name, denied IP
            connector=connector)
        proxy.mark_ready()
        shapes = [
            connect_req("example.com:443"),            # dst-deny
            connect_req("evil.example:443"),          # deny-all
            connect_req("93.184.216.34:443"),         # ip authority
            connect_req("http://example.com/", method="GET"),  # method
            b"GARBAGE\r\n\r\n",                        # malformed
        ]
        for raw in shapes:
            dec, head, c = run_session(proxy, raw)
            c.close()
            self.assertEqual(dec.verdict, "deny")
        self.assertEqual(connector.calls, [])

    def test_connector_called_only_with_decided_target(self):
        policy = base_policy()
        connector = FakeConnector()
        proxy = EgressProxy(policy, resolver=fake_resolver(
            {"example.com": [PUBLIC_IP]}), connector=connector)
        proxy.mark_ready()
        dec, head = run_allow_session(proxy, connect_req("example.com:8443"))
        self.assertEqual(dec.verdict, "allow")
        self.assertEqual(connector.calls,
                         [("example.com", PUBLIC_IP, 8443)])

    def test_header_cap_fail_closed(self):
        # F25 lesson: no unbounded reads on untrusted input.
        policy = base_policy()
        proxy = EgressProxy(policy, resolver=fake_resolver({}),
                            connector=FakeConnector())
        proxy.mark_ready()
        big = b"CONNECT example.com:443 HTTP/1.1\r\n" + b"X-Pad: A" * 4000 \
            + b"\r\n\r\n"
        dec, head, c = run_session(proxy, big)
        c.close()
        self.assertEqual((dec.verdict, dec.rule),
                         ("deny", "malformed-request"))

    def test_relay_transfers_bytes_opaquely(self):
        # The tunnel shape: bytes flow both ways after a 200, opaquely
        # (no TLS interception — deliberate, design doc section 10).
        policy = base_policy()
        connector = FakeConnector()
        proxy = EgressProxy(policy, resolver=fake_resolver(
            {"example.com": [PUBLIC_IP]}), connector=connector)
        proxy.mark_ready()

        def upstream_echo():
            # Fake origin server: read one request chunk, echo it back,
            # then close so the relay sees EOF and terminates promptly.
            peer = connector.peer
            peer.settimeout(10)
            try:
                data = peer.recv(65536)
                if data:
                    peer.sendall(b"ECHO:" + data)
            except OSError:
                pass
            finally:
                try:
                    peer.close()
                except OSError:
                    pass

        client, server = socket.socketpair()
        client.settimeout(10)
        outcome = {}

        def serve():
            try:
                outcome["dec"] = proxy.serve_stream(server, CLIENT)
            except Exception as exc:  # noqa: BLE001
                outcome["error"] = exc
            finally:
                try:
                    server.close()
                except OSError:
                    pass

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            # CONNECT first: the connector (and its peer end) only exists
            # after the proxy reads the request and decides allow.
            client.sendall(connect_req("example.com:443"))
            head = b""
            while b"\r\n\r\n" not in head:
                head += client.recv(4096)
            self.assertIn(b"200", head.split(b"\r\n")[0])
            self.assertIsNotNone(connector.peer)
            eu = threading.Thread(target=upstream_echo, daemon=True)
            eu.start()
            client.sendall(b"hello-tunnel")
            got = b""
            while b"ECHO:hello-tunnel" not in got:
                chunk = client.recv(4096)
                if not chunk:
                    break
                got += chunk
            self.assertIn(b"ECHO:hello-tunnel", got)
        finally:
            client.close()
        t.join(timeout=15)
        eu.join(timeout=15)
        self.assertFalse(t.is_alive(), "relay thread hung")
        if "error" in outcome:
            raise outcome["error"]
        self.assertEqual(outcome["dec"].verdict, "allow")


# ---------------------------------------------------------------------------
# Crash fail-closed + honest reporting (emulated topology).
# ---------------------------------------------------------------------------

class TestCrashFailClosed(unittest.TestCase):
    def test_killed_proxy_means_no_network_never_bypass(self):
        # Break: proxy dies mid-run. Required (emulated): the client's
        # proxy connection fails, DIRECT attempts have no route, and the
        # run reports egress_filtered_unavailable — never network_isolated.
        policy = base_policy()
        proxy = EgressProxy(policy)
        proxy.mark_ready()
        cage = EmulatedCage(("169.254.240.1", 3128), proxy)
        gate = ReadinessGate(proxy)
        run = FilteredRun(cage, gate)
        run.kill_proxy()
        # The proxy socket is gone: the client's half sees EOF.
        client, server = cage.connect_proxy()
        server.close()
        client.settimeout(5)
        try:
            data = client.recv(4096)
        except OSError:
            data = b""
        self.assertEqual(data, b"")  # no proxy -> no bytes, no tunnel
        client.close()
        # Direct egress: no route (the emulated wall).
        with self.assertRaises(NoRouteError):
            cage.connect_direct("93.184.216.34", 443)
        with self.assertRaises(NoRouteError):
            cage.connect_direct("127.0.0.1", 3080)
        # Honest reporting: distinct unavailable state, never collapsed.
        status = run.status()
        self.assertTrue(status["egress_filtered"])
        self.assertTrue(status["egress_filtered_unavailable"])
        self.assertFalse(status["network_isolated"])
        self.assertEqual(status["allowlist_version"], "wave57-001")
        self.assertEqual(status["allowlist_hash"], policy.policy_hash)

    def test_cage_has_no_route_by_construction(self):
        # The ONLY destination the emulated cage can name is the proxy,
        # and only via connect_proxy (the single link route). Even the
        # proxy's own host address is unreachable by direct connect.
        policy = base_policy()
        proxy = EgressProxy(policy)
        cage = EmulatedCage(("169.254.240.1", 3128), proxy)
        with self.assertRaises(NoRouteError):
            cage.connect_direct("169.254.240.1", 22)
        client, server = cage.connect_proxy()
        client.close()
        server.close()


    def test_upstream_firewall_absence_is_reported_not_silent(self):
        # Lane-3 contract §1: a run that never wired the §2 firewall check
        # reports upstream_firewall as "absent" (the enum is exactly
        # verified/degraded/absent — not performing the check IS absent),
        # with a reason string. The field is present, never omitted, never
        # defaulted to verified.
        policy = base_policy()
        proxy = EgressProxy(policy)
        proxy.mark_ready()
        cage = EmulatedCage(("169.254.240.1", 3128), proxy)
        gate = ReadinessGate(proxy)
        run = FilteredRun(cage, gate)
        status = run.status()
        self.assertIn("upstream_firewall", status)
        self.assertEqual(status["upstream_firewall"], "absent")
        self.assertIn("upstream_firewall_reason", status)
        self.assertTrue(status["upstream_firewall_reason"])
        # A deployment that ran the check reports its real state.
        run2 = FilteredRun(cage, gate, firewall_state="verified",
                           firewall_state_reason="operator check exit 0, fresh")
        self.assertEqual(run2.status()["upstream_firewall"], "verified")
        run3 = FilteredRun(cage, gate, firewall_state="absent")
        s3 = run3.status()
        self.assertEqual(s3["upstream_firewall"], "absent")
        self.assertTrue(s3["egress_filtered"])  # two facts, never merged


class TestF125UnicodeDigitPort(unittest.TestCase):
    """Wave-58 Lane 4 (B5 pressure): the CONNECT authority parser must
    never crash on untrusted input. ``str.isdigit()`` accepts non-ASCII
    digits (superscripts, circled numbers, vulgar fractions) that
    ``int()`` rejects — pre-fix, ``decide()`` raised ValueError out of
    ``serve_stream``. Now: ASCII-only port grammar at parse, deny (never
    exception) at decide."""

    def test_unicode_digit_ports_deny_without_exception(self):
        policy = base_policy()
        for auth in ("example.com:\u00b2",      # superscript two
                     "example.com:\u2460\u2461",  # circled digits
                     "example.com:\u00bd",      # vulgar fraction
                     "example.com:\u0668\u0660",  # arabic-indic (int-able but non-ASCII)
                     "[::1]:\u00b2"):
            d = decide(policy, "CONNECT", auth, CLIENT,
                   resolve=fake_resolver({"example.com": [PUBLIC_IP]}))
            self.assertEqual(d.verdict, "deny", auth)
            self.assertEqual(d.rule, "malformed-authority", auth)

    def test_garbage_hosts_deny_without_exception(self):
        policy = base_policy()
        for auth in ("h\x00ost:443", "ho\tst:443", "h\nost:443",
                     "ex%2eample.com:443", "user@host:443", "host:80:evil",
                     "host:", "[::1]", "[]:443", "[::1]:abc"):
            d = decide(policy, "CONNECT", auth, CLIENT,
                   resolve=fake_resolver({"example.com": [PUBLIC_IP]}))
            self.assertEqual(d.verdict, "deny", auth)

    def test_serve_stream_never_raises_on_fuzzed_authority(self):
        # End-to-end: a fuzzed authority over the client socket must yield
        # a Decision (deny), never an escaping exception.
        policy = base_policy()
        proxy = EgressProxy(policy, resolver=fake_resolver({"example.com": [PUBLIC_IP]}))
        proxy.mark_ready()
        for auth in ("example.com:\u00b2", "h\x00ost:443", "host:\u2460"):
            client, server = socket.socketpair()
            try:
                # UTF-8 on the wire (what a real client would send);
                # _read_request decodes latin-1, so multibyte chars become
                # mojibake that the ASCII-only grammar must refuse.
                client.sendall(("CONNECT %s HTTP/1.1\r\n\r\n" % auth).encode("utf-8"))
                d = proxy.serve_stream(server, CLIENT)  # must not raise
                self.assertEqual(d.verdict, "deny", auth)
            finally:
                client.close()
                server.close()

    def test_legitimate_forms_still_parse(self):
        # No legitimate-behavior breakage: policy grammar is ASCII-only,
        # so the tightening cannot refuse anything the allowlist could
        # ever match.
        policy = base_policy()
        d = decide(policy, "CONNECT", "example.com:443", CLIENT,
                   resolve=fake_resolver({"example.com": [PUBLIC_IP]}))
        self.assertEqual(d.verdict, "allow")
        self.assertEqual(d.port, 443)
        d = decide(policy, "CONNECT", "example.com:007", CLIENT,
                   resolve=fake_resolver({"example.com": [PUBLIC_IP]}))
        self.assertEqual(d.verdict, "allow")
        self.assertEqual(d.port, 7)
        d = decide(policy, "CONNECT", "EXAMPLE.COM.:443", CLIENT,
                   resolve=fake_resolver({"example.com": [PUBLIC_IP]}))
        self.assertEqual(d.verdict, "allow")
        self.assertEqual(d.host, "example.com")


# ---------------------------------------------------------------------------
# F81ProxyClosureSpec — Layer B (documentation-only), wave-25 pattern.
#
# These are the three wave-56 design-doc section 9.3 probes, registered in
# evals/scenarios/registry.yaml as closure-probe:pending. They are stated
# against a REAL deployment (real veth/netns topology + operator upstream
# firewall). The synthetic tests above exercise the same shapes against
# the prototype but DO NOT satisfy these probes: a green prototype is a
# mechanism-shape proof, not the wall. F81 stays OPEN until a real
# implementation passes ALL of them plus the wave-25 family.
# ---------------------------------------------------------------------------

class F81ProxyClosureSpec(object):
    """Closure-probe SPECIFICATION for the future real filtered-egress
    implementation. Documentation-only: ``EgressProxy`` is a synthetic
    prototype (EPERM boundary), so these probes are registered — not
    executable against a deployment — in evals/scenarios/registry.yaml.
    """

    # redteam.f81.proxy_dst_deny_above_allow:
    #   Setup: filtered-egress deployment, allowlist ["example.com"],
    #   operator resolver currently answering 10.0.0.9 for example.com
    #   (rebind/poison).
    #   Attack: child CONNECTs example.com:443.
    #   Required: refused at connect time — the dst-deny ordering holds
    #   live, against the address actually connected to, not just the
    #   address checked at decide time.
    proxy_dst_deny_above_allow = "registered; prototype passes synthetically; needs real topology"

    # redteam.f81.proxy_crash_fail_closed:
    #   Setup: filtered-egress deployment mid-run.
    #   Attack: proxy process killed (SIGKILL) mid-run; child attempts
    #   both proxied CONNECT and direct egress.
    #   Required: all egress attempts fail; no bypass; the run reports
    #   egress_filtered_unavailable — never collapsed into
    #   network_isolated=True.
    proxy_crash_fail_closed = "registered; prototype passes synthetically; needs real topology"

    # redteam.f81.proxy_verdict_log_policy_hash:
    #   Setup: filtered-egress deployment with verdict logging.
    #   Attack: rotate the allowlist mid-run; tamper with a verdict line.
    #   Required: verdict lines carry the active allowlist hash, the hash
    #   changes on rotation, and tampering is detected by chain
    #   verification.
    proxy_verdict_log_policy_hash = "registered; prototype passes synthetically; needs real topology"


if __name__ == "__main__":
    unittest.main()
