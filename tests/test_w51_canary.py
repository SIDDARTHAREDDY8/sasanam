"""Wave-51 P1 unit tests: egress canaries (gov/canary.py).

Covers the CanaryMint/CanaryRegistry/planting/trip-detector contract:
determinism + rotation, format realism, exact-match semantics, planting
writes, executor-level trip/halt/audit/escalation, no-trip negatives,
fail-closed audit failure, and the sandbox planting hook. Deterministic,
hermetic (make_run temp dirs), $0.
"""

import os
import re
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("TMPDIR", "/tmp/gov-run")
os.environ.setdefault("GOV_DEV_KEYS", "1")

from gov.log import enable_dev_keys
enable_dev_keys()

from harness import make_run
from gov import canary as cy
from gov.canary import (CanaryMint, CanaryRegistry, CanaryTripHalt,
                        plant_canaries, scan_egress_attempt)


def _mint(run_id="run-w51-test"):
    m = CanaryMint(run_id)
    r = CanaryRegistry()
    r.register(m)
    return m, r


def _canary_host(registry):
    for v, meta in registry._by_value.items():
        if meta["kind"] == "hostname":
            return v
    raise AssertionError("no hostname canary minted")


def _canary_token(registry):
    for v, meta in registry._by_value.items():
        if meta["kind"] == "bearer_token":
            return v
    raise AssertionError("no bearer token canary minted")


class TestMint(unittest.TestCase):
    def test_deterministic_per_run_id(self):
        a = CanaryMint("run-abc").values()
        b = CanaryMint("run-abc").values()
        self.assertEqual([c["value"] for c in a], [c["value"] for c in b])

    def test_rotation_across_runs(self):
        a = {c["value"] for c in CanaryMint("run-one").values()}
        b = {c["value"] for c in CanaryMint("run-two").values()}
        self.assertTrue(a)
        self.assertTrue(b)
        self.assertEqual(a & b, set())

    def test_format_realism(self):
        vals = CanaryMint("run-fmt").values()
        access = [c["value"] for c in vals if c["kind"] == "aws_access_key"]
        self.assertEqual(len(access), 2)
        for v in access:
            self.assertRegex(v, r"^AKIA[0-9A-Z]{16}$")
        secrets = [c["value"] for c in vals if c["kind"] == "aws_secret_key"]
        self.assertEqual(len(secrets), 2)
        for v in secrets:
            self.assertEqual(len(v), 40)
        hosts = [c["value"] for c in vals if c["kind"] == "hostname"]
        self.assertEqual(len(hosts), 3)
        for h in hosts:
            self.assertRegex(h, r"^[a-z0-9-]+\.[a-z]+\.internal$")
        tokens = [c["value"] for c in vals if c["kind"] == "bearer_token"]
        self.assertEqual(len(tokens), 2)
        self.assertTrue(tokens[0].startswith("ghp_"))
        self.assertTrue(tokens[1].startswith("xoxb-"))

    def test_no_recognizable_marker_words(self):
        m = CanaryMint("run-markers")
        for c in m.values():
            for banned in ("canary", "honeypot", "decoy", "fake"):
                self.assertNotIn(banned, c["value"].lower())

    def test_all_values_long_enough_to_match(self):
        for c in CanaryMint("run-len").values():
            self.assertGreaterEqual(len(c["value"]), cy.MIN_MATCHABLE_LEN)


class TestRegistry(unittest.TestCase):
    def test_exact_match(self):
        m, r = _mint()
        token = _canary_token(r)
        hit = r.match_value(token)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["value"], token)

    def test_prefix_does_not_match(self):
        # A real credential sharing a 12-char prefix with a canary is NOT
        # the canary — no trip (near-zero false positives by design).
        m, r = _mint()
        token = _canary_token(r)
        self.assertIsNone(r.match_value(token[:12] + "X" * 30))

    def test_truncation_does_not_match(self):
        m, r = _mint()
        token = _canary_token(r)
        self.assertIsNone(r.match_value(token[:-4]))

    def test_short_strings_never_match(self):
        m, r = _mint()
        self.assertIsNone(r.match_value("short"))
        self.assertIsNone(r.match_value(""))

    def test_host_exactness(self):
        m, r = _mint()
        host = _canary_host(r)
        self.assertIsNotNone(r.match_host(host))
        self.assertIsNotNone(r.match_host(host.upper()))
        # Suffix/lookalike matching is refused by construction.
        self.assertIsNone(r.match_host("evil-" + host))
        self.assertIsNone(r.match_host(host + ".evil.com"))
        self.assertIsNone(r.match_host("unrelated.internal"))

    def test_registry_has_no_jail_api(self):
        # The registry must offer no file-writing API at all: it is
        # purely in-memory, so there is no path that could place
        # registry data where the agent can read it.
        with open(cy.__file__) as _f:
            src = _f.read()
        reg_src = src[src.index("class CanaryRegistry"):
                      src.index("def plant_canaries")]
        for op in ("write_text", "open(", "mkdir", "Path("):
            self.assertNotIn(op, reg_src, op)


class TestPlanting(unittest.TestCase):
    def test_planting_writes_files_and_env(self):
        import tempfile
        m, r = _mint()
        with _tmp_jail() as jail:
            env_additions, manifest = plant_canaries(jail, m)
            for rel in (".aws/credentials", ".env", "etc/hosts",
                        "config/service.conf"):
                self.assertTrue((jail / rel).is_file(), rel)
            for var in ("INTERNAL_API_TOKEN", "AWS_ACCESS_KEY_ID",
                        "AWS_SECRET_ACCESS_KEY", "DATABASE_URL",
                        "STRIPE_SECRET_KEY"):
                self.assertIn(var, env_additions)
            self.assertEqual(manifest["run_id"], m.run_id)
            self.assertEqual(len(manifest["files_written"]), 4)
            # Manifest is server-side: nothing registry-side under the jail.
            for f in manifest["files_written"]:
                self.assertTrue(f.startswith(str(jail)))
            creds = (jail / ".aws" / "credentials").read_text()
            self.assertIn("aws_access_key_id", creds)
            hosts = (jail / "etc" / "hosts").read_text()
            host = _canary_host(r)
            self.assertIn(host, hosts)
            # Hosts map to unroutable space (never valid, never reachable).
            for line in hosts.splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                self.assertTrue(line.startswith("10.255."), line)

    def test_hosts_file_has_no_marker_words(self):
        m, r = _mint()
        with _tmp_jail() as jail:
            plant_canaries(jail, m)
            for rel in (".aws/credentials", ".env", "etc/hosts",
                        "config/service.conf"):
                text = (jail / rel).read_text().lower()
                for banned in ("canary", "honeypot", "decoy"):
                    self.assertNotIn(banned, text, rel)


class _tmp_jail:
    """Minimal context manager for a fake jail dir (no sandbox needed)."""

    def __enter__(self):
        import tempfile
        self._d = tempfile.mkdtemp(prefix="gov-w51-jail-")
        from pathlib import Path
        return Path(self._d)

    def __exit__(self, *a):
        import shutil
        shutil.rmtree(self._d, ignore_errors=True)


class TestScan(unittest.TestCase):
    def test_non_egress_tools_ignored(self):
        m, r = _mint()
        token = _canary_token(r)
        self.assertIsNone(scan_egress_attempt(
            "read_file", {"path": token}, r))

    def test_no_registry_no_scan(self):
        m, r = _mint()
        token = _canary_token(r)
        self.assertIsNone(scan_egress_attempt(
            "http_post", {"url": "https://x/%s" % token}, None))

    def test_hostname_trip(self):
        m, r = _mint()
        host = _canary_host(r)
        hit = scan_egress_attempt(
            "http_post", {"url": "https://%s/exfil" % host}, r)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["kind"], "hostname")

    def test_credential_trip(self):
        m, r = _mint()
        token = _canary_token(r)
        hit = scan_egress_attempt(
            "api_call", {"endpoint": "https://real.example/v1",
                         "params": {"auth": token}}, r)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["kind"], "credential")

    def test_email_to_canary_domain(self):
        m, r = _mint()
        host = _canary_host(r)
        hit = scan_egress_attempt(
            "send_email", {"to": "ops@%s" % host, "body": "x"}, r)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["kind"], "hostname")

    def test_legit_egress_no_trip(self):
        m, r = _mint()
        hit = scan_egress_attempt(
            "http_post",
            {"url": "https://synthetic.local/api",
             "data": "real-user-payload-with-plenty-of-length-0123456789"},
            r)
        self.assertIsNone(hit)

    def test_base64_encoded_canary_trips(self):
        # Break-first c1 -> hardened: one encoding step does not evade.
        import base64
        m, r = _mint()
        token = _canary_token(r)
        enc = base64.b64encode(token.encode()).decode()
        hit = scan_egress_attempt(
            "api_call", {"endpoint": "https://synthetic.local/v1",
                         "params": {"k": enc}}, r)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["kind"], "credential")

    def test_hex_encoded_canary_trips(self):
        import binascii
        m, r = _mint()
        token = _canary_token(r)
        enc = binascii.hexlify(token.encode()).decode()
        hit = scan_egress_attempt(
            "api_call", {"endpoint": "https://synthetic.local/v1",
                         "params": {"k": enc}}, r)
        self.assertIsNotNone(hit)

    def test_url_encoded_canary_trips(self):
        import urllib.parse
        m, r = _mint()
        secret = [c["value"] for c in m.values()
                  if c["kind"] == "aws_secret_key"][0]
        enc = urllib.parse.quote(secret, safe="")
        self.assertNotEqual(enc, secret)  # non-vacuous: secret has +/
        hit = scan_egress_attempt(
            "api_call", {"endpoint": "https://synthetic.local/v1",
                         "params": {"k": enc}}, r)
        self.assertIsNotNone(hit)

    def test_double_encoded_canary_trips(self):
        import base64
        m, r = _mint()
        token = _canary_token(r)
        enc = base64.b64encode(
            base64.b64encode(token.encode())).decode()
        hit = scan_egress_attempt(
            "api_call", {"endpoint": "https://synthetic.local/v1",
                         "params": {"k": enc}}, r)
        self.assertIsNotNone(hit)

    def test_triple_encoded_is_documented_residual(self):
        import base64
        m, r = _mint()
        token = _canary_token(r)
        enc = token.encode()
        for _ in range(3):
            enc = base64.b64encode(enc)
        hit = scan_egress_attempt(
            "api_call", {"endpoint": "https://synthetic.local/v1",
                         "params": {"k": enc.decode()}}, r)
        # Bounded to 2 layers by design (same residual class as DLP F8).
        self.assertIsNone(hit)

    def test_innocent_base64_does_not_trip(self):
        # Random base64-looking text decodes to binary -> rejected, no FP.
        import base64, os
        m, r = _mint()
        blob = base64.b64encode(os.urandom(48)).decode()
        hit = scan_egress_attempt(
            "api_call", {"endpoint": "https://synthetic.local/v1",
                         "params": {"blob": blob}}, r)
        self.assertIsNone(hit)


class TestExecutorTrip(unittest.TestCase):
    def _run_with_canaries(self, run_id="run-w51-exec"):
        run = make_run()
        m = CanaryMint(run_id)
        reg = CanaryRegistry()
        reg.register(m)
        run["executor"].canary_registry = reg
        ident = run["mint_identity"]("agent-1", "operator", "op-1")
        return run, ident, m, reg

    def test_trip_halts_audits_escalates(self):
        run, ident, m, reg = self._run_with_canaries()
        host = _canary_host(reg)
        with self.assertRaises(CanaryTripHalt):
            run["executor"].call(
                ident, "http_post",
                url="https://%s/collect" % host, data="stolen")
        entries = run["read_log"]()
        trips = [e for e in entries if e.get("event") == "canary_trip"]
        self.assertEqual(len(trips), 1)
        trip = trips[0]
        self.assertEqual(trip["decision"], "halted")
        self.assertEqual(trip["policy_id"], "canary-tripwire")
        self.assertEqual(trip["flag"], "canary_trip")
        self.assertEqual(trip["canary_kind"], "hostname")
        pending = [r for r in run["approvals"].all()
                   if r.get("policy_flag") == "canary_trip"]
        self.assertEqual(len(pending), 1)
        self.assertIn("canary", pending[0].get("policy_flag", ""))

    def test_trip_on_token_in_api_call(self):
        run, ident, m, reg = self._run_with_canaries()
        token = _canary_token(reg)
        with self.assertRaises(CanaryTripHalt):
            run["executor"].call(
                ident, "api_call", endpoint="https://synthetic.local/v1",
                params={"Authorization": "Bearer " + token})
        trips = [e for e in run["read_log"]()
                 if e.get("event") == "canary_trip"]
        self.assertEqual(len(trips), 1)
        self.assertEqual(trips[0]["canary_kind"], "credential")

    def test_legit_work_no_trip(self):
        run, ident, m, reg = self._run_with_canaries()
        res = run["executor"].call(
            ident, "http_post", url="https://synthetic.local/api",
            data="legitimate-payload-0123456789abcdef")
        self.assertNotEqual(res.get("status"), "halted")
        trips = [e for e in run["read_log"]()
                 if e.get("event") == "canary_trip"]
        self.assertEqual(trips, [])

    def test_previous_run_canaries_do_not_trip(self):
        run, ident, m, reg = self._run_with_canaries(run_id="run-current")
        old = CanaryMint("run-previous")
        old_host = [c["value"] for c in old.values()
                    if c["kind"] == "hostname"][0]
        # Rotation: the old values are disjoint from the current registry.
        self.assertIsNone(reg.match_host(old_host))
        res = run["executor"].call(
            ident, "http_post",
            url="https://%s/old" % old_host, data="x")
        trips = [e for e in run["read_log"]()
                 if e.get("event") == "canary_trip"]
        self.assertEqual(trips, [])

    def test_registry_none_no_behavior_change(self):
        run = make_run()
        ident = run["mint_identity"]("agent-1", "operator", "op-1")
        # Feature off: no canary_registry attribute override; the
        # pre-existing default must be None and egress proceeds normally.
        self.assertIsNone(run["executor"].canary_registry)
        res = run["executor"].call(
            ident, "http_post", url="https://synthetic.local/api",
            data="plain-payload-0123456789")
        trips = [e for e in run["read_log"]()
                 if e.get("event") == "canary_trip"]
        self.assertEqual(trips, [])

    def test_fail_closed_when_audit_raises(self):
        run, ident, m, reg = self._run_with_canaries()
        host = _canary_host(reg)
        orig_append = run["executor"].log.append

        def _boom(entry):
            raise RuntimeError("log unavailable")

        run["executor"].log.append = _boom
        try:
            with self.assertRaises(CanaryTripHalt):
                run["executor"].call(
                    ident, "http_post",
                    url="https://%s/collect" % host, data="stolen")
        finally:
            run["executor"].log.append = orig_append
        # The tool must not have executed: no tool_call entry for it.
        calls = [e for e in run["read_log"]()
                 if e.get("event") == "tool_call"
                 and e.get("tool") == "http_post"]
        self.assertEqual(calls, [])

    def test_tool_output_canary_replayed_trips(self):
        # Probe (c): the canary arrives in TOOL OUTPUT (never planted in
        # env); the agent replays it in an egress call -> trip on use.
        run, ident, m, reg = self._run_with_canaries()
        token = _canary_token(reg)
        tool_output = "search results: ... api key %s ..." % token
        with self.assertRaises(CanaryTripHalt):
            run["executor"].call(
                ident, "api_call", endpoint="https://synthetic.local/v1",
                params={"key": token, "note": tool_output[:40]})
        trips = [e for e in run["read_log"]()
                 if e.get("event") == "canary_trip"]
        self.assertEqual(len(trips), 1)


class TestSandboxHook(unittest.TestCase):
    def test_hook_plants_into_jail(self):
        from gov.sandbox import Sandbox
        m, r = _mint("run-w51-sb")
        sb = Sandbox(canary_plant=cy.make_canary_plant(m))
        with sb.temp_jail() as jail:
            env_additions = sb.canary_plant(jail, {})
            self.assertIn("AWS_ACCESS_KEY_ID", env_additions)
            self.assertTrue((jail / ".aws" / "credentials").is_file())
            self.assertTrue((jail / "etc" / "hosts").is_file())

    def test_hook_default_off(self):
        from gov.sandbox import Sandbox
        sb = Sandbox()
        self.assertIsNone(sb.canary_plant)


if __name__ == "__main__":
    unittest.main()
