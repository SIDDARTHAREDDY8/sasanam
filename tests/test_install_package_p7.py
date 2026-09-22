"""P7 governed package installation (wave-27): agent-runtime fetch control.

F75 (CLOSED wave-23) governs the product's own dependency graph
(requirements.lock + gov/supplychain.py). This module pins the
agent-runtime angle the incident probe
``redteam.incident.p7.unpinned_dependency_fetch_allowed`` exercises:
raw api_call/http_post fetches from package registries are denied by
policy (deny-ungoverned-package-fetch), and the ONLY sanctioned install
path is the ``install_package`` tool, which enforces the agent-runtime
pin set (allowlist + exact version pin + sha256 artifact verification)
via gov/supplychain_install.py.

Deterministic, synthetic, no network, no real pip, no filesystem
mutation (the fetch is canonical simulated bytes).
"""

import unittest
from pathlib import Path
from unittest import mock

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov import supplychain_install as sc_install
from tests import harness

REPO_ROOT = Path(__file__).resolve().parent.parent

PINNED = {"name": "requests", "version": "2.32.3"}
PIN_DIGEST = sc_install.AGENT_PACKAGE_PINS["requests"]["sha256"]


def _ctx():
    return harness.make_run()


class RegistryHostTest(unittest.TestCase):
    def test_registry_hosts_recognized(self):
        self.assertTrue(sc_install.is_registry_host("pypi.org"))
        self.assertTrue(sc_install.is_registry_host("files.pythonhosted.org"))
        self.assertTrue(sc_install.is_registry_host("registry.synthetic.local"))
        self.assertTrue(sc_install.is_registry_host(
            "mirror.registry.synthetic.local"))

    def test_non_registry_hosts_not_matched(self):
        self.assertFalse(sc_install.is_registry_host("synthetic.local"))
        self.assertFalse(sc_install.is_registry_host("telemetry.synthetic.local"))
        self.assertFalse(sc_install.is_registry_host("evilpypi.org"))
        self.assertFalse(sc_install.is_registry_host(None))
        self.assertFalse(sc_install.is_registry_host(""))

    def test_package_fetch_shape(self):
        self.assertTrue(sc_install.is_package_fetch(
            "api_call", "https://registry.synthetic.local/reqeusts"))
        self.assertTrue(sc_install.is_package_fetch(
            "http_post", "https://pypi.org/simple/requests/"))
        self.assertFalse(sc_install.is_package_fetch(
            "api_call", "https://telemetry.synthetic.local/ping"))
        self.assertFalse(sc_install.is_package_fetch(
            "api_call", "not a url"))
        # The governed tool is the sanctioned path, never a raw fetch.
        self.assertFalse(sc_install.is_package_fetch(
            "install_package", "https://pypi.org/simple/requests/"))


class CheckInstallTest(unittest.TestCase):
    def test_pinned_install_verifies(self):
        ok, digest = sc_install.check_install("requests", "2.32.3")
        self.assertTrue(ok)
        self.assertEqual(digest, PIN_DIGEST)

    def test_typosquat_not_allowlisted(self):
        ok, reason = sc_install.check_install("reqeusts", "2.32.9")
        self.assertFalse(ok)
        self.assertEqual(reason, "not-allowlisted")

    def test_version_drift_refused(self):
        ok, reason = sc_install.check_install("requests", "2.32.4")
        self.assertFalse(ok)
        self.assertEqual(reason, "version-mismatch")

    def test_latest_never_resolves(self):
        ok, reason = sc_install.check_install("requests", "latest")
        self.assertFalse(ok)
        self.assertEqual(reason, "version-mismatch")

    def test_missing_version_refused(self):
        ok, reason = sc_install.check_install("requests", None)
        self.assertFalse(ok)
        self.assertEqual(reason, "version-mismatch")

    def test_tampered_artifact_refused(self):
        with mock.patch.object(sc_install, "fetch_artifact_bytes",
                               return_value=b"tampered-bytes"):
            ok, reason = sc_install.check_install("requests", "2.32.3")
        self.assertFalse(ok)
        self.assertEqual(reason, "integrity-mismatch")


class InstallPackageCallPathTest(unittest.TestCase):
    # -- raw registry fetch: denied on the call path -------------------
    def test_typosquat_api_call_to_registry_denied(self):
        ctx = _ctx()
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]
        r = ex.call(coder, "api_call",
                    endpoint="https://registry.synthetic.local/reqeusts",
                    params={"name": "reqeusts", "version": "2.32.9",
                            "wanted": "latest", "integrity": "unverified"})
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r.get("policy_id"), "deny-ungoverned-package-fetch")

    def test_raw_http_post_to_pypi_denied(self):
        # pypi.org is not on the egress domain allowlist, so the
        # pre-existing deny-egress-unallowlisted fires first — the
        # deny-pass order is unchanged by the new rule.
        ctx = _ctx()
        ex = ctx["executor"]
        researcher = ctx["identities"]["researcher"]
        r = ex.call(researcher, "http_post",
                    url="https://pypi.org/simple/reqeusts/",
                    payload={"name": "reqeusts"})
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r.get("policy_id"), "deny-egress-unallowlisted")

    def test_raw_http_post_to_allowlisted_registry_denied(self):
        # registry.synthetic.local IS egress-allowlisted: this is the
        # shape deny-ungoverned-package-fetch exists for.
        ctx = _ctx()
        ex = ctx["executor"]
        researcher = ctx["identities"]["researcher"]
        r = ex.call(researcher, "http_post",
                    url="https://registry.synthetic.local/reqeusts",
                    payload={"name": "reqeusts", "version": "2.32.9"})
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r.get("policy_id"), "deny-ungoverned-package-fetch")

    def test_non_registry_api_call_unaffected(self):
        # The deny is scoped to registry hosts: ordinary API traffic
        # keeps its existing verdict (not refused by the new rule).
        ctx = _ctx()
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]
        r = ex.call(coder, "api_call",
                    endpoint="https://telemetry.synthetic.local/ping",
                    params={"i": 1})
        self.assertEqual(r["status"], "executed")
        self.assertNotEqual(r.get("policy_id"),
                            "deny-ungoverned-package-fetch")

    def test_non_allowlisted_registry_still_egress_denied(self):
        # registry.npmjs.org is not on the egress allowlist: the
        # pre-existing deny-egress-unallowlisted fires first (deny-pass
        # order preserved — no behavior change there).
        ctx = _ctx()
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]
        r = ex.call(coder, "api_call",
                    endpoint="https://registry.npmjs.org/reqeusts",
                    params={"name": "reqeusts"})
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r.get("policy_id"), "deny-egress-unallowlisted")

    # -- governed install path -----------------------------------------
    def test_pinned_install_executes_with_digest(self):
        ctx = _ctx()
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]
        r = ex.call(coder, "install_package", **PINNED)
        self.assertEqual(r["status"], "executed")
        result = r.get("result") or {}
        self.assertTrue(result.get("installed"))
        self.assertEqual(result.get("sha256"), PIN_DIGEST)
        # The audit entry carries the integrity evidence and the
        # authorizing policy.
        calls = [e for e in ctx["read_log"]()
                 if e.get("event") == "tool_call"
                 and e.get("tool") == "install_package"]
        self.assertTrue(calls)
        self.assertEqual(calls[-1].get("policy_id"), "allow-verified-install")
        self.assertEqual(calls[-1].get("decision"), "allowed_executed")

    def test_typosquat_install_denied(self):
        ctx = _ctx()
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]
        r = ex.call(coder, "install_package",
                    name="reqeusts", version="2.32.9")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r.get("policy_id"), "deny-install-not-allowlisted")

    def test_unpinned_install_denied(self):
        ctx = _ctx()
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]
        r = ex.call(coder, "install_package",
                    name="requests", version="latest")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r.get("policy_id"), "deny-install-not-allowlisted")

    def test_version_drift_install_denied(self):
        ctx = _ctx()
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]
        r = ex.call(coder, "install_package",
                    name="requests", version="9.9.9")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r.get("policy_id"), "deny-install-not-allowlisted")

    def test_tampered_artifact_install_denied(self):
        ctx = _ctx()
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]
        with mock.patch.object(sc_install, "fetch_artifact_bytes",
                               return_value=b"tampered-bytes"):
            r = ex.call(coder, "install_package", **PINNED)
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r.get("policy_id"),
                         "deny-install-integrity-mismatch")

    def test_role_without_install_refused(self):
        # Least privilege: the support role never gets install_package.
        ctx = _ctx()
        ex = ctx["executor"]
        support = ctx["identities"]["support"]
        r = ex.call(support, "install_package", **PINNED)
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r.get("policy_id"), "role-allowlist")

    def test_policy_context_carries_install_gates(self):
        # The decision-input snapshot records what the engine saw.
        ctx = _ctx()
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]
        ex.call(coder, "install_package", **PINNED)
        calls = [e for e in ctx["read_log"]()
                 if e.get("event") == "tool_call"
                 and e.get("tool") == "install_package"]
        snap = calls[-1].get("policy_context") or {}
        self.assertTrue(snap.get("install_allowlisted"))
        self.assertTrue(snap.get("install_integrity_verified"))


if __name__ == "__main__":
    unittest.main()
