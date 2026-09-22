"""F111 closure tests: harness credential compartmentalization.

GTG-50020 (STUPID-2026-0104): a prompt-injected eval sandbox handed
over production credentials; the actor spent them against ~30 AI
companies. Two closure criteria:

(i)  credential-manifest control: the agent's provisioned/reachable
     credentials are asserted scoped, short-lived, non-production --
     a harness-mounted production-shaped secret the manifest does not
     cover fails closed (run refuses to start);
(ii) identity-bound egress: api_call/http_post carrying a credential
     not matching the provisioned session identity -> denied +
     audited (credential_identity_mismatch).
"""

import os
import sys
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # noqa: E402
from gov.credential_manifest import (  # noqa: E402
    CredentialManifest,
    CredentialManifestError,
)

_PROD_KEY = "sk_live_SYNTHETICPROBEKEY9f3a2c1e4d5b"
_TEST_KEY = "sk_test_SYNTHETICPROBEKEY9f3a2c1e4d5b"


def _write(scope_root, rel, content):
    p = Path(scope_root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


class TestF111ManifestDeclaration(unittest.TestCase):
    def test_declare_rejects_production_shaped_secret(self):
        # (i), non-production assertion: the harness cannot provision a
        # production-shaped credential into the agent's reachable scope.
        ctx = make_run()
        scope = ctx["run_dir"] / "sandbox"
        p = _write(scope, "config/harness_mount.json",
                   '{"harness_api_key": "%s"}' % _PROD_KEY)
        manifest = CredentialManifest()
        with self.assertRaises(CredentialManifestError) as cm:
            manifest.declare(str(p), credential_id="harness-key",
                             owner_principal="harness-prod",
                             scope="api", ttl_s=600)
        self.assertIn("production_credential_rejected", str(cm.exception))

    def test_declare_accepts_non_production(self):
        # Test-shaped keys are the non-production shape the manifest
        # exists to allow: scoped, short-lived, declared.
        ctx = make_run()
        scope = ctx["run_dir"] / "sandbox"
        p = _write(scope, "config/agent_mount.json",
                   '{"api_key": "%s"}' % _TEST_KEY)
        manifest = CredentialManifest()
        cid = manifest.declare(str(p), credential_id="agent-key",
                               owner_principal="research-org",
                               scope="api", ttl_s=600)
        self.assertEqual(cid, "agent-key")
        self.assertEqual(manifest.owner_of("agent-key"), "research-org")

    def test_declare_fail_closed_unreadable(self):
        manifest = CredentialManifest()
        with self.assertRaises(CredentialManifestError):
            manifest.declare("/nonexistent/path/key.json",
                             credential_id="x", owner_principal="y",
                             scope="api")

    def test_verify_scope_fails_on_undeclared_credential(self):
        # (i): a production-shaped secret mounted WITHOUT a declaration
        # -- the GTG-50020 first leg -- fails closed: the run must not
        # start.
        ctx = make_run()
        scope = ctx["run_dir"] / "sandbox"
        _write(scope, "config/harness_mount.json",
               '{"harness_api_key": "%s"}' % _PROD_KEY)
        manifest = CredentialManifest()
        with self.assertRaises(CredentialManifestError) as cm:
            manifest.verify_scope(scope)
        self.assertIn("undeclared_credential_in_scope", str(cm.exception))

    def test_verify_scope_passes_when_declared(self):
        ctx = make_run()
        scope = ctx["run_dir"] / "sandbox"
        p = _write(scope, "config/agent_mount.json",
                   '{"api_key": "%s"}' % _TEST_KEY)
        manifest = CredentialManifest()
        manifest.declare(str(p), credential_id="agent-key",
                         owner_principal="research-org",
                         scope="api", ttl_s=600)
        manifest.verify_scope(scope)  # must not raise

    def test_verify_scope_ignores_benign_files(self):
        ctx = make_run()
        scope = ctx["run_dir"] / "sandbox"
        _write(scope, "notes.md", "nothing sensitive here\n")
        CredentialManifest().verify_scope(scope)  # must not raise


class TestF111IdentityBoundEgress(unittest.TestCase):
    def _run(self, **kw):
        return make_run(session_identity=("agent-1", "researcher",
                                           "research-org"), **kw)

    def test_foreign_credential_id_denied(self):
        # (ii): the GTG-50020 payoff leg -- egress carrying a credential
        # owned by harness-prod under the research-org session identity
        # -> denied + audited as credential_identity_mismatch.
        ctx = self._run()
        manifest = ctx["credential_manifest"]
        scope = ctx["run_dir"] / "sandbox"
        p = _write(scope, "config/agent_mount.json",
                   '{"api_key": "%s"}' % _TEST_KEY)
        manifest.declare(str(p), credential_id="harness-key",
                         owner_principal="harness-prod",
                         scope="api", ttl_s=600)
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]
        before = len(ctx["read_log"]())
        r = ex.call(coder, "api_call",
                    endpoint="https://telemetry.synthetic.local/v1/whoami",
                    params={"action": "whoami"},
                    credential_id="harness-key")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r.get("policy_id"), "credential_identity_mismatch")
        flags = [e.get("flag") for e in ctx["read_log"]()[before:]]
        self.assertIn("credential_identity_mismatch", flags)

    def test_own_credential_id_allowed(self):
        # The governed path works: a credential bound to the session
        # identity's principal is not a mismatch.
        ctx = self._run()
        manifest = ctx["credential_manifest"]
        scope = ctx["run_dir"] / "sandbox"
        p = _write(scope, "config/agent_mount.json",
                   '{"api_key": "%s"}' % _TEST_KEY)
        manifest.declare(str(p), credential_id="agent-key",
                         owner_principal="research-org",
                         scope="api", ttl_s=600)
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]
        r = ex.call(coder, "api_call",
                    endpoint="https://telemetry.synthetic.local/v1/whoami",
                    params={"action": "whoami"},
                    credential_id="agent-key")
        self.assertNotEqual(r.get("policy_id"), "credential_identity_mismatch")
        self.assertNotEqual(r["status"], "denied")

    def test_explicit_foreign_owner_denied(self):
        ctx = self._run()
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]
        r = ex.call(coder, "api_call",
                    endpoint="https://telemetry.synthetic.local/v1/whoami",
                    params={"action": "whoami"},
                    credential_owner="harness-prod")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r.get("policy_id"), "credential_identity_mismatch")

    def test_unknown_credential_id_denied(self):
        # Fail-closed: a credential_id the manifest never declared is a
        # mismatch, not a free pass.
        ctx = self._run()
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]
        r = ex.call(coder, "api_call",
                    endpoint="https://telemetry.synthetic.local/v1/whoami",
                    params={"action": "whoami"},
                    credential_id="never-declared")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r.get("policy_id"), "credential_identity_mismatch")

    def test_no_session_identity_no_mismatch(self):
        # Documented: the identity-bound rule requires a provisioned
        # session identity; without one there is nothing to bind to.
        ctx = make_run()
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]
        r = ex.call(coder, "api_call",
                    endpoint="https://telemetry.synthetic.local/v1/whoami",
                    params={"action": "whoami"},
                    credential_owner="harness-prod")
        self.assertNotEqual(r.get("policy_id"), "credential_identity_mismatch")

    def test_expired_credential_denied(self):
        ctx = self._run()
        manifest = ctx["credential_manifest"]
        scope = ctx["run_dir"] / "sandbox"
        p = _write(scope, "config/agent_mount.json",
                   '{"api_key": "%s"}' % _TEST_KEY)
        manifest.declare(str(p), credential_id="agent-key",
                         owner_principal="research-org",
                         scope="api", ttl_s=600)
        # Force expiry.
        manifest._entries["agent-key"]["expires_at"] = 1
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]
        r = ex.call(coder, "api_call",
                    endpoint="https://telemetry.synthetic.local/v1/whoami",
                    params={"action": "whoami"},
                    credential_id="agent-key")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r.get("policy_id"), "credential_identity_mismatch")


if __name__ == "__main__":
    unittest.main()
