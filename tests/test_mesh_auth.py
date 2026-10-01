"""Unit tests for gov/mesh_auth.py (wave-263 lane 2).

Tests sit at the public seams: card declaration, per-call
authorization, and the task escalation state machine. No internals.
"""

import hashlib
import os
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import mesh_auth as ma
from gov import svid_issuer as sv
from gov import scoped_tool_listing as stl
from gov import short_lived_credentials as slc

UNIVERSE = frozenset({"files:read", "net:fetch"})
TICKET_KEY = b"unit-ticket-key-32-bytes-padded-0"
CRED_KEY = b"unit-cred-key-32-bytes-padded-0000"
ISSUER_SEED = bytes(range(32))
TRUST_DOMAIN = "example.org"
SPIFFE_A = "spiffe://example.org/agent-a"
SPIFFE_B = "spiffe://example.org/agent-b"
NOW = 4000000000.0


def _pubkey(tag):
    return hashlib.sha256(("unit-" + tag).encode()).hexdigest()


def _sub(spiffe_id):
    return hashlib.sha256(spiffe_id.encode()).hexdigest()


class World(unittest.TestCase):
    def setUp(self):
        issuer = sv.TestSvidIssuer(issuer_seed=ISSUER_SEED,
                                   key_id="unit-issuer-1")
        verifier = sv.SvidVerifier(
            {"unit-issuer-1": issuer.issuer_public_key}, TRUST_DOMAIN)
        control = sv.MeshControl(verifier,
                                 {"allow": [SPIFFE_A, SPIFFE_B]})
        tickets = stl.ScopeTicketIssuer(TICKET_KEY, UNIVERSE)
        d = tempfile.mkdtemp(prefix="ma-unit-", dir="/var/tmp")
        creds = slc.CredentialIssuer(
            os.path.join(d, "j.jsonl"), key=CRED_KEY)
        self.issuer = issuer
        self.gate = ma.MeshCallGate(svid_control=control,
                                    ticket_issuer=tickets,
                                    credential_issuer=creds)
        self.tickets = tickets
        self.creds = creds

    def svid_env(self, spiffe_id=SPIFFE_A):
        return {"scheme": "svid",
                "credential": self.issuer.issue(
                    spiffe_id, _pubkey(spiffe_id), 15, now=NOW)}

    def ticket_env(self, spiffe_id=SPIFFE_A, scopes=("net:fetch",)):
        return {"scheme": "scope-ticket",
                "credential": self.tickets.seal(_sub(spiffe_id),
                                                set(scopes), NOW)}

    def cred_env(self, principal="svc-a", scope="files:read"):
        c = self.creds.issue(principal, scope, 600)
        return {"scheme": "short-lived-credential",
                "credential": {"credential_id": c["credential_id"],
                               "secret": c["secret"]}}

    def card(self, *schemes):
        return ma.MeshAuthCard("agent-b", list(schemes),
                               endpoints={"rpc": "https://b/x"},
                               capabilities=["fetch_url"])

    def _refused(self, fn, code):
        # Composed verifiers raise their own code-carrying exceptions;
        # their codes propagate unchanged (composition, not wrapping).
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - test helper
            self.assertTrue(
                hasattr(e, "code"),
                "refusal %r carries no machine code" % (e,))
            self.assertEqual(e.code, code)
            return
        self.fail("no refusal raised (wanted %s)" % code)


class DeclarationTest(World):
    def test_a2a_aliases_resolve_to_our_primitives(self):
        c = self.card("mTLS", "oauth2", "apiKey", "http")
        self.assertEqual(c.resolved_schemes,
                         frozenset({"svid", "scope-ticket",
                                    "short-lived-credential"}))

    def test_oidc_declaration_is_malformed(self):
        # We have no OIDC primitive: declaring it refuses rather than
        # pretending support.
        self._refused(lambda: self.card("oidc"), "mesh-auth-malformed")

    def test_unknown_scheme_declaration_is_malformed(self):
        self._refused(lambda: self.card("kerberos"), "mesh-auth-malformed")

    def test_public_view_hides_endpoints(self):
        v = self.card("svid").public_view()
        self.assertNotIn("endpoints", v)
        self.assertEqual(v["security_schemes"], ["svid"])

    def test_authenticated_view_reveals_endpoints(self):
        v = self.card("svid").authenticated_view()
        self.assertEqual(v["endpoints"]["rpc"], "https://b/x")


class GateTest(World):
    def test_svid_call_authorizes(self):
        rec = self.gate.authorize_call(
            self.card("svid"), self.svid_env(), now=NOW)
        self.assertEqual(rec["subject"], SPIFFE_A)
        self.assertEqual(rec["scheme"], "svid")
        self.assertEqual(rec["dimensions"]["who"], SPIFFE_A)
        self.assertEqual(rec["dimensions"]["what"], "agent-b")
        self.assertIn("endpoints", rec["authenticated_card"])

    def test_envelope_missing_refuses(self):
        self._refused(
            lambda: self.gate.authorize_call(
                self.card("svid"), None, now=NOW),
            "mesh-auth-envelope-missing")

    def test_undeclared_scheme_refuses(self):
        self._refused(
            lambda: self.gate.authorize_call(
                self.card("svid"), self.ticket_env(), now=NOW),
            "mesh-auth-undeclared-scheme")

    def test_scheme_confusion_refuses(self):
        # Valid SVID, but the call requires a scope ticket.
        self._refused(
            lambda: self.gate.authorize_call(
                self.card("svid", "scope-ticket"), self.svid_env(),
                required_scheme="scope-ticket", now=NOW),
            "mesh-auth-scheme-confusion")

    def test_wrong_payload_shape_is_confusion(self):
        # Envelope claims scope-ticket but carries an SVID document.
        self._refused(
            lambda: self.gate.authorize_call(
                self.card("scope-ticket"),
                {"scheme": "scope-ticket",
                 "credential": self.svid_env()["credential"]},
                now=NOW),
            "mesh-auth-scheme-confusion")

    def test_tampered_ticket_propagates_scope_code(self):
        env = self.ticket_env()
        bad = env["credential"][:-2] + ("AA" if not env["credential"].endswith("AA") else "BB")
        self._refused(
            lambda: self.gate.authorize_call(
                self.card("scope-ticket"),
                {"scheme": "scope-ticket", "credential": bad}, now=NOW),
            "scope-grant-tampered")

    def test_scope_coverage_enforced(self):
        # Ticket covers net:fetch only; the call requires files:read.
        self._refused(
            lambda: self.gate.authorize_call(
                self.card("scope-ticket"), self.ticket_env(),
                required_scopes={"files:read"}, now=NOW),
            "mesh-auth-scope-uncovered")
        rec = self.gate.authorize_call(
            self.card("scope-ticket"), self.ticket_env(),
            required_scopes={"net:fetch"}, now=NOW)
        self.assertEqual(rec["scopes"], ["net:fetch"])

    def test_subject_mismatch_refuses(self):
        # Ticket bound to A presented with B's authenticated subject.
        self._refused(
            lambda: self.gate.authorize_call(
                self.card("scope-ticket"), self.ticket_env(SPIFFE_A),
                subject=SPIFFE_B, now=NOW),
            "mesh-auth-subject-mismatch")
        rec = self.gate.authorize_call(
            self.card("scope-ticket"), self.ticket_env(SPIFFE_A),
            subject=SPIFFE_A, now=NOW)
        self.assertEqual(rec["subject"], SPIFFE_A)

    def test_short_lived_credential_call_authorizes(self):
        # Credentials are issued on wall-clock time: verify on wall
        # clock too (now=None).
        rec = self.gate.authorize_call(
            self.card("short-lived-credential"), self.cred_env())
        self.assertEqual(rec["subject"], "svc-a")
        self.assertEqual(rec["scopes"], ["files:read"])

    def test_bad_svid_propagates_svid_code(self):
        # Flip a hex char in the signature: trust domain still
        # matches, so the failure lands on signature verification.
        env = self.svid_env()
        sig = env["credential"]["issuer_signature"]
        env["credential"]["issuer_signature"] = \
            ("0" if sig[0] != "0" else "1") + sig[1:]
        self._refused(
            lambda: self.gate.authorize_call(
                self.card("svid"), env, now=NOW),
            "svid-signature-invalid")

    def test_nonfinite_now_refuses_first(self):
        self._refused(
            lambda: self.gate.authorize_call(
                self.card("svid"), self.svid_env(), now=float("nan")),
            "mesh-auth-malformed")


class TaskTest(World):
    def _tasks(self):
        return ma.MeshTaskAuth(self.gate)

    def test_escalate_pauses_and_resume_reauthenticates(self):
        t = self._tasks()
        t.begin("t")
        t.call("t", self.card("svid"), self.svid_env(), now=NOW)
        esc = t.escalate("t", "scope-ticket", "needs the scope grant",
                         now=NOW)
        self.assertEqual(esc["state"], ma.TASK_STATE_AUTH_REQUIRED)
        self.assertEqual(t.state("t"), ma.TASK_STATE_AUTH_REQUIRED)
        self._refused(
            lambda: t.call("t", self.card("svid", "scope-ticket"),
                           self.svid_env(), now=NOW),
            "mesh-auth-task-paused")
        self.assertEqual(t.state("t"), ma.TASK_STATE_AUTH_REQUIRED)
        self._refused(
            lambda: t.resume("t", self.card("svid", "scope-ticket"),
                             self.svid_env(), now=NOW),
            "mesh-auth-escalation-bypass")
        rec = t.resume("t", self.card("svid", "scope-ticket"),
                       self.ticket_env(), subject=SPIFFE_A, now=NOW)
        self.assertEqual(rec["scheme"], "scope-ticket")
        self.assertEqual(t.state("t"), ma.TASK_STATE_ACTIVE)

    def test_escalation_record_is_the_out_of_band_contract(self):
        t = self._tasks()
        t.begin("t")
        t.escalate("t", "scope-ticket", "needs the scope grant", now=NOW)
        rec = t.escalation_record("t")
        self.assertEqual(rec["required_scheme"], "scope-ticket")
        self.assertIn("grant", rec["reason"])

    def test_abandon_is_terminal(self):
        t = self._tasks()
        t.begin("t")
        t.abandon("t")
        self.assertEqual(t.state("t"), ma.TASK_STATE_ABANDONED)
        self._refused(
            lambda: t.call("t", self.card("svid"), self.svid_env(),
                           now=NOW),
            "mesh-auth-malformed")

    def test_escalate_requires_a_reason(self):
        t = self._tasks()
        t.begin("t")
        self._refused(lambda: t.escalate("t", "scope-ticket", "  ",
                                         now=NOW),
                      "mesh-auth-malformed")

    def test_unknown_task_refuses(self):
        t = self._tasks()
        self._refused(lambda: t.state("nope"), "mesh-auth-malformed")


if __name__ == "__main__":
    unittest.main()
