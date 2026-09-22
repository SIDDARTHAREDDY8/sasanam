"""D1-core Phase 3 tests: web-UI delegation + quorum surfaces.

Covers the ``gov/approval_web.py`` D1 additions (§9):

* session principal binding (every session acts as WEB_DECIDED_BY,
  never as a form-supplied name)
* detail/list surfaces for the DELEGATED and QUORUM_COLLECTING
  substates, bridge-expiry markers, and escaped rendering of all D1
  fields
* ``POST /approvals/<id>/delegate`` — happy path, 6-gate stack
  (auth / origin / CSRF), refusal audits, replay protection
* ``POST /approvals/<id>/vote`` — happy path, quorum finalization,
  deny veto, principal-spoof resistance, refusal audits
* decide() interplay: refused on quorum records and on records
  delegated away from the web operator
* policy wiring: --policy installs the delegation section; without
  it delegation stays off (fail closed)

Drives a localhost ThreadingHTTPServer via http.client against
deterministic harness.make_run() fixtures, like
tests/test_gov_approval_web.py. Quiet-box: run with a private
TMPDIR=/tmp/gov-run/<runid>.
"""

import http.client
import json
import os
import re
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_TESTS_DIR)
for _p in (_TESTS_DIR, _REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # noqa: E402
from gov.approval_web import (  # noqa: E402
    WEB_DECIDED_BY,
    make_server,
)
from gov.approvals import approval_record_digest  # noqa: E402

TOKEN = "d1-web-test-token"

QUORUM_WEB = {"min_approvals": 2,
              "eligible_principals": [WEB_DECIDED_BY, "alice", "bob"]}

_DELEG_POLICY = """\
version: 1
approvals:
  delegation:
    enabled: true
    max_hops: 1
"""


class WebD1Base(unittest.TestCase):
    def setUp(self):
        self.ctx = make_run()
        self.policy_file = None
        self.server = make_server(self.ctx["run_dir"], token=TOKEN)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.ident = self.ctx["identities"]["support"]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)

    # -- fixtures ------------------------------------------------------
    def _policy_path(self):
        path = Path(tempfile.mkdtemp(prefix="govred-pol-")) / "policy.yaml"
        path.write_text(_DELEG_POLICY, encoding="utf-8")
        self.policy_file = str(path)
        return self.policy_file

    def make_delegating_server(self):
        """Rebuild the server with --policy so its queue enforces the
        delegation section like the CLI does."""
        self.tearDown()
        self.server = make_server(self.ctx["run_dir"], token=TOKEN,
                                  policy_path=self._policy_path())
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()

    def queue_email(self, to="victim@synthetic.local"):
        res = self.ctx["executor"].call(
            self.ident, "send_email", to=to, subject="s", body="b",
            justification="routine vendor invoice")
        self.assertEqual(res["status"], "queued", res)
        return res["approval_id"]

    def queue_quorum_email(self, cfg=None):
        self.ctx["approvals"].set_quorum_config(cfg or QUORUM_WEB)
        return self.queue_email()

    def approval(self, aid):
        return self.ctx["approvals"].get(aid)

    def audit_events(self, event, approval_id=None):
        return [e for e in self.ctx["read_log"]()
                if e.get("event") == event
                and (approval_id is None or
                     e.get("approval_id") == approval_id)]

    # -- http ----------------------------------------------------------
    def _request(self, method, path, body=None, headers=None, cookie=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = dict(headers or {})
        if cookie:
            h["Cookie"] = cookie
        if body is not None:
            h["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", "replace")
        status = resp.status
        hdrs = dict(resp.getheaders())
        conn.close()
        return status, data, hdrs

    def login(self):
        status, _, hdrs = self._request(
            "POST", "/login", body=urlencode({"token": TOKEN}))
        self.assertEqual(status, 302, "login failed")
        m = re.search(r"session=([^;]+)", hdrs.get("Set-Cookie", ""))
        self.assertIsNotNone(m, "no session cookie on login")
        return "session=" + m.group(1)

    def get_csrf(self, cookie, aid):
        status, body, _ = self._request(
            "GET", "/approvals/%s" % aid, cookie=cookie)
        self.assertEqual(status, 200, "detail page did not render")
        m = re.search(r'''name=['"]csrf['"] value=['"]([^'"]+)['"]''', body)
        self.assertIsNotNone(m, "no CSRF token on detail page")
        return m.group(1)

    def delegate(self, aid, to, reason, cookie=None, csrf=None,
                 extra_fields=None, origin=None):
        fields = {"to": to, "reason": reason}
        if csrf is not None:
            fields["csrf"] = csrf
        if extra_fields:
            fields.update(extra_fields)
        headers = {}
        if origin is not None:
            headers["Origin"] = origin
        status, data, _ = self._request(
            "POST", "/approvals/%s/delegate" % aid,
            body=urlencode(fields), headers=headers, cookie=cookie)
        return status, data

    def vote(self, aid, vote, reason, cookie=None, csrf=None,
             extra_fields=None, origin=None):
        fields = {"vote": vote, "reason": reason}
        if csrf is not None:
            fields["csrf"] = csrf
        if extra_fields:
            fields.update(extra_fields)
        headers = {}
        if origin is not None:
            headers["Origin"] = origin
        status, data, _ = self._request(
            "POST", "/approvals/%s/vote" % aid,
            body=urlencode(fields), headers=headers, cookie=cookie)
        return status, data

    def decide(self, aid, decision, reason, cookie=None, csrf=None):
        fields = {"decision": decision, "reason": reason}
        if csrf is not None:
            fields["csrf"] = csrf
        status, data, _ = self._request(
            "POST", "/approvals/%s/decide" % aid,
            body=urlencode(fields), cookie=cookie)
        return status, data


class TestWebPrincipalBinding(WebD1Base):
    def test_session_binds_web_operator_principal(self):
        cookie = self.login()
        sess = self.server.app.get_session(cookie)
        self.assertIsNotNone(sess)
        self.assertEqual(sess["principal"], WEB_DECIDED_BY)


class TestWebDetailSurfaces(WebD1Base):
    def test_delegated_detail_renders_assignee_and_chain(self):
        self.ctx["approvals"].set_delegation_config({"enabled": True})
        aid = self.queue_email()
        self.ctx["approvals"].delegate(aid, "alice", "alice is on call",
                                       delegated_by="human-operator")
        cookie = self.login()
        status, body, _ = self._request("GET", "/approvals/%s" % aid,
                                     cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn("DELEGATED", body)
        self.assertIn("alice", body)
        self.assertIn("human-operator", body)  # chain hop "from"

    def test_quorum_detail_renders_tally_votes_and_vote_form(self):
        aid = self.queue_quorum_email()
        self.ctx["approvals"].cast_vote(
            aid, True, "looks fine",
            self.ctx["executor"].mint_identity("v-alice", "voter", "alice"))
        cookie = self.login()
        status, body, _ = self._request("GET", "/approvals/%s" % aid,
                                     cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn("QUORUM COLLECTING", body)
        self.assertIn("1 of 2", body)
        self.assertIn("alice", body)  # vote row
        self.assertIn("looks fine", body)  # vote reason
        self.assertIn("/approvals/%s/vote" % aid, body)
        # No direct-decision form on a quorum record.
        self.assertNotIn("/approvals/%s/decide" % aid, body)

    def test_decide_form_hidden_when_delegated_away(self):
        self.ctx["approvals"].set_delegation_config({"enabled": True})
        aid = self.queue_email()
        self.ctx["approvals"].delegate(aid, "alice", "on call",
                                       delegated_by="human-operator")
        cookie = self.login()
        status, body, _ = self._request("GET", "/approvals/%s" % aid,
                                     cookie=cookie)
        self.assertEqual(status, 200)
        self.assertNotIn("/approvals/%s/decide" % aid, body)
        self.assertIn("Only <strong>alice</strong> may decide", body)

    def test_list_page_flags_delegated_and_quorum(self):
        self.ctx["approvals"].set_delegation_config({"enabled": True})
        aid_d = self.queue_email()
        self.ctx["approvals"].delegate(aid_d, "alice", "on call",
                                       delegated_by="human-operator")
        aid_q = self.queue_quorum_email()
        cookie = self.login()
        status, body, _ = self._request("GET", "/", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn("DELEGATED to alice", body)
        self.assertIn("QUORUM 0-of-2", body)

    def test_bridge_expiry_renders_and_late_decision_noted(self):
        aid = self.queue_email()
        self.ctx["approvals"].mark_bridge_expired(
            aid, "bridge-1", "test expiry")
        cookie = self.login()
        status, body, _ = self._request("GET", "/approvals/%s" % aid,
                                     cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn("BRIDGE EXPIRED", body)
        self.assertIn("audit-only", body)

    def test_d1_fields_are_html_escaped(self):
        # Hostile principal/reason strings must never render raw.
        self.ctx["approvals"].set_delegation_config({"enabled": True})
        aid = self.queue_email()
        evil = '"><img src=x onerror=alert(1)>'
        self.ctx["approvals"].delegate(aid, evil, "x", "human-operator")
        aid_q = self.queue_quorum_email()
        self.ctx["approvals"].cast_vote(
            aid_q, True, '<script>alert("vote")</script>',
            self.ctx["executor"].mint_identity("v-alice", "voter", "alice"))
        cookie = self.login()
        for a in (aid, aid_q):
            status, body, _ = self._request("GET", "/approvals/%s" % a,
                                         cookie=cookie)
            self.assertEqual(status, 200)
        status, body, _ = self._request("GET", "/approvals/%s" % aid,
                                     cookie=cookie)
        self.assertNotIn(evil, body)
        self.assertIn("&gt;", body)
        status, body, _ = self._request("GET", "/approvals/%s" % aid_q,
                                     cookie=cookie)
        self.assertNotIn("<script>", body)
        self.assertIn("&lt;script&gt;", body)


class TestWebDelegateRoute(WebD1Base):
    def test_delegate_happy_path(self):
        self.make_delegating_server()
        aid = self.queue_email()
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _ = self.delegate(aid, "alice", "alice is on call",
                                  cookie=cookie, csrf=csrf)
        self.assertEqual(status, 302, "delegate did not redirect")
        record = self.approval(aid)
        self.assertEqual(record["delegated_to"], "alice")
        chain = record["delegation_chain"]
        self.assertEqual((chain[0]["from"], chain[0]["to"]),
                         (WEB_DECIDED_BY, "alice"))
        self.assertTrue(approval_record_digest(record))
        self.assertEqual(
            len(self.audit_events("approval_delegated", aid)), 1)

    def test_delegate_unauthenticated_403(self):
        self.make_delegating_server()
        aid = self.queue_email()
        status, _ = self.delegate(aid, "alice", "x", csrf="whatever")
        self.assertEqual(status, 403)
        self.assertIsNone(self.approval(aid)["delegated_to"])
        self.assertEqual(
            len(self.audit_events("web_auth_failure", aid)), 1)

    def test_delegate_bad_csrf_403_and_audited(self):
        self.make_delegating_server()
        aid = self.queue_email()
        cookie = self.login()
        status, _ = self.delegate(aid, "alice", "x", cookie=cookie,
                                  csrf="forged")
        self.assertEqual(status, 403)
        self.assertIsNone(self.approval(aid)["delegated_to"])
        self.assertEqual(
            len(self.audit_events("web_csrf_failure", aid)), 1)

    def test_delegate_cross_origin_403(self):
        self.make_delegating_server()
        aid = self.queue_email()
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _ = self.delegate(aid, "alice", "x", cookie=cookie,
                                  csrf=csrf, origin="https://evil.example")
        self.assertEqual(status, 403)
        self.assertIsNone(self.approval(aid)["delegated_to"])

    def test_delegate_self_refused_409(self):
        self.make_delegating_server()
        aid = self.queue_email()
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _ = self.delegate(aid, WEB_DECIDED_BY, "self-deal",
                                  cookie=cookie, csrf=csrf)
        self.assertEqual(status, 409)
        self.assertIsNone(self.approval(aid)["delegated_to"])
        self.assertEqual(
            len(self.audit_events("web_delegate_refused", aid)), 1)
        self.assertEqual(
            len(self.audit_events("delegation_refused", aid)), 1)

    def test_delegate_disabled_without_policy_409(self):
        # No --policy: delegation stays off, fail closed.
        aid = self.queue_email()
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _ = self.delegate(aid, "alice", "x", cookie=cookie,
                                  csrf=csrf)
        self.assertEqual(status, 409)
        self.assertIsNone(self.approval(aid)["delegated_to"])
        refused = self.audit_events("web_delegate_refused", aid)
        self.assertEqual(len(refused), 1)
        self.assertIn("delegation_disabled", refused[0]["reason"])

    def test_delegate_replay_refused_wrong_delegator(self):
        self.make_delegating_server()
        aid = self.queue_email()
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _ = self.delegate(aid, "alice", "on call",
                                  cookie=cookie, csrf=csrf)
        self.assertEqual(status, 302)
        # Replay the identical form: the web operator no longer holds
        # the record — delegate() refuses as wrong_delegator.
        status, _ = self.delegate(aid, "alice", "on call",
                                  cookie=cookie, csrf=csrf)
        self.assertEqual(status, 409)
        record = self.approval(aid)
        self.assertEqual(record["delegated_to"], "alice")
        self.assertEqual(len(record["delegation_chain"]), 1)

    def test_delegate_unknown_id_404(self):
        self.make_delegating_server()
        cookie = self.login()
        status, _, _ = self._request("GET", "/", cookie=cookie)
        self.assertEqual(status, 200)
        # any valid-format unknown id
        csrf_holder = self.queue_email()
        csrf = self.get_csrf(cookie, csrf_holder)
        status, _ = self.delegate("no-such-id", "alice", "x",
                                  cookie=cookie, csrf=csrf)
        self.assertEqual(status, 404)

    def test_policy_path_enables_delegation_on_web_queue(self):
        self.make_delegating_server()
        self.assertTrue(self.server.app.queue.delegation_enabled)

    def test_no_policy_keeps_delegation_off(self):
        self.assertFalse(self.server.app.queue.delegation_enabled)
        aid = self.queue_email()
        cookie = self.login()
        _, body, _ = self._request("GET", "/approvals/%s" % aid, cookie=cookie)
        self.assertNotIn("/delegate", body)


class TestWebVoteRoute(WebD1Base):
    def test_vote_happy_path_records_session_principal(self):
        aid = self.queue_quorum_email()
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _ = self.vote(aid, "approve", "looks fine",
                              cookie=cookie, csrf=csrf)
        self.assertEqual(status, 302)
        record = self.approval(aid)
        self.assertEqual(len(record["votes"]), 1)
        self.assertEqual(record["votes"][0]["voter_principal"],
                         WEB_DECIDED_BY)
        self.assertTrue(record["votes"][0]["approve"])
        self.assertTrue(approval_record_digest(record))
        self.assertEqual(len(self.audit_events("quorum_vote", aid)), 1)

    def test_vote_finalizes_at_m(self):
        aid = self.queue_quorum_email()
        self.ctx["approvals"].cast_vote(
            aid, True, "alice agrees",
            self.ctx["executor"].mint_identity("v-alice", "voter", "alice"))
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _ = self.vote(aid, "approve", "web agrees",
                              cookie=cookie, csrf=csrf)
        self.assertEqual(status, 302)
        record = self.approval(aid)
        self.assertEqual(record["status"], "approved")
        self.assertTrue(record["decided_by"].startswith("quorum:"))
        self.assertEqual(
            len(self.audit_events("quorum_finalized", aid)), 1)

    def test_vote_deny_vetoes_immediately(self):
        aid = self.queue_quorum_email()
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _ = self.vote(aid, "deny", "unsafe", cookie=cookie,
                              csrf=csrf)
        self.assertEqual(status, 302)
        record = self.approval(aid)
        self.assertEqual(record["status"], "rejected")

    def test_vote_replay_duplicate_409(self):
        aid = self.queue_quorum_email()
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _ = self.vote(aid, "approve", "first", cookie=cookie,
                              csrf=csrf)
        self.assertEqual(status, 302)
        status, _ = self.vote(aid, "approve", "replay", cookie=cookie,
                              csrf=csrf)
        self.assertEqual(status, 409)
        self.assertEqual(len(self.approval(aid)["votes"]), 1)
        self.assertEqual(len(self.audit_events("web_vote_refused", aid)),
                         1)

    def test_vote_form_principal_cannot_be_spoofed(self):
        # A forged ``principal`` form field is ignored: the vote is
        # minted server-side from the session principal.
        aid = self.queue_quorum_email()
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _ = self.vote(aid, "approve", "x", cookie=cookie,
                              csrf=csrf,
                              extra_fields={"principal": "alice",
                                            "voter_principal": "alice"})
        self.assertEqual(status, 302)
        self.assertEqual(
            self.approval(aid)["votes"][0]["voter_principal"],
            WEB_DECIDED_BY)

    def test_vote_non_eligible_409(self):
        aid = self.queue_quorum_email(
            {"min_approvals": 2,
             "eligible_principals": ["alice", "bob", "carol"]})
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _ = self.vote(aid, "approve", "x", cookie=cookie, csrf=csrf)
        self.assertEqual(status, 409)
        self.assertEqual(self.approval(aid)["votes"], [])
        refused = self.audit_events("web_vote_refused", aid)
        self.assertEqual(len(refused), 1)
        self.assertIn("not_eligible", refused[0]["reason"])

    def test_vote_on_non_quorum_record_409(self):
        aid = self.queue_email()
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _ = self.vote(aid, "approve", "x", cookie=cookie, csrf=csrf)
        self.assertEqual(status, 409)
        self.assertEqual(
            len(self.audit_events("web_vote_refused", aid)), 1)

    def test_vote_bad_csrf_403(self):
        aid = self.queue_quorum_email()
        cookie = self.login()
        status, _ = self.vote(aid, "approve", "x", cookie=cookie,
                              csrf="forged")
        self.assertEqual(status, 403)
        self.assertEqual(self.approval(aid)["votes"], [])

    def test_vote_cross_origin_403(self):
        aid = self.queue_quorum_email()
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _ = self.vote(aid, "approve", "x", cookie=cookie,
                              csrf=csrf, origin="https://evil.example")
        self.assertEqual(status, 403)
        self.assertEqual(self.approval(aid)["votes"], [])

    def test_vote_unauthenticated_403(self):
        aid = self.queue_quorum_email()
        status, _ = self.vote(aid, "approve", "x", csrf="whatever")
        self.assertEqual(status, 403)
        self.assertEqual(self.approval(aid)["votes"], [])


class TestWebDecideInterplay(WebD1Base):
    def test_decide_refused_on_quorum_record(self):
        aid = self.queue_quorum_email()
        cookie = self.login()
        # No decide form is rendered, but a forged POST must still fail.
        status, _ = self.decide(aid, "approve", "bypass",
                                cookie=cookie, csrf="x")
        # CSRF gate fires first on a forged token...
        self.assertEqual(status, 403)
        csrf = self.get_csrf(cookie, aid)
        status, _ = self.decide(aid, "approve", "bypass",
                                cookie=cookie, csrf=csrf)
        self.assertEqual(status, 409)
        self.assertEqual(self.approval(aid)["status"], "pending")
        refused = self.audit_events("web_decision_refused", aid)
        self.assertEqual(len(refused), 1)
        self.assertIn("quorum_direct_decide", refused[0]["reason"])

    def test_decide_refused_when_delegated_away(self):
        self.ctx["approvals"].set_delegation_config({"enabled": True})
        aid = self.queue_email()
        self.ctx["approvals"].delegate(aid, "alice", "on call",
                                       delegated_by="human-operator")
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _ = self.decide(aid, "approve", "overreach",
                                cookie=cookie, csrf=csrf)
        self.assertEqual(status, 409)
        self.assertEqual(self.approval(aid)["status"], "pending")

    def test_decide_allowed_when_delegated_to_web_operator(self):
        self.ctx["approvals"].set_delegation_config({"enabled": True})
        aid = self.queue_email()
        self.ctx["approvals"].delegate(aid, WEB_DECIDED_BY, "web on call",
                                       delegated_by="human-operator")
        cookie = self.login()
        status, body, _ = self._request("GET", "/approvals/%s" % aid,
                                     cookie=cookie)
        self.assertEqual(status, 200)
        # The decide form IS rendered for the current assignee.
        self.assertIn("/approvals/%s/decide" % aid, body)
        csrf = self.get_csrf(cookie, aid)
        status, _ = self.decide(aid, "approve", "fine", cookie=cookie,
                                csrf=csrf)
        self.assertEqual(status, 302)
        self.assertEqual(self.approval(aid)["status"], "approved")

    def test_decide_normal_record_still_works(self):
        aid = self.queue_email()
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _ = self.decide(aid, "deny", "nope", cookie=cookie,
                                csrf=csrf)
        self.assertEqual(status, 302)
        self.assertEqual(self.approval(aid)["status"], "rejected")


if __name__ == "__main__":
    unittest.main()
