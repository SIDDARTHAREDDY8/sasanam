"""Web UI tests: the approval queue over real HTTP (stdlib only).

Each test drives a localhost ``ThreadingHTTPServer`` via ``http.client``
against deterministic ``harness.make_run()`` fixtures
(``TMPDIR=/tmp/gov-run``). The server module under test is
``APPROVAL_WEB_MODULE`` (default: the hardened ``approval_web`` in
``workstreams/platform/``); the red-team step runs the attack-situations
subset against a naive shim to observe them FAIL before the hardened
implementation makes them pass.

Covered: unauthenticated requests rejected, CSRF token enforced
(+ cross-origin POST rejected), replay rejected, decisions through the
canonical ``ApprovalQueue.decide()`` path and audited, corrupt
queue/lock fail closed, HTML escaping, unknown id / empty reason
handling.
"""

import http.client
import importlib
import json
import os
import re
import sys
import threading
import unittest
from urllib.parse import urlencode

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_TESTS_DIR)
_WORK = os.path.dirname(_REPO_ROOT)  # .../agent-governance-demo
for _p in (_TESTS_DIR, _REPO_ROOT,
           os.path.join(_WORK, "workstreams", "platform")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # noqa: E402

MODULE_NAME = os.environ.get("APPROVAL_WEB_MODULE", "approval_web")
mod = importlib.import_module(MODULE_NAME)
DECIDE_PATH = getattr(mod, "DECIDE_PATH", "/approvals/{id}/decide")

TOKEN = "test-token-0123456789abcdef"


class WebBase(unittest.TestCase):
    def setUp(self):
        self.ctx = make_run()
        self.server = mod.make_server(self.ctx["run_dir"], token=TOKEN)
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
    def queue_email(self, to="victim@synthetic.local",
                    justification="routine vendor invoice"):
        res = self.ctx["executor"].call(
            self.ident, "send_email", to=to, subject="s", body="b",
            justification=justification)
        self.assertEqual(res["status"], "queued", res)
        return res["approval_id"]

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
        hdrs = dict(resp.getheaders())
        status = resp.status
        conn.close()
        return status, hdrs, data

    def try_login(self, token):
        """Log in; return the Cookie value, or None when login failed
        (lets red-team runs against the naive shim proceed)."""
        status, hdrs, _ = self._request(
            "POST", "/login", body=urlencode({"token": token}))
        if status != 302:
            return None
        m = re.search(r"session=([^;]+)", hdrs.get("Set-Cookie", ""))
        return "session=" + m.group(1) if m else None

    def login(self):
        cookie = self.try_login(TOKEN)
        self.assertIsNotNone(cookie, "login with the startup token failed")
        return cookie

    def mint_test_session(self):
        """Mint a session directly on the app (for corrupt-queue tests
        where the login page flow cannot render a CSRF form)."""
        app = getattr(self.server, "app", None)
        self.assertIsNotNone(app, "server exposes .app")
        return app.create_test_session()

    def get_csrf(self, cookie, aid):
        status, _, body = self._request(
            "GET", "/approvals/%s" % aid, cookie=cookie)
        self.assertEqual(status, 200, "detail page did not render")
        m = re.search(r'''name=['"]csrf['"] value=['"]([^'"]+)['"]''', body)
        self.assertIsNotNone(m, "no CSRF token in decision form")
        return m.group(1)

    def decide(self, aid, decision, reason, cookie=None, csrf=None,
               extra_fields=None, origin=None):
        fields = {"id": aid, "decision": decision, "reason": reason}
        if csrf is not None:
            fields["csrf"] = csrf
        if extra_fields:
            fields.update(extra_fields)
        headers = {}
        if origin is not None:
            headers["Origin"] = origin
        return self._request("POST", DECIDE_PATH.format(id=aid),
                             body=urlencode(fields), headers=headers,
                             cookie=cookie)


class TestWebAuth(WebBase):
    def test_login_page_reachable(self):
        status, _, body = self._request("GET", "/login")
        self.assertEqual(status, 200)
        self.assertIn("token", body.lower())

    def test_unauthenticated_list_redirects_to_login(self):
        status, hdrs, _ = self._request("GET", "/")
        self.assertEqual(status, 302)
        self.assertEqual(hdrs.get("Location"), "/login")

    def test_unauthenticated_detail_redirects_to_login(self):
        aid = self.queue_email()
        status, hdrs, _ = self._request("GET", "/approvals/%s" % aid)
        self.assertEqual(status, 302)
        self.assertEqual(hdrs.get("Location"), "/login")

    def test_unauthenticated_decide_rejected(self):
        """A1: no session -> 403, record stays pending, nothing audited
        as a decision."""
        aid = self.queue_email()
        status, _, _ = self.decide(aid, "approve", "pwned")
        self.assertEqual(status, 403,
                         "A1: unauthenticated POST decided the approval")
        self.assertEqual(self.approval(aid)["status"], "pending")
        self.assertEqual(self.audit_events("approval_decision", aid), [])

    def test_wrong_token_login_rejected_and_audited(self):
        status, hdrs, _ = self._request(
            "POST", "/login", body=urlencode({"token": "wrong"}))
        self.assertEqual(status, 403)
        self.assertNotIn("Set-Cookie", hdrs)
        self.assertEqual(len(self.audit_events("web_auth_failure")), 1)

    def test_login_sets_session_cookie_with_csrf_flags(self):
        status, hdrs, _ = self._request(
            "POST", "/login", body=urlencode({"token": TOKEN}))
        self.assertEqual(status, 302)
        set_cookie = hdrs.get("Set-Cookie", "")
        self.assertIn("session=", set_cookie)
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=Strict", set_cookie)

    def test_authenticated_list_shows_pending(self):
        aid = self.queue_email()
        cookie = self.login()
        status, _, body = self._request("GET", "/", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn(aid, body)
        self.assertIn("send_email", body)

    def test_logout_destroys_session(self):
        cookie = self.login()
        status, _, _ = self._request("POST", "/logout", body="",
                                     cookie=cookie)
        self.assertEqual(status, 302)
        status, _, _ = self._request("GET", "/", cookie=cookie)
        self.assertEqual(status, 302, "session survived logout")


class TestWebCSRF(WebBase):
    def test_csrf_missing_rejected(self):
        """A2: no CSRF token -> 403, still pending, audited."""
        aid = self.queue_email()
        cookie = self.try_login(TOKEN)  # None on the naive shim: fine
        status, _, _ = self.decide(aid, "approve", "csrf", cookie=cookie,
                                   csrf=None)
        self.assertEqual(status, 403,
                         "A2: POST without CSRF token decided the approval")
        self.assertEqual(self.approval(aid)["status"], "pending")
        self.assertEqual(len(self.audit_events("web_csrf_failure", aid)), 1)

    def test_csrf_wrong_rejected(self):
        aid = self.queue_email()
        cookie = self.login()
        status, _, _ = self.decide(aid, "approve", "csrf", cookie=cookie,
                                   csrf="wrong-token")
        self.assertEqual(status, 403)
        self.assertEqual(self.approval(aid)["status"], "pending")

    def test_cross_origin_post_rejected(self):
        aid = self.queue_email()
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _, _ = self.decide(aid, "approve", "x", cookie=cookie,
                                   csrf=csrf,
                                   origin="https://evil.example")
        self.assertEqual(status, 403,
                         "cross-origin POST with valid session+CSRF was "
                         "honored")
        self.assertEqual(self.approval(aid)["status"], "pending")

    def test_valid_csrf_allows_decision(self):
        aid = self.queue_email()
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _, _ = self.decide(aid, "approve", "ok", cookie=cookie,
                                   csrf=csrf)
        self.assertEqual(status, 302)
        self.assertEqual(self.approval(aid)["status"], "approved")


class TestWebDecisions(WebBase):
    def authed(self, aid):
        cookie = self.login()
        return cookie, self.get_csrf(cookie, aid)

    def test_approve_goes_through_canonical_path_and_is_audited(self):
        aid = self.queue_email()
        cookie, csrf = self.authed(aid)
        before = self.approval(aid)["args"]
        status, hdrs, _ = self.decide(aid, "approve", "looks good",
                                      cookie=cookie, csrf=csrf)
        self.assertEqual(status, 302)
        self.assertEqual(hdrs.get("Location"), "/approvals/%s" % aid)
        rec = self.approval(aid)
        self.assertEqual(rec["status"], "approved")
        self.assertEqual(rec["decided_by"], "human-operator")
        self.assertEqual(rec["decision_reason"], "looks good")
        self.assertEqual(rec["args"], before,
                         "web decision altered the queued args")
        entries = self.audit_events("approval_decision", aid)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["reason"], "looks good")
        self.assertEqual(entries[0]["decision"], "approved")

    def test_deny(self):
        aid = self.queue_email()
        cookie, csrf = self.authed(aid)
        status, _, _ = self.decide(aid, "deny", "too risky",
                                   cookie=cookie, csrf=csrf)
        self.assertEqual(status, 302)
        rec = self.approval(aid)
        self.assertEqual(rec["status"], "rejected")
        entries = self.audit_events("approval_decision", aid)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["decision"], "rejected")

    def test_tampered_form_fields_are_ignored(self):
        """A4: form-supplied authority fields must not reach the record."""
        aid = self.queue_email()
        cookie = self.try_login(TOKEN)
        csrf = self.get_csrf(cookie, aid) if cookie else None
        forged = {"to": "attacker@evil.example", "subject": "s",
                  "body": "b"}
        status, _, _ = self.decide(
            aid, "approve", "tamper", cookie=cookie, csrf=csrf,
            extra_fields={"tool": "HACKED",
                          "args": json.dumps(forged),
                          "decided_by": "attacker",
                          "agent_id": "attacker"})
        rec = self.approval(aid)
        self.assertEqual(rec["args"]["to"], "victim@synthetic.local",
                         "A4: form-supplied args rewrote the queued record")
        self.assertEqual(rec["tool"], "send_email")
        self.assertEqual(rec["decided_by"], "human-operator",
                         "A4: form-supplied decided_by was honored")

    def test_replay_rejected(self):
        """A3: the identical POST twice -> second is 409; exactly one
        canonical decision entry."""
        aid = self.queue_email()
        cookie = self.try_login(TOKEN)
        csrf = self.get_csrf(cookie, aid) if cookie else None
        status1, _, _ = self.decide(aid, "approve", "first",
                                    cookie=cookie, csrf=csrf)
        self.assertIn(status1, (200, 302))
        status2, _, _ = self.decide(aid, "approve", "first",
                                    cookie=cookie, csrf=csrf)
        self.assertEqual(status2, 409,
                         "A3: replayed approval POST was not refused")
        self.assertEqual(
            len(self.audit_events("approval_decision", aid)), 1,
            "A3: replay produced a second decision entry")
        self.assertTrue(
            self.audit_events("approval_decision_attempt", aid),
            "A3: the refused replay left no audit trace")

    def test_empty_reason_rejected(self):
        aid = self.queue_email()
        cookie, csrf = self.authed(aid)
        status, _, _ = self.decide(aid, "approve", "   ",
                                  cookie=cookie, csrf=csrf)
        self.assertEqual(status, 400)
        self.assertEqual(self.approval(aid)["status"], "pending")

    def test_invalid_decision_value_rejected(self):
        aid = self.queue_email()
        cookie, csrf = self.authed(aid)
        status, _, _ = self.decide(aid, "maybe", "x",
                                  cookie=cookie, csrf=csrf)
        self.assertEqual(status, 400)
        self.assertEqual(self.approval(aid)["status"], "pending")

    def test_unknown_id(self):
        cookie = self.login()
        status, _, _ = self._request("GET", "/approvals/no-such-id",
                                     cookie=cookie)
        self.assertEqual(status, 404)
        # csrf is per-session: mint one session and use both parts.
        cookie2, csrf = self.mint_test_session()
        status, _, _ = self.decide("no-such-id", "approve", "x",
                                   cookie=cookie2, csrf=csrf)
        self.assertEqual(status, 404)

    def test_decide_tampered_record_fails_closed(self):
        """T5 via the web layer: queued args rewritten on disk -> the
        canonical F38 check refuses; the record stays pending."""
        aid = self.queue_email()
        records = self.ctx["approvals"].all()
        for r in records:
            if r["id"] == aid:
                r["args"]["to"] = "attacker@evil.example"
        self.ctx["approvals"]._rewrite(records)
        cookie = self.try_login(TOKEN)
        csrf = self.get_csrf(cookie, aid) if cookie else None
        status, _, _ = self.decide(aid, "approve", "looks fine",
                                   cookie=cookie, csrf=csrf)
        self.assertEqual(status, 409)
        self.assertEqual(self.approval(aid)["status"], "pending")


class TestWebFailClosed(WebBase):
    def _corrupt_queue(self):
        (self.ctx["run_dir"] / "approvals.jsonl").write_text(
            "{not valid jsonl\n", encoding="utf-8")

    def test_corrupt_queue_list_fails_closed(self):
        self.queue_email()
        self._corrupt_queue()
        cookie = self.login()  # login does not read the queue
        status, _, body = self._request("GET", "/", cookie=cookie)
        self.assertEqual(status, 500)
        self.assertIn("FAIL CLOSED", body)
        self.assertNotIn("Approve", body,
                         "fail-closed page must not render decision buttons")

    def test_corrupt_queue_decide_fails_closed(self):
        aid = self.queue_email()
        cookie, csrf = self.mint_test_session()  # session minted, no queue read
        self._corrupt_queue()
        status, _, body = self.decide(aid, "approve", "x",
                                      cookie=cookie, csrf=csrf)
        self.assertIn(status, (500, 503),
                      "corrupt queue did not fail closed on decide")
        self.assertIn("FAIL CLOSED", body)
        # The server itself must still be alive (no crash).
        status, _, _ = self._request("GET", "/login")
        self.assertEqual(status, 200)

    def test_corrupt_queue_lock_fails_closed(self):
        aid = self.queue_email()
        # Swap the lock path for a directory: _queue_locked() must
        # refuse (QueueLockPathError) instead of deciding unlocked.
        (self.ctx["run_dir"] / "approvals.lock").mkdir(exist_ok=True)
        cookie, csrf = self.authed(aid)
        status, _, body = self.decide(aid, "approve", "x",
                                      cookie=cookie, csrf=csrf)
        self.assertEqual(status, 503,
                         "corrupt queue lock did not fail closed")
        self.assertIn("FAIL CLOSED", body)
        self.assertEqual(self.approval(aid)["status"], "pending")

    def authed(self, aid):
        cookie = self.login()
        return cookie, self.get_csrf(cookie, aid)


class TestWebDetail(WebBase):
    def test_detail_shows_review_fields(self):
        aid = self.queue_email()
        cookie = self.login()
        status, _, body = self._request("GET", "/approvals/%s" % aid,
                                        cookie=cookie)
        self.assertEqual(status, 200)
        for needle in ("support-1", "send_email", "require",
                       "UNVERIFIED", "args_sha256", "name='csrf'"):
            self.assertIn(needle, body,
                          "detail page missing %r" % needle)

    def test_justification_is_html_escaped(self):
        """A5: stored agent justification must not break out of HTML."""
        aid = self.queue_email(
            justification="<script>alert('xss')</script>")
        cookie = self.login()
        status, _, body = self._request("GET", "/approvals/%s" % aid,
                                        cookie=cookie)
        self.assertEqual(status, 200)
        self.assertNotIn("<script>alert('xss')</script>", body)
        self.assertIn("&lt;script&gt;", body)

    def test_decided_record_shows_decision_no_form(self):
        aid = self.queue_email()
        cookie = self.login()
        csrf = self.get_csrf(cookie, aid)
        self.decide(aid, "deny", "nope", cookie=cookie, csrf=csrf)
        status, _, body = self._request("GET", "/approvals/%s" % aid,
                                        cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn("rejected", body)
        self.assertNotIn("name='csrf'", body,
                         "decided record must not render a decision form")


if __name__ == "__main__":
    unittest.main(verbosity=2)
