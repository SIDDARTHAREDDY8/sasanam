"""Wave-23 P4: queue crash-durability (F83) + web adversarial variants.

Two halves:

1. **F83 closure probes** (queue-level, no HTTP): crash-injection
   mid-``_rewrite`` must leave ``approvals.jsonl`` byte-identical and
   readable; a torn trailing append line is dropped; non-trailing
   corruption still fails closed; the public ``locked()`` seam works.

2. **F80-pattern adversarial variants for the wave-23 web additions**:
   cross-session CSRF token replay on the ``/delegate`` and ``/vote``
   routes (F80 covered only ``/logout`` and ``/decide``), the read-only
   ``GET /audit`` view (auth gate, XSS escaping, never mutates), and
   session properties (server-minted ids, cookie flags).

Drives a localhost ThreadingHTTPServer via http.client against
deterministic harness.make_run() fixtures (TMPDIR=/tmp/gov-run
private subdirs), like tests/test_gov_approval_web.py.
"""

import builtins
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
    ApprovalWebApp,
    make_server,
)
from gov.approvals import (  # noqa: E402
    ApprovalQueue,
    approval_record_digest,
)
from gov.log import ActionLog  # noqa: E402

TOKEN = "durability-test-token"

QUORUM_WEB = {"min_approvals": 2,
              "eligible_principals": [WEB_DECIDED_BY, "alice", "bob"]}

_DELEG_POLICY = """\
version: 1
approvals:
  delegation:
    enabled: true
    max_hops: 1
"""


class _CrashMidWrite:
    """Simulate SIGKILL/OOM-kill during the queue rewrite: every write
    to the temp file used by the atomic rewrite raises."""

    def __init__(self):
        self._real_open = builtins.open

    def __enter__(self):
        real_open = self._real_open

        class CrashyFile:
            def __init__(self, f):
                self._f = f

            def write(self, s):
                raise KeyboardInterrupt("simulated crash mid-rewrite")

            def flush(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self._f.close()
                return False

        def crashy_open(path, mode="r", *args, **kwargs):
            f = real_open(path, mode, *args, **kwargs)
            if ".tmp." in str(path) and "w" in mode:
                return CrashyFile(f)
            return f

        builtins.open = crashy_open
        return self

    def __exit__(self, *args):
        builtins.open = self._real_open
        return False


class TestQueueCrashDurability(unittest.TestCase):
    """F83 closure probes: the durable queue survives crashes."""

    def setUp(self):
        self.ctx = make_run()
        self.q = self.ctx["approvals"]
        self.ident = self.ctx["identities"]["support"]

    def queue_email(self, to="victim@synthetic.local"):
        res = self.ctx["executor"].call(
            self.ident, "send_email", to=to, subject="s", body="b",
            justification="routine vendor invoice")
        self.assertEqual(res["status"], "queued", res)
        return res["approval_id"]

    def test_crash_mid_rewrite_leaves_file_byte_identical(self):
        aid1 = self.queue_email(to="a@synthetic.local")
        aid2 = self.queue_email(to="b@synthetic.local")
        before = self.q.path.read_bytes()
        with _CrashMidWrite():
            with self.assertRaises(KeyboardInterrupt):
                self.q.decide(aid1, True, "ok", decided_by="human-operator")
        # F83: the old file is untouched — no truncation, no partial
        # write, no leftover temp file.
        self.assertEqual(self.q.path.read_bytes(), before)
        self.assertFalse(
            [p for p in self.q.run_dir.iterdir() if ".tmp." in p.name],
            "temp file leaked after crashed rewrite")

    def test_queue_readable_and_decidable_after_crash(self):
        aid1 = self.queue_email(to="a@synthetic.local")
        aid2 = self.queue_email(to="b@synthetic.local")
        with _CrashMidWrite():
            with self.assertRaises(KeyboardInterrupt):
                self.q.decide(aid1, True, "ok", decided_by="human-operator")
        pending = [r["id"] for r in self.q.pending()]
        self.assertEqual(sorted(pending), sorted([aid1, aid2]))
        # The decision can be retried after the crash: exactly-once
        # semantics preserved (no phantom decision recorded).
        self.q.decide(aid1, True, "ok", decided_by="human-operator")
        self.assertEqual(self.q.get(aid1)["status"], "approved")
        self.assertTrue(approval_record_digest(self.q.get(aid1)))

    def test_torn_trailing_append_is_dropped(self):
        aid1 = self.queue_email(to="a@synthetic.local")
        # Crash between write() and fsync: partial last line, no
        # trailing newline.
        with open(self.q.path, "ab") as f:
            f.write(b'{"torn": "par')
        records = self.q.all()
        self.assertEqual([r["id"] for r in records], [aid1])
        # The write path heals the torn tail before appending: the new
        # record lands cleanly instead of gluing onto torn bytes.
        aid2 = self.queue_email(to="b@synthetic.local")
        self.assertEqual(sorted(r["id"] for r in self.q.all()),
                         sorted([aid1, aid2]))
        self.assertTrue(
            self.q.path.read_bytes().endswith(b"\n"))

    def test_glued_torn_append_stays_fail_closed(self):
        # A glued line (torn bytes + a record appended WITHOUT the
        # write-path heal — only possible from a writer that bypasses
        # queue(), e.g. a raw probe append) is indistinguishable from
        # corruption: it fails closed LOUDLY, never silently drops.
        self.queue_email(to="a@synthetic.local")
        with open(self.q.path, "ab") as f:
            f.write(b'{"torn": "par')
        with open(self.q.path, "a", encoding="utf-8") as f:
            f.write('{"id": "glued", "status": "pending"}\n')
        with self.assertRaises(ValueError):
            self.q.all()

    def test_corrupt_middle_line_still_fail_closed(self):
        aid1 = self.queue_email(to="a@synthetic.local")
        aid2 = self.queue_email(to="b@synthetic.local")
        lines = self.q.path.read_text(encoding="utf-8").splitlines()
        lines.insert(1, '{"corrupt": true')
        self.q.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.q.all()
        # And the two real records are still intact on disk.
        raw = self.q.path.read_text(encoding="utf-8")
        self.assertIn(aid1, raw)
        self.assertIn(aid2, raw)

    def test_rewrite_result_is_well_formed(self):
        aid = self.queue_email()
        self.q.decide(aid, True, "ok", decided_by="human-operator")
        raw = self.q.path.read_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        for line in raw.decode("utf-8").splitlines():
            json.loads(line)  # must not raise

    def test_public_locked_seam(self):
        # The D1 pluggability seam: external drivers use locked(),
        # never the private _queue_locked.
        aid = self.queue_email()
        with self.q.locked(timeout=5):
            recs = self.q.all()
        self.assertIn(aid, [r["id"] for r in recs])

    def test_queue_survives_clean_restart(self):
        aid = self.queue_email()
        self.q.decide(aid, True, "ok", decided_by="human-operator")
        # A fresh ApprovalQueue on the same run dir (restart
        # equivalent) sees everything.
        q2 = ApprovalQueue(self.ctx["run_dir"],
                           ActionLog(self.ctx["run_dir"] / "actions.jsonl"))
        self.assertEqual(q2.get(aid)["status"], "approved")


class WebDurabilityBase(unittest.TestCase):
    def setUp(self):
        self.ctx = make_run()
        self.policy_file = None
        self.server = make_server(self.ctx["run_dir"], token=TOKEN,
                                  policy_path=self._policy_path())
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.ident = self.ctx["identities"]["support"]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)

    def _policy_path(self):
        path = Path(tempfile.mkdtemp(prefix="govdur-pol-")) / "policy.yaml"
        path.write_text(_DELEG_POLICY, encoding="utf-8")
        self.policy_file = str(path)
        return self.policy_file

    # -- fixtures ------------------------------------------------------
    def queue_email(self, to="victim@synthetic.local"):
        res = self.ctx["executor"].call(
            self.ident, "send_email", to=to, subject="s", body="b",
            justification="routine vendor invoice")
        self.assertEqual(res["status"], "queued", res)
        return res["approval_id"]

    def queue_quorum_email(self):
        self.ctx["approvals"].set_quorum_config(QUORUM_WEB)
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
        cookie = "session=" + m.group(1)
        return cookie, hdrs.get("Set-Cookie", "")

    def get_csrf(self, cookie, aid):
        status, body, _ = self._request(
            "GET", "/approvals/%s" % aid, cookie=cookie)
        self.assertEqual(status, 200, "detail page did not render")
        m = re.search(r'''name=['"]csrf['"] value=['"]([^'"]+)['"]''', body)
        self.assertIsNotNone(m, "no CSRF token on detail page")
        return m.group(1)

    def delegate(self, aid, to, reason, cookie=None, csrf=None, origin=None):
        fields = {"to": to, "reason": reason}
        if csrf is not None:
            fields["csrf"] = csrf
        headers = {}
        if origin is not None:
            headers["Origin"] = origin
        return self._request(
            "POST", "/approvals/%s/delegate" % aid,
            body=urlencode(fields), headers=headers, cookie=cookie)[:2]

    def vote(self, aid, vote, reason, cookie=None, csrf=None, origin=None):
        fields = {"vote": vote, "reason": reason}
        if csrf is not None:
            fields["csrf"] = csrf
        headers = {}
        if origin is not None:
            headers["Origin"] = origin
        return self._request(
            "POST", "/approvals/%s/vote" % aid,
            body=urlencode(fields), headers=headers, cookie=cookie)[:2]


class TestWebCrossSessionCSRF(WebDurabilityBase):
    """F80-pattern variants for the wave-22/23 routes: a CSRF token is
    bound to its session — replaying a VICTIM's valid token from an
    ATTACKER's session must fail."""

    def test_delegate_cross_session_token_replay_rejected(self):
        aid = self.queue_email()
        victim_cookie, _ = self.login()
        victim_csrf = self.get_csrf(victim_cookie, aid)
        attacker_cookie, _ = self.login()
        self.assertNotEqual(victim_cookie, attacker_cookie)
        # Attacker replays the victim's *valid* token with the
        # attacker's own session cookie.
        status, _ = self.delegate(aid, "alice", "pwned",
                                  cookie=attacker_cookie, csrf=victim_csrf)
        self.assertEqual(status, 403)
        self.assertIsNone(self.approval(aid)["delegated_to"])
        self.assertEqual(
            len(self.audit_events("web_csrf_failure", aid)), 1)

    def test_vote_cross_session_token_replay_rejected(self):
        aid = self.queue_quorum_email()
        victim_cookie, _ = self.login()
        victim_csrf = self.get_csrf(victim_cookie, aid)
        attacker_cookie, _ = self.login()
        status, _ = self.vote(aid, "approve", "pwned",
                              cookie=attacker_cookie, csrf=victim_csrf)
        self.assertEqual(status, 403)
        self.assertEqual(self.approval(aid).get("votes") or [], [])
        self.assertEqual(
            len(self.audit_events("web_csrf_failure", aid)), 1)

    def test_delegate_reversed_session_token_rejected(self):
        # The mirror direction: attacker's token presented with the
        # victim's cookie is equally invalid.
        aid = self.queue_email()
        victim_cookie, _ = self.login()
        attacker_cookie, _ = self.login()
        attacker_csrf = self.get_csrf(attacker_cookie, aid)
        status, _ = self.delegate(aid, "alice", "pwned",
                                  cookie=victim_cookie, csrf=attacker_csrf)
        self.assertEqual(status, 403)
        self.assertIsNone(self.approval(aid)["delegated_to"])


class TestWebAuditView(WebDurabilityBase):
    """The read-only GET /audit trail: auth-gated, escaped, side-effect
    free."""

    def test_audit_requires_login(self):
        status, _, hdrs = self._request("GET", "/audit")
        self.assertEqual(status, 302)
        self.assertIn("/login", hdrs.get("Location", ""))

    def test_audit_renders_and_escapes(self):
        aid = self.queue_email()
        cookie, _ = self.login()
        csrf = self.get_csrf(cookie, aid)
        # An invalid decision value is form-supplied and lands in the
        # audit reason verbatim — hostile markup must be escaped in
        # the audit view, never rendered raw.
        hostile = "<script>alert(1)</script>"
        status, _, _ = self._request(
            "POST", "/approvals/%s/decide" % aid,
            body=urlencode({"decision": hostile, "reason": "x",
                            "csrf": csrf}),
            cookie=cookie)
        self.assertEqual(status, 400)
        refused = self.audit_events("web_decision_refused", aid)
        self.assertEqual(len(refused), 1)
        self.assertIn(hostile, refused[0]["reason"])
        status, body, _ = self._request("GET", "/audit", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn("web_decision_refused", body)
        self.assertIn("&lt;script&gt;", body)
        self.assertNotIn(hostile, body)

    def test_audit_lists_web_decisions_with_distinct_label(self):
        aid = self.queue_email()
        cookie, _ = self.login()
        csrf = self.get_csrf(cookie, aid)
        status, _, _ = self._request(
            "POST", "/approvals/%s/decide" % aid,
            body=urlencode({"decision": "approve", "reason": "fine",
                            "csrf": csrf}),
            cookie=cookie)
        self.assertEqual(status, 302)
        status, body, _ = self._request("GET", "/audit", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn("approval_decision", body)
        self.assertIn("web/human-operator", body)

    def test_audit_get_never_mutates(self):
        aid = self.queue_email()
        cookie, _ = self.login()
        before_records = self.ctx["approvals"].all()
        before_log = self.ctx["read_log"]()
        for _ in range(2):
            status, _, _ = self._request("GET", "/audit", cookie=cookie)
            self.assertEqual(status, 200)
        # Viewing the trail records nothing and changes nothing.
        self.assertEqual(self.ctx["approvals"].all(), before_records)
        self.assertEqual(self.ctx["read_log"](), before_log)

    def test_audit_linked_from_queue_page(self):
        cookie, _ = self.login()
        status, body, _ = self._request("GET", "/", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn("href='/audit'", body)


class TestWebSessionProperties(WebDurabilityBase):
    """Session hygiene: server-minted ids, no fixation, hardened cookie."""

    def test_two_logins_mint_distinct_session_ids(self):
        cookie1, _ = self.login()
        cookie2, _ = self.login()
        self.assertNotEqual(cookie1, cookie2)
        # Both are usable: the console allows concurrent sessions by
        # design (documented honest limit — no per-human login).
        for cookie in (cookie1, cookie2):
            status, _, _ = self._request("GET", "/", cookie=cookie)
            self.assertEqual(status, 200)

    def test_session_id_is_not_client_choosable(self):
        # No login flow accepts a client-supplied session id: a
        # fabricated cookie is simply unauthenticated.
        status, _, hdrs = self._request(
            "GET", "/", cookie="session=attacker-chosen-id")
        self.assertEqual(status, 302)
        self.assertIn("/login", hdrs.get("Location", ""))

    def test_set_cookie_carries_httponly_and_samesite_strict(self):
        _, raw = self.login()
        self.assertIn("HttpOnly", raw)
        self.assertIn("SameSite=Strict", raw)


class TestQueuePortSeam(WebDurabilityBase):
    """D1 pluggability: the web app accepts an injected queue port."""

    def test_queue_injection(self):
        queue = ApprovalQueue(self.ctx["run_dir"],
                              ActionLog(self.ctx["run_dir"] / "actions.jsonl"))
        app = ApprovalWebApp(self.ctx["run_dir"], token=TOKEN, queue=queue)
        self.assertIs(app.queue, queue)
        # A decision through the injected port uses the canonical path.
        aid = self.queue_email()
        cookie, csrf_holder = app.create_test_session()
        record, _ = app.queue.decide(aid, True, "ok",
                                     decided_by=WEB_DECIDED_BY)
        self.assertEqual(record["status"], "approved")
        self.assertEqual(record["decided_by"], WEB_DECIDED_BY)

    def test_default_builds_canonical_queue(self):
        app = ApprovalWebApp(self.ctx["run_dir"], token=TOKEN)
        self.assertIsInstance(app.queue, ApprovalQueue)


if __name__ == "__main__":
    unittest.main()
