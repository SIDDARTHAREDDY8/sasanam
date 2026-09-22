"""Wave-27 (P4) web-UX lane: queue-health advisory panel + cluster banner.

Covers the ``gov/approval_web.py`` wave-27 additions that surface the
F4 approval-fatigue detector (``ApprovalQueue.queue_anomalies()``) in
the console:

* list page: "Queue health" advisory panel with the anomaly clusters
  (fatigue burst / rate spike / unusual tool mix), linked cluster
  members, and explicit advisory-only wording
* detail page: CLUSTER MEMBER banner naming the cluster type(s) for a
  record that belongs to a cluster
* safety: hostile/ malformed QueuePort ``queue_anomalies`` output is
  escaped and normalized; a missing or raising detector degrades to
  "no panel" rather than taking the console down; the panel never
  approves, denies, or mutates records (read-only contract)

Drives a localhost ThreadingHTTPServer via http.client against
deterministic harness.make_run() fixtures for the end-to-end tests,
and direct render-function calls for the escaping/safety tests.
Quiet-box: run with a private TMPDIR=/tmp/gov-w27-web/<runid>.
"""

import http.client
import re
import sys
import os
import threading
import types
import unittest
from urllib.parse import urlencode

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_TESTS_DIR)
for _p in (_TESTS_DIR, _REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # noqa: E402
from gov.approval_web import (  # noqa: E402
    _anomaly_panel,
    _queue_anomalies,
    _record_cluster_types,
    make_server,
    render_detail,
    render_list,
)

TOKEN = "w27-web-test-token"


class WebBase(unittest.TestCase):
    def setUp(self):
        self.ctx = make_run()
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

    def queue_email(self, **kw):
        kw.setdefault("to", "victim@synthetic.local")
        kw.setdefault("subject", "s")
        kw.setdefault("body", "b")
        res = self.ctx["executor"].call(self.ident, "send_email", **kw)
        self.assertEqual(res["status"], "queued", res)
        return res["approval_id"]

    def login(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/login",
                     body=urlencode({"token": TOKEN}),
                     headers={"Content-Type":
                              "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        data = resp.read()
        hdrs = dict(resp.getheaders())
        conn.close()
        self.assertEqual(resp.status, 302, data)
        m = re.search(r"session=([^;]+)", hdrs.get("Set-Cookie", ""))
        self.assertIsNotNone(m, "login did not mint a session")
        return "session=" + m.group(1)

    def get(self, path, cookie=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Cookie": cookie} if cookie else {}
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", "replace")
        conn.close()
        return resp.status, data

    def queue_fatigue_burst(self, n=6):
        """Queue >= ANOMALY_BURST_THRESHOLD pending items from one agent."""
        return [self.queue_email(justification="burst item %d" % i)
                for i in range(n)]


class StubQueue:
    """Minimal QueuePort double for direct-render safety tests."""

    run_id = "stub-run"
    delegation_enabled = False

    def __init__(self, records=(), anomalies=()):
        self._records = list(records)
        self._anomalies = anomalies

    def all(self):
        return list(self._records)

    def pending_risk_sorted(self):
        return [r for r in self._records if r.get("status") == "pending"]

    def risk_detail(self, record):
        return {"score": 10, "level": "low", "factors": ["stub"]}

    def queue_anomalies(self):
        return self._anomalies


class BareQueue:
    """QueuePort double that never implemented the F4 surface at all."""

    run_id = "bare-run"
    delegation_enabled = False

    def __init__(self, records=()):
        self._records = list(records)

    def all(self):
        return list(self._records)

    def pending_risk_sorted(self):
        return [r for r in self._records if r.get("status") == "pending"]

    def risk_detail(self, record):
        return {"score": 10, "level": "low", "factors": ["stub"]}


def _stub_record(i, pending=True):
    return {"id": "aq%d" % i, "agent_id": "agent-x", "tool": "send_email",
            "policy_id": "approval-outbound-sends",
            "status": "pending" if pending else "approved"}


class TestAnomalyPanelHttp(WebBase):
    def test_panel_renders_on_fatigue_burst(self):
        ids = self.queue_fatigue_burst(6)
        cookie = self.login()
        status, body = self.get("/", cookie=cookie)
        self.assertEqual(status, 200, body[:500])
        self.assertIn("anomaly-panel", body)
        self.assertIn("FATIGUE-BURST", body)
        self.assertIn("Queue health", body)
        for aid in ids:
            self.assertIn("/approvals/%s" % aid, body)

    def test_panel_absent_without_anomalies(self):
        self.queue_email()
        cookie = self.login()
        status, body = self.get("/", cookie=cookie)
        self.assertEqual(status, 200, body[:500])
        self.assertNotIn("<div class='anomaly-panel'>", body)

    def test_panel_is_advisory_only(self):
        self.queue_fatigue_burst(6)
        cookie = self.login()
        _, body = self.get("/", cookie=cookie)
        self.assertIn("Advisory only", body)
        self.assertIn("auto-approve", body)
        self.assertIn("auto-deny", body)
        # the "never ..." advisory phrasing is the exact panel copy
        self.assertIn("never auto-approve, auto-deny, or change record state",
                      body)
        self.assertNotIn("approve all", body.lower())

    def test_detail_banner_for_cluster_member(self):
        ids = self.queue_fatigue_burst(6)
        cookie = self.login()
        status, body = self.get("/approvals/%s" % ids[0], cookie=cookie)
        self.assertEqual(status, 200, body[:500])
        self.assertIn("CLUSTER MEMBER", body)
        self.assertIn("fatigue_burst", body)

    def test_detail_no_banner_for_non_member(self):
        aid = self.queue_email()
        cookie = self.login()
        status, body = self.get("/approvals/%s" % aid, cookie=cookie)
        self.assertEqual(status, 200, body[:500])
        self.assertNotIn("CLUSTER MEMBER", body)


class TestAnomalyPanelSafety(unittest.TestCase):
    def _app(self, queue):
        return types.SimpleNamespace(queue=queue)

    def test_hostile_anomaly_fields_escaped(self):
        hostile = {
            "type": "<script>alert(1)</script>",
            "summary": "<img src=x onerror=alert(2)>",
            "items": ["<b>evil</b>", "aq1"],
        }
        q = StubQueue(records=[_stub_record(1)], anomalies=[hostile])
        panel = _anomaly_panel(self._app(q))
        self.assertIn("anomaly-panel", panel)
        self.assertNotIn("<script>", panel)
        self.assertNotIn("<img", panel)
        self.assertNotIn("<b>evil</b>", panel)
        # unknown hostile type maps to the fixed "ANOMALY" label (the
        # hostile type string itself is never rendered, raw or escaped)
        self.assertIn("ANOMALY", panel)
        self.assertNotIn("script", panel.replace("advisory anomaly", ""))
        self.assertIn("&lt;img", panel)  # summary is escaped, not dropped
        self.assertIn("/approvals/aq1", panel)
        self.assertIn("/approvals/&lt;b&gt;evil&lt;/b&gt;", panel)

    def test_malformed_entries_dropped(self):
        q = StubQueue(anomalies=[
            {"type": "fatigue_burst", "summary": "ok", "items": ["aq1"]},
            "not-a-dict",
            42,
            {"type": None, "summary": None, "items": "not-a-list"},
        ])
        panel = _anomaly_panel(self._app(q))
        self.assertIn("FATIGUE-BURST", panel)
        self.assertIn("ANOMALY", panel)  # the None-type entry
        self.assertNotIn("42", panel)

    def test_nonlist_detector_output_ignored(self):
        for junk in ({"weird": 1}, "string", 7, None):
            q = StubQueue(anomalies=junk)
            self.assertEqual(_anomaly_panel(self._app(q)), "")
            self.assertEqual(_queue_anomalies(self._app(q)), [])

    def test_raising_detector_degrades_advisory(self):
        class Raising(StubQueue):
            def queue_anomalies(self):
                raise RuntimeError("detector down")
        q = Raising(records=[_stub_record(1)])
        app = self._app(q)
        self.assertEqual(_anomaly_panel(app), "")
        self.assertEqual(_record_cluster_types(app, "aq1"), [])
        # the list page still renders — advisory loss, not console loss
        html = render_list(app, csrf="c")
        self.assertIn("Pending", html)
        self.assertNotIn("<div class='anomaly-panel'>", html)

    def test_queue_port_double_without_method(self):
        # BareQueue deliberately does NOT define queue_anomalies —
        # a QueuePort double that never implemented the F4 surface.
        q = BareQueue(records=[_stub_record(1)])
        self.assertFalse(hasattr(q, "queue_anomalies"))
        app = self._app(q)
        self.assertEqual(_anomaly_panel(app), "")
        html = render_list(app, csrf="c")
        self.assertIn("Pending", html)

    def test_panel_does_not_mutate_queue(self):
        q = StubQueue(records=[_stub_record(1)], anomalies=[
            {"type": "fatigue_burst", "summary": "s", "items": ["aq1"]}])
        app = self._app(q)
        first = _queue_anomalies(app)
        first.append({"type": "injected"})
        first[0]["items"].append("aq9")
        second = _queue_anomalies(app)
        self.assertEqual(second,
                         [{"type": "fatigue_burst", "summary": "s",
                           "items": ["aq1"]}])
        # and nothing on the stub changed
        self.assertEqual(q._anomalies[0]["items"], ["aq1"])

    def test_render_detail_banner_uses_cluster_types(self):
        q = StubQueue(records=[_stub_record(1)], anomalies=[
            {"type": "fatigue_burst", "summary": "s", "items": ["aq1"]},
            {"type": "rate_spike", "summary": "r", "items": ["aq1"]}])
        app = self._app(q)
        html = render_detail(app, _stub_record(1), "csrf-token")
        self.assertIn("CLUSTER MEMBER", html)
        self.assertIn("fatigue_burst", html)
        self.assertIn("rate_spike", html)


if __name__ == "__main__":
    unittest.main()
