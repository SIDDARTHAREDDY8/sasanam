"""H19: approver-shield brief rendered in the web UI (row 3 residual).

RED (before): a capture-tier approval's detail page in the web UI does not
render the independent shield brief — the GAP-3 shield is CLI +
programmatic only.

GREEN (after): the detail page renders the independent brief (pure
function of the stored record — the same brief dict the CLI shows),
prose-divergence flags, and fatigue state on capture-tier approvals.
Display-only; no new auth surface.

Deterministic in both normal and clean (env -u GOV_DEPLOYMENT_MODE)
environments. $0, synthetic/local only.
"""

import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import http.client
import importlib
import os as _os
import re
import secrets
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode

# The HMAC-chained audit log fails closed without a configured key
# (wave-81): provision an explicit test key like production does.
_os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
_os.environ.setdefault("GOV_LOG_KEY_EPOCH", "h19-probe")

_TESTS_DIR = str(Path(__file__).resolve().parent.parent / "tests")
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
for _p in (_TESTS_DIR, _REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # noqa: E402

# H19 targets gov/approval_web.py (the promoted hardened console), NOT
# the stale workstreams/platform/approval_web.py prototype (which the
# older test module imports as top-level `approval_web`).
_APPROVAL_WEB = importlib.import_module("gov.approval_web")
_SHIELD = importlib.import_module("gov.approver_shield")

TOKEN = "h19-probe-token"

# Justification that names a different recipient than the actual `to`
# -> prose_divergence is set -> capture tier.
DIVERGENT_JUST = ("Please send this to teammate@synthetic.local right away, "
                  "it's urgent and pre-approved by leadership.")


def _brief_markers():
    """HTML markers the shield-brief panel must contain."""
    return [
        "INDEPENDENT SHIELD BRIEF",
        "shield-brief",
        "machine-verified target",
        "quarantine",
    ]


class H19Probe(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="h19-")
        self.ctx = make_run()
        self.server = _APPROVAL_WEB.make_server(
            self.ctx["run_dir"], token=TOKEN)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.ident = self.ctx["identities"]["support"]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)

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
        return status, hdrs, data

    def _login(self):
        status, hdrs, _ = self._request(
            "POST", "/login", body=urlencode({"token": TOKEN}))
        self.assertEqual(status, 302, "login failed")
        m = re.search(r"session=([^;]+)", hdrs.get("Set-Cookie", ""))
        self.assertIsNotNone(m, "no session cookie")
        return "session=" + m.group(1)

    def _queue_capture_tier(self):
        res = self.ctx["executor"].call(
            self.ident, "send_email",
            to="attacker@synthetic.local", subject="s", body="b",
            justification=DIVERGENT_JUST)
        self.assertEqual(res["status"], "queued", res)
        aid = res["approval_id"]
        rec = self.ctx["approvals"].get(aid)
        self.assertTrue(
            _SHIELD.is_capture_tier(rec),
            "fixture did not produce a capture-tier record: %r" % (
                {k: rec.get(k) for k in ("shield_tier", "persuasion_score",
                                         "prose_divergence",
                                         "packet_risk_score")},))
        return aid, rec

    def test_capture_tier_detail_renders_shield_brief(self):
        """Capture-tier detail page renders the independent shield brief."""
        aid, rec = self._queue_capture_tier()
        cookie = self._login()
        status, _, body = self._request(
            "GET", "/approvals/%s" % aid, cookie=cookie)
        self.assertEqual(status, 200, "detail page did not render")
        missing = [m for m in _brief_markers() if m not in body]
        self.assertEqual(
            missing, [],
            "RED: shield brief absent from capture-tier detail page; "
            "missing markers: %r" % (missing,))

    def test_brief_content_matches_cli_brief(self):
        """The web brief is the same brief dict the CLI renders."""
        aid, rec = self._queue_capture_tier()
        cookie = self._login()
        status, _, body = self._request(
            "GET", "/approvals/%s" % aid, cookie=cookie)
        self.assertEqual(status, 200)
        brief = _SHIELD.shield_brief(rec)
        # The machine-verified target and the packet digest must appear
        # verbatim — the web renders the stored record's brief, not a
        # re-derivation.
        target = str((brief.get("action") or {}).get("target") or "")
        self.assertTrue(target, "brief has no target")
        self.assertIn(target, body,
                      "RED: web brief does not carry the CLI brief's "
                      "machine-verified target")
        digest = str(brief.get("packet_digest") or "")
        if digest:
            self.assertIn(digest, body,
                          "RED: web brief does not carry the CLI brief's "
                          "packet digest")

    def test_standard_tier_no_brief_required(self):
        """Standard-tier records are not required to render the brief."""
        res = self.ctx["executor"].call(
            self.ident, "send_email",
            to="vendor@synthetic.local", subject="s", body="b",
            justification="routine vendor invoice")
        self.assertEqual(res["status"], "queued", res)
        aid = res["approval_id"]
        rec = self.ctx["approvals"].get(aid)
        self.assertFalse(_SHIELD.is_capture_tier(rec),
                         "fixture unexpectedly capture-tier")
        cookie = self._login()
        status, _, body = self._request(
            "GET", "/approvals/%s" % aid, cookie=cookie)
        self.assertEqual(status, 200, "detail page did not render")


def main():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(H19Probe)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("RESULT: GREEN — shield brief rendered on capture-tier "
              "detail page; content matches the CLI brief.")
    else:
        print("RESULT: RED — shield brief absent from the web UI "
              "(failures=%d, errors=%d)."
              % (len(result.failures), len(result.errors)))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
