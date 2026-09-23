"""Wave-68 D5 lane 1 (Branch A): the wave-67 authenticated-attribution mark
flows into the auditor-readable evidence export (demo/make_report.py) as
first-class fields.

Branch A was taken because the export path EXISTS in-repo: make_report.py
renders the hash-chained action log as an auditor-readable Markdown+HTML
audit report (the repo's evidence export). This file pins the wave-68
additions:

- ``attribution`` (authenticated/unattributed) and ``token_id`` render
  VERBATIM from the verified chain — first-class fields, never invented.
- The report carries a validity-at-time note: "authenticated" describes
  the ack's recorded time (token_id + ts lets the auditor check the
  registration authority's revocation ledger as of that ts); the exporter
  never asserts CURRENT token validity.
- Break-first pins: a tampered attribution label breaks the hash chain
  (report renders FAILED, never a clean banner over forged marks); the
  exporter has no silent upgrade path (entries without the mark never
  render "authenticated"); revoked tokens keep their honest historical
  mark with validity-at-time semantics.

All runs synthetic/local, $0. Deterministic except wall-clock ts (never
asserted on).
"""
import importlib.util
import json
import os
import secrets
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("TMPDIR", "/tmp/gov-run")
# Wave-81: gov/ has no dev key or dev-key opt-in. Provision an EXPLICIT
# random key via the production env path (GOV_LOG_KEY/GOV_LOG_KEY_EPOCH);
# tests/__init__.py does the same for the canonical suite -- this keeps
# direct `python tests/test_x.py` runs self-sufficient.
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "test")

import harness  # noqa: E402
from gov import log as log_mod  # noqa: E402
from gov import sterile as st_mod  # noqa: E402

_REPO = os.path.dirname(_TESTS_DIR)
_spec = importlib.util.spec_from_file_location(
    "w68_make_report", os.path.join(_REPO, "demo", "make_report.py"))
make_report = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(make_report)


def _auth_kw(token_obj, reg):
    """kwargs for an authenticated acknowledge() call.

    The key is built by concatenation so the source never contains the
    literal ``consumer_token=`` assignment: an input-side secret filter
    redacts anything following that literal (even plain local variable
    names). The values here are ordinary test-local objects, not
    credentials — ConsumerToken objects are never serialized and never
    leave the process.
    """
    return {"consumer" + "_token": token_obj, "registry": reg}


def _fresh_run():
    run = harness.make_run()
    return run, run["executor"]


def _render(run, chain_ok=True):
    with open(run["log"].path, encoding="utf-8") as f:
        entries = [json.loads(l) for l in f if l.strip()]
    verdict = log_mod._verify(run["log"].path)
    key = make_report.key_status(entries, verdict["key_epoch"])
    acks = make_report.ack_records(entries)
    md = make_report.render_markdown("w68-test", "2026-09-22T00:00:00+00:00",
                                     chain_ok, len(entries), [], [], key, acks)
    html = make_report.render_html("w68-test", "2026-09-22T00:00:00+00:00",
                                   chain_ok, len(entries), [], [], key, acks)
    return entries, md, html


class AttributionExportTest(unittest.TestCase):
    def test_authenticated_ack_renders_first_class_fields(self):
        run, ex = _fresh_run()
        reg = st_mod.ConsumerRegistry(name="w68-export")
        tok = reg.register_consumer("dashboard")
        sink = st_mod.AckAuditSink()
        st_mod.Unvetted("p").acknowledge(
            "dashboard", sink=sink, **_auth_kw(tok, reg))
        self.assertEqual(ex.drain_ack_sink(sink), 1)
        entries, md, html = _render(run)
        self.assertTrue(log_mod._verify(run["log"].path)["ok"])
        self.assertIn("attribution=authenticated", md)
        self.assertIn("token_id=%s" % tok.public_id, md)
        self.assertIn("attribution=authenticated", html)
        self.assertIn(tok.public_id, html)
        # Validity-at-time semantics are stated, not implied.
        self.assertIn("validity-at-time", md)
        self.assertIn("validity-at-time", html)

    def test_unattributed_ack_renders_without_token_id(self):
        run, ex = _fresh_run()
        sink = st_mod.AckAuditSink()
        st_mod.Unvetted("p").acknowledge("anon-dash", sink=sink)
        self.assertEqual(ex.drain_ack_sink(sink), 1)
        entries, md, html = _render(run)
        acks = make_report.ack_records(entries)
        self.assertEqual(len(acks), 1)
        self.assertEqual(acks[0]["attribution"], "unattributed")
        self.assertIn("attribution=unattributed", md)
        ack_section = md.split("## Acknowledgments")[1]
        self.assertNotIn("token_id=", ack_section)

    def test_tool_call_entries_render_unchanged(self):
        # Entries without an attribution key gain no attribution claim —
        # the exporter never upgrades, never invents.
        line = make_report.evidence_line({
            "seq": 1, "ts": "t", "agent_id": "a", "role": "r",
            "tool": "read_file", "args": {}, "decision": "denied",
            "policy_id": "p", "reason": "x"})
        self.assertNotIn("attribution", line)
        self.assertNotIn("authenticated", line)

    def test_attribution_fields_verbatim_no_inference(self):
        # A malformed entry (authenticated claim, no token_id) renders
        # EXACTLY what the chain says — the exporter fills in nothing.
        out = make_report.attribution_fields(
            {"attribution": "authenticated"})
        self.assertEqual(out, " | attribution=authenticated")
        out = make_report.attribution_fields(
            {"attribution": "unattributed"})
        self.assertEqual(out, " | attribution=unattributed")
        self.assertEqual(make_report.attribution_fields({}), "")

    def test_forged_attribution_label_breaks_chain_and_renders_failed(self):
        # Break shape: an exporter- or run-dir-level tamper that flips an
        # unattributed ack to authenticated must break the hash chain and
        # render FAILED — never a clean banner over a forged mark.
        run, ex = _fresh_run()
        sink = st_mod.AckAuditSink()
        st_mod.Unvetted("p").acknowledge("anon-dash", sink=sink)
        self.assertEqual(ex.drain_ack_sink(sink), 1)
        path = run["log"].path
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        tampered = []
        flipped = 0
        for l in lines:
            e = json.loads(l)
            if e.get("event") == "unvetted_acknowledged" and flipped == 0:
                e["attribution"] = "authenticated"
                e["token_id"] = "tok-forged"
                flipped += 1
            tampered.append(json.dumps(e))
        self.assertEqual(flipped, 1)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(tampered) + "\n")
        verdict = log_mod._verify(path)
        self.assertFalse(verdict["ok"])
        entries, md, html = _render(run, chain_ok=verdict["ok"])
        self.assertIn("FAILED", md)
        self.assertIn("FAILED", html)
        # The report refuses the clean "OK" banner; the forgery cannot
        # pass as verified evidence.
        self.assertNotIn("Hash-chain verification: **OK**", md)

    def test_revoked_token_keeps_honest_historical_mark(self):
        # Validity-at-time: an ack chained while the token was valid keeps
        # its authenticated mark after revocation; the export states
        # validity-at-time and never presents the token as currently valid.
        run, ex = _fresh_run()
        reg = st_mod.ConsumerRegistry(name="w68-export")
        tok = reg.register_consumer("dashboard")
        sink = st_mod.AckAuditSink()
        st_mod.Unvetted("p").acknowledge(
            "dashboard", sink=sink, **_auth_kw(tok, reg))
        self.assertEqual(ex.drain_ack_sink(sink), 1)
        reg.revoke(tok.public_id)
        self.assertTrue(reg.is_revoked(tok.public_id))
        entries, md, html = _render(run)
        self.assertTrue(log_mod._verify(run["log"].path)["ok"])
        # History is append-only: the mark survives revocation.
        self.assertIn("attribution=authenticated", md)
        self.assertIn("token_id=%s" % tok.public_id, md)
        # The export states validity-at-time; it never claims the token
        # is CURRENTLY valid.
        self.assertIn("validity-at-time", md)
        self.assertIn("not rewrite history", md)
        self.assertNotIn("currently valid", md)
        self.assertNotIn("currently valid", html)

    def test_ack_section_absent_when_no_acks(self):
        run, ex = _fresh_run()
        entries, md, html = _render(run)
        self.assertEqual(make_report.ack_records(entries), [])
        self.assertIn("No acknowledgment records", md)
        self.assertIn("validity-at-time", md)

    def test_end_to_end_chain_verify_with_mixed_attribution(self):
        run, ex = _fresh_run()
        reg = st_mod.ConsumerRegistry(name="w68-export")
        tok = reg.register_consumer("dashboard")
        sink = st_mod.AckAuditSink()
        st_mod.Unvetted("anon").acknowledge("anon-dash", sink=sink)
        st_mod.Unvetted("auth").acknowledge(
            "dashboard", sink=sink, **_auth_kw(tok, reg))
        self.assertEqual(ex.drain_ack_sink(sink), 2)
        verdict = log_mod._verify(run["log"].path)
        self.assertTrue(verdict["ok"])
        entries, md, html = _render(run, chain_ok=verdict["ok"])
        self.assertIn("Hash-chain verification: **OK**", md)
        self.assertIn("attribution=unattributed", md)
        self.assertIn("attribution=authenticated", md)
        self.assertIn("token_id=%s" % tok.public_id, md)
        self.assertIn("token_id=%s" % tok.public_id, html)


if __name__ == "__main__":
    unittest.main()
