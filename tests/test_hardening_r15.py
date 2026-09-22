"""Hardening round-15 regression tests: wave-16 findings F65-F68.

F65 (HIGH):     the harness tracks ALL per-cell temp dirs explicitly
    (the _CELL_DIRS registry, fed by _cell_make_run and _spawn) and
    removes them in run_cell's finally even when the cell raises; a
    diff-sweep of the fresh TMPDIR backstops probe-internal
    tempfile.mkdtemp / make_run() scratch the registry never sees.
    Probes with their own scratch self-clean too: w9's _policy_with_budget
    w9pol-* dirs via a finally (run dirs via the _owned_run context
    manager) and r13's _r13_demo_honesty gov-r13-demo-* dir via a
    finally. GOV_KEEP_CELL_DIRS=1 still retains the cell dirs.
F66 (MEDIUM):   (tests added with the product change below)
F67 (MEDIUM):   (tests added with the product change below)
F68 (MEDIUM):   (tests added with the product change below)
"""

import contextlib
import io
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import make_run  # noqa: E402

try:
    import langchain_core  # noqa: F401
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False


@contextlib.contextmanager
def _fresh_tmpdir():
    """Empty TMPDIR for the block; tempfile re-reads it; restored after."""
    outer = tempfile.mkdtemp(prefix="gov-r15-test-outer-")
    td = os.path.join(outer, "t")
    os.makedirs(td)
    old_env = os.environ.get("TMPDIR")
    old_cached = tempfile.tempdir
    os.environ["TMPDIR"] = td
    tempfile.tempdir = None
    assert tempfile.gettempdir() == td
    try:
        yield td
    finally:
        if old_env is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = old_env
        tempfile.tempdir = old_cached
        shutil.rmtree(outer, ignore_errors=True)


class TestF65CellTmpdirTracking(unittest.TestCase):
    def test_cells_leave_no_new_dirs(self):
        import evals.run_evals as re
        cells = [
            # confederate-spawning cell (_spawn registers 2 run dirs)
            ("sit5", "langchain", "standard", "provisional"),
            # _allow_spawn direct make_run inside the probe
            ("sit31", "langchain", "low", "provisional"),
            # w9 drip: w9pol-* policy dirs + two run dirs (probe self-cleans)
            ("sit53", "langchain", "standard", "real"),
            # r13: gov-r13-demo-* demo scratch (probe self-cleans)
            ("sit89", "mcp", "standard", "provisional"),
            # multiprocessing sit (known concurrent-write load flake)
            ("sit64", "langchain", "standard", "provisional"),
        ]
        with _fresh_tmpdir() as td:
            for sid, adapter, priv, harness in cells:
                before = set(os.listdir(td))
                try:
                    re.run_cell(sid, adapter, priv, harness)
                except Exception:
                    pass  # cleanup must hold even when the cell raises
                new = sorted(set(os.listdir(td)) - before)
                self.assertEqual(
                    new, [],
                    "%s/%s/%s leaked temp dirs: %r" % (sid, adapter, priv, new))

    def test_keep_env_retains_cell_dirs(self):
        import evals.run_evals as re
        with _fresh_tmpdir() as td:
            os.environ["GOV_KEEP_CELL_DIRS"] = "1"
            try:
                before = set(os.listdir(td))
                re.run_cell("sit5", "langchain", "standard", "provisional")
                new = sorted(set(os.listdir(td)) - before)
            finally:
                os.environ.pop("GOV_KEEP_CELL_DIRS", None)
            # ledger dir + main run dir + confederate run dir: non-vacuous
            self.assertGreaterEqual(len(new), 2,
                                   "GOV_KEEP_CELL_DIRS=1 kept nothing: %r" % (new,))
            self.assertTrue(any(n.startswith("govcell-ledger-") for n in new))

    def test_cleanup_removes_explicitly_tracked_nonstandard_prefix(self):
        import evals.run_evals as re
        with _fresh_tmpdir() as td:
            weird = Path(tempfile.mkdtemp(prefix="zz-nonstandard-"))
            (weird / "f.txt").write_text("x")
            outside = Path(tempfile.mkdtemp(prefix="gov-r15-outside-",
                                           dir="/tmp"))
            re._cleanup_cell_dirs(str(weird))
            self.assertFalse(weird.exists(),
                             "explicitly tracked nonstandard-prefix dir survived")
            # safety boundary: dirs outside the active temp root are untouched
            re._cleanup_cell_dirs(str(outside))
            try:
                self.assertTrue(outside.exists(),
                                "cleanup removed a dir outside the temp root")
            finally:
                shutil.rmtree(outside, ignore_errors=True)
            # non-directories and missing paths are tolerated, not fatal
            f = Path(td) / "plain-file"
            f.write_text("x")
            re._cleanup_cell_dirs(str(f), os.path.join(td, "no-such-dir"), "")

    def test_w9_drip_self_cleans_policy_and_run_dirs(self):
        import evals.w9_probes as w9
        with _fresh_tmpdir() as td:
            before = set(os.listdir(td))
            o = w9._w9_drip()
            self.assertTrue(all(o.values()),
                            "w9 drip observations changed: %r" % (o,))
            new = sorted(set(os.listdir(td)) - before)
            self.assertEqual(new, [],
                             "w9 drip leaked temp dirs: %r" % (new,))

    def test_r13_demo_honesty_self_cleans(self):
        import evals.r13_probes as r13
        with _fresh_tmpdir() as td:
            before = set(os.listdir(td))
            o = r13._r13_demo_honesty()
            self.assertIn("e2e_default_shape", o)
            new = sorted(set(os.listdir(td)) - before)
            self.assertEqual(new, [],
                             "r13 demo_honesty leaked temp dirs: %r" % (new,))


if __name__ == "__main__":
    unittest.main()


class TestF66BoundedApprovalRendering(unittest.TestCase):
    MARKER = "MARKER_F66_BOUNDARY_7d1a"

    def _ctx_with_huge_args(self):
        from gov.approvals import _canonical_dumps
        ctx = make_run()
        q = ctx["approvals"]
        ident = ctx["mint_identity"]("support-1", "support", "customer-org")
        big = "x" * (2 * 1024 * 1024)
        args = {"endpoint": "https://api.synthetic.local/v1/run",
                "params": {"payload": big + self.MARKER + big,
                           "mode": "live"}}
        aid = q.queue(
            {"tool": "api_call", "args": args, "redactions": [],
             "agent_justification": "r15 test"},
            SimpleNamespace(policy_id="p", reason="r", flag=None),
            preview="endpoint only",
            policy_hash=ctx["executor"].policy.policy_hash,
            caller_identity=ident)
        rec = [r for r in q.all() if r["id"] == aid][0]
        return ctx, rec, args

    def test_default_view_bounded_with_marker_and_full_hash(self):
        from gov.approvals import (_canonical_dumps, _print_decision_target,
                                  _DECISION_TARGET_CAP_BYTES)
        from hashlib import sha256
        _, rec, args = self._ctx_with_huge_args()
        canon = _canonical_dumps(args)
        raw = canon.encode("utf-8")
        self.assertGreater(len(raw), 4 * 1024 * 1024)
        expected = sha256(raw).hexdigest()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with mock.patch.dict(os.environ, {"GOV_FULL_ARGS": "0"}):
                _print_decision_target(rec)
        out = buf.getvalue()
        # bounded: the marker deep in the payload is NOT shown
        self.assertNotIn(self.MARKER, out)
        self.assertLess(len(out), _DECISION_TARGET_CAP_BYTES + 4096)
        # explicit truncation marker with byte counts
        self.assertIn("TRUNCATED", out)
        self.assertIn(str(len(raw)), out)
        # ...but args_sha256 always covers the FULL exact bytes
        self.assertIn("args_sha256: " + expected, out)

    def test_full_env_renders_exact_bytes(self):
        from gov.approvals import _canonical_dumps, _print_decision_target
        _, rec, args = self._ctx_with_huge_args()
        canon = _canonical_dumps(args)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with mock.patch.dict(os.environ, {"GOV_FULL_ARGS": "1"}):
                _print_decision_target(rec)
        out = buf.getvalue()
        self.assertIn(canon, out)
        self.assertIn(self.MARKER, out)
        self.assertNotIn("TRUNCATED", out)

    def test_hash_matches_record_canonical_bytes_in_list_view(self):
        from gov.approvals import (_canonical_dumps, _print_records,
                                  _DECISION_TARGET_CAP_BYTES)
        from hashlib import sha256
        ctx, rec, args = self._ctx_with_huge_args()
        expected = sha256(_canonical_dumps(args).encode("utf-8")).hexdigest()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with mock.patch.dict(os.environ, {"GOV_FULL_ARGS": "0"}):
                _print_records([rec], ctx["approvals"])
        out = buf.getvalue()
        self.assertIn("args_sha256: " + expected, out)
        self.assertIn("TRUNCATED", out)
        self.assertLess(len(out), _DECISION_TARGET_CAP_BYTES + 8192)

    def test_cli_approve_uses_bounded_helper(self):
        from gov.approvals import main
        ctx, rec, _ = self._ctx_with_huge_args()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with mock.patch.dict(os.environ, {"GOV_FULL_ARGS": "0"}):
                rc = main(["--rundir", str(ctx["run_dir"]), "approve",
                           rec["id"], "--reason", "r15 test"])
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("TRUNCATED", out)
        self.assertIn("args_sha256: ", out)


class TestF67WeakModeWarningFlag(unittest.TestCase):
    def _weak_ctx(self):
        from gov.identity import PrincipalRegistry
        # make_run mints the STANDARD_AGENTS at construction, so the
        # registry must cover their principals plus the ticket parties.
        registry = PrincipalRegistry({
            "customer-org": {"roles": ["support"],
                             "agent_ids": ["support-1"]},
            "dev-org": {"roles": ["coder"], "agent_ids": ["coder-1"]},
            "research-org": {"roles": ["researcher"],
                             "agent_ids": ["researcher-1"]},
            "ops-lead": {"roles": ["operator"], "agent_ids": ["op-1"]},
            "duty-reviewer": {"roles": ["reviewer"],
                              "agent_ids": ["rev-1"]},
        })
        return make_run(principal_registry=registry,
                        break_glass_tickets=[("T-OP", "ops-lead",
                                             "duty-reviewer")])

    def _queue_bg(self, ctx):
        q, ex = ctx["approvals"], ctx["executor"]
        evil = ex.mint_identity("op-1", "operator", "ops-lead")
        aid = q.queue(
            {"tool": "send_email", "args": {"to": "x@synthetic.local"},
             "redactions": [], "agent_justification": "t"},
            SimpleNamespace(policy_id="p", reason="r", flag=None),
            preview="t", policy_hash=ex.policy.policy_hash,
            caller_identity=evil)
        return q, aid, evil

    def test_assignment_to_flag_raises(self):
        ctx = self._weak_ctx()
        q = ctx["approvals"]
        with self.assertRaises(AttributeError):
            q._break_glass_unprotected_warned = True
        self.assertFalse(q._break_glass_unprotected_warned)

    def test_warns_once_across_repeated_calls_and_ticket_consumes(self):
        from gov.log import read_entries_with_stats
        from gov.identity import PrincipalRegistry
        registry = PrincipalRegistry({
            "customer-org": {"roles": ["support"],
                             "agent_ids": ["support-1"]},
            "dev-org": {"roles": ["coder"], "agent_ids": ["coder-1"]},
            "research-org": {"roles": ["researcher"],
                             "agent_ids": ["researcher-1"]},
            "ops-lead": {"roles": ["operator"], "agent_ids": ["op-1"]},
            "duty-reviewer": {"roles": ["reviewer"],
                              "agent_ids": ["rev-1"]},
        })
        ctx = make_run(principal_registry=registry,
                       break_glass_tickets=[("T-OP", "ops-lead",
                                            "duty-reviewer"),
                                           ("T-OP2", "ops-lead",
                                            "duty-reviewer")])
        q, aid, evil = self._queue_bg(ctx)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rec, ticket = q.break_glass(aid, "x", operator_identity=evil,
                                        ticket_id="T-OP")
        self.assertEqual(rec["status"], "approved")
        self.assertTrue(rec["break_glass"])
        self.assertIn("GOVERNANCE WARNING", err.getvalue())
        self.assertTrue(q._break_glass_unprotected_warned)
        # Second weak-mode call with a fresh ticket: still consumes the
        # ticket, but the warning and the audit fire exactly once total.
        # (Resolve the first call's post-review ticket so the second
        # call is admitted; the provisioned reviewer discharges it.)
        rev = ctx["executor"].mint_identity("rev-1", "reviewer",
                                            "duty-reviewer")
        q.resolve_review(ticket["ticket_id"], "reviewed: justified", rev)
        q2, aid2, evil2 = self._queue_bg(ctx)
        err2 = io.StringIO()
        with contextlib.redirect_stderr(err2):
            rec2, _ = q2.break_glass(aid2, "y", operator_identity=evil2,
                                     ticket_id="T-OP2")
        self.assertEqual(rec2["status"], "approved")
        self.assertEqual(err2.getvalue(), "")
        entries, _ = read_entries_with_stats(ctx["run_dir"] / "actions.jsonl")
        warned = [e for e in entries
                  if e.get("event") == "break_glass_unprotected"]
        self.assertEqual(len(warned), 1)

    def test_attack_shape_cannot_silence_warning(self):
        # The F67 attack: set the flag BEFORE the first weak-mode call.
        # Now the plain-attribute write raises, and the warning fires.
        from gov.log import read_entries_with_stats
        ctx = self._weak_ctx()
        q, aid, evil = self._queue_bg(ctx)
        with self.assertRaises(AttributeError):
            q._break_glass_unprotected_warned = True  # the old attack
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rec, _ = q.break_glass(aid, "x", operator_identity=evil,
                                   ticket_id="T-OP")
        self.assertIn("GOVERNANCE WARNING", err.getvalue())
        entries, _ = read_entries_with_stats(ctx["run_dir"] / "actions.jsonl")
        warned = [e for e in entries
                  if e.get("event") == "break_glass_unprotected"]
        self.assertEqual(len(warned), 1)
        self.assertEqual(rec["status"], "approved")  # ticket still consumes


@unittest.skipUnless(_LANGCHAIN_AVAILABLE, "langchain-core not installed")
class TestF68MediationTimeSchemaRecheck(unittest.TestCase):
    def _schema(self, name):
        from pydantic import BaseModel, ConfigDict, Field

        class _S(BaseModel):
            model_config = ConfigDict(extra="allow")
            to: str = Field(description="Recipient")
            subject: str = Field(description="Subject")
            body: str = Field(description="Body")
        _S.__name__ = name
        return _S

    def _tool(self, schema_cls):
        from gov.adapters.core import GovernedBinding
        from gov.adapters.langchain_tools import make_governed_tool
        ctx = make_run()
        ident = ctx["mint_identity"]("support-1", "support", "customer-org")
        binding = GovernedBinding(ctx["executor"], ident)
        tool = make_governed_tool(
            binding, name="send_note", description="Send a note.",
            args_schema=schema_cls, framework_tool="send_email",
            on_denied="return")
        return ctx, tool

    def test_object_setattr_schema_swap_fails_closed(self):
        from pydantic import BaseModel, Field

        class StrictSchema(BaseModel):
            to: str = Field(description="Recipient")

        _, tool = self._tool(self._schema("AllowSchema1"))
        object.__setattr__(tool, "args_schema", StrictSchema)
        with self.assertRaises(ValueError):
            tool._run(to="x@synthetic.local", subject="s", body="b")

    def test_model_config_rebuild_to_ignore_fails_closed(self):
        schema = self._schema("AllowSchema2")
        _, tool = self._tool(schema)
        schema.model_config["extra"] = "ignore"
        schema.model_rebuild(force=True)
        try:
            with self.assertRaises(ValueError):
                tool._run(to="x@synthetic.local", subject="s", body="b")
        finally:
            schema.model_config["extra"] = "allow"
            schema.model_rebuild(force=True)

    def test_extra_allow_still_functional_and_dlp_sees_extras(self):
        import json
        _, tool = self._tool(self._schema("AllowSchema3"))
        out = tool.invoke({
            "to": "x@synthetic.local", "subject": "s", "body": "routine",
            "bcc": "AKIAIOSFODNN7EXAMPLE"})
        payload = json.loads(out)
        self.assertEqual(payload["status"], "denied")
        self.assertEqual(payload["policy_id"], "dlp-credential-block")

    def test_async_arun_path_also_rechecked(self):
        import asyncio
        from pydantic import BaseModel, Field

        class StrictSchema(BaseModel):
            to: str = Field(description="Recipient")

        _, tool = self._tool(self._schema("AllowSchema4"))
        object.__setattr__(tool, "args_schema", StrictSchema)
        with self.assertRaises(ValueError):
            asyncio.run(tool._arun(to="x@synthetic.local", subject="s",
                                   body="b"))


class TestF60FollowupChainVerifiedSuppression(unittest.TestCase):
    FLAG = "queue_lock_invalid"

    def _run_dir(self):
        run_dir = Path(tempfile.mkdtemp(prefix="r15t60-"))
        self.addCleanup(lambda: shutil.rmtree(run_dir, ignore_errors=True))
        (run_dir / "approvals.lock").mkdir()
        return run_dir

    def _executor(self, run_dir):
        from evals.w15_probes import _fresh_executor
        from gov.policy import PolicyEngine
        policy = PolicyEngine(
            str(Path(__file__).resolve().parent.parent
                / "policies" / "default.yaml"))
        return _fresh_executor(run_dir, policy)

    def _sweep(self, run_dir):
        done = self._executor(run_dir).execute_approved()
        self.assertEqual(done, [])  # every sweep refuses fail-closed
        return done

    def _refusals(self, run_dir):
        from gov.log import read_entries
        return [e for e in read_entries(run_dir / "actions.jsonl")
                if e.get("event") == "approval_sweep_refused"
                and e.get("flag") == self.FLAG]

    def test_genuine_verified_entry_suppresses(self):
        # Control: a real, chain-verified refusal entry + corrupt state
        # still suppresses the re-audit (F60 behavior preserved).
        run_dir = self._run_dir()
        self._sweep(run_dir)  # first sweep audits once, genuinely
        self.assertEqual(len(self._refusals(run_dir)), 1)
        (run_dir / "lock_refusal_coalesce.json").write_text(
            '{"broken": true', encoding="utf-8")
        ex = self._executor(run_dir)
        self.assertTrue(ex._log_shows_recent_lock_refusal(self.FLAG))
        self._sweep(run_dir)  # suppressed: still exactly one entry
        self.assertEqual(len(self._refusals(run_dir)), 1)

    def test_planted_mac_invalid_line_does_not_suppress(self):
        # The R14 residual, now closed: a MAC-invalid planted line for
        # the same flag + corrupt state must NOT suppress — the sweep
        # re-audits LOUDLY.
        import json as _json
        from datetime import datetime, timezone
        run_dir = self._run_dir()
        planted = {"event": "approval_sweep_refused", "flag": self.FLAG,
                   "ts": datetime.now(timezone.utc).isoformat(),
                   "seq": 1, "hash": "0" * 64, "prev_hash": "0" * 64}
        (run_dir / "actions.jsonl").write_text(
            _json.dumps(planted) + "\n", encoding="utf-8")
        (run_dir / "lock_refusal_coalesce.json").write_text(
            '{"broken": true', encoding="utf-8")
        ex = self._executor(run_dir)
        self.assertFalse(ex._log_shows_recent_lock_refusal(self.FLAG))
        self.assertTrue(ex._audit_lock_refusal(self.FLAG, "test"))
        genuine = [e for e in self._refusals(run_dir)
                   if e.get("hash") != "0" * 64]
        self.assertEqual(len(genuine), 1)

    def test_broken_chain_falls_back_to_loud_reaudit(self):
        # Tamper with a genuine entry's content (breaks its MAC): the
        # chain no longer verifies, so suppression must not engage.
        run_dir = self._run_dir()
        self._sweep(run_dir)
        self.assertEqual(len(self._refusals(run_dir)), 1)
        p = run_dir / "actions.jsonl"
        lines = p.read_text(encoding="utf-8").splitlines()
        # Tamper the refusal entry (line 2) without touching its flag:
        # any content change breaks its chain MAC.
        self.assertIn('"suppressed_repeats": 0', lines[2])
        lines[2] = lines[2].replace('"suppressed_repeats": 0',
                                    '"suppressed_repeats": 7', 1)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        (run_dir / "lock_refusal_coalesce.json").write_text(
            '{"broken": true', encoding="utf-8")
        ex = self._executor(run_dir)
        self.assertFalse(ex._log_shows_recent_lock_refusal(self.FLAG))
        self._sweep(run_dir)  # loud re-audit: a second genuine entry
        self.assertEqual(len(self._refusals(run_dir)), 2)

    def test_planted_line_never_suppresses_across_sweeps(self):
        # End-to-end: re-plant + re-corrupt before every sweep; every
        # sweep must audit (the planted line never quiets the re-audit).
        import json as _json
        from datetime import datetime, timezone
        run_dir = self._run_dir()
        for _ in range(3):
            planted = {"event": "approval_sweep_refused",
                       "flag": self.FLAG,
                       "ts": datetime.now(timezone.utc).isoformat(),
                       "seq": 999, "hash": "0" * 64}
            with open(run_dir / "actions.jsonl", "a",
                       encoding="utf-8") as f:
                f.write(_json.dumps(planted) + "\n")
            (run_dir / "lock_refusal_coalesce.json").write_text(
                '{"broken": true', encoding="utf-8")
            self._sweep(run_dir)
        genuine = [e for e in self._refusals(run_dir)
                   if e.get("hash") != "0" * 64]
        self.assertEqual(len(genuine), 3)
