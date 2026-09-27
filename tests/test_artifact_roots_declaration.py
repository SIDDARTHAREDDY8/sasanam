#!/usr/bin/env python3
"""Unit tests for the wave-143 watch-root declaration ceremony
(gov/artifact_sweep.py: declare_watch_roots / verify_roots_declaration
/ check_roots_declaration / verify_declaration_chained /
declaration_digest) and the executor wiring.

Seams: the declaration ceremony record/verify (fail-closed, never
raises on malformed input), out-of-band change detection (LOUD
artifact_sweep_roots_undeclared_change + unverified verdict), the
auditor chain-confirmation path, and the executor's
artifact_sweep_complete roots_verdict/roots_verified stamping.
"""

import json
import os
import secrets
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "rootsdecl-unittest")

from gov import artifact_sweep as sweep  # noqa: E402
from gov import keyprovider as keyprovider  # noqa: E402
from gov.artifacts import ArtifactInventory  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402

TEST_KEY = b"wave143-roots-decl-unit-test-key!"

DEFAULT_POLICY = Path(REPO_ROOT) / "policies" / "default.yaml"
PRINCIPAL = "user-1"

_UNGOVERNED_ACK = ("roots-declaration unittest: synthetic harness; raw "
                   "pre-wave-74/75 pipeline by design, declared and "
                   "chained")


def _declare(roots, **kw):
    kw.setdefault("hmac_key", TEST_KEY)
    return sweep.declare_watch_roots(roots, **kw)


def _verify(envelope, **kw):
    kw.setdefault("hmac_key", TEST_KEY)
    return sweep.verify_roots_declaration(envelope, **kw)


def _check(configured, declaration, **kw):
    kw.setdefault("hmac_key", TEST_KEY)
    return sweep.check_roots_declaration(configured, declaration, **kw)


def _mk_tmp():
    return Path(tempfile.mkdtemp(prefix="rootsdecl-ut-"))


class TestDeclareCeremony(unittest.TestCase):
    def test_declare_round_trip_verifies(self):
        env = _declare(["/tmp/rd-a", "/tmp/rd-b"], operator_id="ops-1",
                       reason="initial")
        ok, reason = _verify(env)
        self.assertTrue(ok, reason)
        self.assertEqual(env["roots_declaration"],
                         sweep.ROOTS_DECLARATION_VERSION)
        self.assertEqual(env["roots"], [os.path.realpath("/tmp/rd-a"),
                                        os.path.realpath("/tmp/rd-b")])
        self.assertEqual(env["operator_id"], "ops-1")
        self.assertEqual(env["reason"], "initial")
        self.assertEqual(env["previous_roots"], [])
        self.assertEqual(env["previous_digest"], "")
        self.assertTrue(env["declaration"])

    def test_declare_records_explicit_override_epoch(self):
        env = _declare(["/tmp/rd-a"], operator_id="ops-1")
        self.assertEqual(env["key_epoch"], sweep.EXPLICIT_KEY_EPOCH)

    def test_declare_resolves_and_dedupes(self):
        env = _declare(["/tmp/../tmp/rd-a", "/tmp/rd-a"],
                       operator_id="ops-1")
        self.assertEqual(env["roots"],
                         [os.path.realpath("/tmp/rd-a")])

    def test_declare_rejects_anonymous(self):
        for bad in ("", "   ", None, 42):
            with self.assertRaises(ValueError):
                _declare(["/tmp/rd-a"], operator_id=bad)

    def test_declare_rejects_non_path(self):
        with self.assertRaises(ValueError):
            _declare(["/tmp/rd-a", 42], operator_id="ops-1")

    def test_declare_chains_previous(self):
        old = _declare(["/tmp/rd-a", "/tmp/rd-b"], operator_id="ops-1",
                       reason="v1")
        new = _declare(["/tmp/rd-a"], previous=old, operator_id="ops-1",
                       reason="v2 drops b")
        self.assertEqual(new["previous_roots"],
                         [os.path.realpath("/tmp/rd-a"),
                          os.path.realpath("/tmp/rd-b")])
        self.assertEqual(new["previous_digest"],
                         sweep.declaration_digest(old))
        ok, reason = _verify(new)
        self.assertTrue(ok, reason)

    def test_declare_rejects_malformed_previous(self):
        with self.assertRaises(ValueError):
            _declare(["/tmp/rd-a"], previous={"nope": True},
                      operator_id="ops-1")

    def test_ceremony_event_carries_old_new_operator_reason(self):
        events = []
        old = _declare(["/tmp/rd-a", "/tmp/rd-b"], operator_id="ops-1",
                       reason="v1", audit=events.append)
        events.clear()
        new = _declare(["/tmp/rd-a"], previous=old, operator_id="ops-2",
                       reason="retire b", audit=events.append,
                       run_id="cer-ut")
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event"], sweep.ROOTS_DECLARED_EVENT)
        self.assertEqual(ev["run_id"], "cer-ut")
        self.assertEqual(ev["operator_id"], "ops-2")
        self.assertEqual(ev["reason"], "retire b")
        self.assertEqual(ev["old_roots"],
                         [os.path.realpath("/tmp/rd-a"),
                          os.path.realpath("/tmp/rd-b")])
        self.assertEqual(ev["new_roots"],
                         [os.path.realpath("/tmp/rd-a")])
        self.assertEqual(ev["added"], [])
        self.assertEqual(ev["removed"], [os.path.realpath("/tmp/rd-b")])
        # The ceremony event's digest is the public recomputable
        # commitment to the returned envelope.
        self.assertEqual(ev["declaration_digest"],
                         sweep.declaration_digest(new))
        self.assertTrue(ev["ts"])

    def test_declaration_digest_recomputable(self):
        env = _declare(["/tmp/rd-a"], operator_id="ops-1",
                       reason="r")
        body = sweep._roots_decl_body(
            env["roots_declaration"], env["roots"],
            env["previous_roots"], env["previous_digest"],
            env["operator_id"], env["reason"], env["declared_at"],
            env["key_epoch"])
        self.assertEqual(sweep._roots_decl_mac(TEST_KEY, body),
                         env["declaration"])
        self.assertEqual(sweep.declaration_digest(env),
                         sweep._roots_decl_body_digest(body))

    def test_declaration_digest_rejects_malformed(self):
        with self.assertRaises(ValueError):
            sweep.declaration_digest({"roots_declaration": "bogus"})

    def test_declare_requires_key(self):
        # Unprovisioned deployment: no GOV_LOG_KEY/GOV_KEYRING_FILE ->
        # the ceremony fails closed at ceremony time.
        saved = dict(os.environ)
        os.environ.pop("GOV_LOG_KEY", None)
        os.environ.pop("GOV_KEYRING_FILE", None)
        try:
            with self.assertRaises(keyprovider.NoKeyConfiguredError):
                sweep.declare_watch_roots(["/tmp/rd-a"],
                                          operator_id="ops-1")
        finally:
            os.environ.clear()
            os.environ.update(saved)


class TestVerifyFailClosed(unittest.TestCase):
    def test_tampered_roots_fail(self):
        env = _declare(["/tmp/rd-a"], operator_id="ops-1")
        env2 = dict(env, roots=[os.path.realpath("/tmp/evil")])
        ok, reason = _verify(env2)
        self.assertFalse(ok)
        self.assertIn("mismatch", reason)

    def test_tampered_operator_fails(self):
        env = _declare(["/tmp/rd-a"], operator_id="ops-1")
        env2 = dict(env, operator_id="mallory")
        ok, _ = _verify(env2)
        self.assertFalse(ok)

    def test_wrong_key_fails(self):
        env = _declare(["/tmp/rd-a"], operator_id="ops-1")
        ok, _ = sweep.verify_roots_declaration(
            env, hmac_key=b"a-different-32-byte-key-!!!!!!!!")
        self.assertFalse(ok)

    def test_stale_epoch_fails(self):
        env = _declare(["/tmp/rd-a"], operator_id="ops-1")
        ok, reason = sweep.verify_roots_declaration(
            env, hmac_key=TEST_KEY, current_epoch="rotated-epoch")
        self.assertFalse(ok)
        self.assertIn("stale_declaration_epoch", reason)

    def test_missing_epoch_fails_closed(self):
        env = _declare(["/tmp/rd-a"], operator_id="ops-1")
        env2 = dict(env)
        del env2["key_epoch"]
        ok, reason = _verify(env2)
        self.assertFalse(ok)
        self.assertIn("key_epoch", reason)

    def test_malformed_never_raises(self):
        for bad in (None, [], "x", {},
                    {"roots_declaration": "bogus"},
                    {"roots_declaration":
                     sweep.ROOTS_DECLARATION_VERSION}):
            ok, reason = sweep.verify_roots_declaration(
                bad, hmac_key=TEST_KEY)
            self.assertFalse(ok, bad)
            self.assertTrue(reason, bad)

    def test_key_unavailable_fails_closed(self):
        env = _declare(["/tmp/rd-a"], operator_id="ops-1")
        ok, reason = sweep.verify_roots_declaration(
            env, hmac_key=b"")
        self.assertFalse(ok)
        self.assertIn("key unavailable", reason)


class TestCheckRootsDeclaration(unittest.TestCase):
    def setUp(self):
        self.tmp = _mk_tmp()
        self.addCleanup(__import__("shutil").rmtree, self.tmp,
                        True)
        self.a = self.tmp / "a"
        self.b = self.tmp / "b"
        self.a.mkdir()
        self.b.mkdir()

    def test_same_set_declared_quiet(self):
        events = []
        env = _declare([str(self.a), str(self.b)], operator_id="ops-1")
        rep = _check([(str(self.a), None), (str(self.b), None)], env,
                     audit=events.append)
        self.assertEqual(rep["verdict"], "declared")
        self.assertEqual(events, [])
        self.assertEqual(rep["added"], [])
        self.assertEqual(rep["removed"], [])

    def test_plain_paths_accepted(self):
        env = _declare([str(self.a)], operator_id="ops-1")
        rep = _check([str(self.a)], env)
        self.assertEqual(rep["verdict"], "declared")

    def test_removed_root_loud_undeclared_change(self):
        events = []
        env = _declare([str(self.a), str(self.b)], operator_id="ops-1")
        rep = _check([str(self.a)], env, audit=events.append,
                     run_id="chk-ut")
        self.assertEqual(rep["verdict"], "undeclared_change")
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event"],
                         sweep.ROOTS_UNDECLARED_CHANGE_EVENT)
        self.assertEqual(ev["severity"], "LOUD")
        self.assertEqual(ev["run_id"], "chk-ut")
        self.assertIn(os.path.realpath(str(self.b)), ev["removed"])
        self.assertEqual(ev["added"], [])

    def test_added_root_loud_undeclared_change(self):
        events = []
        env = _declare([str(self.a)], operator_id="ops-1")
        rep = _check([str(self.a), str(self.b)], env,
                     audit=events.append)
        self.assertEqual(rep["verdict"], "undeclared_change")
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["severity"], "LOUD")
        self.assertIn(os.path.realpath(str(self.b)), ev["added"])

    def test_no_declaration_is_explicit_downgrade(self):
        events = []
        rep = _check([str(self.a)], None, audit=events.append)
        self.assertEqual(rep["verdict"], "undeclared")
        self.assertEqual(events, [])

    def test_forged_envelope_loud_unverifiable(self):
        events = []
        env = _declare([str(self.a)], operator_id="ops-1")
        forged = dict(env, roots=[os.path.realpath(str(self.b))])
        rep = _check([str(self.b)], forged, audit=events.append)
        self.assertEqual(rep["verdict"], "unverifiable")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["severity"], "LOUD")
        self.assertEqual(events[0]["event"],
                         sweep.ROOTS_UNDECLARED_CHANGE_EVENT)

    def test_stale_epoch_loud_unverifiable(self):
        events = []
        env = _declare([str(self.a)], operator_id="ops-1")
        rep = sweep.check_roots_declaration(
            [str(self.a)], env, audit=events.append,
            hmac_key=TEST_KEY, current_epoch="rotated")
        self.assertEqual(rep["verdict"], "unverifiable")
        self.assertEqual(events[0]["severity"], "LOUD")
        self.assertIn("stale_declaration_epoch", events[0]["reason"])

    def test_malformed_configured_root_raises(self):
        env = _declare([str(self.a)], operator_id="ops-1")
        with self.assertRaises(ValueError):
            _check([str(self.a), 42], env)


class TestVerifyDeclarationChained(unittest.TestCase):
    def setUp(self):
        self.tmp = _mk_tmp()
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.log_path = self.tmp / "actions.jsonl"
        self.log = ActionLog(str(self.log_path))
        self.a = self.tmp / "a"
        self.a.mkdir()

    def test_chained_ceremony_confirms(self):
        env = _declare([str(self.a)], operator_id="ops-1",
                       audit=self.log.append, run_id="vc-ut")
        ok, reason = sweep.verify_declaration_chained(
            str(self.log_path), env)
        self.assertTrue(ok, reason)

    def test_missing_ceremony_fails_loud(self):
        env = _declare([str(self.a)], operator_id="ops-1")
        ok, reason = sweep.verify_declaration_chained(
            str(self.log_path), env)
        self.assertFalse(ok)
        self.assertIn("LOUD", reason)

    def test_tampered_ceremony_fails_loud(self):
        env = _declare([str(self.a)], operator_id="ops-1",
                       reason="pristine", audit=self.log.append)
        ok, _ = sweep.verify_declaration_chained(str(self.log_path),
                                                 env)
        self.assertTrue(ok)
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        idx = [i for i, ln in enumerate(lines)
               if sweep.ROOTS_DECLARED_EVENT in ln]
        self.assertEqual(len(idx), 1)
        lines[idx[0]] = lines[idx[0]].replace("pristine", "tampered")
        self.log_path.write_text("\n".join(lines) + "\n",
                                 encoding="utf-8")
        ok2, reason2 = sweep.verify_declaration_chained(
            str(self.log_path), env)
        self.assertFalse(ok2)
        self.assertIn("LOUD", reason2)

    def test_malformed_envelope_fails_loud(self):
        ok, reason = sweep.verify_declaration_chained(
            str(self.log_path), {"nope": True})
        self.assertFalse(ok)
        self.assertIn("LOUD", reason)


class TestExecutorWiring(unittest.TestCase):
    def setUp(self):
        self.run_dir = Path(tempfile.mkdtemp(prefix="rootsdecl-ex-"))
        (self.run_dir / "sandbox").mkdir(parents=True, exist_ok=True)
        self.addCleanup(__import__("shutil").rmtree, self.run_dir,
                        True)
        self.a = Path(tempfile.mkdtemp(prefix="rootsdecl-exa-"))
        self.b = Path(tempfile.mkdtemp(prefix="rootsdecl-exb-"))
        self.addCleanup(__import__("shutil").rmtree, self.a, True)
        self.addCleanup(__import__("shutil").rmtree, self.b, True)

    def _executor(self, **kw):
        policy = PolicyEngine(str(DEFAULT_POLICY))
        log = ActionLog(str(self.run_dir / "actions.jsonl"))
        approvals = ApprovalQueue(self.run_dir, log)
        return ToolExecutor(
            self.run_dir, policy, log, approvals,
            ledger_path=str(self.run_dir / "egress_ledger.jsonl"),
            ungoverned_ack=_UNGOVERNED_ACK, **kw)

    def _events(self, name):
        return [e for e in read_entries(self.run_dir / "actions.jsonl")
                if isinstance(e, dict) and e.get("event") == name]

    def _baseline(self, root):
        inv = ArtifactInventory()
        sweep.register_watch_root(str(root), inv)
        return inv

    def test_narrowed_roots_loud_and_unverified(self):
        ex = self._executor()
        env = sweep.declare_watch_roots(
            [str(self.a), str(self.b)], operator_id="ops-1",
            reason="initial", audit=ex.log.append, run_id="ex1")
        # Out-of-band narrowing: config edited directly, B dropped.
        ex.artifact_sweep = {
            "roots_declaration": env,
            "watch_roots": [(str(self.a), self._baseline(self.a))],
        }
        ex.run_artifact_sweep()
        loud = self._events(sweep.ROOTS_UNDECLARED_CHANGE_EVENT)
        self.assertEqual(len(loud), 1)
        self.assertEqual(loud[0]["severity"], "LOUD")
        self.assertIn(os.path.realpath(str(self.b)),
                      loud[0]["removed"])
        comp = self._events(sweep.SWEEP_COMPLETE_EVENT)
        self.assertEqual(len(comp), 1)
        self.assertEqual(comp[0]["roots_verdict"],
                         "undeclared_change")
        self.assertFalse(comp[0]["roots_verified"])

    def test_ceremony_change_quiet_and_declared(self):
        ex = self._executor()
        old = sweep.declare_watch_roots(
            [str(self.a), str(self.b)], operator_id="ops-1",
            reason="initial", audit=ex.log.append)
        new = sweep.declare_watch_roots(
            [str(self.a)], previous=old, operator_id="ops-1",
            reason="retire b", audit=ex.log.append)
        ex.artifact_sweep = {
            "roots_declaration": new,
            "watch_roots": [(str(self.a), self._baseline(self.a))],
        }
        ex.run_artifact_sweep()
        self.assertEqual(
            self._events(sweep.ROOTS_UNDECLARED_CHANGE_EVENT), [])
        comp = self._events(sweep.SWEEP_COMPLETE_EVENT)
        self.assertEqual(len(comp), 1)
        self.assertEqual(comp[0]["roots_verdict"], "declared")
        self.assertTrue(comp[0]["roots_verified"])

    def test_no_declaration_is_explicit_downgrade(self):
        ex = self._executor(artifact_sweep={
            "watch_roots": [(str(self.a), self._baseline(self.a))]})
        ex.run_artifact_sweep()
        self.assertEqual(
            self._events(sweep.ROOTS_UNDECLARED_CHANGE_EVENT), [])
        comp = self._events(sweep.SWEEP_COMPLETE_EVENT)
        self.assertEqual(len(comp), 1)
        self.assertEqual(comp[0]["roots_verdict"], "undeclared")
        self.assertFalse(comp[0]["roots_verified"])

    def test_forged_envelope_fails_closed(self):
        ex = self._executor()
        env = sweep.declare_watch_roots(
            [str(self.a)], operator_id="ops-1", audit=ex.log.append)
        forged = dict(env, roots=[os.path.realpath(str(self.b))])
        ex.artifact_sweep = {
            "roots_declaration": forged,
            "watch_roots": [(str(self.b), self._baseline(self.b))],
        }
        ex.run_artifact_sweep()
        loud = self._events(sweep.ROOTS_UNDECLARED_CHANGE_EVENT)
        self.assertEqual(len(loud), 1)
        self.assertEqual(loud[0]["severity"], "LOUD")
        comp = self._events(sweep.SWEEP_COMPLETE_EVENT)
        self.assertEqual(comp[0]["roots_verdict"], "unverifiable")
        self.assertFalse(comp[0]["roots_verified"])


if __name__ == "__main__":
    unittest.main()
