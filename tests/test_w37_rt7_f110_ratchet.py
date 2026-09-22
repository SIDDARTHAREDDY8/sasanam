"""RT7 ratchet of the F110 closure (wave-37): the deployer-injected
AEAD seam, allow_plaintext opt-in abuse, and audit-ordering races
under concurrency.

FAIL-FIRST: the hardening tests (demo-cipher env gate,
contradictory-posture refusal) were written against behavior that did
not exist yet; the ratchet pins (never-inject loudness, plaintext
auditability, write-ahead under threads) were written expecting the
existing guarantees to hold. Implementation: gov/platform_egress.py.
"""

import inspect
import os
import sys
import threading
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # noqa: E402
from gov.log import verify_chain  # noqa: E402
from gov.platform_egress import (  # noqa: E402
    EVENT_AUTHORIZED,
    PlatformEgressError,
    WorkspaceCollector,
    _DEMO_CIPHER_ENV,
    demonstration_cipher,
    issue_consent,
)

_CONSENT_KEY = b"test-consent-key-32-bytes-synth"
_ARCHIVE_KEY = b"test-archive-key-32-bytes-synth!!"


class _Sink:
    def __init__(self, host):
        self.host = host
        self.uploads = []

    def put(self, name, payload):
        self.uploads.append({"name": name, "payload": payload})


class _FailingSink(_Sink):
    def put(self, name, payload):
        raise IOError("synthetic network failure")


class _RefusingLog:
    """Log whose authorized-event append raises: write-ahead must then
    fail closed with no side effect."""

    def __init__(self, log):
        self._log = log

    def append(self, entry):
        if entry.get("event") == EVENT_AUTHORIZED:
            raise IOError("synthetic log failure")
        return self._log.append(entry)


def _workspace(tmp, tag="ws"):
    ws = Path(tmp) / tag
    (ws / "src").mkdir(parents=True)
    (ws / "src" / "app.py").write_text("print('hello')\n")
    (ws / "notes.md").write_text("synthetic workspace\n")
    return ws


def _ctx():
    return make_run()


def _collector(ctx, log=None, **kw):
    kw.setdefault("egress_allowlist", {"idx.example.com"})
    kw.setdefault("consent_key", _CONSENT_KEY)
    return WorkspaceCollector(log if log is not None else ctx["log"],
                              ctx["policy"], **kw)


def _token(ctx, **kw):
    kw.setdefault("granted_by", "operator-1")
    return issue_consent(ctx["log"], _CONSENT_KEY, **kw)


class _EnvVar:
    """Save/set/restore one env var (determinism hygiene)."""

    def __init__(self, name, value):
        self.name = name
        self.value = value
        self.saved = None
        self.had = False

    def __enter__(self):
        self.had = self.name in os.environ
        self.saved = os.environ.get(self.name)
        if self.value is None:
            os.environ.pop(self.name, None)
        else:
            os.environ[self.name] = self.value
        return self

    def __exit__(self, *exc):
        if self.had:
            os.environ[self.name] = self.saved
        else:
            os.environ.pop(self.name, None)
        return False


class TestDeployerAEADSeam(unittest.TestCase):
    """What if the deployer never injects an AEAD -- is fail-closed
    loud enough?"""

    def test_never_inject_cipher_is_loud(self):
        ctx = _ctx()
        collector = _collector(ctx)
        sink = _Sink("idx.example.com")
        before = len(ctx["read_log"]())
        with self.assertRaises(PlatformEgressError) as cm:
            collector.collect(
                _workspace(ctx["run_dir"]), consent=_token(ctx),
                destination="idx.example.com", sink=sink,
                archive_key=_ARCHIVE_KEY, cipher=None)
        msg = str(cm.exception)
        # Loud = names the missing deployer action AND the remediation.
        self.assertIn("archive_cipher_required", msg)
        self.assertIn("cipher=", msg)
        # Audited denial (fail-closed and visible), no bytes moved.
        denied = [e for e in ctx["read_log"]()[before:]
                  if e.get("event") == "platform_egress_denied"]
        self.assertTrue(denied, "cipher refusal must be audit-logged")
        self.assertIn("archive_cipher_required", denied[0]["reason"])
        self.assertEqual(sink.uploads, [])

    def test_demo_cipher_without_env_is_refused_and_audited(self):
        # The copy-paste accident: deployer passes the TEST-ONLY cipher
        # in a deployment without GOV_DEMO_CIPHER_OK=1 -> loud,
        # audit-logged refusal (early _deny), not silent weak crypto.
        ctx = _ctx()
        collector = _collector(ctx)
        sink = _Sink("idx.example.com")
        before = len(ctx["read_log"]())
        with _EnvVar(_DEMO_CIPHER_ENV, None):
            with self.assertRaises(PlatformEgressError) as cm:
                collector.collect(
                    _workspace(ctx["run_dir"]), consent=_token(ctx),
                    destination="idx.example.com", sink=sink,
                    archive_key=_ARCHIVE_KEY,
                    cipher=demonstration_cipher)
        self.assertIn("demo_cipher_not_enabled", str(cm.exception))
        denied = [e for e in ctx["read_log"]()[before:]
                  if e.get("event") == "platform_egress_denied"]
        self.assertTrue(denied)
        self.assertIn("demo_cipher_not_enabled", denied[0]["reason"])
        self.assertEqual(sink.uploads, [])

    def test_demo_cipher_direct_call_gated(self):
        # Defense in depth: the in-function gate fires even for
        # aliased/wrapped passes that skip collect()'s identity check.
        key, nonce, data = _ARCHIVE_KEY, b"0" * 16, b"hello"
        with _EnvVar(_DEMO_CIPHER_ENV, None):
            with self.assertRaises(PlatformEgressError) as cm:
                demonstration_cipher(key, nonce, data)
            self.assertIn("TEST-ONLY", str(cm.exception))
        with _EnvVar(_DEMO_CIPHER_ENV, "1"):
            ct = demonstration_cipher(key, nonce, data)
            self.assertEqual(demonstration_cipher(key, nonce, ct), data)

    def test_demo_cipher_with_env_still_works_end_to_end(self):
        ctx = _ctx()
        collector = _collector(ctx)
        sink = _Sink("idx.example.com")
        with _EnvVar(_DEMO_CIPHER_ENV, "1"):
            result = collector.collect(
                _workspace(ctx["run_dir"]), consent=_token(ctx),
                destination="idx.example.com", sink=sink,
                archive_key=_ARCHIVE_KEY, cipher=demonstration_cipher)
        self.assertTrue(result["encrypted"])
        self.assertEqual(len(sink.uploads), 1)

    def test_contradictory_posture_refused(self):
        # archive_key AND allow_plaintext=True: the old code encrypted
        # and silently ignored the explicit flag. Confused callers now
        # fail closed instead of having a security-relevant flag
        # silently dropped.
        ctx = _ctx()
        collector = _collector(ctx)
        sink = _Sink("idx.example.com")
        before = len(ctx["read_log"]())
        with self.assertRaises(PlatformEgressError) as cm:
            collector.collect(
                _workspace(ctx["run_dir"]), consent=_token(ctx),
                destination="idx.example.com", sink=sink,
                archive_key=_ARCHIVE_KEY, allow_plaintext=True,
                cipher=demonstration_cipher)
        self.assertIn("contradictory_confidentiality_posture",
                      str(cm.exception))
        denied = [e for e in ctx["read_log"]()[before:]
                  if e.get("event") == "platform_egress_denied"]
        self.assertTrue(denied)
        self.assertEqual(sink.uploads, [])


class TestAllowPlaintextOptIn(unittest.TestCase):
    """allow_plaintext abuse surface: who can set it, is it visible?"""

    def test_default_is_opt_in_not_opt_out(self):
        sig = inspect.signature(WorkspaceCollector.collect)
        self.assertIs(sig.parameters["allow_plaintext"].default, False)

    def test_no_ambient_config_enables_plaintext(self):
        # The flag is a per-call explicit argument: no env var, no
        # config file, no module global can smuggle it in. The only
        # os.environ read in the module is the demo-cipher gate.
        import gov.platform_egress as pe
        src = inspect.getsource(pe)
        self.assertNotIn("ALLOW_PLAINTEXT", src)
        self.assertEqual(src.count("os.environ"), 1)

    def test_plaintext_upload_is_audit_visible(self):
        ctx = _ctx()
        collector = _collector(ctx)
        sink = _Sink("idx.example.com")
        result = collector.collect(
            _workspace(ctx["run_dir"]), consent=_token(ctx),
            destination="idx.example.com", sink=sink,
            allow_plaintext=True)
        self.assertTrue(result["plaintext_explicit"])
        self.assertFalse(result["encrypted"])
        entries = ctx["read_log"]()
        for event in ("platform_egress_authorized",
                      "platform_egress_upload"):
            matches = [e for e in entries if e.get("event") == event]
            self.assertTrue(matches, event)
            self.assertTrue(matches[-1]["plaintext_explicit"],
                            "%s must record the opt-in" % event)
            self.assertFalse(matches[-1]["encrypted"])

    def test_encrypted_upload_marks_plaintext_false(self):
        ctx = _ctx()
        collector = _collector(ctx)
        sink = _Sink("idx.example.com")
        with _EnvVar(_DEMO_CIPHER_ENV, "1"):
            collector.collect(
                _workspace(ctx["run_dir"]), consent=_token(ctx),
                destination="idx.example.com", sink=sink,
                archive_key=_ARCHIVE_KEY, cipher=demonstration_cipher)
        auth = [e for e in ctx["read_log"]()
                if e.get("event") == "platform_egress_authorized"][-1]
        self.assertFalse(auth["plaintext_explicit"])
        self.assertTrue(auth["encrypted"])


class TestAuditOrderingUnderConcurrency(unittest.TestCase):
    """Write-ahead audit under threads: no upload without a preceding
    authorized entry, chain stays verifiable."""

    def _thread_collect(self, ctx, collector, ws, dest, sink,
                        results, i):
        try:
            token = issue_consent(ctx["log"], _CONSENT_KEY,
                                  granted_by="operator-%d" % i)
            out = collector.collect(
                ws, consent=token, destination=dest, sink=sink,
                allow_plaintext=True)
            results[i] = ("ok", out["archive_sha256"])
        except Exception as exc:  # noqa: BLE001 - record, don't die
            results[i] = ("error", "%s: %s" % (type(exc).__name__, exc))

    def _per_thread_workspaces(self, ctx, n):
        # Distinct bytes per thread -> distinct archive digests, so
        # each upload entry correlates 1:1 with its own authorized
        # entry (identical workspaces would share a digest and the
        # correlation below could not pair them).
        out = []
        for i in range(n):
            ws = _workspace(ctx["run_dir"], tag="ws-%d" % i)
            (ws / "notes.md").write_text(
                "synthetic workspace %d\n" % i)
            out.append(ws)
        return out

    def test_concurrent_collects_keep_write_ahead_ordering(self):
        ctx = _ctx()
        allow = {"host-%d.example.com" % i for i in range(8)}
        collector = WorkspaceCollector(
            ctx["log"], ctx["policy"], egress_allowlist=allow,
            consent_key=_CONSENT_KEY)
        workspaces = self._per_thread_workspaces(ctx, 8)
        sinks = [_Sink("host-%d.example.com" % i) for i in range(8)]
        results = {}
        threads = [
            threading.Thread(target=self._thread_collect,
                             args=(ctx, collector, workspaces[i],
                                   "host-%d.example.com" % i, sinks[i],
                                   results, i))
            for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        self.assertFalse(any(t.is_alive() for t in threads),
                         "threads must terminate")
        self.assertTrue(all(v[0] == "ok" for v in results.values()),
                        results)
        entries = ctx["read_log"]()
        authorized = {}
        for e in entries:
            if e.get("event") == "platform_egress_authorized":
                authorized[e["archive_sha256"]] = e["seq"]
        uploads = [e for e in entries
                   if e.get("event") == "platform_egress_upload"]
        self.assertEqual(len(uploads), 8)
        for u in uploads:
            # Every upload has a PRECEDING authorized entry for the
            # same archive digest: no unaudited exfiltration, even
            # with 8 writers racing.
            self.assertIn(u["archive_sha256"], authorized,
                          "upload without authorized entry")
            self.assertLess(authorized[u["archive_sha256"]], u["seq"],
                            "authorized entry must precede the upload")

    def test_concurrent_chain_still_verifies(self):
        ctx = _ctx()
        allow = {"host-%d.example.com" % i for i in range(6)}
        collector = WorkspaceCollector(
            ctx["log"], ctx["policy"], egress_allowlist=allow,
            consent_key=_CONSENT_KEY)
        workspaces = self._per_thread_workspaces(ctx, 6)
        sinks = [_Sink("host-%d.example.com" % i) for i in range(6)]
        results = {}
        threads = [
            threading.Thread(target=self._thread_collect,
                             args=(ctx, collector, workspaces[i],
                                   "host-%d.example.com" % i, sinks[i],
                                   results, i))
            for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        # The HMAC chain must not fork under concurrent writers
        # (F25 flock); verify_chain is the arbiter.
        ok, broken_seq, _n = verify_chain(ctx["log"].path)
        self.assertTrue(ok, "chain broken at seq %r" % (broken_seq,))

    def test_failing_sink_threads_record_failed_uploads(self):
        ctx = _ctx()
        allow = {"host-%d.example.com" % i for i in range(4)}
        collector = WorkspaceCollector(
            ctx["log"], ctx["policy"], egress_allowlist=allow,
            consent_key=_CONSENT_KEY)
        workspaces = self._per_thread_workspaces(ctx, 4)
        sinks = [_FailingSink("host-%d.example.com" % i)
                 if i % 2 else _Sink("host-%d.example.com" % i)
                 for i in range(4)]
        results = {}
        threads = [
            threading.Thread(target=self._thread_collect,
                             args=(ctx, collector, workspaces[i],
                                   "host-%d.example.com" % i, sinks[i],
                                   results, i))
            for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        entries = ctx["read_log"]()
        failed = [e for e in entries
                  if e.get("event") == "platform_egress_upload_failed"]
        uploads = [e for e in entries
                   if e.get("event") == "platform_egress_upload"]
        # 2 failing sinks -> 2 failed entries, 2 successful uploads;
        # every failure still has its write-ahead authorized entry.
        self.assertEqual(len(failed), 2)
        self.assertEqual(len(uploads), 2)
        auth_digests = {e["archive_sha256"] for e in entries
                        if e.get("event") == "platform_egress_authorized"}
        for f in failed:
            self.assertIn(f["archive_sha256"], auth_digests)

    def test_authorized_append_failure_means_no_upload(self):
        # Write-ahead fail-closed: if the authorized entry cannot
        # land, the upload must never be attempted.
        ctx = _ctx()
        collector = _collector(ctx, log=_RefusingLog(ctx["log"]))
        sink = _Sink("idx.example.com")
        with self.assertRaises(Exception):
            collector.collect(
                _workspace(ctx["run_dir"]), consent=_token(ctx),
                destination="idx.example.com", sink=sink,
                allow_plaintext=True)
        self.assertEqual(sink.uploads, [],
                         "no side effect without write-ahead audit")


if __name__ == "__main__":
    unittest.main()
