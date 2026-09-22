"""F110 closure tests: governed harness-initiated platform egress.

The ZCode class (I22): platform code with its own network path,
default-on, silently packing workspaces. The closure control is
gov/platform_egress.py -- the only sanctioned harness-initiated
collection path -- with (a) policy-engine routing of every upload,
(b) default-off + HMAC-bound consent tokens (platform-held key,
stdlib hmac), (c) write-ahead audit ordering (authorized entry before
the side effect), (d) key-required archives (explicit plaintext
opt-in), (e) fail-closed when no production cipher is supplied
(demo cipher test-only, explicit pass), (f) deployer-held
(user-verifiable) archive crypto and no vendor key-fetch path.
"""

import os
import sys
import time
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run, DEFAULT_POLICY  # noqa: E402
from gov.platform_egress import (  # noqa: E402
    ConsentToken,
    PlatformEgressError,
    WorkspaceCollector,
    check_consent,
    demonstration_cipher,
    issue_consent,
)
from gov.policy import PolicyEngine  # noqa: E402

# Synthetic platform-held consent key (test-only; production keys come
# from the deployer's KMS/environment and never appear in code).
_CONSENT_KEY = b"test-consent-key-32-bytes-synth"


class _Sink:
    """In-memory upload target (no network)."""

    def __init__(self, host):
        self.host = host
        self.uploads = []

    def put(self, name, payload):
        self.uploads.append({"name": name, "payload": payload,
                             "host": self.host})


class _FailingSink(_Sink):
    def put(self, name, payload):
        raise IOError("synthetic network failure")


class _OrderLog:
    """Log wrapper recording append order for write-ahead assertions."""

    def __init__(self, log, events):
        self._log = log
        self._events = events

    def append(self, entry):
        self._events.append(("log", entry.get("event")))
        return self._log.append(entry)


class _OrderSink(_Sink):
    def __init__(self, host, events):
        super().__init__(host)
        self._events = events

    def put(self, name, payload):
        self._events.append(("put", name))
        return super().put(name, payload)


def _workspace(tmp):
    ws = Path(tmp) / "ws"
    (ws / "src").mkdir(parents=True)
    (ws / "src" / "app.py").write_text("print('hello')\n")
    (ws / ".git" / "objects").mkdir(parents=True)
    (ws / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (ws / "notes.md").write_text("synthetic workspace\n")
    return ws


def _ctx():
    return make_run()


def _collector(ctx, **kw):
    kw.setdefault("egress_allowlist", {"idx.example.com"})
    kw.setdefault("consent_key", _CONSENT_KEY)
    return WorkspaceCollector(ctx["log"], ctx["policy"], **kw)


def _token(ctx, **kw):
    kw.setdefault("granted_by", "operator-1")
    return issue_consent(ctx["log"], _CONSENT_KEY, **kw)


class TestF110ConsentDefaultOff(unittest.TestCase):
    def test_default_off_no_consent_refused(self):
        # (b): no consent token -> no collection, no upload, denial
        # audited. This is the ZCode default-on property, inverted.
        ctx = _ctx()
        collector = _collector(ctx)
        sink = _Sink("idx.example.com")
        before = len(ctx["read_log"]())
        with self.assertRaises(PlatformEgressError):
            collector.collect(_workspace(ctx["run_dir"]), consent=None,
                              destination="idx.example.com", sink=sink)
        self.assertEqual(sink.uploads, [])
        denied = [e for e in ctx["read_log"]()[before:]
                  if e.get("event") == "platform_egress_denied"]
        self.assertTrue(denied, "denial must be audit-logged")
        self.assertIn("consent", denied[0]["reason"])

    def test_consent_issuance_is_audit_logged(self):
        ctx = _ctx()
        before = len(ctx["read_log"]())
        token = _token(ctx)
        self.assertTrue(token.token_id.startswith("pec-"))
        consents = [e for e in ctx["read_log"]()[before:]
                    if e.get("event") == "platform_egress_consent"]
        self.assertEqual(len(consents), 1)
        self.assertEqual(consents[0]["token_id"], token.token_id)
        self.assertEqual(consents[0]["granted_by"], "operator-1")
        # The MAC is audit-logged (verifiable by a key-holder; the key
        # itself never appears).
        self.assertEqual(consents[0]["mac"], token.as_dict()["mac"])

    def test_expired_consent_refused(self):
        # Expiry is now MAC-bound: the token is issued already-expired
        # (negative ttl) so the MAC is valid but the token is stale.
        ctx = _ctx()
        token = _token(ctx, ttl_s=-1)
        collector = _collector(ctx)
        sink = _Sink("idx.example.com")
        with self.assertRaises(PlatformEgressError) as cm:
            collector.collect(_workspace(ctx["run_dir"]), consent=token,
                              destination="idx.example.com", sink=sink,
                              allow_plaintext=True)
        self.assertIn("expired", str(cm.exception))
        self.assertEqual(sink.uploads, [])

    def test_wrong_scope_consent_refused(self):
        ctx = _ctx()
        token = _token(ctx, scope="telemetry")
        collector = _collector(ctx)
        sink = _Sink("idx.example.com")
        with self.assertRaises(PlatformEgressError):
            collector.collect(_workspace(ctx["run_dir"]), consent=token,
                              destination="idx.example.com", sink=sink,
                              allow_plaintext=True)
        self.assertEqual(sink.uploads, [])


class TestF110ConsentHMAC(unittest.TestCase):
    """Defect 1 (wave-35): consent tokens are HMAC-bound to issuance.

    The platform-held key never leaves the operator/deployer; the
    token carries only the MAC. Forgery shapes: hand-minted token,
    tampered field, wrong key, missing MAC.
    """

    def test_hand_minted_token_refused(self):
        ctx = _ctx()
        now = int(time.time())
        forged = {"token_id": "pec-" + "ab" * 16,
                  "scope": "workspace_collect",
                  "granted_by": "attacker",
                  "granted_at": now,
                  "expires_at": now + 3600}
        with self.assertRaises(PlatformEgressError) as cm:
            check_consent(forged, _CONSENT_KEY)
        self.assertIn("bad_mac", str(cm.exception))

    def test_tampered_expiry_refused(self):
        # A genuinely issued token with a modified field no longer
        # verifies -- the MAC covers every field.
        ctx = _ctx()
        token = _token(ctx)
        d = token.as_dict()
        d["expires_at"] = d["expires_at"] + 86400 * 365
        with self.assertRaises(PlatformEgressError) as cm:
            check_consent(ConsentToken(d), _CONSENT_KEY)
        self.assertIn("bad_mac", str(cm.exception))

    def test_swapped_token_id_refused(self):
        ctx = _ctx()
        token = _token(ctx)
        d = token.as_dict()
        d["token_id"] = "pec-" + "cd" * 16
        with self.assertRaises(PlatformEgressError) as cm:
            check_consent(ConsentToken(d), _CONSENT_KEY)
        self.assertIn("bad_mac", str(cm.exception))

    def test_wrong_key_refused(self):
        ctx = _ctx()
        token = _token(ctx)
        with self.assertRaises(PlatformEgressError) as cm:
            check_consent(token, b"wrong-key-32-bytes-synthetic-00")
        self.assertIn("bad_mac", str(cm.exception))

    def test_missing_mac_refused(self):
        ctx = _ctx()
        token = _token(ctx)
        d = token.as_dict()
        del d["mac"]
        with self.assertRaises(PlatformEgressError) as cm:
            check_consent(d, _CONSENT_KEY)
        self.assertIn("bad_mac", str(cm.exception))

    def test_valid_token_accepted(self):
        ctx = _ctx()
        token = _token(ctx)
        self.assertEqual(check_consent(token, _CONSENT_KEY)["token_id"],
                         token.token_id)

    def test_issue_rejects_weak_key(self):
        ctx = _ctx()
        for bad in (None, "not-bytes", b"short"):
            with self.assertRaises(PlatformEgressError):
                issue_consent(ctx["log"], bad, granted_by="operator-1")

    def test_collector_requires_consent_key(self):
        ctx = _ctx()
        with self.assertRaises(PlatformEgressError) as cm:
            WorkspaceCollector(ctx["log"], ctx["policy"],
                               egress_allowlist={"idx.example.com"})
        self.assertIn("consent_key_required", str(cm.exception))
        with self.assertRaises(PlatformEgressError):
            WorkspaceCollector(ctx["log"], ctx["policy"],
                               egress_allowlist={"idx.example.com"},
                               consent_key=b"short")

    def test_forged_token_cannot_upload(self):
        # End to end: forgery through collect() is refused and audited.
        ctx = _ctx()
        now = int(time.time())
        forged = ConsentToken({
            "token_id": "pec-" + "ab" * 16,
            "scope": "workspace_collect",
            "granted_by": "attacker",
            "granted_at": now,
            "expires_at": now + 3600})
        collector = _collector(ctx)
        sink = _Sink("idx.example.com")
        before = len(ctx["read_log"]())
        with self.assertRaises(PlatformEgressError) as cm:
            collector.collect(_workspace(ctx["run_dir"]), consent=forged,
                              destination="idx.example.com", sink=sink,
                              allow_plaintext=True)
        self.assertIn("bad_mac", str(cm.exception))
        self.assertEqual(sink.uploads, [])
        denied = [e for e in ctx["read_log"]()[before:]
                  if e.get("event") == "platform_egress_denied"]
        self.assertTrue(denied)


class TestF110PolicyRouting(unittest.TestCase):
    def test_non_allowlisted_destination_denied_by_policy(self):
        # (a): valid consent, but the destination is not allowlisted ->
        # deny-platform-egress-unallowlisted fires; nothing uploads.
        ctx = _ctx()
        collector = _collector(ctx)
        token = _token(ctx)
        sink = _Sink("evil-vendor.example.net")
        before = len(ctx["read_log"]())
        with self.assertRaises(PlatformEgressError) as cm:
            collector.collect(_workspace(ctx["run_dir"]), consent=token,
                              destination="evil-vendor.example.net",
                              sink=sink, allow_plaintext=True)
        self.assertIn("policy_denied", str(cm.exception))
        self.assertEqual(sink.uploads, [])
        denied = [e for e in ctx["read_log"]()[before:]
                  if e.get("event") == "platform_egress_denied"]
        self.assertTrue(denied)
        self.assertEqual(denied[0].get("flag"),
                         "platform_egress_violation")

    def test_allowlisted_destination_with_consent_uploads_audited(self):
        # (a)+(b): consent + allowlisted destination -> the upload goes
        # through with full audit entries. Governed, not silent.
        # Write-ahead: the authorized entry exists alongside consent
        # and completion entries.
        ctx = _ctx()
        collector = _collector(ctx)
        token = _token(ctx)
        sink = _Sink("idx.example.com")
        before = len(ctx["read_log"]())
        result = collector.collect(_workspace(ctx["run_dir"]),
                                   consent=token,
                                   destination="idx.example.com",
                                   sink=sink, allow_plaintext=True)
        self.assertTrue(result["uploaded"])
        self.assertEqual(len(sink.uploads), 1)
        self.assertEqual(result["files"], 3)
        new = ctx["read_log"]()[before:]
        uploads = [e for e in new
                   if e.get("event") == "platform_egress_upload"]
        authorized = [e for e in new
                      if e.get("event") == "platform_egress_authorized"]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(len(authorized), 1)
        entry = uploads[0]
        self.assertEqual(entry["destination"], "idx.example.com")
        self.assertEqual(entry["token_id"], token.token_id)
        self.assertEqual(entry["archive_bytes"],
                         len(sink.uploads[0]["payload"]))
        self.assertEqual(entry["policy_id"],
                         "allow-platform-egress-allowlisted")
        self.assertTrue(entry["plaintext_explicit"])
        # The authorized entry carries the same digest (same archive).
        self.assertEqual(authorized[0]["archive_sha256"],
                         entry["archive_sha256"])

    def test_policy_rule_is_not_tool_keyed(self):
        # Structural: the F110 rule is the first egress rule whose match
        # block is NOT keyed on tool: (the probe scans for exactly this).
        policy = PolicyEngine(str(DEFAULT_POLICY))
        nontool = [r for r in policy.policies
                   if "tool" not in (r.get("match") or {})
                   and r.get("match", {}).get("platform_egress") is True]
        ids = {r["id"] for r in nontool}
        self.assertIn("deny-platform-egress-unallowlisted", ids)
        self.assertIn("allow-platform-egress-allowlisted", ids)


class TestF110WriteAheadOrdering(unittest.TestCase):
    """Defect 2 (wave-35): the authorization audit entry lands BEFORE
    the upload side effect; failed uploads are explicitly audited."""

    def test_failed_upload_leaves_authorized_and_failed_entries(self):
        ctx = _ctx()
        collector = _collector(ctx)
        token = _token(ctx)
        sink = _FailingSink("idx.example.com")
        before = len(ctx["read_log"]())
        with self.assertRaises(PlatformEgressError) as cm:
            collector.collect(_workspace(ctx["run_dir"]), consent=token,
                              destination="idx.example.com", sink=sink,
                              allow_plaintext=True)
        self.assertIn("upload_failed", str(cm.exception))
        new = ctx["read_log"]()[before:]
        authorized = [e for e in new
                      if e.get("event") == "platform_egress_authorized"]
        failed = [e for e in new
                  if e.get("event") == "platform_egress_upload_failed"]
        completed = [e for e in new
                     if e.get("event") == "platform_egress_upload"]
        # The attempt is fully audited: authorized BEFORE the put, the
        # failure recorded, and NO completion entry for an upload that
        # never happened.
        self.assertEqual(len(authorized), 1)
        self.assertEqual(len(failed), 1)
        self.assertEqual(len(completed), 0)
        self.assertEqual(failed[0]["token_id"], token.token_id)

    def test_authorized_entry_precedes_put(self):
        ctx = _ctx()
        events = []
        collector = WorkspaceCollector(
            _OrderLog(ctx["log"], events), ctx["policy"],
            egress_allowlist={"idx.example.com"},
            consent_key=_CONSENT_KEY)
        token = _token(ctx)
        sink = _OrderSink("idx.example.com", events)
        collector.collect(_workspace(ctx["run_dir"]), consent=token,
                          destination="idx.example.com", sink=sink,
                          allow_plaintext=True)
        put_idx = next(i for i, e in enumerate(events) if e[0] == "put")
        auth_idx = next(i for i, e in enumerate(events)
                        if e == ("log", "platform_egress_authorized"))
        upload_idx = next(i for i, e in enumerate(events)
                          if e == ("log", "platform_egress_upload"))
        self.assertLess(auth_idx, put_idx,
                        "authorized entry must precede the side effect")
        self.assertLess(put_idx, upload_idx,
                        "completion entry follows the side effect")


class TestF110PlaintextExplicit(unittest.TestCase):
    """Defect 3 (wave-35): no silent plaintext -- an archive_key is
    required, or an explicit allow_plaintext opt-in recorded in the
    audit entry."""

    def test_missing_key_without_opt_in_refused(self):
        ctx = _ctx()
        collector = _collector(ctx)
        token = _token(ctx)
        sink = _Sink("idx.example.com")
        before = len(ctx["read_log"]())
        with self.assertRaises(PlatformEgressError) as cm:
            collector.collect(_workspace(ctx["run_dir"]), consent=token,
                              destination="idx.example.com", sink=sink)
        self.assertIn("archive_key_required", str(cm.exception))
        self.assertEqual(sink.uploads, [])
        denied = [e for e in ctx["read_log"]()[before:]
                  if e.get("event") == "platform_egress_denied"]
        self.assertTrue(denied)

    def test_explicit_plaintext_opt_in_audited(self):
        ctx = _ctx()
        collector = _collector(ctx)
        token = _token(ctx)
        sink = _Sink("idx.example.com")
        before = len(ctx["read_log"]())
        result = collector.collect(_workspace(ctx["run_dir"]),
                                   consent=token,
                                   destination="idx.example.com",
                                   sink=sink, allow_plaintext=True)
        self.assertTrue(result["uploaded"])
        self.assertTrue(result["plaintext_explicit"])
        self.assertFalse(result["encrypted"])
        uploads = [e for e in ctx["read_log"]()[before:]
                   if e.get("event") == "platform_egress_upload"]
        self.assertTrue(uploads[0]["plaintext_explicit"])
        self.assertIn(b"--- .git/HEAD ---", sink.uploads[0]["payload"])


class TestF110CipherRequired(unittest.TestCase):
    """Defect 4 (wave-35): an archive_key without an explicit cipher
    is refused -- the module never silently selects a cipher. The demo
    cipher is test-only and must be passed explicitly."""

    def test_key_without_cipher_refused(self):
        ctx = _ctx()
        collector = _collector(ctx)
        token = _token(ctx)
        sink = _Sink("idx.example.com")
        with self.assertRaises(PlatformEgressError) as cm:
            collector.collect(_workspace(ctx["run_dir"]), consent=token,
                              destination="idx.example.com", sink=sink,
                              archive_key=os.urandom(32))
        self.assertIn("archive_cipher_required", str(cm.exception))
        self.assertEqual(sink.uploads, [])

    def test_explicit_demo_cipher_round_trip(self):
        # (c/f): the archive key is deployer-held; the deployer can
        # decrypt and verify -- the opposite of ZCode's vendor-wrapped
        # key. Round-trip through the EXPLICITLY passed demo cipher.
        ctx = _ctx()
        collector = _collector(ctx)
        token = _token(ctx)
        sink = _Sink("idx.example.com")
        key = os.urandom(32)
        result = collector.collect(_workspace(ctx["run_dir"]),
                                   consent=token,
                                   destination="idx.example.com",
                                   sink=sink, archive_key=key,
                                   cipher=demonstration_cipher)
        self.assertTrue(result["encrypted"])
        blob = sink.uploads[0]["payload"]
        nonce, ciphertext = blob[:16], blob[16:]
        decrypted = demonstration_cipher(key, nonce, ciphertext)
        self.assertTrue(decrypted.startswith(b"--- .git/HEAD ---\n"),
                        "deployer key must decrypt the archive")

    def test_weak_archive_key_rejected(self):
        ctx = _ctx()
        collector = _collector(ctx)
        token = _token(ctx)
        sink = _Sink("idx.example.com")
        with self.assertRaises(PlatformEgressError):
            collector.collect(_workspace(ctx["run_dir"]), consent=token,
                              destination="idx.example.com", sink=sink,
                              archive_key=b"short",
                              cipher=demonstration_cipher)
        self.assertEqual(sink.uploads, [])


class TestF110UserVerifiableCrypto(unittest.TestCase):
    def test_no_vendor_key_fetch_path_in_module(self):
        # (f) structural: no code path in gov/platform_egress.py fetches
        # a key from a vendor -- no network calls, no KMS/RSA use. AST
        # over the module (docstrings don't count): collect every called
        # name and imported name, and require none of them to be a
        # key-fetch/network primitive.
        import ast
        src = Path(_TESTS_DIR).parent.joinpath(
            "gov", "platform_egress.py").read_text()
        tree = ast.parse(src)
        called, imported = set(), set()

        class V(ast.NodeVisitor):
            def visit_Call(self, node):
                f = node.func
                if isinstance(f, ast.Name):
                    called.add(f.id)
                elif isinstance(f, ast.Attribute):
                    called.add(f.attr)
                self.generic_visit(node)

            def visit_Import(self, node):
                for a in node.names:
                    imported.add(a.name.split(".")[0])
                self.generic_visit(node)

            def visit_ImportFrom(self, node):
                if node.module:
                    imported.add(node.module.split(".")[0])
                for a in node.names:
                    called.add(a.asname or a.name)
                self.generic_visit(node)

        V().visit(tree)
        banned_calls = {"urlopen", "urlretrieve", "create_connection",
                        "fetch_key", "get_key", "generate_key", "wrap",
                        "unwrap"}
        banned_imports = {"requests", "urllib", "socket", "ssl", "boto3",
                          "botocore", "Crypto", "Cryptodome"}
        bad = (called & banned_calls) | (imported & banned_imports)
        self.assertFalse(bad,
                         "vendor key-fetch shape in module: %r" % (bad,))


if __name__ == "__main__":
    unittest.main()
