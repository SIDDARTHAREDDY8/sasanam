"""RT10/F117 closure tests (wave-41): degenerate archive ciphers.

F117 (LOW): a cipher that RETURNS without raising but emits degenerate
output (identity/no-op, empty, truncating) uploaded plaintext bytes
while the write-ahead audit entry claimed ``encrypted: True`` -- the
module trusted the cipher's output as the data-fact "this is
ciphertext" without checking its shape (the ADI lens: corrupted data
fact consumed as trusted by a deterministic decision).

The fix (gov/platform_egress.py): after the cipher call, refuse
AUDITED (``archive_cipher_ineffective``) when the output is degenerate
-- plaintext present verbatim in the output, or output STRICTLY SHORTER
than the plaintext (wave-42/F118 correction: same-length non-verbatim
output is a functional stream-cipher shape, not degenerate -- the
sanctioned demonstration_cipher is same-length). The check runs on the
raw cipher output BEFORE the nonce is prepended (F118: the wave-41
check ran on the nonce-prefixed blob, letting sub-nonce truncations
through), and before the write-ahead authorized entry, so no false
``encrypted: True`` claim is ever written.
"""

import os
import sys
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # noqa: E402
from gov.platform_egress import (  # noqa: E402
    EVENT_AUTHORIZED,
    EVENT_DENIED,
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


class _EnvVar:
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


def _workspace(run_dir):
    ws = Path(run_dir) / "ws"
    (ws / "src").mkdir(parents=True, exist_ok=True)
    (ws / "src" / "app.py").write_text("print('hello')\n")
    return ws


def _collect(ctx, cipher, sink):
    collector = WorkspaceCollector(
        ctx["log"], ctx["policy"],
        egress_allowlist={"idx.example.com"}, consent_key=_CONSENT_KEY)
    token = issue_consent(ctx["log"], _CONSENT_KEY, granted_by="operator-1")
    return collector.collect(
        _workspace(ctx["run_dir"]), consent=token,
        destination="idx.example.com", sink=sink,
        archive_key=_ARCHIVE_KEY, cipher=cipher)


class TestDegenerateArchiveCipher(unittest.TestCase):
    """F117: degenerate cipher output refuses AUDITED; no false
    ``encrypted: True`` claim is ever written."""

    def test_identity_cipher_refused_and_audited(self):
        ctx = make_run()
        sink = _Sink("idx.example.com")
        before = len(ctx["read_log"]())
        with self.assertRaises(PlatformEgressError) as cm:
            _collect(ctx, lambda k, n, d: d, sink)
        self.assertIn("archive_cipher_ineffective", str(cm.exception))
        denied = [e for e in ctx["read_log"]()[before:]
                  if e.get("event") == EVENT_DENIED]
        self.assertTrue(denied, "degenerate cipher must be audit-logged")
        self.assertIn("archive_cipher_ineffective", denied[0]["reason"])
        self.assertEqual(sink.uploads, [])
        # And crucially: no authorized entry claiming encrypted=True.
        authorized = [e for e in ctx["read_log"]()[before:]
                      if e.get("event") == EVENT_AUTHORIZED]
        self.assertEqual(authorized, [])

    def test_empty_cipher_refused_and_audited(self):
        ctx = make_run()
        sink = _Sink("idx.example.com")
        before = len(ctx["read_log"]())
        with self.assertRaises(PlatformEgressError) as cm:
            _collect(ctx, lambda k, n, d: b"", sink)
        self.assertIn("archive_cipher_ineffective", str(cm.exception))
        denied = [e for e in ctx["read_log"]()[before:]
                  if e.get("event") == EVENT_DENIED]
        self.assertTrue(denied)
        self.assertEqual(sink.uploads, [])

    def test_truncating_cipher_refused(self):
        ctx = make_run()
        sink = _Sink("idx.example.com")
        with self.assertRaises(PlatformEgressError) as cm:
            _collect(ctx, lambda k, n, d: d[:4], sink)
        self.assertIn("archive_cipher_ineffective", str(cm.exception))
        self.assertEqual(sink.uploads, [])

    def test_legitimate_cipher_still_uploads(self):
        # Vacuity: a real (test) cipher is unaffected by the guard.
        ctx = make_run()
        sink = _Sink("idx.example.com")
        with _EnvVar(_DEMO_CIPHER_ENV, "1"):
            _collect(ctx, demonstration_cipher, sink)
        self.assertEqual(len(sink.uploads), 1)
        payload = sink.uploads[0]["payload"]
        self.assertNotIn(b"print('hello')", payload)
        authorized = [e for e in ctx["read_log"]()
                      if e.get("event") == EVENT_AUTHORIZED]
        self.assertTrue(authorized)
        self.assertTrue(authorized[-1]["encrypted"])

    def test_empty_workspace_with_legitimate_cipher(self):
        # Vacuity: empty plaintext skips the degenerate check (nothing
        # to compare), legitimate cipher still uploads.
        ctx = make_run()
        ws = Path(ctx["run_dir"]) / "emptyws"
        ws.mkdir(parents=True, exist_ok=True)
        collector = WorkspaceCollector(
            ctx["log"], ctx["policy"],
            egress_allowlist={"idx.example.com"}, consent_key=_CONSENT_KEY)
        token = issue_consent(ctx["log"], _CONSENT_KEY,
                              granted_by="operator-1")
        sink = _Sink("idx.example.com")
        with _EnvVar(_DEMO_CIPHER_ENV, "1"):
            collector.collect(ws, consent=token,
                              destination="idx.example.com", sink=sink,
                              archive_key=_ARCHIVE_KEY,
                              cipher=demonstration_cipher)
        self.assertEqual(len(sink.uploads), 1)


if __name__ == "__main__":
    unittest.main()
