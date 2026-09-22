"""RT11/F118 closure tests (wave-42): sub-nonce truncation bypass.

F118 (LOW): the F117 degenerate-output guard ran on the NONCE-PREFIXED
blob (``archive = nonce + cipher(...)``), so a truncating cipher that
dropped fewer than the 16 nonce bytes sailed through both sub-checks:
the blob stayed LONGER than the plaintext (length check passed), and
the truncated plaintext was no longer a contiguous substring (verbatim
check passed). ``lambda k,n,d: d[:-1]`` uploaded ``nonce + d[:-1]``
while the audit claimed ``encrypted: True`` -- the exact false
confidentiality claim F117 was filed to stop. The wave-41 closure probe
tested ``d[:4]`` -- too aggressive a truncation to catch the hole.

The fix (gov/platform_egress.py): the shape check runs on the raw
cipher OUTPUT before the nonce is prepended; refuse AUDITED
(``archive_cipher_ineffective``) when the plaintext is present verbatim
in the output or the output is STRICTLY SHORTER than the plaintext
(truncation is data loss, not encryption). Same-length non-verbatim
output (stream-cipher shape, incl. the sanctioned TEST-ONLY
demonstration_cipher) PASSES by design -- a functional cipher, not a
degenerate one; cipher quality is the deployer's choice. Non-bytes
cipher returns coerce via ``bytes()`` inside the audited-failure path
(F113 property preserved).
"""

import base64
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
    token = issue_consent(ctx["log"], _CONSENT_KEY,
                          granted_by="operator-1", ttl_s=600)
    return collector.collect(
        _workspace(ctx["run_dir"]), consent=token,
        destination="idx.example.com", sink=sink,
        archive_key=_ARCHIVE_KEY, cipher=cipher)


def _assert_refused_audited(tc, ctx, cipher, sink):
    before = len(ctx["read_log"]())
    with tc.assertRaises(PlatformEgressError) as cm:
        _collect(ctx, cipher, sink)
    tc.assertIn("archive_cipher_ineffective", str(cm.exception))
    denied = [e for e in ctx["read_log"]()[before:]
              if e.get("event") == EVENT_DENIED]
    tc.assertTrue(denied, "degenerate cipher must be audit-logged")
    tc.assertIn("archive_cipher_ineffective", denied[0]["reason"])
    tc.assertEqual(sink.uploads, [])
    authorized = [e for e in ctx["read_log"]()[before:]
                  if e.get("event") == EVENT_AUTHORIZED]
    tc.assertEqual(authorized, [],
                   "no authorized entry claiming encrypted=True")


class TestF118SubnonceTruncation(unittest.TestCase):
    """F118: the exact miss shapes -- sub-nonce truncations that sailed
    through the wave-41 guard."""

    def test_off_by_one_truncation_refused(self):
        ctx = make_run()
        _assert_refused_audited(self, ctx, lambda k, n, d: d[:-1],
                                _Sink("idx.example.com"))

    def test_half_truncation_refused(self):
        ctx = make_run()
        _assert_refused_audited(self, ctx, lambda k, n, d: d[:len(d) // 2],
                                _Sink("idx.example.com"))

    def test_one_byte_truncation_refused(self):
        ctx = make_run()
        _assert_refused_audited(self, ctx, lambda k, n, d: d[:1],
                                _Sink("idx.example.com"))

    def test_key_dependent_identity_refused(self):
        def keydep_identity(k, n, d):
            _ = k[0] if k else 0
            return d

        ctx = make_run()
        _assert_refused_audited(self, ctx, keydep_identity,
                                _Sink("idx.example.com"))

    def test_key_dependent_truncation_refused(self):
        ctx = make_run()
        _assert_refused_audited(
            self, ctx, lambda k, n, d: d[:len(d) - 1] if k else d,
            _Sink("idx.example.com"))

    def test_verbatim_in_longer_output_refused(self):
        ctx = make_run()
        _assert_refused_audited(self, ctx, lambda k, n, d: d + b"\x00" * 64,
                                _Sink("idx.example.com"))

    def test_nonce_echo_refused(self):
        ctx = make_run()
        _assert_refused_audited(self, ctx, lambda k, n, d: n + d,
                                _Sink("idx.example.com"))

    def test_non_bytes_cipher_output_refused_audited(self):
        # F113 property: a cipher returning str must not escape with a
        # raw TypeError -- bytes() coerces inside the audited path.
        ctx = make_run()
        sink = _Sink("idx.example.com")
        before = len(ctx["read_log"]())
        with self.assertRaises(PlatformEgressError) as cm:
            _collect(ctx, lambda k, n, d: "not-bytes", sink)
        self.assertIn("archive_cipher_failed", str(cm.exception))
        denied = [e for e in ctx["read_log"]()[before:]
                  if e.get("event") == EVENT_DENIED]
        self.assertTrue(denied)
        self.assertEqual(sink.uploads, [])

    def test_same_length_stream_cipher_passes(self):
        # Boundary: same-length non-verbatim output is a functional
        # cipher (same shape as demonstration_cipher), not degenerate.
        def xor_stream(k, n, d):
            return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))

        ctx = make_run()
        sink = _Sink("idx.example.com")
        with _EnvVar(_DEMO_CIPHER_ENV, "1"):
            _collect(ctx, xor_stream, sink)
        self.assertEqual(len(sink.uploads), 1)

    def test_demonstration_cipher_still_uploads(self):
        ctx = make_run()
        sink = _Sink("idx.example.com")
        with _EnvVar(_DEMO_CIPHER_ENV, "1"):
            _collect(ctx, demonstration_cipher, sink)
        self.assertEqual(len(sink.uploads), 1)

    def test_base64_residual_still_passes(self):
        # Documented residual: non-trivial transform without encryption
        # passes (deployer-trust boundary).
        ctx = make_run()
        sink = _Sink("idx.example.com")
        with _EnvVar(_DEMO_CIPHER_ENV, "1"):
            _collect(ctx, lambda k, n, d: n + base64.b64encode(d), sink)
        self.assertEqual(len(sink.uploads), 1)

    def test_raising_cipher_still_refused_via_f113(self):
        def raising(k, n, d):
            raise RuntimeError("boom")

        ctx = make_run()
        sink = _Sink("idx.example.com")
        with self.assertRaises(PlatformEgressError) as cm:
            _collect(ctx, raising, sink)
        self.assertIn("archive_cipher_failed", str(cm.exception))
        self.assertEqual(sink.uploads, [])


if __name__ == "__main__":
    unittest.main()
