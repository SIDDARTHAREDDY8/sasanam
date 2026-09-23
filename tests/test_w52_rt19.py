"""Wave-52 RT19 unit tests: canary closure ratchet hardenings.

- DLP scanner robustness (wave-52 RT19 break-first): innocent
  base64-looking traffic crashed ``_try_b64_decode`` with
  UnicodeDecodeError because ``_printable_ascii`` is a 0.9-ratio
  heuristic. The final decode is now guarded in all three decoders.
- Persistent halt marker (wave-52 RT19 f3): a canary trip writes a
  server-side ``.canary_halted`` marker into the run dir; a fresh
  executor over the same run dir starts halted, so the halt survives
  executor restarts. No marker -> zero behavior change.

Deterministic, hermetic (make_run temp dirs), $0.
"""

import base64
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

from harness import make_run  # noqa: E402
from gov import canary as cy  # noqa: E402
from gov import dlp as dlp_mod  # noqa: E402
from gov.canary import CanaryMint, CanaryRegistry, CanaryTripHalt  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402


def _armed(run_id="run-w52-rt19"):
    run = make_run()
    mint = CanaryMint(run_id)
    reg = CanaryRegistry()
    reg.register(mint)
    run["executor"].canary_registry = reg
    ident = run["mint_identity"]("agent-1", "researcher", "op-1")
    return run, ident, mint, reg


class TestDlpDecodeRobustness(unittest.TestCase):
    """The scanner must never raise on innocent encoded traffic."""

    def test_b64_decode_non_ascii_returns_none(self):
        # A base64 run that passes the 0.9-ratio printable heuristic
        # but is not pure ASCII must not crash the decoder.
        raw = b"quarterly report: revenue up 12 percent, all " \
              b"regions green\x96\x97"
        enc = base64.b64encode(raw).decode()
        self.assertIsNone(dlp_mod._try_b64_decode(enc))

    def test_b32_decode_non_ascii_returns_none(self):
        import base64 as _b64
        raw = b"staging cluster deploy notes here ok\x96\x97\x98\x99"
        enc = _b64.b32encode(raw).decode()
        self.assertIsNone(dlp_mod._try_b32_decode(enc))

    def test_hex_decode_non_ascii_returns_none(self):
        raw = b"innocent deployment notes payload ok\x96\x97"
        enc = raw.hex()
        self.assertIsNone(dlp_mod._try_hex_decode(enc))

    def test_scan_tool_args_no_crash_on_innocent_b64(self):
        # Exact RT19 break-first trigger: innocent base64 blob inside
        # api_call params crashed find_credential_cross_field.
        doc = base64.b64encode(
            b"quarterly report: revenue up 12 percent, all "
            b"regions green").decode()
        blocked, rule, _, _ = dlp_mod.scan_tool_args(
            "api_call", {"endpoint": "https://synthetic.local/v1",
                         "params": {"doc": doc}})
        self.assertFalse(blocked)

    def test_valid_decodes_still_work(self):
        enc = base64.b64encode(b"AKIAIOSFODNN7EXAMPLE").decode()
        self.assertEqual(dlp_mod._try_b64_decode(enc),
                         "AKIAIOSFODNN7EXAMPLE")


class TestHaltMarker(unittest.TestCase):
    def test_no_marker_no_behavior_change(self):
        run, ident, mint, reg = _armed("w52-marker-neg")
        self.assertFalse((run["run_dir"] / ".canary_halted").exists())
        self.assertFalse(run["executor"]._canary_halted)

    def test_trip_writes_marker(self):
        run, ident, mint, reg = _armed("w52-marker-write")
        host = next(v for v, m in reg._by_value.items()
                    if m["kind"] == "hostname")
        with self.assertRaises(CanaryTripHalt):
            run["executor"].call(
                ident, "http_post",
                url="https://%s/x" % host, data="x")
        self.assertTrue((run["run_dir"] / ".canary_halted").exists())

    def test_restarted_executor_starts_halted(self):
        run, ident, mint, reg = _armed("w52-marker-restart")
        host = next(v for v, m in reg._by_value.items()
                    if m["kind"] == "hostname")
        with self.assertRaises(CanaryTripHalt):
            run["executor"].call(
                ident, "http_post",
                url="https://%s/x" % host, data="x")
        ex2 = ToolExecutor(run["run_dir"], run["policy"], run["log"],
                           run["approvals"], canary_registry=reg)
        self.assertTrue(ex2._canary_halted)
        ident2 = ex2.mint_identity("agent-9", "researcher", "op-1")
        # Even a benign non-egress call is refused: the run is terminal.
        with self.assertRaises(CanaryTripHalt):
            ex2.call(ident2, "read_file", path="/tmp/x")

    def test_marker_best_effort_read_only_dir(self):
        # If the marker cannot be read, construction degrades to the
        # old in-memory behavior (no crash, no false halt).
        run, ident, mint, reg = _armed("w52-marker-ro")
        ex2 = ToolExecutor(run["run_dir"], run["policy"], run["log"],
                           run["approvals"], canary_registry=reg)
        self.assertFalse(ex2._canary_halted)


if __name__ == "__main__":
    unittest.main()
