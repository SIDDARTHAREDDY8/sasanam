"""Wave-63 RT21: F128 (non-string receiver-reconstruction leaves) closure tests.

F128: the canary and DLP traversals inspected string values only. A
canary/credential value represented as a JSON int array (the canonical
byte encoding), as bytes, or placed as a dict key executed with no
trip and no DLP block, and bytes nested in structured params crashed
the egress byte budget with an uncaught TypeError (F123 class).

Closure pins: int-array/bytes/dict-key representations trip the
canary and block in DLP (strict rules only); nested bytes no longer
crash the budget counter; legitimate non-string args (port lists,
bools, short lists) still execute with no trip and no block.

Deterministic, hermetic (make_run temp dirs), $0.
"""

import base64
import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("TMPDIR", "/tmp/gov-run")
os.environ.setdefault("GOV_DEV_KEYS", "1")

from gov.log import enable_dev_keys  # noqa: E402
enable_dev_keys()

from harness import make_run  # noqa: E402
from gov import canary as cy_mod  # noqa: E402
from gov import dlp  # noqa: E402


def _armed_run(run_id="w63-f128"):
    run = make_run()
    mint = cy_mod.CanaryMint(run_id)
    reg = cy_mod.CanaryRegistry()
    reg.register(mint)
    run["executor"].canary_registry = reg
    ident = run["mint_identity"]("agent-1", "researcher", "op-1")
    return run, ident, mint, reg


def _secret(reg):
    for v, meta in reg._by_value.items():
        if meta.get("label") == "aws-secret-0":
            return v
    raise AssertionError("no aws-secret-0 canary")


class TestF128CanaryNonStringLeaves(unittest.TestCase):
    def test_int_array_secret_trips(self):
        run, ident, mint, reg = _armed_run()
        ints = [ord(c) for c in _secret(reg)]
        with self.assertRaises(cy_mod.CanaryTripHalt):
            run["executor"].call(
                ident, "api_call",
                endpoint="https://synthetic.local/x", params={"data": ints})

    def test_nested_int_array_secret_trips(self):
        run, ident, mint, reg = _armed_run()
        ints = [ord(c) for c in _secret(reg)]
        with self.assertRaises(cy_mod.CanaryTripHalt):
            run["executor"].call(
                ident, "api_call",
                endpoint="https://synthetic.local/x",
                params={"outer": {"inner": [ints]}})

    def test_secret_as_dict_key_trips(self):
        run, ident, mint, reg = _armed_run()
        with self.assertRaises(cy_mod.CanaryTripHalt):
            run["executor"].call(
                ident, "api_call",
                endpoint="https://synthetic.local/x",
                params={_secret(reg): "innocent"})

    def test_bytes_secret_trips(self):
        run, ident, mint, reg = _armed_run()
        with self.assertRaises(cy_mod.CanaryTripHalt):
            run["executor"].call(
                ident, "api_call",
                endpoint="https://synthetic.local/x",
                params={"blob": _secret(reg).encode("ascii")})

    def test_short_bytes_leaf_does_not_trip(self):
        run, ident, mint, reg = _armed_run()
        r = run["executor"].call(
            ident, "api_call",
            endpoint="https://synthetic.local/x",
            params={"blob": b"tiny"})
        self.assertEqual(r["status"], "executed")

    def test_non_printable_int_array_does_not_trip(self):
        run, ident, mint, reg = _armed_run()
        r = run["executor"].call(
            ident, "api_call",
            endpoint="https://synthetic.local/x",
            params={"data": [1, 2, 3, 0, 255] * 8})
        self.assertEqual(r["status"], "executed")

    def test_bool_list_does_not_trip(self):
        run, ident, mint, reg = _armed_run()
        r = run["executor"].call(
            ident, "api_call",
            endpoint="https://synthetic.local/x",
            params={"flags": [True, False] * 20})
        self.assertEqual(r["status"], "executed")

    def test_legit_numeric_args_still_execute(self):
        run, ident, mint, reg = _armed_run()
        r = run["executor"].call(
            ident, "api_call",
            endpoint="https://synthetic.local/x",
            params={"ports": [80, 443, 8080], "retries": 3,
                    "ratio": 0.5, "enabled": True, "note": None})
        self.assertEqual(r["status"], "executed")


class TestF128DlpNonStringLeaves(unittest.TestCase):
    AKIA = "AKIAIOSFODNN7EXAMPLE"

    def test_int_array_akia_blocked_cross_field(self):
        self.assertEqual(
            dlp.find_credential_cross_field(
                {"data": [ord(c) for c in self.AKIA]}),
            "dlp-aws-access-key")

    def test_nested_int_array_akia_blocked(self):
        self.assertEqual(
            dlp.find_credential_cross_field(
                {"o": {"i": [[ord(c) for c in self.AKIA]]}}),
            "dlp-aws-access-key")

    def test_bytes_field_akia_blocked_per_field(self):
        blocked, rule, _red, _hits = dlp.scan_tool_args(
            "api_call", {"payload": self.AKIA.encode("ascii")})
        self.assertTrue(blocked)
        self.assertEqual(rule, "dlp-aws-access-key")

    def test_akia_as_dict_key_blocked(self):
        self.assertEqual(
            dlp.find_credential_cross_field({self.AKIA: "x"}),
            "dlp-aws-access-key")

    def test_keys_do_not_poison_join_reassembly(self):
        # Wave-63 regression pin: dict keys must not glue onto adjacent
        # values in the cross-field join (broke A4/A5 b64 reassembly).
        full = base64.b64encode(self.AKIA.encode()).decode()
        self.assertEqual(
            dlp.find_credential_cross_field(
                {"a": full[:10], "b": full[10:]}),
            "dlp-aws-access-key")

    def test_legit_arrays_not_blocked(self):
        self.assertIsNone(dlp.find_credential_cross_field(
            {"ports": [80, 443], "flags": [True, False],
             "short": [1, 2, 3]}))
        self.assertIsNone(dlp.find_credential_cross_field(
            {"msg": "hello world this is fine"}))

    def test_short_slack_token_int_array_blocked(self):
        # Shortest credential shape (14 chars) must clear the leaf gate.
        tok = "xoxb-1234567890"
        self.assertEqual(
            dlp.find_credential_cross_field(
                {"data": [ord(c) for c in tok]}),
            "dlp-slack-token")


class TestF128BytesAvailability(unittest.TestCase):
    def test_nested_bytes_no_longer_crashes_budget(self):
        run, ident, _m, _r = _armed_run()
        r = run["executor"].call(
            ident, "api_call",
            endpoint="https://synthetic.local/x",
            params={"blob": b"\x00\x01binary", "nested": {"b": bytearray(b"zz")}})
        self.assertEqual(r["status"], "executed")

    def test_bytes_field_scanned_but_innocent_bytes_execute(self):
        run, ident, _m, _r = _armed_run()
        r = run["executor"].call(
            ident, "api_call",
            endpoint="https://synthetic.local/x",
            params={"blob": b"just some innocent bytes here"})
        self.assertEqual(r["status"], "executed")


if __name__ == "__main__":
    unittest.main()
