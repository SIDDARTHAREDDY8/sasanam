"""Unit tests for the F255 closure: INST/OBJ/NEWOBJ join the sink rule.

Wave-272 closure lane for F255 (filed 2026-10-01, wave-271 red team):
``gov/bundle_scan.py`` modeled only (resolved sink global + REDUCE) as
a call-capable pair; protocol-0 ``INST`` (callable in the opcode
argument, no GLOBAL at all), ``OBJ`` and ``NEWOBJ`` (callable from the
stack) all execute attacker callables at unpickle time but never
refused. These tests pin the fixed behavior at the unit level; the
red-first battery ``evals/w272_f255_probes.py`` pins it at the seam.

The one deliberately-executing test (test_inst_payload_executes_at_load)
uses a protocol-0 INST stream calling builtins.print under a redirected
stdout -- it proves the probe payload is a real attack, not a dead
stream. Everything else is scan-only.
"""

import contextlib
import io
import pickle
import re
import unittest

from gov import bundle_scan as scan

TAXONOMY_PIN = 1458  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).

SINK_CODE = "bundlescan-rce-global"

_INST_PRINT = b"(Vhello-from-inst\ni" + b"builtins\nprint\n" + b"."
_INST_SYSTEM = b"(Vecho-hi\ni" + b"os\nsystem\n" + b"."
_INST_EVAL = b"(Vhello\ni" + b"builtins\neval\n" + b"."
_OBJ_SYSTEM = b"(cos\nsystem\nVecho-hi\no."
_NEWOBJ_SYSTEM = b"(cos\nsystem\nVecho-hi\n\x81."
_STACKGLOBAL_OBJ_SYSTEM = (
    b"(\x80\x04"
    b"X\x02\x00\x00\x00os\x94"
    b"X\x06\x00\x00\x00system\x94"
    b"\x93"
    b"X\x07\x00\x00\x00echo-hi\x94"
    b"o."
)
_OBJ_UNKNOWN = b"(cmyapp\nWidget\nVhello\no."
_INST_UNKNOWN = b"(Vhello\ni" + b"myapp\nWidget\n" + b"."


def _codes(res):
    return [f["code"] for f in res["findings"]]


class TestCallOpcodeSinkRule(unittest.TestCase):
    def test_inst_payload_executes_at_load(self):
        """The F255 attack is real: this INST stream executes under
        pickle.loads (builtins.print with attacker bytes)."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            pickle.loads(_INST_PRINT)
        self.assertEqual(buf.getvalue(), "hello-from-inst\n")

    def test_inst_sink_refused(self):
        """INST naming os.system refuses with the sink code -- the sink
        is resolved from the INST opcode argument."""
        res = scan.scan_pickle_stream(_INST_SYSTEM)
        self.assertEqual(res["verdict"], "refuse")
        self.assertIn(SINK_CODE, _codes(res))
        self.assertEqual(res["severity"], "critical")

    def test_inst_builtin_eval_refused(self):
        """INST naming builtins.eval also refuses (not just os.system)."""
        res = scan.scan_pickle_stream(_INST_EVAL)
        self.assertEqual(res["verdict"], "refuse")
        self.assertIn(SINK_CODE, _codes(res))

    def test_obj_sink_refused(self):
        """OBJ of os.system refuses with the sink code -- the sink is
        resolved from GLOBAL, the call from OBJ."""
        res = scan.scan_pickle_stream(_OBJ_SYSTEM)
        self.assertEqual(res["verdict"], "refuse")
        self.assertIn(SINK_CODE, _codes(res))

    def test_newobj_sink_refused(self):
        """NEWOBJ of os.system refuses with the sink code."""
        res = scan.scan_pickle_stream(_NEWOBJ_SYSTEM)
        self.assertEqual(res["verdict"], "refuse")
        self.assertIn(SINK_CODE, _codes(res))

    def test_stackglobal_obj_sink_refused(self):
        """Sink resolved from STACK_GLOBAL + OBJ refuses."""
        res = scan.scan_pickle_stream(_STACKGLOBAL_OBJ_SYSTEM)
        self.assertEqual(res["verdict"], "refuse")
        self.assertIn(SINK_CODE, _codes(res))

    def test_sink_without_call_opcode_still_advisory(self):
        """A sink global with no call-capable opcode anywhere is the
        'loaded gun, not a fired one' -- advisory, unchanged."""
        payload = b"(cos\nsystem\n."
        res = scan.scan_pickle_stream(payload)
        self.assertEqual(res["verdict"], "advisory")
        self.assertIn("bundlescan-suspicious-global", _codes(res))

    def test_obj_unknown_class_advisory_never_refused(self):
        """Anti-vacuous: OBJ of an unlisted class is MEDIUM advisory,
        never a refusal."""
        res = scan.scan_pickle_stream(_OBJ_UNKNOWN)
        self.assertEqual(res["verdict"], "advisory")
        self.assertIn("bundlescan-unknown-global", _codes(res))

    def test_inst_unknown_global_advisory_never_refused(self):
        """Anti-vacuous: INST of an unlisted global is MEDIUM advisory,
        never a refusal."""
        res = scan.scan_pickle_stream(_INST_UNKNOWN)
        self.assertEqual(res["verdict"], "advisory")
        self.assertIn("bundlescan-unknown-global", _codes(res))

    def test_reduce_sink_still_refused(self):
        """REDUCE behavior is unchanged (b04 pin)."""
        class _Evil(object):
            def __reduce__(self):
                import os as _os
                return (_os.system, ("id",))
        res = scan.scan_pickle_stream(pickle.dumps(_Evil(), protocol=2))
        self.assertEqual(res["verdict"], "refuse")
        self.assertIn(SINK_CODE, _codes(res))

    def test_garbage_bytes_fail_closed_malformed(self):
        """Garbage bytes that genops cannot parse refuse
        bundlescan-malformed -- the seam never raises on hostile
        input. (The INST argument is always a string or genops raises,
        verified against pickletools; there is no reachable INST
        'unresolvable' arm to pin -- the defensive else-arm is shared
        with GLOBAL's pre-existing pattern.)"""
        res = scan.scan_pickle_stream(b"\xff\xff\xff.")
        self.assertEqual(res["verdict"], "refuse")
        self.assertIn("bundlescan-malformed", _codes(res))

    def test_py2_builtin_spelling_inst_sink_refused(self):
        """'__builtin__ eval' via INST is normalized to builtins.eval."""
        payload = b"(Vhello\ni" + b"__builtin__\neval\n" + b"."
        res = scan.scan_pickle_stream(payload)
        self.assertEqual(res["verdict"], "refuse")
        self.assertIn(SINK_CODE, _codes(res))


class TestNoNewCodes(unittest.TestCase):
    def test_taxonomy_pin_unchanged(self):
        with open("gov/decision_codes.py") as fh:
            src = fh.read()
        codes = re.findall(
            r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
        self.assertEqual(len(codes), TAXONOMY_PIN)
        self.assertEqual(len(set(codes)), TAXONOMY_PIN)


if __name__ == "__main__":
    unittest.main()
