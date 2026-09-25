"""F168 (MEDIUM): ingest_foreign_result must accrue deterministic usage.

The production/real-adapter metering path (``ingest_foreign_result``)
built ``{"content": blob}`` with no ``_usage``, so
``_accrue_result_usage`` read 0 tokens — the spec claim that routing
real results through it accrues usage was false.

These tests drive the public seam (``ingest_foreign_result``) and
assert the user-visible meter (``_tokens_used`` deltas). Expected
values are worked examples from the spec (api_call base 80 tokens +
content bytes // 4), not recomputed by the implementation.

Deterministic, stdlib only (unittest), no network, no real systems.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tests.harness import make_run  # noqa: E402

_POLICY = """\
version: 2
roles:
  worker: [api_call, read_file, write_file]
policies:
  - id: test-allow-api
    effect: allow
    match:
      tool: [api_call]
    reason: Test policy allows api_call.
"""

# Worked example: mint_usage("api_call", {}, {"content": blob}) =
# base 80 + len(blob) // 4.
_BLOB = "y" * 40000
_EXPECTED_BLOB_TOKENS = 80 + len(_BLOB) // 4  # 10080


def _run(test):
    tmp = Path(tempfile.mkdtemp(prefix="govf168-"))
    test.addCleanup(__import__("shutil").rmtree, tmp, True)
    p = tmp / "policy.yaml"
    p.write_text(_POLICY, encoding="utf-8")
    return make_run(policy_path=str(p))


class TestForeignMetering(unittest.TestCase):
    def test_foreign_blob_accrues_governed_shaped_usage(self):
        """A 40KB foreign blob accrues 80 + 40000//4 = 10080 tokens —
        the same deterministic mint the governed path uses."""
        run = _run(self)
        ex = run["executor"]
        before = ex._tokens_used
        ex.ingest_foreign_result("api_call", {"data": _BLOB},
                                 principal="acme")
        self.assertEqual(ex._tokens_used - before, _EXPECTED_BLOB_TOKENS)

    def test_adapter_asserted_usage_is_ignored(self):
        """A foreign result carrying an adapter-asserted _usage cannot
        forge or deflate its meter: the mint comes from the normalized
        blob, never from the input dict."""
        run = _run(self)
        ex = run["executor"]
        before = ex._tokens_used
        blob = "z" * 400
        ex.ingest_foreign_result(
            "api_call",
            {"content": blob, "_usage": {"tokens": 1, "spend": 0.0}},
            principal="acme")
        self.assertEqual(ex._tokens_used - before, 80 + len(blob) // 4)

    def test_opaque_result_accrues_base_rate(self):
        """An opaque foreign result (pure bytes: no text blob) still
        accrues the tool's base rate — the execution happened, the
        content is invisible, the base is the honest minimum."""
        run = _run(self)
        ex = run["executor"]
        before = ex._tokens_used
        ex.ingest_foreign_result("api_call", b"\x00\x01\x02" * 1000,
                                 principal="acme")
        self.assertEqual(ex._tokens_used - before, 80)

    def test_none_result_accrues_nothing(self):
        """result=None stays a clean no-op (unchanged)."""
        run = _run(self)
        ex = run["executor"]
        before = ex._tokens_used
        ex.ingest_foreign_result("api_call", None, principal="acme")
        self.assertEqual(ex._tokens_used - before, 0)

    def test_metering_is_loud_while_taint_stays_fail_open(self):
        """Metering happens OUTSIDE the taint fail-open block: even
        when taint ingestion throws, the result path does not break
        AND the usage is still accrued loudly (no silent 0)."""
        run = _run(self)
        ex = run["executor"]
        before = ex._tokens_used
        with mock.patch.object(ex, "_ingest_result",
                               side_effect=RuntimeError("taint boom")):
            # Must not raise: ingestion trouble never breaks the
            # result path (deliberate fail-open posture, unchanged).
            ex.ingest_foreign_result("api_call", {"data": _BLOB},
                                     principal="acme")
        # ...but metering already accrued, loudly, before the taint
        # block ran.
        self.assertEqual(ex._tokens_used - before, _EXPECTED_BLOB_TOKENS)

    def test_no_double_count(self):
        """One ingestion = exactly one mint: the internal accrual
        inside _ingest_result reads the _usage-less dict as 0."""
        run = _run(self)
        ex = run["executor"]
        before = ex._tokens_used
        ex.ingest_foreign_result("api_call", {"data": _BLOB},
                                 principal="acme")
        ex.ingest_foreign_result("api_call", {"data": _BLOB},
                                 principal="acme")
        self.assertEqual(ex._tokens_used - before,
                         2 * _EXPECTED_BLOB_TOKENS)


if __name__ == "__main__":
    unittest.main()
