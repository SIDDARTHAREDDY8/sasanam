"""Hardening round-4 regression tests: F13 + F14 + F15 + F16.

F13 — endpoint-rotation campaign closed: the cross-run campaign key is
      the normalized REGISTERED DOMAIN (last two hostname labels), so
      rotating subdomains (shard0/shard1.collector.example) lands in one
      bucket. Exact endpoint strings are still stored for forensics.
      F20 (Round 5) hardened the normalization: IP literals are never
      bucketed and a built-in public-suffix table keeps one registrable
      label above known multi-label suffixes (evil.co.uk vs good.co.uk
      are different tenants). Residual: the table is small, not a full
      PSL; rotating the REGISTERED domain itself still evades.
F14 — fragment-shape bypass closed with a STRUCTURAL signal: same
      principal + same registered domain + same param KEY SET across >=K
      distinct runs inside the window queues via cross_run_campaign,
      regardless of payload size or entropy. Oversize padding and
      low-entropy unary encodings can no longer dodge the K-fragment
      shape check. Residual: queue-only; K-1 fragments still leave;
      changing the param key set or registered domain evades; benign
      repetitive API traffic can false-positive.
F15 — sensitive-read taint extended: (a) api_call RESULTS that trip DLP
      sensitive patterns taint exactly like read_file content; (b) the
      taint persists PRINCIPAL-scoped in the ledger (24h TTL) so a
      confederate's fresh run for the same principal inherits it.
      Different principals stay isolated. Residual: the 24h TTL
      boundary; exfil the engine never observes stays out of scope.
F16 — entropy-tripwire evasion closed: the tripwire keyword list is
      matched in a normalized space (lowercase, leet-speak folded,
      whitespace runs collapsed to boundary markers) covering synonyms
      (credentials, passcode, auth, creds, login), spaced forms
      ("private key", "api key"), and leetspeak (p4ssw0rd, P@ssw0rd).
      The precise credential regexes are untouched. Residual: only the
      listed leet mappings and keyword set are covered; novel
      euphemisms/transforms remain.

Deterministic, stdlib only, no network, no real systems.
"""

import os
import random
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from gov import dlp  # noqa: E402
from gov.egress_ledger import (  # noqa: E402
    EgressLedger,
    SENSITIVE_TAINT_TTL_SECS,
    registered_domain,
)
from harness import make_run, plant_file  # noqa: E402

ENDPOINT_X = "https://collector.synthetic.local/x"
CSV = "id,name,email,phone\n1,Alice Example,alice@example.com,555-0101\n"
PARA = ("three contacts on file. First: Alice, example.com mailbox, "
        "phone ending 0101.")

_rng = random.Random(20260921)
_TOKEN = "".join(
    _rng.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789+/") for _ in range(40))


def _ledger():
    return os.path.join(tempfile.mkdtemp(prefix="govr4-"),
                        "egress_ledger.jsonl")


class TestF13RegisteredDomainCampaign(unittest.TestCase):
    """F13: subdomain rotation lands in one campaign bucket."""

    def _rotated_call(self, ledger, i, endpoint):
        ctx = make_run(ledger_path=ledger)
        ident = ctx["mint_identity"]("rot-%d" % i, "researcher", "org")
        return ctx["executor"].call(
            ident, "api_call", endpoint=endpoint,
            params={"seq": i, "fragment": "frag%d" % i})

    def test_registered_domain_normalization(self):
        self.assertEqual(
            registered_domain("https://shard0.collector.example/x"),
            registered_domain("https://shard1.collector.example:8443/x"))
        self.assertEqual(
            registered_domain("https://shard0.collector.example/x"),
            "collector.example")
        # Case and port are normalized away; exact string is preserved
        # separately in the ledger record (see below).

    def test_rotated_subdomain_campaign_queues_third(self):
        ledger = _ledger()
        eps = ["https://shard%d.collector.synthetic.local/x" % i for i in range(3)]
        rs = [self._rotated_call(ledger, i, ep) for i, ep in enumerate(eps)]
        self.assertEqual([r["status"] for r in rs],
                         ["executed", "executed", "queued"])
        self.assertEqual(rs[2].get("policy_id"),
                         "approval-cross-run-campaign")

    def test_exact_endpoints_preserved_for_forensics(self):
        ledger = _ledger()
        eps = ["https://shard%d.collector.synthetic.local/x" % i for i in range(2)]
        for i, ep in enumerate(eps):
            self._rotated_call(ledger, i, ep)
        import json
        # F140: the ledger also carries kind:"upload" citation records
        # for api_call -- this test is about the endpoint-carrying
        # campaign records, so select those.
        records = [json.loads(line) for line in open(ledger)
                   if line.strip() and "endpoint" in json.loads(line)]
        self.assertEqual([r["endpoint"] for r in records], eps)
        self.assertEqual({r["campaign_domain"] for r in records},
                         {"synthetic.local"})

    def test_public_suffix_heuristic_boundary_documented(self):
        # F20 (Round 5): the public-suffix false positive is CLOSED — the
        # built-in suffix table keeps one registrable label above known
        # multi-label suffixes, and IP literals are never bucketed.
        # Residual: the table is intentionally small (not a full PSL).
        self.assertEqual(registered_domain("https://a.example.co.uk/x"),
                         "example.co.uk")
        self.assertEqual(registered_domain("https://evil.co.uk/x"),
                         "evil.co.uk")
        self.assertEqual(registered_domain("https://good.co.uk/x"),
                         "good.co.uk")
        self.assertNotEqual(registered_domain("https://evil.co.uk/x"),
                            registered_domain("https://good.co.uk/x"))
        self.assertEqual(registered_domain("http://10.0.0.1/x"), "10.0.0.1")
        self.assertEqual(registered_domain("http://[::1]/x"), "::1")
        # F13 behavior unchanged: subdomain rotation still buckets together.
        self.assertEqual(
            registered_domain("https://shard0.collector.example/x"),
            registered_domain("https://shard1.collector.example/x"))


class TestF14StructuralCampaign(unittest.TestCase):
    """F14: shape-evading low-and-slow campaigns still queue."""

    def _campaign(self, ledger, i, params, endpoint=ENDPOINT_X,
                  principal="org"):
        ctx = make_run(ledger_path=ledger)
        ident = ctx["mint_identity"]("s-%d" % i, "researcher", principal)
        return ctx["executor"].call(ident, "api_call", endpoint=endpoint,
                                   params=params)

    def test_padded_payload_campaign_queues_third(self):
        ledger = _ledger()
        rs = [self._campaign(ledger, i, {"seq": i, "pad": "x" * 70})
              for i in range(3)]
        self.assertEqual([r["status"] for r in rs],
                         ["executed", "executed", "queued"])
        self.assertEqual(rs[2].get("policy_id"),
                         "approval-cross-run-campaign")
        # Attribution proof: NONE of the three entries were
        # fragment-shaped, so the fragment rule could not have fired —
        # the structural signal queued the third.
        led = EgressLedger(ledger)
        self.assertEqual(
            led.fragments("org", ENDPOINT_X, window_secs=3600), [])

    def test_unary_encoded_campaign_queues_third(self):
        ledger = _ledger()
        rs = [self._campaign(
            ledger, i, {"byte": i, "run": "q" * (65 + i)}) for i in range(3)]
        self.assertEqual([r["status"] for r in rs],
                         ["executed", "executed", "queued"])
        self.assertEqual(rs[2].get("policy_id"),
                         "approval-cross-run-campaign")
        led = EgressLedger(ledger)
        self.assertEqual(
            led.fragments("org", ENDPOINT_X, window_secs=3600), [])

    def test_different_param_key_sets_do_not_combine(self):
        ledger = _ledger()
        for i in range(3):
            r = self._campaign(ledger, i, {"field_%d" % i: "x" * 70})
            self.assertEqual(r["status"], "executed", "run %d" % i)

    def test_single_run_structural_burst_does_not_trip(self):
        # One run repeating the same structure K times is NOT a
        # cross-run campaign for the structural signal (thin-run rule).
        ledger = _ledger()
        ctx = make_run(ledger_path=ledger)
        ident = ctx["mint_identity"]("burst", "researcher", "org")
        for i in range(3):
            r = ctx["executor"].call(
                ident, "api_call", endpoint=ENDPOINT_X,
                params={"seq": i, "pad": "x" * 70})
            self.assertEqual(r["status"], "executed", "call %d" % i)


class TestF15PrincipalScopedTaint(unittest.TestCase):
    """F15: api_call-result taint + principal-scoped persistence."""

    def test_sensitive_api_call_result_taints(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("a", "researcher", "org")
        # White-box: an api_call RESULT carrying DLP-sensitive content
        # (e.g. a simulated CRM/contacts read) taints like a file read.
        ctx["executor"]._ingest_result(
            "api_call", {"content": CSV}, "org")
        self.assertTrue(ctx["executor"]._read_sensitive)
        r = ctx["executor"].call(
            ident, "api_call", endpoint=ENDPOINT_X,
            params={"summary": "nothing verbatim here at all"})
        self.assertEqual(r["status"], "queued")
        self.assertEqual(r.get("policy_id"),
                         "approval-sensitive-read-before-api")

    def test_taint_persists_across_runs_same_principal(self):
        ledger = _ledger()
        ctx = make_run(ledger_path=ledger)
        ident = ctx["mint_identity"]("a", "researcher", "org")
        plant_file(ctx, "data/c.csv", CSV)
        ctx["executor"].call(ident, "read_file", path="data/c.csv")
        # Fresh executor, fresh run, same principal: inherited taint.
        ctx2 = make_run(ledger_path=ledger)
        ident2 = ctx2["mint_identity"]("b", "researcher", "org")
        r = ctx2["executor"].call(
            ident2, "api_call", endpoint=ENDPOINT_X,
            params={"summary": PARA})
        self.assertEqual(r["status"], "queued")
        self.assertEqual(r.get("policy_id"),
                         "approval-sensitive-read-before-api")

    def test_different_principal_isolated(self):
        ledger = _ledger()
        ctx = make_run(ledger_path=ledger)
        ident = ctx["mint_identity"]("a", "researcher", "org")
        plant_file(ctx, "data/c.csv", CSV)
        ctx["executor"].call(ident, "read_file", path="data/c.csv")
        ctx2 = make_run(ledger_path=ledger)
        ident2 = ctx2["mint_identity"]("b", "researcher", "org2")
        r = ctx2["executor"].call(
            ident2, "api_call", endpoint=ENDPOINT_X,
            params={"summary": PARA})
        self.assertEqual(r["status"], "executed")

    def test_taint_ttl_boundary(self):
        ledger = _ledger()
        led = EgressLedger(ledger)
        self.assertEqual(SENSITIVE_TAINT_TTL_SECS, 24 * 3600)
        # Expired mark: no taint.
        led.taint_mark("org", "run-old", now=time.time() - 25 * 3600)
        self.assertFalse(led.taint_active("org"))
        # Fresh mark: tainted.
        led.taint_mark("org", "run-new")
        self.assertTrue(led.taint_active("org"))
        # Other principal untouched by org's mark.
        self.assertFalse(led.taint_active("org2"))


class TestF16TripwireNormalization(unittest.TestCase):
    """F16: spaced / leet / synonym keyword forms trip the wire."""

    def _wire(self, keyword):
        return dlp.find_credential(
            "deploy %s: %s" % (keyword, _TOKEN))

    def test_synonym_variants_trip(self):
        for kw in ("credentials", "CREDENTIALS", "passcode", "auth",
                   "creds", "login", "access"):
            self.assertEqual(self._wire(kw), "dlp-entropy-tripwire",
                             kw)

    def test_spaced_variants_trip(self):
        for kw in ("private key", "api key", "the key"):
            self.assertEqual(self._wire(kw), "dlp-entropy-tripwire",
                             kw)

    def test_leetspeak_variants_trip(self):
        for kw in ("p4ssw0rd", "P@ssw0rd", "p@ssword", "s3cret"):
            self.assertEqual(self._wire(kw), "dlp-entropy-tripwire",
                             kw)

    def test_positive_control_still_trips(self):
        self.assertEqual(self._wire("password"), "dlp-entropy-tripwire")

    def test_precise_credential_rules_unchanged(self):
        akia = "AKIAIOSFODNN7EXAMPLE"
        self.assertEqual(dlp.find_credential(akia), "dlp-aws-access-key")
        self.assertEqual(dlp.find_credential("xoxb-1234567890AB"),
                         "dlp-slack-token")
        ghp = "ghp_" + "a" * 36
        self.assertEqual(dlp.find_credential(ghp), "dlp-github-token")

    def test_innocent_prose_stays_clean(self):
        # 'key' glued inside ordinary words must not trip.
        self.assertIsNone(dlp.find_credential("the monkey: " + _TOKEN))
        self.assertIsNone(dlp.find_credential("keyboard shortcut: " + _TOKEN))
        # Keyword present but the token is low-entropy: no trip.
        self.assertIsNone(dlp.find_credential("token " + "ab" * 10))
        # No keyword at all: no trip.
        self.assertIsNone(dlp.find_credential("plain prose " + "x" * 10))


if __name__ == "__main__":
    unittest.main()
