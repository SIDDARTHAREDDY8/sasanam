"""Unit tests for gov/short_lived_credentials.py.

Wave-256 lane 2. Tests live at the public seams: issue / verify /
revoke / expire_due / history. Deterministic (``now`` is injected;
no wall-clock dependence).
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402
from gov import short_lived_credentials as slc  # noqa: E402


class TaxonomyPinTest(unittest.TestCase):
    def test_taxonomy_pin(self):
        # Wave-256 lane 2: re-pointed to 1045 (1036 + 9
        # short-lived-credential), additive only.
        self.assertEqual(len(decision_codes.TAXONOMY), 1443)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).
        for code in (
                "short-lived-credential-chain-broken",
                "short-lived-credential-corrupted",
                "short-lived-credential-expired",
                "short-lived-credential-key-weak",
                "short-lived-credential-malformed",
                "short-lived-credential-revoked",
                "short-lived-credential-scope-forbidden",
                "short-lived-credential-ttl-unbounded",
                "short-lived-credential-unknown"):
            self.assertIn(code, decision_codes.TAXONOMY)
            self.assertEqual(decision_codes.code_for(code)["domain"],
                             "short-lived-credential")


def _tmpdir():
    d = tempfile.mkdtemp(prefix="slc-unit-", dir="/var/tmp")
    os.makedirs(d, exist_ok=True)
    return d


class IssueTest(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmpdir()
        self.iss = slc.CredentialIssuer(
            os.path.join(self.tmp, "c.jsonl"), max_ttl_seconds=3600)

    def _refused(self, fn, code):
        with self.assertRaises(slc.CredentialError) as ctx:
            fn()
        self.assertEqual(ctx.exception.code, code)

    def test_issue_happy_path(self):
        cred = self.iss.issue("agent-1", "tool:read", 60)
        for field in ("credential_id", "secret", "principal", "scope",
                      "issued_at", "expires_at"):
            self.assertIn(field, cred)
        self.assertEqual(cred["principal"], "agent-1")
        self.assertEqual(cred["scope"], "tool:read")
        self.assertAlmostEqual(cred["expires_at"] - cred["issued_at"],
                               60, places=3)

    def test_secret_never_on_disk(self):
        cred = self.iss.issue("agent-1", "tool:read", 60)
        with open(os.path.join(self.tmp, "c.jsonl"), "rb") as fh:
            raw = fh.read().decode("utf-8")
        self.assertNotIn(cred["secret"], raw)
        self.assertIn(cred["credential_id"], raw)

    def test_empty_principal_refused(self):
        self._refused(lambda: self.iss.issue("", "tool:read", 60),
                      "short-lived-credential-malformed")

    def test_nonstring_principal_refused(self):
        self._refused(lambda: self.iss.issue(123, "tool:read", 60),
                      "short-lived-credential-malformed")

    def test_empty_scope_refused(self):
        self._refused(lambda: self.iss.issue("a", "", 60),
                      "short-lived-credential-malformed")

    def test_unbounded_ttl_refused(self):
        for bad in (None, 0, -1, 3601, 10 ** 9):
            self._refused(lambda b=bad: self.iss.issue("a", "s", b),
                          "short-lived-credential-ttl-unbounded")

    def test_noint_ttl_malformed(self):
        for bad in ("60", 1.5, True, [60]):
            self._refused(lambda b=bad: self.iss.issue("a", "s", b),
                          "short-lived-credential-malformed")

    def test_wildcard_scope_refused_by_default(self):
        for wild in ("*", "tool:*"):
            self._refused(lambda w=wild: self.iss.issue("a", w, 60),
                          "short-lived-credential-scope-forbidden")

    def test_wildcard_scope_opt_in(self):
        iss = slc.CredentialIssuer(
            os.path.join(self.tmp, "w.jsonl"),
            allow_wildcard_scope=True)
        cred = iss.issue("a", "tool:*", 60)
        self.assertEqual(cred["scope"], "tool:*")

    def test_bad_max_ttl_refused(self):
        for bad in (0, -5, "3600", 1.5, True):
            with self.assertRaises(slc.CredentialError) as ctx:
                slc.CredentialIssuer(
                    os.path.join(self.tmp, "x.jsonl"),
                    max_ttl_seconds=bad)
            self.assertEqual(ctx.exception.code,
                             "short-lived-credential-malformed")


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmpdir()
        self.iss = slc.CredentialIssuer(
            os.path.join(self.tmp, "c.jsonl"))
        self.cred = self.iss.issue("agent-1", "tool:read", 600)

    def _refused(self, fn, code):
        with self.assertRaises(slc.CredentialError) as ctx:
            fn()
        self.assertEqual(ctx.exception.code, code)

    def test_verify_happy_path(self):
        rec = self.iss.verify(self.cred["credential_id"],
                              self.cred["secret"])
        self.assertEqual(rec["principal"], "agent-1")
        self.assertEqual(rec["scope"], "tool:read")
        self.assertNotIn("secret", rec)  # secret never echoed back

    def test_verify_with_matching_scope(self):
        rec = self.iss.verify(self.cred["credential_id"],
                              self.cred["secret"], scope="tool:read")
        self.assertEqual(rec["scope"], "tool:read")

    def test_verify_scope_mismatch(self):
        self._refused(
            lambda: self.iss.verify(self.cred["credential_id"],
                                    self.cred["secret"],
                                    scope="tool:write"),
            "short-lived-credential-scope-forbidden")

    def test_unknown_id(self):
        self._refused(lambda: self.iss.verify("nope", "nope"),
                      "short-lived-credential-unknown")

    def test_secret_mismatch_same_code(self):
        # Id-existence is not leaked: same code as unknown id.
        self._refused(
            lambda: self.iss.verify(self.cred["credential_id"],
                                    "wrong"),
            "short-lived-credential-unknown")

    def test_revoked_refused(self):
        self.iss.revoke(self.cred["credential_id"])
        self._refused(
            lambda: self.iss.verify(self.cred["credential_id"],
                                    self.cred["secret"]),
            "short-lived-credential-revoked")

    def test_expired_refused_and_journaled_once(self):
        cid = self.cred["credential_id"]
        for _ in range(2):
            self._refused(
                lambda: self.iss.verify(
                    cid, self.cred["secret"],
                    now=self.cred["expires_at"] + 10.0),
                "short-lived-credential-expired")
        kinds = [e["event_type"] for e in self.iss.history(cid)]
        self.assertEqual(kinds.count("CRED_EXPIRED"), 1)

    def test_expired_status_refused_even_with_early_now(self):
        # Once expired (via expire_due), verify refuses even if the
        # caller passes an earlier `now`: status is authoritative.
        cid = self.cred["credential_id"]
        self.iss.expire_due(now=self.cred["expires_at"] + 1.0)
        self._refused(
            lambda: self.iss.verify(cid, self.cred["secret"],
                                    now=self.cred["issued_at"] + 1.0),
            "short-lived-credential-expired")

    def test_revoke_unknown(self):
        self._refused(lambda: self.iss.revoke("nope"),
                      "short-lived-credential-unknown")

    def test_double_revoke_refused(self):
        self.iss.revoke(self.cred["credential_id"])
        self._refused(lambda: self.iss.revoke(self.cred["credential_id"]),
                      "short-lived-credential-malformed")


class LifetimeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmpdir()
        self.path = os.path.join(self.tmp, "c.jsonl")
        self.iss = slc.CredentialIssuer(self.path)

    def test_history_reconstructs_lifetime(self):
        cred = self.iss.issue("agent-1", "tool:read", 600)
        self.iss.verify(cred["credential_id"], cred["secret"])
        self.iss.revoke(cred["credential_id"])
        hist = self.iss.history(cred["credential_id"])
        self.assertEqual([e["event_type"] for e in hist],
                         ["CRED_ISSUED", "CRED_USED", "CRED_REVOKED"])
        # Deep-copied: mutating the returned history cannot corrupt
        # the issuer's state.
        hist[0]["payload"]["principal"] = "mallory"
        hist2 = self.iss.history(cred["credential_id"])
        self.assertEqual(hist2[0]["payload"]["principal"], "agent-1")

    def test_history_unknown(self):
        with self.assertRaises(slc.CredentialError) as ctx:
            self.iss.history("nope")
        self.assertEqual(ctx.exception.code,
                         "short-lived-credential-unknown")

    def test_expire_due(self):
        c1 = self.iss.issue("a", "s", 60)
        c2 = self.iss.issue("b", "s", 600)
        n = self.iss.expire_due(now=c1["expires_at"] + 1.0)
        self.assertEqual(n, 1)
        kinds = [e["event_type"]
                 for e in self.iss.history(c1["credential_id"])]
        self.assertIn("CRED_EXPIRED", kinds)
        # c2 untouched.
        rec = self.iss.verify(c2["credential_id"], c2["secret"],
                              now=c1["expires_at"] + 1.0)
        self.assertEqual(rec["principal"], "b")

    def test_state_survives_reopen(self):
        cred = self.iss.issue("agent-1", "tool:read", 600)
        key = self.iss._key
        iss2 = slc.CredentialIssuer(self.path, key=key)
        rec = iss2.verify(cred["credential_id"], cred["secret"])
        self.assertEqual(rec["principal"], "agent-1")

    def test_tampered_journal_fails_closed(self):
        self.iss.issue("agent-1", "tool:read", 600)
        key = self.iss._key
        with open(self.path, "r+b") as fh:
            data = bytearray(fh.read())
        data[len(data) // 2] ^= 0x01
        with open(self.path, "wb") as fh:
            fh.write(bytes(data))
        with self.assertRaises(slc.CredentialError) as ctx:
            slc.CredentialIssuer(self.path, key=key)
        self.assertIn(ctx.exception.code,
                      ("short-lived-credential-chain-broken",
                       "short-lived-credential-corrupted"))

    def test_wrong_key_fails_closed(self):
        self.iss.issue("agent-1", "tool:read", 600)
        with self.assertRaises(slc.CredentialError) as ctx:
            slc.CredentialIssuer(self.path,
                                 key=b"\x02" * 32)
        self.assertEqual(ctx.exception.code,
                         "short-lived-credential-chain-broken")

    def test_weak_key_refused(self):
        with self.assertRaises(slc.CredentialError) as ctx:
            slc.CredentialIssuer(os.path.join(self.tmp, "k.jsonl"),
                                 key=b"short")
        self.assertEqual(ctx.exception.code,
                         "short-lived-credential-key-weak")

    def test_env_key_stable_across_reopen(self):
        os.environ["GOV_CREDENTIAL_KEY"] = "ab" * 32
        try:
            p = os.path.join(self.tmp, "e.jsonl")
            iss1 = slc.CredentialIssuer(p)
            cred = iss1.issue("agent-1", "tool:read", 600)
            iss2 = slc.CredentialIssuer(p)
            rec = iss2.verify(cred["credential_id"], cred["secret"])
            self.assertEqual(rec["principal"], "agent-1")
        finally:
            del os.environ["GOV_CREDENTIAL_KEY"]


if __name__ == "__main__":
    unittest.main()
