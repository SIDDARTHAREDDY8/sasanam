"""Unit tests for the F252 issuance-registry fix (gov/output_ifc.py).

Grant authenticity: ``issue_grant`` records the minted digest in an
``IssuanceRegistry``; ``exercise_privilege`` consults it and refuses
self-minted grants with ``ifc-grant-unissued`` (distinct from the
digest-mismatch ``ifc-privilege-unauthorized`` path). Deterministic;
explicit ``now`` timestamps; scratch journals under /var/tmp.
"""

import hashlib
import json
import os
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import output_ifc as ifc  # noqa: E402

NOW = "2026-10-01T10:00:00Z"
LATER = "2026-10-01T10:30:00Z"
EXPIRED_NOW = "2026-10-01T12:00:00Z"

PRIV = {"declassification": ["credential"],
        "endorsement": ["user-verified"]}
AUTH = {"kind": "human-approval", "ref": "appr-ut"}


def _grant(registry=None, **kw):
    args = {"privilege": PRIV, "granted_by": "officer",
            "authorization": AUTH, "ttl_seconds": 3600, "now": NOW}
    args.update(kw)
    return ifc.issue_grant(registry=registry, **args)


def _forge(ref):
    """Self-mint a grant: valid public digest, never issued."""
    body = {
        "v": 1,
        "privilege": {"declassification": ["credential"],
                      "endorsement": ["user-verified"]},
        "granted_by": "attacker",
        "authorization": {"kind": "human-approval", "ref": ref},
        "issued_at": NOW,
        "expires_at": "2026-10-01T11:00:00Z",
    }
    grant = dict(body)
    grant["grant_digest"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True).encode("utf-8")).hexdigest()
    return grant


def _label():
    return {"secrecy": [], "integrity": ["tool-external"]}


def _audit():
    records = []

    def hook(record):
        records.append(record)
    return records, hook


class ForgeryRefusalTest(unittest.TestCase):
    def test_forged_grant_refused_unissued(self):
        records, hook = _audit()
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.exercise_privilege(_forge("ut-f1"), _label(), "endorse",
                                   ["user-verified"], hook, NOW)
        self.assertEqual(ctx.exception.code, "ifc-grant-unissued")
        self.assertEqual(records, [])

    def test_forgery_code_distinct_from_tamper_code(self):
        # Tampered (digest mismatch) keeps its own code.
        grant = _grant()
        tampered = dict(grant)
        tampered["granted_by"] = "attacker"
        records, hook = _audit()
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.exercise_privilege(tampered, _label(), "endorse",
                                   ["user-verified"], hook, NOW)
        self.assertEqual(ctx.exception.code, "ifc-privilege-unauthorized")
        self.assertNotEqual(ctx.exception.code, "ifc-grant-unissued")


class RegistryScopingTest(unittest.TestCase):
    def test_issue_into_a_exercise_against_b_refuses(self):
        reg_a = ifc.IssuanceRegistry()
        reg_b = ifc.IssuanceRegistry()
        grant = _grant(registry=reg_a)
        records, hook = _audit()
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.exercise_privilege(grant, _label(), "endorse",
                                   ["user-verified"], hook, NOW,
                                   registry=reg_b)
        self.assertEqual(ctx.exception.code, "ifc-grant-unissued")

    def test_default_registry_contract(self):
        grant = _grant()
        records, hook = _audit()
        out = ifc.exercise_privilege(grant, _label(), "endorse",
                                     ["user-verified"], hook, NOW)
        self.assertIn("user-verified", out["label"]["integrity"])
        self.assertEqual(len(records), 1)

    def test_non_registry_arg_malformed(self):
        grant = _grant()
        records, hook = _audit()
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.exercise_privilege(grant, _label(), "endorse",
                                   ["user-verified"], hook, NOW,
                                   registry=object())
        self.assertEqual(ctx.exception.code, "ifc-label-malformed")

    def test_revoke_refuses(self):
        reg = ifc.IssuanceRegistry()
        grant = _grant(registry=reg)
        reg.revoke(grant["grant_digest"])
        records, hook = _audit()
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.exercise_privilege(grant, _label(), "endorse",
                                   ["user-verified"], hook, NOW,
                                   registry=reg)
        self.assertEqual(ctx.exception.code, "ifc-grant-unissued")

    def test_revoke_then_reissue_rearms(self):
        reg = ifc.IssuanceRegistry()
        grant = _grant(registry=reg)
        reg.revoke(grant["grant_digest"])
        reg.record(grant["grant_digest"], NOW)
        records, hook = _audit()
        out = ifc.exercise_privilege(grant, _label(), "endorse",
                                     ["user-verified"], hook, NOW,
                                     registry=reg)
        self.assertIn("user-verified", out["label"]["integrity"])

    def test_record_bad_digest_malformed(self):
        reg = ifc.IssuanceRegistry()
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            reg.record("not-a-digest", NOW)
        self.assertEqual(ctx.exception.code, "ifc-label-malformed")


class DurableRegistryTest(unittest.TestCase):
    def _scratch(self):
        return tempfile.mkdtemp(prefix="g270-ut-ifc-", dir="/var/tmp")

    def test_journal_replays_across_restart(self):
        path = os.path.join(self._scratch(), "grants.jsonl")
        reg1 = ifc.IssuanceRegistry(path=path)
        grant = _grant(registry=reg1)
        reg2 = ifc.IssuanceRegistry(path=path)  # simulated restart
        self.assertTrue(reg2.contains(grant["grant_digest"]))
        records, hook = _audit()
        out = ifc.exercise_privilege(grant, _label(), "endorse",
                                     ["user-verified"], hook, NOW,
                                     registry=reg2)
        self.assertIn("user-verified", out["label"]["integrity"])

    def test_revoke_survives_restart(self):
        path = os.path.join(self._scratch(), "grants.jsonl")
        reg1 = ifc.IssuanceRegistry(path=path)
        grant = _grant(registry=reg1)
        reg1.revoke(grant["grant_digest"])
        reg2 = ifc.IssuanceRegistry(path=path)
        self.assertFalse(reg2.contains(grant["grant_digest"]))

    def test_corrupt_journal_refuses_loud(self):
        path = os.path.join(self._scratch(), "grants.jsonl")
        with open(path, "w") as f:
            f.write("garbage\n")
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.IssuanceRegistry(path=path)
        self.assertEqual(ctx.exception.code, "ifc-registry-corrupt")

    def test_malformed_record_refuses_loud(self):
        path = os.path.join(self._scratch(), "grants.jsonl")
        with open(path, "w") as f:
            f.write('{"event": "issued"}\n')  # missing digest
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.IssuanceRegistry(path=path)
        self.assertEqual(ctx.exception.code, "ifc-registry-corrupt")

    def test_missing_file_starts_empty(self):
        path = os.path.join(self._scratch(), "grants.jsonl")
        reg = ifc.IssuanceRegistry(path=path)
        self.assertFalse(reg.contains("ab" * 32))

    def test_bad_path_type_malformed(self):
        with self.assertRaises(ifc.OutputIFCError) as ctx:
            ifc.IssuanceRegistry(path=123)
        self.assertEqual(ctx.exception.code, "ifc-label-malformed")


class NewCodesTest(unittest.TestCase):
    def test_new_codes_live(self):
        for code in ("ifc-grant-unissued", "ifc-registry-corrupt"):
            self.assertIn(code, ifc.CODES)
            self.assertIn(
                code,
                __import__("gov.decision_codes",
                           fromlist=["TAXONOMY"]).TAXONOMY)


if __name__ == "__main__":
    unittest.main()
