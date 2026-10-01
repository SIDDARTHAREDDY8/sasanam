#!/usr/bin/env python3
"""Unit tests for the approval-ceremony v2 gate (gov/approval_ceremony.py)
and the 11 ``ceremony-v2-*`` decision codes.

Conventions: staging default; spec vectors are independent literals
(fixed seeds / fixed keys), never recomputed through the code under
test; ``verify`` results asserted with ``is True`` / ``is False``
(wave-243); the lane-local taxonomy pin (1336) is asserted on quoted
source literals, never ``len(dict)`` (wave-260); no in-repo git
subprocesses (wave-224).
"""

import base64
import json
import os
import re
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import approval_ceremony as ac  # noqa: E402
from gov import corroboration_receipt as cr  # noqa: E402
from gov import decision_codes as dc  # noqa: E402
from gov.agent_identity import did_key_from_pubkey  # noqa: E402
from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402

NOW = 1700000000
PAYLOAD = {"action": "tool.execute", "tool": "shell",
           "args": {"cmd": "ls /tmp"}}


def _signer(i):
    return Ed25519Signer(bytes([i]) * 32)


def _did(signer):
    return did_key_from_pubkey(signer.public_key)


def _receipt(signer, payload_digest):
    stmt = cr.build_statement(
        _did(signer), payload_digest, ["b" * 64],
        {"action": "approval.resume", "resource": "ceremony-test"},
        "corroborated", "2026-10-01T12:00:00Z",
        "approval-ceremony", "c" * 64)
    return cr.sign_envelope(cr.dsse_envelope(stmt), signer, signer.key_id)


def _gate(store=None):
    signer = _signer(1)
    store = store or ac.MemoryApprovalStore()
    return (ac.ApprovalGate(
        store, {_did(signer): Ed25519Verifier(signer.public_key)}),
        signer)


def _record_schema():
    return ac.ResponseSchema.record({
        "action": ac.ResponseSchema.text(),
        "args": ac.ResponseSchema.record({
            "cmd": ac.ResponseSchema.text()}),
    })


class TestResponseSchema(unittest.TestCase):
    def test_kinds_validate(self):
        self.assertIsNone(ac.ResponseSchema.none().validate(None))
        self.assertEqual(ac.ResponseSchema.text().validate("hi"), "hi")
        self.assertEqual(
            ac.ResponseSchema.enum(("a", "b")).validate("b"), "b")

    def test_violations(self):
        with self.assertRaises(Exception):
            ac.ResponseSchema.none().validate("x")
        with self.assertRaises(Exception):
            ac.ResponseSchema.text().validate(3)
        with self.assertRaises(Exception):
            ac.ResponseSchema.enum(("a",)).validate("z")
        # Record: extra fields rejected, missing fields rejected.
        rec = ac.ResponseSchema.record({"x": ac.ResponseSchema.text()})
        with self.assertRaises(Exception):
            rec.validate({"x": "ok", "y": "extra"})
        with self.assertRaises(Exception):
            rec.validate({})
        with self.assertRaises(Exception):
            rec.validate({"x": 5})

    def test_action_shape(self):
        good = {"action": "shell.run", "args": {"cmd": "ls"}}
        self.assertEqual(ac.ResponseSchema.action().validate(good), good)
        with self.assertRaises(Exception):
            ac.ResponseSchema.action().validate({"action": "x"})
        with self.assertRaises(Exception):
            ac.ResponseSchema.action().validate(
                {"action": "x", "args": "nope"})
        with self.assertRaises(Exception):
            ac.ResponseSchema.action().validate("nope")

    def test_bad_construction(self):
        with self.assertRaises(Exception):
            ac.ResponseSchema("json-schema")
        with self.assertRaises(Exception):
            ac.ResponseSchema.enum(())
        with self.assertRaises(Exception):
            ac.ResponseSchema.record({"x": "not-a-schema"})

    def test_schema_roundtrip(self):
        s = _record_schema()
        s2 = ac.ResponseSchema.from_json(
            json.loads(json.dumps(s.to_json())))
        self.assertEqual(s2.validate(
            {"action": "a", "args": {"cmd": "c"}}),
            {"action": "a", "args": {"cmd": "c"}})


class TestRequest(unittest.TestCase):
    def test_idempotent_and_deterministic(self):
        gate, _ = _gate()
        r1 = gate.request_approval("t", "n", PAYLOAD, now=NOW)
        r2 = gate.request_approval("t", "n", PAYLOAD, now=NOW)
        self.assertEqual(r1["approval_id"], r2["approval_id"])
        # Same inputs on a fresh gate -> same routing-key id.
        gate2, _ = _gate()
        r3 = gate2.request_approval("t", "n", PAYLOAD, now=NOW)
        self.assertEqual(r1["approval_id"], r3["approval_id"])
        # Different name -> different id.
        r4 = gate.request_approval("t", "other", PAYLOAD, now=NOW)
        self.assertNotEqual(r1["approval_id"], r4["approval_id"])

    def test_id_is_not_a_secret(self):
        gate, _ = _gate()
        r = gate.request_approval("t", "n", PAYLOAD, now=NOW)
        self.assertIn("id_note", r)
        self.assertEqual(len(r["approval_id"]), 32)

    def test_bare_dict_schema_refused(self):
        gate, _ = _gate()
        with self.assertRaises(ac.ApprovalCeremonyError) as ctx:
            gate.request_approval("t", "n", PAYLOAD, now=NOW,
                                  response_schema={"type": "object"})
        self.assertEqual(ctx.exception.code, "ceremony-v2-schema-invalid")

    def test_malformed_requests(self):
        gate, _ = _gate()
        for kwargs in ({"thread_id": "", "name": "n", "payload": PAYLOAD},
                       {"thread_id": "t", "name": "n",
                        "payload": "not-a-dict"},
                       {"thread_id": "t", "name": "n",
                        "payload": PAYLOAD,
                        "allowed_verdicts": ("accept", "nuke")},
                       {"thread_id": "t", "name": "n",
                        "payload": PAYLOAD, "allowed_verdicts": ()}):
            with self.assertRaises(ac.ApprovalCeremonyError) as ctx:
                gate.request_approval(now=NOW, **kwargs)
            self.assertEqual(ctx.exception.code, "ceremony-v2-malformed")
        # No ambient clock: now is required and must be int.
        with self.assertRaises(ac.ApprovalCeremonyError):
            gate.request_approval("t", "n", PAYLOAD)

    def test_verifier_registry_required(self):
        with self.assertRaises(ac.ApprovalCeremonyError):
            ac.ApprovalGate(ac.MemoryApprovalStore(), {})


class TestResume(unittest.TestCase):
    def _pending(self, gate, thread, name="n", **kw):
        rec = gate.request_approval(thread, name, PAYLOAD, now=NOW, **kw)
        return rec["approval_id"], rec["payload_digest"]

    def test_one_shot(self):
        gate, signer = _gate()
        aid, digest = self._pending(gate, "t")
        env = _receipt(signer, digest)
        out = gate.resume_approval(aid, "accept", None, env, now=NOW)
        self.assertEqual(out["outcome"], "accepted")
        self.assertTrue(out["approved"] is True)
        self.assertEqual(out["payload"], PAYLOAD)
        self.assertEqual(out["checked"][-1], "schema")
        self.assertIn("out_of_scope", out)
        with self.assertRaises(ac.ApprovalCeremonyError) as ctx:
            gate.resume_approval(aid, "accept", None, env, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "ceremony-v2-already-consumed")

    def test_unknown_approval(self):
        gate, _ = _gate()
        with self.assertRaises(ac.ApprovalCeremonyError) as ctx:
            gate.resume_approval("0" * 32, "accept", None, {}, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "ceremony-v2-unknown-approval")

    def test_ambiguity_fails_closed(self):
        gate, signer = _gate()
        self._pending(gate, "t", name="a")
        self._pending(gate, "t", name="b")
        with self.assertRaises(ac.ApprovalCeremonyError) as ctx:
            gate.resume_next("t", "accept", None,
                             _receipt(signer, "0" * 64), now=NOW)
        self.assertEqual(ctx.exception.code,
                         "ceremony-v2-ambiguous-resume")

    def test_forged_and_tampered_receipts(self):
        gate, signer = _gate()
        aid, digest = self._pending(gate, "t")
        forged = _receipt(_signer(9), digest)
        with self.assertRaises(ac.ApprovalCeremonyError) as ctx:
            gate.resume_approval(aid, "accept", None, forged, now=NOW)
        self.assertEqual(ctx.exception.code, "ceremony-v2-receipt-invalid")
        env = _receipt(signer, digest)
        env["signatures"][0]["sig"] = base64.b64encode(
            b"\x00" * 64).decode("ascii")
        with self.assertRaises(ac.ApprovalCeremonyError) as ctx:
            gate.resume_approval(aid, "accept", None, env, now=NOW)
        self.assertEqual(ctx.exception.code, "ceremony-v2-receipt-invalid")
        # Still pending: refusals never consume.
        self.assertEqual(
            [p["approval_id"] for p in gate.pending("t")], [aid])

    def test_payload_binding(self):
        gate, signer = _gate()
        aid, _digest = self._pending(gate, "t")
        env = _receipt(signer, "0" * 64)
        with self.assertRaises(ac.ApprovalCeremonyError) as ctx:
            gate.resume_approval(aid, "accept", None, env, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "ceremony-v2-payload-tampered")

    def test_verdict_allowlist_engine_enforced(self):
        gate, signer = _gate()
        aid, digest = self._pending(
            gate, "t", allowed_verdicts=("accept", "ignore"))
        env = _receipt(signer, digest)
        with self.assertRaises(ac.ApprovalCeremonyError) as ctx:
            gate.resume_approval(aid, "edit",
                                 {"action": "a", "args": {}},
                                 env, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "ceremony-v2-verdict-not-allowed")

    def test_typed_arg_shapes(self):
        gate, signer = _gate()
        aid, digest = self._pending(gate, "t")
        env = _receipt(signer, digest)
        # accept/ignore carry no payload.
        with self.assertRaises(ac.ApprovalCeremonyError) as ctx:
            gate.resume_approval(aid, "accept", "junk", env, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "ceremony-v2-verdict-arg-mismatch")
        # respond carries str.
        with self.assertRaises(ac.ApprovalCeremonyError) as ctx:
            gate.resume_approval(aid, "respond", 42, env, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "ceremony-v2-verdict-arg-mismatch")
        # edit carries an action mapping.
        with self.assertRaises(ac.ApprovalCeremonyError) as ctx:
            gate.resume_approval(aid, "edit", "junk", env, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "ceremony-v2-verdict-arg-mismatch")

    def test_schema_enforced_validated_object_returned(self):
        gate, signer = _gate()
        aid, digest = self._pending(
            gate, "t", response_schema=_record_schema())
        env = _receipt(signer, digest)
        bad = {"action": "tool.execute", "args": {"cmd": "ls"},
               "extra": "field"}
        with self.assertRaises(ac.ApprovalCeremonyError) as ctx:
            gate.resume_approval(aid, "edit", bad, env, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "ceremony-v2-schema-violation")
        good = {"action": "tool.execute", "args": {"cmd": "ls /var"}}
        out = gate.resume_approval(aid, "edit", good, env, now=NOW)
        self.assertEqual(out["outcome"], "edited")
        self.assertEqual(out["payload"], good)

    def test_verdict_flows(self):
        gate, signer = _gate()
        # respond: feedback returned, not a grant.
        aid, digest = self._pending(gate, "t1")
        out = gate.resume_approval(
            aid, "respond", "looks risky",
            _receipt(signer, digest), now=NOW)
        self.assertEqual(out["outcome"], "responded")
        self.assertEqual(out["payload"], "looks risky")
        self.assertTrue(out["approved"] is False)
        # ignore: decline, no payload.
        aid, digest = self._pending(gate, "t2")
        out = gate.resume_approval(
            aid, "ignore", None, _receipt(signer, digest), now=NOW)
        self.assertEqual(out["outcome"], "declined")
        self.assertIsNone(out["payload"])
        self.assertTrue(out["approved"] is False)


class TestLineage(unittest.TestCase):
    def test_fork_refires_stale_refused(self):
        gate, signer = _gate()
        rec = gate.request_approval("t", "n", PAYLOAD, now=NOW)
        aid = rec["approval_id"]
        refired = gate.fork_thread("t", "l1", now=NOW)
        self.assertEqual(len(refired), 1)
        self.assertNotEqual(refired[0], aid)
        env = _receipt(signer, rec["payload_digest"])
        with self.assertRaises(ac.ApprovalCeremonyError) as ctx:
            gate.resume_approval(aid, "accept", None, env, now=NOW)
        self.assertEqual(ctx.exception.code, "ceremony-v2-stale-lineage")
        # The re-fired approval resumes under its new id.
        out = gate.resume_approval(
            refired[0], "accept", None, env, now=NOW)
        self.assertEqual(out["outcome"], "accepted")


class TestRunOnce(unittest.TestCase):
    def test_cached(self):
        gate, _ = _gate()
        calls = []
        v1 = gate.run_once("t", "tok", lambda: calls.append(1) or "r")
        v2 = gate.run_once("t", "tok", lambda: calls.append(1) or "r")
        self.assertEqual((v1, v2), ("r", "r"))
        self.assertEqual(calls, [1])

    def test_must_be_json(self):
        gate, _ = _gate()
        with self.assertRaises(ac.ApprovalCeremonyError):
            gate.run_once("t", "tok", lambda: object())


class TestFileStore(unittest.TestCase):
    def test_journal_replay(self):
        path = os.path.join(tempfile.mkdtemp(), "a.jsonl")
        gate, signer = _gate(ac.FileApprovalStore(path))
        rec = gate.request_approval("t", "n", PAYLOAD, now=NOW)
        gate.run_once("t", "tok", lambda: "v")
        gate2, _ = _gate(ac.FileApprovalStore(path))
        self.assertEqual(
            [p["approval_id"] for p in gate2.pending("t")],
            [rec["approval_id"]])
        self.assertEqual(
            gate2.run_once("t", "tok", lambda: "other"), "v")

    def test_malformed_journal_raises(self):
        path = os.path.join(tempfile.mkdtemp(), "a.jsonl")
        with open(path, "w") as fh:
            fh.write('{"event": "bogus"}\n')
        with self.assertRaises(ac.ApprovalCeremonyError) as ctx:
            ac.FileApprovalStore(path)
        self.assertEqual(ctx.exception.code, "ceremony-v2-malformed")


class TestTaxonomyPin(unittest.TestCase):
    def test_taxonomy_pin_1411(self):
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "..", "gov", "decision_codes.py"),
                  encoding="utf-8") as fh:
            src = fh.read()
        literals = re.findall(r'"code": \'([^\']*)\'', src)
        self.assertEqual(len(literals), 1482)
        self.assertEqual(len(set(literals)), 1482)
        for code in ("ceremony-v2-already-consumed",
                     "ceremony-v2-ambiguous-resume",
                     "ceremony-v2-malformed",
                     "ceremony-v2-payload-tampered",
                     "ceremony-v2-receipt-invalid",
                     "ceremony-v2-schema-invalid",
                     "ceremony-v2-schema-violation",
                     "ceremony-v2-stale-lineage",
                     "ceremony-v2-unknown-approval",
                     "ceremony-v2-verdict-arg-mismatch",
                     "ceremony-v2-verdict-not-allowed"):
            self.assertIn(code, literals)
            self.assertIn(code, dc.TAXONOMY)
            self.assertEqual(dc.TAXONOMY[code]["domain"], "ceremony")


if __name__ == "__main__":
    unittest.main()
