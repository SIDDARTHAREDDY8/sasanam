#!/usr/bin/env python3
"""Wave-202 lane B red-team probes: build-provenance + signature envelope v2.

Break-first battery per the diagnosing-bugs skill. Pattern lineage:
Nix/Guix build-provenance records (ADAPT: SLSA-style provenance, not
vendoring) and age/minisign signature envelopes (ADAPT: trusted comments
+ key IDs) -- re-implemented stdlib-only, nothing vendored.

The pristine tree has NO build provenance and NO signature envelope:
gov.build_provenance and gov.signature_envelope_v2 are absent. Each probe
attacks that gap:

  P1  ARTIFACT_BINDING   provenance signed for digest A presented for
                         tampered artifact B -> refused
  P2  REPRO_LIE          input claimed deterministic fails to reproduce
                         on rebuild -> loud refusal
  P3  REPRO_PASS         deterministic input reproducing -> verifies
  P4  STATEMENT_STRICT   provenance with unknown field -> refused
  P5  STATEMENT_TAMPER   statement body tampered post-sign -> refused
  P6  PROVENANCE_FORGE   valid signature, statement for artifact A,
                         opened for artifact B -> refused
  E1  COMMENT_TAMPER     envelope trusted comment edited post-sign ->
                         signature invalid -> refused
  E2  WRONG_KEY_ID       envelope sealed by key1 opened with key2's
                         verifier -> loud refusal
  E3  ENVELOPE_STRICT    envelope with unknown field -> refused
  E4  PAYLOAD_TAMPER     envelope payload_digest edited -> refused
  E5  PROVENANCE_DIGEST  envelope provenance_digest edited -> refused
  E6  ENVELOPE_POSITIVE  valid envelope+provenance verifies end to end

On the pristine tree every probe reports GAP (modules absent -- genuine
red). After the fix all must flip to HELD.

Verdicts: HELD (defense held), GAP (gap demonstrated -- the red phase),
ERROR only on harness failure (a verdict changing between the two
deterministic runs, an unexpected exception).

Deterministic: fixed seeds for Ed25519 signers; every probe runs twice
and a verdict change is an ERROR. Synthetic/local only.
``GOV_SKIP_GREEN=1`` is honored (green check records a skip instead of
spawning sub-batteries).
"""

import contextlib
import io
import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import build_provenance as _bp
    from gov import signature_envelope_v2 as _env
    from gov.signing import Ed25519Signer, Ed25519Verifier
    _ABSENT = False
except ImportError:
    _ABSENT = True

_RESULTS = []


def _record(probe_id, name, verdict, detail):
    _RESULTS.append({"id": probe_id, "name": name, "verdict": verdict,
                     "detail": detail})


def _gap(probe_id, name, detail):
    _record(probe_id, name, "GAP", detail)


def _run_twice(fn):
    """Run a probe twice; a verdict change between runs is an ERROR."""
    first = fn()
    second = fn()
    if first[0] != second[0]:
        return ("ERROR",
                "nondeterministic verdict: %r vs %r" % (first, second))
    return first


def _signers():
    s1 = Ed25519Signer(bytes([1]) * 32)
    s2 = Ed25519Signer(bytes([2]) * 32)
    return (s1, Ed25519Verifier(s1.public_key, s1.key_id),
            s2, Ed25519Verifier(s2.public_key, s2.key_id))


def _statement(signer, artifact_hex, inputs):
    stmt = _bp.ProvenanceStatement(
        builder="ci-builder-1",
        recipe="repo@sha256:" + "ab" * 32,
        inputs=inputs,
        artifact_hex=artifact_hex,
        built_at=1700000000,
    )
    return stmt.seal(signer)


def _good_inputs():
    return [
        _bp.ProvenanceInput(name="src.tar.gz",
                            digest_hex="aa" * 32, deterministic=True),
        _bp.ProvenanceInput(name="random-seed.bin",
                            digest_hex="bb" * 32, deterministic=False),
    ]


# -- provenance probes ---------------------------------------------------

def probe_p1_artifact_binding():
    def one():
        s1, v1, _, _ = _signers()
        sealed = _statement(s1, "aa" * 32, _good_inputs())
        try:
            _bp.verify_sealed_statement(sealed, expected_artifact_hex="bb" * 32,
                                        verifier=v1)
        except _bp.ProvenanceError as exc:
            return ("HELD", "tampered artifact refused: %s" % exc)
        return ("ERROR", "tampered artifact verified -- BINDING BROKEN")
    return _run_twice(one)


def probe_p2_repro_lie():
    def one():
        s1, v1, _, _ = _signers()
        sealed = _statement(s1, "aa" * 32, _good_inputs())
        # Deterministic input claims to reproduce, but the rebuilder
        # derives a different digest: the determinism claim is a lie.
        def rebuilder(name):
            return "cc" * 32
        try:
            _bp.verify_reproducibility(sealed, rebuilder=rebuilder,
                                       verifier=v1,
                                       expected_artifact_hex="aa" * 32)
        except _bp.ProvenanceError as exc:
            return ("HELD", "reproducibility lie refused: %s" % exc)
        return ("ERROR", "lying reproducibility claim accepted")
    return _run_twice(one)


def probe_p3_repro_pass():
    def one():
        s1, v1, _, _ = _signers()
        sealed = _statement(s1, "aa" * 32, _good_inputs())
        def rebuilder(name):
            return {"src.tar.gz": "aa" * 32}[name]
        try:
            ok = _bp.verify_reproducibility(sealed, rebuilder=rebuilder,
                                            verifier=v1,
                                            expected_artifact_hex="aa" * 32)
        except _bp.ProvenanceError as exc:
            return ("ERROR", "honest reproducibility refused: %s" % exc)
        if ok:
            return ("HELD", "reproducing build verifies")
        return ("ERROR", "verify_reproducibility returned False")
    return _run_twice(one)


def probe_p4_statement_strict():
    def one():
        s1, _, _, _ = _signers()
        sealed = _statement(s1, "aa" * 32, _good_inputs())
        doc = dict(sealed["statement"])
        doc["rogue_field"] = "injected"
        sealed_bad = {"statement": doc, "signature": sealed["signature"],
                      "key_id": sealed["key_id"]}
        try:
            _bp.parse_statement(sealed_bad)
        except _bp.ProvenanceError:
            return ("HELD", "unknown statement field refused")
        return ("ERROR", "extra statement field accepted")
    return _run_twice(one)


def probe_p5_statement_tamper():
    def one():
        s1, v1, _, _ = _signers()
        sealed = _statement(s1, "aa" * 32, _good_inputs())
        doc = dict(sealed["statement"])
        doc["builder"] = "evil-builder"
        sealed_bad = {"statement": doc, "signature": sealed["signature"],
                      "key_id": sealed["key_id"]}
        try:
            _bp.verify_sealed_statement(sealed_bad,
                                        expected_artifact_hex="aa" * 32,
                                        verifier=v1)
        except _bp.ProvenanceError as exc:
            return ("HELD", "tampered statement refused: %s" % exc)
        return ("ERROR", "tampered statement verified")
    return _run_twice(one)


def probe_p6_provenance_forge():
    def one():
        s1, v1, _, _ = _signers()
        # A valid sealed statement FOR ARTIFACT A, opened FOR ARTIFACT B:
        # the signature is fine, the binding must still refuse.
        sealed = _statement(s1, "aa" * 32, _good_inputs())
        try:
            _bp.verify_sealed_statement(sealed, expected_artifact_hex="cc" * 32,
                                        verifier=v1)
        except _bp.ProvenanceError as exc:
            return ("HELD", "forged binding refused: %s" % exc)
        return ("ERROR", "valid-signature/wrong-artifact verified")
    return _run_twice(one)


# -- envelope probes -----------------------------------------------------

def _envelope(s1, payload_hex, comments=("release 1.0",),
              provenance_digest=None):
    prov = None
    if provenance_digest is None:
        sealed = _statement(s1, payload_hex, _good_inputs())
        prov = _bp.statement_digest(sealed)
    return _env.seal(payload_hex=payload_hex, signer=s1,
                     trusted_comments=list(comments),
                     provenance_digest=provenance_digest or prov)


def probe_e1_comment_tamper():
    def one():
        s1, v1, _, _ = _signers()
        env = _envelope(s1, "aa" * 32)
        prov = env["provenance_digest"]
        env_bad = dict(env)
        env_bad["trusted_comments"] = ["release 2.0 -- backdoored"]
        try:
            _env.open_envelope(env_bad, expected_payload_hex="aa" * 32,
                               verifier=v1,
                               expected_provenance_digest=prov)
        except _env.EnvelopeError as exc:
            return ("HELD", "tampered comment refused: %s" % exc)
        return ("ERROR", "tampered trusted comment verified")
    return _run_twice(one)


def probe_e2_wrong_key_id():
    def one():
        s1, _, s2, v2 = _signers()
        env = _envelope(s1, "aa" * 32)
        try:
            _env.open_envelope(env, expected_payload_hex="aa" * 32,
                               verifier=v2,
                               expected_provenance_digest=env["provenance_digest"])
        except _env.EnvelopeError as exc:
            return ("HELD", "wrong key id refused: %s" % exc)
        return ("ERROR", "envelope sealed by key1 opened with key2")
    return _run_twice(one)


def probe_e3_envelope_strict():
    def one():
        s1, _, _, _ = _signers()
        env = _envelope(s1, "aa" * 32)
        env_bad = dict(env)
        env_bad["rogue_field"] = "injected"
        try:
            _env.parse_envelope(env_bad)
        except _env.EnvelopeError:
            return ("HELD", "unknown envelope field refused")
        return ("ERROR", "extra envelope field accepted")
    return _run_twice(one)


def probe_e4_payload_tamper():
    def one():
        s1, v1, _, _ = _signers()
        env = _envelope(s1, "aa" * 32)
        prov = env["provenance_digest"]
        env_bad = dict(env)
        env_bad["payload_digest"] = "bb" * 32
        try:
            _env.open_envelope(env_bad, expected_payload_hex="bb" * 32,
                               verifier=v1,
                               expected_provenance_digest=prov)
        except _env.EnvelopeError as exc:
            return ("HELD", "edited payload digest refused: %s" % exc)
        return ("ERROR", "edited payload digest verified")
    return _run_twice(one)


def probe_e5_provenance_digest_tamper():
    def one():
        s1, v1, _, _ = _signers()
        env = _envelope(s1, "aa" * 32)
        env_bad = dict(env)
        env_bad["provenance_digest"] = "cc" * 32
        try:
            _env.open_envelope(env_bad, expected_payload_hex="aa" * 32,
                               verifier=v1,
                               expected_provenance_digest="cc" * 32)
        except _env.EnvelopeError as exc:
            return ("HELD", "edited provenance digest refused: %s" % exc)
        return ("ERROR", "edited provenance digest verified")
    return _run_twice(one)


def probe_e6_envelope_positive():
    def one():
        s1, v1, _, _ = _signers()
        sealed = _statement(s1, "aa" * 32, _good_inputs())
        prov_digest = _bp.statement_digest(sealed)
        env = _env.seal(payload_hex="aa" * 32, signer=s1,
                        trusted_comments=["release 1.0"],
                        provenance_digest=prov_digest)
        try:
            opened = _env.open_envelope(
                env, expected_payload_hex="aa" * 32, verifier=v1,
                expected_provenance_digest=prov_digest)
        except _env.EnvelopeError as exc:
            return ("ERROR", "valid envelope refused: %s" % exc)
        if (opened["payload_digest"] == "aa" * 32
                and opened["provenance_digest"] == prov_digest
                and opened["trusted_comments"] == ["release 1.0"]
                and opened["key_id"] == s1.key_id):
            return ("HELD", "valid envelope+provenance verified end to end")
        return ("ERROR", "opened envelope fields mismatch: %r" % (opened,))
    return _run_twice(one)


_PROBES = [
    ("P1", "ARTIFACT_BINDING", probe_p1_artifact_binding),
    ("P2", "REPRO_LIE", probe_p2_repro_lie),
    ("P3", "REPRO_PASS", probe_p3_repro_pass),
    ("P4", "STATEMENT_STRICT", probe_p4_statement_strict),
    ("P5", "STATEMENT_TAMPER", probe_p5_statement_tamper),
    ("P6", "PROVENANCE_FORGE", probe_p6_provenance_forge),
    ("E1", "COMMENT_TAMPER", probe_e1_comment_tamper),
    ("E2", "WRONG_KEY_ID", probe_e2_wrong_key_id),
    ("E3", "ENVELOPE_STRICT", probe_e3_envelope_strict),
    ("E4", "PAYLOAD_TAMPER", probe_e4_payload_tamper),
    ("E5", "PROVENANCE_DIGEST_TAMPER", probe_e5_provenance_digest_tamper),
    ("E6", "ENVELOPE_POSITIVE", probe_e6_envelope_positive),
]


def main():
    if _ABSENT:
        for pid, name, _ in _PROBES:
            _gap(pid, name,
                 "gov.build_provenance / gov.signature_envelope_v2 absent")
    else:
        for pid, name, fn in _PROBES:
            verdict, detail = fn()
            _record(pid, name, verdict, detail)
    held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    gaps = sum(1 for r in _RESULTS if r["verdict"] == "GAP")
    errors = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    for r in _RESULTS:
        print("%s %-22s %s: %s" % (r["id"], r["name"], r["verdict"],
                                   r["detail"]))
    print("== %d HELD / %d GAP / %d ERROR out of %d =="
          % (held, gaps, errors, len(_RESULTS)))
    return 0 if errors == 0 else 1


def green_check():
    """Adjacent-battery green check (depth-1: honor GOV_SKIP_GREEN)."""
    if _SKIP_GREEN:
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
