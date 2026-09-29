#!/usr/bin/env python3
"""Wave-204 lane C red-team probes: build-provenance verifier.

Break-first battery per the diagnosing-bugs skill. Pattern lineage:
in-toto artifact rules (STEAL: terminal-DISALLOW discipline, REQUIRE /
MATCH digest-bound step chaining -- re-implemented stdlib-only, nothing
vendored) and Nix reproducibility verification (ADAPT: double-build
check, input-closure hash as identity, signed binary substitution).

The pristine tree has the provenance RECORD (gov.build_provenance,
wave-202 lane B) but NO provenance VERIFIER: gov.provenance_verifier
is absent. Each probe attacks that gap:

  V1  CHAIN_POSITIVE     complete two-step chain (REQUIRE + MATCH +
                         terminal DISALLOW) verifies
  V2  MISSING_RECORD     REQUIRE for an artifact with no sealed
                         statement -> refused
  V3  DIGEST_MISMATCH    artifact digest != statement's pinned digest
                         -> refused
  V4  RECEIPT_SWAP       two digest receipts swapped between steps ->
                         caught (the wave-178 falsifiable probe)
  V5  TERMINAL_DISALLOW  artifact not covered by any rule -> refused;
                         rule set without terminal DISALLOW -> refused
                         (lint discipline, fail-closed)
  V6  DOUBLE_BUILD       deterministic input that does not rebuild
                         twice to the same digest -> refused; rebuilder
                         digest != recorded digest -> refused
  V7  CLOSURE_DRIFT      observed input closure != statement's declared
                         inputs -> refused
  V8  UNSIGNED_PREBUILT  prebuilt artifact with no sealed statement ->
                         refused (signed binary substitution)

On the pristine tree every probe reports GAP (module absent -- genuine
red). After the fix all must flip to HELD.

Verdicts: HELD (defense held), GAP (gap demonstrated -- the red phase),
ERROR only on harness failure (a verdict changing between the two
deterministic runs, an unexpected exception).

Deterministic: fixed seeds for Ed25519 signers; every probe runs twice
and a verdict change is an ERROR. Synthetic/local only.
``GOV_SKIP_GREEN=1`` is honored (green check records a skip instead of
spawning sub-batteries).
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import build_provenance as _bp
    from gov import provenance_verifier as _pv
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


def _held(probe_id, name, detail):
    _record(probe_id, name, "HELD", detail)


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


def _seal(signer, artifact_hex, inputs):
    stmt = _bp.ProvenanceStatement(
        builder="ci-builder-1",
        recipe="repo@sha256:" + "ab" * 32,
        inputs=inputs,
        artifact_hex=artifact_hex,
        built_at=1700000000,
    )
    return stmt.seal(signer)


def _inp(name, digest_char, deterministic=True):
    return _bp.ProvenanceInput(name=name,
                               digest_hex=digest_char * 64,
                               deterministic=deterministic)


def _two_step():
    """Two-step chain fixture: step A builds lib.o, step B builds app.

    Returns (named_statements, artifacts, verifiers). named_statements
    is the trusted name -> statement binding (layout analog).
    """
    s1, v1, _, _ = _signers()
    lib_inputs = [_inp("src/lib.c", "a"), _inp("build-flags", "b")]
    lib_digest = "c0" * 32
    sealed_a = _seal(s1, lib_digest, lib_inputs)
    app_inputs = [_inp("lib.o", "c", deterministic=True),
                  _inp("src/main.c", "d")]
    app_digest = "e0" * 32
    sealed_b = _seal(s1, app_digest, app_inputs)
    named = {"lib.o": sealed_a, "app": sealed_b}
    artifacts = {"lib.o": lib_digest, "app": app_digest}
    verifiers = {v1.key_id: v1}
    return named, artifacts, verifiers


def _expect_refusal(fn):
    """fn must raise _pv.ProvenanceVerifierError; anything else is ERROR."""
    try:
        fn()
    except _pv.ProvenanceVerifierError as exc:
        return ("HELD", "refused: %s" % exc)
    except Exception as exc:  # noqa: BLE001 -- harness must name surprises
        return ("ERROR", "unexpected %s: %s"
                % (type(exc).__name__, exc))
    return ("ERROR", "NOT refused -- attack succeeded")


# -- verifier probes -----------------------------------------------------

def probe_v1_chain_positive():
    def one():
        named, artifacts, verifiers = _two_step()
        # REQUIRE verifies lib.o's statement and consumes it; MATCH
        # verifies app's statement AND binds its digest to the expected
        # value (pinned by the deployment manifest); terminal DISALLOW
        # closes the queue.
        rules = [("REQUIRE", "lib.o"),
                 ("MATCH", "app", "e0" * 32),
                 ("DISALLOW",)]
        try:
            res = _pv.verify_provenance_chain(
                dict(named), dict(artifacts), rules, verifiers)
        except _pv.ProvenanceVerifierError as exc:
            return ("ERROR", "valid chain refused: %s" % exc)
        if sorted(res["consumed"]) != ["app", "lib.o"]:
            return ("ERROR", "bad consumption report: %r" % (res,))
        return ("HELD", "two-step chain verified")
    return _run_twice(one)


def probe_v2_missing_record():
    def one():
        named, artifacts, verifiers = _two_step()
        # "app" has no statement bound in the trusted mapping -> refused.
        del named["app"]
        rules = [("REQUIRE", "lib.o"), ("REQUIRE", "app"), ("DISALLOW",)]
        return _expect_refusal(lambda: _pv.verify_provenance_chain(
            dict(named), dict(artifacts), rules, verifiers))
    return _run_twice(one)


def probe_v3_digest_mismatch():
    def one():
        named, artifacts, verifiers = _two_step()
        # Receipt claims a different digest than the statement pins.
        tampered = dict(artifacts)
        tampered["lib.o"] = "ff" * 32
        rules = [("REQUIRE", "lib.o"), ("REQUIRE", "app"), ("DISALLOW",)]
        return _expect_refusal(lambda: _pv.verify_provenance_chain(
            dict(named), tampered, rules, verifiers))
    return _run_twice(one)


def probe_v4_receipt_swap():
    """The wave-178 falsifiable probe: swap two digest receipts.

    Statement A pins lib.o->c0..., statement B pins app->e0....
    The receipts claim lib.o->e0... and app->c0... (swapped).
    Verification must catch it.
    """
    def one():
        named, artifacts, verifiers = _two_step()
        swapped = {"lib.o": artifacts["app"], "app": artifacts["lib.o"]}
        rules = [("REQUIRE", "lib.o"), ("REQUIRE", "app"), ("DISALLOW",)]
        return _expect_refusal(lambda: _pv.verify_provenance_chain(
            dict(named), swapped, rules, verifiers))
    return _run_twice(one)


def probe_v5_terminal_disallow():
    def one():
        named, artifacts, verifiers = _two_step()
        # (a) artifact not covered by any rule -> terminal DISALLOW fires.
        with_extra = dict(artifacts)
        with_extra["mystery.bin"] = "11" * 32
        rules = [("REQUIRE", "lib.o"), ("REQUIRE", "app"), ("DISALLOW",)]
        r1 = _expect_refusal(lambda: _pv.verify_provenance_chain(
            dict(named), with_extra, rules, verifiers))
        if r1[0] != "HELD":
            return ("ERROR", "uncovered artifact not refused: %s" % (r1,))
        # (b) rule set WITHOUT terminal DISALLOW -> lint discipline fails
        # closed even when every artifact is consumed.
        no_disallow = [("REQUIRE", "lib.o"), ("REQUIRE", "app")]
        r2 = _expect_refusal(lambda: _pv.verify_provenance_chain(
            dict(named), dict(artifacts), no_disallow, verifiers))
        if r2[0] != "HELD":
            return ("ERROR", "missing terminal DISALLOW not refused: %s"
                    % (r2,))
        return ("HELD", "terminal DISALLOW enforced both ways")
    return _run_twice(one)


def probe_v6_double_build():
    def one():
        s1, v1, _, _ = _signers()
        sealed = _seal(s1, "aa" * 32,
                       [_inp("src/lib.c", "a"),
                        _inp("random-seed", "b", deterministic=False)])
        verifiers = {v1.key_id: v1}
        # (a) deterministic input rebuilds to a DIFFERENT digest on the
        # second build -> non-deterministic despite the claim -> refused.
        calls = {"n": 0}

        def flaky(name):
            calls["n"] += 1
            return "a" * 64 if calls["n"] == 1 else "a1" * 32

        r1 = _expect_refusal(lambda: _pv.verify_double_build(
            sealed, flaky, v1, "aa" * 32))
        if r1[0] != "HELD":
            return ("ERROR", "flaky double build not refused: %s" % (r1,))
        # (b) stable but WRONG digest -> reproducibility lie -> refused.
        r2 = _expect_refusal(lambda: _pv.verify_double_build(
            sealed, lambda name: "zz" * 31 + "z0", v1, "aa" * 32))
        if r2[0] != "HELD":
            return ("ERROR", "reproducibility lie not refused: %s" % (r2,))
        # (c) honest rebuilder passes.
        try:
            res = _pv.verify_double_build(
                sealed, lambda name: {"src/lib.c": "a" * 64}[name],
                v1, "aa" * 32)
        except _pv.ProvenanceVerifierError as exc:
            return ("ERROR", "honest double build refused: %s" % exc)
        if res["checked"] != ["src/lib.c"] or \
                res["unchecked"] != ["random-seed"]:
            return ("ERROR", "bad double-build report: %r" % (res,))
        return ("HELD", "double build verified; lies refused")
    return _run_twice(one)


def probe_v7_closure_drift():
    def one():
        s1, v1, _, _ = _signers()
        sealed = _seal(s1, "aa" * 32,
                       [_inp("src/lib.c", "a"), _inp("build-flags", "b")])
        # Observed closure drifts (build-flags digest changed) -> refused.
        drifted = [("src/lib.c", "a" * 64), ("build-flags", "cc" * 32)]
        r1 = _expect_refusal(lambda: _pv.verify_input_closure(
            sealed, drifted, v1, "aa" * 32))
        if r1[0] != "HELD":
            return ("ERROR", "closure drift not refused: %s" % (r1,))
        # Honest observed closure passes and names its digest.
        honest = [("src/lib.c", "a" * 64), ("build-flags", "b" * 64)]
        try:
            res = _pv.verify_input_closure(sealed, honest, v1, "aa" * 32)
        except _pv.ProvenanceVerifierError as exc:
            return ("ERROR", "honest closure refused: %s" % exc)
        if res["closure"] != _pv.input_closure_digest(sealed):
            return ("ERROR", "closure digest mismatch: %r" % (res,))
        # Statement for a different artifact -> binding refused.
        r3 = _expect_refusal(lambda: _pv.verify_input_closure(
            sealed, honest, v1, "ff" * 32))
        if r3[0] != "HELD":
            return ("ERROR", "wrong-artifact closure not refused: %s"
                    % (r3,))
        return ("HELD", "closure drift refused; honest closure accepted")
    return _run_twice(one)


def probe_v8_unsigned_prebuilt():
    def one():
        s1, v1, _, _ = _signers()
        sealed = _seal(s1, "aa" * 32, [_inp("src/lib.c", "a")])
        # (a) no statement at all -> refused.
        r1 = _expect_refusal(lambda: _pv.verify_prebuilt(
            "lib.o", "aa" * 32, None, v1))
        if r1[0] != "HELD":
            return ("ERROR", "unsigned prebuilt not refused: %s" % (r1,))
        # (b) statement for a DIFFERENT digest -> refused.
        r2 = _expect_refusal(lambda: _pv.verify_prebuilt(
            "lib.o", "ff" * 32, sealed, v1))
        if r2[0] != "HELD":
            return ("ERROR", "wrong-digest prebuilt not refused: %s"
                    % (r2,))
        # (c) valid signed prebuilt passes.
        try:
            _pv.verify_prebuilt("lib.o", "aa" * 32, sealed, v1)
        except _pv.ProvenanceVerifierError as exc:
            return ("ERROR", "signed prebuilt refused: %s" % exc)
        return ("HELD", "unsigned prebuilts refused")
    return _run_twice(one)


_PROBES = [
    ("V1", "CHAIN_POSITIVE", probe_v1_chain_positive),
    ("V2", "MISSING_RECORD", probe_v2_missing_record),
    ("V3", "DIGEST_MISMATCH", probe_v3_digest_mismatch),
    ("V4", "RECEIPT_SWAP", probe_v4_receipt_swap),
    ("V5", "TERMINAL_DISALLOW", probe_v5_terminal_disallow),
    ("V6", "DOUBLE_BUILD", probe_v6_double_build),
    ("V7", "CLOSURE_DRIFT", probe_v7_closure_drift),
    ("V8", "UNSIGNED_PREBUILT", probe_v8_unsigned_prebuilt),
]


def main():
    if _ABSENT:
        for pid, name, _ in _PROBES:
            _gap(pid, name, "gov.provenance_verifier absent")
    else:
        for pid, name, fn in _PROBES:
            verdict, detail = fn()
            _record(pid, name, verdict, detail)
    held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    gaps = sum(1 for r in _RESULTS if r["verdict"] == "GAP")
    errors = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    for r in _RESULTS:
        print("%s %-18s %s: %s" % (r["id"], r["name"], r["verdict"],
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
