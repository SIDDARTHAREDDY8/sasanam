"""Compile-policy-once + strict-xfail battery (wave-217, lane B).

sigstore policy-controller DISCIPLINE (idea only, no upstream source
vendored): authoring errors fail at COMPILE time; one compiled
verifier serves many artifacts. sigstore attestation-verify
DISCIPLINE (idea only): strict-xfail -- a declared expected-failure
that now PASSES fails the run loudly.

Pristine tree: gov/policy_compile.py and gov/strict_xfail.py do not
exist -> every probe GAP (honest red). Fixed tree: every probe HELD.

Probes cover:
  * malformed identity-policy specs raise PolicyAuthoringError AT
    COMPILE (unknown predicate, empty anyOf/allOf, unsafeAllow
    without a reason)
  * malformed artifact rulesets raise ArtifactRuleError AT COMPILE
    (missing/misplaced DISALLOW, bad digest pin)
  * compiled forms evaluate with NO authoring-error class reachable
    (garbage claims -> error VERDICT, not an exception; evaluation
    signatures take no spec/rules parameter)
  * compiled ruleset never re-parses (post-compile spec mutation is
    invisible; fingerprint stable)
  * 100-artifact reuse: identical structure, constant digest
  * legacy report equality: compiled == verify_artifacts byte-identical
  * artifact DATA errors still fail closed at EVALUATION time
  * strict-xfail: unexpected pass fails loudly, declared break
    recorded, undeclared break fails, error never expected, stale
    xfail names and duplicate probes are loud

Verdict vocabulary: HELD (attack/shape refused or discipline holds),
BREAK (genuine finding, file it), GAP (defense absent -- honest red).

Stdlib only. Deterministic: no clock, no randomness, no I/O, no env.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import inspect
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

try:
    from gov import policy_compile as pc
    from gov import strict_xfail as sx
    _HAVE = True
except ImportError:
    _HAVE = False

_RESULTS = []
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        def run():
            if not _HAVE:
                return (name, "GAP", "gov.policy_compile/gov.strict_xfail absent")
            try:
                verdict, detail = fn()
            except Exception as e:  # noqa: BLE001 - battery must not die
                return (name, "ERROR", "%s: %s"
                        % (type(e).__name__, str(e)[:160]))
            if isinstance(verdict, tuple):
                verdict, detail = verdict
            assert verdict in ("HELD", "GAP", "BREAK"), verdict
            return (name, verdict, detail)
        _PROBE_FNS[name] = run
        return run
    return deco


# ------------------------------------------------------------------ helpers

_CLAIMS = {
    "iss": "https://token.actions.githubusercontent.com",
    "sub": "repo:acme/app:ref:refs/heads/main",
    "sans": {"rfc822Name": ["ci@acme.dev"], "uri": [], "otherName": []},
    "extensions": {"1.3.6.1.4.1.99999.1": "builder-acme"},
}

_ID_SPEC = {"allOf": [
    {"oidcIssuer": "https://token.actions.githubusercontent.com"},
    {"identity": {"identity": "ci@acme.dev",
                  "issuer": "https://token.actions.githubusercontent.com"}},
    {"extension": {"oid": "1.3.6.1.4.1.99999.1", "value": "builder-acme"}},
]}

_RULE_SPECS = [
    ("REQUIRE", "src.tar"),
    ("CREATE", "build/*.whl"),
    ("DISALLOW",),
]


def _artifacts(seed):
    mats = {"src.tar": hashlib.sha256(b"mats-%d" % seed).hexdigest()}
    prods = {"build/pkg-%d.whl" % seed:
             hashlib.sha256(b"prods-%d" % seed).hexdigest()}
    return mats, prods


# ------------------------------------------------- identity compile probes

@_probe("identity_unknown_predicate_compile")
def _p_id_unknown():
    try:
        pc.compile_policy({"frobnicate": {"x": 1}})
    except Exception as e:  # noqa: BLE001
        from gov import identity_policy as ip
        if isinstance(e, ip.PolicyAuthoringError):
            return ("HELD", "unknown predicate refused at compile: %s"
                    % type(e).__name__)
        return ("BREAK", "wrong error class at compile: %s" % type(e).__name__)
    return ("BREAK", "unknown predicate compiled without error")


@_probe("identity_empty_anyof_compile")
def _p_id_anyof():
    try:
        pc.compile_policy({"anyOf": []})
    except Exception as e:  # noqa: BLE001
        from gov import identity_policy as ip
        if isinstance(e, ip.PolicyAuthoringError):
            return ("HELD", "empty anyOf refused at compile")
        return ("BREAK", "wrong error class: %s" % type(e).__name__)
    return ("BREAK", "empty anyOf compiled without error")


@_probe("identity_empty_allof_compile")
def _p_id_allof():
    try:
        pc.compile_policy({"allOf": []})
    except Exception as e:  # noqa: BLE001
        from gov import identity_policy as ip
        if isinstance(e, ip.PolicyAuthoringError):
            return ("HELD", "empty allOf refused at compile")
        return ("BREAK", "wrong error class: %s" % type(e).__name__)
    return ("BREAK", "empty allOf compiled without error")


@_probe("identity_unsafe_no_reason_compile")
def _p_id_unsafe():
    try:
        pc.compile_policy({"unsafeAllow": ""})
    except Exception as e:  # noqa: BLE001
        from gov import identity_policy as ip
        if isinstance(e, ip.PolicyAuthoringError):
            return ("HELD", "reasonless unsafeAllow refused at compile")
        return ("BREAK", "wrong error class: %s" % type(e).__name__)
    return ("BREAK", "reasonless unsafeAllow compiled without error")


@_probe("identity_garbage_claims_no_authoring_error")
def _p_id_garbage():
    from gov import identity_policy as ip
    compiled = pc.compile_policy(_ID_SPEC)
    # Garbage claims must fail closed WITHOUT an authoring exception:
    # authoring validation is over, only data is judged. An "error"
    # verdict (could not judge) or a "fail" verdict (judged and
    # rejected, e.g. a non-str iss) are both fail-closed at admit().
    for bad in (None, 42, "claims", {"iss": 1}, []):
        try:
            verdict = compiled.verify(bad)
        except ip.PolicyAuthoringError:
            return ("BREAK", "authoring error leaked at evaluation")
        except Exception:
            return ("BREAK", "unexpected exception class at evaluation")
        if verdict.verdict not in ("error", "fail"):
            return ("BREAK", "garbage claims passed: %s" % verdict.verdict)
        # admit() must refuse fail AND error alike.
        try:
            compiled.admit(bad)
        except ip.PolicyViolation:
            pass
        else:
            return ("BREAK", "admit() did not refuse garbage claims")
    return ("HELD", "5 garbage claim shapes fail closed, no raise")


@_probe("identity_no_spec_param_at_evaluation")
def _p_id_nospec():
    from gov import identity_policy as ip
    compiled = pc.compile_policy(_ID_SPEC)
    for meth in ("verify", "admit"):
        params = inspect.signature(getattr(compiled, meth)).parameters
        for forbidden in ("spec", "policy", "predicate", "rules",
                          "rule_specs"):
            if forbidden in params:
                return ("BREAK",
                        "%s() takes %r: unvalidated shapes smuggle-able"
                        % (meth, forbidden))
    assert isinstance(compiled, pc.CompiledIdentityPolicy)
    v = compiled.verify(_CLAIMS)
    if v.verdict != "pass":
        return ("BREAK", "valid claims did not pass: %s" % v.code)
    rep = compiled.admit(_CLAIMS)
    if rep["verdict"] != "pass" or "fingerprint" not in rep:
        return ("BREAK", "admit report malformed")
    return ("HELD", "evaluation takes claims only; valid claims pass")


@_probe("identity_compile_reuse_100_claims")
def _p_id_reuse():
    compiled = pc.compile_policy(_ID_SPEC)
    fp = compiled.fingerprint()
    codes = set()
    for i in range(100):
        claims = dict(_CLAIMS)
        claims["sub"] = "repo:acme/app:run:%d" % i
        v = compiled.verify(claims)
        codes.add((v.verdict, v.code))
        if compiled.fingerprint() != fp:
            return ("BREAK", "fingerprint drifted across evaluations")
    if codes != {("pass", "pass")}:
        return ("BREAK", "inconsistent verdicts: %r" % (codes,))
    return ("HELD", "100 claims, one compiled verifier, identical pass")


# -------------------------------------------------- ruleset compile probes

@_probe("rules_missing_disallow_compile")
def _p_r_nodisallow():
    from gov import artifact_rules as ar
    try:
        pc.compile_policy([("REQUIRE", "a")])
    except ar.ArtifactRuleError:
        return ("HELD", "DISALLOW-less ruleset refused at compile")
    except Exception as e:  # noqa: BLE001
        return ("BREAK", "wrong error class: %s" % type(e).__name__)
    return ("BREAK", "DISALLOW-less ruleset compiled without error")


@_probe("rules_mid_disallow_compile")
def _p_r_middisallow():
    from gov import artifact_rules as ar
    try:
        pc.compile_policy([("DISALLOW",), ("REQUIRE", "a"), ("DISALLOW",)])
    except ar.ArtifactRuleError:
        return ("HELD", "non-terminal DISALLOW refused at compile")
    except Exception as e:  # noqa: BLE001
        return ("BREAK", "wrong error class: %s" % type(e).__name__)
    return ("BREAK", "non-terminal DISALLOW compiled without error")


@_probe("rules_bad_digest_pin_compile")
def _p_r_baddigest():
    from gov import artifact_rules as ar
    try:
        pc.compile_policy([("MATCH", "a", "not-hex"), ("DISALLOW",)])
    except ar.ArtifactRuleError:
        return ("HELD", "non-hex digest pin refused at compile")
    except Exception as e:  # noqa: BLE001
        return ("BREAK", "wrong error class: %s" % type(e).__name__)
    return ("BREAK", "non-hex digest pin compiled without error")


@_probe("rules_no_reparse_after_mutation")
def _p_r_noreparse():
    specs = [list(s) for s in _RULE_SPECS]
    compiled = pc.compile_policy([tuple(s) for s in specs])
    fp = compiled.fingerprint()
    mats, prods = _artifacts(1)
    before = compiled.evaluate(mats, prods)
    # Mutate the ORIGINAL spec list after compile: a compiled verifier
    # that re-parsed would change behavior. It must not.
    specs.append(("DISALLOW",))
    specs[0] = ("REQUIRE", "something-else")
    after = compiled.evaluate(mats, prods)
    if before != after:
        return ("BREAK", "post-compile spec mutation changed evaluation")
    if compiled.fingerprint() != fp:
        return ("BREAK", "fingerprint changed after spec mutation")
    return ("HELD", "spec mutation invisible; fingerprint stable")


@_probe("rules_100_artifacts_identical")
def _p_r_100():
    compiled = pc.compile_policy(_RULE_SPECS)
    digests = set()
    for i in range(100):
        mats, prods = _artifacts(i)
        rep = compiled.evaluate(mats, prods, context="run-%d" % i)
        if not rep["ok"]:
            return ("BREAK", "evaluation %d failed" % i)
        digests.add(rep["rule_set_digest"])
    if len(digests) != 1:
        return ("BREAK", "rule_set_digest not constant: %d" % len(digests))
    return ("HELD", "100 evaluations, constant digest, all ok")


@_probe("rules_legacy_report_equality")
def _p_r_legacy():
    from gov import artifact_rules as ar
    compiled = pc.compile_policy(_RULE_SPECS)
    for i in range(10):
        mats, prods = _artifacts(i)
        legacy = ar.verify_artifacts(mats, prods, _RULE_SPECS,
                                     context="c%d" % i)
        new = compiled.evaluate(mats, prods, context="c%d" % i)
        if legacy != new:
            return ("BREAK", "compiled report != legacy report at %d" % i)
    return ("HELD", "10/10 compiled reports byte-identical to legacy")


@_probe("rules_data_error_stays_evaluation")
def _p_r_dataerr():
    from gov import artifact_rules as ar
    compiled = pc.compile_policy(_RULE_SPECS)
    # Bad DATA (not bad policy) must still fail closed AT EVALUATION.
    try:
        compiled.evaluate({"src.tar": "not-a-digest"}, {})
    except ar.ArtifactRuleError:
        return ("HELD", "malformed digest refused at evaluation")
    except Exception as e:  # noqa: BLE001
        return ("BREAK", "wrong error class: %s" % type(e).__name__)
    return ("BREAK", "malformed digest accepted")


@_probe("rules_no_rules_param_at_evaluation")
def _p_r_norules():
    params = inspect.signature(
        pc.CompiledArtifactRuleset.evaluate).parameters
    for forbidden in ("rule_specs", "spec", "rules", "policy"):
        if forbidden in params:
            return ("BREAK",
                    "evaluate() takes %r: unvalidated rules smuggle-able"
                    % forbidden)
    return ("HELD", "evaluate(materials, products, context) only")


# ------------------------------------------------------- strict-xfail

@_probe("xfail_unexpected_pass_fails_loudly")
def _p_x_unexp():
    m = sx.XFailManifest("b", xfail=("healed",))
    rep = m.run([("healed", lambda: "held")])
    if rep.ok:
        return ("BREAK", "unexpected pass did not fail the run")
    try:
        rep.raise_if_bad()
    except sx.UnexpectedPassError:
        return ("HELD", "UnexpectedPassError raised loudly")
    return ("BREAK", "wrong exception class")


@_probe("xfail_declared_break_recorded")
def _p_x_declared():
    m = sx.XFailManifest("b", xfail=("known",))
    rep = m.run([("known", lambda: "break"), ("fine", lambda: "held")])
    if not rep.ok:
        return ("BREAK", "declared break should keep the run green")
    if rep.expected_breaks != ["known"]:
        return ("BREAK", "declared break not recorded: %r" % (rep.records,))
    rep.raise_if_bad()  # must not raise
    return ("HELD", "declared break recorded, run green")


@_probe("xfail_undeclared_break_fails")
def _p_x_undecl():
    m = sx.XFailManifest("b")
    rep = m.run([("sneaky", lambda: "break")])
    if rep.ok:
        return ("BREAK", "undeclared break did not fail the run")
    try:
        rep.raise_if_bad()
    except sx.UnexpectedBreakError:
        return ("HELD", "UnexpectedBreakError raised loudly")
    return ("BREAK", "wrong exception class")


@_probe("xfail_error_never_expected")
def _p_x_error():
    m = sx.XFailManifest("b", xfail=("flaky",))
    rep = m.run([("flaky", lambda: "error")])
    if rep.ok:
        return ("BREAK", "error on declared xfail treated as expected")
    if rep.unexpected_breaks != ["flaky"]:
        return ("BREAK", "error not in unexpected_breaks")
    return ("HELD", "error verdict never counts as expected")


@_probe("xfail_stale_name_loud")
def _p_x_stale():
    m = sx.XFailManifest("b", xfail=("never-runs",))
    try:
        m.run([("other", lambda: "held")])
    except sx.ProbeError:
        return ("HELD", "stale xfail name refused loudly")
    return ("BREAK", "stale xfail name accepted silently")


@_probe("xfail_duplicate_probe_loud")
def _p_x_dup():
    m = sx.XFailManifest("b")
    try:
        m.run([("p", lambda: "held"), ("p", lambda: "held")])
    except sx.ProbeError:
        return ("HELD", "duplicate probe name refused loudly")
    return ("BREAK", "duplicate probe name accepted silently")


# ------------------------------------------------------------------ green

def _green_check():
    """Depth-1: run the adjacent identity-policy battery + the two unit
    suites once, with GOV_SKIP_GREEN=1 so nothing nests."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1, no nested suites)")]
    import subprocess
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    notes = []
    py = sys.executable
    for label, cmd in (
        ("w215-identity-policy-battery",
         [py, os.path.join(_REPO_ROOT, "evals",
                           "w215_identity_policy_probes.py")]),
        ("test_identity_policy",
         [py, "-m", "unittest", "tests.test_identity_policy"]),
        ("test_artifact_rules",
         [py, "-m", "unittest", "tests.test_artifact_rules"]),
    ):
        try:
            r = subprocess.run(cmd, env=env, capture_output=True,
                               text=True, timeout=600, cwd=_REPO_ROOT)
        except Exception as e:  # noqa: BLE001
            notes.append((label, "ERROR", "%s" % e))
            continue
        tail = (r.stdout + r.stderr)[-400:]
        if r.returncode == 0:
            notes.append((label, "HELD", tail.strip().splitlines()[-1]
                          if tail.strip() else "exit 0"))
        else:
            notes.append((label, "ERROR", "exit %d: %s"
                          % (r.returncode, tail.strip().splitlines()[-1]
                             if tail.strip() else "")))
    return notes


# ------------------------------------------------------------------- main

def main():
    names = sorted(_PROBE_FNS)
    rows = [(_PROBE_FNS[n]()) for n in names]
    held = sum(1 for _, v, _ in rows if v == "HELD")
    gap = sum(1 for _, v, _ in rows if v == "GAP")
    brk = sum(1 for _, v, _ in rows if v == "BREAK")
    err = sum(1 for _, v, _ in rows if v == "ERROR")
    print("== w217 compile-once battery: %d probes ==" % len(rows))
    for name, verdict, detail in rows:
        print("[%s] %s: %s" % (verdict, name, detail))
    print("-- %d HELD / %d GAP / %d BREAK / %d ERROR" % (held, gap, brk,
                                                        err))
    # determinism: second pass must be verdict-identical
    rows2 = [(_PROBE_FNS[n]()) for n in names]
    det = all(a[1] == b[1] for a, b in zip(rows, rows2))
    print("-- determinism: %s" % ("PASS" if det else "FAIL"))
    for label, verdict, detail in _green_check():
        print("[%s] green %s: %s" % (verdict, label, detail))
    if brk or err or not det:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
