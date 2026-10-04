"""Wave-296 lane 5 red-first battery: first-class decision traces.

Builds gov/decision_trace.py (permify/permify STEAL, Apache-2.0,
mechanism only, stdlib only): every policy decide evaluation emits a
signed per-edge decision trace -- decision_id, policy version +
snapshot token (reproducibility contract), ordered evaluation edges,
input DIGESTS (never raw inputs), final decision, signature.
verify_trace checks the signature and replays the edges against the
recorded version/snapshot: forgery / replay-mismatch / invalid are
coded refusals. Composes with gov/tool_call_policy.py decide
(additive: traced by default when a DecisionTracer is bound, documented
opt-out; unbound decide unchanged; a broken tracer never breaks a
decision).

Base: wave-295 merge 10777555 (verified via git rev-parse HEAD before
work).

Pin 1750 -> 1753 (+3 decision-trace-*); the repoint is tree-wide
(value-token-only, code/comment splitter, history comments extended),
so adjacent batteries' own pin probes stay green.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g296-dt && TMPDIR=/var/tmp/g296-dt \
    ~/workspace/.gov-venv/bin/python evals/w296_decision_trace_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g296-dtb \
    ~/workspace/.gov-venv/bin/python evals/w296_decision_trace_probes.py
"""

import os
import subprocess
import sys

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-296 lane 5: pin 1750 -> 1753 (+3 decision-trace-forgery,
# decision-trace-invalid, decision-trace-replay-mismatch).
TAXONOMY_PIN = 2018 # Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded)



try:
    from gov import decision_trace as DT
    from gov import tool_call_policy as TCP
    from gov import decision_codes
    from gov import ed25519 as _ed
except ImportError:
    DT = None
    TCP = None
    decision_codes = None
    _ed = None


class _Break(Exception):
    """A probe that fails because the feature is absent or wrong."""


def _need():
    if DT is None or TCP is None:
        raise _Break("gov.decision_trace / tool_call_policy trace wiring "
                     "absent on this tree")


_SEED = bytes(range(32))
_SEED2 = bytes([255 - b for b in range(32)])


def _doc(mode="enforce", rules=None):
    return {
        "format": "sasanam-tool-call-policy/v1",
        "name": "trace-battery",
        "selector": {"agents": ["agent-a"]},
        "mode": mode,
        "rules": rules if rules is not None else [
            {"action": "DENY", "name": "no-shell", "tool": "shell",
             "operation": "exec", "severity": 3, "message": "no"},
            {"action": "ALLOW", "name": "read-ok", "tool": "fs",
             "operation": "read", "severity": 3, "message": "ok"},
        ],
    }


def _caller(ident="agent-a"):
    return {"identity": ident, "authenticated": True, "tags": []}


def _traced_policy(mode="enforce", version="v-test"):
    _need()
    pol = TCP.compile_policy(_doc(mode=mode))
    tracer = DT.DecisionTracer(_SEED, version)
    pol.bind_tracer(tracer)
    return pol, tracer


def _refused(fn, code):
    try:
        fn()
    except Exception as e:  # noqa: BLE001 -- assert coded refusal
        got = getattr(e, "code", None)
        if got != code:
            raise _Break("expected code %r, got %r (%s)"
                         % (code, got, e))
        return
    raise _Break("expected coded refusal %r, nothing raised" % (code,))


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def p_pin_count():
    _need()
    n = len(decision_codes.TAXONOMY)
    if n != TAXONOMY_PIN:
        raise _Break("taxonomy %d != pin %d" % (n, TAXONOMY_PIN))


def p_pin_raw_literals():
    _need()
    import re
    src = open(os.path.join(REPO, "gov", "decision_codes.py")).read()
    codes = re.findall(r'''"code": '([^']+)'|"code": "([^"]+)"''', src)
    codes = [a or b for a, b in codes]
    if len(codes) != len(set(codes)):
        raise _Break("duplicate raw code literals")
    if codes != sorted(codes):
        raise _Break("raw code literals not sorted")
    if len(codes) != TAXONOMY_PIN:
        raise _Break("raw literals %d != pin %d" % (len(codes),
                                                    TAXONOMY_PIN))


def p_emit_signed_envelope():
    _need()
    tracer = DT.DecisionTracer(_SEED, "v1")
    env = tracer.emit("d1", "snap", [{"seq": 0, "layer": "authz",
                                      "rule": "allow[0]", "outcome": "allow",
                                      "reason": None}],
                      {"tool": "fs"}, "ALLOW", None)
    if not isinstance(env.get("trace"), dict) or \
            not isinstance(env.get("signature"), str):
        raise _Break("envelope shape wrong: %r" % (env,))
    body = env["trace"]
    for field in ("decision_id", "subsystem", "policy_version",
                  "snapshot_token", "edges", "inputs_digests",
                  "final_decision", "decided_at"):
        if field not in body:
            raise _Break("trace body missing %r" % (field,))


def p_verify_roundtrip():
    _need()
    pol, tracer = _traced_policy()
    d = pol.decide(_caller(), "fs", "read", {"path": "/x"})
    if d.trace is None:
        raise _Break("no trace attached to an ALLOW decision")
    body = DT.verify_trace(d.trace, tracer.pubkey_hex,
                           expected_policy_version="v-test",
                           expected_snapshot_token=pol.digest)
    if body["final_decision"]["verdict"] != "ALLOW":
        raise _Break("roundtrip verdict wrong")


def p_deny_trace_verifies():
    _need()
    pol, tracer = _traced_policy()
    d = pol.decide(_caller(), "shell", "exec", {})
    if d.verdict != "DENY" or d.trace is None:
        raise _Break("expected traced DENY, got %r" % (d.verdict,))
    DT.verify_trace(d.trace, tracer.pubkey_hex)
    edges = d.trace["trace"]["edges"]
    if not any(e["outcome"] == "deny" for e in edges):
        raise _Break("deny trace has no deny edge: %r" % (edges,))


def p_snapshot_is_policy_digest():
    _need()
    pol, tracer = _traced_policy()
    d = pol.decide(_caller(), "fs", "read", {})
    if d.trace["trace"]["snapshot_token"] != pol.digest:
        raise _Break("snapshot token is not the policy digest")
    if d.trace["trace"]["policy_version"] != "v-test":
        raise _Break("policy version not recorded")


def p_inputs_are_digests_not_raw():
    _need()
    pol, tracer = _traced_policy()
    secretish = "sk-live-SECRET-VALUE-12345"
    d = pol.decide(_caller(), "fs", "read", {"token": secretish})
    blob = str(d.trace["trace"]["inputs_digests"])
    if secretish in blob:
        raise _Break("raw input value leaked into the trace")
    if set(d.trace["trace"]["inputs_digests"]) != \
            {"caller", "tool", "operation", "args"}:
        raise _Break("inputs_digests keys wrong")


def p_unbound_decide_works_untraced():
    _need()
    pol = TCP.compile_policy(_doc())
    d = pol.decide(_caller(), "fs", "read", {})
    if d.verdict != "ALLOW":
        raise _Break("unbound decide verdict changed: %r" % (d.verdict,))
    if d.trace is not None:
        raise _Break("unbound decide must not attach a trace")


def p_opt_out_disables_trace():
    _need()
    pol, tracer = _traced_policy()
    pol.set_trace_enabled(False)
    d = pol.decide(_caller(), "fs", "read", {})
    if d.trace is not None:
        raise _Break("opt-out did not disable tracing")
    if d.verdict != "ALLOW":
        raise _Break("opt-out changed the decision")
    pol.set_trace_enabled(True)
    d2 = pol.decide(_caller(), "fs", "read", {})
    if d2.trace is None:
        raise _Break("re-enable did not restore tracing")


def p_audit_would_deny_folds_allow():
    _need()
    pol, tracer = _traced_policy(mode="audit")
    d = pol.decide(_caller(), "shell", "exec", {})
    if d.verdict != "ALLOW":
        raise _Break("audit mode must not enforce; got %r" % (d.verdict,))
    if d.trace is None:
        raise _Break("audit-mode decision has no trace")
    edges = d.trace["trace"]["edges"]
    if not any(e["outcome"] == "would-deny" for e in edges):
        raise _Break("no would-deny edge: %r" % (edges,))
    DT.verify_trace(d.trace, tracer.pubkey_hex)  # fold => ALLOW


def p_fold_default_deny():
    _need()
    if DT.fold_edges([]) != "DENY":
        raise _Break("empty edges must fold to fail-closed DENY")
    if DT.fold_edges([{"seq": 0, "outcome": "no-match"},
                      {"seq": 1, "outcome": "pass"}]) != "DENY":
        raise _Break("no outcome edge must fold to DENY")


def p_broken_tracer_never_breaks_decide():
    _need()
    pol = TCP.compile_policy(_doc())
    tracer = DT.DecisionTracer(_SEED, "v1")
    pol.bind_tracer(tracer)
    tracer.emit = lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("tracer exploded"))
    d = pol.decide(_caller(), "fs", "read", {})
    if d.verdict != "ALLOW":
        raise _Break("broken tracer changed the decision")
    if d.trace is not None:
        raise _Break("broken tracer must leave trace None, not half-built")


def p_bad_seed_refused():
    _need()
    _refused(lambda: DT.DecisionTracer(b"short", "v1"),
             DT.INVALID)
    _refused(lambda: DT.DecisionTracer("not-bytes-at-all", "v1"),
             DT.INVALID)


def p_forged_signature():
    _need()
    pol, tracer = _traced_policy()
    d = pol.decide(_caller(), "fs", "read", {})
    env = {"trace": d.trace["trace"],
           "signature": "00" * 64, "keyid": "decision-tracer"}
    _refused(lambda: DT.verify_trace(env, tracer.pubkey_hex), DT.FORGERY)


def p_wrong_key_forgery():
    _need()
    pol, tracer = _traced_policy()
    d = pol.decide(_caller(), "fs", "read", {})
    other = DT.DecisionTracer(_SEED2, "v1")
    _refused(lambda: DT.verify_trace(d.trace, other.pubkey_hex),
             DT.FORGERY)


def p_tampered_body_forgery():
    _need()
    pol, tracer = _traced_policy()
    d = pol.decide(_caller(), "fs", "read", {})
    import copy
    env = copy.deepcopy(d.trace)
    env["trace"]["final_decision"]["verdict"] = "DENY"
    _refused(lambda: DT.verify_trace(env, tracer.pubkey_hex), DT.FORGERY)


def p_replay_mismatch_flipped_final():
    _need()
    tracer = DT.DecisionTracer(_SEED, "v1")
    edges = [{"seq": 0, "layer": "authz", "rule": "deny[0]",
              "outcome": "deny", "reason": "toolcall-denied"}]
    body = {"trace_format": DT.TRACE_FORMAT, "decision_id": "d9",
            "subsystem": "tool-call-policy", "policy_version": "v1",
            "snapshot_token": "s", "replay_rule": DT.REPLAY_RULE_V1,
            "edges": edges,
            "inputs_digests": {"tool": "00"},
            "final_decision": {"verdict": "ALLOW", "code": None},
            "decided_at": 1700000000}
    env = {"trace": body, "signature": tracer.sign_body(body),
           "keyid": "decision-tracer"}
    # Signature is VALID (signed by the real key) but the edges fold to
    # DENY while the trace records ALLOW -> replay mismatch, not forgery.
    _refused(lambda: DT.verify_trace(env, tracer.pubkey_hex),
             DT.REPLAY_MISMATCH)


def p_version_mismatch():
    _need()
    pol, tracer = _traced_policy(version="v1")
    d = pol.decide(_caller(), "fs", "read", {})
    _refused(lambda: DT.verify_trace(d.trace, tracer.pubkey_hex,
                                     expected_policy_version="v2"),
             DT.REPLAY_MISMATCH)


def p_snapshot_substitution():
    _need()
    pol, tracer = _traced_policy()
    d = pol.decide(_caller(), "fs", "read", {})
    _refused(lambda: DT.verify_trace(d.trace, tracer.pubkey_hex,
                                     expected_snapshot_token="0" * 64),
             DT.REPLAY_MISMATCH)


def p_unsigned_trace_refused():
    _need()
    pol, tracer = _traced_policy()
    d = pol.decide(_caller(), "fs", "read", {})
    env = {"trace": d.trace["trace"], "keyid": "decision-tracer"}
    _refused(lambda: DT.verify_trace(env, tracer.pubkey_hex), DT.INVALID)


def p_malformed_envelope_refused():
    _need()
    tracer = DT.DecisionTracer(_SEED, "v1")
    _refused(lambda: DT.verify_trace("not-a-dict", tracer.pubkey_hex),
             DT.INVALID)
    _refused(lambda: DT.verify_trace({}, tracer.pubkey_hex), DT.INVALID)
    _refused(lambda: DT.verify_trace({"trace": {}, "signature": "aa"},
                                     tracer.pubkey_hex), DT.INVALID)


def p_verify_returns_exact_bool_contract():
    _need()
    # Wave-243 lesson, pinned: gov.ed25519.verify returns exact
    # True/False; verify_trace must refuse (not crash) on False.
    if _ed.verify(b"\x00" * 32, b"m", b"\x00" * 64) is not False:
        raise _Break("ed25519.verify contract changed")


PROBES = [
    ("pin-count", p_pin_count),
    ("pin-raw-literals", p_pin_raw_literals),
    ("emit-signed-envelope", p_emit_signed_envelope),
    ("verify-roundtrip", p_verify_roundtrip),
    ("deny-trace-verifies", p_deny_trace_verifies),
    ("snapshot-is-policy-digest", p_snapshot_is_policy_digest),
    ("inputs-are-digests-not-raw", p_inputs_are_digests_not_raw),
    ("unbound-decide-works-untraced", p_unbound_decide_works_untraced),
    ("opt-out-disables-trace", p_opt_out_disables_trace),
    ("audit-would-deny-folds-allow", p_audit_would_deny_folds_allow),
    ("fold-default-deny", p_fold_default_deny),
    ("broken-tracer-never-breaks-decide",
     p_broken_tracer_never_breaks_decide),
    ("bad-seed-refused", p_bad_seed_refused),
    ("forged-signature", p_forged_signature),
    ("wrong-key-forgery", p_wrong_key_forgery),
    ("tampered-body-forgery", p_tampered_body_forgery),
    ("replay-mismatch-flipped-final", p_replay_mismatch_flipped_final),
    ("version-mismatch", p_version_mismatch),
    ("snapshot-substitution", p_snapshot_substitution),
    ("unsigned-trace-refused", p_unsigned_trace_refused),
    ("malformed-envelope-refused", p_malformed_envelope_refused),
    ("verify-exact-bool-contract", p_verify_returns_exact_bool_contract),
]


def _green_check(battery):
    # Depth-1 green check (wave-173 lesson): adjacent batteries run with
    # GOV_SKIP_GREEN=1 in the child env; every green-check honors the var.
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    path = os.path.join(REPO, "evals", battery)
    if not os.path.exists(path):
        return ("SKIP", "battery %s not present" % battery)
    try:
        out = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=600, env=env, cwd=REPO)
    except subprocess.TimeoutExpired:
        return ("ERROR", "timeout")
    tail = (out.stdout + out.stderr).strip().splitlines()
    summary = tail[-1] if tail else "(no output)"
    if "0 BREAK" in out.stdout and "0 ERROR" in out.stdout:
        return ("HELD", summary)
    return ("BREAK", summary)


def main():
    brk = held = err = 0
    failures = []
    for name, fn in PROBES:
        try:
            fn()
        except _Break as e:
            brk += 1
            failures.append((name, "BREAK: %s" % (e,)))
        except AssertionError as e:
            brk += 1
            failures.append((name, "BREAK(assert): %s" % (e,)))
        except Exception as e:  # noqa: BLE001 -- probe harness
            err += 1
            failures.append((name, "ERROR: %r" % (e,)))
        else:
            held += 1
    print("w296_decision_trace: %d BREAK / %d HELD / %d ERROR "
          "over %d probes" % (brk, held, err, len(PROBES)))
    for name, why in failures:
        print("  %s -> %s" % (name, why))
    if not SKIP_GREEN:
        for battery in ("w294_filter_pipeline_probes.py",
                        "w294_tool_schemas_probes.py"):
            status, summary = _green_check(battery)
            print("green-check %-32s %s: %s" % (battery, status, summary))
    if brk or err:
        sys.exit(1)


if __name__ == "__main__":
    main()
