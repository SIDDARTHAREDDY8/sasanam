"""Wave-243 decision-vs-effect agreement probes (W243-9, red-first).

ADAPT, pattern only, prose re-derived from the gilda -01 three-valued
agreement idea: record BOTH the authorization decision and the
observed effect, then derive their agreement.

Probes:
  effect-agreement-aligned-happy-path -- a decision and a matching
      observed effect yield agreement=aligned.
  effect-agreement-contradicted-refused -- an observed effect that
      contradicts the recorded decision refuses
      effect-decision-contradicted.
  effect-agreement-unknown-flagged -- a decision with NO observed
      effect yields agreement=unknown with flag effect-unobserved:
      never silently assumed, never silently passed.
  effect-agreement-unbound-effect-refused -- agreement computed over
      effect bytes that do not digest to the recorded effect digest
      refuses effect-not-bound.
  effect-agreement-missing-decision-refused -- agreement with no
      recorded decision refuses effect-decision-missing.

Stdlib only. Deterministic: fixed action ids and fixed timestamps.
No in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NEW_API = False
try:
    from gov import effect_agreement as _ea
    HAVE_NEW_API = all(hasattr(_ea, n) for n in (
        "record_decision", "record_observed_effect",
        "compute_agreement", "EffectAgreementError"))
except ImportError:
    _ea = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

T0 = 1727731200                  # fixed decision time
T1 = T0 + 5                      # fixed observation time
ACTION = "file:read"
PARAMS = {"path": "/var/log/app.log"}


def _run_probe(name, fn):
    if not HAVE_NEW_API:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _expect_refusal(fn, code):
    """fn must raise EffectAgreementError with .code == code."""
    try:
        fn()
    except _ea.EffectAgreementError as exc:
        assert exc.code == code, "code %r, expected %r" % (exc.code, code)
        return "refused %s" % code
    raise AssertionError("no refusal; expected %s" % code)


def _registry():
    return {}


def _probe_aligned():
    reg = _registry()
    rec = _ea.record_decision(reg, "a1", {"verdict": "allow",
                                         "action": ACTION,
                                         "params": PARAMS},
                              decided_by="policy-engine", now=T0)
    assert rec["decision_digest"], "decision not digest-bound"
    obs = _ea.record_observed_effect(reg, "a1", {"action": ACTION,
                                                "params": PARAMS,
                                                "outcome": "success"},
                                     observed_at=T1, observer="auditor")
    assert obs["effect_digest"], "effect not digest-bound"
    res = _ea.compute_agreement(reg, "a1")
    assert res["agreement"] == "aligned", "got %r" % (res["agreement"],)
    assert res["decision_digest"] == rec["decision_digest"]
    assert res["effect_digest"] == obs["effect_digest"]
    return "aligned happy path"


def _probe_contradicted():
    reg = _registry()
    _ea.record_decision(reg, "a2", {"verdict": "allow", "action": ACTION,
                                   "params": PARAMS}, now=T0)
    _ea.record_observed_effect(reg, "a2", {"action": "file:write",
                                           "params": PARAMS,
                                           "outcome": "success"},
                               observed_at=T1, observer="auditor")
    return _expect_refusal(lambda: _ea.compute_agreement(reg, "a2"),
                           "effect-decision-contradicted")


def _probe_unknown():
    reg = _registry()
    _ea.record_decision(reg, "a3", {"verdict": "allow", "action": ACTION,
                                   "params": PARAMS}, now=T0)
    res = _ea.compute_agreement(reg, "a3")
    assert res["agreement"] == "unknown", "got %r" % (res["agreement"],)
    assert res["effect_digest"] is None, "unknown must carry no digest"
    assert res["flag"] == "effect-unobserved", "got flag %r" % (
        res.get("flag"),)
    return "unknown flagged, never assumed"


def _probe_unbound():
    reg = _registry()
    _ea.record_decision(reg, "a4", {"verdict": "allow", "action": ACTION,
                                   "params": PARAMS}, now=T0)
    obs = _ea.record_observed_effect(reg, "a4", {"action": ACTION,
                                                "params": PARAMS,
                                                "outcome": "success"},
                                     observed_at=T1, observer="auditor")
    # Attacker swaps the stored effect bytes but keeps the digest.
    reg["a4"]["effect_bytes"] = b'{"action":"file:delete"}'
    assert obs["effect_digest"] != _ea._digest(reg["a4"]["effect_bytes"])
    return _expect_refusal(lambda: _ea.compute_agreement(reg, "a4"),
                           "effect-not-bound")


def _probe_missing_decision():
    reg = _registry()
    return _expect_refusal(lambda: _ea.compute_agreement(reg, "nope"),
                           "effect-decision-missing")


PROBES = [
    ("effect-agreement-aligned-happy-path", _probe_aligned),
    ("effect-agreement-contradicted-refused", _probe_contradicted),
    ("effect-agreement-unknown-flagged", _probe_unknown),
    ("effect-agreement-unbound-effect-refused", _probe_unbound),
    ("effect-agreement-missing-decision-refused", _probe_missing_decision),
]


def _green_check():
    """Adjacent wave-242 batteries, depth-1 (children skip green)."""
    import subprocess
    adj = [
        ["evals/w242_aggregate_budget_probes.py"],
        ["evals/w242_stale_authority_probes.py"],
        ["evals/w242_containment_probes.py"],
        ["evals/w242_exception_ttl_probes.py"],
        ["evals/w242_three_outcome_conformance_probes.py"],
        ["evals/w242_ir8587_conformance_probes.py"],
        ["evals/w242_absence_epoch_probes.py"],
        ["evals/w242_aee_parity_probes.py"],
    ]
    repo = os.path.join(os.path.dirname(__file__), "..")
    py = os.environ.get("GOV_PY", sys.executable)
    notes = []
    for cmd in adj:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        try:
            out = subprocess.run(
                [py, os.path.join(repo, cmd[0])], capture_output=True,
                text=True, timeout=300, env=env, cwd=repo)
        except Exception as exc:  # noqa: BLE001
            return "green-check ERROR on %s: %r" % (cmd[0], exc)
        if "GAP" in (out.stdout or "") and "0 HELD" not in (out.stdout or ""):
            pass  # tolerated: battery may genuinely lack the API
        notes.append("%s -> rc=%d" % (cmd[0], out.returncode))
    return "adjacent wave-242 batteries: %s" % ("; ".join(notes),)


def main():
    results = [_run_probe(name, fn) for name, fn in PROBES]
    held = sum(1 for _, s, _ in results if s == "HELD")
    gap = sum(1 for _, s, _ in results if s == "GAP")
    for name, status, note in results:
        print("%-55s %-6s %s" % (name, status, note))
    print("HELD %d/%d  GAP %d/%d" % (held, len(results), gap, len(results)))
    if not GREEN_SKIP:
        print(_green_check())
    else:
        print("green-check skipped (GOV_SKIP_GREEN=1)")
    if gap:
        print("GENUINE RED: %d probes have no implementation on this base"
              % gap)
    bad = [r for r in results if r[1] in ("BREAK", "ERROR")]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
