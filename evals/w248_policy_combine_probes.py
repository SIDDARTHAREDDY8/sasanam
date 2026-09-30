"""Wave-248 forbid-overrides-permit probes (red-first).

W248-6: build ``gov/policy_combine.py`` -- the Cedar-adapted evaluator
guarantee (Apache-2.0, cedar-policy/cedar, pattern only, not the
language or engine): when a request is evaluated against a SET of
policies, the combination rule is structural, not a convention:

  * any FORBID match  -> DENY (regardless of permits)
  * PERMIT matches     -> ALLOW only with zero forbid matches
  * require_approval   -> REQUIRE_APPROVAL only with zero forbids
  * no permits at all  -> DENY (default deny)

The single policy engine (gov/policy.py) already does deny-first
within one policy file; the gap is cross-policy combination -- a
permit buried in one policy must not be smuggled past another
policy's forbid by ordering, flags, or structure.

The guarantee is structural: ``combine()`` takes per-policy
decisions and NOTHING ELSE -- no flag, option, mode, or priority
parameter that could express "permit overrides forbid". The only
legal input is a sequence of PolicyDecision objects (or
decision_contract.Decision via to_policy_decision()); anything else
refuses fail-closed as combiner misuse.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import inspect
import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_COMBINE = False
try:
    from gov import policy_combine as _pc
    HAVE_COMBINE = all(
        hasattr(_pc, n) for n in (
            "combine", "CombinedDecision", "CombinerMisuseError"))
except ImportError:
    _pc = None

HAVE_ENG = False
try:
    from gov.policy import PolicyEngine as _PE
    from gov.policy import PolicyDecision as _PD
    HAVE_ENG = True
except ImportError:
    _PE = _PD = None

HAVE_ALL = HAVE_COMBINE and HAVE_ENG

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"


def _run_probe(name, fn, have):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


# ------------------------------------------------- decision factories

_PERMIT_YAML = """\
version: "1"
policies:
  - id: allow-send
    effect: allow
    match:
      tool: send_email
"""

_FORBID_YAML = """\
version: "1"
policies:
  - id: deny-send
    effect: deny
    match:
      tool: send_email
"""

_APPROVAL_YAML = """\
version: "1"
policies:
  - id: approval-send
    effect: require_approval
    match:
      tool: send_email
"""

_ACTION = {"tool": "send_email", "args": {"to": "a@example.com"}}


def _engine_decision(yaml_text, action=_ACTION):
    eng = _PE.from_text(yaml_text, source_label="<probe>")
    return eng.evaluate(action, record_telemetry=False)


def _forbid():
    return _engine_decision(_FORBID_YAML)


def _permit():
    return _engine_decision(_PERMIT_YAML)


def _approval():
    return _engine_decision(_APPROVAL_YAML)


# ---------------------------------------------------------------- probes

def _probe_forbid_plus_permit_deny():
    out = _pc.combine([_forbid(), _permit()])
    assert out.effect == "deny", out.effect
    assert "deny-send" in out.reason, out.reason
    assert out.code == "combine-forbid-overrides", out.code
    return "forbid + permit -> DENY naming the forbidding policy"


def _probe_permit_only_allow():
    out = _pc.combine([_permit()])
    assert out.effect == "allow", out.effect
    return "permit-only -> ALLOW"


def _probe_empty_set_default_deny():
    out = _pc.combine([])
    assert out.effect == "deny", out.effect
    assert out.code == "combine-default-deny", out.code
    return "empty policy set -> DENY (default deny)"


def _probe_forbid_second_wins():
    a = _pc.combine([_permit(), _forbid()])
    b = _pc.combine([_forbid(), _permit()])
    assert a.effect == "deny" and b.effect == "deny", (a.effect, b.effect)
    assert a.code == b.code == "combine-forbid-overrides"
    return "forbid wins regardless of input order"


def _probe_no_permit_override_flag():
    # Structural impossibility: combine() must take exactly one
    # parameter; there is no flag/option/mode to express
    # "permit overrides forbid".
    sig = inspect.signature(_pc.combine)
    params = list(sig.parameters.values())
    assert len(params) == 1, "combine() must take exactly one parameter"
    p = params[0]
    assert p.default is inspect.Parameter.empty, "no default (no option)"
    assert p.kind in (inspect.Parameter.POSITIONAL_ONLY,
                      inspect.Parameter.POSITIONAL_OR_KEYWORD), p.kind
    for bad_kwarg in ("prefer_permit", "permit_overrides_forbid",
                      "forbid_priority", "mode", "allow_overrides"):
        try:
            _pc.combine([_permit()], **{bad_kwarg: True})
        except TypeError:
            pass
        else:
            raise AssertionError(
                "combine() accepted override kwarg %r" % (bad_kwarg,))
    return "no override expressible: 1 param, 5 override kwargs refused"


def _probe_require_approval_middle():
    out = _pc.combine([_approval(), _permit()])
    assert out.effect == "require_approval", out.effect
    return "require_approval + permit (no forbid) -> REQUIRE_APPROVAL"


def _probe_forbid_beats_approval():
    out = _pc.combine([_forbid(), _approval()])
    assert out.effect == "deny", out.effect
    assert out.code == "combine-forbid-overrides"
    return "forbid + require_approval -> DENY"


def _probe_misuse_non_decision_refused():
    for bad in ("allow", 42, None, ["allow"], object()):
        try:
            _pc.combine([bad])
        except _pc.CombinerMisuseError as exc:
            assert exc.code == "combine-misuse", exc.code
        else:
            raise AssertionError("expected CombinerMisuseError for %r"
                                 % (bad,))
    return "non-decision inputs refuse fail-closed with combine-misuse"


def _probe_misuse_dict_refused():
    # A raw dict shaped like a decision must NOT be accepted: only
    # validated PolicyDecision / Decision objects enter the combiner.
    try:
        _pc.combine([{"effect": "allow", "reason": "smuggled"}])
    except _pc.CombinerMisuseError as exc:
        assert exc.code == "combine-misuse"
    else:
        raise AssertionError("raw dict must not enter the combiner")
    return "raw dicts refused: only validated decision objects combine"


def _probe_end_to_end_engines():
    # Two REAL PolicyEngines (operator permit, deployment forbid)
    # evaluated on the same request: the combiner must deny.
    out = _pc.combine([_permit(), _forbid()])
    assert out.effect == "deny", out.effect
    assert "deny-send" in out.reason
    return "operator-permit + deployment-forbid -> DENY end-to-end"


def _probe_smuggle_forged_permit():
    # Even a fabricated permit (hand-built, attacker-chosen policy_id)
    # cannot rescue the request: the forbid still wins. The guarantee
    # is over EFFECTS, not over provenance.
    forged = _PD(effect="allow", reason="forged by attacker",
                 policy_id="attacker-policy")
    out = _pc.combine([_forbid(), forged])
    assert out.effect == "deny", out.effect
    assert out.code == "combine-forbid-overrides"
    return "forged permit cannot smuggle past a forbid"


def _probe_verdict_deterministic():
    a = _pc.combine([_permit(), _forbid()])
    b = _pc.combine([_permit(), _forbid()])
    assert (a.effect, a.reason, a.code) == (b.effect, b.reason, b.code)
    return "identical input sets -> identical verdicts"


def _probe_taxonomy_codes_present():
    from gov import decision_codes as dc
    for code in ("combine-forbid-overrides", "combine-default-deny",
                 "combine-misuse"):
        assert code in dc.TAXONOMY, "missing taxonomy code %r" % (code,)
        assert dc.TAXONOMY[code]["domain"] == "policy-combine", code
    return "3 combine codes in taxonomy under policy-combine"


_PROBES = {
    "forbid-plus-permit-deny": (_probe_forbid_plus_permit_deny, HAVE_ALL),
    "permit-only-allow": (_probe_permit_only_allow, HAVE_ALL),
    "empty-set-default-deny": (_probe_empty_set_default_deny, HAVE_ALL),
    "forbid-second-wins": (_probe_forbid_second_wins, HAVE_ALL),
    "no-permit-override-flag": (_probe_no_permit_override_flag,
                                HAVE_COMBINE),
    "require-approval-middle": (_probe_require_approval_middle, HAVE_ALL),
    "forbid-beats-approval": (_probe_forbid_beats_approval, HAVE_ALL),
    "misuse-non-decision-refused": (_probe_misuse_non_decision_refused,
                                    HAVE_ALL),
    "misuse-dict-refused": (_probe_misuse_dict_refused, HAVE_ALL),
    "end-to-end-engines": (_probe_end_to_end_engines, HAVE_ALL),
    "smuggle-forged-permit": (_probe_smuggle_forged_permit, HAVE_ALL),
    "verdict-deterministic": (_probe_verdict_deterministic, HAVE_ALL),
    "taxonomy-codes-present": (_probe_taxonomy_codes_present, HAVE_COMBINE),
}

PROBE_NAMES = list(_PROBES)


def _run_green_checks():
    """Depth-1 green checks (never spawns another battery's main).

    Honors GOV_SKIP_GREEN=1.
    """
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    import subprocess  # noqa: PLC0415
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env.setdefault("GOV_DEPLOYMENT_MODE", "staging")
    root = os.path.join(os.path.dirname(__file__), "..")
    for mod in ("tests.test_policy_combine", "tests.test_decision_codes"):
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", mod],
            cwd=root, env=env, capture_output=True, text=True, timeout=300)
        notes.append("unit %s rc=%d" % (mod, proc.returncode))
        if proc.returncode != 0:
            notes.append("unit tail: %s" % (proc.stderr[-500:],))
    return notes


def main():
    print("wave-248 policy_combine probes (combiner present: %s)"
          % (HAVE_COMBINE,))
    held = gap = 0
    for name in PROBE_NAMES:
        fn, have = _PROBES[name]
        name_r, status, note = _run_probe(name, fn, have)
        if status == "HELD":
            held += 1
        elif status == "GAP":
            gap += 1
        print("%-32s %s %s" % (name_r, status, note))
    notes = _run_green_checks()
    for note in notes:
        print("green: %s" % note)
    print("summary: %d HELD / %d GAP / %d total"
          % (held, gap, len(PROBE_NAMES)))
    if held != len(PROBE_NAMES):
        raise SystemExit("battery not fully HELD (%d/%d)"
                         % (held, len(PROBE_NAMES)))


if __name__ == "__main__":
    main()
