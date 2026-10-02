"""Break-first closure battery for F217.

Wave-255 lane 2 (F217 closure). Stdlib only. Deterministic
(staging + `env -u GOV_DEPLOYMENT_MODE`).

Target: gov/policy_authoring.py's explain_candidate(). On the
pristine wave-254 base, non-dict action / context=None escape raw
AttributeError; the fixed seam either normalises (None -> {},
engine-consistent with Request.from_action's own `or {}` fallbacks)
or refuses fail-closed with a policy-authoring-* machine code.

Verdict per probe: HELD (fixed contract) or BREAK (raw exception
escapes). Fixed tree must exit 0.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import policy_authoring as pa  # noqa: E402

TAXONOMY_PIN = 1660  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660 (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).

_SIMPLE = """
version: 1
policies:
  - name: p1
    filters:
      - type: value-filter
        key: tool
        op: in
        value: [read_file]
    actions:
      - type: deny
        reason: x
"""

_BOOL = """
version: 1
policies:
  - name: p1
    filters:
      - type: value-filter
        key: source_untrusted
        op: eq
        value: true
    actions:
      - type: deny
        reason: x
"""

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _is_raw(exc):
    """True for the raw-exception classes F217 is about: bare
    AttributeError/TypeError escaping instead of a machine code."""
    return isinstance(exc, (AttributeError, TypeError))


@probe("f217/action-none-normalised")
def _p_action_none():
    # Engine tolerates action=None (from_action: action or {});
    # the explanation seam must too -- or refuse with a machine
    # code. Raw AttributeError is the break.
    c = pa.compile_authoring(_SIMPLE)
    try:
        recs = pa.explain_candidate(c, None, {})
    except Exception as exc:
        if _is_raw(exc):
            return _break("F217: raw %r on action=None"
                          % (type(exc).__name__,))
        if isinstance(exc, pa.AuthoringError):
            return _held("refused with machine code %s" % exc.code)
        return _break("unexpected %r" % (exc,))
    if not all("matched" in r for r in recs):
        return _break("malformed explanation shape")
    return _held("action=None normalised, explanation returned")


@probe("f217/context-none-normalised")
def _p_context_none():
    # context=None must not escape raw AttributeError via the
    # signal/counter explain paths (checked_bool, _counter_value).
    c = pa.compile_authoring(_BOOL)
    try:
        recs = pa.explain_candidate(c, {"tool": "read_file"}, None)
    except Exception as exc:
        if _is_raw(exc):
            return _break("F217: raw %r on context=None"
                          % (type(exc).__name__,))
        if isinstance(exc, pa.AuthoringError):
            return _held("refused with machine code %s" % exc.code)
        return _break("unexpected %r" % (exc,))
    if not all("matched" in r for r in recs):
        return _break("malformed explanation shape")
    return _held("context=None normalised, explanation returned")


@probe("f217/non-dict-action-refused")
def _p_action_shape():
    # Non-mapping truthy actions (str/int/list) must be refused
    # with a machine code -- never raw AttributeError. (The engine
    # itself would escape AttributeError here; the seam must be
    # strictly more robust.)
    c = pa.compile_authoring(_SIMPLE)
    for bad in ("read_file", 42, ["read_file"]):
        try:
            pa.explain_candidate(c, bad, {})
        except pa.AuthoringError as exc:
            if not exc.code.startswith("policy-authoring-"):
                return _break("wrong machine code %r" % (exc.code,))
            continue
        except Exception as exc:
            if _is_raw(exc):
                return _break("F217: raw %r on action=%r"
                              % (type(exc).__name__, bad))
            return _held("non-dict action refused: %s"
                         % type(exc).__name__)
        return _break("non-dict action %r silently accepted" % (bad,))
    return _held("all non-dict actions refused with machine code")


@probe("f217/non-dict-context-refused")
def _p_context_shape():
    # Non-mapping truthy contexts must be refused with a machine
    # code -- never raw AttributeError.
    c = pa.compile_authoring(_BOOL)
    for bad in ("yes", 42):
        try:
            pa.explain_candidate(c, {"tool": "read_file"}, bad)
        except pa.AuthoringError as exc:
            if not exc.code.startswith("policy-authoring-"):
                return _break("wrong machine code %r" % (exc.code,))
            continue
        except Exception as exc:
            if _is_raw(exc):
                return _break("F217: raw %r on context=%r"
                              % (type(exc).__name__, bad))
            return _held("non-dict context refused: %s"
                         % type(exc).__name__)
        return _break("non-dict context %r silently accepted" % (bad,))
    return _held("all non-dict contexts refused with machine code")


@probe("f217/dict-shapes-unchanged")
def _p_dict_regression():
    # Well-shaped dicts must flow through unchanged: no silent
    # weakening from the new seam validation (anti-regression pin).
    c = pa.compile_authoring(_SIMPLE)
    recs = pa.explain_candidate(c, {"tool": "read_file"}, {})
    if not any(r["matched"] for r in recs):
        return _break("match lost after seam change")
    recs = pa.explain_candidate(c, {"tool": "api_call"}, {})
    if any(r["matched"] for r in recs):
        return _break("non-match became a match after seam change")
    c2 = pa.compile_authoring(_BOOL)
    recs = pa.explain_candidate(
        c2, {"tool": "read_file"}, {"source_untrusted": True})
    if not any(r["matched"] for r in recs):
        return _break("signal match lost after seam change")
    return _held("dict shapes: match semantics unchanged")


@probe("f217/no-raw-anywhere")
def _p_no_raw():
    # Sweep: for a matrix of action/context shapes, assert no raw
    # AttributeError/TypeError escapes from explain_candidate --
    # the exact class F215 closed and F217 is about.
    c = pa.compile_authoring(_BOOL)
    shapes = [None, {}, {"tool": "x"}, "s", 42, 3.5, ["a"], ("a",)]
    for action in shapes:
        for context in shapes:
            try:
                pa.explain_candidate(c, action, context)
            except Exception as exc:
                if _is_raw(exc):
                    return _break("raw %r for action=%r context=%r"
                                  % (type(exc).__name__, action,
                                     context))
    return _held("no raw AttributeError/TypeError on 64 shape pairs")


def main():
    assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN, (  # Wave-258 merge: pin -> 1080.
        "taxonomy pin: expected %d, got %d"
        % (TAXONOMY_PIN, len(decision_codes.TAXONOMY)))  # Wave-258 merge: pin -> 1080.
    held, broken, errors = 0, 0, 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001 -- probe harness
            verdict, detail = ("ERROR", "%r" % (exc,))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            broken += 1
        else:
            errors += 1
        print("%-42s %-6s %s" % (name, verdict, detail))
    print("probes=%d held=%d break=%d error=%d"
          % (len(_PROBES), held, broken, errors))
    return 0 if (broken == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
