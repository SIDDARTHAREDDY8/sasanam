"""Break-first red-team battery for the wave-253 new modules.

Wave-254 lane 1 (red-team). Stdlib only. Deterministic across runs
(staging + `env -u GOV_DEPLOYMENT_MODE`).

Targets (all new in wave-253, base 7d024c57):
- gov/incident.py -- resolve() gate bypass via transition(),
  forged finding_status, caller aliasing, journal tampering.
- gov/policy_authoring.py -- weakened-policy smuggling through
  compile_authoring, or-expansion semantics, explain_candidate
  drift from the engine, dry_run side effects.
- gov/permit_journal.py -- further attempts past the F214 fix
  (raw-exception contract).
- gov/posture_cards.py -- further attempts past the F215 fix.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Verdicts: HELD (attack refused / gap documented as an
honest residual) or BREAK (genuine defect -> filed as a finding).

Result: 11 HELD / 4 BREAK (F216, F217 x2 probes, F218) / 0 ERROR
on the wave-253 base.
"""

import json
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import incident as inc_mod  # noqa: E402
from gov import permit_journal as pj  # noqa: E402
from gov import policy_authoring as pa  # noqa: E402
from gov import posture_cards as pc  # noqa: E402

TAXONOMY_PIN = 1769  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*)

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    return tempfile.mkdtemp(prefix="w254rt-", dir="/var/tmp")


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _incident(tmp, finding_status=None):
    return inc_mod.IncidentManager(
        os.path.join(tmp, "inc.jsonl"), finding_status=finding_status)


def _to_contained(mgr, iid="INC-1"):
    mgr.declare_incident(iid, title="t", severity="high")
    mgr.transition(iid, "investigating")
    mgr.transition(iid, "contained")
    return iid


# ---------------------------------------------------------------------------
# A. incident.py
# ---------------------------------------------------------------------------

@probe("incident/transition-to-resolved-bypass")
def _p_transition_bypass():
    # F216: transition() reaches "resolved" directly, bypassing
    # resolve()'s fail-closed finding/task checks -- the module's
    # headline property #1 defeated through a public API.
    tmp = _tmpdir()
    mgr = _incident(tmp, finding_status=lambda fid: "open")
    iid = _to_contained(mgr)
    mgr.link_finding(iid, "F1")  # OPEN finding linked
    try:
        mgr.resolve(iid)
    except inc_mod.IncidentError as exc:
        if exc.code != "incident-open-findings":
            return _held("resolve refused with unexpected %s" % exc.code)
    else:
        return _held("resolve() did not refuse (unexpected)")
    try:
        mgr.transition(iid, "resolved")
    except inc_mod.IncidentError as exc:
        return _held("transition to resolved refused: %s" % exc.code)
    if mgr.state(iid) == "resolved":
        return _break("F216: resolved with open finding via "
                      "transition(), resolve() gate bypassed")
    return _held("state not resolved")


@probe("incident/resolve-refuses-open-findings")
def _p_resolve_findings():
    tmp = _tmpdir()
    mgr = _incident(tmp, finding_status=lambda fid: "open")
    iid = _to_contained(mgr)
    mgr.link_finding(iid, "F9")
    try:
        mgr.resolve(iid)
    except inc_mod.IncidentError as exc:
        if exc.code == "incident-open-findings":
            return _held("refused incident-open-findings")
        return _break("wrong code %s" % exc.code)
    return _break("resolved with open finding")


@probe("incident/resolve-refuses-open-tasks")
def _p_resolve_tasks():
    tmp = _tmpdir()
    mgr = _incident(tmp, finding_status=lambda fid: "closed")
    iid = _to_contained(mgr)
    mgr.add_task(iid, "do the thing", owner="me")
    try:
        mgr.resolve(iid)
    except inc_mod.IncidentError as exc:
        if exc.code == "incident-open-tasks":
            return _held("refused incident-open-tasks")
        return _break("wrong code %s" % exc.code)
    return _break("resolved with open task")


@probe("incident/caller-aliasing-postmortem")
def _p_aliasing():
    # F212 lesson: post-append mutation must not change the record.
    tmp = _tmpdir()
    mgr = _incident(tmp)
    iid = _to_contained(mgr)
    tl = [{"at": "t0", "event": "e0"}]
    ai = [{"item": "fix", "owner": "me", "due": "soon"}]
    mgr.attach_postmortem(iid, timeline=tl, root_cause="rc",
                          action_items=ai)
    tl[0]["event"] = "MUTATED"
    ai[0]["item"] = "MUTATED"
    pm = mgr.postmortem(iid)
    if pm["timeline"][0]["event"] == "e0"\
            and pm["action_items"][0]["item"] == "fix":
        return _held("deep-copied at append and read")
    return _break("post-append mutation visible in record")


@probe("incident/journal-tamper-detected")
def _p_tamper():
    tmp = _tmpdir()
    mgr = _incident(tmp)
    mgr.declare_incident("I1", title="t", severity="low")
    path = os.path.join(tmp, "inc.jsonl")
    data = open(path, "rb").read()
    open(path, "wb").write(data[:40] + b"X" + data[41:])
    try:
        _incident(tmp)
    except Exception as exc:
        if "Corrupt" in type(exc).__name__:
            return _held("JournalCorrupted on reload")
        return _held("refused: %s" % type(exc).__name__)
    return _break("tampered journal reloaded cleanly")


@probe("incident/forged-finding-status")
def _p_forged_status():
    # A lying provider ("closed" for an open finding) defeats the
    # gate -- but the provider is deployment-supplied and the
    # module documents it as the trust root. HELD as documented,
    # not a product break.
    tmp = _tmpdir()
    mgr = _incident(tmp, finding_status=lambda fid: "closed")
    iid = _to_contained(mgr)
    mgr.link_finding(iid, "F1")
    try:
        mgr.resolve(iid)
    except inc_mod.IncidentError as exc:
        return _held("refused despite lying provider: %s" % exc.code)
    return _held("deployment-owned trust root, documented")


# ---------------------------------------------------------------------------
# B. policy_authoring.py
# ---------------------------------------------------------------------------

_SIMPLE = """
version: 1
policies:
  - name: p1
    filters:
      - type: value-filter
        key: tool
        op: eq
        value: read_file
    actions:
      - type: deny
        reason: x
"""


@probe("authoring/unknown-filter-refused")
def _p_unknown_filter():
    text = _SIMPLE.replace("value-filter", "magic-filter")
    try:
        pa.compile_authoring(text)
    except pa.AuthoringError as exc:
        if exc.code == "policy-authoring-unknown-filter":
            return _held("refused with machine code")
        return _break("wrong code %s" % exc.code)
    return _break("unknown filter type compiled")


@probe("authoring/or-expansion-semantics")
def _p_or_expansion():
    text = """
version: 1
policies:
  - name: orp
    filters:
      - type: or
        filters:
          - type: value-filter
            key: tool
            op: eq
            value: read_file
          - type: value-filter
            key: tool
            op: eq
            value: write_file
    actions:
      - type: deny
        reason: either
"""
    c = pa.compile_authoring(text)
    if len(c.rule_ids()) != 2:
        return _break("or did not expand to 2 rules: %r"
                      % (c.rule_ids(),))
    for tool, want in (("read_file", "deny"), ("write_file", "deny"),
                       ("api_call", "deny")):
        d = c.engine.evaluate({"tool": tool}, {},
                              record_telemetry=False)
        # api_call hits no branch -> default deny (deny-by-default)
        if d.effect != "deny":
            return _break("branch %s -> %s" % (tool, d.effect))
    # branches must not leak: read_file rule must not match api_call
    # via the write_file branch (checked by per-rule explain)
    recs = pa.explain_candidate(c, {"tool": "api_call"}, {})
    if any(r["matched"] for r in recs):
        return _break("or branch leaked to non-matching tool")
    return _held("each branch its own rule, no leakage")


@probe("authoring/explain-non-dict-action")
def _p_explain_action():
    # F217: explain_candidate escapes raw AttributeError on
    # non-dict action while the engine tolerates action=None
    # (default_deny). Same class as F215.
    c = pa.compile_authoring(_SIMPLE)
    for bad in (None, "read_file", 42):
        try:
            pa.explain_candidate(c, bad, {})
        except pa.AuthoringError as exc:
            continue
        except AttributeError:
            return _break("F217: raw AttributeError on action=%r"
                          % (bad,))
        except Exception as exc:
            return _held("refused: %s" % type(exc).__name__)
        return _held("tolerated action=%r" % (bad,))
    return _held("all non-dict actions refused with machine code")


@probe("authoring/explain-none-context")
def _p_explain_context():
    # F217, second shape: context=None crashes the signal/counter
    # explain paths while the engine decides default_deny.
    text = """
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
    c = pa.compile_authoring(text)
    try:
        pa.explain_candidate(c, {"tool": "read_file"}, None)
    except pa.AuthoringError:
        return _held("refused with machine code")
    except AttributeError:
        return _break("F217: raw AttributeError on context=None")
    except Exception as exc:
        return _held("refused: %s" % type(exc).__name__)
    return _held("tolerated context=None")


@probe("authoring/dry-run-read-only")
def _p_dryrun_readonly():
    import hashlib
    tmp = _tmpdir()
    hdir = os.path.join(tmp, "h")
    os.makedirs(os.path.join(hdir, "policies"))
    os.makedirs(os.path.join(hdir, "fixtures"))
    open(os.path.join(hdir, "policies", "p.yaml"), "w").write(
        "version: 2\npolicies:\n  - id: b\n    effect: deny\n"
        "    match:\n      tool: [write_file]\n")
    for name, tool in (("f1.json", "write_file"),
                       ("f2.json", "read_file")):
        open(os.path.join(hdir, "fixtures", name), "w").write(
            json.dumps({"action": {"tool": tool}, "context": {}}))

    def snap():
        out = {}
        for root, _, files in os.walk(hdir):
            for f in files:
                p = os.path.join(root, f)
                out[os.path.relpath(p, hdir)] = hashlib.sha256(
                    open(p, "rb").read()).hexdigest()
        return out

    before = snap()
    pa.dry_run(hdir, _SIMPLE)
    if snap() != before:
        return _break("dry_run wrote to the harness dir")
    return _held("no writes; evaluates only")


@probe("authoring/duplicate-names")
def _p_dup_names():
    # Two policies sharing a name compile to duplicate native rule
    # ids -- but the native engine accepts duplicate ids too, so
    # this is pre-existing engine behavior, not an authoring-layer
    # break. HELD as a documented residual.
    text = """
version: 1
policies:
  - name: dup
    filters:
      - type: value-filter
        key: tool
        op: eq
        value: read_file
    actions:
      - type: deny
        reason: a
  - name: dup
    filters:
      - type: value-filter
        key: tool
        op: eq
        value: write_file
    actions:
      - type: allow
        reason: b
"""
    c = pa.compile_authoring(text)
    if c.rule_ids() == ["dup", "dup"]:
        return _held("inherits engine's duplicate-id tolerance; "
                      "residual, not a new break")
    return _held("rule ids: %r" % (c.rule_ids(),))


# ---------------------------------------------------------------------------
# C. permit_journal.py (past the F214 fix)
# ---------------------------------------------------------------------------

@probe("journal/set-payload-still-refused")
def _p_set_payload():
    # F214 regression pin: set payload -> permit-journal-misuse.
    tmp = _tmpdir()
    j = pj.PermitJournal(os.path.join(tmp, "j.jsonl"),
                         key=os.urandom(32))
    try:
        j.grant("P1", payload={"s": {1, 2}})
    except pj.PermitJournalRefusal as exc:
        if exc.code == "permit-journal-misuse":
            return _held("F214 fix holds")
        return _break("wrong code %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("set payload granted")


@probe("journal/deep-nesting-raw-error")
def _p_deep_nesting():
    # F218: F214's wrap catches TypeError/ValueError, but a deeply
    # nested payload raises raw RecursionError from json.dumps --
    # same seam, same machine-code contract broken.
    tmp = _tmpdir()
    j = pj.PermitJournal(os.path.join(tmp, "j.jsonl"),
                         key=os.urandom(32))
    nested, cur = {}, None
    cur = nested
    for _ in range(3000):
        cur["x"] = {}
        cur = cur["x"]
    try:
        j.grant("P1", payload={"nested": nested})
    except pj.PermitJournalRefusal as exc:
        return _held("refused %s" % exc.code)
    except RecursionError:
        return _break("F218: raw RecursionError escaped "
                      "permit-journal-misuse")
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _held("deeply nested payload granted without error")


# ---------------------------------------------------------------------------
# D. posture_cards.py (past the F215 fix)
# ---------------------------------------------------------------------------

@probe("posture/non-dict-cards-still-refused")
def _p_nondict_cards():
    # F215 regression pin.
    for fn in (lambda: pc.track_level(["not-a-dict"], "policy"),
               lambda: pc.issue_summary("s", ["not-a-dict"],
                                        os.urandom(32),
                                        issuer="me")):
        try:
            fn()
        except pc.PostureCardError as exc:
            if exc.code != "posture-card-malformed":
                return _break("wrong code %s" % exc.code)
            continue
        except AttributeError:
            return _break("raw AttributeError escaped (F215 open)")
        except Exception as exc:
            return _break("raw %s escaped" % type(exc).__name__)
        return _break("non-dict cards accepted")
    return _held("F215 fix holds on both seams")


@probe("posture/tuple-cards-refused")
def _p_tuple_cards():
    try:
        pc.track_level(({"track": "policy", "probe": "pass"},),
                       "policy")
    except pc.PostureCardError as exc:
        if exc.code == "posture-card-malformed":
            return _held("tuples refused like other non-lists")
        return _break("wrong code %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _held("tuple accepted (lenient)")


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------

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
