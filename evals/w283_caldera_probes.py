"""Wave-283 lane 7 red-first battery: Caldera campaign ADAPT.

Base: wave-282 push ad222ce. The gap under test is the missing campaign
layer: the attack ledger replays isolated scenarios but has no chaining
semantics (no requires/produces preconditions on atomic tests), no typed
fact store, no planner seam, and no fact-goal objective termination with
auto-close. Caldera's model (requirements-gated ability chaining, typed
fact store, pluggable planners, fact-goal objectives, auto-close) is
ADAPTED here as gov/campaign.py (+ requires/produces on atomic specs in
gov/battery_lang.py) -- mechanism only, apache/caldera contract shapes,
stdlib-only, no code vendored.

Red-first: on the pristine base (module absent) every capability probe
BREAKs. After the build, all HELD in staging and
env -u GOV_DEPLOYMENT_MODE.

$0 spend, synthetic/local, deterministic (no wall-clock assertions).
Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g283-caldera && TMPDIR=/var/tmp/g283-caldera \
    ~/workspace/.gov-venv/bin/python evals/w283_caldera_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g283-caldera2 \
    ~/workspace/.gov-venv/bin/python evals/w283_caldera_probes.py
"""

import hashlib
import json
import os
import re
import secrets
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w283-caldera")
os.environ.setdefault("TMPDIR", "/var/tmp/g283-caldera")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# No new decision codes in this lane: campaign refusals are
# ValueError-family (CampaignError); atomic requires/produces validation
# reuses the registered atomic-spec-invalid code.
TAXONOMY_PIN = 1829  # Wave-282 merge: 1563 -> 1579 (+16 codes).; Wave-283 merge: pin 1579 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

_RESULTS = []

PLUGIN_META = ("authz-bypass", "direct", "held-vs-expected")
PROBE_METADATA = {}


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict, "note": note})
    PROBE_METADATA.setdefault(probe_id, PLUGIN_META)


def _needs_modules(probe_id):
    try:
        from gov import campaign as cp
        from gov import battery_lang as bl
        return cp, bl
    except ImportError:
        _record(probe_id, "BREAK", "gov.campaign absent on base")
        return None


def _literals():
    with open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "gov", "decision_codes.py"),
            encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD",
            "%d/%d/0 sorted" % (TAXONOMY_PIN, TAXONOMY_PIN))


def _atomic(name, verdict, **kw):
    """Minimal valid atomic spec with a deterministic executor."""
    def _run(ctx):
        return verdict, "%s-note" % name

    spec = {
        "name": name,
        "description": "probe atomic %s" % name,
        "input_arguments": {},
        "dependencies": [],
        "executor": {"run": _run, "cleanup": None,
                     "elevation_required": False},
    }
    spec.update(kw)
    return spec


def p_factstore_typed():
    mods = _needs_modules("p_factstore_typed")
    if mods is None:
        return
    cp, _ = mods
    fs = cp.FactStore()
    fs.set_fact("tool.file_write.available", True, "bool", source="seed")
    if fs.get("tool.file_write.available") is not True:
        return _record("p_factstore_typed", "BREAK", "seeded fact not readable")
    # Strict typing: bool is not int; wrong type refused.
    try:
        fs.set_fact("tool.file_write.available", 1, "int", source="seed")
    except ValueError:
        pass
    else:
        return _record("p_factstore_typed", "BREAK",
                       "type-confused overwrite accepted")
    try:
        fs.set_fact("bad trait!", True, "bool", source="seed")
    except ValueError:
        pass
    else:
        return _record("p_factstore_typed", "BREAK",
                       "malformed trait accepted")
    try:
        fs.set_fact("a.b.c", "x", "nope", source="seed")
    except ValueError:
        pass
    else:
        return _record("p_factstore_typed", "BREAK",
                       "unknown fact type accepted")
    _record("p_factstore_typed", "HELD",
            "typed store: strict, fail-closed on mismatch")


def p_requires_gates_eligibility():
    mods = _needs_modules("p_requires_gates_eligibility")
    if mods is None:
        return
    cp, bl = mods
    gated = _atomic("gated", "HELD", requires=[
        {"fact": "tool.file_write.available", "op": "eq", "value": True}])
    runner = cp.CampaignRunner({})
    fs = cp.FactStore()
    if runner._eligible(gated, fs):
        return _record("p_requires_gates_eligibility", "BREAK",
                       "atomic eligible with requirement unsatisfied")
    fs.set_fact("tool.file_write.available", True, "bool", source="seed")
    if not runner._eligible(gated, fs):
        return _record("p_requires_gates_eligibility", "BREAK",
                       "atomic ineligible with requirement satisfied")
    _record("p_requires_gates_eligibility", "HELD",
            "requires gates eligibility (Caldera requirements)")


def p_requires_bad_shape_refused():
    mods = _needs_modules("p_requires_bad_shape_refused")
    if mods is None:
        return
    _, bl = mods
    bad = _atomic("bad", "HELD",
                  requires=[{"fact": "a.b.c", "op": "frobnicates"}])
    try:
        bl.validate_atomic_spec(bad)
    except bl.AtomicError as e:
        if e.code != "atomic-spec-invalid":
            return _record("p_requires_bad_shape_refused", "BREAK",
                           "wrong code: %s" % e.code)
    else:
        return _record("p_requires_bad_shape_refused", "BREAK",
                       "unknown op accepted")
    bad2 = _atomic("bad2", "HELD", requires=[{"op": "eq", "value": 1}])
    try:
        bl.validate_atomic_spec(bad2)
    except bl.AtomicError:
        pass
    else:
        return _record("p_requires_bad_shape_refused", "BREAK",
                       "requirement without fact accepted")
    _record("p_requires_bad_shape_refused", "HELD",
            "malformed requirements refused with atomic-spec-invalid")


def p_produces_written_on_break():
    mods = _needs_modules("p_produces_written_on_break")
    if mods is None:
        return
    cp, _ = mods
    reg = {}
    b = _atomic("writer", "BREAK", produces=[
        {"fact": "policy.attachment_scan.bypassed", "type": "bool",
         "value": True, "on": "break"}])
    h = _atomic("holder", "HELD", produces=[
        {"fact": "policy.attachment_scan.bypassed", "type": "bool",
         "value": True, "on": "break"}])
    cp.register_campaign_atomics(reg, [b, h])
    d = tempfile.mkdtemp(prefix="cal-", dir=os.environ["TMPDIR"])
    runner = cp.CampaignRunner(reg)
    cid = runner.run("p1", atomics=["writer"], planner_id="minimize-to-first-break",
                     objectives=[], seed_facts={},
                     args_map={}, evidence_path=os.path.join(d, "e.jsonl"))
    facts = runner.facts
    if facts.get("policy.attachment_scan.bypassed") is not True:
        return _record("p_produces_written_on_break", "BREAK",
                       "produced fact missing after BREAK")
    runner2 = cp.CampaignRunner(reg)
    runner2.run("p2", atomics=["holder"], planner_id="minimize-to-first-break",
                objectives=[], seed_facts={}, args_map={},
                evidence_path=os.path.join(d, "e2.jsonl"))
    if runner2.facts.get("policy.attachment_scan.bypassed") is not None:
        return _record("p_produces_written_on_break", "BREAK",
                       "on:break fact written after HELD")
    _record("p_produces_written_on_break", "HELD",
            "produces written on verdict match only")


def p_produces_type_mismatch_refused():
    mods = _needs_modules("p_produces_type_mismatch_refused")
    if mods is None:
        return
    _, bl = mods
    bad = _atomic("bad", "HELD", produces=[
        {"fact": "a.b.c", "type": "bool", "value": "not-a-bool"}])
    try:
        bl.validate_atomic_spec(bad)
    except bl.AtomicError as e:
        if e.code != "atomic-spec-invalid":
            return _record("p_produces_type_mismatch_refused", "BREAK",
                           "wrong code: %s" % e.code)
    else:
        return _record("p_produces_type_mismatch_refused", "BREAK",
                       "mistyped produces value accepted")
    bad2 = _atomic("bad2", "HELD", produces=[
        {"fact": "a.b.c", "type": "enum", "value": "x"}])
    try:
        bl.validate_atomic_spec(bad2)
    except bl.AtomicError:
        pass
    else:
        return _record("p_produces_type_mismatch_refused", "BREAK",
                       "enum produces without choices accepted")
    _record("p_produces_type_mismatch_refused", "HELD",
            "mistyped produces refused at spec validation")


def p_parser_facts():
    mods = _needs_modules("p_parser_facts")
    if mods is None:
        return
    cp, _ = mods

    def _parser(outcome):
        return [{"fact": "recon.host.user", "value": outcome["executor_note"]}]

    spec = _atomic("parsed", "BREAK",
                   produces=[{"fact": "recon.host.user", "type": "str",
                              "value": "ignored-static", "on": "always"}],
                   fact_parser=_parser)
    reg = {}
    cp.register_campaign_atomics(reg, [spec])
    d = tempfile.mkdtemp(prefix="cal-", dir=os.environ["TMPDIR"])
    runner = cp.CampaignRunner(reg)
    runner.run("p", atomics=["parsed"], planner_id="minimize-to-first-break",
               objectives=[], seed_facts={}, args_map={},
               evidence_path=os.path.join(d, "e.jsonl"))
    if runner.facts.get("recon.host.user") != "parsed-note":
        return _record("p_parser_facts", "BREAK",
                       "parser-harvested fact missing/wrong: %r"
                       % (runner.facts.get("recon.host.user"),))

    def _evil_parser(outcome):
        return [{"fact": "undeclared.fact.x", "value": 1}]

    evil = _atomic("evil", "BREAK",
                   produces=[{"fact": "recon.host.user", "type": "str",
                              "value": "s", "on": "always"}],
                   fact_parser=_evil_parser)
    reg2 = {}
    cp.register_campaign_atomics(reg2, [evil])
    d2 = tempfile.mkdtemp(prefix="cal-", dir=os.environ["TMPDIR"])
    runner2 = cp.CampaignRunner(reg2)
    cid = runner2.run("p2", atomics=["evil"],
                      planner_id="minimize-to-first-break",
                      objectives=[], seed_facts={}, args_map={},
                      evidence_path=os.path.join(d2, "e.jsonl"))
    rows = cp.read_campaign_records(os.path.join(d2, "e.jsonl"))
    steps = [r for r in rows if r["record_type"] == "campaign-step"]
    if runner2.facts.get("undeclared.fact.x") is not None:
        return _record("p_parser_facts", "BREAK",
                       "undeclared parser fact written")
    if not any("undeclared" in (s.get("parser_note") or "")
               for s in steps):
        return _record("p_parser_facts", "BREAK",
                       "parser refusal not recorded in step evidence")
    _record("p_parser_facts", "HELD",
            "parser facts harvested; undeclared facts refused LOUD")


def p_enum_facts():
    # Spec-axis finding (review): enum facts must be storable end to
    # end -- seed, produces, and parser harvest -- with the declared
    # choices domain enforced.
    mods = _needs_modules("p_enum_facts")
    if mods is None:
        return
    cp, _ = mods
    fs = cp.FactStore()
    try:
        fs.set_fact("host.os.family", "linux", "enum",
                    choices=["linux", "macos", "windows"], source="seed")
    except ValueError as e:
        return _record("p_enum_facts", "BREAK",
                       "enum seed refused: %s" % (e,))
    if fs.get("host.os.family") != "linux":
        return _record("p_enum_facts", "BREAK", "enum seed not readable")
    try:
        fs.set_fact("host.os.family", "plan9", "enum",
                    choices=["linux", "macos", "windows"], source="seed")
    except ValueError:
        pass
    else:
        return _record("p_enum_facts", "BREAK",
                       "enum value outside choices accepted")
    try:
        fs.set_fact("host.os.family", "macos", "enum",
                    choices=["linux", "macos"], source="seed")
    except ValueError:
        pass
    else:
        return _record("p_enum_facts", "BREAK", "enum domain change accepted")
    try:
        fs.set_fact("host.os.family", "macos", "enum",
                    choices=["linux", "macos", "windows"], source="seed")
    except ValueError as e:
        return _record("p_enum_facts", "BREAK",
                       "enum same-domain update refused: %s" % (e,))
    # End to end: enum via produces in a campaign run.
    reg = {}
    cp.register_campaign_atomics(reg, [_atomic(
        "enumwriter", "BREAK",
        produces=[{"fact": "host.os.family", "type": "enum",
                   "value": "windows",
                   "choices": ["linux", "macos", "windows"]}])])
    d = tempfile.mkdtemp(prefix="cal-", dir=os.environ["TMPDIR"])
    path = os.path.join(d, "e.jsonl")
    runner = cp.CampaignRunner(reg)
    runner.run("p", atomics=["enumwriter"],
               planner_id="coverage-maximizer", objectives=[],
               seed_facts={}, args_map={}, evidence_path=path)
    if runner.facts.get("host.os.family") != "windows":
        return _record("p_enum_facts", "BREAK",
                       "enum produces not written: %r" % (runner.facts,))
    _record("p_enum_facts", "HELD",
            "enum facts: typed, domain-enforced, end-to-end")


def p_minimize_stops_at_first_break():
    # minimize-to-first-break stops at the first BREAK intrinsically
    # (no campaign.breaks objective needed); an objective met on the
    # same step still wins (checked first).
    mods = _needs_modules("p_minimize_stops_at_first_break")
    if mods is None:
        return
    cp, _ = mods
    reg = {}
    cp.register_campaign_atomics(reg, [_atomic("a1", "BREAK"),
                                       _atomic("a2", "BREAK")])
    d = tempfile.mkdtemp(prefix="cal-", dir=os.environ["TMPDIR"])
    path = os.path.join(d, "e.jsonl")
    runner = cp.CampaignRunner(reg)
    runner.run("p", atomics=["a1", "a2"],
               planner_id="minimize-to-first-break", objectives=[],
               seed_facts={}, args_map={}, evidence_path=path)
    rows = cp.read_campaign_records(path)
    closes = [r for r in rows if r["record_type"] == "campaign-close"]
    steps = [r for r in rows if r["record_type"] == "campaign-step"]
    if len(steps) != 1:
        return _record("p_minimize_stops_at_first_break", "BREAK",
                       "ran %d steps, want 1" % len(steps))
    if not closes or closes[0]["outcome"] != "planner-stopped":
        return _record("p_minimize_stops_at_first_break", "BREAK",
                       "expected planner-stopped, got %r" % (closes,))
    _record("p_minimize_stops_at_first_break", "HELD",
            "minimize-to-first-break stops intrinsically at first BREAK")


def p_planner_seam():
    mods = _needs_modules("p_planner_seam")
    if mods is None:
        return
    cp, _ = mods
    for pid in ("greedy-break-chaser", "coverage-maximizer",
                "minimize-to-first-break"):
        if pid not in cp.PLANNERS:
            return _record("p_planner_seam", "BREAK",
                           "planner %r missing" % pid)
    reg = {}
    cp.register_campaign_atomics(reg, [_atomic("a", "HELD")])
    d = tempfile.mkdtemp(prefix="cal-", dir=os.environ["TMPDIR"])
    runner = cp.CampaignRunner(reg)
    try:
        runner.run("p", atomics=["a"], planner_id="no-such-planner",
                   objectives=[], seed_facts={}, args_map={},
                   evidence_path=os.path.join(d, "e.jsonl"))
    except cp.CampaignError:
        pass
    else:
        return _record("p_planner_seam", "BREAK",
                       "unknown planner accepted")
    _record("p_planner_seam", "HELD",
            "planner seam: 3 planners registered, unknown refused")


def p_objective_terminates():
    mods = _needs_modules("p_objective_terminates")
    if mods is None:
        return
    cp, _ = mods
    reg = {}
    cp.register_campaign_atomics(reg, [_atomic("breacher", "BREAK"),
                                       _atomic("other", "BREAK")])
    d = tempfile.mkdtemp(prefix="cal-", dir=os.environ["TMPDIR"])
    path = os.path.join(d, "e.jsonl")
    runner = cp.CampaignRunner(reg)
    cid = runner.run("p", atomics=["breacher", "other"],
                     planner_id="minimize-to-first-break",
                     objectives=[{"count": 1, "operator": "gte",
                                  "target": "campaign.breaks", "value": 1}],
                     seed_facts={}, args_map={}, evidence_path=path)
    rows = cp.read_campaign_records(path)
    closes = [r for r in rows if r["record_type"] == "campaign-close"]
    steps = [r for r in rows if r["record_type"] == "campaign-step"]
    if len(closes) != 1 or closes[0]["outcome"] != "objectives-met":
        return _record("p_objective_terminates", "BREAK",
                       "close record wrong: %r" % (closes,))
    if len(steps) != 1:
        return _record("p_objective_terminates", "BREAK",
                       "ran %d steps after objective met" % len(steps))
    _record("p_objective_terminates", "HELD",
            "fact-goal objective terminates campaign (auto-close)")


def p_auto_close_exhaustion():
    mods = _needs_modules("p_auto_close_exhaustion")
    if mods is None:
        return
    cp, _ = mods
    reg = {}
    cp.register_campaign_atomics(reg, [_atomic("lonely", "HELD", requires=[
        {"fact": "never.seeded", "op": "exists"}])])
    d = tempfile.mkdtemp(prefix="cal-", dir=os.environ["TMPDIR"])
    path = os.path.join(d, "e.jsonl")
    runner = cp.CampaignRunner(reg)
    runner.run("p", atomics=["lonely"], planner_id="minimize-to-first-break",
               objectives=[], seed_facts={}, args_map={},
               evidence_path=path)
    rows = cp.read_campaign_records(path)
    closes = [r for r in rows if r["record_type"] == "campaign-close"]
    if not closes or closes[0]["outcome"] != "no-eligible-atomics":
        return _record("p_auto_close_exhaustion", "BREAK",
                       "expected no-eligible-atomics, got %r" % (closes,))
    # Step budget.
    reg2 = {}
    cp.register_campaign_atomics(reg2, [_atomic("s%d" % i, "HELD")
                                        for i in range(5)])
    d2 = tempfile.mkdtemp(prefix="cal-", dir=os.environ["TMPDIR"])
    path2 = os.path.join(d2, "e.jsonl")
    runner2 = cp.CampaignRunner(reg2)
    runner2.run("p2", atomics=["s%d" % i for i in range(5)],
                planner_id="coverage-maximizer",
                objectives=[{"count": 99, "operator": "gte",
                             "target": "campaign.breaks", "value": 1}],
                seed_facts={}, args_map={}, evidence_path=path2,
                max_steps=2)
    rows2 = cp.read_campaign_records(path2)
    closes2 = [r for r in rows2 if r["record_type"] == "campaign-close"]
    steps2 = [r for r in rows2 if r["record_type"] == "campaign-step"]
    if not closes2 or closes2[0]["outcome"] != "step-budget-exhausted":
        return _record("p_auto_close_exhaustion", "BREAK",
                       "expected step-budget-exhausted, got %r" % (closes2,))
    if len(steps2) != 2:
        return _record("p_auto_close_exhaustion", "BREAK",
                       "ran %d steps with max_steps=2" % len(steps2))
    _record("p_auto_close_exhaustion", "HELD",
            "auto-close: exhaustion and step budget")


def p_campaign_chaining():
    mods = _needs_modules("p_campaign_chaining")
    if mods is None:
        return
    cp, _ = mods
    first = _atomic("first", "BREAK", produces=[
        {"fact": "recon.host.reachable", "type": "bool", "value": True}])
    second = _atomic("second", "BREAK", requires=[
        {"fact": "recon.host.reachable", "op": "eq", "value": True}],
        produces=[{"fact": "exfil.channel.open", "type": "bool",
                   "value": True}])
    reg = {}
    # Deliberately register in reverse: the planner must still chain
    # first -> second by precondition satisfaction.
    cp.register_campaign_atomics(reg, [second, first])
    d = tempfile.mkdtemp(prefix="cal-", dir=os.environ["TMPDIR"])
    path = os.path.join(d, "e.jsonl")
    runner = cp.CampaignRunner(reg)
    runner.run("chain", atomics=["second", "first"],
               planner_id="coverage-maximizer",
               objectives=[{"count": 1, "operator": "eq",
                            "target": "exfil.channel.open", "value": True}],
               seed_facts={}, args_map={}, evidence_path=path)
    rows = cp.read_campaign_records(path)
    steps = [r for r in rows if r["record_type"] == "campaign-step"]
    order = [s["atomic_name"] for s in steps]
    if order != ["first", "second"]:
        return _record("p_campaign_chaining", "BREAK",
                       "chaining order wrong: %r" % (order,))
    if runner.facts.get("exfil.channel.open") is not True:
        return _record("p_campaign_chaining", "BREAK",
                       "chained fact missing")
    closes = [r for r in rows if r["record_type"] == "campaign-close"]
    if not closes or closes[0]["outcome"] != "objectives-met":
        return _record("p_campaign_chaining", "BREAK",
                       "chain did not meet objective: %r" % (closes,))
    _record("p_campaign_chaining", "HELD",
            "planner chains by precondition satisfaction: first -> second")


def p_deterministic_replay():
    mods = _needs_modules("p_deterministic_replay")
    if mods is None:
        return
    cp, _ = mods
    reg = {}
    cp.register_campaign_atomics(reg, [_atomic("r1", "BREAK"),
                                       _atomic("r2", "HELD")])
    d = tempfile.mkdtemp(prefix="cal-", dir=os.environ["TMPDIR"])
    path = os.path.join(d, "e.jsonl")
    runner = cp.CampaignRunner(reg)
    runner.run("rep", atomics=["r1", "r2"],
               planner_id="minimize-to-first-break",
               objectives=[], seed_facts={}, args_map={},
               evidence_path=path)
    if not cp.verify_campaign_records(cp.read_campaign_records(path)):
        return _record("p_deterministic_replay", "BREAK",
                       "fresh evidence failed verification")
    diffs = cp.replay_campaign(path, reg)
    if diffs:
        return _record("p_deterministic_replay", "BREAK",
                       "clean replay produced diffs: %r" % (diffs,))
    # Tamper: flip a verdict byte in the evidence.
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    tampered = []
    flipped = False
    for ln in lines:
        obj = json.loads(ln)
        if obj.get("record_type") == "campaign-step" and not flipped:
            obj["verdict"] = "BREAK" if obj["verdict"] == "HELD" else "HELD"
            flipped = True
        tampered.append(json.dumps(obj, sort_keys=True))
    tpath = os.path.join(d, "t.jsonl")
    with open(tpath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(tampered) + "\n")
    if cp.verify_campaign_records(cp.read_campaign_records(tpath)):
        return _record("p_deterministic_replay", "BREAK",
                       "tampered evidence verified true")
    _record("p_deterministic_replay", "HELD",
            "evidence verifies; replay clean; tamper detected")


def p_guid_stability_legacy():
    """Old specs (no requires/produces) keep their guids byte-for-byte."""
    mods = _needs_modules("p_guid_stability_legacy")
    if mods is None:
        return
    _, bl = mods

    def _run(ctx):
        return "HELD", "n"

    spec = {"name": "legacy", "description": "d", "input_arguments": {},
            "dependencies": [],
            "executor": {"run": _run, "cleanup": None,
                         "elevation_required": False}}
    norm = bl.validate_atomic_spec(spec)
    # The pre-change serializable shape: requires/produces absent.
    legacy_shape = {"name": norm["name"], "description": norm["description"],
                    "input_arguments": norm["input_arguments"],
                    "dependencies": norm["dependencies"],
                    "executor": {"elevation_required": False,
                                 "has_cleanup": False}}
    want = hashlib.sha256(json.dumps(
        legacy_shape, sort_keys=True,
        separators=(",", ":")).encode("utf-8")).hexdigest()
    if norm["guid"] != want:
        return _record("p_guid_stability_legacy", "BREAK",
                       "legacy guid changed: %s != %s"
                       % (norm["guid"][:12], want[:12]))
    # And a spec WITH requires binds a different guid (preconditions are
    # identity when present).
    spec2 = dict(spec)
    spec2["requires"] = [{"fact": "a.b.c", "op": "exists"}]
    norm2 = bl.validate_atomic_spec(spec2)
    if norm2["guid"] == want:
        return _record("p_guid_stability_legacy", "BREAK",
                       "requires not bound into guid")
    _record("p_guid_stability_legacy", "HELD",
            "legacy guids stable; preconditions bound when present")


def p_greedy_break_chaser():
    mods = _needs_modules("p_greedy_break_chaser")
    if mods is None:
        return
    cp, _ = mods
    reg = {}
    cp.register_campaign_atomics(reg, [_atomic("low", "BREAK"),
                                       _atomic("high", "BREAK")])
    guids = {s["name"]: g for g, s in
             ((g, e["spec"]) for g, e in reg.items())}
    memory = {guids["low"]: {"breaks": 0, "runs": 4},
              guids["high"]: {"breaks": 3, "runs": 4}}
    d = tempfile.mkdtemp(prefix="cal-", dir=os.environ["TMPDIR"])
    path = os.path.join(d, "e.jsonl")
    runner = cp.CampaignRunner(reg, break_memory=memory)
    runner.run("g", atomics=["low", "high"],
               planner_id="greedy-break-chaser",
               objectives=[{"count": 1, "operator": "gte",
                            "target": "campaign.breaks", "value": 1}],
               seed_facts={}, args_map={}, evidence_path=path,
               max_steps=1)
    rows = cp.read_campaign_records(path)
    steps = [r for r in rows if r["record_type"] == "campaign-step"]
    if not steps or steps[0]["atomic_name"] != "high":
        return _record("p_greedy_break_chaser", "BREAK",
                       "greedy planner did not chase break rate: %r"
                       % ([s["atomic_name"] for s in steps],))
    _record("p_greedy_break_chaser", "HELD",
            "greedy-break-chaser orders by ledger break rate")


def p_manual_approve():
    mods = _needs_modules("p_manual_approve")
    if mods is None:
        return
    cp, _ = mods
    reg = {}
    cp.register_campaign_atomics(reg, [_atomic("blast", "BREAK")])
    d = tempfile.mkdtemp(prefix="cal-", dir=os.environ["TMPDIR"])
    path = os.path.join(d, "e.jsonl")
    runner = cp.CampaignRunner(reg)
    runner.run("m", atomics=["blast"], planner_id="minimize-to-first-break",
               objectives=[], seed_facts={}, args_map={},
               evidence_path=path, manual_approve=True,
               approve_fn=lambda name: False)
    rows = cp.read_campaign_records(path)
    closes = [r for r in rows if r["record_type"] == "campaign-close"]
    steps = [r for r in rows if r["record_type"] == "campaign-step"]
    if not closes or closes[0]["outcome"] != "approval-denied":
        return _record("p_manual_approve", "BREAK",
                       "expected approval-denied, got %r" % (closes,))
    if steps:
        return _record("p_manual_approve", "BREAK",
                       "atomic ran despite denied approval")
    _record("p_manual_approve", "HELD",
            "manual-approve gate denies before execution")


def _green_check(mod_name):
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-" + mod_name, "HELD", "skipped (depth-1)")
        return
    import subprocess
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    r = subprocess.run(
        [sys.executable, "evals/%s_probes.py" % mod_name],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        capture_output=True, text=True, env=env, timeout=600)
    out = (r.stdout or "") + (r.stderr or "")
    # The wave-282 red-team battery honestly reports BREAKs for the open
    # F311 finding; green = it ran clean with no ERRORs.
    bad = ("[ERROR]" in out) or (r.returncode != 0)
    _record("green-" + mod_name, "HELD" if not bad else "BREAK",
            "rc=%d" % r.returncode)


def main():
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
    p_taxonomy_pin()
    p_factstore_typed()
    p_enum_facts()
    p_requires_gates_eligibility()
    p_requires_bad_shape_refused()
    p_produces_written_on_break()
    p_produces_type_mismatch_refused()
    p_parser_facts()
    p_planner_seam()
    p_minimize_stops_at_first_break()
    p_objective_terminates()
    p_auto_close_exhaustion()
    p_campaign_chaining()
    p_deterministic_replay()
    p_guid_stability_legacy()
    p_greedy_break_chaser()
    p_manual_approve()
    _green_check("w282_redteam")

    n_break = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    n_held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    n_err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    for r in _RESULTS:
        print("[%s] %s: %s" % (r["verdict"], r["probe_id"], r["note"]))
    print("== %d BREAK / %d HELD / %d ERROR ==" % (n_break, n_held, n_err))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
