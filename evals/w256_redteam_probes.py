"""Break-first red-team battery for the wave-254/255 new modules.

Wave-256 lane 1 (red-team). Stdlib only. Deterministic across runs
(staging + `env -u GOV_DEPLOYMENT_MODE`).

Targets (new since the last red-team, base 23967f50):
- gov/approval_policy.py -- auto-approve without audit sink,
  disapproval defaulted, simulation side effects, rule confusion,
  predicate injection, raw-exception seams.
- gov/compliance_emitter.py -- dangling evidence refs, unlinked
  claims, format confusion, source aliasing, drift digest.
- gov/inventory_catalog.py -- dangling relationships, duplicate
  entries, scorecard confusion, grant-edge seams, immutability.
- gov/incident.py -- deeper attempts past the F216 closure.
- gov/policy_authoring.py -- deeper attempts past the F217 closure.
- gov/permit_journal.py -- deeper attempts past F214/F218.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Verdicts: HELD (attack refused / gap documented as an
honest residual) or BREAK (genuine defect -> filed as a finding).
"""

import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import approval_policy as ap  # noqa: E402
from gov import compliance_emitter as ce  # noqa: E402
from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import incident as inc_mod  # noqa: E402
from gov import inventory_catalog as ic  # noqa: E402
from gov import permit_journal as pj  # noqa: E402
from gov import policy_authoring as pa  # noqa: E402

TAXONOMY_PIN = 2021 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 1: pin 2020 -> 2021 (+1 witness-alert-state-lost)



_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    return tempfile.mkdtemp(prefix="w256rt-", dir="/var/tmp")


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _auto_rules():
    return ap.compile_rules({
        "version": 1,
        "rules": [{
            "id": "r-auto",
            "when": {"field": "kind", "op": "eq", "value": "x"},
            "action": "auto-approve",
        }],
    })


def _deep_dict(depth):
    deep = {"leaf": 1}
    for _ in range(depth):
        deep = {"n": deep}
    return deep


_DEEP = 12000  # json.dumps raises RecursionError at ~10000 here


def _deep_request():
    return {"kind": "x", "payload": _deep_dict(_DEEP)}


# ---------------------------------------------------------------------------
# A. approval_policy.py (new in wave-254)
# ---------------------------------------------------------------------------

@probe("approval/route-deep-request-raw-error")
def _p_route_deep():
    # F219: _request_digest catches (TypeError, ValueError) only;
    # a deeply-nested request escapes raw RecursionError from the
    # public route() seam -- same class as F218, same machine-code
    # contract broken (callers catching ApprovalPolicyError miss it).
    rs = _auto_rules()
    try:
        rs and ap.route(rs, _deep_request(),
                        audit_sink=lambda entry: None)
    except RecursionError:
        return _break("F219: raw RecursionError escaped route()")
    except ap.ApprovalPolicyError as exc:
        return _held("machine-coded refusal %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("deep request auto-approved")


@probe("approval/simulate-deep-request-raw-error")
def _p_simulate_deep():
    # F219: simulate() digests every request; raw RecursionError
    # escapes the read-only preview seam too.
    rs = _auto_rules()
    try:
        ap.simulate(rs, [_deep_request()])
    except RecursionError:
        return _break("F219: raw RecursionError escaped simulate()")
    except ap.ApprovalPolicyError as exc:
        return _held("machine-coded refusal %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("deep request simulated without error")


@probe("approval/compile-deep-predicate-raw-error")
def _p_compile_deep():
    # F219: _check_predicate recurses on and/or structure; a
    # deeply-nested predicate escapes raw RecursionError from the
    # compile seam instead of approval-policy-malformed.
    pred = {"field": "a", "op": "eq", "value": 1}
    for _ in range(_DEEP):
        pred = {"and": [pred]}
    doc = {"version": 1, "rules": [{
        "id": "r-deep", "when": pred, "action": "require-approval"}]}
    try:
        ap.compile_rules(doc)
    except RecursionError:
        return _break("F219: raw RecursionError escaped "
                      "compile_rules()")
    except ap.ApprovalPolicyError as exc:
        return _held("machine-coded refusal %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("pathological predicate compiled")


@probe("approval/no-audit-sink-refused")
def _p_no_sink():
    rs = _auto_rules()
    try:
        ap.route(rs, {"kind": "x"})
    except ap.ApprovalPolicyError as exc:
        if exc.code == ap.NO_AUDIT_SINK:
            return _held("silent auto-approve refused")
        return _break("wrong code %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("auto-approved with no sink")


@probe("approval/non-callable-sink-refused")
def _p_bad_sink():
    rs = _auto_rules()
    try:
        ap.route(rs, {"kind": "x"}, audit_sink="not-callable")
    except ap.ApprovalPolicyError as exc:
        if exc.code == ap.NO_AUDIT_SINK:
            return _held("non-callable sink refused")
        return _break("wrong code %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("auto-approved with non-callable sink")


@probe("approval/disapproval-defaulted")
def _p_disapproval_defaulted():
    # Hand-built RuleSet smuggling a disapproval outcome without
    # the explicit opt-in: route-time defense-in-depth must refuse.
    rules = ap.RuleSet([("r-evil", {"field": "a", "op": "exists"},
                         "disapproval-opt-in", False)])
    try:
        ap.route(rules, {"a": 1}, audit_sink=lambda e: None)
    except ap.ApprovalPolicyError as exc:
        if exc.code == ap.DISAPPROVAL_DEFAULTED:
            return _held("defaulted disapproval refused")
        return _break("wrong code %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("disapproval taken without opt-in")


@probe("approval/disapproval-opt-in-audited")
def _p_disapproval_legit():
    # The legitimate path: explicit opt-in + sink -> audited
    # disapproval with a recorded entry.
    seen = []
    rs = ap.compile_rules({
        "version": 1,
        "rules": [{
            "id": "r-deny",
            "when": {"field": "kind", "op": "eq", "value": "bad"},
            "action": "disapproval-opt-in", "disapproval": True}],
    })
    out = ap.route(rs, {"kind": "bad"}, audit_sink=seen.append)
    if out.get("audited") and seen and\
            seen[0]["decision"] == "disapproved":
        return _held("opt-in disapproval audited")
    return _break("opt-in path misbehaved: %r" % (out,))


@probe("approval/no-match-requires-approval")
def _p_no_match():
    # No rule matches -> require-approval; with no queue the seam
    # refuses SEAM_UNAVAILABLE (dropped, never auto-passed).
    rs = _auto_rules()
    try:
        ap.route(rs, {"kind": "nope"})
    except ap.ApprovalPolicyError as exc:
        if exc.code == ap.SEAM_UNAVAILABLE:
            return _held("unmatched request dropped, not auto-passed")
        return _break("wrong code %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("unmatched request routed without a queue")


@probe("approval/predicate-field-injection")
def _p_field_injection():
    # Dotted-path reads never call getattr: dunder fields cannot
    # escape the dict descent.
    rs = ap.compile_rules({
        "version": 1,
        "rules": [{
            "id": "r-inj",
            "when": {"field": "__class__.__name__", "op": "eq",
                     "value": "dict"},
            "action": "auto-approve"}],
    })
    out = rs.evaluate({"__class__": "planted"})
    if out.action == "require-approval" and not out.matched:
        return _held("dunder field does not match")
    return _break("injection matched: %r" % (out.to_dict(),))


@probe("approval/evaluate-non-dict-refused")
def _p_eval_nondict():
    rs = _auto_rules()
    try:
        rs.evaluate("not-a-dict")
    except ap.ApprovalPolicyError as exc:
        if exc.code == ap.MALFORMED:
            return _held("non-dict request refused")
        return _break("wrong code %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("non-dict request evaluated")


@probe("approval/unknown-op-refused-at-compile")
def _p_unknown_op():
    try:
        ap.compile_rules({
            "version": 1,
            "rules": [{
                "id": "r-bad",
                "when": {"field": "a", "op": "regex", "value": "x"},
                "action": "require-approval"}],
        })
    except ap.ApprovalPolicyError as exc:
        if exc.code == ap.MALFORMED:
            return _held("unknown op refused at compile")
        return _break("wrong code %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("unknown op compiled")


# ---------------------------------------------------------------------------
# B. compliance_emitter.py (new in wave-254)
# ---------------------------------------------------------------------------

def _good_source():
    return {
        "id": "SAS-T-001",
        "title": "T",
        "description": "D",
        "mappings": [{
            "kind": "code", "ref": "permit-journal-misuse",
            "rationale": "R"}],
    }


@probe("compliance/dangling-code-refused")
def _p_dangling_code():
    src = _good_source()
    src["mappings"][0]["ref"] = "no-such-code"
    try:
        ce.validate_source(src)
    except ce.ComplianceEmitterError as exc:
        if exc.code == ce.UNKNOWN_CODE:
            return _held("unknown code refused")
        return _break("wrong code %s" % exc.code)
    return _break("dangling code mapping validated")


@probe("compliance/dangling-mechanism-refused")
def _p_dangling_mech():
    src = _good_source()
    src["mappings"] = [{
        "kind": "mechanism", "ref": "no-such-mechanism",
        "rationale": "R"}]
    try:
        ce.validate_source(src)
    except ce.ComplianceEmitterError as exc:
        if exc.code == ce.UNKNOWN_MECHANISM:
            return _held("unknown mechanism refused")
        return _break("wrong code %s" % exc.code)
    return _break("dangling mechanism mapping validated")


@probe("compliance/dangling-track-refused")
def _p_dangling_track():
    src = _good_source()
    src["mappings"] = [{
        "kind": "posture_track", "ref": "no-such-track",
        "rationale": "R"}]
    try:
        ce.validate_source(src)
    except ce.ComplianceEmitterError as exc:
        if exc.code == ce.UNKNOWN_TRACK:
            return _held("unknown track refused")
        return _break("wrong code %s" % exc.code)
    return _break("dangling track mapping validated")


@probe("compliance/dangling-finding-refused")
def _p_dangling_finding():
    src = _good_source()
    src["mappings"] = [{
        "kind": "finding", "ref": "F999", "rationale": "R"}]
    # (a) no findings index at all
    try:
        ce.validate_source(src)
        return _break("finding validated with no index")
    except ce.ComplianceEmitterError as exc:
        if exc.code != ce.UNKNOWN_FINDING:
            return _break("wrong code %s" % exc.code)
    # (b) index present but id unknown
    try:
        ce.validate_source(src, findings={"F214": "closed"})
        return _break("unknown finding id validated")
    except ce.ComplianceEmitterError as exc:
        if exc.code != ce.UNKNOWN_FINDING:
            return _break("wrong code %s" % exc.code)
    return _held("unknown finding refused with/without index")


@probe("compliance/unlinked-claim-refused")
def _p_unlinked():
    src = _good_source()
    src["mappings"] = []
    try:
        ce.validate_source(src)
    except ce.ComplianceEmitterError as exc:
        if exc.code == ce.UNLINKED_CLAIM:
            return _held("zero-mapping claim refused")
        return _break("wrong code %s" % exc.code)
    return _break("unlinked claim validated")


@probe("compliance/unknown-format-refused")
def _p_unknown_format():
    try:
        ce.emit(_good_source(), "xml")
    except ce.ComplianceEmitterError as exc:
        if exc.code == ce.UNKNOWN_FORMAT:
            return _held("unknown format refused")
        return _break("wrong code %s" % exc.code)
    return _break("unknown format emitted")


@probe("compliance/source-aliasing")
def _p_aliasing():
    # validate_source must return a normalized deep copy: caller
    # mutation afterwards cannot change what was validated.
    src = _good_source()
    norm = ce.validate_source(src)
    src["mappings"][0]["ref"] = "MUTATED"
    src["mappings"].append(
        {"kind": "code", "ref": "zzz", "rationale": "z"})
    if norm["mappings"][0]["ref"] == "permit-journal-misuse" and\
            len(norm["mappings"]) == 1:
        return _held("normalized copy isolated from caller")
    return _break("caller mutation leaked into normalized source")


@probe("compliance/drift-digest")
def _p_drift():
    # The source digest binds resolved finding statuses: a status
    # flip changes the digest carried in every artifact.
    src = _good_source()
    src["mappings"] = [{
        "kind": "finding", "ref": "F214", "rationale": "R"}]
    d1 = ce.source_content_digest(src, findings={"F214": "open"})
    d2 = ce.source_content_digest(src, findings={"F214": "closed"})
    if d1 != d2 and len(d1) == 64:
        return _held("digest binds finding status")
    return _break("digest does not bind status")


# ---------------------------------------------------------------------------
# C. inventory_catalog.py (new in wave-255)
# ---------------------------------------------------------------------------

def _two_entry_catalog():
    return ic.load_catalog([
        {"kind": "agent", "name": "a1", "owner": "o",
         "relationships": [{"to": "t1", "type": "uses"}]},
        {"kind": "tool", "name": "t1", "owner": "o",
         "relationships": []},
    ])


@probe("inventory/dangling-rel-refused")
def _p_dangling_rel():
    try:
        ic.load_catalog([{
            "kind": "agent", "name": "a1", "owner": "o",
            "relationships": [{"to": "ghost", "type": "uses"}]}])
    except ic.CatalogRefused as exc:
        if exc.code == ic.DANGLING_REFERENCE:
            return _held("dangling relationship refused")
        return _break("wrong code %s" % exc.code)
    return _break("dangling relationship loaded")


@probe("inventory/duplicate-entry-refused")
def _p_duplicate():
    try:
        ic.load_catalog([
            {"kind": "agent", "name": "a1", "owner": "o",
             "relationships": []},
            {"kind": "tool", "name": "a1", "owner": "o",
             "relationships": []},
        ])
    except ic.CatalogRefused as exc:
        if exc.code == ic.DUPLICATE_ENTRY:
            return _held("duplicate name refused")
        return _break("wrong code %s" % exc.code)
    return _break("duplicate names loaded")


@probe("inventory/non-dict-cards-refused")
def _p_nondict_cards():
    cat = _two_entry_catalog()
    try:
        ic.attach_scorecard(cat, "a1", ["not-a-dict"])
    except ic.CatalogRefused as exc:
        if exc.code == ic.CARD_MALFORMED:
            return _held("non-dict cards refused (F215 class)")
        return _break("wrong code %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("non-dict scorecard attached")


@probe("inventory/grant-from-non-agent-refused")
def _p_grant_nonagent():
    cat = ic.load_catalog([
        {"kind": "tool", "name": "t1", "owner": "o",
         "relationships": [{"to": "t2", "type": "grant"}]},
        {"kind": "tool", "name": "t2", "owner": "o",
         "relationships": []},
    ])
    try:
        ic.grant_edges(cat, grants_provider=lambda a, t: True)
    except ic.CatalogRefused as exc:
        if exc.code == ic.ENTRY_MALFORMED:
            return _held("grant from non-agent refused")
        return _break("wrong code %s" % exc.code)
    return _break("non-agent grant edge resolved")


@probe("inventory/no-provider-refused")
def _p_no_provider():
    cat = ic.load_catalog([
        {"kind": "agent", "name": "a1", "owner": "o",
         "relationships": [{"to": "t1", "type": "grant"}]},
        {"kind": "tool", "name": "t1", "owner": "o",
         "relationships": []},
    ])
    try:
        ic.grant_edges(cat)
    except ic.CatalogRefused as exc:
        if exc.code == ic.SEAM_UNAVAILABLE:
            return _held("missing grants seam refused")
        return _break("wrong code %s" % exc.code)
    return _break("grant edges resolved with no provider")


@probe("inventory/provider-failure-refused")
def _p_provider_failure():
    cat = ic.load_catalog([
        {"kind": "agent", "name": "a1", "owner": "o",
         "relationships": [{"to": "t1", "type": "grant"}]},
        {"kind": "tool", "name": "t1", "owner": "o",
         "relationships": []},
    ])

    def boom(agent, tool):
        raise RuntimeError("provider down")

    try:
        ic.grant_edges(cat, grants_provider=boom)
    except ic.CatalogRefused as exc:
        if exc.code == ic.GRANT_UNRESOLVED:
            return _held("provider failure refused closed")
        return _break("wrong code %s" % exc.code)
    return _break("grant resolved despite provider failure")


@probe("inventory/entry-immutability")
def _p_immutability():
    # F212 lesson: readers return deep copies; caller mutation
    # cannot corrupt catalog state.
    cat = _two_entry_catalog()
    entry = ic.entry_of(cat, "a1")
    entry["relationships"].append({"to": "zzz", "type": "uses"})
    entry["owner"] = "mallory"
    fresh = ic.entry_of(cat, "a1")
    if len(fresh["relationships"]) == 1 and\
            fresh["owner"] == "o":
        return _held("catalog immune to caller mutation")
    return _break("caller mutation corrupted catalog state")


# ---------------------------------------------------------------------------
# D. incident.py (past the F216 closure)
# ---------------------------------------------------------------------------

def _incident(tmp, finding_status=None):
    return inc_mod.IncidentManager(
        os.path.join(tmp, "inc.jsonl"), finding_status=finding_status)


@probe("incident/f216-regression")
def _p_f216():
    # F216 closure: transition() to "resolved" is refused;
    # resolve() is the single fail-closed path.
    tmp = _tmpdir()
    mgr = _incident(tmp)
    mgr.declare_incident("INC-1", title="t", severity="high")
    mgr.transition("INC-1", "investigating")
    mgr.transition("INC-1", "contained")
    try:
        mgr.transition("INC-1", "resolved")
    except inc_mod.IncidentError:
        return _held("F216 fix holds")
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("transition to resolved allowed (F216 open)")


@probe("incident/complete-unknown-task-refused")
def _p_unknown_task():
    tmp = _tmpdir()
    mgr = _incident(tmp)
    mgr.declare_incident("INC-1", title="t", severity="low")
    try:
        mgr.complete_task("INC-1", "task-999")
    except inc_mod.IncidentError as exc:
        if exc.code == "incident-unknown":
            return _held("unknown task refused")
        return _break("wrong code %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("unknown task completed")


@probe("incident/open-to-closed-refused")
def _p_open_closed():
    tmp = _tmpdir()
    mgr = _incident(tmp)
    mgr.declare_incident("INC-1", title="t", severity="low")
    try:
        mgr.transition("INC-1", "closed")
    except inc_mod.IncidentError as exc:
        if exc.code == "incident-illegal-transition":
            return _held("open -> closed refused")
        return _break("wrong code %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("open -> closed allowed")


# ---------------------------------------------------------------------------
# E. policy_authoring.py (past the F217 closure)
# ---------------------------------------------------------------------------

@probe("authoring/f217-regression")
def _p_f217():
    # F217 closure: explain_candidate() normalizes action/context;
    # no raw AttributeError escapes.
    compiled = pa.compile_authoring(
        "version: 1\n"
        "policies:\n"
        "  - name: p1\n"
        "    description: d\n"
        "    filters:\n"
        "      - type: value-filter\n"
        "        key: tool\n"
        "        op: eq\n"
        "        value: read_file\n"
        "    actions:\n"
        "      - type: deny\n"
        "        reason: d\n",
        source_label="w256rt")
    for action, context in ((["not", "a", "dict"], None),
                            ("x", {})):
        try:
            pa.explain_candidate(compiled, action, context)
        except pa.AuthoringError:
            continue
        except AttributeError:
            return _break("raw AttributeError escaped (F217 open)")
        except Exception as exc:
            return _break("raw %s escaped" % type(exc).__name__)
    return _held("F217 fix holds")


@probe("authoring/explain-non-compiled-refused")
def _p_non_compiled():
    try:
        pa.explain_candidate(None, {}, {})
    except pa.AuthoringError as exc:
        if exc.code == pa.MALFORMED_CODE:
            return _held("non-CompiledPolicy refused")
        return _break("wrong code %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("None compiled accepted")


# ---------------------------------------------------------------------------
# F. permit_journal.py (past F214/F218)
# ---------------------------------------------------------------------------

@probe("journal/f214-regression")
def _p_f214():
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


@probe("journal/f218-regression")
def _p_f218():
    # F218 closure: depth-bounded before any write, on the single
    # choke point -- record_use (not just grant) is covered.
    tmp = _tmpdir()
    j = pj.PermitJournal(os.path.join(tmp, "j.jsonl"),
                         key=os.urandom(32))
    j.grant("P1", payload={"ok": True})
    deep = {"a": 1}
    for _ in range(300):
        deep = {"n": deep}
    try:
        j.record_use("P1", payload=deep)
    except pj.PermitJournalRefusal as exc:
        if exc.code == "permit-journal-misuse":
            return _held("F218 fix holds on record_use")
        return _break("wrong code %s" % exc.code)
    except RecursionError:
        return _break("raw RecursionError escaped (F218 open)")
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("deep payload recorded")


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
