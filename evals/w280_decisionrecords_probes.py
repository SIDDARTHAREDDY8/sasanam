"""Wave-280 lane 7 red-first battery: CheckResources contract + NDJSON decision records.

Gap (base 7849c86): the policy engine's evaluate() returns a Decision, but
there is no Cerbos-shaped CheckResources contract -- no
principal/resource/action request surface, no matched-policy provenance
in the response (which rule decided and why), no derived roles, no
compile-time shadow detection, and no uniform hash-chained decision
record per decision in the audit log.

Red-first: on base every probe BREAKs (module absent). After the fix:
the contract answers per-action decisions with matched-rule provenance,
derived roles resolve at request time, shadowed/duplicate rules refuse
at load, every decision lands as a chained decision-record in the HMAC
log at decision time (never batched), tampering refuses, and secrets
never land raw in the record.

Pattern lineage: cerbos/cerbos CheckResources (Apache-2.0 -- shapes only,
no code vendored, no Go sidecar in-tree): request {principal, resource,
actions} -> per-action effect + matched policy + requestId; derived
roles; compile-error-on-shadow; NDJSON decision logs. Composed with
gov/guardrail_evidence.py's wire (ActionLog.append), not duplicating it.
"""

import hashlib
import json
import os
import secrets
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w280-decisionrecords")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe_lines  # noqa: E402  (canonical probe-line form)

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


_RESULTS = []


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict, "note": note})


def _needs_module(probe_id):
    try:
        from gov import check_resources as cr
        return cr
    except ImportError:
        _record(probe_id, "BREAK", "gov.check_resources absent on base")
        return None


def _fresh_log():
    d = tempfile.mkdtemp(prefix="g280_", dir=os.environ["TMPDIR"])
    from gov.log import ActionLog
    return ActionLog(os.path.join(d, "audit.jsonl"))


def _base_bundle():
    return {
        "bundle_version": "1",
        "policy_version": "2026-10-02",
        "derived_roles": [
            {"name": "owner",
             "when": [{"subject": "resource.attr.owner", "op": "eq",
                       "ref": "principal.id"}]},
        ],
        "rules": [
            {"id": "read-own", "resource_kind": "document",
             "actions": ["read"], "roles": ["owner"], "effect": "allow",
             "reason": "owners may read their documents", "conditions": []},
            {"id": "deny-delete", "resource_kind": "document",
             "actions": ["delete"], "roles": [], "effect": "deny",
             "reason": "documents are immutable", "conditions": []},
        ],
    }


def _req(principal_id="alice", roles=("viewer",), owner="alice",
         actions=("read",), request_id="r1"):
    return {
        "request_id": request_id,
        "principal": {"id": principal_id, "roles": list(roles), "attrs": {}},
        "resource": {"kind": "document", "id": "d1",
                     "attrs": {"owner": owner}},
        "actions": list(actions),
        "context": {},
    }


# -- probes ---------------------------------------------------------------


def p_module_present():
    cr = _needs_module("p_module_present")
    if cr is None:
        return
    _record("p_module_present", "HELD", "gov.check_resources present")


def p_shadow_refused_at_load():
    cr = _needs_module("p_shadow_refused_at_load")
    if cr is None:
        return
    b = _base_bundle()
    # "read-anyone" matches a superset of "read-own" and precedes it, so
    # "read-own" can never fire: a compile error, not a silent dead rule.
    b["rules"] = [
        {"id": "read-anyone", "resource_kind": "document",
         "actions": ["read"], "roles": [], "effect": "allow",
         "reason": "anyone reads", "conditions": []},
        {"id": "read-own", "resource_kind": "document",
         "actions": ["read"], "roles": ["owner"], "effect": "allow",
         "reason": "owners read", "conditions": []},
    ]
    try:
        cr.compile_bundle(b)
    except cr.BundleCompileError as e:
        if "read-own" in str(e):
            return _record("p_shadow_refused_at_load", "HELD",
                           "shadowed rule read-own refused at load: %s" % (e,))
        return _record("p_shadow_refused_at_load", "BREAK",
                       "compile error names no rule: %s" % (e,))
    except Exception as e:  # noqa: BLE001 - probe asserts the typed error
        return _record("p_shadow_refused_at_load", "BREAK",
                       "wrong exception type: %r" % (type(e).__name__,))
    _record("p_shadow_refused_at_load", "BREAK",
            "shadowed rule compiled without complaint")


def p_shadow_same_effect_still_refused():
    cr = _needs_module("p_shadow_same_effect_still_refused")
    if cr is None:
        return
    b = _base_bundle()
    b["rules"] = [
        {"id": "deny-all-delete", "resource_kind": "document",
         "actions": ["delete"], "roles": [], "effect": "deny",
         "reason": "no deletes", "conditions": []},
        {"id": "deny-owner-delete", "resource_kind": "document",
         "actions": ["delete"], "roles": ["owner"], "effect": "deny",
         "reason": "no deletes for owners either", "conditions": []},
    ]
    try:
        cr.compile_bundle(b)
    except cr.BundleCompileError:
        return _record("p_shadow_same_effect_still_refused", "HELD",
                       "dead rule refused even when effects agree")
    _record("p_shadow_same_effect_still_refused", "BREAK",
            "same-effect shadow compiled without complaint")


def p_duplicate_rule_id_refused():
    cr = _needs_module("p_duplicate_rule_id_refused")
    if cr is None:
        return
    b = _base_bundle()
    b["rules"] = [dict(b["rules"][0]), dict(b["rules"][0])]
    try:
        cr.compile_bundle(b)
    except cr.BundleCompileError:
        return _record("p_duplicate_rule_id_refused", "HELD",
                       "duplicate rule id refused at load")
    _record("p_duplicate_rule_id_refused", "BREAK",
            "duplicate rule id compiled without complaint")


def p_unknown_op_refused_at_load():
    cr = _needs_module("p_unknown_op_refused_at_load")
    if cr is None:
        return
    b = _base_bundle()
    b["rules"][0]["conditions"] = [
        {"subject": "resource.attr.flag", "op": "approximately",
         "value": True}]
    try:
        cr.compile_bundle(b)
    except cr.BundleCompileError:
        return _record("p_unknown_op_refused_at_load", "HELD",
                       "unknown condition op refused at load")
    _record("p_unknown_op_refused_at_load", "BREAK",
            "unknown op compiled without complaint")


def p_default_deny():
    cr = _needs_module("p_default_deny")
    if cr is None:
        return
    pdp = cr.CheckResources(cr.compile_bundle(_base_bundle()), _fresh_log())
    resp = pdp.check(_req(actions=("write",)))
    d = resp.results["write"]
    if d.effect == "deny" and d.matched_rule_id == "default_deny":
        return _record("p_default_deny", "HELD",
                       "no-match -> deny with default_deny provenance")
    _record("p_default_deny", "BREAK",
            "no-match gave %r / %r" % (d.effect, d.matched_rule_id))


def p_matched_provenance():
    cr = _needs_module("p_matched_provenance")
    if cr is None:
        return
    pdp = cr.CheckResources(cr.compile_bundle(_base_bundle()), _fresh_log())
    resp = pdp.check(_req())
    d = resp.results["read"]
    if d.effect == "allow" and d.matched_rule_id == "read-own"\
            and d.reason == "owners may read their documents":
        return _record("p_matched_provenance", "HELD",
                       "allow names rule read-own + its declared reason")
    _record("p_matched_provenance", "BREAK",
            "provenance wrong: %r / %r / %r"
            % (d.effect, d.matched_rule_id, d.reason))


def p_derived_role_grants():
    cr = _needs_module("p_derived_role_grants")
    if cr is None:
        return
    pdp = cr.CheckResources(cr.compile_bundle(_base_bundle()), _fresh_log())
    yes = pdp.check(_req()).results["read"]
    no = pdp.check(_req(owner="mallory")).results["read"]
    if yes.effect == "allow" and "owner" in yes.derived_roles\
            and no.effect == "deny":
        return _record("p_derived_role_grants", "HELD",
                       "owner derived iff resource.attr.owner == principal.id")
    _record("p_derived_role_grants", "BREAK",
            "derived role wrong: %r / %r" % (yes.effect, no.effect))


def p_derived_role_recorded():
    cr = _needs_module("p_derived_role_recorded")
    if cr is None:
        return
    log = _fresh_log()
    pdp = cr.CheckResources(cr.compile_bundle(_base_bundle()), log)
    pdp.check(_req())
    recs = cr.decision_records(log)
    if len(recs) == 1 and recs[0]["derived_roles"] == ["owner"]\
            and recs[0]["principal_id"] == "alice":
        return _record("p_derived_role_recorded", "HELD",
                       "decision record carries derived_roles=['owner']")
    _record("p_derived_role_recorded", "BREAK",
            "record missing derived roles: %r" % (recs,))


def p_record_chained_at_decision_time():
    cr = _needs_module("p_record_chained_at_decision_time")
    if cr is None:
        return
    log = _fresh_log()
    pdp = cr.CheckResources(cr.compile_bundle(_base_bundle()), log)
    pdp.check(_req(actions=("read", "delete")))
    recs = cr.decision_records(log)
    if len(recs) != 2:
        return _record("p_record_chained_at_decision_time", "BREAK",
                       "expected 2 records, got %d" % (len(recs),))
    if recs[0]["prev_decision_record_digest"] != "genesis"\
            or recs[1]["prev_decision_record_digest"] !=\
            recs[0]["record_digest"]:
        return _record("p_record_chained_at_decision_time", "BREAK",
                       "per-writer chain broken")
    if not cr.verify_decision_records(recs):
        return _record("p_record_chained_at_decision_time", "BREAK",
                       "fresh chain does not verify")
    eff = {r["action"]: r["effect"] for r in recs}
    if eff != {"read": "allow", "delete": "deny"}:
        return _record("p_record_chained_at_decision_time", "BREAK",
                       "record effects wrong: %r" % (eff,))
    _record("p_record_chained_at_decision_time", "HELD",
            "2 chained records at decision time; read=allow, delete=deny")


def p_tamper_detected():
    cr = _needs_module("p_tamper_detected")
    if cr is None:
        return
    log = _fresh_log()
    pdp = cr.CheckResources(cr.compile_bundle(_base_bundle()), log)
    pdp.check(_req(actions=("read", "delete")))
    recs = cr.decision_records(log)
    mutated = [dict(r) for r in recs]
    mutated[0]["effect"] = "allow" if mutated[0]["effect"] == "deny"\
        else "deny"
    dropped = recs[:1]
    if cr.verify_decision_records(mutated):
        return _record("p_tamper_detected", "BREAK",
                       "mutated effect still verifies")
    # A chain cannot attest to its own completeness (a valid prefix
    # verifies); the action_index/action_count pair closes that.
    if cr.request_records_complete(dropped, request_id="r1"):
        return _record("p_tamper_detected", "BREAK",
                       "dropped record still complete")
    _record("p_tamper_detected", "HELD",
            "mutated effect refuses; dropped suffix incomplete")


def p_secrets_not_in_record():
    cr = _needs_module("p_secrets_not_in_record")
    if cr is None:
        return
    log = _fresh_log()
    pdp = cr.CheckResources(cr.compile_bundle(_base_bundle()), log)
    req = _req()
    req["resource"]["attrs"]["owner"] = "alice"
    req["resource"]["attrs"]["secret_note"] = "hunter2-confidential"
    pdp.check(req)
    raw = open(log.path, encoding="utf-8").read()
    if "hunter2-confidential" in raw:
        return _record("p_secrets_not_in_record", "BREAK",
                       "secret value present raw in the log")
    recs = cr.decision_records(log)
    want = hashlib.sha256(json.dumps(
        {"owner": "alice", "secret_note": "hunter2-confidential"},
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if recs[0]["resource_attrs_digest"] != want:
        return _record("p_secrets_not_in_record", "BREAK",
                       "attrs digest does not bind actual attrs")
    _record("p_secrets_not_in_record", "HELD",
            "attrs bound by digest only; no raw secret in log")


def p_log_required():
    cr = _needs_module("p_log_required")
    if cr is None:
        return
    try:
        cr.CheckResources(cr.compile_bundle(_base_bundle()), None)
    except cr.CheckResourcesError:
        return _record("p_log_required", "HELD",
                       "no audit sink -> loud refusal (Cerbos opt-in trap "
                       "avoided)")
    except Exception as e:  # noqa: BLE001 - probe asserts the typed error
        return _record("p_log_required", "BREAK",
                       "wrong exception type: %r" % (type(e).__name__,))
    _record("p_log_required", "BREAK",
            "PDP constructed without a log: silent unaudited decisions")


def p_batch_actions():
    cr = _needs_module("p_batch_actions")
    if cr is None:
        return
    pdp = cr.CheckResources(cr.compile_bundle(_base_bundle()), _fresh_log())
    resp = pdp.check(_req(actions=("read", "write", "delete")))
    eff = {a: d.effect for a, d in resp.results.items()}
    if eff == {"read": "allow", "write": "deny", "delete": "deny"}:
        return _record("p_batch_actions", "HELD",
                       "per-action effects independent in one request")
    _record("p_batch_actions", "BREAK", "batch effects wrong: %r" % (eff,))


def p_type_strict_eq():
    cr = _needs_module("p_type_strict_eq")
    if cr is None:
        return
    b = _base_bundle()
    b["rules"] = [
        {"id": "flag-read", "resource_kind": "document",
         "actions": ["read"], "roles": [], "effect": "allow",
         "reason": "flagged", "conditions": [
             {"subject": "resource.attr.flag", "op": "eq", "value": 1}]},
    ]
    pdp = cr.CheckResources(cr.compile_bundle(b), _fresh_log())
    req = _req()
    req["resource"]["attrs"] = {"flag": True}
    d = pdp.check(req).results["read"]
    if d.effect == "deny":
        return _record("p_type_strict_eq", "HELD",
                       "eq is type-strict: True does not match 1")
    _record("p_type_strict_eq", "BREAK",
            "bool/int conflated in eq: %r" % (d.effect,))


def p_malformed_request_loud():
    cr = _needs_module("p_malformed_request_loud")
    if cr is None:
        return
    pdp = cr.CheckResources(cr.compile_bundle(_base_bundle()), _fresh_log())
    bad = _req()
    bad["principal"]["id"] = 12345
    try:
        pdp.check(bad)
    except cr.CheckRequestError:
        return _record("p_malformed_request_loud", "HELD",
                       "non-string principal id -> typed refusal")
    except Exception as e:  # noqa: BLE001 - probe asserts the typed error
        return _record("p_malformed_request_loud", "BREAK",
                       "raw exception escaped: %r" % (type(e).__name__,))
    _record("p_malformed_request_loud", "BREAK",
            "malformed request was accepted")


def p_duplicate_actions_refused():
    cr = _needs_module("p_duplicate_actions_refused")
    if cr is None:
        return
    pdp = cr.CheckResources(cr.compile_bundle(_base_bundle()), _fresh_log())
    req = _req(actions=("read", "read"))
    try:
        pdp.check(req)
    except cr.CheckRequestError:
        return _record("p_duplicate_actions_refused", "HELD",
                       "duplicate actions -> typed refusal (response/log "
                       "cannot diverge)")
    except Exception as e:  # noqa: BLE001 - probe asserts the typed error
        return _record("p_duplicate_actions_refused", "BREAK",
                       "raw exception escaped: %r" % (type(e).__name__,))
    _record("p_duplicate_actions_refused", "BREAK",
            "duplicate actions were accepted")


def p_taxonomy_pin():
    import re
    src = open(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "gov", "decision_codes.py")).read()
    codes = re.findall(r'"code":\s*\'([^\']+)\'', src)
    if len(codes) != TAXONOMY_PIN or len(set(codes)) != TAXONOMY_PIN:
        return _record("p_taxonomy_pin", "BREAK",
                       "pin drift: %d raw / %d unique, want %d"
                       % (len(codes), len(set(codes)), TAXONOMY_PIN))
    _record("p_taxonomy_pin", "HELD", "taxonomy pin %d holds, no new codes"
            % TAXONOMY_PIN)


def _green_checks():
    # Depth-1: adjacent suites only, never spawn another battery's main.
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "SKIP", "GOV_SKIP_GREEN=1")
        return
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    for mod in ("tests.test_decision_codes",):
        r = subprocess.run([sys.executable, "-m", "unittest", mod],
                           cwd=os.path.dirname(here), env=env,
                           capture_output=True, text=True, timeout=300)
        _record("green-check_" + mod,
                "HELD" if r.returncode == 0 else "ERROR",
                (r.stderr or r.stdout)[-200:])


def main():
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
    for probe in (p_module_present, p_shadow_refused_at_load,
                  p_shadow_same_effect_still_refused,
                  p_duplicate_rule_id_refused, p_unknown_op_refused_at_load,
                  p_default_deny, p_matched_provenance,
                  p_derived_role_grants, p_derived_role_recorded,
                  p_record_chained_at_decision_time, p_tamper_detected,
                  p_secrets_not_in_record, p_log_required, p_batch_actions,
                  p_type_strict_eq, p_malformed_request_loud,
                  p_duplicate_actions_refused, p_taxonomy_pin):
        try:
            probe()
        except Exception as e:  # noqa: BLE001 - battery must never die
            _record(probe.__name__, "ERROR", "%r" % (e,))
    _green_checks()
    n_break = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    n_err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    n_held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    print("w280_decisionrecords: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    probe_lines.emit_dicts(_RESULTS, verdict_key="verdict",
                           pid_key="probe_id", note_key="note")
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
