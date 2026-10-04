#!/usr/bin/env python3
"""Wave-206 lane C: red-first battery for the decision+diagnostics contract.

RED-FIRST: run against the PRISTINE tree first. Every probe imports
gov.decision_diagnostics -- absent there -- so the pristine run is
uniformly ERROR (missing public seams), and the fixed tree holds. The
canonical PERM model/policy/scenarios are duplicated verbatim from
evals/perm_loader_probes.py (hermetic per that file's plan).

Probes:

  diag_every_decision_carries_determiners -- the 9 spike scenarios
      each produce a record whose determining_policies name the exact
      matched rows of the deciding screen (non-empty when a screen
      fired); verify_decision_record passes on all 9.
  diag_typo_pack_refused               -- model with a typo'd request
      column (actoin) refused at load (Cedar typo-trap regression).
  diag_unknown_attr_refused            -- policy row with an unknown
      column refused at load (regression lock on strictness).
  diag_no_decision_explicit            -- a request no row matches
      yields an explicit no-decision record (unknown_entities +
      decision_holds_iff) under default_as_no_decision, and a
      default_used=True record otherwise. No silent default.
  diag_forged_determiners_break_digest -- editing determining_policies
      (or the decision) post-hoc breaks decision_id verification.
  diag_record_rebinding               -- a record does not verify
      against a different request (request_digest) or a different
      pack (perm digests): cross-request / cross-pack swaps refused.
  diag_v2_roundtrip                    -- diagnostics ride a v2 event:
      verify_event passes; the v2 decision_id binds the block
      (tampering breaks it); legacy events without the block still
      verify (bytes preserved).
  diag_const_false_matcher_refused     -- a screen matcher that
      constant-folds to False (provably never-true) is refused at
      load: the silently-never-matching pack shape.
  diag_const_true_matcher_allowed      -- documents the asymmetry: a
      constant-TRUE matcher ("match all") is the pack author's
      explicit, digest-visible choice and loads.
  diag_no_decision_record_ctor         -- the explicit no_decision_record
      constructor validates model/request and carries the residual.
"""

import copy
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
sys.path.insert(0, REPO_ROOT)

_records = []


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md): this battery
# records PASS/FAIL/HELD/BROKEN/GAP/RED/GREEN/ERROR/SKIP; the
# canonical emission vocabulary is BREAK/HELD/ERROR/SKIP, mapped
# red-first (PASS/GREEN->HELD, FAIL/BROKEN/GAP/RED->BREAK). Probe
# logic, verdict computation and count code are untouched -- only
# the print loop below maps.
_VERDICT_MAP = {
    "PASS": "HELD", "HELD": "HELD", "GREEN": "HELD",
    "FAIL": "BREAK", "BROKEN": "BREAK", "GAP": "BREAK",
    "RED": "BREAK", "BREAK": "BREAK",
    "ERROR": "ERROR", "SKIP": "SKIP", "SKIPPED": "SKIP",
}

PERM_MODEL_YML = """\
perm_model: sasanam-perm/v1
model_version: 1
description: "Wave-200 canonical PERM model: tool-call governance with deny/approval/allow screens."
request_schema:
  agent_id: str
  tool_name: str
  egress_class: str
  velocity_1m: int
  approval_state: str
policy_schema:
  agent_pat: str
  tool_pat: str
  vel_limit: int
  eft: eft
matchers:
  toolMatch: glob
screens:
  -
    name: deny
    description: "Forbid-overrides: a forbidden tool, or velocity above the line limit, denies."
    effect: "!some(where (p_eft == deny))"
    matcher:
      and:
        -
          or:
            -
              eq:
                -
                  pol: agent_pat
                - "*"
            -
              eq:
                -
                  req: agent_id
                -
                  pol: agent_pat
        -
          or:
            -
              call:
                - toolMatch
                -
                  req: tool_name
                -
                  pol: tool_pat
            -
              gt:
                -
                  req: velocity_1m
                -
                  pol: vel_limit
  -
    name: approval
    description: "Classified tool without a granted approval needs a human."
    effect: "some(where (p_eft == allow))"
    matcher:
      and:
        -
          or:
            -
              eq:
                -
                  pol: agent_pat
                - "*"
            -
              eq:
                -
                  req: agent_id
                -
                  pol: agent_pat
        -
          call:
            - toolMatch
            -
              req: tool_name
            -
              pol: tool_pat
        -
          neq:
            -
              req: approval_state
            - granted
        -
          lte:
            -
              req: velocity_1m
            -
              pol: vel_limit
  -
    name: allow
    description: "Ordinary tools, or classified tools with a granted approval."
    effect: "some(where (p_eft == allow))"
    matcher:
      and:
        -
          or:
            -
              eq:
                -
                  pol: agent_pat
                - "*"
            -
              eq:
                -
                  req: agent_id
                -
                  pol: agent_pat
        -
          call:
            - toolMatch
            -
              req: tool_name
            -
              pol: tool_pat
        -
          lte:
            -
              req: velocity_1m
            -
              pol: vel_limit
        -
          or:
            -
              neq:
                -
                  req: egress_class
                - classified
            -
              eq:
                -
                  req: approval_state
                - granted
composition:
  default_verdict: deny
  order:
    -
      screen: deny
      verdict: deny
      invert: true
    -
      screen: approval
      verdict: require_approval
    -
      screen: allow
      verdict: allow
"""

PERM_POLICY_YML = """\
perm_policy: sasanam-perm/v1
description: "Wave-200 canonical PERM policy rows for the 9 spike scenarios."
policies:
  deny:
    -
      agent_pat: "*"
      tool_pat: install_package
      vel_limit: 999999999
      eft: deny
    -
      agent_pat: "*"
      tool_pat: __no_tool__
      vel_limit: 10
      eft: deny
  approval:
    -
      agent_pat: "*"
      tool_pat: send_email
      vel_limit: 999999999
      eft: allow
    -
      agent_pat: "*"
      tool_pat: db_write_production
      vel_limit: 999999999
      eft: allow
  allow:
    -
      agent_pat: "*"
      tool_pat: read_file
      vel_limit: 999999999
      eft: allow
    -
      agent_pat: "*"
      tool_pat: list_dir
      vel_limit: 999999999
      eft: allow
    -
      agent_pat: "*"
      tool_pat: send_email
      vel_limit: 999999999
      eft: allow
    -
      agent_pat: "*"
      tool_pat: db_write_production
      vel_limit: 999999999
      eft: allow
"""

# The spike's 9 scenarios, re-expressed against the request schema.
# Each: (name, request, expected_verdict).
PERM_SCENARIOS = [
    ("ordinary tool",
     {"agent_id": "agent-a", "tool_name": "read_file",
      "egress_class": "none", "velocity_1m": 3,
      "approval_state": "none"},
     "allow"),
    ("forbidden tool",
     {"agent_id": "agent-a", "tool_name": "install_package",
      "egress_class": "none", "velocity_1m": 1,
      "approval_state": "none"},
     "deny"),
    ("forbidden tool even with approval granted",
     {"agent_id": "agent-a", "tool_name": "install_package",
      "egress_class": "none", "velocity_1m": 1,
      "approval_state": "granted"},
     "deny"),
    ("classified egress, no approval",
     {"agent_id": "agent-a", "tool_name": "send_email",
      "egress_class": "classified", "velocity_1m": 2,
      "approval_state": "none"},
     "require_approval"),
    ("classified egress, approval granted",
     {"agent_id": "agent-a", "tool_name": "send_email",
      "egress_class": "classified", "velocity_1m": 2,
      "approval_state": "granted"},
     "allow"),
    ("classified egress, approval denied",
     {"agent_id": "agent-a", "tool_name": "send_email",
      "egress_class": "classified", "velocity_1m": 2,
      "approval_state": "denied"},
     "require_approval"),
    ("velocity exceeded on ordinary tool",
     {"agent_id": "agent-a", "tool_name": "read_file",
      "egress_class": "none", "velocity_1m": 50,
      "approval_state": "none"},
     "deny"),
    ("unknown tool (default deny)",
     {"agent_id": "agent-a", "tool_name": "exfiltrate",
      "egress_class": "none", "velocity_1m": 1,
      "approval_state": "none"},
     "deny"),
    ("prod db write, no approval",
     {"agent_id": "agent-a", "tool_name": "db_write_production",
      "egress_class": "classified", "velocity_1m": 1,
      "approval_state": "none"},
     "require_approval"),
]

# (scenario name, expected deciding screen or "default",
#  expected determining (screen, policy_index, effect) rows).
# Indices are into the fixture's policy lists above.
_EXPECTED_TRACE = {
    "ordinary tool": ("allow", [("allow", 0, "allow")]),
    "forbidden tool": ("deny", [("deny", 0, "deny")]),
    "forbidden tool even with approval granted":
        ("deny", [("deny", 0, "deny")]),
    "classified egress, no approval":
        ("approval", [("approval", 0, "allow")]),
    "classified egress, approval granted":
        ("allow", [("allow", 2, "allow")]),
    "classified egress, approval denied":
        ("approval", [("approval", 0, "allow")]),
    "velocity exceeded on ordinary tool":
        ("deny", [("deny", 1, "deny")]),
    "unknown tool (default deny)": ("default", []),
    "prod db write, no approval":
        ("approval", [("approval", 1, "allow")]),
}


def _imports():
    from gov import perm_loader as pl
    from gov import decision_diagnostics as dd
    from gov import decision_log_v2 as dlv
    return pl, dd, dlv


def _model(pl):
    return pl.compile_perm_model(
        PERM_MODEL_YML.encode(), PERM_POLICY_YML.encode())


def _record(name, verdict, detail):
    _records.append((name, verdict, detail))


def p_every_decision_carries_determiners():
    pl, dd, _ = _imports()
    model = _model(pl)
    for name, request, expected in PERM_SCENARIOS:
        rec = dd.decide_with_diagnostics(model, request)
        if rec["decision"] != expected:
            return ("FAIL", "%s: decision %r != %r"
                    % (name, rec["decision"], expected))
        want_screen, want_rows = _EXPECTED_TRACE[name]
        det = rec["determining_policies"]
        if want_screen == "default":
            if det:
                return ("FAIL", "%s: default path must carry no "
                        "determining policies" % name)
            if not rec["residuals"]["default_used"]:
                return ("FAIL", "%s: default path must set "
                        "default_used" % name)
        else:
            got = [(d["screen"], d["policy_index"], d["effect"])
                   for d in det]
            if got != want_rows:
                return ("FAIL", "%s: determining %r != %r"
                        % (name, got, want_rows))
            if rec["residuals"]["default_used"]:
                return ("FAIL", "%s: screen-fired path must not set "
                        "default_used" % name)
        try:
            dd.verify_decision_record(rec, request=request,
                                      perm_model=model)
        except Exception as e:  # noqa: BLE001
            return ("FAIL", "%s: verify failed: %s: %s"
                    % (name, type(e).__name__, e))
    return ("PASS", "9/9 scenarios carry exact determining rows; "
            "all verify (request+pack rebound)")


def p_typo_pack_refused():
    pl, _, _ = _imports()
    bad = PERM_MODEL_YML.replace("req: agent_id", "req: actoin")
    try:
        pl.compile_perm_model(bad.encode(), PERM_POLICY_YML.encode())
    except pl.PermError:
        return ("PASS", "typo'd request column refused at load")
    return ("FAIL", "typo'd request column compiled")


def p_unknown_attr_refused():
    pl, _, _ = _imports()
    bad = PERM_POLICY_YML.replace("eft: deny", "eft: deny\n      bogus: 1",
                                  1)
    try:
        pl.compile_perm_model(PERM_MODEL_YML.encode(), bad.encode())
    except pl.PermError:
        return ("PASS", "unknown policy column refused at load")
    return ("FAIL", "unknown policy column compiled")


def p_no_decision_explicit():
    pl, dd, _ = _imports()
    model = _model(pl)
    request = {"agent_id": "agent-a", "tool_name": "exfiltrate",
               "egress_class": "none", "velocity_1m": 1,
               "approval_state": "none"}
    rec = dd.decide_with_diagnostics(model, request,
                                     default_as_no_decision=True)
    if rec["decision"] != "no-decision":
        return ("FAIL", "expected no-decision, got %r" % rec["decision"])
    if rec["determining_policies"]:
        return ("FAIL", "no-decision must carry no determining policies")
    res = rec["residuals"]
    if not res["unknown_entities"]:
        return ("FAIL", "no-decision must name unknown_entities")
    if not res["decision_holds_iff"]:
        return ("FAIL", "no-decision must carry decision_holds_iff")
    if res["default_used"]:
        return ("FAIL", "no-decision must not set default_used")
    names = {u["name"] for u in res["unknown_entities"]}
    if names != set(request):
        return ("FAIL", "unknown_entities %r != request attrs" % names)
    dd.verify_decision_record(rec, request=request, perm_model=model)
    # The other fork: composition default, loudly labeled.
    rec2 = dd.decide_with_diagnostics(model, request)
    if rec2["decision"] != "deny" or not \
            rec2["residuals"]["default_used"]:
        return ("FAIL", "default fork must be deny+default_used, got %r"
                % rec2["decision"])
    if rec2["decision_id"] == rec["decision_id"]:
        return ("FAIL", "no-decision and default records must differ")
    return ("PASS", "no-decision explicit (unknown_entities=%d, "
            "holds_iff set); default fork labeled default_used; "
            "ids differ" % len(res["unknown_entities"]))


def p_forged_determiners_break_digest():
    pl, dd, _ = _imports()
    model = _model(pl)
    request = dict(PERM_SCENARIOS[0][1])
    rec = dd.decide_with_diagnostics(model, request)
    # (i) forge the determining policy id.
    forged = copy.deepcopy(rec)
    forged["determining_policies"][0]["policy_id"] = "allow[9]"
    try:
        dd.verify_decision_record(forged)
    except dd.RecordVerifyError:
        pass
    else:
        return ("FAIL", "forged policy_id verified")
    # (ii) forge the decision itself.
    forged2 = copy.deepcopy(rec)
    forged2["decision"] = "deny"
    try:
        dd.verify_decision_record(forged2)
    except dd.RecordVerifyError:
        pass
    else:
        return ("FAIL", "forged decision verified")
    # (iii) drop a determining row.
    forged3 = copy.deepcopy(rec)
    forged3["determining_policies"] = []
    try:
        dd.verify_decision_record(forged3)
    except dd.RecordVerifyError:
        pass
    else:
        return ("FAIL", "dropped determiners verified")
    return ("PASS", "policy_id / decision / row-drop forgeries all "
            "break decision_id")


def p_record_rebinding():
    pl, dd, _ = _imports()
    model = _model(pl)
    request = dict(PERM_SCENARIOS[0][1])
    rec = dd.decide_with_diagnostics(model, request)
    # Cross-request swap.
    other = dict(request)
    other["velocity_1m"] = 4
    try:
        dd.verify_decision_record(rec, request=other)
    except dd.RecordVerifyError:
        pass
    else:
        return ("FAIL", "cross-request swap verified")
    # Cross-pack swap: same shape, one row's eft flipped.
    other_policy = PERM_POLICY_YML.replace(
        "tool_pat: read_file\n      vel_limit: 999999999\n      eft: allow",
        "tool_pat: read_file\n      vel_limit: 999999999\n      eft: deny",
        1)
    model2 = pl.compile_perm_model(PERM_MODEL_YML.encode(),
                                   other_policy.encode())
    try:
        dd.verify_decision_record(rec, perm_model=model2)
    except dd.RecordVerifyError:
        pass
    else:
        return ("FAIL", "cross-pack swap verified")
    # Sanity: the un-tampered record still verifies.
    dd.verify_decision_record(rec, request=request, perm_model=model)
    return ("PASS", "cross-request and cross-pack swaps refused; "
            "clean record verifies")


def p_v2_roundtrip():
    pl, dd, dlv = _imports()
    model = _model(pl)
    request = dict(PERM_SCENARIOS[3][1])
    rec = dd.decide_with_diagnostics(model, request)
    raw_body = {"agent_id": "agent-a", "tool_name": "send_email",
                "note": "classified egress, no approval"}
    replay_inputs = {"rules": [{"id": "r1", "effect": "allow",
                                "match": {"tool": "send_email"}}],
                     "request": {"tool": "send_email"}}
    replay_verdict = {"effect": "allow", "matched_rule": "r1",
                      "reason": "rule r1 matched"}
    event = dd.build_diagnostic_event(
        record=rec, raw_body=raw_body, replay_fn="deny_first_rules",
        replay_inputs=replay_inputs, replay_verdict=replay_verdict)
    if event.get("diagnostics") != rec:
        return ("FAIL", "diagnostics block not carried")
    dd.verify_diagnostic_event(event, request=request, perm_model=model)
    # The v2 decision_id binds the block: tamper -> mismatch.
    tampered = copy.deepcopy(event)
    tampered["diagnostics"]["determining_policies"][0]["effect"] = "deny"
    try:
        dlv.verify_event(tampered)
    except dlv.EventVerifyError:
        pass
    else:
        return ("FAIL", "tampered diagnostics passed v2 verify")
    # The same event without diagnostics has a different id (bound,
    # not ignored) ...
    plain = dlv.build_event(
        decision=event["decision"], raw_body=raw_body,
        replay_fn="deny_first_rules", replay_inputs=replay_inputs,
        replay_verdict=replay_verdict)
    if plain["decision_id"] == event["decision_id"]:
        return ("FAIL", "diagnostics not bound by v2 decision_id")
    # ... and legacy events without the block still verify.
    dlv.verify_event(plain)
    if "diagnostics" in plain:
        return ("FAIL", "legacy event gained a diagnostics key")
    return ("PASS", "diagnostics ride v2 (bound by decision_id); "
            "tamper breaks v2 verify; legacy events unchanged")


_MINIMAL_MODEL_TMPL = """\
perm_model: sasanam-perm/v1
model_version: 1
description: "Minimal model for the constant-fold probes."
request_schema:
  agent_id: str
policy_schema:
  agent_pat: str
  eft: eft
matchers:
  m: glob
screens:
  -
    name: deny
    description: "Screen under test."
    effect: "!some(where (p_eft == deny))"
    matcher:
%s
composition:
  default_verdict: deny
  order:
    -
      screen: deny
      verdict: deny
      invert: true
"""

_MINIMAL_POLICY_YML = """\
perm_policy: sasanam-perm/v1
description: "Minimal policy for the constant-fold probes."
policies:
  deny:
    -
      agent_pat: "*"
      eft: deny
"""


def p_const_false_matcher_refused():
    pl, _, _ = _imports()
    # The WHOLE screen matcher constant-folds to False: the screen can
    # never fire, so its policy rows are silently dead. Refused.
    bad = _MINIMAL_MODEL_TMPL % ("      eq:\n"
                                 "        - \"never\"\n"
                                 "        - \"matches\"")
    try:
        pl.compile_perm_model(bad.encode(),
                              _MINIMAL_POLICY_YML.encode())
    except pl.PermError as e:
        if "never-true" not in str(e):
            return ("FAIL", "refused for the wrong reason: %s" % e)
        return ("PASS", "constant-false matcher refused at load")
    return ("FAIL", "constant-false matcher compiled")


def p_const_true_matcher_allowed():
    pl, _, _ = _imports()
    # A constant-TRUE matcher is the pack author's explicit,
    # digest-visible "match all" -- allowed, documented asymmetry.
    doc = _MINIMAL_MODEL_TMPL % ("      eq:\n"
                                 "        - 1\n"
                                 "        - 1")
    try:
        model = pl.compile_perm_model(doc.encode(),
                                      _MINIMAL_POLICY_YML.encode())
    except pl.PermError as e:
        return ("FAIL", "constant-true matcher refused: %s" % e)
    verdict, _, _ = model.decide({"agent_id": "agent-a"})
    if verdict != "deny":
        return ("FAIL", "constant-true screen misbehaved: %r" % verdict)
    return ("PASS", "constant-true matcher loads (explicit match-all)")


def p_no_decision_record_ctor():
    pl, dd, _ = _imports()
    model = _model(pl)
    request = dict(PERM_SCENARIOS[7][1])
    rec = dd.no_decision_record(model=model, request=request,
                                reason="partial evaluation: velocity "
                                "snapshot not yet loaded")
    if rec["decision"] != "no-decision":
        return ("FAIL", "expected no-decision")
    if rec["residuals"]["decision_holds_iff"] != \
            "partial evaluation: velocity snapshot not yet loaded":
        return ("FAIL", "residual reason not carried")
    if not rec["residuals"]["unknown_entities"]:
        return ("FAIL", "unknown_entities empty")
    dd.verify_decision_record(rec, request=request, perm_model=model)
    # Malformed request fails closed, like decide().
    bad = dict(request)
    del bad["agent_id"]
    try:
        dd.no_decision_record(model=model, request=bad, reason="x")
    except pl.PermError:
        pass
    else:
        return ("FAIL", "malformed request built a no-decision record")
    return ("PASS", "explicit no-decision ctor carries residual; "
            "malformed request fails closed")


PROBES = [
    p_every_decision_carries_determiners,
    p_typo_pack_refused,
    p_unknown_attr_refused,
    p_no_decision_explicit,
    p_forged_determiners_break_digest,
    p_record_rebinding,
    p_v2_roundtrip,
    p_const_false_matcher_refused,
    p_const_true_matcher_allowed,
    p_no_decision_record_ctor,
]


def _run_once():
    _records.clear()
    for probe in PROBES:
        try:
            verdict, detail = probe()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, detail = "ERROR", "%s: %s" % (
                type(e).__name__, e)
        _record(probe.__name__, verdict, detail)
    return list(_records)


def _green_check_adjacent():
    """Depth-1 green check: adjacent unit tests, GOV_SKIP_GREEN honored."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("SKIP",
                "nested adjacency skipped (GOV_SKIP_GREEN=1); run "
                "tests/test_decision_diagnostics.py standalone")
    import subprocess  # noqa: E402
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmpd = tempfile.mkdtemp(prefix="diag-green-")
    env["TMPDIR"] = tmpd
    r = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_decision_diagnostics",
         "tests.test_perm_loader",
         "tests.test_decision_log_v2", "-v"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
        timeout=600)
    tail = (r.stderr or "").strip().splitlines()[-1:] or [""]
    return ("PASS" if r.returncode == 0 else "FAIL",
            "adjacent units rc=%d %s" % (r.returncode, tail[0]))


def main():
    first = _run_once()
    second = _run_once()  # determinism: identical verdicts twice
    det_ok = ([(n, v) for n, v, _ in first]
              == [(n, v) for n, v, _ in second])
    _record("determinism",
            "PASS" if det_ok else "FAIL",
            "two in-process runs agree on all %d probes" % len(PROBES)
            if det_ok else "MISMATCH between run 1 and run 2")
    gv, gd = _green_check_adjacent()
    _record("green_check_adjacent_units", gv, gd)
    npass = sum(1 for _, v, _ in _records if v == "PASS")
    nfail = sum(1 for _, v, _ in _records if v in ("FAIL", "ERROR"))
    skipped = sum(1 for _, v, _ in _records if v == "SKIP")
    print("== decision-diagnostics battery ==")
    final = [(n, _VERDICT_MAP[v], d) for n, v, d in _records]
    probe_lines.emit(final)
    brk = sum(1 for _, v, _ in final if v == "BREAK")
    held = sum(1 for _, v, _ in final if v == "HELD")
    err = sum(1 for _, v, _ in final if v == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        final, brk, held, err)
    if not _coh_ok:
        print("coherence-WARNING: %s"
              % ("; ".join(_coh_diags)))
    print("%d BREAK / %d HELD / %d ERROR"
          % (brk, held, err))
    print("PASS=%d FAIL/ERROR=%d SKIP=%d" % (npass, nfail, skipped))
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
