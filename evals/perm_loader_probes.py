#!/usr/bin/env python3
"""Wave-200: red-first battery for the PERM model-as-data loader.

RED-FIRST: run against the PRISTINE tree first. Every probe imports
gov.perm_loader -- absent there -- so the pristine run is uniformly
ERROR (missing public seams), and the fixed tree holds. The
canonical model/policy/scenarios are duplicated from
~/workspace/teams/wave200-capperm/perm_fixtures.py (hermetic per
that file's plan). Probes:

  perm_model_compiles            -- the canonical model + policy
                                   compile; screens deny/approval/
                                   allow in order.
  perm_nine_scenarios            -- the spike's 9 scenarios render
                                   the expected verdicts.
  perm_unknown_effect            -- unknown effect string refused.
  perm_subject_priority_refused  -- subjectPriority refused (no
                                   subject hierarchy in the engine).
  perm_top_level_not            -- top-level matcher not refused.
  perm_unknown_matcher_d3        -- unknown matcher function refused.
  perm_invalid_regex             -- bad regex literal refused at load.
  perm_unsigned_model            -- pack with stripped signatures
                                   refused at activation.
  perm_trust_domain_confusion    -- detection-domain pack refused as
                                   a PERM pack.
  perm_effect_tamper             -- re-signed model with flipped
                                   effect carries a different model
                                   digest (tamper is visible, never
                                   silent).
  perm_malformed_request         -- missing/extra/wrong-type request
                                   columns fail closed (never allow).
  perm_two_human_mint            -- threshold=1 mint refused; the
                                   two-human ceremony round-trips.
  perm_bom_section               -- bom_perm_section carries the four
                                   digests; verify_bom re-derives
                                   model+policy and refuses swaps.
"""

import hashlib
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

_records = []


def _record(name, verdict, detail):
    _records.append((name, verdict, detail))


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


_SEED1 = bytes.fromhex("41" * 32)
_SEED2 = bytes.fromhex("42" * 32)
ISSUED = "2026-09-01T00:00:00+00:00"
EXPIRES = "2030-01-01T00:00:00+00:00"
NOW = "2026-10-01T00:00:00+00:00"


def _setup():
    from gov import perm_loader as pl
    from gov import pack_loader as pload
    from gov import rule_pack as rp
    from gov import decision_bom as db
    from gov.keyset import (new_keyset, rotate_keyset,
                            keyset_signer_for_version)
    from gov.signing import Ed25519Signer
    return pl, pload, rp, db, new_keyset, rotate_keyset, \
        keyset_signer_for_version, Ed25519Signer


def _two_human(pl, rp, new_keyset, rotate_keyset, Ed25519Signer):
    ks, _ = new_keyset(_SEED1,
                       purpose=rp.KEYSET_PURPOSE_PERM_PACK)
    ks, _ = rotate_keyset(ks, _SEED2, _SEED1)
    return ks, [Ed25519Signer(_SEED2), Ed25519Signer(_SEED1)]


def _req(**kw):
    base = {"agent_id": "agent-a", "tool_name": "read_file",
            "egress_class": "none", "velocity_1m": 1,
            "approval_state": "none"}
    base.update(kw)
    return base


def p_model_compiles():
    pl, _pload, _rp, _db, _nk, _rk, _ksfv, _es = _setup()
    model = pl.compile_perm_model(PERM_MODEL_YML, PERM_POLICY_YML)
    names = [s["name"] for s in model._model["screens"]]
    ok = names == ["deny", "approval", "allow"]
    return ("PASS" if ok else "FAIL", "screens=%s" % names)


def p_nine_scenarios():
    pl, _pload, _rp, _db, _nk, _rk, _ksfv, _es = _setup()
    model = pl.compile_perm_model(PERM_MODEL_YML, PERM_POLICY_YML)
    for name, request, want in PERM_SCENARIOS:
        verdict, _screen, _detail = model.decide(request)
        if verdict != want:
            return ("FAIL", "%r: got %s want %s"
                    % (name, verdict, want))
    return ("PASS", "9/9 scenarios hold")


def p_unknown_effect():
    pl, _pload, _rp, _db, _nk, _rk, _ksfv, _es = _setup()
    bad = PERM_MODEL_YML.replace(
        'effect: "some(where (p_eft == allow))"',
        'effect: "sometimes(maybe)"', 1)
    try:
        pl.compile_perm_model(bad, PERM_POLICY_YML)
        return ("FAIL", "unknown effect compiled")
    except pl.PermError as e:
        return ("PASS", "refused: %s" % str(e)[:60])


def p_subject_priority_refused():
    pl, _pload, _rp, _db, _nk, _rk, _ksfv, _es = _setup()
    bad = PERM_MODEL_YML.replace(
        'effect: "some(where (p_eft == allow))"',
        'effect: "subjectPriority(p_eft) || deny"', 1)
    try:
        pl.compile_perm_model(bad, PERM_POLICY_YML)
        return ("FAIL", "subjectPriority compiled")
    except pl.PermError:
        return ("PASS", "subjectPriority refused (no hierarchy)")


def p_top_level_not():
    pl, _pload, _rp, _db, _nk, _rk, _ksfv, _es = _setup()
    bad = PERM_MODEL_YML.replace(
        """    matcher:
      and:""",
        """    matcher:
      not:
        and:""", 1)
    try:
        pl.compile_perm_model(bad, PERM_POLICY_YML)
        return ("FAIL", "top-level not compiled")
    except pl.PermError:
        return ("PASS", "top-level not refused")


def p_unknown_matcher_d3():
    pl, _pload, _rp, _db, _nk, _rk, _ksfv, _es = _setup()
    bad = PERM_MODEL_YML.replace("- toolMatch", "- noSuchFn", 1)
    try:
        pl.compile_perm_model(bad, PERM_POLICY_YML)
        return ("FAIL", "unknown matcher compiled")
    except pl.PermError as e:
        ok = "unknown matcher function" in str(e)
        return ("PASS" if ok else "FAIL", str(e)[:60])


def p_invalid_regex():
    pl, _pload, _rp, _db, _nk, _rk, _ksfv, _es = _setup()
    m2 = PERM_MODEL_YML.replace("toolMatch: glob",
                                "toolMatch: glob\n  rx: regex", 1)
    bad = m2.replace(
        """              call:
                - toolMatch
                -
                  req: tool_name
                -
                  pol: tool_pat""",
        """              call:
                - rx
                -
                  req: tool_name
                - "([bad\"""", 1)
    try:
        pl.compile_perm_model(bad, PERM_POLICY_YML)
        return ("FAIL", "invalid regex compiled")
    except pl.PermError:
        return ("PASS", "invalid regex refused at load")


def p_unsigned_model():
    pl, pload, rp, _db, new_keyset, rotate_keyset, _ksfv, \
        Ed25519Signer = _setup()
    ks, signers = _two_human(pl, rp, new_keyset, rotate_keyset,
                             Ed25519Signer)
    doc = pl.mint_perm_pack(
        ks, signers, model_bytes=PERM_MODEL_YML,
        policy_bytes=PERM_POLICY_YML, pack_version=1,
        issued_at=ISSUED, expires_at=EXPIRES, threshold=2)
    doc["signatures"] = []
    loader = pl.new_perm_pack_loader(ks)
    try:
        loader.present(
            doc, {"perm-model.yml": PERM_MODEL_YML.encode(),
                  "perm-policy.yml": PERM_POLICY_YML.encode()},
            now=NOW)
        return ("FAIL", "unsigned pack activated")
    except pload.PackActivationError as e:
        return ("PASS", "code=%s" % e.code)


def p_trust_domain_confusion():
    pl, pload, rp, _db, new_keyset, _rk, ksfv, _es = _setup()
    rule_ks, _ = new_keyset(_SEED1,
                            purpose=rp.KEYSET_PURPOSE_RULE_PACK)
    members = {"perm-model.yml": b"model: x\n",
               "perm-policy.yml": b"policy: x\n"}
    digests = {
        mid: "sha256:" + hashlib.sha256(data).hexdigest()
        for mid, data in members.items()}
    doc = rp.mint_rule_pack(
        rule_ks, [ksfv(rule_ks, 1, _SEED1)], rules=digests,
        pack_version=1, issued_at=ISSUED, expires_at=EXPIRES,
        threshold=1)
    active = pload.PackLoader(rule_ks, "detection").present(
        doc, dict(members), now=NOW)
    try:
        pl.load_perm_from_active_pack(active)
        return ("FAIL", "detection pack accepted as PERM")
    except pl.PermError as e:
        ok = "trust domain" in str(e)
        return ("PASS" if ok else "FAIL", str(e)[:70])


def p_effect_tamper():
    pl, _pload, rp, _db, new_keyset, rotate_keyset, _ksfv, \
        Ed25519Signer = _setup()
    # D2: a re-signed model with a flipped deny effect is a
    # DIFFERENT model -- the digest changes, so the tamper is
    # visible in the BOM, never silent.
    evil = PERM_MODEL_YML.replace(
        'effect: "!some(where (p_eft == deny))"',
        'effect: "some(where (p_eft == allow))"', 1)
    ks, signers = _two_human(pl, rp, new_keyset, rotate_keyset,
                             Ed25519Signer)
    doc = pl.mint_perm_pack(
        ks, signers, model_bytes=evil,
        policy_bytes=PERM_POLICY_YML, pack_version=2,
        issued_at=ISSUED, expires_at=EXPIRES, threshold=2)
    loader = pl.new_perm_pack_loader(ks)
    active = loader.present(
        doc, {"perm-model.yml": evil.encode(),
              "perm-policy.yml": PERM_POLICY_YML.encode()},
        now=NOW)
    model = pl.load_perm_from_active_pack(active)
    good = pl.compile_perm_model(PERM_MODEL_YML, PERM_POLICY_YML)
    ok = model.model_digest != good.model_digest
    return ("PASS" if ok else "FAIL",
            "re-signed tamper changes the model digest")


def p_malformed_request():
    pl, _pload, _rp, _db, _nk, _rk, _ksfv, _es = _setup()
    model = pl.compile_perm_model(PERM_MODEL_YML, PERM_POLICY_YML)
    cases = []
    r1 = _req()
    del r1["tool_name"]
    cases.append(r1)
    cases.append(_req(sneaky="x"))
    cases.append(_req(velocity_1m="fast"))
    cases.append(_req(velocity_1m=True))
    cases.append(None)
    for req in cases:
        try:
            model.decide(req)
            return ("FAIL", "malformed request decided: %r" % (req,))
        except pl.PermError:
            pass
    return ("PASS", "5 malformed shapes fail closed")


def p_two_human_mint():
    pl, _pload, rp, _db, new_keyset, rotate_keyset, ksfv, \
        Ed25519Signer = _setup()
    ks1, _ = new_keyset(_SEED1,
                        purpose=rp.KEYSET_PURPOSE_PERM_PACK)
    try:
        pl.mint_perm_pack(
            ks1, [ksfv(ks1, 1, _SEED1)],
            model_bytes=PERM_MODEL_YML,
            policy_bytes=PERM_POLICY_YML, pack_version=1,
            issued_at=ISSUED, expires_at=EXPIRES, threshold=1)
        return ("FAIL", "threshold=1 PERM pack minted")
    except pl.PermError:
        pass
    ks, signers = _two_human(pl, rp, new_keyset, rotate_keyset,
                             Ed25519Signer)
    doc = pl.mint_perm_pack(
        ks, signers, model_bytes=PERM_MODEL_YML,
        policy_bytes=PERM_POLICY_YML, pack_version=1,
        issued_at=ISSUED, expires_at=EXPIRES, threshold=2)
    loader = pl.new_perm_pack_loader(ks)
    active = loader.present(
        doc, {"perm-model.yml": PERM_MODEL_YML.encode(),
              "perm-policy.yml": PERM_POLICY_YML.encode()},
        now=NOW)
    model = pl.load_perm_from_active_pack(active)
    verdict, _s, _d = model.decide(_req(tool_name="read_file"))
    ok = active.threshold == 2 and verdict == "allow"
    return ("PASS" if ok else "FAIL",
            "two-human ceremony round-trips; read_file=%s" % verdict)


def p_bom_section():
    pl, _pload, _rp, db, _nk, _rk, _ksfv, _es = _setup()
    model = pl.compile_perm_model(PERM_MODEL_YML, PERM_POLICY_YML)
    section = model.bom_perm_section()
    if sorted(section) != ["composition_digest",
                           "function_set_digest", "model_digest",
                           "policy_digest"]:
        return ("FAIL", "section keys=%s" % sorted(section))
    bom = db.build_bom(
        policy_id="p", policy_version="1",
        policy_digest="ab" * 32, evidence_head_digest="head",
        principal={"agent_id": "a"}, perm_model=section)
    ok_shape, _ = db.check_bom_shape(bom)
    if not ok_shape:
        return ("FAIL", "shape check failed")
    ok, reason = db.verify_bom(
        bom, perm_model_bytes=PERM_MODEL_YML.encode(),
        perm_policy_bytes=PERM_POLICY_YML.encode())
    if not ok:
        return ("FAIL", "re-derive failed: %s" % reason)
    ok_swap, _ = db.verify_bom(bom, perm_model_bytes=b"swapped")
    if ok_swap:
        return ("FAIL", "swapped model verified")
    return ("PASS", "4 digests; re-derive ok; swap refused")


PROBES = [
    p_model_compiles,
    p_nine_scenarios,
    p_unknown_effect,
    p_subject_priority_refused,
    p_top_level_not,
    p_unknown_matcher_d3,
    p_invalid_regex,
    p_unsigned_model,
    p_trust_domain_confusion,
    p_effect_tamper,
    p_malformed_request,
    p_two_human_mint,
    p_bom_section,
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
                "tests/test_perm_loader.py standalone")
    import subprocess  # noqa: E402
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmpd = tempfile.mkdtemp(prefix="perm-green-")
    env["TMPDIR"] = tmpd
    r = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_perm_loader",
         "-v"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
        timeout=600)
    tail = (r.stderr or "").strip().splitlines()[-1:] or [""]
    return ("PASS" if r.returncode == 0 else "FAIL",
            "tests.test_perm_loader rc=%d %s"
            % (r.returncode, tail[0]))


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
    print("== perm-loader battery ==")
    for n, v, d in _records:
        print("[%s] %s -- %s" % (v, n, d))
    print("PASS=%d FAIL/ERROR=%d SKIP=%d" % (npass, nfail, skipped))
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
