#!/usr/bin/env python3
"""Wave-206 Lane D: red-first battery for the symcc-style pack red-team lint.

RED-FIRST: run against the PRISTINE tree first. Every probe imports
gov.pack_lint -- absent there -- so the pristine run is uniformly
ERROR (missing public seams), and the fixed tree holds.

The lint is Cedar `symcc`'s triple ADAPTED (wave-205 prospecting §2):
safety (no vacuously-bypassable policy: no never-matching rules, no
unreachable branches, no shadowed grants), liveness (the pack is not
trivially-deny-all / never-fires), sanity (no self-contradicting rule
pairs, no fail-open defaults). It is a BOUNDED red-team approximation
-- witness search, no SMT solver -- stated honestly in gov/pack_lint.

Probes:

  plint_valid_rule_pack_clean   -- a well-formed capability-rule pack
                                 lints clean (no violations).
  plint_valid_perm_pack_clean   -- the canonical PERM model+policy
                                 lints clean.
  plint_shadowed_row            -- PERM: a policy row shadowed by an
                                 earlier row -> safety/shadowed-row.
  plint_unreachable_allow       -- PERM: an allow row that can never
                                 match -> safety/vacuous-row.
  plint_vacuous_rule            -- capability rule that can never fire
                                 -> safety/unsatisfiable-rule.
  plint_contradictory_pair      -- PERM: two rows, equivalent
                                 matchers, different eft ->
                                 safety/contradictory-pair.
  plint_dead_match_ref          -- capability composite matching a
                                 namespace prefix with no target ->
                                 safety/dead-match-ref.
  plint_never_fires             -- capability pack where no rule can
                                 fire -> liveness/pack-never-fires.
  plint_trivially_denies_all    -- PERM pack that can never allow ->
                                 liveness/trivially-denies-all.
  plint_default_allow_sanity    -- PERM default_verdict allow ->
                                 sanity/default-allow.
  plint_uncompilable_pack       -- capability pack that fails to
                                 compile -> sanity/uncompilable-pack.
  plint_log_only_marker         -- lint-failed pack activates in
                                 LOG_ONLY (default); the ActivePack
                                 carries lint_failed; a PERM model
                                 built from it marks decide() output.
  plint_enforce_refuses         -- lint-failed pack refused in
                                 ENFORCE (pack-lint-failed); the
                                 prior pack stays active; promotion
                                 needs two distinct operators and a
                                 clean current pack.
"""

import hashlib
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


def _record(name, verdict, detail):
    _records.append((name, verdict, detail))


def _setup():
    from gov import pack_lint as pl
    from gov import pack_loader as pload
    from gov import perm_loader as perm
    from gov import rule_pack as rp
    from gov.keyset import (new_keyset, keyset_signer_for_version,
                            rotate_keyset)
    from gov.signing import Ed25519Signer
    return (pl, pload, perm, rp, new_keyset, keyset_signer_for_version,
            rotate_keyset, Ed25519Signer)


def _two_human_perm_keyset(new_keyset, rotate_keyset, Ed25519Signer, rp):
    """A PERM-purpose keyset with two distinct human signers."""
    ks, _ = new_keyset(_SEED1, purpose=rp.KEYSET_PURPOSE_PERM_PACK)
    ks, _ = rotate_keyset(ks, _SEED2, _SEED1)
    return ks, [Ed25519Signer(_SEED2), Ed25519Signer(_SEED1)]


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

_SEED1 = bytes.fromhex("41" * 32)
_SEED2 = bytes.fromhex("42" * 32)
ISSUED = "2026-09-01T00:00:00+00:00"
EXPIRES = "2030-01-01T00:00:00+00:00"
NOW = "2026-10-01T00:00:00+00:00"


def _rule_doc(name, namespace, scope, features, tags=None):
    tags = tags or [namespace]
    return """\
rules:
  -
    meta:
      name: "%s"
      namespace: %s
      scopes:
        static: %s
      capability_tags: [%s]
      label: "%s"
    features:
%s
""" % (name, namespace, scope,
       ", ".join(tags), name, features)


def _indent(block, n=6):
    pad = " " * n
    return "\n".join(pad + ln if ln.strip() else ln
                     for ln in block.splitlines())


_VALID_RULES = {
    "r0.yml": _rule_doc(
        "egress socket", "capability/egress/socket", "module",
        _indent("import: socket", 6)).encode("utf-8"),
    "r1.yml": _rule_doc(
        "secret read", "capability/secrets/read", "module",
        _indent('pattern: "AKIA[0-9A-Z]{16}"', 6)).encode("utf-8"),
    "r2.yml": _rule_doc(
        "cred egress", "capability/egress/credential-bearing", "module",
        _indent("and:\n  - match: capability/egress/*\n"
                "  - match: capability/secrets/*", 6)).encode("utf-8"),
}

_VACUOUS_RULES = {
    "v0.yml": _rule_doc(
        "impossible", "capability/egress/impossible", "module",
        _indent("and:\n  - pattern: \"^aaa\"\n  - pattern: \"^bbb\"",
                6)).encode("utf-8"),
}

_DEADREF_RULES = dict(_VALID_RULES)
_DEADREF_RULES["r3.yml"] = _rule_doc(
    "dead composite", "capability/egress/dead", "module",
    _indent("and:\n  - match: capability/nonexistent/*\n"
            "  - import: socket", 6)).encode("utf-8")

_UNCOMPILABLE = {
    "bad.yml": b"rules:\n  - {name: oops}\n",
}

_PERM_MODEL = """\
perm_model: sasanam-perm/v1
model_version: 1
description: "lint fixture model"
request_schema:
  agent_id: str
  tool_name: str
  velocity_1m: int
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
    description: "deny screen"
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
    name: allow
    description: "allow screen"
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
composition:
  default_verdict: deny
  order:
    -
      screen: deny
      verdict: deny
      invert: true
    -
      screen: allow
      verdict: allow
"""

_PERM_POLICY = """\
perm_policy: sasanam-perm/v1
description: "lint fixture policy"
policies:
  deny:
    -
      agent_pat: "*"
      tool_pat: install_package
      vel_limit: 999999999
      eft: deny
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
"""

_PERM_MODEL_SIMPLE = """\
perm_model: sasanam-perm/v1
model_version: 1
request_schema:
  tool_name: str
  velocity_1m: int
policy_schema:
  tool_pat: str
  vel_limit: int
  eft: eft
matchers:
  toolMatch: glob
screens:
  -
    name: allow
    effect: "some(where (p_eft == allow))"
    matcher:
      and:
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
composition:
  default_verdict: deny
  order:
    -
      screen: allow
      verdict: allow
"""


def _violations_by_check(report):
    out = {}
    for v in report.violations:
        out.setdefault(v.check, []).append(v)
    return out


def _has(report, check, rule_sub=""):
    for v in report.violations:
        if v.check == check and rule_sub in v.rule:
            return True
    return False


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def p_valid_rule_pack_clean():
    pl = _setup()[0]
    report = pl.lint_capability_rule_files(dict(_VALID_RULES))
    if report.clean:
        return ("HELD", "valid rule pack: 0 violations, checks=%s"
                % (",".join(report.checks),))
    return ("BROKEN", "valid pack flagged: %s" % (report.summary(),))


def p_valid_perm_pack_clean():
    pl = _setup()[0]
    report = pl.lint_perm_pack(_PERM_MODEL, _PERM_POLICY)
    if report.clean:
        return ("HELD", "valid PERM pack: 0 violations, checks=%s"
                % (",".join(report.checks),))
    return ("BROKEN", "valid PERM pack flagged: %s" % (report.summary(),))


def p_shadowed_row():
    pl = _setup()[0]
    policy = """\
perm_policy: sasanam-perm/v1
policies:
  allow:
    -
      tool_pat: "*"
      vel_limit: 999999999
      eft: allow
    -
      tool_pat: send_email
      vel_limit: 999999999
      eft: allow
"""
    report = pl.lint_perm_pack(_PERM_MODEL_SIMPLE, policy)
    if _has(report, "safety/shadowed-row", "row[1]"):
        return ("HELD", "shadowed allow row[1] caught: %s"
                % (report.summary(),))
    return ("BROKEN", "shadowed row not caught: %s" % (report.summary(),))


def p_unreachable_allow():
    pl = _setup()[0]
    model = _PERM_MODEL_SIMPLE.replace(
        """        -
          lte:
            -
              req: velocity_1m
            -
              pol: vel_limit""",
        """        -
          and:
            -
              gt:
                -
                  req: velocity_1m
                -
                  pol: vel_limit
            -
              lt:
                -
                  req: velocity_1m
                -
                  pol: vel_limit""")
    policy = """\
perm_policy: sasanam-perm/v1
policies:
  allow:
    -
      tool_pat: send_email
      vel_limit: 5
      eft: allow
"""
    report = pl.lint_perm_pack(model, policy)
    if _has(report, "safety/vacuous-row", "row[0]"):
        return ("HELD", "unreachable allow row caught: %s"
                % (report.summary(),))
    return ("BROKEN", "unreachable allow not caught: %s"
            % (report.summary(),))


def p_vacuous_rule():
    pl = _setup()[0]
    report = pl.lint_capability_rule_files(dict(_VACUOUS_RULES))
    if _has(report, "safety/unsatisfiable-rule", "impossible"):
        return ("HELD", "vacuous rule caught: %s" % (report.summary(),))
    return ("BROKEN", "vacuous rule not caught: %s" % (report.summary(),))


def p_contradictory_pair():
    pl = _setup()[0]
    model = _PERM_MODEL_SIMPLE.replace(
        'effect: "some(where (p_eft == allow))"',
        'effect: "some(where (p_eft == allow)) && '
        '!some(where (p_eft == deny))"')
    policy = """\
perm_policy: sasanam-perm/v1
policies:
  allow:
    -
      tool_pat: send_email
      vel_limit: 999999999
      eft: allow
    -
      tool_pat: send_email
      vel_limit: 999999999
      eft: deny
"""
    report = pl.lint_perm_pack(model, policy)
    if _has(report, "safety/contradictory-pair"):
        return ("HELD", "contradictory pair caught: %s"
                % (report.summary(),))
    return ("BROKEN", "contradictory pair not caught: %s"
            % (report.summary(),))


def p_dead_match_ref():
    pl = _setup()[0]
    report = pl.lint_capability_rule_files(dict(_DEADREF_RULES))
    if _has(report, "safety/dead-match-ref", "dead composite"):
        return ("HELD", "dead match ref caught: %s" % (report.summary(),))
    return ("BROKEN", "dead match ref not caught: %s" % (report.summary(),))


def p_never_fires():
    pl = _setup()[0]
    report = pl.lint_capability_rule_files(dict(_VACUOUS_RULES))
    if _has(report, "liveness/pack-never-fires"):
        return ("HELD", "never-firing pack caught: %s"
                % (report.summary(),))
    return ("BROKEN", "pack-never-fires not caught: %s"
            % (report.summary(),))


def p_trivially_denies_all():
    pl = _setup()[0]
    model = _PERM_MODEL_SIMPLE.replace(
        """        -
          lte:
            -
              req: velocity_1m
            -
              pol: vel_limit""",
        """        -
          and:
            -
              gt:
                -
                  req: velocity_1m
                -
                  pol: vel_limit
            -
              lt:
                -
                  req: velocity_1m
                -
                  pol: vel_limit""")
    policy = """\
perm_policy: sasanam-perm/v1
policies:
  allow:
    -
      tool_pat: send_email
      vel_limit: 5
      eft: allow
"""
    report = pl.lint_perm_pack(model, policy)
    if _has(report, "liveness/trivially-denies-all"):
        return ("HELD", "trivially-denying pack caught: %s"
                % (report.summary(),))
    return ("BROKEN", "trivially-denies-all not caught: %s"
            % (report.summary(),))


def p_default_allow_sanity():
    pl = _setup()[0]
    model = _PERM_MODEL_SIMPLE.replace("default_verdict: deny",
                                       "default_verdict: allow")
    policy = """\
perm_policy: sasanam-perm/v1
policies:
  allow: []
"""
    report = pl.lint_perm_pack(model, policy)
    if _has(report, "sanity/default-allow"):
        return ("HELD", "default-allow caught: %s" % (report.summary(),))
    return ("BROKEN", "default-allow not caught: %s" % (report.summary(),))


def p_uncompilable_pack():
    pl = _setup()[0]
    report = pl.lint_capability_rule_files(dict(_UNCOMPILABLE))
    if _has(report, "sanity/uncompilable-pack"):
        return ("HELD", "uncompilable pack caught: %s"
                % (report.summary(),))
    return ("BROKEN", "uncompilable pack not caught: %s"
            % (report.summary(),))


# ---------------------------------------------------------------------------
# LOG_ONLY / ENFORCE graduation probes
# ---------------------------------------------------------------------------

def _digests(members):
    return {mid: "sha256:" + hashlib.sha256(data).hexdigest()
            for mid, data in members.items()}


def _mint_pack(rp, new_keyset, keyset_signer_for_version, members,
               version=1, purpose=None, threshold=1):
    """Mint a signed pack doc and return (keyset, pack_doc, members)."""
    purpose = purpose or rp.KEYSET_PURPOSE_RULE_PACK
    ks, _ = new_keyset(_SEED1, purpose=purpose)
    signer = keyset_signer_for_version(ks, 1, _SEED1)
    doc = rp.mint_rule_pack(
        ks, [signer], rules=_digests(members), pack_version=version,
        issued_at=ISSUED, expires_at=EXPIRES, threshold=threshold,
        purpose=purpose)
    return ks, doc, dict(members)


def p_log_only_marker():
    (pl, pload, perm, rp, new_keyset, ksfv,
     rotate_keyset, Ed25519Signer) = _setup()
    # A lint-failing detection pack: the member cannot compile, so
    # sanity/uncompilable-pack fires.
    ks, doc, members = _mint_pack(rp, new_keyset, ksfv,
                                  {"m0.yml": _UNCOMPILABLE["bad.yml"]})
    loader = pload.PackLoader(ks, "lint-fixture")  # LOG_ONLY by default
    try:
        active = loader.present(doc, members, guard=None, now=NOW)
    except Exception as e:  # noqa: BLE001
        return ("BROKEN", "LOG_ONLY refused a lint-failed pack: %s" % (e,))
    if not active.lint_failed:
        return ("BROKEN", "LOG_ONLY pack lacks lint_failed marker")
    if not any(v.check == "sanity/uncompilable-pack"
               for v in active.lint_violations):
        return ("BROKEN", "expected sanity/uncompilable-pack, got: %s"
                % (active.lint_report.summary(),))
    # PERM side: a lint-failed PERM pack marks every decide() output.
    bad_policy = """\
perm_policy: sasanam-perm/v1
policies:
  allow:
    -
      tool_pat: "*"
      vel_limit: 999999999
      eft: allow
    -
      tool_pat: send_email
      vel_limit: 999999999
      eft: allow
"""
    ks2, signers2 = _two_human_perm_keyset(new_keyset, rotate_keyset,
                                           Ed25519Signer, rp)
    doc2 = perm.mint_perm_pack(
        ks2, signers2,
        model_bytes=_PERM_MODEL_SIMPLE.encode(),
        policy_bytes=bad_policy.encode(),
        pack_version=1, issued_at=ISSUED, expires_at=EXPIRES, threshold=2)
    loader2 = perm.new_perm_pack_loader(ks2)
    active2 = loader2.present(
        doc2, {"perm-model.yml": _PERM_MODEL_SIMPLE.encode(),
               "perm-policy.yml": bad_policy.encode()},
        guard=None, now=NOW)
    if not active2.lint_failed:
        return ("BROKEN", "LOG_ONLY PERM pack lacks lint_failed marker")
    model = perm.load_perm_from_active_pack(active2)
    verdict, screen, detail = model.decide(
        {"tool_name": "send_email", "velocity_1m": 0})
    if not detail.get("pack_lint_failed"):
        return ("BROKEN",
                "decide() detail lacks pack_lint_failed marker: %r"
                % (detail,))
    return ("HELD",
            "LOG_ONLY activates lint-failed packs with the marker on "
            "ActivePack and on every decide() output")


def p_enforce_refuses():
    (pl, pload, perm, rp, new_keyset, ksfv,
     rotate_keyset, Ed25519Signer) = _setup()
    bad_members = {"m0.yml": _UNCOMPILABLE["bad.yml"]}
    ks, bad_doc, bad_files = _mint_pack(rp, new_keyset, ksfv, bad_members)
    loader = pload.PackLoader(ks, "lint-fixture",
                              enforcement_mode="enforce")
    try:
        loader.present(bad_doc, bad_files, guard=None, now=NOW)
    except pload.PackActivationError as e:
        if e.code != "pack-lint-failed":
            return ("BROKEN",
                    "wrong refusal code for lint-failed pack: %s" % (e.code,))
    except Exception as e:  # noqa: BLE001
        return ("BROKEN", "unexpected error type: %s: %s"
                % (type(e).__name__, e))
    else:
        return ("BROKEN", "ENFORCE activated a lint-failed pack")
    if loader.current is not None:
        return ("BROKEN", "refused pack left a current pack behind")
    # A clean pack activates; the bad v2 must not displace it.
    _, good_doc, good_files = _mint_pack(rp, new_keyset, ksfv,
                                         dict(_VALID_RULES))
    good = loader.present(good_doc, good_files, guard=None, now=NOW)
    try:
        loader.present(bad_doc, bad_files, guard=None, now=NOW)
    except pload.PackActivationError:
        pass
    if loader.current is not good:
        return ("BROKEN", "failed v2 displaced the active pack")
    # Promotion: one operator is not enough; two distinct operators pass.
    loader3 = pload.PackLoader(ks, "lint-fixture")
    loader3.present(good_doc, good_files, guard=None, now=NOW)
    try:
        loader3.promote_to_enforce(["op1"])
    except pload.PackActivationError:
        pass
    else:
        return ("BROKEN", "single-operator promotion accepted")
    try:
        loader3.promote_to_enforce(["op1", "op1"])
    except pload.PackActivationError:
        pass
    else:
        return ("BROKEN", "duplicate-operator promotion accepted")
    loader3.promote_to_enforce(["op1", "op2"])
    if loader3.enforcement_mode != "enforce":
        return ("BROKEN", "two-operator promotion did not engage ENFORCE")
    # After promotion, a lint-failed v2 is still refused.
    _, bad_doc2, bad_files2 = _mint_pack(rp, new_keyset, ksfv,
                                         bad_members, version=2)
    try:
        loader3.present(bad_doc2, bad_files2, guard=None, now=NOW)
    except pload.PackActivationError as e:
        if e.code != "pack-lint-failed":
            return ("BROKEN", "wrong code after promotion: %s" % (e.code,))
    else:
        return ("BROKEN", "ENFORCE accepted lint-failed v2 after promotion")
    return ("HELD",
            "ENFORCE refuses lint-failed packs; promotion needs two "
            "distinct operators and keeps the prior pack on refusal")


def p_cap_manifest_marker():
    """WIRING: verify_skill_manifest marks results when the store's
    pack came from a lint-failed pack; the clean contract is
    byte-identical."""
    (pl, pload, perm, rp, new_keyset, ksfv,
     rotate_keyset, Ed25519Signer) = _setup()
    from gov import capability_manifests as cm
    from gov import capability_rules as cr
    from gov import ed25519 as _ed
    pack = cr.load_pack_files(dict(_VALID_RULES))
    content = b"hello world\n"
    seed = b"\x41" * 32

    def store_for(lint_failed):
        manifest = cm.make_manifest(
            "s", content, capabilities={}, kid="k1", seed=seed)
        return cm.ManifestStore(
            keys={"k1": _ed.publickey(seed)},
            manifests={"s": manifest},
            capability_pack=pack,
            capability_pack_lint_failed=lint_failed)

    ok, detail = cm.verify_skill_manifest(
        "s", content, store_for(True))
    if "pack-lint-failed" not in detail:
        return ("BROKEN",
                "lint-failed pack result not marked: %r" % (detail,))
    ok2, detail2 = cm.verify_skill_manifest(
        "s", content, store_for(False))
    if (ok2, detail2) != (True, "clean"):
        return ("BROKEN",
                "clean-pack contract changed: %r" % ((ok2, detail2),))
    try:
        cm.ManifestStore(capability_pack_lint_failed="yes")
        return ("BROKEN", "non-bool lint flag accepted")
    except ValueError:
        pass
    return ("HELD",
            "verify_skill_manifest marks lint-failed pack results; "
            "clean contract intact; flag strictly bool")


PROBES = [
    p_valid_rule_pack_clean,
    p_valid_perm_pack_clean,
    p_shadowed_row,
    p_unreachable_allow,
    p_vacuous_rule,
    p_contradictory_pair,
    p_dead_match_ref,
    p_never_fires,
    p_trivially_denies_all,
    p_default_allow_sanity,
    p_uncompilable_pack,
    p_log_only_marker,
    p_enforce_refuses,
    p_cap_manifest_marker,
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
                "tests/test_pack_loader.py tests/test_perm_loader.py "
                "tests/test_pack_lint.py standalone")
    import subprocess  # noqa: E402
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmpd = tempfile.mkdtemp(prefix="plint-green-")
    env["TMPDIR"] = tmpd
    r = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_pack_loader", "tests.test_perm_loader",
         "tests.test_pack_lint", "-v"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
        timeout=600)
    tail = (r.stderr or "").strip().splitlines()[-1:] or [""]
    return ("PASS" if r.returncode == 0 else "FAIL",
            "adjacent unit tests rc=%d %s" % (r.returncode, tail[0]))


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
    npass = sum(1 for _, v, _ in _records if v in ("PASS", "HELD"))
    nfail = sum(1 for _, v, _ in _records if v in ("FAIL", "BROKEN", "ERROR"))
    skipped = sum(1 for _, v, _ in _records if v == "SKIP")
    print("== pack-lint battery ==")
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
