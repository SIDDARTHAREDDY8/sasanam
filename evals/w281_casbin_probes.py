"""Wave-281 lane 7 red-first battery: Casbin PERM DSL ADAPT (mechanisms only).

Gap (base b95c0e5): the policy engine has no declarative agent->tool policy
CONF -- no PERM sections, no deny-override/priority effect combinators, no
enforce_ex explain (decision + matched rule rows), no matched-row evidence
feeding the signed decision packet.

Red-first: on base every probe BREAKs (gov.casbin_perm absent). After the
fix: deny-override / allow-override / priority combinators hold, enforce_ex
returns decision + matched rows, rows hash into the decision packet and the
packet verifies, batch_enforce agrees with single enforce, role inheritance
is transitive and cycle-safe, malformed CONF / unknown matcher functions /
shadowed rows refuse at load, runtime matcher errors fail closed to deny,
and the taxonomy pin holds.

Pattern lineage: casbin/casbin PERM metamodel (Apache-2.0 -- mechanisms
only, no code vendored, pycasbin rejected on supply-chain grounds):
[request_definition]/[policy_definition]/[role_definition]/[policy_effect]/
[matchers] CONF sections; enforce_ex explain; BatchEnforce. Composed with
gov/decision_packet.py's existing matched_rules section (composition, not
duplication).
"""

import hashlib
import json
import os
import secrets
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w281-casbin")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TAXONOMY_PIN = 1587  # Wave-280 merge 1545 + 4 casbin-* codes.; Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).

_RESULTS = []


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict, "note": note})


def _needs_module(probe_id):
    try:
        from gov import casbin_perm as cp
        return cp
    except ImportError:
        _record(probe_id, "BREAK", "gov.casbin_perm absent on base")
        return None


_DENY_OVERRIDE_CONF = """\
[request_definition]
r = agent, tool, action

[policy_definition]
p = agent, tool, action, eft

[role_definition]
g = _, _

[policy_effect]
e = !some(where (p.eft == deny))

[matchers]
m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action

[policy]
p, admin, shell, exec, allow
p, blocked, shell, exec, deny

[role_policy]
g, alice, admin
g, bob, blocked
"""

_ALLOW_OVERRIDE_CONF = _DENY_OVERRIDE_CONF.replace(
    "e = !some(where (p.eft == deny))",
    "e = some(where (p.eft == allow))")

_PRIORITY_CONF = """\
[request_definition]
r = agent, tool, action

[policy_definition]
p = agent, tool, action, eft

[role_definition]
g = _, _

[policy_effect]
e = priority(p.eft)

[matchers]
m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action

[policy]
p, alice, shell, exec, allow
p, alice, shell, delete, deny

[role_policy]
g, alice, admin
"""


def p_deny_override_deny_wins():
    pid = "deny-override-deny-wins"
    cp = _needs_module(pid)
    if cp is None:
        return
    m = cp.compile_model(_DENY_OVERRIDE_CONF)
    if cp.enforce(m, "bob", "shell", "exec") is False:
        _record(pid, "HELD", "deny row beats allow-capable path under deny-override")
    else:
        _record(pid, "BREAK", "deny did not override")


def p_allow_override_allow_wins():
    pid = "allow-override-allow-wins"
    cp = _needs_module(pid)
    if cp is None:
        return
    m = cp.compile_model(_ALLOW_OVERRIDE_CONF)
    # bob inherits the deny row's agent; alice inherits allow. Under
    # allow-override give carol both roles to force a real conflict.
    conf = _ALLOW_OVERRIDE_CONF.replace("g, bob, blocked",
                                        "g, carol, admin\ng, carol, blocked")
    m2 = cp.compile_model(conf)
    if cp.enforce(m2, "carol", "shell", "exec") is True:
        _record(pid, "HELD", "allow wins under allow-override")
    else:
        _record(pid, "BREAK", "allow did not override")


def p_priority_first_match_decides():
    pid = "priority-first-match-decides"
    cp = _needs_module(pid)
    if cp is None:
        return
    m = cp.compile_model(_PRIORITY_CONF)
    dec, rows = cp.enforce_ex(m, "alice", "shell", "exec")
    if dec is True and rows and rows[0]["eft"] == "allow":
        _record(pid, "HELD", "first matching row (allow) decides under priority")
    else:
        _record(pid, "BREAK", "priority did not take the first match: %r" % (rows,))


def p_enforce_ex_matched_rows():
    pid = "enforce-ex-matched-rows"
    cp = _needs_module(pid)
    if cp is None:
        return
    m = cp.compile_model(_DENY_OVERRIDE_CONF)
    dec, rows = cp.enforce_ex(m, "alice", "shell", "exec")
    ids = [r["row_id"] for r in rows]
    if dec is True and ids == ["p:0"] and rows[0]["eft"] == "allow":
        _record(pid, "HELD", "explain names the deciding row p:0")
    else:
        _record(pid, "BREAK", "matched rows wrong: %r" % (ids,))


def p_packet_feed_row_digests():
    pid = "packet-feed-row-digests"
    cp = _needs_module(pid)
    if cp is None:
        return
    m = cp.compile_model(_DENY_OVERRIDE_CONF)
    result = cp.evaluate(m, "alice", "shell", "exec")
    dec, rows = result["decision"], result["matched_rows"]
    ev = cp.packet_evidence(result)
    if (len(ev) == 1 and len(ev[0]["row_digest"]) == 64
            and ev[0]["row_digest"] == cp.row_digest(rows[0])):
        from gov import decision_packet as dp
        from gov import decision_bom as bom
        bundle_digest = cp.policy_bundle_digest(m)
        body = dp.build_decision_packet(
            decision="allow" if dec else "deny",
            boundary_declared=False,
            matched_rules=ev,
            policy_bundle_digest=bundle_digest,
            policy_id="casbin-perm", policy_version="w281",
            identity={"agent_id": "alice", "role": None,
                      "principal": None, "run_id": None},
            bill_of_materials=bom.build_bom(
                policy_id="casbin-perm", policy_version="w281",
                policy_digest=bundle_digest,
                evidence_head_digest="GENESIS",
                principal={"agent_id": "alice", "role": None,
                           "principal": None, "run_id": None}),
            issued_at="2026-10-02T00:00:00Z")
        pkt = dp.sign_packet(body, bytes.fromhex("22" * 32))
        ok, _reason = dp.verify_decision_packet(pkt)
        if ok is True:
            _record(pid, "HELD", "row digests ride matched_rules; packet verifies")
        else:
            _record(pid, "BREAK", "packet did not verify: %r" % (ok,))
    else:
        _record(pid, "BREAK", "row digest evidence malformed")


def p_batch_enforce_agrees():
    pid = "batch-enforce-agrees"
    cp = _needs_module(pid)
    if cp is None:
        return
    m = cp.compile_model(_DENY_OVERRIDE_CONF)
    reqs = [("alice", "shell", "exec"), ("bob", "shell", "exec"),
            ("mallory", "shell", "exec")]
    batched = cp.batch_enforce(m, reqs)
    single = [cp.enforce(m, a, t, ac) for (a, t, ac) in reqs]
    if batched == single == [True, False, False]:
        _record(pid, "HELD", "batch agrees with single-enforce")
    else:
        _record(pid, "BREAK", "batch/single diverged: %r vs %r" % (batched, single))


def p_role_inheritance_transitive():
    pid = "role-inheritance-transitive"
    cp = _needs_module(pid)
    if cp is None:
        return
    conf = _DENY_OVERRIDE_CONF + "g, carol, alice\n"
    m = cp.compile_model(conf)
    if cp.enforce(m, "carol", "shell", "exec") is True:
        _record(pid, "HELD", "carol -> alice -> admin transitively allows")
    else:
        _record(pid, "BREAK", "transitive role inheritance failed")


def p_role_cycle_terminates():
    pid = "role-cycle-terminates"
    cp = _needs_module(pid)
    if cp is None:
        return
    conf = _DENY_OVERRIDE_CONF + "g, alice, bob\ng, bob, alice\n"
    try:
        m = cp.compile_model(conf)
        dec = cp.enforce(m, "alice", "shell", "exec")
    except Exception as e:  # noqa: BLE001 -- cycle must not hang or crash
        _record(pid, "BREAK", "cycle raised instead of terminating: %r" % (e,))
        return
    _record(pid, "HELD", "role cycle terminates (decision %r)" % (dec,))


def p_compile_unknown_function_refused():
    pid = "compile-unknown-function-refused"
    cp = _needs_module(pid)
    if cp is None:
        return
    bad = _DENY_OVERRIDE_CONF.replace(
        "m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action",
        "m = evil(r.agent, p.agent)")
    try:
        cp.compile_model(bad)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", "") == "casbin-unknown-matcher-function":
            _record(pid, "HELD", "unknown matcher function refused at compile")
        else:
            _record(pid, "BREAK", "wrong refusal shape: %r" % (e,))
    else:
        _record(pid, "BREAK", "unknown matcher function compiled silently")


def p_compile_bad_conf_refused():
    pid = "compile-bad-conf-refused"
    cp = _needs_module(pid)
    if cp is None:
        return
    try:
        cp.compile_model("[policy]\np, alice\n")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", "") == "casbin-conf-invalid":
            _record(pid, "HELD", "malformed CONF refused at compile")
        else:
            _record(pid, "BREAK", "wrong refusal shape: %r" % (e,))
    else:
        _record(pid, "BREAK", "malformed CONF compiled silently")


def p_compile_shadowed_refused():
    pid = "compile-shadowed-refused"
    cp = _needs_module(pid)
    if cp is None:
        return
    # Under deny-override the earlier deny covers everything the later
    # allow could match: the allow row can never decide.
    shadowed = _DENY_OVERRIDE_CONF.replace(
        "p, blocked, shell, exec, deny",
        "p, blocked, shell, exec, deny\np, blocked, shell, exec, allow")
    try:
        cp.compile_model(shadowed)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", "") == "casbin-policy-shadowed":
            _record(pid, "HELD", "shadowed row refused at load")
        else:
            _record(pid, "BREAK", "wrong refusal shape: %r" % (e,))
    else:
        _record(pid, "BREAK", "shadowed row loaded silently")


def p_compile_duplicate_refused():
    pid = "compile-duplicate-refused"
    cp = _needs_module(pid)
    if cp is None:
        return
    dup = _DENY_OVERRIDE_CONF.replace(
        "p, blocked, shell, exec, deny",
        "p, blocked, shell, exec, deny\np, blocked, shell, exec, deny")
    try:
        cp.compile_model(dup)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", "") == "casbin-policy-shadowed":
            _record(pid, "HELD", "duplicate row refused at load")
        else:
            _record(pid, "BREAK", "wrong refusal shape: %r" % (e,))
    else:
        _record(pid, "BREAK", "duplicate row loaded silently")


def p_fail_closed_runtime_error():
    pid = "fail-closed-runtime-error"
    cp = _needs_module(pid)
    if cp is None:
        return
    # regexMatch over a non-string request field: matcher errors at
    # runtime must deny, never raise, never allow.
    conf = _DENY_OVERRIDE_CONF.replace(
        "m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action",
        "m = regexMatch(r.tool, p.tool) && g(r.agent, p.agent)")
    m = cp.compile_model(conf)
    try:
        dec, rows = cp.enforce_ex(m, "alice", None, "exec")
    except Exception as e:  # noqa: BLE001
        _record(pid, "BREAK", "runtime matcher error raised: %r" % (e,))
        return
    if dec is False:
        _record(pid, "HELD", "runtime matcher error failed closed to deny")
    else:
        _record(pid, "BREAK", "runtime matcher error allowed")


def p_nonboolean_matcher_fail_closed():
    pid = "nonboolean-matcher-fail-closed"
    cp = _needs_module(pid)
    if cp is None:
        return
    conf = _DENY_OVERRIDE_CONF.replace(
        "m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action",
        "m = r.tool")
    m = cp.compile_model(conf)
    try:
        dec, rows = cp.enforce_ex(m, "alice", "shell", "exec")
    except Exception as e:  # noqa: BLE001
        _record(pid, "BREAK", "non-boolean matcher raised: %r" % (e,))
        return
    if dec is False:
        _record(pid, "HELD", "non-boolean matcher failed closed to deny")
    else:
        _record(pid, "BREAK", "non-boolean matcher matched truthy")


def _shadow_conf(matcher):
    return "\n".join([
        "[request_definition]", "r = agent, tool, action",
        "[policy_definition]", "p = agent, tool, action, eft",
        "[policy_effect]", "e = some(where (p.eft == allow))",
        "[matchers]", "m = " + matcher,
        "[policy]",
        "p, admin, *, exec, allow",
        "p, admin, shell, exec, allow",
    ])


def p_shadow_nonmonotone_no_false_flag():
    # S1: `*`-in-earlier under `!=` matches nothing, so the later row is
    # live — the subset analysis must stay silent (no false flag), and the
    # later row must decide.
    pid = "shadow-nonmonotone-no-false-flag"
    cp = _needs_module(pid)
    if cp is None:
        return
    conf = _shadow_conf(
        "r.agent == p.agent && r.tool != p.tool && r.action == p.action")
    try:
        m = cp.compile_model(conf)
    except Exception as e:  # noqa: BLE001
        _record(pid, "BREAK",
                "false flag: live row refused under != matcher: %r" % (e,))
        return
    if cp.enforce(m, "admin", "ls", "exec") is True:
        _record(pid, "HELD", "non-monotone matcher: no false flag, live row decides")
    else:
        _record(pid, "BREAK", "non-monotone matcher: live row did not decide")


def p_shadow_negation_no_false_flag():
    # S1 variant with `!`: same no-false-flag requirement.
    pid = "shadow-negation-no-false-flag"
    cp = _needs_module(pid)
    if cp is None:
        return
    conf = _shadow_conf(
        "r.agent == p.agent && !(r.tool == p.tool) && r.action == p.action")
    try:
        m = cp.compile_model(conf)
    except Exception as e:  # noqa: BLE001
        _record(pid, "BREAK",
                "false flag: live row refused under ! matcher: %r" % (e,))
        return
    if cp.enforce(m, "admin", "ls", "exec") is True:
        _record(pid, "HELD", "negated matcher: no false flag, live row decides")
    else:
        _record(pid, "BREAK", "negated matcher: live row did not decide")


def p_matcher_unknown_attr_compile_refusal():
    # S2: unknown r.*/p.* attributes are refused at compile with a code.
    pid = "matcher-unknown-attr-compile-refusal"
    cp = _needs_module(pid)
    if cp is None:
        return
    for attr in ("r.agnet", "p.row_id", "p.lineno"):
        conf = _DENY_OVERRIDE_CONF.replace(
            "m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action",
            "m = g(r.agent, p.agent) && %s == p.tool && r.action == p.action" % attr
            if attr.startswith("r.") else
            "m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action && %s == \"p:0\"" % attr)
        try:
            cp.compile_model(conf)
        except Exception as e:  # noqa: BLE001
            if getattr(e, "code", "") != "casbin-conf-invalid":
                _record(pid, "BREAK",
                        "%s refused without code: %r" % (attr, e))
                return
        else:
            _record(pid, "BREAK", "%s accepted in matcher" % attr)
            return
    _record(pid, "HELD", "unknown r.*/p.* attrs refused at compile with code")


def p_deep_matcher_compile_refusal():
    # S3: pathologically nested matcher must refuse with a code, not leak
    # a bare RecursionError.
    pid = "deep-matcher-compile-refusal"
    cp = _needs_module(pid)
    if cp is None:
        return
    nested = "!" * 5000 + "(r.tool == p.tool)"
    conf = _DENY_OVERRIDE_CONF.replace(
        "m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action",
        "m = g(r.agent, p.agent) && %s && r.action == p.action" % nested)
    try:
        cp.compile_model(conf)
    except RecursionError:
        _record(pid, "BREAK", "bare RecursionError escaped compile_model")
        return
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", "") == "casbin-conf-invalid":
            _record(pid, "HELD", "deep matcher refused with coded error")
        else:
            _record(pid, "BREAK", "deep matcher refused without code: %r" % (e,))
        return
    _record(pid, "BREAK", "5000-deep matcher compiled without refusal")


def p_batch_string_triple_raises():
    # S4: a str is not a triple — fail-fast ValueError, never silent deny.
    pid = "batch-string-triple-raises"
    cp = _needs_module(pid)
    if cp is None:
        return
    m = cp.compile_model(_DENY_OVERRIDE_CONF)
    try:
        cp.batch_enforce(m, ["abc"])
    except ValueError:
        _record(pid, "HELD", "str triple raises ValueError (fail-fast)")
        return
    except Exception as e:  # noqa: BLE001
        _record(pid, "BREAK", "str triple raised %r" % (e,))
        return
    _record(pid, "BREAK", "str triple silently accepted")


def p_default_deny():
    pid = "default-deny"
    cp = _needs_module(pid)
    if cp is None:
        return
    m = cp.compile_model(_DENY_OVERRIDE_CONF)
    dec, rows = cp.enforce_ex(m, "mallory", "shell", "exec")
    if dec is False and rows == []:
        _record(pid, "HELD", "no matching rows denies with empty explain")
    else:
        _record(pid, "BREAK", "default-deny violated: %r %r" % (dec, rows))


def p_keymatch_builtin():
    pid = "keymatch-builtin"
    cp = _needs_module(pid)
    if cp is None:
        return
    conf = _DENY_OVERRIDE_CONF.replace(
        "m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action",
        "m = g(r.agent, p.agent) && keyMatch(r.tool, p.tool) && r.action == p.action")
    conf = conf.replace("p, admin, shell, exec, allow",
                        "p, admin, shell/*, exec, allow")
    m = cp.compile_model(conf)
    if cp.enforce(m, "alice", "shell/ls", "exec") is True:
        _record(pid, "HELD", "keyMatch prefix wildcard matched")
    else:
        _record(pid, "BREAK", "keyMatch did not match")


def p_invalid_regex_refused_at_compile():
    pid = "invalid-regex-refused-at-compile"
    cp = _needs_module(pid)
    if cp is None:
        return
    conf = _DENY_OVERRIDE_CONF.replace(
        "m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action",
        "m = regexMatch(r.tool, p.tool) && g(r.agent, p.agent)")
    conf = conf.replace("p, admin, shell, exec, allow",
                        "p, admin, ([invalid, exec, allow")
    try:
        cp.compile_model(conf)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", "") == "casbin-conf-invalid":
            _record(pid, "HELD", "invalid regex refused at compile")
        else:
            _record(pid, "BREAK", "wrong refusal shape: %r" % (e,))
    else:
        _record(pid, "BREAK", "invalid regex compiled silently")


def p_taxonomy_pin():
    pid = "pin-taxonomy-1545"
    try:
        from gov import decision_codes as dc
        raw = open("gov/decision_codes.py", encoding="utf-8").read()
        # Wave-260 lesson: assert uniqueness on raw source literals, not
        # the deduped dict. Every code must appear exactly once as a
        # "code": '<code>' literal (raw.count == 1 for each).
        dupes = [c for c in dc.TAXONOMY
                 if raw.count('"code": \'%s\'' % c) != 1]
        keys = list(dc.TAXONOMY.keys())
        ok = (len(dc.TAXONOMY) == TAXONOMY_PIN and not dupes
              and keys == sorted(keys))
        _record(pid, "HELD" if ok else "BREAK",
                "taxonomy %d/%d, dupes=%r" % (len(keys), TAXONOMY_PIN, dupes[:4]))
    except Exception as e:  # noqa: BLE001
        _record(pid, "BREAK", "taxonomy check errored: %r" % (e,))


def p_green_checks():
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-checks-skipped", "HELD", "depth-1: parent ran green checks")
        return
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    for mod in ("tests.test_decision_codes", "tests.test_casbin_perm"):
        r = subprocess.run(
            [sys.executable, "-m", "unittest", mod, "-v"],
            capture_output=True, text=True, env=env,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        if r.returncode != 0:
            _record("green-" + mod, "BREAK", r.stderr[-500:])
            return
    _record("green-checks", "HELD", "adjacent suites green")


PROBES = [
    p_deny_override_deny_wins,
    p_allow_override_allow_wins,
    p_priority_first_match_decides,
    p_enforce_ex_matched_rows,
    p_packet_feed_row_digests,
    p_batch_enforce_agrees,
    p_role_inheritance_transitive,
    p_role_cycle_terminates,
    p_compile_unknown_function_refused,
    p_compile_bad_conf_refused,
    p_compile_shadowed_refused,
    p_compile_duplicate_refused,
    p_fail_closed_runtime_error,
    p_nonboolean_matcher_fail_closed,
    p_shadow_nonmonotone_no_false_flag,
    p_shadow_negation_no_false_flag,
    p_matcher_unknown_attr_compile_refusal,
    p_deep_matcher_compile_refusal,
    p_batch_string_triple_raises,
    p_default_deny,
    p_keymatch_builtin,
    p_invalid_regex_refused_at_compile,
    p_taxonomy_pin,
    p_green_checks,
]

PROBE_METADATA = {
    # (plugin, strategy, grader) drawn from gov/battery_lang.py's closed
    # vocabularies so tools/battery-generate can pin this suite.
    "deny-override-deny-wins": ("privilege-escalation", "direct", "held-vs-expected"),
    "allow-override-allow-wins": ("privilege-escalation", "direct", "held-vs-expected"),
    "priority-first-match-decides": ("privilege-escalation", "direct", "held-vs-expected"),
    "enforce-ex-matched-rows": ("guardrail-evidence", "direct", "held-vs-expected"),
    "packet-feed-row-digests": ("guardrail-evidence", "replay", "held-vs-expected"),
    "batch-enforce-agrees": ("privilege-escalation", "replay", "replay-identical"),
    "role-inheritance-transitive": ("delegation-binding", "direct", "held-vs-expected"),
    "role-cycle-terminates": ("delegation-binding", "direct", "held-vs-expected"),
    "compile-unknown-function-refused": ("supply-chain", "schema-bypass", "held-vs-expected"),
    "compile-bad-conf-refused": ("supply-chain", "schema-bypass", "held-vs-expected"),
    "compile-shadowed-refused": ("policy-drift", "regression", "held-vs-expected"),
    "compile-duplicate-refused": ("policy-drift", "regression", "held-vs-expected"),
    "fail-closed-runtime-error": ("privilege-escalation", "type-confusion", "held-vs-expected"),
    "nonboolean-matcher-fail-closed": ("privilege-escalation", "type-confusion", "held-vs-expected"),
    "shadow-nonmonotone-no-false-flag": ("policy-bypass", "shadowing", "held-vs-expected"),
    "shadow-negation-no-false-flag": ("policy-bypass", "shadowing", "held-vs-expected"),
    "matcher-unknown-attr-compile-refusal": ("privilege-escalation", "type-confusion", "held-vs-expected"),
    "deep-matcher-compile-refusal": ("denial-of-service", "resource-exhaustion", "held-vs-expected"),
    "batch-string-triple-raises": ("privilege-escalation", "type-confusion", "held-vs-expected"),
    "default-deny": ("privilege-escalation", "direct", "held-vs-expected"),
    "keymatch-builtin": ("privilege-escalation", "normalization-variant", "held-vs-expected"),
    "invalid-regex-refused-at-compile": ("supply-chain", "schema-bypass", "held-vs-expected"),
    "pin-taxonomy-1545": ("closure-repin", "regression", "held-vs-expected"),
    "green-checks": ("closure-repin", "regression", "held-vs-expected"),
}


def main():
    for probe in PROBES:
        probe()
    held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    brk = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    print(json.dumps({"held": held, "break": brk, "error": err,
                      "results": _RESULTS}, indent=1))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
