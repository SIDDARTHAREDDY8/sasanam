"""Break-first red battery: policy authoring layer + harness dry-run
(wave-253 lane 3; cloud-custodian/cloud-custodian ADAPT -- the
filters/actions authoring VOCABULARY and the dry-run/structured-match
UX only, never c7n code or its cloud-resource model).

The gap under test: policy authors write native engine YAML by hand,
with no friendlier vocabulary, no way to preview "what would this
rule do" against fixtures without enforcing it, and no structured
record of which filter matched and why. A misspelled authoring
construct must refuse fail-closed at compile time -- never silently
compile to a weaker rule.

On the pristine wave-252 base every probe reports GAP (the module
does not exist). After the build, every probe must report HELD under
both staging and a clean environment.

Synthetic/local only. Deterministic: fixed fixtures, sorted
assertions, no wall clock in asserted values. Stdlib only, no
in-repo git subprocesses. Fresh TMPDIR per process is the caller's
concern; this battery writes only inside the stdlib tempdir.
"""

import json
import os
import shutil
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

# Repo root (this file lives in evals/) so `gov` is importable when the
# battery is run from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# ------------------------------------------------------------------
# probe harness
# ------------------------------------------------------------------

RESULTS = []


def _record(name, verdict, detail=""):
    RESULTS.append({"probe": name, "verdict": verdict, "detail": detail})
    return verdict


def load_authoring_module():
    """Return (gov.policy_authoring, None) or (None, reason)."""
    try:
        from gov import policy_authoring
        return policy_authoring, None
    except ImportError as exc:  # noqa: BLE001 - importability is the gap
        return None, str(exc)


def _mktmp():
    tmpd = tempfile.mkdtemp(prefix="w253-authoring-")
    return tmpd


# --- authored fixtures ------------------------------------------------

GOOD_DENY = """\
version: 1
policies:
  - name: block-secret-reads
    description: Deny reads of secret-like paths.
    filters:
      - type: value-filter
        key: tool
        op: eq
        value: read_file
      - type: value-filter
        key: path
        op: contains-any
        value: [secret, credentials]
    actions:
      - type: deny
        reason: Read of a secret-like path is denied.
        flag: secret_access_attempt
"""

OR_POLICY = """\
version: 1
policies:
  - name: block-bad-egress
    filters:
      - type: or
        filters:
          - type: value-filter
            key: tool
            op: eq
            value: send_email
          - type: value-filter
            key: tool
            op: eq
            value: http_post
      - type: value-filter
        key: domain_allowlisted
        op: eq
        value: false
    actions:
      - type: deny
        reason: Egress to a non-allowlisted domain is denied.
"""

ALLOW_APPROVAL = """\
version: 1
policies:
  - name: allow-reads
    filters:
      - type: value-filter
        key: tool
        op: eq
        value: read_file
    actions:
      - type: allow
        reason: Reads are allowed.
  - name: approval-sends
    filters:
      - type: value-filter
        key: tool
        op: eq
        value: send_email
    actions:
      - type: require-approval
        reason: Sends need a human.
"""


def _harness_dir(tmpd):
    """A minimal harness dir: one native policy + two fixtures."""
    hdir = os.path.join(tmpd, "harness")
    os.makedirs(os.path.join(hdir, "policies"))
    os.makedirs(os.path.join(hdir, "fixtures"))
    os.makedirs(os.path.join(hdir, "expected"))
    with open(os.path.join(hdir, "policies", "base.yaml"), "w",
              encoding="utf-8") as fh:
        fh.write("version: 2\npolicies:\n"
                 "  - id: allow-read\n"
                 "    effect: allow\n"
                 "    match:\n"
                 "      tool: [read_file]\n"
                 "  - id: allow-send\n"
                 "    effect: allow\n"
                 "    match:\n"
                 "      tool: [send_email]\n")
    fixtures = {
        "read.json": ({"tool": "read_file",
                       "args": {"path": "/tmp/notes.txt"}},
                      {"counters": {}}),
        "send.json": ({"tool": "send_email",
                       "args": {"to": "x@synthetic.local"}},
                      {"domain_allowlisted": True, "counters": {}}),
    }
    for fname, (action, context) in fixtures.items():
        with open(os.path.join(hdir, "fixtures", fname), "w",
                  encoding="utf-8") as fh:
            json.dump({"action": action, "context": context}, fh)
        with open(os.path.join(hdir, "expected", fname), "w",
                  encoding="utf-8") as fh:
            json.dump({"effect": "allow"}, fh)
    return hdir


def _snapshot(hdir):
    """(relpath -> (size, mtime_ns)) for every file under hdir."""
    out = {}
    for root, _dirs, files in os.walk(hdir):
        for f in files:
            p = os.path.join(root, f)
            st = os.stat(p)
            out[os.path.relpath(p, hdir)] = (st.st_size,
                                             st.st_mtime_ns)
    return out


# --- probes ------------------------------------------------------------

def probe_unknown_filter_type():
    """A filter type we do not know must refuse, never weaken."""
    mod, reason = load_authoring_module()
    if mod is None:
        return _record("authoring/unknown-filter-type", "GAP", reason)
    text = GOOD_DENY.replace("type: value-filter",
                             "type: quantum-filter", 1)
    try:
        mod.compile_authoring(text)
    except mod.AuthoringError as exc:
        if exc.code == "policy-authoring-unknown-filter":
            return _record("authoring/unknown-filter-type", "HELD",
                           "refused with code")
        return _record("authoring/unknown-filter-type", "BREAK",
                       "wrong code %r" % (exc.code,))
    return _record("authoring/unknown-filter-type", "BREAK",
                   "unknown filter type compiled silently")


def probe_unknown_action():
    """An action type we do not know must refuse, never weaken."""
    mod, reason = load_authoring_module()
    if mod is None:
        return _record("authoring/unknown-action", "GAP", reason)
    text = GOOD_DENY.replace("- type: deny", "- type: self-destruct")
    try:
        mod.compile_authoring(text)
    except mod.AuthoringError as exc:
        if exc.code == "policy-authoring-unknown-action":
            return _record("authoring/unknown-action", "HELD",
                           "refused with code")
        return _record("authoring/unknown-action", "BREAK",
                       "wrong code %r" % (exc.code,))
    return _record("authoring/unknown-action", "BREAK",
                   "unknown action compiled silently")


def probe_unknown_op():
    """An op the key does not support must refuse, never coerce."""
    mod, reason = load_authoring_module()
    if mod is None:
        return _record("authoring/unknown-op", "GAP", reason)
    # op teleport on tool
    text = GOOD_DENY.replace("op: eq", "op: teleport", 1)
    try:
        mod.compile_authoring(text)
        return _record("authoring/unknown-op", "BREAK",
                       "unknown op compiled silently")
    except mod.AuthoringError as exc:
        if exc.code != "policy-authoring-unknown-op":
            return _record("authoring/unknown-op", "BREAK",
                           "wrong code %r" % (exc.code,))
    # op eq on path (only contains-any is honest there)
    text2 = GOOD_DENY.replace("op: contains-any", "op: eq")
    try:
        mod.compile_authoring(text2)
        return _record("authoring/unknown-op", "BREAK",
                       "path/eq compiled silently")
    except mod.AuthoringError as exc:
        if exc.code != "policy-authoring-unknown-op":
            return _record("authoring/unknown-op", "BREAK",
                           "wrong code %r" % (exc.code,))
    return _record("authoring/unknown-op", "HELD", "both refused")


def probe_unknown_key():
    """A filter key we cannot compile must refuse."""
    mod, reason = load_authoring_module()
    if mod is None:
        return _record("authoring/unknown-key", "GAP", reason)
    text = GOOD_DENY.replace("key: tool", "key: social_security_number",
                             1)
    try:
        mod.compile_authoring(text)
    except mod.AuthoringError as exc:
        if exc.code == "policy-authoring-unknown-filter":
            return _record("authoring/unknown-key", "HELD",
                           "refused with code")
        return _record("authoring/unknown-key", "BREAK",
                       "wrong code %r" % (exc.code,))
    return _record("authoring/unknown-key", "BREAK",
                   "unknown key compiled silently")


def probe_conflicting_and():
    """Two filters on the same key inside one AND must refuse --
    merging them would be a UNION (weaker), not the author's AND."""
    mod, reason = load_authoring_module()
    if mod is None:
        return _record("authoring/conflicting-and", "GAP", reason)
    text = """\
version: 1
policies:
  - name: impossible
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
        reason: x
"""
    try:
        mod.compile_authoring(text)
    except mod.AuthoringError as exc:
        if exc.code == "policy-authoring-conflicting-filters":
            return _record("authoring/conflicting-and", "HELD",
                           "refused with code")
        return _record("authoring/conflicting-and", "BREAK",
                       "wrong code %r" % (exc.code,))
    return _record("authoring/conflicting-and", "BREAK",
                   "conflicting AND compiled silently")


def probe_or_expands():
    """or must expand to one native rule per branch; every branch
    enforces (no branch silently dropped)."""
    mod, reason = load_authoring_module()
    if mod is None:
        return _record("authoring/or-expands", "GAP", reason)
    compiled = mod.compile_authoring(OR_POLICY)
    if len(compiled.plans) != 2:
        return _record("authoring/or-expands", "BREAK",
                       "expected 2 rules, got %d"
                       % len(compiled.plans))
    engine = compiled.engine
    cases = [
        ({"tool": "send_email", "args": {}},
         {"domain_allowlisted": False}, "deny"),
        ({"tool": "http_post", "args": {}},
         {"domain_allowlisted": False}, "deny"),
        # Neither branch matches: default deny (fail-closed), and --
        # critically -- no branch allows.
        ({"tool": "read_file", "args": {}}, {}, "deny"),
        # Allowlisted egress: no branch matches -> default deny.
        ({"tool": "send_email", "args": {}},
         {"domain_allowlisted": True}, "deny"),
    ]
    for action, context, want in cases:
        got = engine.evaluate(action, context,
                              record_telemetry=False).effect
        if got != want:
            return _record("authoring/or-expands", "BREAK",
                           "tool %r: expected %r, got %r"
                           % (action["tool"], want, got))
    ids = compiled.rule_ids()
    if len(set(ids)) != 2:
        return _record("authoring/or-expands", "BREAK",
                       "rule ids not unique: %r" % (ids,))
    return _record("authoring/or-expands", "HELD", "2 rules, 4/4")


def probe_dry_run_no_mutation():
    """dry_run must be read-only AND must preview the candidate's
    would-deny on a fixture the current set allows."""
    mod, reason = load_authoring_module()
    if mod is None:
        return _record("authoring/dry-run-no-mutation", "GAP", reason)
    tmpd = _mktmp()
    hdir = _harness_dir(tmpd)
    before = _snapshot(hdir)
    # Candidate: deny send_email to non-allowlisted domains. The
    # fixture's send has domain_allowlisted=True, so craft the
    # candidate to fire on the flag absent (fail-closed signal).
    candidate = """\
version: 1
policies:
  - name: preview-deny-sends
    filters:
      - type: value-filter
        key: tool
        op: eq
        value: send_email
    actions:
      - type: deny
        reason: preview
"""
    report = mod.dry_run(hdir, authoring_text=candidate)
    after = _snapshot(hdir)
    if before != after:
        return _record("authoring/dry-run-no-mutation", "BREAK",
                       "harness dir mutated by dry_run")
    by_name = {f["fixture"]: f for f in report.to_dict()["fixtures"]}
    send = by_name["send.json"]
    if send["current"]["effect"] != "allow":
        return _record("authoring/dry-run-no-mutation", "BREAK",
                       "current effect wrong: %r"
                       % (send["current"]["effect"],))
    if send["with_candidate"]["effect"] != "deny":
        return _record("authoring/dry-run-no-mutation", "BREAK",
                       "candidate did not flip to deny: %r"
                       % (send["with_candidate"]["effect"],))
    if not send["changed"]:
        return _record("authoring/dry-run-no-mutation", "BREAK",
                       "changed flag not set")
    if send["candidate"] is None or send["candidate"]["effect"] \
            != "deny":
        return _record("authoring/dry-run-no-mutation", "BREAK",
                       "candidate-alone verdict missing/wrong")
    # expected/ files must NOT be required: dry-run previews, it
    # does not grade.
    shutil.rmtree(os.path.join(hdir, "expected"))
    no_expected = mod.dry_run(hdir, authoring_text=candidate)
    if no_expected.fixtures[0]["with_candidate"]["effect"] != "deny":
        return _record("authoring/dry-run-no-mutation", "BREAK",
                       "dry_run requires expected/ files")
    return _record("authoring/dry-run-no-mutation", "HELD",
                   "read-only; allow->deny previewed")


def probe_match_explanation_honest():
    """The authoring-layer filter explanation must agree with the
    engine's own trace on rule-level verdicts -- the explanation is
    never a prettier lie."""
    mod, reason = load_authoring_module()
    if mod is None:
        return _record("authoring/match-explanation", "GAP", reason)
    compiled = mod.compile_authoring(GOOD_DENY)
    engine = compiled.engine
    from gov.decision_contract import Request
    cases = [
        ({"tool": "read_file", "args": {"path": "/x/secret.txt"}},
         {}),
        ({"tool": "read_file", "args": {"path": "/x/notes.txt"}},
         {}),
        ({"tool": "send_email", "args": {}}, {}),
        ({"tool": "read_file", "args": {"path": "/c/credentials"}},
         {}),
    ]
    for action, context in cases:
        explained = mod.explain_candidate(compiled, action, context)
        request = Request.from_action(action, context)
        trace = {t.rule_id: bool(t.matched)
                 for t in engine.decide(
                     request,
                     record_telemetry=False).diagnostics.trace}
        for rec in explained:
            engine_says = trace.get(rec["rule"])
            if engine_says is None:
                return _record("authoring/match-explanation", "BREAK",
                               "rule %r missing from engine trace"
                               % (rec["rule"],))
            if rec["matched"] != engine_says:
                return _record("authoring/match-explanation", "BREAK",
                               "rule %r: explanation says %r, engine "
                               "says %r" % (rec["rule"],
                                            rec["matched"],
                                            engine_says))
            # The why must name the filter and be non-empty.
            for f in rec["filters"]:
                if not f["why"] or f["key"] not in f["why"]:
                    return _record("authoring/match-explanation",
                                   "BREAK",
                                   "empty/opaque why: %r" % (f,))
    # The secret path must NOT leak into the why (policy-authored
    # substrings only).
    explained = mod.explain_candidate(
        compiled, {"tool": "read_file",
                   "args": {"path": "/x/s3cr3t-bucket"}},
        {})
    blob = json.dumps(explained)
    if "s3cr3t-bucket" in blob:
        return _record("authoring/match-explanation", "BREAK",
                       "raw path leaked into explanation")
    # Case 5: F146 -- the engine matches against context
    # path_resolved as well as the declared path. The explanation
    # must agree with the engine trace and must leak neither the
    # declared nor the resolved raw path.
    resolved_ctx = {"path_resolved": "/vault/secret-thing"}
    action = {"tool": "read_file", "args": {"path": "/x/notes"}}
    recs = mod.explain_candidate(compiled, action, resolved_ctx)
    engine = compiled.engine
    trace = {t.rule_id: bool(t.matched)
             for t in engine.decide(
                 Request.from_action(action, resolved_ctx),
                 record_telemetry=False).diagnostics.trace}
    got = {r["rule"]: r for r in recs}["block-secret-reads"]
    if not trace["block-secret-reads"]:
        return _record("authoring/match-explanation", "BREAK",
                       "F146 setup: engine did not match resolved "
                       "target")
    if not got["matched"]:
        return _record("authoring/match-explanation", "BREAK",
                       "explanation disagrees with engine on "
                       "path_resolved")
    blob = json.dumps(recs)
    if "secret-thing" in blob:
        return _record("authoring/match-explanation", "BREAK",
                       "why leaks the resolved path")
    return _record("authoring/match-explanation", "HELD",
                   "5/5 agree with engine trace; no path leak")


def probe_compile_roundtrip():
    """The compiled native YAML must load via PolicyEngine.from_text
    directly (engine-valid by construction) and be byte-identical
    across compiles (deterministic)."""
    mod, reason = load_authoring_module()
    if mod is None:
        return _record("authoring/compile-roundtrip", "GAP", reason)
    first = mod.compile_authoring(GOOD_DENY).native_text
    second = mod.compile_authoring(GOOD_DENY).native_text
    if first != second:
        return _record("authoring/compile-roundtrip", "BREAK",
                       "non-deterministic compile")
    from gov.policy import PolicyEngine
    try:
        engine = PolicyEngine.from_text(first,
                                        source_label="battery-check")
    except Exception as exc:  # noqa: BLE001 - loud is the point
        return _record("authoring/compile-roundtrip", "BREAK",
                       "native text refused: %r" % (exc,))
    got = engine.evaluate({"tool": "read_file",
                           "args": {"path": "/x/secret"}},
                          record_telemetry=False).effect
    if got != "deny":
        return _record("authoring/compile-roundtrip", "BREAK",
                       "compiled rule does not deny: %r" % (got,))
    return _record("authoring/compile-roundtrip", "HELD",
                   "engine-valid, deterministic")


def probe_action_effect_mapping():
    """deny/allow/require-approval must map to the native effects and
    the forbid-overrides-permit combiner must still win for deny."""
    mod, reason = load_authoring_module()
    if mod is None:
        return _record("authoring/action-effect-mapping", "GAP", reason)
    compiled = mod.compile_authoring(ALLOW_APPROVAL)
    engine = compiled.engine
    cases = [
        ({"tool": "read_file", "args": {}}, "allow"),
        ({"tool": "send_email", "args": {}}, "require_approval"),
    ]
    for action, want in cases:
        got = engine.evaluate(action, {}, record_telemetry=False
                              ).effect
        if got != want:
            return _record("authoring/action-effect-mapping", "BREAK",
                           "tool %r: expected %r, got %r"
                           % (action["tool"], want, got))
    # Forbid still overrides: combine the authored allow with a
    # native deny for the same tool.
    from gov import policy_combine
    from gov.policy import PolicyEngine as PE
    deny_engine = PE.from_text(
        "version: 2\npolicies:\n"
        "  - id: deny-read\n"
        "    effect: deny\n"
        "    match:\n"
        "      tool: [read_file]\n",
        source_label="battery-deny")
    decisions = [
        engine.evaluate({"tool": "read_file", "args": {}},
                        {}, record_telemetry=False),
        deny_engine.evaluate({"tool": "read_file", "args": {}},
                             {}, record_telemetry=False),
    ]
    combined = policy_combine.combine(decisions)
    if combined.effect != "deny":
        return _record("authoring/action-effect-mapping", "BREAK",
                       "forbid did not override authored allow")
    return _record("authoring/action-effect-mapping", "HELD",
                   "effects map; forbid wins")


def probe_dry_run_deterministic():
    """Two dry_run calls on the same harness must be byte-identical."""
    mod, reason = load_authoring_module()
    if mod is None:
        return _record("authoring/dry-run-deterministic", "GAP",
                       reason)
    tmpd = _mktmp()
    hdir = _harness_dir(tmpd)
    first = mod.dry_run(hdir).to_json()
    second = mod.dry_run(hdir).to_json()
    if first != second:
        return _record("authoring/dry-run-deterministic", "BREAK",
                       "non-deterministic dry_run")
    return _record("authoring/dry-run-deterministic", "HELD",
                   "byte-identical")


# ------------------------------------------------- green checks (depth-1)

def _green():
    """Depth-1: run the adjacent wave-251 harness battery with
    GOV_SKIP_GREEN=1 and require zero BREAK/ERROR. Honors
    GOV_SKIP_GREEN itself (records skip, never spawns)."""
    import subprocess
    if SKIP_GREEN:
        return ["green checks skipped (GOV_SKIP_GREEN=1)"]
    here = os.path.dirname(os.path.abspath(__file__))
    batteries = ["w251_harness_probes.py"]
    notes = []
    for bat in batteries:
        path = os.path.join(here, bat)
        if not os.path.exists(path):
            notes.append("%s: missing, skipped" % bat)
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        tmpd = _mktmp()
        env["TMPDIR"] = tmpd
        try:
            proc = subprocess.run(
                [sys.executable, path], env=env, capture_output=True,
                text=True, timeout=600, cwd=os.path.join(here, ".."))
        except Exception as exc:  # noqa: BLE001
            raise AssertionError("%s green check failed: %r" % (bat,
                                                                exc))
        out = (proc.stdout or "") + (proc.stderr or "")
        # Exit code is the primary signal; the token scan catches a
        # non-HELD verdict even if a battery mis-reports its status.
        bad = ("BREAK" in out and "0 BREAK" not in out) or \
              ("ERROR" in out and "0 ERROR" not in out)
        if proc.returncode != 0 or bad:
            raise AssertionError(
                "%s green check failed (rc=%d): %s"
                % (bat, proc.returncode, out[-2000:]))
        notes.append("%s: green" % bat)
    return notes


# --- main ---------------------------------------------------------------

def main():
    probes = [
        probe_unknown_filter_type,
        probe_unknown_action,
        probe_unknown_op,
        probe_unknown_key,
        probe_conflicting_and,
        probe_or_expands,
        probe_dry_run_no_mutation,
        probe_match_explanation_honest,
        probe_compile_roundtrip,
        probe_action_effect_mapping,
        probe_dry_run_deterministic,
    ]
    for probe in probes:
        try:
            probe()
        except Exception as exc:  # noqa: BLE001 - one bad probe
            # must not mask the rest.
            _record(probe.__name__, "ERROR", "%r" % (exc,))
    try:
        notes = _green()
    except Exception as exc:  # noqa: BLE001
        _record("green-checks", "ERROR", "%r" % (exc,))
        notes = []
    held = sum(1 for r in RESULTS if r["verdict"] == "HELD")
    gap = sum(1 for r in RESULTS if r["verdict"] == "GAP")
    brk = sum(1 for r in RESULTS if r["verdict"] == "BREAK")
    err = sum(1 for r in RESULTS if r["verdict"] == "ERROR")
    total = len(RESULTS)
    print("w253_authoring_probes: %d/%d HELD (%d GAP, %d BREAK, "
          "%d ERROR)" % (held, total, gap, brk, err))
    for r in RESULTS:
        print("  [%s] %s %s" % (r["verdict"], r["probe"],
                                r["detail"]))
    if notes:
        print("  green: %s" % ("; ".join(notes),))
    # Non-zero unless every probe HELD: GAP (pristine base) and any
    # BREAK/ERROR fail the battery.
    return 0 if (held == total and gap == 0 and brk == 0
                 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
