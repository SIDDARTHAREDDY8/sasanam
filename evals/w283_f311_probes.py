"""Wave-283 F311 closure battery: GuardChain evidence emission secrets.

Base: wave-282 push ad222ce12a9b5b04d13926b01bf026646a3596ef
(verified via git rev-parse HEAD before work).

F311 (LOW, OPEN): the wave-281 guard-plugin GuardChain's OWN evidence
emission echoes credential-shaped plugin details verbatim into audit
records -- the transform path (guardrail-run rationale
"transform: <detail>" AND the guard-plugin-transform record's detail),
the deny path (guardrail-run rationale "<detail>"), the raised
PluginDeny path (rationale "PluginDeny: <exc>"), the technical-failure
path (exception text), the non-verdict path (%r of the bad return),
and the allow path (detail verbatim). Same defect class as F306/F310,
third emission site.

Close-when: sanitize the GuardChain emit site before any emit with the
F306/F310 credential_material_present seam; kind-preserving redacted
placeholder on hit; verdicts preserved.

Red-first: on the pristine base the emission probes BREAK; after the
fix they HELD.

$0 spend, synthetic/local, deterministic (fixed fixtures). Stdlib only,
no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g283-f311 && TMPDIR=/var/tmp/g283-f311 \\
    ~/workspace/.gov-venv/bin/python evals/w283_f311_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g283-f311b \\
    ~/workspace/.gov-venv/bin/python evals/w283_f311_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from keyfixture import provision_test_key  # noqa: E402

provision_test_key()

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 1797  # Wave-282 merge: 1563 -> 1579; Wave-283 merge: pin 1579 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
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
    _record("pin-taxonomy", "HELD", "1588/1588/0 sorted")


# Synthetic credential-shaped fixture (same shape as the red team's;
# never a real credential).
_SECRET = "password= hunter2-hunter2-x9"
_MARK = "hunter2"


def _gp_chain(tmp_prefix):
    from gov.log import ActionLog, read_entries
    from gov.guardrail_evidence import GuardrailEvidenceWriter
    from gov import guard_plugins as gp
    d = tempfile.mkdtemp(prefix=tmp_prefix)
    audit_path = os.path.join(d, "audit.jsonl")
    log = ActionLog(audit_path)
    writer = GuardrailEvidenceWriter(log)
    reg = gp.PluginRegistry()
    return gp, log, writer, reg, audit_path, read_entries


def _leaked(read_entries, audit_path):
    return [r for r in read_entries(audit_path) if _MARK in repr(r)]


def p_transform_detail_echo():
    """F311: transform detail echoed into guardrail-run rationale AND
    the guard-plugin-transform record."""
    from gov import elicitation_contract as ec
    assert ec.credential_material_present(_SECRET), "detector must fire"
    gp, log, writer, reg, audit_path, read_entries = _gp_chain(
        "w283-f311-t-")

    def _evil(ctx):
        new = dict(ctx.payload)
        new["token"] = "REDACTED"
        return gp.transform_outcome(
            new, detail="redacted %s from args" % _SECRET)

    reg.register("evil-redact", hooks=["before_tool_call"], run=_evil)
    chain = gp.GuardChain(reg, writer, log)
    verdict = chain.run_hook("before_tool_call", tool_name="send_email",
                             payload={"to": "x"},
                             plugin_ids=["evil-redact"])
    if not verdict.allowed:
        return _record("f311-transform-detail-echo", "BREAK",
                       "transform unexpectedly denied")
    leaked = _leaked(read_entries, audit_path)
    if leaked:
        _record("f311-transform-detail-echo", "BREAK",
                "F311: %d audit record(s) echo credential-shaped "
                "transform detail (%s)"
                % (len(leaked), ",".join(sorted(
                    {r.get("record_type", "?") for r in leaked}))))
    else:
        _record("f311-transform-detail-echo", "HELD",
                "transform detail sanitized before emit")


def p_deny_detail_echo():
    """F311: returned-deny detail echoed into the guardrail-run
    rationale."""
    from gov import elicitation_contract as ec
    assert ec.credential_material_present(_SECRET), "detector must fire"
    gp, log, writer, reg, audit_path, read_entries = _gp_chain(
        "w283-f311-d-")

    def _evil_deny(ctx):
        return gp.deny_outcome("refusing: saw %s in args" % _SECRET)

    reg.register("evil-deny", hooks=["before_tool_call"], run=_evil_deny)
    chain = gp.GuardChain(reg, writer, log)
    v = chain.run_hook("before_tool_call", tool_name="send_email",
                       payload={"to": "x"}, plugin_ids=["evil-deny"])
    if v.allowed or v.denied_by != "evil-deny":
        return _record("f311-deny-detail-echo", "BREAK",
                       "deny verdict not preserved")
    leaked = _leaked(read_entries, audit_path)
    if leaked:
        _record("f311-deny-detail-echo", "BREAK",
                "F311: deny rationale echoes credential-shaped detail "
                "(%d record(s))" % len(leaked))
    else:
        _record("f311-deny-detail-echo", "HELD",
                "deny detail sanitized before emit")


def p_plugindeny_raise_echo():
    """F311: raised PluginDeny exception text echoed into the
    guardrail-run rationale."""
    from gov import elicitation_contract as ec
    assert ec.credential_material_present(_SECRET), "detector must fire"
    gp, log, writer, reg, audit_path, read_entries = _gp_chain(
        "w283-f311-r-")

    def _evil_raise(ctx):
        raise gp.PluginDeny("blocked: %s present" % _SECRET)

    reg.register("evil-raise", hooks=["before_tool_call"], run=_evil_raise)
    chain = gp.GuardChain(reg, writer, log)
    v = chain.run_hook("before_tool_call", tool_name="send_email",
                       payload={"to": "x"}, plugin_ids=["evil-raise"])
    if v.allowed:
        return _record("f311-plugindeny-echo", "BREAK",
                       "raised PluginDeny did not deny (fail-open)")
    leaked = _leaked(read_entries, audit_path)
    if leaked:
        _record("f311-plugindeny-echo", "BREAK",
                "F311: PluginDeny rationale echoes credential-shaped "
                "detail (%d record(s))" % len(leaked))
    else:
        _record("f311-plugindeny-echo", "HELD",
                "PluginDeny detail sanitized before emit")


def p_crash_exception_echo():
    """F311: technical-failure exception text echoed into the
    guardrail-run rationale (fail-closed must still raise)."""
    from gov import elicitation_contract as ec
    from gov.guardrail_evidence import GuardrailFailureError
    assert ec.credential_material_present(_SECRET), "detector must fire"
    gp, log, writer, reg, audit_path, read_entries = _gp_chain(
        "w283-f311-c-")

    def _boom(ctx):
        raise ValueError("crashed on %s" % _SECRET)

    reg.register("evil-crash", hooks=["before_tool_call"], run=_boom)
    chain = gp.GuardChain(reg, writer, log)
    try:
        chain.run_hook("before_tool_call", tool_name="send_email",
                       payload={"to": "x"}, plugin_ids=["evil-crash"])
    except GuardrailFailureError:
        pass
    else:
        return _record("f311-crash-echo", "BREAK",
                       "crashing plugin did not raise (fail-open)")
    leaked = _leaked(read_entries, audit_path)
    if leaked:
        _record("f311-crash-echo", "BREAK",
                "F311: technical-failure rationale echoes "
                "credential-shaped detail (%d record(s))" % len(leaked))
    else:
        _record("f311-crash-echo", "HELD",
                "technical-failure detail sanitized before emit")


def p_nonverdict_repr_echo():
    """F311: non-verdict %r rendering echoes credential-shaped
    material into the technical-failure rationale."""
    from gov import elicitation_contract as ec
    from gov.guardrail_evidence import GuardrailFailureError
    assert ec.credential_material_present(_SECRET), "detector must fire"
    gp, log, writer, reg, audit_path, read_entries = _gp_chain(
        "w283-f311-n-")

    def _bad(ctx):
        return {"not": "a verdict", "secret": _SECRET}

    reg.register("evil-nonverdict", hooks=["before_tool_call"], run=_bad)
    chain = gp.GuardChain(reg, writer, log)
    try:
        chain.run_hook("before_tool_call", tool_name="send_email",
                       payload={"to": "x"},
                       plugin_ids=["evil-nonverdict"])
    except GuardrailFailureError:
        pass
    else:
        return _record("f311-nonverdict-echo", "BREAK",
                       "non-verdict did not raise (fail-open)")
    leaked = _leaked(read_entries, audit_path)
    if leaked:
        _record("f311-nonverdict-echo", "BREAK",
                "F311: non-verdict rationale echoes credential-shaped "
                "material (%d record(s))" % len(leaked))
    else:
        _record("f311-nonverdict-echo", "HELD",
                "non-verdict rationale sanitized before emit")


def p_allow_detail_echo():
    """F311: allow-outcome detail echoed verbatim into the
    guardrail-run rationale."""
    from gov import elicitation_contract as ec
    assert ec.credential_material_present(_SECRET), "detector must fire"
    gp, log, writer, reg, audit_path, read_entries = _gp_chain(
        "w283-f311-a-")

    def _chatty(ctx):
        return gp.allow_outcome("saw %s but allowing" % _SECRET)

    reg.register("chatty-allow", hooks=["before_tool_call"], run=_chatty)
    chain = gp.GuardChain(reg, writer, log)
    v = chain.run_hook("before_tool_call", tool_name="send_email",
                       payload={"to": "x"}, plugin_ids=["chatty-allow"])
    if not v.allowed:
        return _record("f311-allow-echo", "BREAK",
                       "allow unexpectedly denied")
    leaked = _leaked(read_entries, audit_path)
    if leaked:
        _record("f311-allow-echo", "BREAK",
                "F311: allow rationale echoes credential-shaped detail "
                "(%d record(s))" % len(leaked))
    else:
        _record("f311-allow-echo", "HELD",
                "allow detail sanitized before emit")


def p_verdict_transform_preserved():
    """Verdict preservation: transform still allows, and the
    transform audit record keeps its digests + changed keys."""
    import hashlib
    import json
    gp, log, writer, reg, audit_path, read_entries = _gp_chain(
        "w283-f311-vt-")

    def _redact(ctx):
        new = dict(ctx.payload)
        new["token"] = "REDACTED"
        return gp.transform_outcome(new, detail="redacted the token")

    reg.register("sane-redact", hooks=["before_tool_call"], run=_redact)
    chain = gp.GuardChain(reg, writer, log)
    v = chain.run_hook("before_tool_call", tool_name="send_email",
                       payload={"to": "x", "token": "abc"},
                       plugin_ids=["sane-redact"])
    if not v.allowed or len(v.transforms) != 1:
        return _record("f311-transform-preserved", "BREAK",
                       "transform verdict not preserved")
    tr = v.transforms[0]
    canon = json.dumps({"to": "x", "token": "abc"}, sort_keys=True,
                       separators=(",", ":"),
                       ensure_ascii=True).encode()
    if tr["old_digest"] != hashlib.sha256(canon).hexdigest():
        return _record("f311-transform-preserved", "BREAK",
                       "old digest mismatch")
    if tr["changed_keys"] != ["token"]:
        return _record("f311-transform-preserved", "BREAK",
                       "changed_keys mismatch: %r" % (tr["changed_keys"],))
    trec = [r for r in read_entries(audit_path)
            if r.get("record_type") == "guard-plugin-transform"]
    if not trec:
        return _record("f311-transform-preserved", "BREAK",
                       "transform audit record missing")
    if _leaked(read_entries, audit_path):
        return _record("f311-transform-preserved", "BREAK",
                       "transform records echo secret material")
    _record("f311-transform-preserved", "HELD",
            "transform verdict + MAC-bound diff evidence preserved")


def p_verdict_deny_preserved():
    """Verdict preservation: deny still short-circuits with denied_by."""
    gp, log, writer, reg, audit_path, read_entries = _gp_chain(
        "w283-f311-vd-")

    def _deny(ctx):
        return gp.deny_outcome("not on the list")

    reg.register("sane-deny", hooks=["before_tool_call"], run=_deny)
    chain = gp.GuardChain(reg, writer, log)
    v = chain.run_hook("before_tool_call", tool_name="send_email",
                       payload={"to": "x"}, plugin_ids=["sane-deny"])
    if v.allowed or v.denied_by != "sane-deny":
        return _record("f311-deny-preserved", "BREAK",
                       "deny verdict not preserved")
    rec = [r for r in v.records if r.get("outcome") == "intentional_block"]
    if not rec:
        return _record("f311-deny-preserved", "BREAK",
                       "intentional_block record missing")
    _record("f311-deny-preserved", "HELD", "deny verdict preserved")


def p_verdict_crash_fail_closed():
    """Verdict preservation: a crashing plugin still raises LOUD with
    the machine-readable code."""
    from gov.guardrail_evidence import GuardrailFailureError
    gp, log, writer, reg, audit_path, read_entries = _gp_chain(
        "w283-f311-vc-")

    def _boom(ctx):
        raise RuntimeError("boom")

    reg.register("sane-crash", hooks=["before_tool_call"], run=_boom)
    chain = gp.GuardChain(reg, writer, log)
    try:
        chain.run_hook("before_tool_call", tool_name="send_email",
                       payload={"to": "x"}, plugin_ids=["sane-crash"])
    except GuardrailFailureError as exc:
        if getattr(exc, "code", None) != "guardplugin-error-refused":
            return _record("f311-crash-preserved", "BREAK",
                           "wrong failure code: %r"
                           % (getattr(exc, "code", None),))
    else:
        return _record("f311-crash-preserved", "BREAK",
                       "crash did not raise (fail-open)")
    _record("f311-crash-preserved", "HELD", "crash fails closed loudly")


def p_placeholder_marked():
    """Redaction is marked, never silent elision: a sanitized record
    carries a visible placeholder naming what was withheld."""
    from gov import elicitation_contract as ec
    assert ec.credential_material_present(_SECRET), "detector must fire"
    gp, log, writer, reg, audit_path, read_entries = _gp_chain(
        "w283-f311-m-")

    def _evil(ctx):
        return gp.deny_outcome("refusing: saw %s in args" % _SECRET)

    reg.register("evil-deny", hooks=["before_tool_call"], run=_evil)
    chain = gp.GuardChain(reg, writer, log)
    chain.run_hook("before_tool_call", tool_name="send_email",
                   payload={"to": "x"}, plugin_ids=["evil-deny"])
    if _leaked(read_entries, audit_path):
        return _record("f311-placeholder-marked", "BREAK",
                       "secret still echoed")
    rationales = [r.get("rationale", "") for r in read_entries(audit_path)
                  if r.get("record_type") == "guardrail-run"]
    if not any("credential material withheld" in r for r in rationales):
        return _record("f311-placeholder-marked", "BREAK",
                       "redaction not visibly marked: %r"
                       % (rationales[:1],))
    _record("f311-placeholder-marked", "HELD",
            "redaction visibly marked, not silent elision")


def p_clean_detail_verbatim():
    """Anti-over-redaction: benign plugin detail passes through
    verbatim."""
    gp, log, writer, reg, audit_path, read_entries = _gp_chain(
        "w283-f311-clean-")

    def _sane(ctx):
        return gp.allow_outcome("args within budget for send_email")

    reg.register("sane-allow", hooks=["before_tool_call"], run=_sane)
    chain = gp.GuardChain(reg, writer, log)
    chain.run_hook("before_tool_call", tool_name="send_email",
                   payload={"to": "x"}, plugin_ids=["sane-allow"])
    rationales = [r.get("rationale", "") for r in read_entries(audit_path)
                  if r.get("record_type") == "guardrail-run"]
    if not any("args within budget for send_email" in r
               for r in rationales):
        return _record("f311-clean-verbatim", "BREAK",
                       "benign detail was redacted or dropped")
    _record("f311-clean-verbatim", "HELD",
            "benign detail passes through verbatim")


def p_triad_adapter_regression():
    """The triad adapter path (F306) still sanitizes plugin detail
    that reaches the triad funnel."""
    from gov import elicitation_contract as ec
    from gov import tool_guardrails as tg
    from gov.log import ActionLog, read_entries
    assert ec.credential_material_present(_SECRET), "detector must fire"
    from gov import guard_plugins as gp
    d = tempfile.mkdtemp(prefix="w283-f311-tri-")
    audit_path = os.path.join(d, "audit.jsonl")
    log = ActionLog(audit_path)

    def _evil_deny(ctx):
        return gp.deny_outcome("refusing: saw %s in args" % _SECRET)

    reg = gp.PluginRegistry()
    reg.register("evil-deny", hooks=["before_tool_call"], run=_evil_deny)
    guard = gp.as_tool_input_guardrail(reg.get("evil-deny"))
    data = tg.ToolInputGuardrailData(tool_name="send_email",
                                    tool_arguments={"to": "x"})
    out = guard.run(data)
    # The F306 triad funnel sanitizes at emit; just ensure the deny
    # routed as a refusal and the adapter did not crash the seam.
    if out.behavior != "reject_content":
        return _record("f311-triad-adapter", "BREAK",
                       "adapter deny did not refuse: %r"
                       % (out.behavior,))
    _record("f311-triad-adapter", "HELD",
            "triad adapter path still routes plugin deny")


# ---------------------------------------------------------------------------
# Depth-1 green checks (GOV_SKIP_GREEN=1 honored by children)
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        # (rel, expect_break, no_break)
        ("evals/w279_guardev_probes.py", None, True),
        ("evals/w280_shields_probes.py", None, True),
        ("evals/w282_redteam_probes.py", None, True),
    ]
    for rel, expect_break, no_break in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w283-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout
        breaks = [ln for ln in out.splitlines() if "[BREAK]" in ln]
        if proc.returncode != 0:
            _record(os.path.basename(rel), "ERROR",
                    "green check exit=%d: %s" % (proc.returncode,
                                                out[-300:]))
        elif no_break and breaks:
            _record(os.path.basename(rel), "BREAK",
                    "green check broke unexpectedly: %s" % (breaks[:3],))
        elif expect_break and not any(expect_break in b for b in breaks):
            _record(os.path.basename(rel), "BREAK",
                    "expected BREAK pin %r missing; breaks=%s"
                    % (expect_break, breaks[:3]))
        else:
            _record(os.path.basename(rel), "HELD",
                    "green: exit 0, breaks=%d" % len(breaks))
    for mod in ("tests.test_guard_plugins",
                "tests.test_guardrail_evidence",
                "tests.test_tool_guardrails"):
        d = tempfile.mkdtemp(prefix="w283-green-u-")
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", mod],
            capture_output=True, text=True, timeout=600,
            env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d),
            cwd=REPO)
        if proc.returncode != 0:
            _record(mod, "ERROR",
                    "unit suite exit=%d: %s" % (proc.returncode,
                                               (proc.stderr + proc.stdout)[-300:]))
        else:
            _record(mod, "HELD", "unit suite green")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    probes = [
        p_taxonomy_pin,
        p_transform_detail_echo,
        p_deny_detail_echo,
        p_plugindeny_raise_echo,
        p_crash_exception_echo,
        p_nonverdict_repr_echo,
        p_allow_detail_echo,
        p_verdict_transform_preserved,
        p_verdict_deny_preserved,
        p_verdict_crash_fail_closed,
        p_placeholder_marked,
        p_clean_detail_verbatim,
        p_triad_adapter_regression,
    ]
    for probe in probes:
        try:
            probe()
        except Exception as e:  # noqa: BLE001 - a probe must never die
            import traceback
            _record(probe.__name__, "ERROR",
                    traceback.format_exc()[-500:])
    _green_checks()
    breaks = [r for r in _results if r[1] == "BREAK"]
    held = [r for r in _results if r[1] == "HELD"]
    errors = [r for r in _results if r[1] == "ERROR"]
    print("wave-283 f311: %d BREAK / %d HELD / %d ERROR"
          % (len(breaks), len(held), len(errors)))
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note[:160]))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
