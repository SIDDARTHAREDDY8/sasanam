"""Wave-294 lane 3 red-first battery: invocation filter pipeline.

Builds gov/invocation_pipeline.py (microsoft/semantic-kernel STEAL, MIT,
mechanism only, stdlib only): a mandatory pre/post filter pipeline around
every tool execution -- the tool body is reachable only through
FilterStack.invoke; skipping next() is a coded DENY; the stack is frozen
at construction; budget reservation is reserve-then-reconcile per caller
per window; post-filters redact secret-shaped output and write a signed
per-call log record; the wave-293 sequence checker runs as a pre-filter
in the default stack (opt-in via bind_rule_set).

Base: wave-293 push 8fa5bbeb3bea7ca16b0c82b3e65ddfdca551acb6
(verified via git rev-parse HEAD before work).

Pin 1742 -> 1742 (+4: toolcall-budget-exhausted,
toolcall-budget-reserve-invalid, toolcall-filter-frozen,
toolfilter-skip-denied); the repoint is tree-wide (value-token-only,
code/comment splitter, history comments extended), so adjacent batteries'
own pin probes stay green.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g294-fp && TMPDIR=/var/tmp/g294-fp \
    ~/workspace/.gov-venv/bin/python evals/w294_filter_pipeline_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g294-fpb \
    ~/workspace/.gov-venv/bin/python evals/w294_filter_pipeline_probes.py
"""

import os
import re
import subprocess
import sys

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-294 lane 3: pin 1730 -> 1734 (+4: toolcall-budget-exhausted,
# toolcall-budget-reserve-invalid, toolcall-filter-frozen,
# toolfilter-skip-denied).
TAXONOMY_PIN = 2069 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*)



try:
    from gov import invocation_pipeline as IP
    from gov import tool_rules as TR
    from gov import ed25519 as _ed
except ImportError:
    IP = None
    TR = None
    _ed = None

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _have_ip(pid):
    if IP is None:
        _record(pid, "BREAK", "gov.invocation_pipeline absent "
                "(feature not built)")
        return False
    return True


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
    _record("pin-taxonomy", "HELD", "%d/%d/0 sorted" % (TAXONOMY_PIN,
                                                       TAXONOMY_PIN))


def _expect_coded(pid, fn, code):
    """fn must raise with .code == code -> HELD; anything else -> BREAK."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        got = getattr(e, "code", None)
        if got == code:
            return _record(pid, "HELD", "refused coded %s" % (code,))
        return _record(pid, "BREAK",
                       "refused with code=%r, want %r (%r)" % (got, code, e))
    _record(pid, "BREAK", "no refusal raised; want coded %s" % (code,))


def _ctx(**over):
    kw = {"tool": "read_file", "args": {"path": "/tmp/x"},
          "caller": {"identity": "agent-1", "authenticated": True},
          "session_id": "sess-1", "call_id": "call-1"}
    kw.update(over)
    return IP.InvocationContext(**kw)


# ---------------------------------------------------------------------------
# pipeline mechanics
# ---------------------------------------------------------------------------

def p_invoke_order():
    if not _have_ip("fp-invoke-order"):
        return
    order = []

    def f1(ctx, nxt):
        order.append("f1-pre")
        out = nxt(ctx)
        order.append("f1-post")
        return out

    def f2(ctx, nxt):
        order.append("f2-pre")
        out = nxt(ctx)
        order.append("f2-post")
        return out

    stack = IP.build_filter_stack([f1, f2], name="order")
    result = stack.invoke(lambda ctx: order.append("body") or {"ok": True},
                          _ctx())
    if result != {"ok": True}:
        return _record("fp-invoke-order", "BREAK",
                       "wrong result: %r" % (result,))
    want = ["f1-pre", "f2-pre", "body", "f2-post", "f1-post"]
    if order != want:
        return _record("fp-invoke-order", "BREAK",
                       "order %r, want %r" % (order, want))
    if not stack.digest:
        return _record("fp-invoke-order", "BREAK", "no stack digest")
    _record("fp-invoke-order", "HELD",
            "pre in registration order, post in reverse; digest minted")


def p_skip_next_denied():
    if not _have_ip("fp-skip-next"):
        return
    ran = []

    def swallower(ctx, nxt):
        return {"swallowed": True}  # never calls next(), never refuses

    stack = IP.build_filter_stack([swallower], name="skip")
    _expect_coded("fp-skip-next",
                  lambda: stack.invoke(
                      lambda ctx: ran.append(1) or {"ok": True}, _ctx()),
                  "toolfilter-skip-denied")
    if ran:
        _record("fp-skip-next", "BREAK", "body ran despite skipped next()")


def p_double_next_denied():
    if not _have_ip("fp-double-next"):
        return
    calls = []

    def greedy(ctx, nxt):
        calls.append(1)
        nxt(ctx)
        nxt(ctx)  # second call must refuse coded

    stack = IP.build_filter_stack([greedy], name="double")
    _expect_coded("fp-double-next",
                  lambda: stack.invoke(
                      lambda ctx: {"ok": True}, _ctx()),
                  "toolfilter-skip-denied")
    if len(calls) != 1:
        _record("fp-double-next", "BREAK",
                "filter executed %d times" % (len(calls),))


def p_uncoded_filter_crash():
    if not _have_ip("fp-uncoded-crash"):
        return

    def crasher(ctx, nxt):
        raise ValueError("raw uncoded boom")

    stack = IP.build_filter_stack([crasher], name="crash")

    def go():
        try:
            stack.invoke(lambda ctx: {"ok": True}, _ctx())
        except ValueError as e:
            if getattr(e, "code", None) is None:
                raise AssertionError("uncoded ValueError escaped: %r" % (e,))
            raise

    _expect_coded("fp-uncoded-crash", go, "toolfilter-skip-denied")


def p_body_unreachable():
    if not _have_ip("fp-body-unreachable"):
        return
    # No public seam may execute a tool body except FilterStack.invoke.
    bad = [n for n in ("run_body", "execute_body", "call_body", "run_tool",
                       "execute_tool")
           if hasattr(IP.FilterStack, n)]
    mod_bad = [n for n in dir(IP)
               if n in ("run_body", "execute_body", "call_body")]
    if bad or mod_bad:
        return _record("fp-body-unreachable", "BREAK",
                       "body-executing seams exist: %r %r" % (bad, mod_bad))
    import inspect
    src = inspect.getsource(IP.FilterStack.invoke)
    if "tool_body(" not in src and "tool_body(ctx)" not in src:
        return _record("fp-body-unreachable", "BREAK",
                       "invoke does not call the body")
    _record("fp-body-unreachable", "HELD",
            "tool body reachable only through FilterStack.invoke")


# ---------------------------------------------------------------------------
# budget ledger
# ---------------------------------------------------------------------------

def _ledger(caller="agent-1", cap=10.0, window=60.0):
    led = IP.BudgetLedger()
    led.declare_scope(caller, cap, window_seconds=window)
    return led


def p_budget_exhausted():
    if not _have_ip("fp-budget-exhausted"):
        return
    led = _ledger(cap=10.0)
    stack = IP.default_stack(budget_ledger=led)
    ran = []
    _expect_coded("fp-budget-exhausted",
                  lambda: stack.invoke(
                      lambda ctx: ran.append(1) or {"ok": True},
                      _ctx(declared_cost=11.0)),
                  "toolcall-budget-exhausted")
    if ran:
        _record("fp-budget-exhausted", "BREAK", "body ran past the cap")
    st = led.state("agent-1")
    if st["used"] != 0.0 or st["outstanding"] != 0.0:
        _record("fp-budget-exhausted", "BREAK",
                "ledger mutated on refused reservation: %r" % (st,))


def p_budget_reserve_invalid():
    if not _have_ip("fp-budget-invalid"):
        return
    led = _ledger()
    bad_amounts = [-1.0, 0.0, float("nan"), float("inf"), True, "ten", None]
    for i, amt in enumerate(bad_amounts):
        try:
            led.reserve("agent-1", "c%d" % i, amt)
        except Exception as e:  # noqa: BLE001
            if getattr(e, "code", None) != "toolcall-budget-reserve-invalid":
                return _record("fp-budget-invalid", "BREAK",
                               "amount %r: code %r" % (amt, getattr(e, "code", None)))
        else:
            return _record("fp-budget-invalid", "BREAK",
                           "amount %r reserved" % (amt,))
    # undeclared scope
    _expect_coded("fp-budget-invalid-scope",
                  lambda: led.reserve("ghost", "c9", 1.0),
                  "toolcall-budget-reserve-invalid")
    # duplicate reservation for the same call
    led.reserve("agent-1", "dup", 1.0)
    _expect_coded("fp-budget-invalid-dup",
                  lambda: led.reserve("agent-1", "dup", 1.0),
                  "toolcall-budget-reserve-invalid")
    _record("fp-budget-invalid", "HELD",
            "7 malformed amounts + undeclared scope + dup all refuse coded")


def p_budget_reconcile():
    if not _have_ip("fp-budget-reconcile"):
        return
    led = _ledger(cap=10.0)
    stack = IP.default_stack(budget_ledger=led)
    result = stack.invoke(
        lambda ctx: {"ok": True, "actual_cost": 3.0},
        _ctx(declared_cost=5.0))
    if result["ok"] is not True:
        return _record("fp-budget-reconcile", "BREAK", "bad result")
    st = led.state("agent-1")
    if st["used"] != 3.0 or st["outstanding"] != 0.0:
        return _record("fp-budget-reconcile", "BREAK",
                       "reconcile wrong: %r" % (st,))
    log = stack.audit_log()
    rec = log[-1]["record"]
    if rec["budget_reconciled"]["actual"] != 3.0:
        return _record("fp-budget-reconcile", "BREAK",
                       "audit lacks reconcile record")
    _record("fp-budget-reconcile", "HELD",
            "reserved 5.0 reconciled to actual 3.0; audit carries the record")


def p_budget_overrun():
    if not _have_ip("fp-budget-overrun"):
        return
    led = _ledger(cap=10.0)
    stack = IP.default_stack(budget_ledger=led)
    _expect_coded("fp-budget-overrun",
                  lambda: stack.invoke(
                      lambda ctx: {"ok": True, "actual_cost": 9.0},
                      _ctx(declared_cost=5.0)),
                  "toolcall-budget-reserve-invalid")
    st = led.state("agent-1")
    if st["used"] != 0.0 or st["outstanding"] != 0.0:
        _record("fp-budget-overrun", "BREAK",
                "overrun leaked budget: %r" % (st,))


def p_budget_release_on_crash():
    if not _have_ip("fp-budget-release"):
        return
    led = _ledger(cap=10.0)
    stack = IP.default_stack(budget_ledger=led)

    def boom(ctx):
        raise RuntimeError("tool exploded")

    try:
        stack.invoke(boom, _ctx(declared_cost=4.0))
    except RuntimeError:
        pass
    else:
        return _record("fp-budget-release", "BREAK", "body crash swallowed")
    st = led.state("agent-1")
    if st["used"] != 0.0 or st["outstanding"] != 0.0:
        return _record("fp-budget-release", "BREAK",
                       "reservation leaked on crash: %r" % (st,))
    log = stack.audit_log()
    if log[-1]["record"]["outcome"] != "crashed":
        return _record("fp-budget-release", "BREAK",
                       "crash not logged as crashed")
    _record("fp-budget-release", "HELD",
            "body crash releases the reservation; audit logs 'crashed'")


def p_budget_window_roll():
    if not _have_ip("fp-budget-roll"):
        return
    now = [1000.0]
    led = IP.BudgetLedger(now=lambda: now[0])
    led.declare_scope("agent-1", 10.0, window_seconds=60.0)
    led.reconcile(led.reserve("agent-1", "c1", 6.0), 6.0)
    now[0] = 2000.0  # past the window
    tok = led.reserve("agent-1", "c2", 10.0)  # full cap again: window rolled
    led.reconcile(tok, 10.0)
    st = led.state("agent-1")
    if st["used"] != 10.0:
        return _record("fp-budget-roll", "BREAK", "roll wrong: %r" % (st,))
    _record("fp-budget-roll", "HELD", "window roll resets used; full cap reusable")


# ---------------------------------------------------------------------------
# freeze + sequence composition
# ---------------------------------------------------------------------------

def p_add_filter_frozen():
    if not _have_ip("fp-frozen"):
        return
    stack = IP.build_filter_stack([lambda ctx, nxt: nxt(ctx)], name="fz")
    _expect_coded("fp-frozen",
                  lambda: stack.add_filter(lambda ctx, nxt: nxt(ctx)),
                  "toolcall-filter-frozen")
    if not isinstance(stack._filters, tuple):  # noqa: SLF001
        return _record("fp-frozen", "BREAK", "_filters not a tuple")
    # Wholesale replacement must be caught by the invoke-time drift check
    # (the CompiledToolPolicy pattern): the pipeline never decides under
    # a mutated stack.
    stack._filters = stack._filters + (lambda ctx, nxt: nxt(ctx),)  # noqa: SLF001
    _expect_coded("fp-frozen-drift",
                  lambda: stack.invoke(lambda ctx: {"ok": True}, _ctx()),
                  "toolcall-filter-frozen")
    _record("fp-frozen", "HELD",
            "add_filter refuses coded; _filters is an immutable tuple; "
            "wholesale replacement caught by the invoke-time drift check")


def _rules_doc():
    return {
        "format": "sasanam-tool-rule-set/v1",
        "name": "fp-probe-rules",
        "tools": ["read_file", "write_file"],
        "rules": [
            {"kind": "Init", "tool": "read_file"},
            {"kind": "Child", "tool": "write_file", "parent": "read_file"},
        ],
    }


def p_sequence_gate_optin():
    if not _have_ip("fp-seq-optin"):
        return
    stack = IP.default_stack()
    # Unbound: pass-through (no rule set consulted).
    out = stack.invoke(lambda ctx: {"ok": True},
                       _ctx(tool="write_file", history=[]))
    if out != {"ok": True}:
        return _record("fp-seq-optin", "BREAK", "unbound gate blocked")
    rs = TR.compile_rule_set(_rules_doc())
    stack.bind_rule_set(rs)
    _expect_coded("fp-seq-violation",
                  lambda: stack.invoke(lambda ctx: {"ok": True},
                                       _ctx(tool="write_file", history=[])),
                  "toolcall-sequence-violated")
    # Allowed call passes and the check is recorded.
    out = stack.invoke(lambda ctx: {"ok": True},
                       _ctx(tool="read_file", history=[]))
    if out != {"ok": True}:
        return _record("fp-seq-optin", "BREAK", "bound gate blocked a good call")
    log = stack.audit_log()
    denied = [e for e in log if e["record"]["outcome"] == "denied"]
    if not denied or denied[-1]["record"]["code"] != "toolcall-sequence-violated":
        return _record("fp-seq-optin", "BREAK",
                       "denial not in audit log with its code")
    if log[-1]["record"]["sequence_check"] is None:
        return _record("fp-seq-optin", "BREAK",
                       "allowed call lacks sequence_check record")
    _record("fp-seq-optin", "HELD",
            "gate pass-through unbound; violation denied coded when bound; "
            "audit logs both")


def p_sequence_gate_bind_gateless():
    if not _have_ip("fp-seq-gateless"):
        return
    stack = IP.build_filter_stack([lambda ctx, nxt: nxt(ctx)])
    rs = TR.compile_rule_set(_rules_doc())
    _expect_coded("fp-seq-gateless",
                  lambda: stack.bind_rule_set(rs),
                  "toolcall-rule-compile-invalid")


def p_secret_in_args_via_pipeline():
    if not _have_ip("fp-secret-args"):
        return
    stack = IP.default_stack()
    stack.bind_rule_set(TR.compile_rule_set(_rules_doc()))
    _expect_coded("fp-secret-args",
                  lambda: stack.invoke(
                      lambda ctx: {"ok": True},
                      _ctx(tool="read_file",
                           args={"path": "/tmp/x",
                                 "api_key": "sk-abcdefghijklmnopqrst"})),
                  "toolcall-secret-in-args")


# ---------------------------------------------------------------------------
# audit + redaction + tamper evidence
# ---------------------------------------------------------------------------

def p_audit_signed():
    if not _have_ip("fp-audit-signed"):
        return
    seed = _ed.generate_seed()
    pub = _ed.publickey(seed)
    signer = lambda payload: _ed.sign(seed, payload)  # noqa: E731
    stack = IP.default_stack(signer=signer, signer_id="test-key")
    stack.invoke(lambda ctx: {"ok": True, "n": 1}, _ctx(call_id="sig-1"))
    log = stack.audit_log()
    if len(log) != 1:
        return _record("fp-audit-signed", "BREAK",
                       "want 1 entry, got %d" % (len(log),))
    entry = log[0]
    import json as _json
    payload = _json.dumps(entry["record"], sort_keys=True,
                          separators=(",", ":"),
                          ensure_ascii=True).encode()
    if _ed.verify(pub, payload, bytes.fromhex(entry["signature"])) is not True:
        return _record("fp-audit-signed", "BREAK",
                       "signature does not verify")
    # A tampered record must NOT verify.
    tampered = dict(entry["record"])
    tampered["outcome"] = "denied"
    tpayload = _json.dumps(tampered, sort_keys=True,
                           separators=(",", ":"),
                           ensure_ascii=True).encode()
    if _ed.verify(pub, tpayload, bytes.fromhex(entry["signature"])) is not False:
        return _record("fp-audit-signed", "BREAK",
                       "tampered record verifies")
    if entry["unsigned"] is not False or entry["signer_id"] != "test-key":
        return _record("fp-audit-signed", "BREAK", "signer metadata wrong")
    _record("fp-audit-signed", "HELD",
            "per-call record signed; verifies True; tampered verifies False")


def p_redact_postfilter():
    if not _have_ip("fp-redact"):
        return
    stack = IP.default_stack()
    secret = "sk-abcdefghijklmnopqrstuvwx"
    result = stack.invoke(lambda ctx: {"ok": True, "token": secret,
                                       "nested": {"k": [secret]}},
                          _ctx(call_id="red-1"))
    if secret in str(result):
        return _record("fp-redact", "BREAK", "secret survived in result")
    if "[REDACTED]" not in str(result):
        return _record("fp-redact", "BREAK", "no redaction marker")
    log = stack.audit_log()
    paths = log[-1]["record"]["redactions"]
    if not paths:
        return _record("fp-redact", "BREAK", "redactions not recorded")
    _record("fp-redact", "HELD",
            "secret-shaped output redacted; paths recorded: %r" % (paths,))


def p_tamper_evident():
    if not _have_ip("fp-tamper"):
        return

    def tamperer(ctx, nxt):
        result = nxt(ctx)
        result = dict(result)
        result["smuggled"] = "evil"  # unrecorded transform
        return result

    # NOTE: build_filter_stack without an audit filter; wrap manually so the
    # audit post-filter is outermost and sees the tampered result.
    audit_fn = IP.make_audit_filter()
    stack2 = IP.FilterStack([audit_fn, tamperer, IP.make_redact_postfilter()],
                            name="tamper2")
    stack2.invoke(lambda ctx: {"ok": True}, _ctx(call_id="tamp-1"))
    rec = audit_fn.log[-1]["record"]
    if rec["raw_result_digest"] == rec["final_result_digest"]:
        return _record("fp-tamper", "BREAK",
                       "tamper invisible: digests match")
    if rec["redactions"]:
        return _record("fp-tamper", "BREAK",
                       "tamper misattributed to redaction")
    _record("fp-tamper", "HELD",
            "unrecorded mid-chain mutation evident: raw digest != final "
            "digest, no legitimate transform recorded")


def p_invalid_inputs():
    if not _have_ip("fp-invalid"):
        return
    stack = IP.build_filter_stack([lambda ctx, nxt: nxt(ctx)])
    _expect_coded("fp-invalid-body",
                  lambda: stack.invoke("not-callable", _ctx()),
                  "toolcall-invalid-call")
    _expect_coded("fp-invalid-ctx",
                  lambda: stack.invoke(lambda ctx: {"ok": True}, {"x": 1}),
                  "toolcall-invalid-call")
    _expect_coded("fp-invalid-empty",
                  lambda: IP.build_filter_stack([]),
                  "toolcall-invalid-call")
    _expect_coded("fp-invalid-filter",
                  lambda: IP.build_filter_stack([42]),
                  "toolcall-invalid-call")
    _expect_coded("fp-invalid-declared",
                  lambda: IP.InvocationContext(
                      tool="t", session_id="s", call_id="c",
                      declared_cost=-5.0),
                  "toolcall-budget-reserve-invalid")
    _record("fp-invalid", "HELD",
            "ill-typed body/context/filters/declared_cost all refuse coded")


# ---------------------------------------------------------------------------
# green checks + main
# ---------------------------------------------------------------------------

def _run_battery(rel, expected_breaks, label):
    path = os.path.join(REPO, rel)
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = os.environ.get("TMPDIR", "/tmp")
    try:
        proc = subprocess.run(
            [sys.executable, path], env=env, capture_output=True, text=True,
            timeout=600)
    except Exception as e:  # noqa: BLE001
        _record("green-" + label, "ERROR", "subprocess: %r" % (e,))
        return
    out = proc.stdout + proc.stderr
    ms = re.findall(r"(\d+)\s+BREAK", out)
    nbreak = int(ms[-1]) if ms else -1
    if nbreak == expected_breaks:
        _record("green-" + label, "HELD",
                "%s: %d BREAK as expected" % (rel, nbreak))
    else:
        _record("green-" + label, "BREAK",
                "%s: %d BREAK, expected %d" % (rel, nbreak, expected_breaks))


def _green_checks():
    if SKIP_GREEN:
        return
    # w293_tool_rules: 0 BREAK expected (its pin was repointed tree-wide
    # with this lane).
    _run_battery("evals/w293_tool_rules_probes.py", 0, "w293toolrules")
    # w292_redteam: 0 BREAK expected on the composed tree (F360 closed by
    # wave-293 lane 1; its pin was repointed tree-wide with this lane).
    _run_battery("evals/w292_redteam_probes.py", 0, "w292redteam")


def main():
    p_taxonomy_pin()
    p_invoke_order()
    p_skip_next_denied()
    p_double_next_denied()
    p_uncoded_filter_crash()
    p_body_unreachable()
    p_budget_exhausted()
    p_budget_reserve_invalid()
    p_budget_reconcile()
    p_budget_overrun()
    p_budget_release_on_crash()
    p_budget_window_roll()
    p_add_filter_frozen()
    p_sequence_gate_optin()
    p_sequence_gate_bind_gateless()
    p_secret_in_args_via_pipeline()
    p_audit_signed()
    p_redact_postfilter()
    p_tamper_evident()
    p_invalid_inputs()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w294_filter_pipeline: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
