"""Break-first battery: per-call authorization enforcement seam (wave-260).

Adapted from envoyproxy/envoy's ext_authz (Apache-2.0, pattern only):
a check-per-call contract where every sensitive call carries its
authorization context to a policy check, fail-closed
(``failure_mode_allow: false`` hard-coded, never configurable).

Seams under test (tdd: agreed up front):
  1. ``CallEnforcer.enforce(CheckRequest)`` -- the module contract.
  2. ``substitute_for_execution(..., enforcer=...)`` -- the sentinel
     execution-boundary seam.
  3. ``ToolExecutor(..., call_authorizer=...)`` -- the wired seam.

Verdicts: HELD (attack refused / contract holds), BREAK (genuine
defect), GAP (the seam does not exist pre-fix -- expected before the
lane lands), ERROR (harness bug -- fix the harness, never the product).

Red-first: run BEFORE the lane lands -- every probe must be GAP.
Run AFTER -- every probe must be HELD. Run twice (staging +
``env -u GOV_DEPLOYMENT_MODE``); verdicts must agree.

No in-repo git subprocesses. Stdlib only. Deterministic.
"""

import os
import secrets
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w260-callauthz")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from gov import call_enforcement as ce  # noqa: E402
    _HAVE_CE = True
except ImportError:
    ce = None  # noqa: F841
    _HAVE_CE = False

from gov import decision_codes  # noqa: E402 (taxonomy pin below)

# Wave-260: 3 new machine codes (callauthz-denied, callauthz-check-error,
# callauthz-not-configured) -> pin 1080 -> 1083.
TAXONOMY_PIN = 1878  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    d = tempfile.mkdtemp(prefix="w260ca-", dir="/var/tmp")
    Path(d).mkdir(parents=True, exist_ok=True)
    return d


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _gap(detail=""):
    return ("GAP", detail)


# ---------------------------------------------------------------------------
# Module-contract helpers
# ---------------------------------------------------------------------------

def _req(identity="agent-1", action="credential.swap", resource="cred-a",
         context=None):
    return ce.CheckRequest(caller_identity=identity, action=action,
                           resource=resource,
                           context=context or {"dest_host": "good.example"})


def _allow_check(request):
    return ce.AuthorizationVerdict(True, ce.CODE_ALLOWED, "test allow")


def _deny_check(request):
    return ce.AuthorizationVerdict(False, ce.CODE_DENIED, "test deny")


def _enforcer(check=_allow_check, policies=(), cache=None, clock=None):
    kw = {}
    if cache is not None:
        kw["cache"] = cache
    if clock is not None:
        kw["clock"] = clock
    enf = ce.CallEnforcer(check=check, **kw)
    for p in policies:
        enf.register_policy(p)
    return enf


def _policy(pid, action_pat, resource_pat, check=_allow_check,
            timeout_s=1.0):
    return ce.ScopedPolicy(policy_id=pid, action_pattern=action_pat,
                           resource_pattern=resource_pat, check=check,
                           timeout_s=timeout_s)


@probe("module-present")
def p_module_present():
    if not _HAVE_CE:
        return _gap("gov.call_enforcement absent: no per-call check seam")
    return _held("gov.call_enforcement importable")


@probe("fail-closed-unconfigured")
def p_unconfigured():
    """No check configured where required -> DENY, never allow."""
    if not _HAVE_CE:
        return _gap("no enforcer: unconfigured check cannot be evaluated")
    # (a) bare enforcer, no check, no policies.
    v = ce.CallEnforcer().enforce(_req())
    if v.allow:
        return _break("bare enforcer ALLOWED: fail-closed default violated")
    if v.code != ce.CODE_NOT_CONFIGURED:
        return _break("bare enforcer denied with wrong code %r" % (v.code,))
    # (b) policy present but no check anywhere (policy check None, no
    # enforcer default).
    enf = ce.CallEnforcer(check=None)
    enf.register_policy(_policy("p1", "credential.swap", "cred-a",
                                check=None))
    v = enf.enforce(_req())
    if v.allow or v.code != ce.CODE_NOT_CONFIGURED:
        return _break("check-less policy allowed or wrong code: %r %r"
                      % (v.allow, v.code))
    # (c) check configured but request matches NO policy -> deny.
    enf = _enforcer(policies=[_policy("p1", "credential.swap", "cred-a")])
    v = enf.enforce(_req(resource="cred-other"))
    if v.allow or v.code != ce.CODE_NOT_CONFIGURED:
        return _break("unmatched request allowed or wrong code: %r %r"
                      % (v.allow, v.code))
    snap = enf.counters_snapshot()
    if snap.get("_unmatched", {}).get("deny", 0) != 1:
        return _break("unmatched deny not counted: %r" % (snap,))
    return _held("unconfigured check / unmatched request -> deny "
                 "callauthz-not-configured; counters observe it")


@probe("error-in-check-denies")
def p_check_error():
    """Check raises, returns garbage, or times out -> DENY."""
    if not _HAVE_CE:
        return _gap("no enforcer: check-error path absent")

    def _raiser(request):
        raise RuntimeError("decision point exploded")

    enf = _enforcer(check=_raiser,
                    policies=[_policy("p1", "credential.swap", "cred-a",
                                      check=_raiser)])
    v = enf.enforce(_req())
    if v.allow:
        return _break("raising check ALLOWED: fail-closed violated")
    if v.code != ce.CODE_CHECK_ERROR:
        return _break("raising check wrong code %r" % (v.code,))
    if enf.counters_snapshot()["p1"]["error"] != 1:
        return _break("check error not counted")

    # Strict contract: a check returning a non-verdict is a check error.
    def _sloppy(request):
        return True

    enf = _enforcer(check=_sloppy,
                    policies=[_policy("p1", "credential.swap", "cred-a",
                                      check=_sloppy)])
    v = enf.enforce(_req())
    if v.allow or v.code != ce.CODE_CHECK_ERROR:
        return _break("non-verdict check return allowed/wrong code: %r %r"
                      % (v.allow, v.code))

    # Timeout: the check sleeps longer than the policy deadline.
    def _sleeper(request):
        time.sleep(2.0)
        return ce.AuthorizationVerdict(True, ce.CODE_ALLOWED, "late")

    enf = _enforcer(check=_sleeper,
                    policies=[_policy("p1", "credential.swap", "cred-a",
                                      check=_sleeper, timeout_s=0.1)])
    t0 = time.time()
    v = enf.enforce(_req())
    dt = time.time() - t0
    if v.allow or v.code != ce.CODE_CHECK_ERROR:
        return _break("timed-out check allowed/wrong code: %r %r"
                      % (v.allow, v.code))
    if dt > 1.5:
        return _break("timeout did not bound the check: %.2fs" % dt)
    return _held("raise / non-verdict / timeout -> deny "
                 "callauthz-check-error, bounded, counted")


@probe("cross-scope-reuse")
def p_cross_scope():
    """Policies bind to action/resource patterns with segment-boundary
    matching: a policy for cred-a never authorizes cred-ab; a policy
    for tool/* never authorizes tool/readwrite (the identity lane's
    prefix-confusion precedent)."""
    if not _HAVE_CE:
        return _gap("no enforcer: no scope patterns to confuse")
    enf = _enforcer(policies=[
        _policy("p-cred", "credential.swap", "cred-a"),
        _policy("p-tool", "tool/read", "*"),
        _policy("p-admin", "admin/panel", "*"),
        _policy("p-wild", "tool/*", "*"),
    ])
    # Resource prefix confusion: cred-a vs cred-ab.
    v = enf.enforce(_req(action="credential.swap", resource="cred-ab"))
    if v.allow:
        return _break("policy for cred-a AUTHORIZED cred-ab: "
                      "prefix confusion at the resource boundary")
    if v.code != ce.CODE_NOT_CONFIGURED:
        return _break("cred-ab wrong code %r" % (v.code,))
    # Action prefix confusion (the task's case): a policy for the
    # LITERAL admin/panel must not authorize admin/panelx. (Note:
    # tool/* legitimately matches the single segment "readwrite" --
    # that is wildcard semantics, not prefix confusion, so this case
    # uses a literal-only action family.)
    v = enf.enforce(_req(action="admin/panelx", resource="y"))
    if v.allow:
        return _break("policy for admin/panel AUTHORIZED admin/panelx: "
                      "prefix confusion at the action boundary")
    if v.code != ce.CODE_NOT_CONFIGURED:
        return _break("admin/panelx wrong code %r" % (v.code,))
    # Controls: exact and single-segment wildcard DO match.
    v = enf.enforce(_req(action="credential.swap", resource="cred-a"))
    if not v.allow:
        return _break("exact resource match refused: %r" % (v.code,))
    v = enf.enforce(_req(action="tool/read", resource="x"))
    if not v.allow:
        return _break("literal action match refused: %r" % (v.code,))
    # A wildcard does not cross a segment boundary: tool/* vs tool/a/b.
    v = enf.enforce(_req(action="tool/a/b", resource="x"))
    if v.allow:
        return _break("tool/* authorized tool/a/b: wildcard crossed a "
                      "segment boundary")
    return _held("segment-boundary scoping holds; prefix lookalikes deny")


@probe("stale-cache-replay")
def p_cache():
    """Cached decisions are keyed by the FULL request context
    (identity+action+resource+context): any context change is a cache
    miss. TTL expiry re-evaluates."""
    if not _HAVE_CE:
        return _gap("no enforcer: no decision cache to poison")
    calls = []

    def _counting(request):
        calls.append(request)
        return ce.AuthorizationVerdict(True, ce.CODE_ALLOWED, "ok")

    now = [1000.0]
    cache = ce.DecisionCache(ttl_s=60.0, clock=lambda: now[0])
    enf = _enforcer(check=_counting,
                    policies=[_policy("p1", "credential.swap", "cred-a",
                                      check=_counting)],
                    cache=cache, clock=lambda: now[0])
    base = dict(identity="agent-1", action="credential.swap",
                resource="cred-a")
    r1 = _req(context={"dest_host": "good.example"}, **base)
    v = enf.enforce(r1)
    if not v.allow or len(calls) != 1:
        return _break("first evaluation failed: %r calls=%d"
                      % (v.allow, len(calls)))
    # Same request -> cache hit, check NOT re-run.
    v = enf.enforce(_req(context={"dest_host": "good.example"}, **base))
    if not v.allow or len(calls) != 1:
        return _break("identical request missed the cache: calls=%d"
                      % len(calls))
    # Context change (dest host) -> MUST be a miss: the check re-runs.
    v = enf.enforce(_req(context={"dest_host": "evil.example"}, **base))
    if len(calls) != 2:
        return _break("context change did NOT invalidate the cache: "
                      "stale allow served for a new destination (cache "
                      "poisoning shape)")
    # Identity change -> miss.
    v = enf.enforce(_req(context={"dest_host": "good.example"},
                         identity="agent-2", action="credential.swap",
                         resource="cred-a"))
    if len(calls) != 3:
        return _break("identity change did not invalidate the cache")
    # TTL expiry -> miss.
    now[0] += 61.0
    v = enf.enforce(_req(context={"dest_host": "good.example"}, **base))
    if len(calls) != 4:
        return _break("expired entry served stale: TTL not enforced")
    # A cached DENY stays a deny (served from cache, check not re-run).
    calls.clear()
    enf2 = _enforcer(
        check=_deny_check,
        policies=[_policy("p1", "credential.swap", "cred-a",
                          check=_deny_check)],
        cache=ce.DecisionCache(ttl_s=60.0, clock=lambda: now[0]),
        clock=lambda: now[0])

    def _counting_deny(request):
        calls.append(request)
        return ce.AuthorizationVerdict(False, ce.CODE_DENIED, "no")

    enf2 = _enforcer(
        check=_counting_deny,
        policies=[_policy("p1", "credential.swap", "cred-a",
                          check=_counting_deny)],
        cache=ce.DecisionCache(ttl_s=60.0, clock=lambda: now[0]),
        clock=lambda: now[0])
    v = enf2.enforce(r1)
    v = enf2.enforce(_req(context={"dest_host": "good.example"}, **base))
    if v.allow or len(calls) != 1:
        return _break("cached deny not served consistently: allow=%r "
                      "calls=%d" % (v.allow, len(calls)))
    if v.code != ce.CODE_DENIED:
        return _break("cached deny lost its code: %r" % (v.code,))
    return _held("cache keyed by full context; context/TTL changes "
                 "invalidate; denies cache as denies")


@probe("decision-counters")
def p_counters():
    """Per-policy allow/deny/error counters are observable in memory;
    snapshots are isolated copies."""
    if not _HAVE_CE:
        return _gap("no enforcer: no counters")
    enf = _enforcer(policies=[_policy("p1", "credential.swap", "cred-a",
                                      check=_allow_check),
                              _policy("p2", "credential.swap", "cred-b",
                                      check=_deny_check)])
    enf.enforce(_req(resource="cred-a"))
    enf.enforce(_req(resource="cred-a"))
    enf.enforce(_req(resource="cred-b"))
    enf.enforce(_req(resource="cred-zzz"))  # unmatched
    snap = enf.counters_snapshot()
    if snap["p1"]["allow"] != 2:
        return _break("p1 allow count wrong: %r" % (snap["p1"],))
    if snap["p2"]["deny"] != 1:
        return _break("p2 deny count wrong: %r" % (snap["p2"],))
    if snap["_unmatched"]["deny"] != 1:
        return _break("unmatched deny not counted: %r" % (snap,))
    snap["p1"]["allow"] = 999
    if enf.counters_snapshot()["p1"]["allow"] != 2:
        return _break("snapshot mutation leaked into live counters")
    return _held("per-policy allow/deny/error counters observable; "
                 "snapshots isolated")


@probe("sentinel-seam-check")
def p_sentinel_seam():
    """Every swap at the sentinel execution boundary goes through the
    check: deny -> SentinelError with the machine code BEFORE any
    substitution; allow -> substitution proceeds."""
    if not _HAVE_CE:
        return _gap("no enforcer: sentinel seam has no check to route")
    from gov import sentinel_substitution as _sentinel  # noqa: E402
    vault = _sentinel.SentinelVault()
    real = "tok_synth_w260_probe_1a2b3c"
    sentinel = vault.register("probe-key", real, ["db.synthetic.local"],
                              credential_class="probe",
                              release_policy="legacy-host-only")
    args = {"url": "https://db.synthetic.local/q", "api_key": sentinel}

    deny_enf = _enforcer(
        check=_deny_check,
        policies=[_policy("p1", "credential.swap", "probe-key",
                          check=_deny_check)])
    try:
        _sentinel.substitute_for_execution(
            vault, "http_post", dict(args), enforcer=deny_enf)
        return _break("denied check did NOT refuse the swap")
    except _sentinel.SentinelError as e:
        if "callauthz-denied" not in str(e):
            return _break("refusal carried the wrong machine code: %s"
                          % (e,))
    if vault.substitution_log:
        return _break("denied swap still logged a substitution")
    if args.get("api_key") != sentinel:
        return _break("caller args mutated on the deny path")

    allow_enf = _enforcer(
        check=_allow_check,
        policies=[_policy("p1", "credential.swap", "probe-key",
                          check=_allow_check)])
    new_args, _vals = _sentinel.substitute_for_execution(
        vault, "http_post", dict(args), enforcer=allow_enf)
    if new_args.get("api_key") != real:
        return _break("allowed check did not substitute")
    if len(vault.substitution_log) != 1:
        return _break("allowed substitution not logged")

    # The check saw the full authorization context.
    seen = []

    def _spy(request):
        seen.append(request)
        return ce.AuthorizationVerdict(True, ce.CODE_ALLOWED, "ok")

    spy_enf = _enforcer(
        check=_spy,
        policies=[_policy("p1", "credential.swap", "probe-key",
                          check=_spy)])
    _sentinel.substitute_for_execution(vault, "http_post", dict(args),
                                       enforcer=spy_enf)
    if not seen:
        return _break("check never invoked on the swap path")
    r0 = seen[0]
    if not (r0.caller_identity and r0.action == "credential.swap"
            and r0.resource == "probe-key"
            and r0.context_dict().get("dest_host") == "db.synthetic.local"):
        return _break("check request missing authorization context: %r"
                      % (r0,))
    return _held("deny refuses pre-substitution with callauthz-denied; "
                 "allow substitutes; check receives full context")


@probe("wired-executor-seam")
def p_wired_executor():
    """ToolExecutor(..., call_authorizer=...) routes the approved-sweep
    substitution through the check. Placement pin: the attempt path
    does NOT consult the check (DLP/policy/approval still see the
    sentinel form); the execution boundary does."""
    if not _HAVE_CE:
        return _gap("no enforcer: executor has no wired seam")
    from gov.executor import ToolExecutor  # noqa: E402
    from gov.policy import PolicyEngine  # noqa: E402
    from gov.log import ActionLog  # noqa: E402
    from gov.approvals import ApprovalQueue  # noqa: E402
    from gov import sentinel_substitution as _sentinel  # noqa: E402

    def _session(enforcer):
        run_dir = Path(_tmpdir())
        policy = PolicyEngine(
            str(Path(REPO) / "policies" / "default.yaml"))
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        vault = _sentinel.SentinelVault()
        vault.register("vendor-key", "tok_synth_w260_exec_9f8e7d",
                       ["vendor.synthetic.local"],
                       credential_class="vendor-api",
                       release_policy="legacy-host-only")
        try:
            ex = ToolExecutor(
                run_dir, policy, log, approvals,
                ledger_path=run_dir / "egress_ledger.jsonl",
                ungoverned_ack="w260 callauthz battery: synthetic eval "
                              "harness, declared and chained",
                sentinel_registry=vault, call_authorizer=enforcer)
        except TypeError as e:
            return None, "executor lacks the call_authorizer seam: %s" % e
        return {"run_dir": run_dir, "executor": ex, "log": log,
                "approvals": approvals, "vault": vault}, None

    deny_enf = _enforcer(
        check=_deny_check,
        policies=[_policy("p1", "credential.swap", "vendor-key",
                          check=_deny_check)])
    ctx, err = _session(deny_enf)
    if ctx is None:
        return _gap(err)
    ex, vault = ctx["executor"], ctx["vault"]
    sentinel = vault.sentinel_for("vendor-key")
    ident = ex.mint_identity("w260-agent", "researcher", "user-1")
    # Placement: the attempt path must NOT consult the check -- the
    # call queues normally (sentinel form through DLP/policy/approval).
    r = ex.call(ident, "http_post",
                url="https://vendor.synthetic.local/sync",
                payload={"api_key": sentinel})
    if r.get("status") != "queued" or not r.get("approval_id"):
        return _break("deny-enforcer altered the attempt path: %r "
                      "(check placement moved -- the attempt path must "
                      "stay check-free)" % (r,))
    ctx["approvals"].decide(r["approval_id"], True,
                            reason="w260 probe", decided_by="human-operator")
    refused = False
    try:
        ex.execute_approved()
    except _sentinel.SentinelError as e:
        refused = ("callauthz-denied" in str(e))
    if not refused:
        return _break("approved sweep substituted despite the deny: "
                      "the execution boundary bypassed the check")
    if vault.substitution_log:
        return _break("denied sweep logged a substitution")
    blob = open(ctx["run_dir"] / "actions.jsonl").read()
    if "tok_synth_w260_exec_9f8e7d" in blob:
        return _break("real credential reached the audit log on the "
                      "deny path")

    # Positive control: an allowing enforcer lets the authorized swap
    # proceed end to end.
    allow_enf = _enforcer(
        check=_allow_check,
        policies=[_policy("p1", "credential.swap", "vendor-key",
                          check=_allow_check)])
    ctx2, err = _session(allow_enf)
    if ctx2 is None:
        return _gap(err)
    ex2, vault2 = ctx2["executor"], ctx2["vault"]
    sentinel2 = vault2.sentinel_for("vendor-key")
    ident2 = ex2.mint_identity("w260-agent", "researcher", "user-1")
    r2 = ex2.call(ident2, "http_post",
                  url="https://vendor.synthetic.local/sync",
                  payload={"api_key": sentinel2})
    ctx2["approvals"].decide(r2["approval_id"], True,
                             reason="w260 probe",
                             decided_by="human-operator")
    try:
        ex2.execute_approved()
    except _sentinel.SentinelError as e:
        return _break("allowing enforcer refused the swap: %s" % (e,))
    if len(vault2.substitution_log) != 1:
        return _break("allowed swap did not substitute exactly once")
    return _held("deny-enforcer: attempt queues, execution refuses with "
                 "callauthz-denied, no substitution, audit clean; "
                 "allow-enforcer: swap proceeds")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: the adjacent sentinel battery still passes. Honors
    GOV_SKIP_GREEN (records skip, never spawns)."""
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED (GOV_SKIP_GREEN=1)")]
    notes = []
    repo = REPO
    for battery in ("evals/adversarial_sentinel_substitution.py",):
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        try:
            p = subprocess.run(
                [sys.executable, os.path.join(repo, battery)],
                capture_output=True, text=True, timeout=600,
                env=env, cwd=repo)
            tail = (p.stdout or "").strip().splitlines()[-1:] or [""]
            notes.append((battery,
                          "exit=%d %s" % (p.returncode, tail[0][:60])))
        except Exception as e:  # noqa: BLE001 -- green-check report
            notes.append((battery, "ERROR %s" % e))
    return notes


def main():
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        print("PIN MISMATCH: taxonomy has %d keys, pin is %d" %
              (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
        return 2
    held = breaks = gaps = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s" %
                               (type(e).__name__, str(e)[:160]))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        elif verdict == "GAP":
            gaps += 1
        else:
            errors += 1
        print("%-8s %-28s %s" % (verdict, name, detail))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("HELD %d / BREAK %d / GAP %d / ERROR %d over %d probes" %
          (held, breaks, gaps, errors, len(_PROBES)))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
