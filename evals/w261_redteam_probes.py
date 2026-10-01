"""Break-first red-team battery for the wave-260 seams (second pass).

Wave-261 independent red-team lane. Stdlib only. Deterministic across
runs (staging + `env -u GOV_DEPLOYMENT_MODE`), except the two
concurrency probes which are probabilistic by nature (documented
below; the live_keys race is near-deterministic, the double-issue
race was 6/150 trials at 64 threads on base). No in-repo git
subprocesses (wave-36 supply-chain probe: fail closed).

Targets (base c2a1fc02e4f82101aaf3285596c7144a2850e95b, taxonomy pin
1092):
- gov/policy_distribution.py -- hostile-input robustness of
  Subscriber.apply (F235: RecursionError escapes on deeply-nested
  unsigned input), publisher monotonicity, cross-topic replay,
  equivocation, signature-malleability handling.
- gov/call_enforcement.py -- the opt-in None seam (is there a
  configured-deployment path with silently no enforcement? --
  answered: both executor swap paths wire it; spawn drops it but the
  child also drops the registry so no swaps occur there), segment
  boundaries, timeout/check-error fail-closed.
- gov/mesh_admission.py -- route-table composition: no-downgrade
  between the SVID and kernel seams, default-deny routes.
- gov/svid_enrollment.py -- F236: the key table has no concurrency
  control (concurrent redeem double-issues; live_keys raises under
  concurrent issue); digest-only storage; burn-before-issue.
- F230-F234 seams: cross-checked only (filed OPEN, dedicated lanes
  own them). Probes reproduce the defect on this base as BASELINE.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Verdicts: HELD (attack refused / gap is a documented
residual), BREAK (genuine defect -> filed as a finding F235+),
BASELINE (filed-open finding reproduced -- NOT a new finding),
ERROR (harness bug -- fix the harness, never the product).
"""

import hashlib
import inspect
import json
import os
import secrets
import sys
import tempfile
import threading
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w261-redteam")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import policy_distribution as poldist  # noqa: E402
from gov import call_enforcement as ce  # noqa: E402
from gov import mesh_admission as ma  # noqa: E402
from gov import svid_enrollment as enr  # noqa: E402
from gov import svid_issuer as sv  # noqa: E402

# Wave-261 base pin: no taxonomy codes added or removed by this lane.
# If the count moves, the delta must be explained by a landed taxonomy
# change -- never repoint blindly (replace the VALUE only).
TAXONOMY_PIN = 1151  # Wave-260 merge pin; wave-261 redteam adds none.

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    return tempfile.mkdtemp(prefix="w261rt-", dir="/var/tmp")


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _baseline(detail=""):
    return ("BASELINE", detail)


def _poldist_pair(topic="policies"):
    seed = bytes.fromhex("ab" * 32)
    pub = poldist.Publisher(seed)
    sub = poldist.Subscriber(topic, pub.pubkey)
    return pub, sub


def _poldist_code(bundle, sub):
    out = sub.apply(bundle)
    code = out.get("code")
    if isinstance(code, dict):
        return out["outcome"] + "/" + code["code"]
    return out["outcome"]


# ---------------------------------------------------------------------------
# F235: Subscriber.apply raises RecursionError on hostile deeply-nested
# input -- the "never raises on hostile input" contract is violated.
# ---------------------------------------------------------------------------

@probe("poldist/recursion-error-on-hostile-unsigned-input")
def _p_f235():
    _, sub = _poldist_pair()
    # Hand-crafted hostile bytes (no stdlib json on the attack side):
    # an UNSIGNED bundle whose payload nests 30000 deep. Every shape
    # check passes until json.loads, which raises RecursionError --
    # not caught (apply only catches UnicodeDecodeError/ValueError).
    depth = 30000
    raw = ('{"v":1,"topic":"policies","version":1,"payload":{"nest":'
           + "[" * depth + '"x"' + "]" * depth
           + '},"sig":"' + "0" * 128 + '"}').encode("utf-8")
    try:
        out = sub.apply(raw)
    except Exception as e:  # noqa: BLE001 -- the defect under test
        return _break(
            "unsigned hostile input raised %s out of apply() "
            "(contract: never raises on hostile input): %s"
            % (type(e).__name__, str(e)[:90]))
    code = out.get("code")
    c = code["code"] if isinstance(code, dict) else code
    return _held("deeply-nested unsigned input refused as %s" % c)


# ---------------------------------------------------------------------------
# poldist HELD: the lane-1 claims hold under break-first pressure
# ---------------------------------------------------------------------------

@probe("poldist/publisher-refuses-non-increasing-version")
def _h_pd_mono():
    pub, _ = _poldist_pair()
    pub.sign_bundle("t", 3, {"a": 1})
    try:
        pub.sign_bundle("t", 3, {"a": 2})
        return _break("publisher re-signed version 3")
    except poldist.PublisherError:
        pass
    try:
        pub.sign_bundle("t", 2, {"a": 2})
        return _break("publisher signed a lower version")
    except poldist.PublisherError:
        pass
    # ... but a higher version on a DIFFERENT topic is fine (per-topic).
    pub.sign_bundle("other", 1, {"a": 1})
    return _held("non-increasing version refused per topic at the source")


@probe("poldist/cross-topic-replay-refused-before-signature")
def _h_pd_xtopic():
    pub, sub = _poldist_pair()
    # A bundle validly signed for another topic must die on binding,
    # before any signature work (no validity oracle for foreigners).
    b = pub.sign_bundle("other", 1, {"x": 1})
    out = sub.apply(b)
    code = out.get("code")
    c = code["code"] if isinstance(code, dict) else code
    if out["outcome"] == "refused" and c == "poldist-topic-cross":
        return _held("foreign-topic bundle refused on binding")
    return _break("cross-topic bundle not refused on binding: %s/%s"
                  % (out["outcome"], c))


@probe("poldist/equivocation-same-version-refused")
def _h_pd_equiv():
    # Two publisher instances sharing one seed (the documented fork
    # residual): the subscriber must refuse the second head at the
    # same version, never switch to it.
    seed = bytes.fromhex("ab" * 32)
    p1, p2 = poldist.Publisher(seed), poldist.Publisher(seed)
    sub = poldist.Subscriber("t", p1.pubkey)
    r1 = sub.apply(p1.sign_bundle("t", 1, {"a": 1}))
    r2 = sub.apply(p2.sign_bundle("t", 1, {"a": 2}))
    c2 = r2.get("code")
    c2 = c2["code"] if isinstance(c2, dict) else c2
    if r1["outcome"] == "applied" and r2["outcome"] == "refused" \
            and c2 == "poldist-version-rollback" \
            and sub.payload == {"a": 1}:
        return _held("same-version fork refused; head not switched")
    return _break("equivocation handling wrong: %s then %s/%s"
                  % (r1["outcome"], r2["outcome"], c2))


@probe("poldist/mauled-signature-rejected")
def _h_pd_malleable():
    # Ed25519 S-malleability: S' = S + L must NOT verify (verify
    # rejects s >= L). A mauled signature is a mismatch, never a
    # second valid signature for the same bundle.
    from gov import ed25519 as _ed  # noqa: E402
    pub, sub = _poldist_pair()
    b = pub.sign_bundle("policies", 1, {"a": 1})
    env = json.loads(b.decode("utf-8"))
    sig = bytes.fromhex(env["sig"])
    s = int.from_bytes(sig[32:], "little")
    mauled = sig[:32] + ((s + _ed._L) % (2 ** 256)).to_bytes(32, "little")
    assert _ed.verify(pub.pubkey,
                      poldist.signed_bytes("policies", 1, {"a": 1}),
                      mauled) is not True
    env["sig"] = mauled.hex()
    raw = json.dumps(env, sort_keys=True, separators=(",", ":")).encode()
    out = sub.apply(raw)
    code = out.get("code")
    c = code["code"] if isinstance(code, dict) else code
    if out["outcome"] == "refused" and c == "poldist-signature-mismatch":
        return _held("S-mauled signature refused (s >= L rejected)")
    return _break("mauled signature not refused: %s/%s"
                  % (out["outcome"], c))


@probe("poldist/duplicate-redelivery-idempotent")
def _h_pd_dup():
    pub, sub = _poldist_pair()
    b = pub.sign_bundle("policies", 1, {"a": 1})
    r1 = sub.apply(b)
    r2 = sub.apply(b)  # at-least-once redelivery of the current head
    if r1["outcome"] == "applied" and r2.get("duplicate") is True \
            and sub.version == 1 and sub.payload == {"a": 1}:
        return _held("identical redelivery applied idempotently")
    return _break("duplicate handling wrong: %r then %r" % (r1, r2))


# ---------------------------------------------------------------------------
# F236: EnrollmentAuthority has no concurrency control on its key table.
# (a) concurrent redeem() of one key double-issues SVIDs -- the
#     "exactly one SVID per key / burned on redemption" invariant dies
#     under threads (check-then-set on record["used"], no lock);
# (b) live_keys() raises RuntimeError under concurrent issue_key().
# The module documents cross-INSTANCE burn atomicity as
# deployment-owned; in-process atomicity is its own job (there is no
# lock anywhere in the module).
# ---------------------------------------------------------------------------

def _enr_pair():
    issuer = sv.TestSvidIssuer(issuer_seed=bytes.fromhex("aa" * 32))
    return enr.EnrollmentAuthority(issuer), issuer


@probe("enrollment/concurrent-redeem-double-issues-single-key")
def _p_f236a():
    # Probabilistic by nature (race window is a few dozen bytecodes):
    # 64 threads x 150 trials measured 6 double-issuances on base.
    # P(no hit over 150 trials) ~= 0.2%.
    auth, _ = _enr_pair()
    old_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-7)  # harness-side scheduling pressure only
    try:
        double = 0
        trials, nthreads = 150, 64
        for _ in range(trials):
            key = auth.issue_key(spiffe_id="spiffe://example.org/w/r")
            barrier = threading.Barrier(nthreads)
            results = []
            rlock = threading.Lock()

            def worker():
                barrier.wait()
                try:
                    auth.redeem(key, "spiffe://example.org/w/r",
                                "bb" * 32, 5)
                    r = "svid"
                except sv.SvidError as e:
                    r = e.code
                with rlock:
                    results.append(r)

            ths = [threading.Thread(target=worker)
                   for _ in range(nthreads)]
            for th in ths:
                th.start()
            for th in ths:
                th.join()
            if results.count("svid") > 1:
                double += 1
    finally:
        sys.setswitchinterval(old_interval)
    if double:
        return _break(
            "%d/%d trials issued 2+ SVIDs from ONE enrollment key "
            "(single-use invariant broken under concurrency)" % (double,
                                                                 trials))
    return _held("no double-issuance observed over %d trials" % trials)


@probe("enrollment/live-keys-raises-under-concurrent-issue")
def _p_f236b():
    auth, _ = _enr_pair()
    for _ in range(50):
        auth.issue_key()
    old_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-7)
    stop = threading.Event()
    crashed = []
    try:
        def reader():
            while not stop.is_set():
                try:
                    auth.live_keys()
                except Exception as e:  # noqa: BLE001 -- defect shape
                    crashed.append(type(e).__name__)
                    return

        def writer():
            while not stop.is_set():
                auth.issue_key()

        ths = ([threading.Thread(target=reader) for _ in range(8)]
               + [threading.Thread(target=writer) for _ in range(4)])
        for th in ths:
            th.start()
        time.sleep(3)
        stop.set()
        for th in ths:
            th.join()
    finally:
        sys.setswitchinterval(old_interval)
    if crashed:
        return _break(
            "live_keys() raised %s under concurrent issue_key "
            "(no lock on the key table)" % crashed[0])
    return _held("live_keys() survived 3s of concurrent mutation")


# ---------------------------------------------------------------------------
# enrollment HELD: the documented ceremony properties hold (single-threaded)
# ---------------------------------------------------------------------------

@probe("enrollment/records-store-digest-only")
def _h_enr_digest():
    auth, _ = _enr_pair()
    key = auth.issue_key(spiffe_id="spiffe://example.org/w/a")
    assert len(auth._records) == 1
    (digest, rec), = auth._records.items()
    if digest != hashlib.sha256(key.encode("utf-8")).hexdigest():
        return ("ERROR", "record not keyed by key digest")
    blob = json.dumps(rec, sort_keys=True, default=str)
    if key in blob or key[:16] in blob:
        return _break("raw key material present in the stored record")
    if rec["bind_spiffe_id"] != "spiffe://example.org/w/a":
        return ("ERROR", "binding not stored normalized")
    return _held("only the sha256 digest is stored; raw key never "
                 "retained; binding stored normalized")


@probe("enrollment/unknown-expired-mismatch-codes")
def _h_enr_codes():
    auth, _ = _enr_pair()

    def code_of(fn):
        try:
            fn()
        except sv.SvidError as e:
            return e.code
        return "NO-RAISE"

    unk = code_of(lambda: auth.redeem("never-issued-key",
                                      "spiffe://example.org/w/a",
                                      "bb" * 32, 5))
    k_exp = auth.issue_key(ttl_seconds=60)
    exp = code_of(lambda: auth.redeem(k_exp, "spiffe://example.org/w/a",
                                      "bb" * 32, 5, now=time.time() + 3600))
    # expired keys burn on refusal: second attempt is replayed
    exp2 = code_of(lambda: auth.redeem(k_exp, "spiffe://example.org/w/a",
                                       "bb" * 32, 5,
                                       now=time.time() + 3600))
    k_bind = auth.issue_key(spiffe_id="spiffe://example.org/w/bound")
    mm = code_of(lambda: auth.redeem(k_bind, "spiffe://example.org/w/other",
                                     "bb" * 32, 5))
    # misuse burns: the bound key is dead even for its bound id now
    mm2 = code_of(lambda: auth.redeem(k_bind, "spiffe://example.org/w/bound",
                                       "bb" * 32, 5))
    want = {
        "unknown": (unk, enr.ENROLLMENT_KEY_UNKNOWN_CODE),
        "expired": (exp, enr.ENROLLMENT_KEY_EXPIRED_CODE),
        "expired-again": (exp2, enr.ENROLLMENT_KEY_REPLAYED_CODE),
        "mismatch": (mm, enr.ENROLLMENT_SPIFFE_MISMATCH_CODE),
        "mismatch-again": (mm2, enr.ENROLLMENT_KEY_REPLAYED_CODE),
    }
    bad = ["%s=%s" % (k, got) for k, (got, w) in want.items() if got != w]
    if bad:
        return _break("wrong machine codes: " + "; ".join(bad))
    return _held("unknown/expired/mismatch coded; dead keys burn")


@probe("enrollment/burn-before-issue-on-failed-issuance")
def _h_enr_burn():
    auth, _ = _enr_pair()
    key = auth.issue_key()  # unbound
    try:
        auth.redeem(key, "not-a-spiffe-id", "bb" * 32, 5)
        return ("ERROR", "bad spiffe id did not raise")
    except sv.SvidError as e:
        first = e.code
    try:
        auth.redeem(key, "spiffe://example.org/w/a", "bb" * 32, 5)
        return _break("key usable again after failed issuance")
    except sv.SvidError as e:
        if first == sv.SVID_IDENTITY_MALFORMED_CODE and \
                e.code == enr.ENROLLMENT_KEY_REPLAYED_CODE:
            return _held("issuance failure still burns the key "
                         "(exactly-once, single-threaded)")
        return ("ERROR", "unexpected codes %s/%s" % (first, e.code))


# ---------------------------------------------------------------------------
# call_enforcement: the opt-in None seam.
#
# Question: is there a path where a DEPLOYMENT that configured an
# enforcer silently gets no enforcement? Both in-executor swap paths
# (direct + approved sweep) thread call_authorizer into
# substitute_for_execution. spawn_sub_agent does NOT propagate
# call_authorizer to the child -- BUT it also does not propagate
# sentinel_registry, so the child performs no sentinel swaps at all:
# the dropped enforcer is currently unreachable (latent wiring
# inconsistency, not an exploitable bypass). Probed behaviorally
# below via a real governed spawn.
# ---------------------------------------------------------------------------

def _ce_enforcer(check, policies=(), cache=None):
    enf = ce.CallEnforcer(check=check, cache=cache)
    for p in policies:
        enf.register_policy(p)
    return enf


def _ce_policy(pid, action_pat, resource_pat, check, timeout_s=1.0):
    return ce.ScopedPolicy(pid, action_pat, resource_pat, check=check,
                           timeout_s=timeout_s)


def _allow_check(request):
    return ce.AuthorizationVerdict(True, ce.CODE_ALLOWED, "ok")


def _deny_check(request):
    return ce.AuthorizationVerdict(False, "probe-deny", "no")


@probe("callauthz/spawned-child-drops-call-authorizer")
def _h_ce_spawn():
    """Behavioral: a real governed spawn; the child's call_authorizer
    (and sentinel_registry) must be observed, not assumed."""
    from pathlib import Path  # noqa: E402
    from gov import delegation_tokens as _dt  # noqa: E402
    from gov.executor import ToolExecutor  # noqa: E402
    from gov.log import ActionLog  # noqa: E402
    from gov.policy import PolicyEngine  # noqa: E402
    from gov.approvals import ApprovalQueue  # noqa: E402
    from gov import sentinel_substitution as _sentinel  # noqa: E402
    from gov import policy_change as _pc  # noqa: E402

    _BASE_POLICY = ("version: 2\nroles:\n  scout: [read_file]\npolicies:\n"
                    "  - id: allow-scout-reads\n    effect: allow\n"
                    "    match:\n      tool: [read_file]\n"
                    "    reason: w261 probe\n")
    run_dir = Path(_tmpdir()) / "run"
    run_dir.mkdir()
    policy = PolicyEngine.from_text(_BASE_POLICY,
                                    source_label="<w261>")
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)

    # Key ceremony + token trio + bound delegation context (the
    # wave-86 governed-spawn recipe).
    human = _dt.generate_test_keypair()
    idp = _dt.generate_test_keypair()
    authority = _dt.generate_test_keypair()
    parent = _dt.generate_test_keypair()
    session = run_dir.name
    aud = "w261-probe"
    user_tok = _dt.issue_user_token(idp[0], "alice", ("tool:read_file",),
                                    session, ttl_s=3600, audience=aud)
    agent_tok = _dt.issue_agent_token(authority[0], "agent-a", "scout",
                                      "alice", ("tool:read_file",),
                                      session, ttl_s=3600, audience=aud)
    deleg_tok = _dt.issue_delegation(human[0], "alice", user_tok,
                                     agent_tok, ("tool:read_file",),
                                     session, "urn:w261:revoke",
                                     ttl_s=3600, audience=aud)
    trust = _dt.DelegationTrust(
        human_keys={human[0].key_id: human[1]},
        authority_keys={authority[0].key_id: authority[1]},
        user_issuer_keys={idp[0].key_id: idp[1]},
        agent_keys={"agent-a": parent[1]}, audience=aud)
    ctx = _dt.DelegationContext(
        user_token=user_tok, agent_token=agent_tok,
        delegation_token=deleg_tok, parent_chain=[], trust=trust,
        session_id=session).bind()

    # The governed core the wave-85 constructor gate requires: the
    # child inherits policy_store from the parent at spawn.
    store = _pc.GovernedPolicyStore(deployment_mode="dev", trust=trust,
                                    log=log,
                                    session_id="sess-w261-store")
    store.bootstrap(_BASE_POLICY, human[0], "alice", "w261 genesis",
                    approver_signers=[human[0]])

    vault = _sentinel.SentinelVault()
    vault.register("probe-key", "tok_synth_w261_spawnsess",
                   ["db.synthetic.local"], credential_class="probe",
                   release_policy="legacy-host-only")
    enf = _ce_enforcer(
        _deny_check,
        [_ce_policy("p1", "credential.swap", "probe-key", _deny_check)])
    ex = ToolExecutor(
        run_dir, policy, log, approvals,
        ledger_path=run_dir / "egress_ledger.jsonl",
        capability_ungoverned_ack="w261 redteam battery: the subject "
                                  "under test is spawn wiring, not the "
                                  "capability gate; declared, not silent",
        delegation_context=ctx,
        policy_store=store,
        session_identity=("agent-a", "scout", "alice"),
        sentinel_registry=vault, call_authorizer=enf)
    if getattr(ex, "call_authorizer", None) is not enf:
        return ("ERROR", "parent executor did not retain call_authorizer")
    try:
        child = ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                                   parent[0])
    except Exception as e:  # noqa: BLE001 -- harness diagnostic
        return ("ERROR", "spawn failed: %s: %s"
                % (type(e).__name__, str(e)[:100]))
    child_enf = getattr(child, "call_authorizer", "MISSING")
    child_reg = getattr(child, "sentinel_registry", "MISSING")
    if child_enf is enf:
        return _held("spawn propagates call_authorizer to the child")
    # The drop is real, but so is the registry drop: with
    # sentinel_registry None the child's execution paths skip
    # substitute_for_execution entirely, so no swap in the child can
    # dodge the check -- latent, not exploitable.
    if child_enf is None and child_reg is None:
        return _held(
            "spawn drops call_authorizer AND sentinel_registry: the "
            "child performs no sentinel swaps, so the dropped enforcer "
            "is unreachable (latent wiring inconsistency, not an "
            "exploitable bypass)")
    return _break("spawn produced an enforcing-capable child without "
                  "the enforcer: call_authorizer=%r registry=%r"
                  % (child_enf, child_reg))


@probe("callauthz/both-executor-paths-thread-enforcer")
def _h_ce_wiring():
    # Wiring pin (source-level): every substitute_for_execution call
    # inside gov/executor.py must pass enforcer=.
    from gov import executor as _exec_mod  # noqa: E402
    src = inspect.getsource(_exec_mod)
    calls = [i for i in range(len(src))
             if src.startswith("substitute_for_execution(", i)]
    wired = sum(1 for i in calls
                if "enforcer=" in src[i:i + 2000].split("\n\n")[0])
    if not calls:
        return ("ERROR", "no substitute_for_execution call sites found")
    if wired == len(calls):
        return _held("%d/%d executor swap paths pass enforcer="
                     % (wired, len(calls)))
    return _break("executor swap path without enforcer=: %d/%d wired"
                  % (wired, len(calls)))


@probe("callauthz/segment-boundary-matching")
def _h_ce_segments():
    # The identity lane's prefix-confusion precedent: a LITERAL
    # pattern tool/read must never authorize tool/readwrite; a "*"
    # matches exactly one whole segment (so tool/* DOES match the
    # single segment "readwrite" -- that is the documented wildcard
    # semantic, not a bypass).
    p_lit = _ce_policy("p-lit", "tool/read", "cred/x", _allow_check)
    p_wild = _ce_policy("p-wild", "tool/*", "cred/*", _allow_check)
    enf = _ce_enforcer(_allow_check, [p_lit, p_wild])

    def verdict(action, resource):
        req = ce.CheckRequest("a1", action, resource)
        return enf.enforce(req).allow

    if verdict("tool/read", "cred/x") is not True:
        return _break("exact literal match did not allow")
    if verdict("tool/readwrite", "cred/x") is not False:
        # p-lit must not match; p-wild (tool/*) legitimately matches
        # the single segment "readwrite" -- so scope the check to the
        # literal policy directly.
        if p_lit.matches(ce.CheckRequest("a1", "tool/readwrite",
                                         "cred/x")):
            return _break("prefix confusion: literal tool/read "
                          "matched tool/readwrite")
    if p_wild.matches(ce.CheckRequest("a1", "tool/a/b", "cred/x")):
        return _break("depth confusion: tool/* matched tool/a/b")
    if p_wild.matches(ce.CheckRequest("a1", "tool/", "cred/x")):
        return _break("empty segment matched wildcard")
    if verdict("tool/a/b", "cred/x") is not False:
        return _break("tool/a/b allowed despite no matching policy")
    return _held("literal patterns are segment-exact; wildcards match "
                 "whole segments only")


@probe("callauthz/timeout-and-error-deny-fail-closed")
def _h_ce_failclosed():
    def sleeper(request):
        time.sleep(30)

    def raiser(request):
        raise RuntimeError("boom")

    def sloppy(request):
        return "not-a-verdict"

    p1 = _ce_policy("p1", "a/*", "r/*", sleeper, timeout_s=0.2)
    p2 = _ce_policy("p2", "b/*", "r/*", raiser)
    p3 = _ce_policy("p3", "c/*", "r/*", sloppy)
    enf = _ce_enforcer(_allow_check, [p1, p2, p3])

    def code(action):
        v = enf.enforce(ce.CheckRequest("a1", action, "r/x"))
        return (v.allow, v.code)

    ok1, c1 = code("a/zzz")
    ok2, c2 = code("b/zzz")
    ok3, c3 = code("c/zzz")
    ok4, c4 = code("zzz/zzz")  # no policy matches
    bad = []
    if ok1 or c1 != ce.CODE_CHECK_ERROR:
        bad.append("timeout=%s/%s" % (ok1, c1))
    if ok2 or c2 != ce.CODE_CHECK_ERROR:
        bad.append("raise=%s/%s" % (ok2, c2))
    if ok3 or c3 != ce.CODE_CHECK_ERROR:
        bad.append("non-verdict=%s/%s" % (ok3, c3))
    if ok4 or c4 != ce.CODE_NOT_CONFIGURED:
        bad.append("unmatched=%s/%s" % (ok4, c4))
    if bad:
        return _break("fail-closed wrong: " + "; ".join(bad))
    return _held("timeout/raise/non-verdict/unmatched all deny with "
                 "machine codes")


# ---------------------------------------------------------------------------
# mesh_admission HELD: the no-downgrade composition holds
# ---------------------------------------------------------------------------

def _mesh_triple():
    issuer = sv.TestSvidIssuer(issuer_seed=bytes.fromhex("aa" * 32))
    verifier = sv.SvidVerifier({issuer.key_id: issuer.issuer_public_key},
                               "example.org")
    mc = sv.MeshControl(verifier,
                        {"allow": ["spiffe://example.org/workload"]})
    mesh = ma.MeshAdmission(
        {"svc-a": {"require": "svid"},
         "svc-b": {"require": "kernel"},
         "svc-c": {"require": "either"}}, mc)
    return issuer, mesh


def _mesh_code(fn):
    try:
        r = fn()
        return "ADMITTED/" + r.get("mode", "?")
    except sv.SvidError as e:
        return "svid:" + e.code
    except Exception as e:  # noqa: BLE001 -- channel seam codes
        return "other:" + getattr(e, "code", type(e).__name__)


def _good_kernel(now, seq=0):
    from gov import attested_channel as _ac  # noqa: E402
    kloc = next(iter(_ac._EXTERNAL_KEY_LOCATIONS))
    return {"peer_identity": {"uid": 1000, "gid": 1000, "pid": 1234,
                              "exe": "/usr/bin/agent"},
            "emitter_claim": {"principal": "agent-1", "ts_emit": now,
                              "seq": seq, "payload": {"ok": True}},
            "key_location": kloc}


@probe("mesh/either-bad-svid-never-downgrades-to-kernel")
def _h_mesh_nodowngrade():
    issuer, mesh = _mesh_triple()
    good = issuer.issue("spiffe://example.org/workload/agent1",
                        "bb" * 32, 5)
    bad = dict(good)
    bad["issuer_signature"] = "00" * 64
    now = time.time()
    # A presented-but-bad SVID is terminal even when valid kernel
    # credentials ride along: never falls through to the weaker path.
    got = _mesh_code(lambda: mesh.admit("svc-c", svid=bad,
                                        kernel=_good_kernel(now), now=now))
    if got == "svid:svid-signature-invalid":
        return _held("bad SVID on either-route refused terminally")
    return _break("downgrade or wrong code: %s" % got)


@probe("mesh/kernel-required-ignores-valid-svid")
def _h_mesh_kernelonly():
    issuer, mesh = _mesh_triple()
    good = issuer.issue("spiffe://example.org/workload/agent1",
                        "bb" * 32, 5)
    now = time.time()
    got = _mesh_code(lambda: mesh.admit("svc-b", svid=good, now=now))
    if got == "other:channel-identity-unattested":
        return _held("valid SVID never admits on a kernel route")
    return _break("kernel route consulted the SVID: %s" % got)


@probe("mesh/svid-required-never-consults-kernel")
def _h_mesh_svidonly():
    _, mesh = _mesh_triple()
    now = time.time()
    got = _mesh_code(lambda: mesh.admit("svc-a",
                                        kernel=_good_kernel(now), now=now))
    if got == "svid:svid-missing":
        return _held("kernel material never re-routes an SVID refusal")
    return _break("svid route consulted kernel: %s" % got)


@probe("mesh/undeclared-route-default-deny")
def _h_mesh_unknown():
    _, mesh = _mesh_triple()
    got = _mesh_code(lambda: mesh.admit("no-such-route",
                                        now=time.time()))
    got2 = _mesh_code(lambda: mesh.admit(123, now=time.time()))
    if got == "svid:svid-acl-denied" and got2 == "svid:svid-acl-denied":
        return _held("undeclared/non-string routes default-deny")
    return _break("undeclared route handling wrong: %s / %s" % (got, got2))


@probe("mesh/either-falsy-svid-fail-closed")
def _h_mesh_falsy():
    _, mesh = _mesh_triple()
    # b"" is not None: it must go down the SVID seam and refuse,
    # never be treated as "no SVID presented".
    got = _mesh_code(lambda: mesh.admit("svc-c", svid=b"",
                                        now=time.time()))
    if got.startswith("svid:"):
        return _held("falsy-but-present SVID refused on the SVID seam")
    return _break("falsy SVID misrouted: %s" % got)


# ---------------------------------------------------------------------------
# BASELINE: F230-F234 seams, cross-checked only (filed OPEN, dedicated
# lanes own them). Each probe reproduces the wave-260 standing pin on
# this base; a HELD here would mean the defect was fixed incidentally
# and must be reported, never re-filed.
# ---------------------------------------------------------------------------

@probe("baseline/f230-tail-truncation-invisible-to-verify-log")
def _b_f230():
    from gov import transparency_log as tl  # noqa: E402
    seed = bytes.fromhex("cc" * 32)
    d = _tmpdir()
    log = tl.TransparencyLog(d, signing_key=seed)
    for tag in ("aa", "bb", "cc", "dd", "ee"):
        log.append(tag * 32)
    ok_before, _ = tl.TransparencyLog(
        d, public_key=bytes.fromhex(log._log_id)).verify_log()
    if not ok_before:
        return ("ERROR", "pristine log did not verify before tampering")
    for fname in (tl.LEAVES_FILE, tl.HEADS_FILE):
        path = os.path.join(d, fname)
        with open(path, encoding="utf-8") as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines[:-1]) + "\n")
    reopened = tl.TransparencyLog(d,
                                  public_key=bytes.fromhex(log._log_id))
    ok, detail = reopened.verify_log()
    conflicts = reopened.detect_equivocation()
    if ok and not conflicts:
        return _baseline("F230 still open: verify_log=True (%s) after "
                         "tail deletion" % detail)
    return _held("tail truncation now detected (F230 fixed?)")


@probe("baseline/f231-unsigned-head-counts-as-conflict")
def _b_f231():
    from gov import transparency_log as tl  # noqa: E402
    seed = bytes.fromhex("cc" * 32)
    d = _tmpdir()
    log = tl.TransparencyLog(d, signing_key=seed)
    head = log.append("ab" * 32)
    forged = dict(head)
    forged["root_hash"] = "ff" * 32
    forged["signature"] = "00" * 128
    assert not tl.verify_tree_head(forged, log._log_id)
    conflicts = log.detect_equivocation([head, forged])
    if conflicts:
        return _baseline("F231 still open: conflict from an UNSIGNED "
                         "head")
    return _held("unsigned head ignored (F231 fixed?)")


@probe("baseline/f232-operator-path-raw-oserror-escapes")
def _b_f232():
    from gov import transparency_log as tl  # noqa: E402
    seed = bytes.fromhex("cc" * 32)
    raw = []
    fd, fpath = tempfile.mkstemp(prefix="w261rt-file-", dir="/var/tmp")
    os.close(fd)
    try:
        tl.TransparencyLog(fpath, signing_key=seed)
        raw.append("init-path-is-file: no exception")
    except tl.TransparencyLogError:
        pass
    except Exception as e:  # noqa: BLE001 -- the defect under test
        raw.append("init-path-is-file: raw %s" % type(e).__name__)
    finally:
        os.unlink(fpath)
    d = _tmpdir()
    log = tl.TransparencyLog(d, signing_key=seed)
    log.append("ab" * 32)
    os.remove(os.path.join(d, tl.LEAVES_FILE))
    os.mkdir(os.path.join(d, tl.LEAVES_FILE))
    try:
        log.append("cd" * 32)
        raw.append("append-io-failure: no exception")
    except tl.TransparencyLogError:
        pass
    except Exception as e:  # noqa: BLE001 -- the defect under test
        raw.append("append-io-failure: raw %s" % type(e).__name__)
    if raw:
        return _baseline("F232 still open: " + "; ".join(raw))
    return _held("operator path raises TransparencyLogError (F232 "
                 "fixed?)")


@probe("baseline/f233-usage-never-enforced")
def _b_f233():
    issuer = sv.TestSvidIssuer(issuer_seed=bytes.fromhex("aa" * 32))
    verifier = sv.SvidVerifier({issuer.key_id: issuer.issuer_public_key},
                               "example.org")
    mesh_svid = issuer.issue("spiffe://example.org/workload/agent1",
                             "bb" * 32, 5, profile="mesh-control")
    mesh_acl = sv.MeshControl(verifier,
                              {"allow": ["spiffe://example.org/workload"]})
    admitted = mesh_acl.admit(mesh_svid)
    claims = verifier.verify(mesh_svid)
    if admitted and claims["usage"] == ["mesh-control"]:
        return _baseline("F233 still open: mesh-control SVID admitted "
                         "to a workload ACL")
    return _held("usage mismatch refused (F233 fixed?)")


@probe("baseline/f234-now-validation-path-dependent")
def _b_f234():
    issuer = sv.TestSvidIssuer(issuer_seed=bytes.fromhex("aa" * 32))
    verifier = sv.SvidVerifier({issuer.key_id: issuer.issuer_public_key},
                               "example.org")
    good = issuer.issue("spiffe://example.org/w/a", "bb" * 32, 5)
    bad_sig = dict(good)
    bad_sig["issuer_signature"] = "00" * 64

    def code_of(fn):
        try:
            fn()
        except sv.SvidError as e:
            return e.code
        return "NO-RAISE"

    paths = {
        "good": code_of(lambda: verifier.verify(good, now="yesterday")),
        "bad-sig": code_of(lambda: verifier.verify(bad_sig,
                                                   now="yesterday")),
        "missing": code_of(lambda: verifier.verify(None,
                                                   now="yesterday")),
    }
    bad = ["%s=%s" % (k, v) for k, v in paths.items()
           if v != sv.SVID_MALFORMED_CODE]
    if bad:
        return _baseline("F234 still open: " + ", ".join(bad))
    return _held("`now` validated before every refusal (F234 fixed?)")


# ---------------------------------------------------------------------------
# Green check (depth-1; honors GOV_SKIP_GREEN)
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: adjacent wave-260 batteries still green. Honors
    GOV_SKIP_GREEN (records skip, never spawns).
    """
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED (GOV_SKIP_GREEN=1)")]
    notes = []
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for battery in ("evals/w260_callauthz_probes.py",
                    "evals/w260_redteam_probes.py"):
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
    held = breaks = baselines = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s" %
                               (type(e).__name__, str(e)[:120]))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        elif verdict == "BASELINE":
            baselines += 1
        else:
            errors += 1
        print("%-8s %-55s %s" % (verdict, name, detail))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("HELD %d / BREAK %d / BASELINE %d / ERROR %d "
          "over %d probes" % (held, breaks, baselines, errors,
                               len(_PROBES)))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
