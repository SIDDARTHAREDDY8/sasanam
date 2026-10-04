"""Break-first probes for Residual Authority Replay (wave-265 probe lane).

arXiv:2609.33910 ("When Consent Outlives Context") reports approvals
granted in one execution context are replayable in adversarial
execution contexts. This battery probes Sasanam's approval artifacts
for cross-context replay at the PUBLIC seams, and distinguishes --
per probe -- "replay accepted because the artifact is intentionally
holder-scoped" (documented residual, not a finding) from "replay
accepted where the module promises context binding" (defect).

Targets (base 8b0d38b79244ed477a37cf4743f92d301f94baea, pin 1177):

A. Approval queue records (execution boundary):
   - cross-run replay -> approval_run_mismatch (F38) [expect HELD]
   - double execution -> consumed by the F39 durable claim [expect HELD]
   - expired approval (TTL) -> approval-ttl refusal [expect HELD]
   - tampered record decide -> F38 MAC refusal [expect HELD, control]
B. Signed decision packets / AuthorityProof:
   - packets are EVIDENCE, not authority: a replayed packet verifies
     as a record but grants nothing (no redeem seam) [documented]
   - AuthorityProof.check is recomputed per action; proofs are not
     redeemed [documented]
C. Wave-264 bounded mandates:
   - closed mandate double-presented -> mandate-replay [expect HELD]
   - closed mandate to a fresh verifier instance -> accepted
     (documented in-memory residual) [BASELINE, not a finding]
   - open mandate presented for a different task within bounds ->
     accepted (intended: bounds ARE the authority) [BASELINE]
D. Scope tickets / consent tokens (post-F241):
   - ticket used across tasks -> authorizes (holder capability by
     design; subject binding is opt-in) [BASELINE]
   - consent token as scope ticket -> scope-grant-tampered [HELD]
   - expired consent token -> scope-consent-expired [HELD]
E. Durable approval workflows:
   - ApprovalGranted replayed into another workflow's journal ->
     JournalCorrupted (chain break) [expect HELD]
   - double grant -> GrantRefused [expect HELD, control]

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Verdicts: HELD (attack refused / no authority leaked),
BREAK (replay succeeded where context binding is promised),
BASELINE (informational: documented holder/instance semantics),
ERROR (harness fault).

Stdlib only. Deterministic. No in-repo git subprocesses (wave-36
supply-chain probe: fail closed). Green check is depth-1 and honors
GOV_SKIP_GREEN=1.
"""

import copy
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Fixed key (not random): the cross-run probe needs both runs under the
# same log key, so the MAC verifies and the run-mismatch guard is the
# thing being tested.
os.environ.setdefault("GOV_LOG_KEY",
                      "9f" * 32)
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w265-replay-battery")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.policy import PolicyEngine  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.approvals import (  # noqa: E402
    ApprovalQueue, approval_digest_ok)
from gov.executor import ToolExecutor  # noqa: E402
from gov import decision_codes  # noqa: E402
from gov import decision_packet as dp  # noqa: E402
from gov import authority_proof as ap  # noqa: E402
from gov import bounded_mandates as bm  # noqa: E402
from gov import scoped_tool_listing as stl  # noqa: E402
from gov import durable_approval as da  # noqa: E402
from gov import decision_bom as dbom  # noqa: E402
from gov.durable_journal import JournalCorrupted  # noqa: E402

TAXONOMY_PIN = 1915 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 1: pin 1906 -> 1915 (+9 grantneg-*)

TMP_BASE = "/var/tmp/g265replay"
Path(TMP_BASE).mkdir(parents=True, exist_ok=True)

DEFAULT_POLICY = os.path.join(REPO_ROOT, "policies", "default.yaml")
_UNGOVERNED_ACK = ("synthetic test: w265 residual-authority-replay "
                   "battery; the bypass is declared, not silent")
_POST_URL = "https://synthetic.local/post"

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _baseline(detail=""):
    return ("BASELINE", detail)


# ------------------------------------------------------------------ world


def _make_run(tag, policy_path=None):
    """One executor run: unique tmpdir, default policy, minimal wiring.

    The run dir NAME is the run_id (F42, gov/approvals.py:886): it must
    be unique per run, or the cross-run guard cannot be exercised.
    """
    tmpdir = tempfile.mkdtemp(prefix="w265-%s-" % tag, dir=TMP_BASE)
    run_dir = Path(tmpdir) / ("run-" + tag)
    run_dir.mkdir()
    policy = PolicyEngine(policy_path or DEFAULT_POLICY)
    log = ActionLog(str(run_dir / "actions.jsonl"))
    approvals = ApprovalQueue(str(run_dir), log)
    ex = ToolExecutor(
        str(run_dir), policy, log, approvals,
        ledger_path=str(run_dir / "egress_ledger.jsonl"),
        ungoverned_ack=_UNGOVERNED_ACK)
    ident = ex.mint_identity("agent-1", "researcher", "tester")
    return {"tmpdir": tmpdir, "run_dir": run_dir, "ex": ex,
            "ident": ident, "log": log, "approvals": approvals}


def _queue_post(ctx):
    ex, ident, approvals = ctx["ex"], ctx["ident"], ctx["approvals"]
    r = ex.call(ident, "http_post", url=_POST_URL,
                payload={"kind": "w265-replay"})
    if r.get("status") != "queued":
        return None, "call did not queue: %r" % (r.get("status"),)
    return r["approval_id"], None


def _approve(ctx, aid):
    ctx["approvals"].decide(aid, True, reason="w265 replay probe approval",
                            decided_by="human-operator")


def _executed(ctx, aid):
    return [e for e in read_entries(str(ctx["run_dir"] / "actions.jsonl"))
            if e.get("decision") == "approved_executed"
            and e.get("approval_id") == aid]


def _refusals(ctx, aid, flag=None):
    out = [e for e in read_entries(str(ctx["run_dir"] / "actions.jsonl"))
           if e.get("event") == "approval_execution_refused"
           and e.get("approval_id") == aid]
    if flag is not None:
        out = [e for e in out if e.get("flag") == flag]
    return out


# ------------------------------------------------- A. queue approvals


@probe("queue/cross-run-replay-refused")
def _p_cross_run():
    """F38: an approval granted in run A must not execute in run B.

    The planted record's MAC verifies (same log key), so the
    run-mismatch guard -- not the integrity guard -- is what must fire.
    """
    a = _make_run("a")
    aid, err = _queue_post(a)
    if err:
        return ("ERROR", err)
    _approve(a, aid)
    b = _make_run("b")
    shutil.copy(str(a["run_dir"] / "approvals.jsonl"),
                str(b["run_dir"] / "approvals.jsonl"))
    done = b["ex"].execute_approved()
    if _executed(b, aid):
        return _break("cross-run approval EXECUTED in run B "
                      "(residual authority replay)")
    if _refusals(b, aid, flag="approval_run_mismatch"):
        return _held("cross-run replay refused approval_run_mismatch; "
                     "nothing executed")
    return ("ERROR", "no execution but no approval_run_mismatch refusal; "
                     "done=%r" % (done,))


@probe("queue/double-execution-consumed")
def _p_double_exec():
    """F39: an approved record is single-use; the durable claim must
    consume it so a second sweep cannot re-execute."""
    ctx = _make_run("dbl")
    aid, err = _queue_post(ctx)
    if err:
        return ("ERROR", err)
    _approve(ctx, aid)
    first = ctx["ex"].execute_approved()
    second = ctx["ex"].execute_approved()
    n = len(_executed(ctx, aid))
    if n == 1 and not _executed(ctx, aid)[1:]:
        return _held("executed exactly once; second sweep found nothing "
                     "to execute (done=%r/%r)" % (first, second))
    return _break("approved record executed %d times" % n)


@probe("queue/expired-approval-refused")
def _p_expired():
    """TTL: an approval older than approvals.ttl_hours must refuse at
    the sweep with the approval-ttl flag, not execute."""
    # Custom policy with a zero TTL: any positive age is expired.
    raw = Path(DEFAULT_POLICY).read_text()
    tmp = tempfile.mkdtemp(prefix="w265-pol-", dir=TMP_BASE)
    ppath = os.path.join(tmp, "policy.yaml")
    Path(ppath).write_text(raw.replace("ttl_hours: 24", "ttl_hours: 0"))
    ctx = _make_run("ttl", policy_path=ppath)
    aid, err = _queue_post(ctx)
    if err:
        return ("ERROR", err)
    _approve(ctx, aid)
    ctx["ex"].execute_approved()
    if _executed(ctx, aid):
        return _break("expired approval EXECUTED")
    hits = [e for e in read_entries(str(ctx["run_dir"] / "actions.jsonl"))
            if e.get("event") == "approval_expired"
            and e.get("approval_id") == aid]
    if hits:
        return _held("expired approval refused with approval-ttl flag")
    return ("ERROR", "no execution but no approval_expired entry")


@probe("queue/tampered-record-decide-refused")
def _p_tamper_decide():
    """Control: rewriting a pending record's args breaks the F38 keyed
    MAC, so decide() must refuse fail-closed."""
    ctx = _make_run("tamper")
    aid, err = _queue_post(ctx)
    if err:
        return ("ERROR", err)
    qpath = ctx["run_dir"] / "approvals.jsonl"
    lines = qpath.read_text().splitlines()
    rec = json.loads(lines[-1])
    rec["args"] = {"url": _POST_URL,
                   "payload": {"kind": "TAMPERED"}}
    lines[-1] = json.dumps(rec)
    qpath.write_text("\n".join(lines) + "\n")
    try:
        ctx["approvals"].decide(aid, True, reason="tamper",
                                decided_by="human-operator")
    except Exception as e:  # noqa: BLE001 -- harness classifies
        return _held("decide() on tampered record refused: %s: %s"
                     % (type(e).__name__, str(e)[:80]))
    return _break("decide() APPROVED a tampered record")


# ------------------------------------------------- E. durable journal


def _durable_world(tag):
    tmpdir = tempfile.mkdtemp(prefix="w265-dur-%s-" % tag, dir=TMP_BASE)
    jpath = os.path.join(tmpdir, "journal.jsonl")
    outdir = os.path.join(tmpdir, "outcomes")
    eng = da.Engine(jpath, outdir, audit_append=None)
    return eng, jpath, tmpdir


@probe("durable/grant-into-foreign-journal-refused")
def _p_durable_foreign():
    """An ApprovalGranted journaled in workflow W1 cannot be replayed
    into workflow W2: the hash chain breaks on load (JournalCorrupted)."""
    e1, j1, _t1 = _durable_world("w1")
    e1.request("a1", "agent-1", "digest-aaa", "http_post",
               "idem-1", ttl_seconds=3600)
    e1.grant("a1", "human-operator")
    lines = Path(j1).read_text().splitlines()
    granted = [ln for ln in lines if '"ApprovalGranted"' in ln]
    if not granted:
        return ("ERROR", "no APPROVAL_GRANTED record in W1 journal")
    e2, j2, _t2 = _durable_world("w2")
    e2.request("b1", "agent-2", "digest-bbb", "http_post",
               "idem-2", ttl_seconds=3600)
    with open(j2, "a") as f:
        f.write(granted[0] + "\n")
    try:
        da.Engine(j2, os.path.join(_t2, "outcomes2"), audit_append=None)
    except JournalCorrupted as e:
        return _held("foreign grant replay broke the chain on load: %s"
                     % str(e)[:90])
    except Exception as e:  # noqa: BLE001
        return _held("foreign grant replay refused on load: %s: %s"
                     % (type(e).__name__, str(e)[:80]))
    return _break("foreign APPROVAL_GRANTED loaded into W2's journal "
                  "without complaint")


@probe("durable/double-grant-refused")
def _p_durable_double():
    """Control: granting the same durable approval twice refuses."""
    e1, _j1, _t1 = _durable_world("dbl")
    e1.request("a1", "agent-1", "digest-aaa", "http_post",
               "idem-1", ttl_seconds=3600)
    e1.grant("a1", "human-operator")
    try:
        e1.grant("a1", "human-operator")
    except da.GrantRefused:
        return _held("second grant refused GrantRefused")
    except Exception as e:  # noqa: BLE001
        return _held("second grant refused: %s" % type(e).__name__)
    return _break("double grant journaled")


# ------------------------------------------------- B. packets / proofs


def _packet_key():
    prev = os.environ.get("GOV_DECISION_PACKET_KEY")
    seed = secrets.token_bytes(32)
    os.environ["GOV_DECISION_PACKET_KEY"] = seed.hex()
    os.environ.pop("GOV_DECISION_PACKET_KEY_FILE", None)

    def restore():
        if prev is None:
            os.environ.pop("GOV_DECISION_PACKET_KEY", None)
        else:
            os.environ["GOV_DECISION_PACKET_KEY"] = prev
    return seed, restore


def _one_packet(decision="allow"):
    """A minimal signed allow packet with its Decision BOM."""
    bom = dbom.build_bom(
        policy_id="default", policy_version="unversioned",
        policy_digest="ab" * 32, evidence_head_digest="GENESIS",
        principal={"agent_id": None, "role": None,
                   "principal": None, "run_id": None})
    return dp.build_decision_packet(
        decision=decision, boundary_declared=False,
        policy_id="default", policy_version="unversioned",
        policy_digest="ab" * 32, policy_rev_id="rev-w265-probe",
        decision_digest="ab" * 32, evidence_head_digest="GENESIS",
        bill_of_materials=bom)


@probe("packet/replay-verifies-but-grants-nothing")
def _p_packet_replay():
    """Decision packets are EVIDENCE, not authority: a signed allow
    packet built for context A verifies in context B (record
    integrity holds), but there is no product seam that converts a
    packet into execution authority -- verify returns a verdict
    tuple, never a grant."""
    seed, restore = _packet_key()
    try:
        packet = dp.sign_packet(_one_packet(), seed)
        ok, reason = dp.verify_decision_packet(packet)
        if not ok:
            return ("ERROR", "fresh packet did not verify: %s" % reason)
        # The "replay": present the packet in a different context.
        ok2, reason2 = dp.verify_decision_packet(packet)
        # No redeem seam: the public API surface of decision_packet
        # offers build/sign/verify only -- verify yields (bool, reason).
        public = [n for n in dir(dp) if not n.startswith("_")]
        redeem = [n for n in public
                  if "redeem" in n or "authorize" in n or "grant" in n]
        if ok2 and not redeem:
            return _held(
                "replayed packet verifies as a record (expected) and "
                "grants nothing: no redeem/authorize/grant seam exists "
                "on the module (public: %d fns)" % len(public))
        return ("ERROR", "unexpected: ok2=%r redeem=%r" % (ok2, redeem))
    finally:
        restore()


@probe("packet/tamper-breaks-signature")
def _p_packet_tamper():
    """Control: a tampered packet must fail verification."""
    seed, restore = _packet_key()
    try:
        packet = dp.sign_packet(_one_packet(), seed)
        p2 = copy.deepcopy(packet)
        p2["decision"]["value"] = "deny"
        ok, reason = dp.verify_decision_packet(p2)
        if not ok:
            return _held("tampered packet refused: %s" % str(reason)[:70])
        return _break("tampered packet VERIFIED")
    finally:
        restore()


@probe("proof/recomputed-not-redeemed")
def _p_proof_replay():
    """AuthorityProof.check is a pure function recomputed per action
    against the operator boundary: there is no artifact to replay.
    A proof record for action X cannot authorize action Y because no
    seam redeems proofs -- enforcement calls check() itself."""
    boundary = ap.boundary_from_dict({
        "boundary_id": "b1", "version": "1",
        "fs_read_prefixes": ["/data"],
    })
    proof_x = ap.check({"tool": "read_file", "args": {"path": "/data/x"}},
                       {}, boundary)
    proof_y = ap.check({"tool": "write_file",
                        "args": {"path": "/etc/passwd"}}, {}, boundary)
    if proof_x.verdict != ap.WITHIN:
        return ("ERROR", "within-boundary proof did not verify: %r"
                % (proof_x.verdict,))
    if proof_y.verdict == ap.WITHIN:
        return ("ERROR", "out-of-boundary action proved within")
    public = [n for n in dir(ap) if not n.startswith("_")]
    redeem = [n for n in public
              if "redeem" in n or "authorize" in n or "grant" in n]
    if not redeem:
        return _held(
            "proofs are recomputed verdicts, not redeemed artifacts: "
            "X->%s, Y->%s; no redeem seam on the module"
            % (proof_x.verdict, proof_y.verdict))
    return ("ERROR", "unexpected redeem-like API: %r" % redeem)


# ------------------------------------------------- C. bounded mandates


_MKEY = b"w264-mandate-test-key-32-bytes-0000"
_MNOW = 4000000000.0


def _mandate_world():
    iss = bm.MandateIssuer(_MKEY)
    exe = bm.MandateExecutor(_MKEY)
    ver = bm.MandateVerifier(_MKEY)
    cons = {"tools": ["db:query"], "spend_cap": 100,
            "not_before": _MNOW - 100.0, "not_after": _MNOW + 3600.0,
            "data_scopes": ["db:customers"]}
    open_m = iss.issue_open(subject="alice-subject-digest",
                            constraints=cons, now=_MNOW)
    closed = exe.close_action(open_m, "db:query", {"q": "select 1"},
                              cost=10, executed_at=_MNOW)
    return iss, exe, ver, open_m, closed


@probe("mandate/closed-replay-refused")
def _p_mandate_replay():
    """A closed mandate presented twice to the same verifier must
    refuse mandate-replay: the approval is consumed."""
    _iss, _exe, ver, open_m, closed = _mandate_world()
    first = ver.verify(open_m, closed, now=_MNOW)
    if not first.get("ok"):
        return ("ERROR", "first verify failed: %r" % (first,))
    try:
        ver.verify(open_m, closed, now=_MNOW + 1.0)
    except bm.MandateReplay:
        return _held("second presentation refused mandate-replay")
    except bm.MandateError as e:
        return _held("second presentation refused: %s" % type(e).__name__)
    return _break("closed mandate verified TWICE (replay accepted)")


@probe("mandate/closed-cross-verifier-accepted")
def _p_mandate_cross_verifier():
    """Documented residual: replay/spend/chain state is in-memory per
    verifier instance, so a FRESH verifier accepts a closed mandate
    already consumed elsewhere. The module docstring discloses this;
    deployments needing durable replay protection must persist state
    or re-verify the chain from the journal."""
    _iss, _exe, _ver, open_m, closed = _mandate_world()
    fresh = bm.MandateVerifier(_MKEY)
    res = fresh.verify(open_m, closed, now=_MNOW)
    if res.get("ok"):
        return _baseline(
            "fresh verifier accepted the closed mandate: in-memory "
            "replay state is the documented residual, not a finding")
    return ("ERROR", "fresh verifier refused: %r" % (res,))


@probe("mandate/open-cross-task-accepted")
def _p_mandate_cross_task():
    """Intended semantics: an open mandate authorizes BOUNDS, not a
    task. Presenting it for a different task within the bounds
    verifies -- the mandate's context IS its stated constraints
    (tools/spend/window/scopes). Not a finding."""
    _iss, exe, ver, open_m, _closed = _mandate_world()
    # "Task B": a different action, same bounds, same subject.
    closed_b = exe.close_action(open_m, "db:query", {"q": "select 2"},
                                cost=5, executed_at=_MNOW + 2.0)
    res = ver.verify(open_m, closed_b, now=_MNOW + 3.0)
    if res.get("ok"):
        return _baseline(
            "open mandate honored across tasks within bounds: "
            "approve-the-bounds/verify-the-actions is the designed "
            "human-not-present semantic, not a finding")
    return ("ERROR", "in-bounds cross-task verify failed: %r" % (res,))


# ------------------------------------------------- D. tickets / consent


_SCOPE_KEY = b"w265-scope-ticket-deployment-key!"
_UNIVERSE = frozenset({"files:read", "db:query"})


def _ticket_world():
    iss = stl.ScopeTicketIssuer(_SCOPE_KEY, _UNIVERSE)
    reg = stl.ToolRegistry(_UNIVERSE).bind_issuer(iss)
    reg.register("read_file", {"files:read"}, "Read a file.")
    return iss, reg


@probe("ticket/cross-task-bearer-accepted")
def _p_ticket_cross_task():
    """Documented residual: a scope ticket is a holder capability bound
    to (subject, scopes), not to a task. Using it in a different task
    authorizes -- subject binding is opt-in via expected_subject
    (F240); without it, holder semantics are the documented design."""
    iss, reg = _ticket_world()
    ticket = iss.seal("alice-subject-digest", {"files:read"}, 1000.0)
    out_a = reg.invoke(ticket, "read_file", lambda: "task-a-ran")
    out_b = reg.invoke(ticket, "read_file", lambda: "task-b-ran")
    if out_a == "task-a-ran" and out_b == "task-b-ran":
        return _baseline(
            "ticket authorized in both tasks: holder-scoped capability "
            "by design (subject binding opt-in, F240 residual)")
    return ("ERROR", "unexpected invoke results %r %r" % (out_a, out_b))


@probe("ticket/cross-protocol-refused")
def _p_ticket_cross_protocol():
    """Control (F241): a consent token presented as a scope ticket must
    refuse machine-coded under the shared key (MAC domain mismatch)."""
    _iss, reg = _ticket_world()
    ci = stl.ConsentIssuer(_SCOPE_KEY)
    url = ci.mint_consent_url("appr-1", "read_file", {"files:read"},
                              "alice-subject-digest", 1000.0,
                              "https://consent.synthetic.local")
    consent_token = url.split("?ct=", 1)[1]
    try:
        reg.invoke(consent_token, "read_file", lambda: "ran")
    except stl.ScopedListingError as e:
        if e.code == "scope-grant-tampered":
            return _held("consent-as-ticket refused scope-grant-tampered")
        return ("ERROR", "wrong code %r" % e.code)
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "raw escape: %s" % type(e).__name__)
    return _break("consent token VERIFIED as a scope ticket")


@probe("consent/expired-refused")
def _p_consent_expired():
    """Control: an expired consent token must refuse scope-consent-expired."""
    ci = stl.ConsentIssuer(_SCOPE_KEY)
    url = ci.mint_consent_url("appr-1", "read_file", {"files:read"},
                              "alice-subject-digest", 1000.0,
                              "https://consent.synthetic.local")
    token = url.split("?ct=", 1)[1]
    try:
        ci.confirm_consent(token, "appr-1", "read_file",
                           "alice-subject-digest", 1000.0 + 301.0,
                           lambda e: None)
    except stl.ScopedListingError as e:
        if e.code == "scope-consent-expired":
            return _held("expired consent refused scope-consent-expired")
        return ("ERROR", "wrong code %r" % e.code)
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "raw escape: %s" % type(e).__name__)
    return _break("expired consent token ACCEPTED")


# ------------------------------------------------------------------ main


def _green_check():
    """Depth-1 adjacent-battery check; honors GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("skipped", "GOV_SKIP_GREEN=1")]
    notes = []
    for battery in ("evals/w264_mandate_probes.py",
                    "evals/w264_f240f241f242_probes.py",
                    "evals/durable_approval_probes.py"):
        path = os.path.join(REPO_ROOT, battery)
        if not os.path.exists(path):
            notes.append((battery, "absent, skipped"))
            continue
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        try:
            p = subprocess.run(
                [sys.executable, path], env=env, cwd=REPO_ROOT,
                capture_output=True, text=True, timeout=600)
        except Exception as e:  # noqa: BLE001
            notes.append((battery, "harness error: %s" % e))
            continue
        notes.append((battery, "exit=%d %s" % (
            p.returncode, "GREEN" if p.returncode == 0 else "RED")))
    return notes


def main():
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        print("PIN MISMATCH: taxonomy has %d keys, pin is %d"
              % (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
        return 2
    held = breaks = baselines = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s"
                               % (type(e).__name__, str(e)[:160]))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        elif verdict == "BASELINE":
            baselines += 1
        else:
            errors += 1
        print("%-8s %-48s %s" % (verdict, name, detail))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("HELD %d / BREAK %d / BASELINE %d / ERROR %d over %d probes"
          % (held, breaks, baselines, errors, len(_PROBES)))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
