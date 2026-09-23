"""Wave-84 break-first probes (2026-09-23): adversarial hardening of the
governing-the-governors seam (policy-change-as-chained-governed-event).

White-box adversary: every probe is shaped from a reading of
``gov/policy_change.py`` itself (the wave-83 anti-deception pattern —
assume the adversary READ THE MANUAL and engineers around it). The
battery runs break-first against the UNMODIFIED machinery; the
pre-fix headline is recorded in BUILD_LOG.md before any fix lands.

Verdict "stopped" means the ATTACK was stopped (refused / detected /
impossible-by-construction); "break" means the governors layer failed
to catch it (a genuine miss); "residual" means a documented,
measured boundary — pinned, not filed.

  AUTHORSHIP REPLAY:
    authorship_token_replay_refused -- a token minted for change A
      (valid sig, current head as parent) presented after the head
      moves: the chain-link check refuses. The store's public API
      never consults a caller-supplied token at all.
  TIER CONFUSION:
    tier_confusion_cross_mode_refused -- dev-minted approval replayed
      onto a production change: refused. The token's tier +
      deployment_mode claims are bound into the change_id, so a
      cross-mode change_id collision is impossible and the approval's
      (change_id, policy_ref) binding does the refusing.
  GENESIS:
    second_bootstrap_lineage_lie -- F130 (filed wave-84): a second
      bootstrap() succeeds pre-fix and chains a record claiming
      prior_version GENESIS with a "<genesis>" diff marker — the real
      diff is hidden and the lineage lies. Post-fix: refused.
  BREAK-GLASS:
    breakglass_routine_use_no_authority -- repeated full ceremonies:
      every step is a chained record and the ceremony grants NO
      capability (a denied tool stays denied) — routine invocation
      only deepens the trail.
    breakglass_hollow_justification_refused -- whitespace purpose /
      finding / action-summary accepted pre-fix (the PAL
      "purpose-declared" contract weakened); refused post-fix.
    breakglass_record_tamper_breaks_chain -- flipping a breakglass
      phase in the log file breaks the chain (key-holder reforge is
      the stated wave-72/73 residual, answered by the anchor).
  DIFF SMUGGLING:
    diff_narrative_does_not_move_bytes -- a 5-rule change filed under
      purpose "typo fix": the enforced bytes are the real 5-rule
      text, the digest commits to the real diff, approvals bind the
      digest — the narrative never moves bytes.
    diff_summary_validator_boundary -- RESIDUAL PIN: the provenance
      validator accepts a hand-built record with zeroed diff_summary
      next to the real diff_digest (shape-only validation — the
      record carries no text to recompute from). The digest, not the
      summary, is what approvals bind to.
  LIFECYCLE:
    lifecycle_matrix_refused -- approve-before-propose, approve/reject
      after apply, apply after reject, double apply, propose before
      bootstrap: every invalid transition refused.
  VERSION RACING:
    version_race_second_apply_refused -- two proposals against the
      same head: the first apply moves the head; the second apply is
      refused by the token parent-link (not by prior_version — the
      link is the enforcement).
  THE LEGACY SEAM (wave-80 residual, CLOSED by wave-85 — these three
  probes are now the closure regression):
    legacy_executor_ignores_governed_change -- STOPPED: the undeclared
      legacy construction is refused at construction
      (UngovernedConstructionError); the silent legacy path is gone.
    legacy_construction_zero_ceremony -- STOPPED: attacker YAML ->
      PolicyEngine(path) -> ToolExecutor with no declaration is
      refused; the attacker rule never goes live, and the refusal is
      chained.
    legacy_blast_radius_counted -- STOPPED: re-census — every
      ToolExecutor construction site in the repo now carries the
      governed core or an explicit ungoverned_ack declaration; zero
      silent legacy sites.

All runs synthetic/local, $0. Deterministic except wall-clock ts
(never asserted on). Env hygiene restores every mutated variable in
finally.
"""

import contextlib
import io
import json
import os
import re
import secrets
import sys
import tempfile
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from gov import log as log_mod  # noqa: E402
from gov import policy_change as pc_mod  # noqa: E402
from gov import provenance as prov_mod  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.delegation_tokens import DelegationTrust  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.executor import UngovernedConstructionError  # noqa: E402
from gov.log import ActionLog  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402

RESULTS = []
SITUATIONS = {}


@contextlib.contextmanager
def _env(**pairs):
    saved = {k: os.environ.get(k) for k in pairs}
    had = {k: k in os.environ for k in pairs}
    for k, v in pairs.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k in pairs:
            if had[k]:
                os.environ[k] = saved[k]
            else:
                os.environ.pop(k, None)


@contextlib.contextmanager
def _dev_keys(enabled=True):
    """Wave-81: explicit test-key provisioning (no dev fallback)."""
    if not enabled:
        yield
        return
    import secrets as _secrets
    _saved = {n: os.environ.get(n) for n in (
        "GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")}
    _had = {n: n in os.environ for n in _saved}
    os.environ["GOV_LOG_KEY"] = _secrets.token_hex(32)
    os.environ["GOV_LOG_KEY_EPOCH"] = "test"
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)
    try:
        yield
    finally:
        for _n in _saved:
            if _had[_n]:
                os.environ[_n] = _saved[_n]
            else:
                os.environ.pop(_n, None)


@contextlib.contextmanager
def _govrun():
    old = os.environ.get("TMPDIR")
    old_cached = tempfile.tempdir
    os.environ["TMPDIR"] = "/tmp/gov-run"
    tempfile.tempdir = None
    run_tmp = tempfile.mkdtemp(prefix="w84probe-")
    try:
        yield run_tmp
    finally:
        if old is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = old
        tempfile.tempdir = old_cached
        import shutil
        shutil.rmtree(run_tmp, ignore_errors=True)


def _sit(sid):
    def deco(fn):
        def wrapper():
            try:
                with _govrun():
                    with _env(GOV_DEPLOYMENT_MODE="staging"):
                        with _dev_keys(True):
                            with redirect_stderr(io.StringIO()):
                                detail = fn()
                if not isinstance(detail, dict) or \
                        detail.get("verdict") not in (
                            "stopped", "break", "residual"):
                    detail = {"verdict": "break",
                              "note": "probe returned no verdict: %r"
                              % (detail,)}
            except Exception as exc:  # noqa: BLE001 -- one bad probe
                detail = {"verdict": "break",
                          "note": "probe raised %s: %s"
                          % (type(exc).__name__, exc)}
            RESULTS.append({"id": sid, "verdict": detail["verdict"],
                            "detail": detail})
        SITUATIONS[sid] = wrapper
        return wrapper
    return deco


def _human():
    return Ed25519Signer(secrets.token_bytes(32))


def _trust(*humans):
    ax, ux = _human(), _human()
    return DelegationTrust(
        human_keys={h.key_id: h.public_key for h in humans},
        authority_keys={ax.key_id: ax.public_key},
        user_issuer_keys={ux.key_id: ux.public_key})


_BASE = (REPO_ROOT / "policies" / "default.yaml").read_text()
_RULE = ("\n  - id: w84-probe-rule\n"
         "    effect: deny\n"
         "    match:\n"
         "      tool: delete_file\n")
_RULE2 = ("\n  - id: w84-second-rule\n"
          "    effect: deny\n"
          "    match:\n"
          "      tool: read_file\n")
_T0 = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)


def _store(mode, humans, log=None, session_id="sess-w84-probe"):
    trust = _trust(*humans)
    store = pc_mod.GovernedPolicyStore(
        deployment_mode=mode, trust=trust, log=log,
        session_id=session_id)
    store.bootstrap(_BASE, humans[0], "alice", "initial policy",
                    approver_signers=[humans[0]] +
                    ([humans[1]] if mode == "production" else []),
                    now=_T0)
    return store


def _change_records(log_path):
    out = []
    p = Path(log_path)
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        prov = e.get("prov")
        if isinstance(prov, dict) and \
                prov.get("record_type") == "policy_change":
            out.append(e)
    return out


def _breakglass_records(log_path):
    out = []
    p = Path(log_path)
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        prov = e.get("prov")
        if isinstance(prov, dict) and \
                prov.get("record_type") == "breakglass":
            out.append(e)
    return out

# ----------------------------------------------------------------------
# The battery
# ----------------------------------------------------------------------

@_sit("redteam.governors_w84.authorship_token_replay_refused")
def sit_authorship_token_replay_refused():
    """White-box: the adversary read issue_authorship_token and mints a
    VALID token for text T1 (roster key, current head as parent) — then
    tries to replay it after the chain head moves, and tries to get the
    store to consult a caller-supplied token at all.

    Must show: (1) the stale-parent token is refused by the chain-link
    check; (2) the public API never reads a caller token — propose()
    issues its own, apply() re-verifies text<->policy_ref and
    parent<->head on the STORED artifact."""
    h1 = _human()
    store = _store("dev", [h1])
    h0 = store.authorship_head()
    t1 = _BASE + _RULE
    # A valid token for a never-proposed change with text t1.
    tok = pc_mod.issue_authorship_token(
        h1, policy_ref=pc_mod.policy_digest(t1),
        prior_ref=pc_mod.policy_digest(_BASE),
        parent_token_hash=h0, author="alice",
        diff_digest="0" * 64, tier="single-human",
        deployment_mode="dev", session_id="sess-w84-probe",
        purpose="replay me", now=_T0)
    pc_mod.verify_authorship_token(tok, store.trust,
                                   expected_parent=h0)  # sanity: valid now
    # The real chain advances: propose -> approve -> apply.
    chg = store.propose(t1, h1, "alice", "real change", now=_T0)
    store.approve(chg.change_id, h1, now=_T0)
    store.apply(chg.change_id, now=_T0)
    h1head = store.authorship_head()
    if h1head == h0:
        return {"verdict": "break", "note": "head did not advance"}
    # Replay: present tok (parent h0) at the new head.
    try:
        pc_mod.verify_authorship_token(tok, store.trust,
                                       expected_parent=h1head)
    except pc_mod.AuthorshipError:
        pass
    else:
        return {"verdict": "break",
                "note": "stale-parent token verified at the new head — "
                        "the chain link does not stop replay"}
    # The store never consults caller tokens: the stored change's token
    # always binds the stored text (the binding apply() enforces).
    chg2 = store.propose(
        _BASE + _RULE2, h1, "alice", "second", now=_T0)
    if chg2.authorship_token["policy_ref"] != \
            pc_mod.policy_digest(chg2.text):
        return {"verdict": "break",
                "note": "stored token does not bind stored text"}
    return {"verdict": "stopped",
            "note": "stale-parent token refused by the chain link "
                    "(parent %s... != head %s...); no public API accepts "
                    "a caller-supplied token — propose() issues its own "
                    "and apply() re-verifies text<->policy_ref and "
                    "parent<->head on the stored artifact"
            % (h0[:8], h1head[:8])}


@_sit("redteam.governors_w84.tier_confusion_cross_mode_refused")
def sit_tier_confusion_cross_mode_refused():
    """White-box: the approval body binds (change_id, policy_ref) but
    NOT tier/deployment_mode — the w78 pin closed dev-tier replay for
    digest pins via a tier-committed body. Check the policy-change
    path independently: a dev-minted approval replayed onto a
    production change must be refused.

    The binding that does it: the authorship token's tier +
    deployment_mode claims feed the change_id (via the token ref), so
    a cross-mode change_id collision is impossible by construction."""
    h1, h2 = _human(), _human()
    trust = _trust(h1, h2)
    dstore = pc_mod.GovernedPolicyStore(
        deployment_mode="dev", trust=trust, log=None,
        session_id="sess-w84-xmode")
    pstore = pc_mod.GovernedPolicyStore(
        deployment_mode="production", trust=trust, log=None,
        session_id="sess-w84-xmode")
    # Identical in every attacker-controlled dimension: same text,
    # author, purpose, session, timestamps, proposal order.
    dstore.bootstrap(_BASE, h1, "alice", "init",
                     approver_signers=(h1,), now=_T0)
    pstore.bootstrap(_BASE, h1, "alice", "init",
                     approver_signers=(h1, h2), now=_T0)
    dchg = dstore.propose(_BASE + _RULE, h1, "alice", "xmode", now=_T0)
    pchg = pstore.propose(_BASE + _RULE, h1, "alice", "xmode", now=_T0)
    if dchg.change_id == pchg.change_id:
        return {"verdict": "break",
                "note": "cross-mode change_id collision — the tier/mode "
                        "claims are NOT bound into the change id"}
    dtier = dchg.authorship_token["claims"]["tier"]
    ptier = pchg.authorship_token["claims"]["tier"]
    if (dtier, ptier) != ("single-human", "two-person"):
        return {"verdict": "break",
                "note": "token tier claims wrong: %r / %r" % (dtier, ptier)}
    # Transplant: h2's approval minted for the DEV change, replayed
    # onto the PROD change alongside h1's legitimate prod approval.
    ap_dev = pc_mod.sign_approval(
        h2, change_id=dchg.change_id,
        policy_ref=pc_mod.policy_digest(dchg.text), now=_T0)
    pstore.approve(pchg.change_id, h1, now=_T0)
    pchg.approvals.append(ap_dev)
    try:
        pstore.apply(pchg.change_id)
    except pc_mod.TierError as e:
        if "does not bind" not in str(e):
            return {"verdict": "break",
                    "note": "refused but for the wrong reason: %s" % e}
    else:
        return {"verdict": "break",
                "note": "dev-minted approval counted toward the "
                        "production two-person tier"}
    return {"verdict": "stopped",
            "note": "dev change %s... vs prod change %s... (tier claims "
                    "%s/%s bound into the id); the transplanted approval "
                    "was refused on its (change_id, policy_ref) binding — "
                    "a single-human ceremony can never satisfy the "
                    "production tier" % (dchg.change_id[:8],
                                         pchg.change_id[:8], dtier, ptier)}


@_sit("redteam.governors_w84.second_bootstrap_lineage_lie")
def sit_second_bootstrap_lineage_lie():
    """F130 (filed wave-84): bootstrap() is the chain's GENESIS — but
    nothing stops calling it twice. Pre-fix the second bootstrap
    succeeds and chains a record claiming prior_version GENESIS with
    a "<genesis>" diff marker: the REAL diff (v2 -> attacker text) is
    hidden from reviewers and the lineage lies, while the authorship
    token's parent link quietly continues the old chain.

    Post-fix: bootstrap on a live store is refused — policy evolution
    goes through propose()."""
    h1 = _human()
    run_dir = Path(tempfile.mkdtemp(prefix="w84gen-"))
    lg = ActionLog(run_dir / "actions.jsonl")
    store = _store("dev", [h1], log=lg)
    chg = store.propose(_BASE + _RULE, h1, "alice", "tighten", now=_T0)
    store.approve(chg.change_id, h1, now=_T0)
    store.apply(chg.change_id, now=_T0)
    head_before = store.authorship_head()
    live_v2 = store.current_version()
    evil = _BASE + _RULE2
    try:
        chg2 = store.bootstrap(evil, h1, "alice", "re-genesis",
                               approver_signers=(h1,), now=_T0)
    except pc_mod.PolicyChangeError as e:
        return {"verdict": "stopped",
                "note": "second bootstrap refused: %s" % e}
    # Pre-fix: it succeeded. Show the lie in the chained record.
    recs = _change_records(run_dir / "actions.jsonl")
    applied = [r for r in recs
               if r["prov"]["policy"]["status"] == "applied"]
    genesis_claims = [r for r in applied
                      if r["prov"]["policy"]["prior_version"] == "GENESIS"]
    if len(genesis_claims) < 2:
        return {"verdict": "break",
                "note": "second bootstrap applied but the lineage lie "
                        "did not materialize as expected"}
    second = genesis_claims[1]["prov"]["policy"]
    lied_diff = second["diff_summary"]["sections_changed"] == ["<genesis>"]
    continued_chain = (chg2.authorship_token["parent_token_hash"] ==
                       head_before != "GENESIS")
    if not (lied_diff and continued_chain):
        return {"verdict": "break",
                "note": "second bootstrap applied; lie shape differs: "
                        "diff=%r parent=%s..." % (
                            second["diff_summary"].get("sections_changed"),
                            chg2.authorship_token["parent_token_hash"][:8])}
    return {"verdict": "break",
            "note": "F130: second bootstrap applied over live %s — the "
                    "chained record claims prior_version GENESIS and "
                    "diff '<genesis>' (the real v->evil diff hidden from "
                    "reviewers) while the token parent %s... quietly "
                    "continues the old chain"
            % (live_v2,
               chg2.authorship_token["parent_token_hash"][:8])}


@_sit("redteam.governors_w84.breakglass_routine_use_no_authority")
def sit_breakglass_routine_use_no_authority():
    """Break-glass as routine bypass: run the FULL ceremony three times
    back to back (declare -> activate -> use -> distinct-human
    review). Must show: every step is a chained record, the review
    gate clears properly, outstanding reviews empty — and the ceremony
    grants NO capability: a tool denied by governed policy stays
    denied through all of it. Routine invocation only deepens the
    trail; there is nothing to bypass WITH."""
    h1, h2 = _human(), _human()
    run_dir = Path(tempfile.mkdtemp(prefix="w84bg-"))
    lg = ActionLog(run_dir / "actions.jsonl")
    store = _store("dev", [h1], log=lg)
    chg = store.propose(_BASE + _RULE, h1, "alice", "deny deletes",
                        now=_T0)
    store.approve(chg.change_id, h1, now=_T0)
    store.apply(chg.change_id, now=_T0)
    ex = ToolExecutor(run_dir, store.current_engine(), lg,
                      ApprovalQueue(run_dir, lg), policy_store=store,
                      # Wave-85: wave-84 breakglass probe — the store is
                      # the subject; delegation identity not installed,
                      # so the bypass is declared and chained, never
                      # silent.
                      ungoverned_ack=(
                          "wave-84 breakglass probe: the policy store is "
                          "the subject; delegation identity not "
                          "installed"))
    ident = ex.mint_identity("bg-agent", "coder", "alice")
    r0 = ex.call(ident, "delete_file", path="notes.txt")
    if r0["status"] != "denied":
        return {"verdict": "break",
                "note": "setup: delete_file not denied: %r" % r0["status"]}
    bg = pc_mod.BreakGlass(trust=_trust(h1, h2), log=lg,
                           session_id="sess-w84-probe")
    for i in range(3):
        d = bg.declare("routine window %d" % i, 600, h1)
        bg.activate(d.declaration_id)
        bg.use(d.declaration_id, "routine override %d" % i)
        bg.review(d.declaration_id, h2, "reviewed %d" % i)
    if bg.outstanding_reviews():
        return {"verdict": "break",
                "note": "reviews outstanding after full ceremonies"}
    recs = _breakglass_records(run_dir / "actions.jsonl")
    phases = sorted(r["prov"]["breakglass"]["phase"] for r in recs)
    if len(recs) != 12 or phases != sorted(
            ["declared", "activated", "used", "reviewed"] * 3):
        return {"verdict": "break",
                "note": "ceremony trail incomplete: %d records %r"
                % (len(recs), phases)}
    r1 = ex.call(ident, "delete_file", path="notes.txt")
    if r1["status"] != "denied":
        return {"verdict": "break",
                "note": "break-glass GRANTED capability: delete_file "
                        "%r after ceremonies" % r1["status"]}
    return {"verdict": "stopped",
            "note": "3 full ceremonies -> 12 chained records, 0 "
                    "outstanding reviews; delete_file still denied "
                    "(policy w84-probe-rule) — the ceremony is evidence, "
                    "not a capability; no consumer in gov/ consults "
                    "BreakGlass, so routine invocation bypasses nothing"}


@_sit("redteam.governors_w84.breakglass_hollow_justification_refused")
def sit_breakglass_hollow_justification_refused():
    """The PAL contract is 'purpose-declared': every declaration needs
    a stated purpose, every use an action summary, every review a
    finding. White-box: declare() only checks truthiness — a
    whitespace purpose passes. Pre-fix the ceremony accepts hollow
    justifications; post-fix all three are refused."""
    h1, h2 = _human(), _human()
    bg = pc_mod.BreakGlass(trust=_trust(h1, h2), log=None,
                           session_id="sess-w84-probe")
    hollow = []
    try:
        bg.declare("   ", 600, h1)
    except pc_mod.BreakGlassError:
        pass
    else:
        hollow.append("declare accepted whitespace purpose")
    d = bg.declare("real purpose", 600, h1)
    bg.activate(d.declaration_id)
    bg.use(d.declaration_id, "did the thing")
    try:
        bg.review(d.declaration_id, h2, "  ")
    except pc_mod.BreakGlassError:
        pass
    else:
        hollow.append("review accepted whitespace finding")
    bg.review(d.declaration_id, h2, "fine")  # clear the ceremony gate
    d2 = bg.declare("real purpose 2", 600, h1)
    bg.activate(d2.declaration_id)
    try:
        bg.use(d2.declaration_id, "\t")
    except pc_mod.BreakGlassError:
        pass
    else:
        hollow.append("use accepted whitespace action summary")
    if hollow:
        return {"verdict": "break",
                "note": "hollow justifications accepted: %s"
                % "; ".join(hollow)}
    return {"verdict": "stopped",
            "note": "whitespace purpose / finding / action-summary all "
                    "refused — the purpose-declared contract holds on "
                    "all three ceremony mouths"}


@_sit("redteam.governors_w84.breakglass_record_tamper_breaks_chain")
def sit_breakglass_record_tamper_breaks_chain():
    """Break-glass record tampering: flip a breakglass phase in the log
    file (no key). The chain must break at that seq. (Key-holder
    reforge + anchor is the stated wave-72/73 residual — pinned for
    policy_change by w75's backdated probe; the shape is identical
    here.)"""
    h1, h2 = _human(), _human()
    run_dir = Path(tempfile.mkdtemp(prefix="w84bgt-"))
    lg = ActionLog(run_dir / "actions.jsonl")
    bg = pc_mod.BreakGlass(trust=_trust(h1, h2), log=lg,
                           session_id="sess-w84-probe")
    d = bg.declare("failover", 600, h1)
    bg.activate(d.declaration_id)
    bg.use(d.declaration_id, "restarted pool")
    p = run_dir / "actions.jsonl"
    lines = p.read_text(encoding="utf-8").splitlines()
    hit = False
    out = []
    for line in lines:
        e = json.loads(line)
        prov = e.get("prov")
        if isinstance(prov, dict) and \
                prov.get("record_type") == "breakglass" and \
                prov.get("breakglass", {}).get("phase") == "activated" \
                and not hit:
            prov["breakglass"]["phase"] = "used"  # the tamper
            hit = True
        out.append(json.dumps(e, ensure_ascii=True))
    p.write_text("\n".join(out) + "\n", encoding="utf-8")
    if not hit:
        return {"verdict": "break", "note": "no activated record to flip"}
    ok, broken, _count = log_mod.verify_chain(str(p))
    if ok:
        return {"verdict": "break",
                "note": "tampered breakglass record verified clean"}
    return {"verdict": "stopped",
            "note": "phase flip broke the chain at seq %r (no reforge); "
                    "key-holder reforge remains the stated residual, "
                    "answered by the anchor as in w75's backdated probe"
            % (broken,)}

@_sit("redteam.governors_w84.diff_narrative_does_not_move_bytes")
def sit_diff_narrative_does_not_move_bytes():
    """Diff smuggling, author-as-adversary: file a 5-rule change under
    the purpose string 'typo fix'. The author cannot touch the summary
    (computed by _new_change from the actual texts) — must show the
    enforced bytes are the real 5-rule text, the diff_digest commits
    to the real diff, the summary counts 5 added, and the approval
    bound policy_digest (never the narrative)."""
    h1 = _human()
    run_dir = Path(tempfile.mkdtemp(prefix="w84diff-"))
    lg = ActionLog(run_dir / "actions.jsonl")
    store = _store("dev", [h1], log=lg)
    rules = "".join(
        "\n  - id: w84-smuggle-%d\n"
        "    effect: deny\n"
        "    match:\n"
        "      tool: %s\n" % (i, tool)
        for i, tool in enumerate(
            ["delete_file", "read_file", "write_file", "send_email",
             "http_post"]))
    new_text = _BASE + rules
    chg = store.propose(new_text, h1, "alice", "typo fix", now=_T0)
    # The author-computed diff must already name all five rules.
    if chg.diff["rules_added"] != \
            sorted("w84-smuggle-%d" % i for i in range(5)):
        return {"verdict": "break",
                "note": "diff missed rules: %r" % chg.diff["rules_added"]}
    store.approve(chg.change_id, h1, now=_T0)
    engine = store.apply(chg.change_id, now=_T0)
    # NOTE: engine.policy_hash is sha256 of the RAW text bytes while
    # policy_digest() is the canonical-meaning digest — two different
    # digests for two purposes (engine identity vs approval binding).
    # The enforced-bytes claim is checked against the raw bytes.
    import hashlib as _hl2
    if engine.policy_hash != \
            _hl2.sha256(new_text.encode("utf-8")).hexdigest():
        return {"verdict": "break",
                "note": "enforced bytes are not the authored text"}
    recs = _change_records(run_dir / "actions.jsonl")
    applied = [r for r in recs
               if r["prov"]["policy"]["status"] == "applied"]
    if not applied:
        return {"verdict": "break", "note": "no applied record"}
    pol = applied[-1]["prov"]["policy"]
    import hashlib as _hl
    expect_digest = _hl.sha256(
        pc_mod._canonical(chg.diff)).hexdigest()
    if pol["diff_digest"] != expect_digest:
        return {"verdict": "break",
                "note": "record diff_digest != digest of the real diff"}
    if pol["diff_summary"].get("rules_added") != 5:
        return {"verdict": "break",
                "note": "record summary hides rules: %r"
                % pol["diff_summary"]}
    if pol["policy_digest"] != pc_mod.policy_digest(new_text):
        return {"verdict": "break",
                "note": "record policy_digest != enforced bytes digest"}
    return {"verdict": "stopped",
            "note": "purpose said 'typo fix'; enforced bytes are the "
                    "5-rule text (digest %s...), diff_digest commits to "
                    "the real 5-rule diff, summary counts 5 added — the "
                    "approval bound the digest, never the narrative"
            % pol["policy_digest"][:12]}


@_sit("redteam.governors_w84.diff_summary_validator_boundary")
def sit_diff_summary_validator_boundary():
    """RESIDUAL PIN (documented boundary, not a miss): hand-build a
    policy_change record with a LYING diff_summary (zeroed counts)
    next to the real diff_digest and append it — the provenance
    validator accepts it (shape-only: the record carries no text to
    recompute from). Anyone with log-append can already write any
    valid-shaped claim (purpose strings are human-stated too); the
    enforced binding is digest<-approvals, and the summary is
    convenience, never authority."""
    h1 = _human()
    run_dir = Path(tempfile.mkdtemp(prefix="w84diffv-"))
    lg = ActionLog(run_dir / "actions.jsonl")
    real_diff, real_digest = pc_mod.diff_policies(_BASE, _BASE + _RULE)
    assert real_diff["rules_added"] == ["w84-probe-rule"]
    rec = pc_mod.build_policy_change_record(
        session_id="sess-w84-probe",
        session_open="2026-09-23T12:00:00+00:00",
        policy_version="v9.deadbeef", change_id="c" * 32,
        new_version="v9.deadbeef", prior_version="v8.cafef00d",
        status="proposed", tier="single-human", author_key_id="k1",
        approver_key_ids=[], policy_digest="d" * 64,
        prior_digest="p" * 64, diff_digest=real_digest,
        diff_summary={"rules_added": 0, "rules_removed": 0,
                      "rules_changed": 0, "sections_changed": []},
        purpose="nothing to see here", authorship_ref="r" * 64,
        approvals=[])
    try:
        prov_mod.append_provenance(lg, rec)
    except Exception as e:
        return {"verdict": "break",
                "note": "validator refused the lying summary — boundary "
                        "pin wrong: %s: %s" % (type(e).__name__, e)}
    return {"verdict": "residual",
            "note": "validator accepted diff_summary {added:0} beside "
                    "the real diff_digest %s... — shape-only validation "
                    "by construction (no text in the record to recompute "
                    "from). Documented boundary: approvals bind "
                    "policy_digest/diff_digest, never the summary; "
                    "human-stated fields are claims, not proofs"
            % real_digest[:12]}


@_sit("redteam.governors_w84.lifecycle_matrix_refused")
def sit_lifecycle_matrix_refused():
    """Lifecycle violations: every invalid transition must raise
    PolicyChangeError — approve-before-propose (unknown id), approve
    after reject, reject after apply, apply after reject, double
    apply, propose before bootstrap, approve after apply."""
    h1 = _human()
    store = _store("dev", [h1])
    bad = []

    def expect_refused(name, fn):
        try:
            fn()
        except pc_mod.PolicyChangeError:
            return
        except Exception as e:  # noqa: BLE001
            bad.append("%s raised %s not PolicyChangeError"
                       % (name, type(e).__name__))
            return
        bad.append("%s was NOT refused" % name)

    expect_refused("approve-before-propose",
                   lambda: store.approve("no-such-change", h1))
    expect_refused("propose-before-bootstrap",
                   lambda: pc_mod.GovernedPolicyStore(
                       deployment_mode="dev", trust=store.trust,
                       log=None,
                       session_id="s").propose(_BASE + _RULE, h1,
                                               "alice", "x"))
    c1 = store.propose(_BASE + _RULE, h1, "alice", "c1", now=_T0)
    store.reject(c1.change_id, "nope")
    expect_refused("approve-after-reject",
                   lambda: store.approve(c1.change_id, h1))
    expect_refused("apply-after-reject",
                   lambda: store.apply(c1.change_id))
    c2 = store.propose(_BASE + _RULE2, h1, "alice", "c2", now=_T0)
    store.approve(c2.change_id, h1)
    store.apply(c2.change_id)
    expect_refused("double-apply", lambda: store.apply(c2.change_id))
    expect_refused("reject-after-apply",
                   lambda: store.reject(c2.change_id, "late"))
    expect_refused("approve-after-apply",
                   lambda: store.approve(c2.change_id, h1))
    if bad:
        return {"verdict": "break",
                "note": "lifecycle holes: %s" % "; ".join(bad)}
    return {"verdict": "stopped",
            "note": "7/7 invalid transitions refused "
                    "(approve-before-propose, propose-before-bootstrap, "
                    "approve/apply-after-reject, double-apply, "
                    "reject/approve-after-apply)"}


@_sit("redteam.governors_w84.version_race_second_apply_refused")
def sit_version_race_second_apply_refused():
    """Version racing: two proposals against the same head (both
    tokens parented at H0). The first apply moves the head; the
    second apply must be refused — by the token parent-link, not by
    prior_version (the link is the enforcement; prior_version is
    descriptive). Version ids must stay unique."""
    h1 = _human()
    store = _store("dev", [h1])
    h0 = store.authorship_head()
    a = store.propose(_BASE + _RULE, h1, "alice", "race A", now=_T0)
    b = store.propose(_BASE + _RULE2, h1, "alice", "race B", now=_T0)
    if a.authorship_token["parent_token_hash"] != h0 or \
            b.authorship_token["parent_token_hash"] != h0:
        return {"verdict": "break",
                "note": "concurrent proposals not parented at the head"}
    store.approve(a.change_id, h1, now=_T0)
    store.approve(b.change_id, h1, now=_T0)
    store.apply(a.change_id, now=_T0)
    va = store.current_version()
    try:
        store.apply(b.change_id)
    except pc_mod.AuthorshipError as e:
        if "parent_token_hash" not in str(e):
            return {"verdict": "break",
                    "note": "stale apply refused, wrong reason: %s" % e}
    else:
        return {"verdict": "break",
                "note": "stale proposal applied over the new head — "
                        "version fork"}
    if b.status != "proposed":
        return {"verdict": "break",
                "note": "loser status %r, expected proposed" % b.status}
    if store.current_version() != va:
        return {"verdict": "break", "note": "live version moved"}
    return {"verdict": "stopped",
            "note": "A applied (%s); B refused by the token parent-link "
                    "(parent H0 != head %s...) — the chain stays linear; "
                    "prior_version was never consulted"
            % (va, store.authorship_head()[:8])}


@_sit("redteam.governors_w84.legacy_executor_ignores_governed_change")
def sit_legacy_executor_ignores_governed_change():
    """CLOSED by wave-85: the legacy construction this probe used to
    measure — ToolExecutor(run_dir, PolicyEngine(path), ...) with NO
    policy_store and NO declaration — is now REFUSED at construction
    (UngovernedConstructionError), before anything executes. The
    "governed apply silently ineffective on the legacy path" residual
    cannot be reached anymore: there is no silent legacy path, only
    the refused one and the declared (ack'd, chained, non-production)
    one."""
    run_dir = Path(tempfile.mkdtemp(prefix="w84leg-"))
    policy_file = run_dir / "p.yaml"
    policy_file.write_text(_BASE)
    lg = ActionLog(run_dir / "actions.jsonl")
    legacy_engine = PolicyEngine(str(policy_file))
    try:
        ToolExecutor(run_dir, legacy_engine, lg,
                     ApprovalQueue(run_dir, lg))  # NO policy_store, NO ack
    except UngovernedConstructionError as e:
        refusals = [e_ for e_ in
                    log_mod.read_entries(run_dir / "actions.jsonl")
                    if e_.get("event") == "ungoverned_bypass_refused"]
        if not refusals:
            return {"verdict": "break",
                    "note": "refused but the refusal left no chained "
                            "record: %s" % (e,)}
        return {"verdict": "stopped",
                "note": "undeclared legacy construction refused at "
                        "construction (%s); refusal chained as "
                        "ungoverned_bypass_refused" % (e,)}
    return {"verdict": "break",
            "note": "undeclared legacy construction was NOT refused — "
                    "the wave-84 seam is open again"}


@_sit("redteam.governors_w84.legacy_construction_zero_ceremony")
def sit_legacy_construction_zero_ceremony():
    """CLOSED by wave-85 (the seam's sharp edge, blunted): attacker YAML
    -> PolicyEngine(path) -> ToolExecutor with no store and no
    declaration is now REFUSED at construction
    (UngovernedConstructionError) — the attacker-chosen rule never goes
    live, and the refusal itself is chained. Zero ceremony is gone;
    the only non-refused path is the declared one (ack'd, chained,
    non-production)."""
    run_dir = Path(tempfile.mkdtemp(prefix="w84leg0-"))
    attacker_file = run_dir / "evil.yaml"
    attacker_file.write_text(
        _BASE + "\n  - id: attacker-rule\n"
        "    effect: deny\n"
        "    match:\n"
        "      tool: delete_file\n")
    lg = ActionLog(run_dir / "actions.jsonl")
    try:
        ToolExecutor(run_dir, PolicyEngine(str(attacker_file)), lg,
                     ApprovalQueue(run_dir, lg))  # NO store, NO ack
    except UngovernedConstructionError as e:
        entries = log_mod.read_entries(run_dir / "actions.jsonl")
        n_changes = len([e_ for e_ in entries
                         if isinstance(e_.get("prov"), dict)
                         and e_.get("prov", {}).get("record_type")
                         == "policy_change"])
        refused = [e_ for e_ in entries
                   if e_.get("event") == "ungoverned_bypass_refused"]
        if n_changes != 0:
            return {"verdict": "break",
                    "note": "refused but policy_change records exist: %d"
                            % n_changes}
        if not refused:
            return {"verdict": "break",
                    "note": "refused but the refusal left no chained "
                            "record"}
        return {"verdict": "stopped",
                "note": "attacker-rule never went live: undeclared "
                        "construction refused (%s); refusal chained; 0 "
                        "policy_change records" % (e,)}
    return {"verdict": "break",
            "note": "undeclared attacker-policy construction was NOT "
                    "refused — the wave-84 sharp edge is open again"}


@_sit("redteam.governors_w84.legacy_blast_radius_counted")
def sit_legacy_blast_radius_counted():
    """CLOSED by wave-85 — the re-measured blast radius: census every
    *.py in the repo for REAL ToolExecutor( construction calls (AST,
    not text) and require each containing file to carry either the
    governed core (policy_store= AND delegation_context=) or an
    explicit ungoverned_ack= declaration. The wave-84 posture ("the
    default deployment posture is ungoverned") is gone: every site is
    either governed or declared-and-chained.

    Excluded: this battery's own files (w84) and the wave-85 battery
    (w85), whose refusal probes deliberately construct WITHOUT an ack
    inside try/except to prove the refusal fires."""
    import ast as _ast
    skip = lambda p: ("w84" in p.name) or ("w85" in p.name)  # noqa: E731
    violators = []
    counted = 0
    for p in sorted(REPO_ROOT.rglob("*.py")):
        if skip(p):
            continue
        try:
            tree = _ast.parse(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        has_call = any(
            isinstance(n, _ast.Call) and (
                (isinstance(n.func, _ast.Name)
                 and n.func.id == "ToolExecutor") or
                (isinstance(n.func, _ast.Attribute)
                 and n.func.attr == "ToolExecutor"))
            for n in _ast.walk(tree))
        if not has_call:
            continue
        counted += 1
        text = p.read_text(encoding="utf-8")
        governed_core = ("policy_store=" in text
                         and "delegation_context=" in text)
        declared = "ungoverned_ack=" in text
        if not (governed_core or declared):
            violators.append(str(p.relative_to(REPO_ROOT)))
    if violators:
        return {"verdict": "break",
                "note": "%d files construct ToolExecutor with neither "
                        "the governed core nor a declared ack: %r"
                        % (len(violators), violators)}
    return {"verdict": "stopped",
            "note": "census: %d files construct ToolExecutor; every one "
                    "carries the governed core or an explicit "
                    "ungoverned_ack declaration — zero silent legacy "
                    "sites" % counted}


def main():
    for sid in sorted(SITUATIONS):
        SITUATIONS[sid]()
    n_hold = sum(1 for r in RESULTS if r["verdict"] == "stopped")
    n_res = sum(1 for r in RESULTS if r["verdict"] == "residual")
    n_miss = sum(1 for r in RESULTS if r["verdict"] not in (
        "stopped", "residual"))
    for r in RESULTS:
        print("%-62s %s  %s" % (r["id"], r["verdict"],
                                r["detail"].get("note", "")))
    print("w84 battery: %d HOLD / %d RESIDUAL / %d MISS|ERROR"
          % (n_hold, n_res, n_miss))
    return 1 if n_miss else 0


if __name__ == "__main__":
    sys.exit(main())
