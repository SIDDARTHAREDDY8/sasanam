"""Wave-75 break-first probes (2026-09-22): governing the governors.

Policy-change control: who changed the rules, when, chained + anchored
like everything else. Break-first: every attack probe must end with
the governors layer refusing or the attack being impossible by
construction. Verdict "stopped" means the ATTACK was stopped
(refused/detected/impossible); "break" means the governors layer
failed to catch it.

  SILENT REWRITE:
    silent_rewrite_impossible -- rewrite the policy YAML on disk
      mid-run: the live engine on the governed path must not move
      (no reload-from-disk path exists). Impossible-by-construction.
  FORGED AUTHORSHIP:
    forged_authorship_refused -- a change authored by a non-roster key
      must be refused at propose time (Ed25519, roster-only verify).
  TIER BYPASS:
    tier_bypass_refused -- a production change with only the author's
      approval must be refused at apply (the nuclear rule).
  APPROVER IMPERSONATION:
    same_key_twice_refused -- the author's key twice must not count as
      two-person; distinct KEYS are required.
  BREAK-GLASS:
    breakglass_undeclared_use -- use without a declaration: refused.
    breakglass_expired_use -- use after TTL: refused AND the expiry is
      appended as a chained record (loud, not silent).
    breakglass_review_gate -- a new declaration cannot activate while a
      prior use is unreviewed; the gate clears after review.
  BACKDATED CHANGE (the wave-73 residual shape):
    backdated_change_flagged -- a key-holder rewrites a chained
      policy_change record (author + timestamp backdated) with valid
      reforged MACs: in-chain verification passes (stated residual),
      but the anchor catches the rewrite -- the epoch is downgraded to
      operator-attested-only with head_match False.
  IN-FLIGHT PINNING:
    inflight_version_pinned -- apply a new version between two calls:
      each decision record must carry the digest of the engine that
      decided it ("which rule decided this" stays answerable).

All runs synthetic/local, $0. Deterministic except wall-clock ts
(never asserted on). Env hygiene restores every mutated variable and
the gov.log dev flags in finally.
"""

import contextlib
import io
import json
import os
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
from gov import anchor_backend as ab_mod  # noqa: E402
from gov import anchorer as anchorer_mod  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.delegation_tokens import DelegationTrust  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.log import ActionLog  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402

RESULTS = []
SITUATIONS = {}

_KEY_ENV = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE",
            "GOV_DEPLOYMENT_MODE", "GOV_KEYRING_FILE")


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
    """Wave-81: explicit test-key provisioning.

    Replaces the deleted gov.log dev-key opt-in. With enabled=True,
    yields with an explicit random GOV_LOG_KEY/GOV_LOG_KEY_EPOCH set
    and GOV_LOG_KEY_ARCHIVE cleared, restoring everything afterwards.
    enabled=False is a plain passthrough (no key provisioned).
    """
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
    run_tmp = tempfile.mkdtemp(prefix="w75probe-")
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
                        detail.get("verdict") not in ("stopped", "break"):
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
_RULE = ("\n  - id: w75-probe-rule\n"
         "    effect: deny\n"
         "    match:\n"
         "      tool: delete_file\n")


def _store(mode, humans, log=None):
    trust = _trust(*humans)
    store = pc_mod.GovernedPolicyStore(
        deployment_mode=mode, trust=trust, log=log,
        session_id="sess-w75-probe")
    store.bootstrap(_BASE, humans[0], "alice", "initial policy",
                    approver_signers=[humans[0]] +
                    ([humans[1]] if mode == "production" else []))
    return store


def _reforge_with_key(log_path, mutate):
    """Key-holder rewrite: mutate entries, recompute every MAC (chain +
    checkpoint sidecar) with the dev key -- the wave-72/73 full
    key-holder model."""
    key, epoch = log_mod._active_key()
    p = Path(log_path)
    entries = [json.loads(l) for l in
               p.read_text(encoding="utf-8").splitlines() if l.strip()]
    mutate(entries)
    prev = log_mod.GENESIS
    new_hashes = {}
    for i, e in enumerate(entries, 1):
        e["seq"] = i
        e["prev_hash"] = prev
        e["hash"] = log_mod._compute_mac(
            key, e.get("key_epoch", epoch), prev, log_mod._canonical(e))
        prev = e["hash"]
        new_hashes[i] = e["hash"]
    p.write_text("\n".join(json.dumps(e, ensure_ascii=True)
                           for e in entries) + "\n",
                 encoding="utf-8")
    cp_path = p.parent / "checkpoints.jsonl"
    if cp_path.exists():
        out = []
        for line in cp_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            cp = json.loads(line)
            cs = cp.get("seq")
            if isinstance(cs, int) and cs in new_hashes:
                cp = dict(cp)
                cp["hash"] = new_hashes[cs]
                cp["mac"] = log_mod._checkpoint_mac(
                    key, cp.get("key_epoch", epoch), cs, new_hashes[cs],
                    log_mod._pin_gen_of(cp))
            out.append(cp)
        cp_path.write_text("\n".join(json.dumps(c, ensure_ascii=True)
                                     for c in out) + "\n",
                           encoding="utf-8")


def _anchor_key(n=9):
    seed = bytes([n & 0xFF]) * 32
    pub = ab_mod.anchor_pubkey(seed)
    return {"seed": seed, "key_id": ab_mod.anchor_key_id(pub),
            "pubkey_hex": pub.hex(), "dev": True}


class _Ctx:
    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="w75probe-ctx-"))
        self.anchorers = []

    def log(self):
        return ActionLog(str(self.dir / "actions.jsonl"))

    def entries(self):
        p = self.dir / "actions.jsonl"
        if not p.exists():
            return []
        return [json.loads(l) for l in
                p.read_text(encoding="utf-8").splitlines() if l.strip()]

    def anchorer(self, lg, backend, **kw):
        kw.setdefault("policy", anchorer_mod.AnchorPolicy(
            records_per_epoch=10 ** 9, seconds_per_epoch=None,
            anchor_on_close=False))
        kw.setdefault("anchor_key", None)
        kw.setdefault("warn", lambda m: None)
        a = anchorer_mod.Anchorer(lg, backend, **kw)
        self.anchorers.append(a)
        return a

    def anchor_now(self, a):
        if a.maybe_anchor(force=True) != "queued":
            return None
        a._queue.join()
        recs = [e for e in self.entries()
                if e.get("event") == anchorer_mod.ANCHOR_RECEIPT_EVENT]
        return recs[-1] if recs else None

    def close(self):
        for a in self.anchorers:
            try:
                a.close(timeout=10)
            except Exception:
                pass
        self.anchorers = []
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)


# ----------------------------------------------------------------------
# The battery
# ----------------------------------------------------------------------

@_sit("redteam.governors_w75.silent_rewrite_impossible")
def sit_silent_rewrite_impossible():
    """Rewrite the policy YAML on disk mid-run. On the governed path
    the live engine must not move: no reload-from-disk code path
    exists, so the silent rewrite is impossible-by-construction."""
    h1 = _human()
    policy_file = Path(tempfile.mkdtemp(prefix="w75p-")) / "p.yaml"
    policy_file.write_text(_BASE)
    run_dir = Path(tempfile.mkdtemp(prefix="w75e-"))
    lg = ActionLog(run_dir / "actions.jsonl")
    store = _store("dev", [h1], log=lg)
    ex = ToolExecutor(run_dir, PolicyEngine(str(policy_file)), lg,
                      ApprovalQueue(run_dir, lg), policy_store=store,
                      # Wave-85: wave-75 governors battery — the policy
                      # store is the subject; delegation identity not
                      # installed, so the bypass is declared and chained,
                      # never silent.
                      ungoverned_ack=(
                          "wave-75 governors battery: the policy store is "
                          "the subject; delegation identity not "
                          "installed"))
    before = ex._resolve_engine().policy_hash
    verdict_before = ex._resolve_engine().evaluate(
        {"tool": "delete_file", "role": "coder"}, {})
    # The attacker rewrites the file to allow-all.
    policy_file.write_text(
        "version: 2\nroles:\n  coder: [delete_file]\n"
        "policies:\n  - id: allow-all\n"
        "    effect: allow\n"
        "    match:\n"
        "      tool: delete_file\n")
    after = ex._resolve_engine().policy_hash
    verdict_after = ex._resolve_engine().evaluate(
        {"tool": "delete_file", "role": "coder"}, {})
    if after != before or verdict_after.policy_id == "allow-all":
        return {"verdict": "break",
                "note": "disk rewrite moved the live engine"}
    return {"verdict": "stopped",
            "note": "disk rewrite had no effect: live engine digest "
                    "%s unchanged, delete_file verdict %s unchanged "
                    "(impossible-by-construction: no reload-from-disk "
                    "path)" % (before[:12], verdict_before.policy_id)}


@_sit("redteam.governors_w75.forged_authorship_refused")
def sit_forged_authorship_refused():
    h1, attacker = _human(), _human()
    store = _store("dev", [h1])
    try:
        store.propose(_BASE + _RULE, attacker, "mallory", "evil")
    except pc_mod.AuthorshipError:
        return {"verdict": "stopped",
                "note": "propose by a non-roster key refused at propose "
                        "time (Ed25519: verifier holds only roster pubs)"}
    return {"verdict": "break",
            "note": "non-roster authorship was accepted"}


@_sit("redteam.governors_w75.tier_bypass_refused")
def sit_tier_bypass_refused():
    h1, h2 = _human(), _human()
    store = _store("production", [h1, h2])
    chg = store.propose(_BASE + _RULE, h1, "alice", "prod rule")
    store.approve(chg.change_id, h1)  # single-human on production
    try:
        store.apply(chg.change_id)
    except pc_mod.TierError:
        return {"verdict": "stopped",
                "note": "production change with one approval refused "
                        "at apply (the nuclear rule)"}
    return {"verdict": "break", "note": "tier bypass was applied"}


@_sit("redteam.governors_w75.same_key_twice_refused")
def sit_same_key_twice_refused():
    h1, h2 = _human(), _human()
    store = _store("production", [h1, h2])
    chg = store.propose(_BASE + _RULE, h1, "alice", "prod rule")
    store.approve(chg.change_id, h1)
    store.approve(chg.change_id, h1)  # same key twice
    try:
        store.apply(chg.change_id)
    except pc_mod.TierError:
        return {"verdict": "stopped",
                "note": "same human key twice refused as two-person "
                        "(distinct KEYS required, not signatures)"}
    return {"verdict": "break",
            "note": "approver impersonation counted as two-person"}


@_sit("redteam.governors_w75.breakglass_undeclared_use")
def sit_breakglass_undeclared_use():
    h1, h2 = _human(), _human()
    bg = pc_mod.BreakGlass(trust=_trust(h1, h2), log=None,
                           session_id="sess-w75-probe")
    try:
        bg.use("bg-999999", "sneaky override")
    except pc_mod.BreakGlassError:
        return {"verdict": "stopped",
                "note": "use without a declaration refused (and "
                        "unrecorded — there is nothing to dual-record)"}
    return {"verdict": "break", "note": "undeclared use was allowed"}


@_sit("redteam.governors_w75.breakglass_expired_use")
def sit_breakglass_expired_use():
    h1, h2 = _human(), _human()
    ctx = _Ctx()
    try:
        lg = ctx.log()
        bg = pc_mod.BreakGlass(trust=_trust(h1, h2), log=lg,
                               session_id="sess-w75-probe")
        t0 = datetime(2026, 9, 22, 12, 0, 0, tzinfo=timezone.utc)
        d = bg.declare("short window", 60, h1, now=t0)
        bg.activate(d.declaration_id, now=t0 + timedelta(seconds=30))
        try:
            bg.use(d.declaration_id, "too late",
                   now=t0 + timedelta(seconds=120))
        except pc_mod.BreakGlassError:
            pass
        else:
            return {"verdict": "break",
                    "note": "post-expiry use was allowed"}
        phases = [e["prov"]["breakglass"]["phase"] for e in ctx.entries()
                  if isinstance(e.get("prov"), dict)
                  and e["prov"].get("record_type") == "breakglass"]
        if "expired" not in phases:
            return {"verdict": "break",
                    "note": "expiry was refused but not chained loudly"}
        return {"verdict": "stopped",
                "note": "post-expiry use refused AND the expiry is a "
                        "chained record (phases seen: %s)" % phases}
    finally:
        ctx.close()


@_sit("redteam.governors_w75.breakglass_review_gate")
def sit_breakglass_review_gate():
    h1, h2 = _human(), _human()
    bg = pc_mod.BreakGlass(trust=_trust(h1, h2), log=None,
                           session_id="sess-w75-probe")
    d = bg.declare("first", 3600, h1)
    bg.activate(d.declaration_id)
    bg.use(d.declaration_id, "did the thing")
    d2 = bg.declare("second", 3600, h1)
    try:
        bg.activate(d2.declaration_id)
    except pc_mod.BreakGlassError:
        pass
    else:
        return {"verdict": "break",
                "note": "new declaration activated with review pending"}
    bg.review(d.declaration_id, h2, "justified")
    bg.activate(d2.declaration_id)
    return {"verdict": "stopped",
            "note": "ceremony gate held until the required review "
                    "landed, then cleared"}


@_sit("redteam.governors_w75.backdated_change_flagged")
def sit_backdated_change_flagged():
    """Key-holder backdates a chained policy_change record (author +
    timestamp rewritten) with valid reforged MACs. In-chain
    verification passes (stated residual -- the chain cannot catch a
    key-holder backdate), but the anchor catches the rewrite: the
    epoch is downgraded to operator-attested-only with head_match
    False (the wave-73 backdate lesson applied to governor events)."""
    h1 = _human()
    ctx = _Ctx()
    try:
        lg = ctx.log()
        store = _store("dev", [h1], log=lg)
        chg = store.propose(_BASE + _RULE, h1, "alice", "probe rule")
        store.approve(chg.change_id, h1)
        store.apply(chg.change_id)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        backend = ab_mod.FakeWitness(clock=lambda: now.isoformat())
        a = ctx.anchorer(lg, backend, anchor_key=_anchor_key())
        if ctx.anchor_now(a) is None:
            return {"verdict": "break",
                    "note": "anchoring itself failed"}
        rep0 = anchorer_mod.audit_anchors(
            str(ctx.dir / "actions.jsonl"), backend)
        if not rep0["epochs"] or rep0["epochs"][0]["grade"] != \
                anchorer_mod.GRADE_ANCHORED:
            return {"verdict": "break",
                    "note": "epoch did not anchor pre-attack"}
        # Key-holder backdate: rewrite the applied policy_change
        # record's author + backdate its log timestamp, reforge MACs.
        backdated = (now - timedelta(days=30)).isoformat()

        def mutate(entries):
            for e in entries:
                prov = e.get("prov")
                if not isinstance(prov, dict):
                    continue
                if prov.get("record_type") == "policy_change" and \
                        prov.get("policy", {}).get("status") == "applied":
                    prov["policy"]["author_key_id"] = "attacker-key"
                    prov["policy"]["purpose"] = "backdated rewrite"
                    e["ts"] = backdated

        _reforge_with_key(str(ctx.dir / "actions.jsonl"), mutate)
        verdict = log_mod._verify(str(ctx.dir / "actions.jsonl"))
        residual_pinned = verdict["ok"]
        rep = anchorer_mod.audit_anchors(
            str(ctx.dir / "actions.jsonl"), backend)
        ep = rep["epochs"][0] if rep["epochs"] else {}
        caught = (ep.get("grade") == anchorer_mod.GRADE_OPERATOR_ONLY
                  and ep.get("checks", {}).get("head_match") is False)
        if not caught:
            return {"verdict": "break",
                    "note": "key-holder policy backdate survived the "
                            "anchor too: %r" % (ep,)}
        return {"verdict": "stopped",
                "note": "in-chain residual pinned (reforged chain "
                        "verifies: %s); anchor caught the rewrite "
                        "(head_match False, grade "
                        "operator-attested-only)" % residual_pinned}
    finally:
        ctx.close()


@_sit("redteam.governors_w75.inflight_version_pinned")
def sit_inflight_version_pinned():
    """Apply a new policy version between two governed calls, through a
    REAL ToolExecutor.call() each time: each decision record must carry
    the digest of the engine that decided it, so 'which rule decided
    this' stays answerable across the swap. The verdict itself moves
    with the version (delete_file flips executed -> denied)."""
    h1 = _human()
    run_dir = Path(tempfile.mkdtemp(prefix="w75pin-"))
    lg = ActionLog(run_dir / "actions.jsonl")
    store = _store("dev", [h1], log=lg)
    ex = ToolExecutor(run_dir, store.current_engine(), lg,
                      ApprovalQueue(run_dir, lg), policy_store=store,
                      # Wave-85: wave-75 governors battery — the policy
                      # store is the subject; delegation identity not
                      # installed, so the bypass is declared and chained,
                      # never silent.
                      ungoverned_ack=(
                          "wave-75 governors battery: the policy store is "
                          "the subject; delegation identity not "
                          "installed"))
    ident = ex.mint_identity("pin-agent", "coder", "alice")
    v1_digest = store.current_engine().policy_hash
    r1 = ex.call(ident, "delete_file", path="notes.txt")
    if r1["status"] != "executed":
        return {"verdict": "break",
                "note": "pre-swap call did not execute: %r" % r1["status"]}
    chg = store.propose(_BASE + _RULE, h1, "alice", "pin probe")
    store.approve(chg.change_id, h1)
    store.apply(chg.change_id)
    v2_digest = store.current_engine().policy_hash
    if v1_digest == v2_digest:
        return {"verdict": "break", "note": "swap did not change digest"}
    r2 = ex.call(ident, "delete_file", path="notes.txt")
    if r2["status"] != "denied" or r2.get("policy_id") != "w75-probe-rule":
        return {"verdict": "break",
                "note": "post-swap verdict did not move with the version: "
                        "%r %r" % (r2["status"], r2.get("policy_id"))}
    ents = {e["seq"]: e
            for e in log_mod.read_entries(run_dir / "actions.jsonl")}
    e1, e2 = ents[r1["seq"]], ents[r2["seq"]]
    if e1.get("policy_hash") != v1_digest:
        return {"verdict": "break",
                "note": "pre-swap decision record does not name the "
                        "v1 engine (ph=%r)" % str(e1.get("policy_hash"))[:12]}
    if e2.get("policy_hash") != v2_digest:
        return {"verdict": "break",
                "note": "post-swap decision record does not name the "
                        "v2 engine (ph=%r)" % str(e2.get("policy_hash"))[:12]}
    # The applied store record names the live version explicitly.
    recs = [e for e in
            (json.loads(l) for l in
             (run_dir / "actions.jsonl").read_text(
                 encoding="utf-8").splitlines() if l.strip())
            if isinstance(e.get("prov"), dict)
            and e["prov"].get("record_type") == "policy_change"]
    versions = {r["prov"]["policy"]["status"]:
                r["prov"]["policy"]["policy_version"] for r in recs}
    if versions.get("applied") != store.current_version():
        return {"verdict": "break",
                "note": "applied record does not name the live version"}
    return {"verdict": "stopped",
            "note": "v1 digest %s decided the pre-swap call (executed), "
                    "v2 digest %s decided the post-swap call (denied); "
                    "each decision record names its engine; applied "
                    "record names %s"
            % (v1_digest[:12], v2_digest[:12], versions.get("applied"))}


def main():
    for sid in sorted(SITUATIONS):
        SITUATIONS[sid]()
    n_hold = sum(1 for r in RESULTS if r["verdict"] == "stopped")
    n_miss = sum(1 for r in RESULTS if r["verdict"] not in ("stopped",))
    for r in RESULTS:
        print("%-62s %s  %s" % (r["id"], r["verdict"],
                                r["detail"].get("note", "")))
    print("w75 battery: %d HOLD / %d MISS|ERROR" % (n_hold, n_miss))
    return 1 if n_miss else 0


if __name__ == "__main__":
    sys.exit(main())
