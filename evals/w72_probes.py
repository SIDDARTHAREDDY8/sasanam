"""Wave-72 break-first probes (2026-09-22): Haber-Stornetta anchoring of the
audit chain.

The load-bearing guarantee under test:
"no undetected rewrite of history prior to the last anchor" -- history
after the last anchor is soft, and the anchor cadence is the security
parameter.

Threat model: the HMAC key-holder (dev key here, the documented attacker
model) reforges the chain AND the checkpoint sidecar with valid MACs --
the anchor is the only thing that stops them. Break-first: every attack
probe must end with the auditor grading the epoch
``operator-attested-only`` (never silently ``anchored``), i.e. verdict
"stopped" means the ATTACK was stopped (detected); "break" means the
anchor failed to detect it.

  KEY-HOLDER ADVERSARY (the whole point of the wave):
    keyholder_rewrite_after_anchor_detected -- anchor 4 entries; the
      key-holder rewrites entry 2 with valid MACs AND a reforged
      checkpoint sidecar (the full design-§1 attacker). The forged chain
      still verifies -- the anchor must catch it (head_match False,
      grade operator-attested-only).
    walltime_tamper_breaks_mac -- backdate an entry's ts without the
      key: the HMAC chain breaks (verify_chain fails).
    checkpoint_head_mismatch_detected -- tamper the STORED statement's
      head_hash (no anchor key), reforge the chain MACs: statement_sig
      and anchor_hash_bind must both fail, grade operator-attested-only.
    witness_time_games_detected -- witness clock 2h in the past: the
      receipt is well-formed at the witness level, but the auditor must
      refuse the anchored grade (witness_time_window False).
    receipt_proof_tamper_detected -- flip an inclusion-proof hash in the
      chained receipt (key-holder reforges the entry MAC): the auditor's
      receipt check must fail, grade operator-attested-only.
  RESIDUAL PIN (designed, not a finding):
    anchor_interval_residual_pinned -- anchor, append 3 more records:
      the report must STATE the soft window numerically
      (open_epoch.unanchored_records == 4, grade "open (soft window)")
      while the anchored epoch keeps its grade.
  PRIVACY:
    privacy_bytes_pinned -- the witness boundary is hash-only:
      FakeWitness.submit rejects dicts/non-hex/wrong-length loudly;
      LocalAnchorLog's file holds no "statement"/"epoch_id"; the
      RekorBackend outbound bytes contain no epoch metadata, wall
      times, or record content (hash + digest sig + pubkey only).
  FAILURE SEMANTICS:
    async_failure_loud_unanchored_chain_continues -- witness down:
      epoch marked anchor_epoch_unanchored (reason backend-down, loud),
      the chain keeps appending and verifying, the auditor grades
      operator-attested-only with "no anchor receipt chained".
    recover_requeues_after_outage -- recover() after the outage
      requeues exactly the unanchored epoch (returns 1), it anchors,
      and a second recover() returns 0 (idempotent).
  LAYERING / HYGIENE:
    anchor_path_unreachable_from_sandbox -- importing gov.sandbox must
      not pull gov.anchorer / gov.anchor_backend into the process
      (executor-side only; deny-all egress).
    double_anchor_same_epoch_refused -- two force-closes before the
      worker drains: the second returns "already-closed", exactly one
      receipt lands (idempotence guard).
    unknown_backend_tag_fails_closed -- backend_for_receipt on an
      unknown backend tag raises AnchorerError (never verifies against
      a backend the receipt does not name).
    rekor_backend_two_leaf_proof_verifies -- RekorBackend's RFC 6962
      path against a realistic 2-leaf tree (leaf = sha256(0x00 || entry
      body), Rekor's leaf convention): both leaves' receipts verify,
      and a tampered sibling / wrong root / swapped sibling all fail.

All runs synthetic/local, $0. Deterministic except wall-clock ts (never
asserted on). Env hygiene restores every mutated variable and the
gov.log dev flags in finally.
"""

import base64
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import threading
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
# Import the test harness WITHOUT running tests/__init__.py (which flips
# on the dev-key opt-in process-wide); dev keys are enabled per-probe
# with _dev_keys() instead, and restored afterwards.
sys.path.insert(0, str(REPO_ROOT / "tests"))

import harness  # noqa: E402
from gov import anchor_backend as ab_mod  # noqa: E402
from gov import anchorer as anchorer_mod  # noqa: E402
from gov import ed25519 as ed_mod  # noqa: E402
from gov import log as log_mod  # noqa: E402
from gov.log import ActionLog  # noqa: E402

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
    run_tmp = tempfile.mkdtemp(prefix="w72probe-")
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
                if not isinstance(detail, dict):
                    detail = {"note": str(detail)}
                verdict = detail.pop("verdict", "stopped")
                RESULTS.append({"id": sid, "verdict": verdict,
                                "detail": detail})
            except Exception as e:  # noqa: BLE001 - probe must not die
                RESULTS.append({"id": sid, "verdict": "error",
                                "detail": {"error": "%s: %s"
                                           % (type(e).__name__, e)}})
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        SITUATIONS[sid] = wrapper
        return wrapper
    return deco


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _anchor_key(n=7):
    seed = bytes([n & 0xFF]) * 32
    pub = ab_mod.anchor_pubkey(seed)
    return {"seed": seed, "key_id": ab_mod.anchor_key_id(pub),
            "pubkey_hex": pub.hex(), "dev": True}


class _Ctx:
    """Per-probe scratch: temp dir, log, anchorers (closed in finally)."""

    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="w72probe-ctx-"))
        self.anchorers = []

    def log(self, n=0):
        lg = ActionLog(str(self.dir / "actions.jsonl"))
        for i in range(1, n + 1):
            lg.append({"event": "tool_call", "n": i, "principal": "p",
                       "agent_id": "a"})
        return lg

    def anchorer(self, lg, backend, **kw):
        kw.setdefault("policy", anchorer_mod.AnchorPolicy(
            records_per_epoch=10 ** 9, seconds_per_epoch=None,
            anchor_on_close=False))
        kw.setdefault("clock", _now_iso)
        kw.setdefault("anchor_key", _anchor_key())
        kw.setdefault("warn", lambda m: None)
        a = anchorer_mod.Anchorer(lg, backend, **kw)
        self.anchorers.append(a)
        return a

    def entries(self):
        p = self.dir / "actions.jsonl"
        return [json.loads(l) for l in p.read_text(encoding="utf-8")
                .splitlines() if l.strip()]

    def rewrite_with_key(self, seq, patch):
        """Full key-holder rewrite: patch entry ``seq``, recompute the
        HMAC chain from there, AND reforge the checkpoint sidecar
        (the design-§1 attacker holds the key the checkpoint MACs are
        keyed under)."""
        key, _ = log_mod._active_key()
        entries = self.entries()
        new_hashes = {}
        prev = log_mod.GENESIS
        for e in entries:
            if e["seq"] == seq:
                e.update(patch)
            if e["seq"] >= seq:
                e["prev_hash"] = prev
                mac = log_mod._compute_mac(
                    key, e["key_epoch"], prev, log_mod._canonical(e))
                e["hash"] = mac
                prev = mac
            else:
                prev = e["hash"]
            new_hashes[e["seq"]] = e["hash"]
        (self.dir / "actions.jsonl").write_text(
            "\n".join(json.dumps(e, ensure_ascii=True)
                      for e in entries) + "\n", encoding="utf-8")
        cp_path = self.dir / "checkpoints.jsonl"
        if cp_path.exists():
            out = []
            for line in cp_path.read_text(
                    encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                cp = json.loads(line)
                cs = cp.get("seq")
                if isinstance(cs, int) and cs >= seq \
                        and cs in new_hashes:
                    cp = dict(cp)
                    cp["hash"] = new_hashes[cs]
                    cp["mac"] = log_mod._checkpoint_mac(
                        key, cp.get("key_epoch"), cs, new_hashes[cs],
                        log_mod._pin_gen_of(cp))
                out.append(cp)
            cp_path.write_text(
                "\n".join(json.dumps(c, ensure_ascii=True)
                          for c in out) + "\n", encoding="utf-8")

    def anchor_now(self, a):
        """Force-close the epoch and drain the worker; return the last
        receipt record (or None)."""
        if a.maybe_anchor(force=True) != "queued":
            return None
        a._queue.join()
        recs = [e for e in self.entries()
                if e.get("event") == anchorer_mod.ANCHOR_RECEIPT_EVENT]
        return recs[-1] if recs else None

    def audit(self, backend):
        return anchorer_mod.audit_anchors(
            str(self.dir / "actions.jsonl"), backend)

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
# Key-holder adversary
# ----------------------------------------------------------------------

@_sit("redteam.anchor_w72.keyholder_rewrite_after_anchor_detected")
def sit_keyholder_rewrite_after_anchor_detected():
    """The crown-jewel attack: anchor 4 entries, then the key-holder
    rewrites entry 2 with valid MACs AND a reforged checkpoint sidecar.
    The forged chain still verifies -- the anchor must catch it: the
    auditor grades operator-attested-only with head_match False."""
    ctx = _Ctx()
    try:
        lg = ctx.log(n=4)
        w = ab_mod.FakeWitness(clock=_now_iso)
        a = ctx.anchorer(lg, w)
        if ctx.anchor_now(a) is None:
            return {"verdict": "break",
                    "note": "anchoring itself failed"}
        ctx.rewrite_with_key(2, {"n": 999, "note": "forged"})
        ok, broken, _ = log_mod.verify_chain(
            str(ctx.dir / "actions.jsonl"))
        if not ok:
            return {"verdict": "break",
                    "note": "forged chain did not verify (broken=%r); "
                            "the attacker model is weaker than designed"
                    % (broken,)}
        rep = ctx.audit(w)
        ep = rep["epochs"][0]
        if (ep["grade"] == anchorer_mod.GRADE_OPERATOR_ONLY
                and ep["checks"].get("head_match") is False
                and rep["chain_ok"]):
            return {"verdict": "stopped",
                    "note": "rewrite detected: anchored head != chain "
                            "head; grade operator-attested-only"}
        return {"verdict": "break",
                "note": "rewrite NOT detected: %r" % (ep,)}
    finally:
        ctx.close()


@_sit("redteam.anchor_w72.walltime_tamper_breaks_mac")
def sit_walltime_tamper_breaks_mac():
    """Backdate an entry's ts without the key: the HMAC chain must
    break (verify_chain fails)."""
    ctx = _Ctx()
    try:
        lg = ctx.log(n=3)
        entries = ctx.entries()
        entries[1]["ts"] = "2001-01-01T00:00:00+00:00"
        (ctx.dir / "actions.jsonl").write_text(
            "\n".join(json.dumps(e, ensure_ascii=True)
                      for e in entries) + "\n", encoding="utf-8")
        ok, broken, _ = log_mod.verify_chain(
            str(ctx.dir / "actions.jsonl"))
        if not ok and broken == 2:
            return {"verdict": "stopped",
                    "note": "wall-time tamper breaks the MAC at seq 2"}
        return {"verdict": "break",
                "note": "wall-time tamper not caught: ok=%r broken=%r"
                        % (ok, broken)}
    finally:
        ctx.close()


@_sit("redteam.anchor_w72.checkpoint_head_mismatch_detected")
def sit_checkpoint_head_mismatch_detected():
    """Tamper the STORED statement's head_hash (no anchor key), reforge
    the chain MACs: statement_sig and anchor_hash_bind must both fail,
    grade operator-attested-only."""
    ctx = _Ctx()
    try:
        lg = ctx.log(n=4)
        w = ab_mod.FakeWitness(clock=_now_iso)
        a = ctx.anchorer(lg, w)
        rec = ctx.anchor_now(a)
        if rec is None:
            return {"verdict": "break",
                    "note": "anchoring itself failed"}
        bad_stmt = dict(rec["statement"], head_hash="00" * 32)
        ctx.rewrite_with_key(rec["seq"], {"statement": bad_stmt})
        rep = ctx.audit(w)
        ep = rep["epochs"][0]
        if (ep["grade"] == anchorer_mod.GRADE_OPERATOR_ONLY
                and ep["checks"].get("statement_sig") is False
                and ep["checks"].get("anchor_hash_bind") is False):
            return {"verdict": "stopped",
                    "note": "stored-statement tamper detected (sig + "
                            "hash binding both fail)"}
        return {"verdict": "break",
                "note": "statement tamper NOT detected: %r" % (ep,)}
    finally:
        ctx.close()


@_sit("redteam.anchor_w72.witness_time_games_detected")
def sit_witness_time_games_detected():
    """Witness clock 2h in the past: the receipt is well-formed at the
    witness level, but the auditor must refuse the anchored grade
    (witness_time_window False) -- backdating detected."""
    ctx = _Ctx()
    try:
        lg = ctx.log(n=4)
        past = (datetime.now(timezone.utc)
                - timedelta(hours=2)).isoformat()
        w = ab_mod.FakeWitness(clock=lambda: past)
        a = ctx.anchorer(lg, w)
        rec = ctx.anchor_now(a)
        if rec is None:
            return {"verdict": "break",
                    "note": "anchoring itself failed"}
        ok, _ = w.verify_receipt(rec["receipt"],
                                 anchor_hash=rec["anchor_hash"])
        if not ok:
            return {"verdict": "break",
                    "note": "receipt malformed at the witness level; "
                            "the game is weaker than designed"}
        rep = ctx.audit(w)
        ep = rep["epochs"][0]
        if (ep["grade"] == anchorer_mod.GRADE_OPERATOR_ONLY
                and ep["checks"].get("witness_time_window") is False):
            return {"verdict": "stopped",
                    "note": "backdated witness time refused (outside "
                            "the epoch window)"}
        return {"verdict": "break",
                "note": "backdated witness time NOT detected: %r"
                        % (ep,)}
    finally:
        ctx.close()


@_sit("redteam.anchor_w72.receipt_proof_tamper_detected")
def sit_receipt_proof_tamper_detected():
    """Flip an inclusion-proof hash in the chained receipt (key-holder
    reforges the entry MAC): the auditor's receipt check must fail,
    grade operator-attested-only."""
    ctx = _Ctx()
    try:
        lg = ctx.log(n=2)
        w = ab_mod.FakeWitness(clock=_now_iso)
        a = ctx.anchorer(lg, w)
        if ctx.anchor_now(a) is None:
            return {"verdict": "break",
                    "note": "first anchor failed"}
        lg.append({"event": "tool_call", "n": 3, "principal": "p",
                   "agent_id": "a"})
        lg.append({"event": "tool_call", "n": 4, "principal": "p",
                   "agent_id": "a"})
        rec2 = ctx.anchor_now(a)
        if rec2 is None or len(rec2["receipt"]["inclusion_proof"]) == 0:
            return {"verdict": "break",
                    "note": "second anchor failed or proof empty; the "
                            "game is weaker than designed"}
        bad = dict(rec2["receipt"])
        proof = list(bad["inclusion_proof"])
        first = bytearray(bytes.fromhex(proof[0]))
        first[0] ^= 0xFF
        proof[0] = bytes(first).hex()
        bad["inclusion_proof"] = proof
        ctx.rewrite_with_key(rec2["seq"], {"receipt": bad})
        rep = ctx.audit(w)
        ep = [e for e in rep["epochs"]
              if e["checkpoint_seq"] == rec2["checkpoint_seq"]][0]
        if (ep["grade"] == anchorer_mod.GRADE_OPERATOR_ONLY
                and ep["checks"].get("receipt") is False):
            return {"verdict": "stopped",
                    "note": "forged inclusion proof detected"}
        return {"verdict": "break",
                "note": "proof tamper NOT detected: %r" % (ep,)}
    finally:
        ctx.close()


# ----------------------------------------------------------------------
# Residual pin (designed, not a finding)
# ----------------------------------------------------------------------

@_sit("redteam.anchor_w72.anchor_interval_residual_pinned")
def sit_anchor_interval_residual_pinned():
    """Anchor, append 3 more records: the report must STATE the soft
    window numerically -- open_epoch.unanchored_records == 4 (the 3 new
    records plus the receipt record itself) with grade exactly
    "open (soft window)" -- while the anchored epoch keeps its grade."""
    ctx = _Ctx()
    try:
        lg = ctx.log(n=4)
        w = ab_mod.FakeWitness(clock=_now_iso)
        a = ctx.anchorer(lg, w)
        if ctx.anchor_now(a) is None:
            return {"verdict": "break",
                    "note": "anchoring itself failed"}
        for i in range(5, 8):
            lg.append({"event": "tool_call", "n": i, "principal": "p",
                       "agent_id": "a"})
        rep = ctx.audit(w)
        open_ep = rep["open_epoch"]
        if (rep["epochs"][0]["grade"]
                == anchorer_mod.GRADE_ANCHORED
                and open_ep["unanchored_records"] == 4
                and open_ep["grade"] == "open (soft window)"):
            return {"verdict": "stopped",
                    "note": "residual stated numerically: 4 unanchored "
                            "records in the soft window"}
        return {"verdict": "break",
                "note": "residual not stated honestly: %r" % (rep,)}
    finally:
        ctx.close()


# ----------------------------------------------------------------------
# Privacy
# ----------------------------------------------------------------------

@_sit("redteam.anchor_w72.privacy_bytes_pinned")
def sit_privacy_bytes_pinned():
    """The witness boundary is hash-only: FakeWitness.submit rejects
    dicts/non-hex/wrong-length loudly; LocalAnchorLog's file holds no
    "statement"/"epoch_id"; the RekorBackend outbound bytes carry no
    epoch metadata, wall times, or record content."""
    ctx = _Ctx()
    try:
        w = ab_mod.FakeWitness()
        ahash = hashlib.sha256(b"epoch-bytes").hexdigest()
        for bad in ({"anchor_hash": ahash}, "not-hex", "ab" * 16):
            try:
                w.submit(bad)
            except ab_mod.WitnessError:
                pass
            else:
                return {"verdict": "break",
                        "note": "submit(%r) did not raise" % (bad,)}
        ll = ab_mod.LocalAnchorLog(str(ctx.dir / "anchors.jsonl"))
        rec = ll.submit(ahash)
        ok, reason = ll.verify_receipt(rec, anchor_hash=ahash)
        if not ok:
            return {"verdict": "break",
                    "note": "local receipt did not verify: %s" % reason}
        content = (ctx.dir / "anchors.jsonl").read_text(
            encoding="utf-8")
        if "epoch_id" in content or "statement" in content:
            return {"verdict": "break",
                    "note": "local anchor log leaks statement metadata"}
        # RekorBackend: intercept the exact outbound bytes.
        seed = bytes([9]) * 32
        pub = ab_mod.anchor_pubkey(seed)
        seen = {}

        def transport(req):
            seen["body"] = req["body"]
            seen["url"] = req["url"]
            entry = {
                "body": base64.b64encode(json.dumps(
                    {"spec": {"data": {"hash": {
                        "algorithm": "sha256", "value": ahash}}}})
                    .encode()).decode(),
                "integratedTime": 1780000000,
                "logIndex": 41,
                "logID": ab_mod.REKOR_LOG_ID,
                "verification": {
                    "inclusionProof": {
                        "hashes": [], "rootHash": "ab" * 32,
                        "treeSize": 1, "logIndex": 0},
                    "signedEntryTimestamp":
                        base64.b64encode(b"set").decode(),
                },
            }
            return {"status": 201,
                    "body": json.dumps({"uuid-w72-probe": entry})}

        rb = ab_mod.RekorBackend(transport=transport, anchor_seed=seed,
                                 anchor_pubkey=pub)
        rb.submit(ahash)
        low = seen["body"].lower()
        for forbidden in ("epoch_id", "wall", "head_hash",
                          "prev_anchor", "tool_call", "principal"):
            if forbidden in low:
                return {"verdict": "break",
                        "note": "outbound bytes leak %r" % forbidden}
        parsed = json.loads(seen["body"])
        sig = base64.b64decode(parsed["spec"]["signature"]["content"])
        if not ed_mod.verify(pub, bytes.fromhex(ahash), sig):
            return {"verdict": "break",
                    "note": "envelope signature is not over the digest"}
        return {"verdict": "stopped",
                "note": "witness boundary is hash-only on all three "
                        "backends"}
    finally:
        ctx.close()


# ----------------------------------------------------------------------
# Failure semantics
# ----------------------------------------------------------------------

@_sit("redteam.anchor_w72.async_failure_loud_unanchored_chain_continues")
def sit_async_failure_loud_unanchored_chain_continues():
    """Witness down: the epoch is loudly marked anchor_epoch_unanchored
    (reason backend-down, grade operator-attested-only), the chain keeps
    appending and verifying, and the auditor grades the epoch
    operator-attested-only with "no anchor receipt chained"."""
    ctx = _Ctx()
    try:
        lg = ctx.log(n=4)
        w = ab_mod.FakeWitness(clock=_now_iso)
        w.down = True
        a = ctx.anchorer(lg, w)
        if a.maybe_anchor(force=True) != "queued":
            return {"verdict": "break",
                    "note": "anchor job did not queue"}
        a._queue.join()
        un = [e for e in ctx.entries()
              if e.get("event")
              == anchorer_mod.ANCHOR_UNANCHORED_EVENT]
        if len(un) != 1 or un[0]["reason"] != "backend-down" \
                or un[0]["grade"] != anchorer_mod.GRADE_OPERATOR_ONLY:
            return {"verdict": "break",
                    "note": "epoch not loudly marked unanchored: %r"
                            % (un,)}
        lg.append({"event": "tool_call", "n": 5, "principal": "p",
                   "agent_id": "a"})
        ok, _, _ = log_mod.verify_chain(str(ctx.dir / "actions.jsonl"))
        if not ok:
            return {"verdict": "break",
                    "note": "chain stopped verifying after witness "
                            "failure"}
        rep = ctx.audit(w)
        ep = rep["epochs"][0]
        if ep["grade"] == anchorer_mod.GRADE_OPERATOR_ONLY \
                and any("no anchor receipt chained" in r
                        for r in ep["reasons"]):
            return {"verdict": "stopped",
                    "note": "failure is loud, the chain continues, the "
                            "grade is honest"}
        return {"verdict": "break",
                "note": "auditor grade wrong: %r" % (ep,)}
    finally:
        ctx.close()


@_sit("redteam.anchor_w72.recover_requeues_after_outage")
def sit_recover_requeues_after_outage():
    """recover() after an outage requeues exactly the unanchored epoch
    (returns 1); it anchors; a second recover() returns 0 (idempotent)."""
    ctx = _Ctx()
    try:
        lg = ctx.log(n=4)
        w = ab_mod.FakeWitness(clock=_now_iso)
        w.down = True
        a = ctx.anchorer(lg, w)
        a.maybe_anchor(force=True)
        a._queue.join()
        w.down = False
        if a.recover() != 1:
            return {"verdict": "break",
                    "note": "recover() did not requeue exactly 1 epoch"}
        a._queue.join()
        rep = ctx.audit(w)
        if rep["epochs"][0]["grade"] \
                != anchorer_mod.GRADE_ANCHORED:
            return {"verdict": "break",
                    "note": "requeued epoch did not anchor: %r"
                            % (rep["epochs"][0],)}
        if a.recover() != 0:
            return {"verdict": "break",
                    "note": "recover() not idempotent"}
        return {"verdict": "stopped",
                "note": "recover() requeues exactly once, then anchors"}
    finally:
        ctx.close()


# ----------------------------------------------------------------------
# Layering / hygiene
# ----------------------------------------------------------------------

@_sit("redteam.anchor_w72.anchor_path_unreachable_from_sandbox")
def sit_anchor_path_unreachable_from_sandbox():
    """Importing gov.sandbox must not pull gov.anchorer /
    gov.anchor_backend into the process: the anchor client is
    executor-side only (deny-all egress)."""
    import subprocess
    code = ("import sys, gov.sandbox; sys.exit(0 "
            "if 'gov.anchorer' not in sys.modules "
            "and 'gov.anchor_backend' not in sys.modules else 1)")
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, timeout=120,
                       cwd=str(REPO_ROOT))
    if r.returncode == 0:
        return {"verdict": "stopped",
                "note": "sandbox import pulls no anchor client"}
    return {"verdict": "break",
            "note": "gov.sandbox imports the anchor client: %s"
                    % r.stderr.decode()[:200]}


@_sit("redteam.anchor_w72.double_anchor_same_epoch_refused")
def sit_double_anchor_same_epoch_refused():
    """Two force-closes before the worker drains: the second must
    return "already-closed" and exactly one receipt lands (the
    idempotence guard)."""
    ctx = _Ctx()
    try:
        lg = ctx.log(n=3)
        w = ab_mod.FakeWitness(clock=_now_iso)
        a = ctx.anchorer(lg, w)
        first = a.maybe_anchor(force=True)
        second = a.maybe_anchor(force=True)
        a._queue.join()
        recs = [e for e in ctx.entries()
                if e.get("event") == anchorer_mod.ANCHOR_RECEIPT_EVENT]
        if first == "queued" and second == "already-closed" \
                and len(recs) == 1:
            return {"verdict": "stopped",
                    "note": "same epoch never double-anchors"}
        return {"verdict": "break",
                "note": "first=%r second=%r receipts=%d"
                        % (first, second, len(recs))}
    finally:
        ctx.close()


@_sit("redteam.anchor_w72.unknown_backend_tag_fails_closed")
def sit_unknown_backend_tag_fails_closed():
    """backend_for_receipt on an unknown backend tag must raise
    AnchorerError -- never verify against a backend the receipt does
    not name."""
    try:
        anchorer_mod.backend_for_receipt({"backend": "evil-witness"})
    except anchorer_mod.AnchorerError:
        return {"verdict": "stopped",
                "note": "unknown backend tag refused loud"}
    except Exception as e:  # noqa: BLE001
        return {"verdict": "break",
                "note": "wrong exception type: %r" % e}
    return {"verdict": "break",
            "note": "unknown backend tag accepted"}


@_sit("redteam.anchor_w72.rekor_backend_two_leaf_proof_verifies")
def sit_rekor_backend_two_leaf_proof_verifies():
    """RekorBackend's RFC 6962 path against a realistic 2-leaf tree,
    built per Rekor's real leaf convention (leaf =
    sha256(0x00 || entry body bytes), NOT sha256 of the anchor hash):
    both leaves' receipts must verify, and a tampered sibling, a wrong
    root_hash, and a swapped sibling must all fail. (A first draft of
    this probe built the tree over the anchor hash and failed -- that
    was the probe's error, and it pinned down the correct leaf
    convention.)"""
    seed = bytes([9]) * 32
    pub = ab_mod.anchor_pubkey(seed)
    ah1 = hashlib.sha256(b"epoch-one").hexdigest()
    ah2 = hashlib.sha256(b"epoch-two").hexdigest()
    body1 = json.dumps({"spec": {"data": {"hash": {
        "algorithm": "sha256", "value": ah1}}}}).encode()
    body2 = json.dumps({"spec": {"data": {"hash": {
        "algorithm": "sha256", "value": ah2}}}}).encode()
    leaf1 = hashlib.sha256(b"\x00" + body1).digest()
    leaf2 = hashlib.sha256(b"\x00" + body2).digest()
    root = hashlib.sha256(b"\x01" + leaf1 + leaf2).digest()

    def transport(req):
        ah = json.loads(req["body"])["spec"]["data"]["hash"]["value"]
        idx = 0 if ah == ah1 else 1
        sib = leaf2.hex() if idx == 0 else leaf1.hex()
        body = body1 if idx == 0 else body2
        entry = {
            "body": base64.b64encode(body).decode(),
            "integratedTime": int(datetime.now(timezone.utc)
                                  .timestamp()),
            "logIndex": idx, "logID": ab_mod.REKOR_LOG_ID,
            "verification": {
                "inclusionProof": {"hashes": [sib],
                                   "rootHash": root.hex(),
                                   "treeSize": 2, "logIndex": idx},
                "signedEntryTimestamp":
                    base64.b64encode(b"set").decode(),
            },
        }
        return {"status": 201,
                "body": json.dumps({"uuid-%d" % idx: entry})}

    rb = ab_mod.RekorBackend(transport=transport, anchor_seed=seed,
                             anchor_pubkey=pub)
    r1 = rb.submit(ah1)
    r2 = rb.submit(ah2)
    ok1, rs1 = rb.verify_receipt(r1, anchor_hash=ah1)
    ok2, rs2 = rb.verify_receipt(r2, anchor_hash=ah2)
    if not (ok1 and ok2):
        return {"verdict": "break",
                "note": "valid 2-leaf proofs did not verify: %r %r"
                        % (rs1, rs2)}
    bad_sib = dict(r1)
    bad_sib["inclusion_proof"] = dict(
        r1["inclusion_proof"], hashes=["ff" * 32])
    bad_root = dict(r2)
    bad_root["inclusion_proof"] = dict(
        r2["inclusion_proof"], root_hash="00" * 32)
    swapped = dict(r2)
    swapped["inclusion_proof"] = dict(
        r2["inclusion_proof"], hashes=[leaf2.hex()])
    tampers = [
        (bad_sib, ah1, "tampered sibling"),
        (bad_root, ah2, "wrong root_hash"),
        (swapped, ah2, "swapped sibling"),
    ]
    for receipt, ah, what in tampers:
        ok, reason = rb.verify_receipt(receipt, anchor_hash=ah)
        if ok:
            return {"verdict": "break",
                    "note": "%s accepted by verify_receipt" % what}
    return {"verdict": "stopped",
            "note": "2-leaf proofs verify; tampered sibling, wrong "
                    "root, and swapped sibling all rejected"}


def main():
    for sid in sorted(SITUATIONS):
        SITUATIONS[sid]()
    n_hold = sum(1 for r in RESULTS if r["verdict"] == "stopped")
    n_miss = sum(1 for r in RESULTS if r["verdict"] not in ("stopped",))
    for r in RESULTS:
        print("%-62s %s  %s" % (r["id"], r["verdict"],
                                r["detail"].get("note", "")))
    print("w72 battery: %d HOLD / %d MISS|ERROR" % (n_hold, n_miss))
    return 1 if n_miss else 0


if __name__ == "__main__":
    sys.exit(main())
