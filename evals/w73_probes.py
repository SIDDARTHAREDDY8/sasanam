"""Wave-73 break-first probes (2026-09-22): the provenance record.

The letter inside the envelope: every governed record carries a
versioned, validator-enforced ``prov`` section (Art-12-shaped schema:
who/when/resource/outcome, delegation chain, approvals, session
timing, tiering, retention). Break-first: every attack probe must end
with the schema layer refusing or the auditor flagging — verdict
"stopped" means the ATTACK was stopped (detected/refused); "break"
means the provenance layer failed to catch it.

  PROVENANCE FORGERY:
    provenance_forgery_fails -- forge a record's identity/session fields
      without the key: chain verification must break at the forged seq.
  SESSION-TIMING GAMES (key-holder residual, pinned honestly):
    session_backdate_keyholder_residual -- the key-holder backdates
      session start/end with valid reforged MACs: in-chain verification
      PASSES (the stated residual — the chain cannot catch a key-holder
      backdate), but the anchor catches the rewrite: the auditor must
      grade operator-attested-only with head_match False (the wave-72
      key-holder pattern applied to session timing).
  RECORD-TYPE CONFUSION:
    record_type_confusion_rejected -- swap a decision record's
      type/fields to escalate what it authorizes: schema validation
      must refuse.
  SCHEMA VERSION GAMES:
    schema_version_games_fail_closed -- v2 fields to a v1 verifier and
      vice versa: fail closed, never silently accept.
  DELEGATION-PATH TRUNCATION (Wave-74 contract pin):
    delegation_truncation_detected -- drop a middle hop: the binds
      chain must break verification.
  PAYLOAD-TIER BYPASS:
    payload_tier_bypass_refused -- smuggle full prompt content into the
      default tier: tier enforcement must refuse.
  CONTROL:
    valid_record_verifies -- well-formed v1 record: verifies clean.

All runs synthetic/local, $0. Deterministic except wall-clock ts (never
asserted on). Env hygiene restores every mutated variable and the
gov.log dev flags in finally.
"""

import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
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
from gov import log as log_mod  # noqa: E402
from gov import provenance as prov_mod  # noqa: E402
from gov.log import ActionLog  # noqa: E402

RESULTS = []
SITUATIONS = {}

_KEY_ENV = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE",
            "GOV_DEV_KEYS", "GOV_DEPLOYMENT_MODE", "GOV_KEYRING_FILE")


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
    """Per-probe dev-key opt-in (in-code factor only; env set by hand)."""
    prev = log_mod._dev_enabled
    prev_warned = log_mod._dev_warned
    log_mod._dev_enabled = enabled
    log_mod._dev_warned = False
    try:
        yield
    finally:
        log_mod._dev_enabled = prev
        log_mod._dev_warned = prev_warned


@contextlib.contextmanager
def _govrun():
    old = os.environ.get("TMPDIR")
    old_cached = tempfile.tempdir
    os.environ["TMPDIR"] = "/tmp/gov-run"
    tempfile.tempdir = None
    run_tmp = tempfile.mkdtemp(prefix="w73probe-")
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
                    with _env(GOV_DEV_KEYS="1",
                              GOV_DEPLOYMENT_MODE="staging"):
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


_T0 = "2026-09-22T15:00:00+00:00"
_T1 = "2026-09-22T15:05:00+00:00"
_UNTIL = "2027-03-22T15:00:00+00:00"


def _delegation():
    return prov_mod.build_delegation([
        {"kind": "principal", "ref": "user:u_8f31"},
        {"kind": "agent", "ref": "agent:orchestrator-7"},
        {"kind": "sub-agent", "ref": "agent:researcher-3"},
        {"kind": "tool", "ref": "tool:webfetch"},
    ])


def _decision(overrides=None):
    prov = {
        "schema_version": 1,
        "record_type": "decision",
        "session_id": "sess-0001",
        "session_open": _T0,
        "clock_source": "system-wall:UTC+00:00",
        "principal": {"kind": "user", "ref": "user:u_8f31"},
        "delegation": _delegation(),
        "approvals": [{"approval_id": "ap-1", "decision": "approved",
                       "decided_by": "human:ops", "decided_at": _T0}],
        "action": {"verb": "fetch", "tool": "webfetch",
                   "args_digest": "sha256:abc"},
        "resource": {"kind": "url", "ref": "https://example.com/x",
                     "scope": "read"},
        "policy_version": "demo-policy:2026-09-22",
        "matched_rules": ["R3"],
        "payload_tier": "decision",
        "retention": {"class": "decision", "until": _UNTIL,
                      "policy": "art12-default"},
    }
    if overrides:
        prov.update(overrides)
    return {"event": "prov_decision", "prov": prov}


class _Ctx:
    """Per-probe scratch: temp dir, log, anchorers (closed in finally)."""

    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="w73probe-ctx-"))
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
        kw.setdefault("anchor_key", None)  # set by caller when anchoring
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


def _anchor_key(n=7):
    seed = bytes([n & 0xFF]) * 32
    pub = ab_mod.anchor_pubkey(seed)
    return {"seed": seed, "key_id": ab_mod.anchor_key_id(pub),
            "pubkey_hex": pub.hex(), "dev": True}


def _reforge_with_key(log_path, mutate):
    """Key-holder rewrite: mutate entries, recompute every MAC (chain +
    checkpoint sidecar) with the dev key -- the wave-72 full key-holder
    model. Checkpoint ``hash`` fields are updated to the reforged entry
    hashes (mirrors w72's rewrite_with_key); only the MAC over the new
    hash is recomputed."""
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


# ----------------------------------------------------------------------
# Provenance forgery
# ----------------------------------------------------------------------

@_sit("redteam.provenance_w73.provenance_forgery_fails")
def sit_provenance_forgery_fails():
    """Forge a record's identity/session fields WITHOUT the key: the HMAC
    chain must break at the forged seq."""
    ctx = _Ctx()
    try:
        lg = ctx.log()
        prov_mod.append_provenance(lg, _decision())
        p = ctx.dir / "actions.jsonl"
        lines = p.read_text(encoding="utf-8").splitlines()
        forged = json.loads(lines[0])
        forged["prov"]["principal"]["ref"] = "user:attacker"
        forged["prov"]["session_id"] = "sess-evil"
        lines[0] = json.dumps(forged, ensure_ascii=True)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        verdict = log_mod._verify(str(p))
        if verdict["ok"]:
            return {"verdict": "break",
                    "note": "forged identity fields verified clean"}
        return {"verdict": "stopped",
                "note": "chain broke at seq %s after keyless forgery: %s"
                % (verdict["broken_seq"], verdict["error"])}
    finally:
        ctx.close()


# ----------------------------------------------------------------------
# Session-timing games (key-holder residual)
# ----------------------------------------------------------------------

@_sit("redteam.provenance_w73.session_backdate_keyholder_residual")
def sit_session_backdate_keyholder_residual():
    """Key-holder backdates session start/end with valid reforged MACs:
    in-chain verification PASSES (the stated residual -- the chain cannot
    catch a key-holder backdate), but the anchor catches the rewrite: the
    auditor must grade the epoch operator-attested-only with a head
    mismatch (the wave-72 key-holder pattern applied to session timing).
    The export-time impossible-timing check itself is pinned by unit
    test against a fabricated anchored summary."""
    ctx = _Ctx()
    try:
        lg = ctx.log()
        prov_mod.append_provenance(lg, _decision())
        # Anchor for real (FakeWitness, real-now clock): the witness clock
        # must stay near real now -- a clock hours in the past is refused
        # the anchored grade by the auditor (wave-72 pin).
        now = datetime.now(timezone.utc).replace(microsecond=0)
        fixed = now.isoformat()
        backend = ab_mod.FakeWitness(clock=lambda: fixed)
        a = ctx.anchorer(lg, backend, anchor_key=_anchor_key())
        if ctx.anchor_now(a) is None:
            return {"verdict": "break",
                    "note": "anchoring itself failed"}
        rep0 = anchorer_mod.audit_anchors(
            str(ctx.dir / "actions.jsonl"), backend)
        if not rep0["epochs"] or rep0["epochs"][0]["grade"] != \
                anchorer_mod.GRADE_ANCHORED:
            return {"verdict": "break",
                    "note": "epoch did not anchor pre-attack: %r"
                    % (rep0["epochs"],)}
        # Key-holder backdate: session times rewritten, all MACs reforged.
        late = (now + timedelta(hours=2)).isoformat()
        early = (now - timedelta(hours=3)).isoformat()

        def mutate(entries):
            for e in entries:
                if not isinstance(e.get("prov"), dict):
                    continue  # anchor_receipt records carry no prov
                e["prov"]["session_open"] = early
                e["prov"]["session_close"] = late

        _reforge_with_key(str(ctx.dir / "actions.jsonl"), mutate)
        verdict = log_mod._verify(str(ctx.dir / "actions.jsonl"))
        residual_pinned = verdict["ok"]  # chain CANNOT catch this: stated
        rep = anchorer_mod.audit_anchors(
            str(ctx.dir / "actions.jsonl"), backend)
        ep = rep["epochs"][0] if rep["epochs"] else {}
        caught = (ep.get("grade") == anchorer_mod.GRADE_OPERATOR_ONLY
                  and ep.get("checks", {}).get("head_match") is False)
        if not caught:
            return {"verdict": "break",
                    "note": "key-holder session backdate survived the "
                            "anchor too: %r" % (ep,)}
        return {"verdict": "stopped",
                "note": "in-chain residual pinned (reforged chain verifies: "
                        "%s); anchor caught the rewrite (head_match False, "
                        "grade operator-attested-only)" % residual_pinned}
    finally:
        ctx.close()


# ----------------------------------------------------------------------
# Record-type confusion
# ----------------------------------------------------------------------

@_sit("redteam.provenance_w73.record_type_confusion_rejected")
def sit_record_type_confusion_rejected():
    """Swap a decision record's type/fields to escalate what it
    authorizes: schema validation must refuse every confusion shape."""
    shapes = []
    e = _decision()
    e["prov"]["outcome"] = {"status": "ok", "detail": "self-ok"}
    shapes.append(("decision+outcome", e))
    e = _decision({"record_type": "approval"})
    shapes.append(("decision-fields-as-approval", e))
    e = _decision({"record_type": "session_open",
                   "session_close": _T1})
    for f in ("action", "resource", "approvals"):
        e["prov"].pop(f, None)
    shapes.append(("session_open+session_close", e))
    refused = []
    for name, ev in shapes:
        v = prov_mod.validate_provenance(ev)
        refused.append((name, not v["ok"]))
    bad = [n for n, ok in refused if not ok]
    if bad:
        return {"verdict": "break",
                "note": "type-confusion shapes accepted: %s" % bad}
    return {"verdict": "stopped",
            "note": "all %d confusion shapes refused: %s"
            % (len(shapes), [n for n, _ in refused])}


# ----------------------------------------------------------------------
# Schema version games
# ----------------------------------------------------------------------

@_sit("redteam.provenance_w73.schema_version_games_fail_closed")
def sit_schema_version_games_fail_closed():
    """v2 fields to a v1 verifier and vice versa: fail closed, never
    silently accept."""
    v2 = _decision({"schema_version": 2})
    v2["prov"]["future_field"] = "v2-only content"
    r1 = prov_mod.validate_provenance(v2)["ok"]
    s1 = _decision({"schema_version": "1"})
    r2 = prov_mod.validate_provenance(s1)["ok"]
    e = _decision()
    del e["prov"]["schema_version"]
    r3 = prov_mod.validate_provenance(e)["ok"]
    if r1 or r2 or r3:
        return {"verdict": "break",
                "note": "version games accepted: v2=%s str1=%s missing=%s"
                % (r1, r2, r3)}
    return {"verdict": "stopped",
            "note": "v2-to-v1, string-version, and missing-version all "
            "refused fail-closed"}


# ----------------------------------------------------------------------
# Delegation-path truncation (Wave-74 contract pin)
# ----------------------------------------------------------------------

@_sit("redteam.provenance_w73.delegation_truncation_detected")
def sit_delegation_truncation_detected():
    """Drop a middle hop from the delegation path: the binds chain must
    break verification (this pins the Wave-74 contract)."""
    d = _delegation()
    d["hops"] = [d["hops"][0], d["hops"][1], d["hops"][3]]
    errs = prov_mod.validate_delegation(d)
    rec_ok = prov_mod.validate_provenance(
        _decision({"delegation": d}))["ok"]
    if not errs or rec_ok:
        return {"verdict": "break",
                "note": "truncated delegation path verified clean"}
    return {"verdict": "stopped",
            "note": "middle-hop drop broke binds verification: %s"
            % errs[0]}


# ----------------------------------------------------------------------
# Payload-tier bypass
# ----------------------------------------------------------------------

@_sit("redteam.provenance_w73.payload_tier_bypass_refused")
def sit_payload_tier_bypass_refused():
    """Smuggle full prompt content into the default tier (top level and
    nested): tier enforcement must refuse."""
    e1 = _decision()
    e1["prompt_text"] = "full user prompt with PII"
    e2 = _decision()
    e2["prov"]["resource"] = {"kind": "url",
                                 "ref": "https://x", "scope": "read",
                                 "transcript": ["turn1", "turn2"]}
    r1 = prov_mod.validate_provenance(e1)
    r2 = prov_mod.validate_provenance(e2)
    if r1["ok"] or r2["ok"]:
        return {"verdict": "break",
                "note": "payload smuggling accepted into default tier"}
    return {"verdict": "stopped",
            "note": "top-level and nested payload smuggling both refused"}


# ----------------------------------------------------------------------
# Control
# ----------------------------------------------------------------------

@_sit("redteam.provenance_w73.valid_record_verifies")
def sit_valid_record_verifies():
    """Control: a well-formed v1 record appends, verifies, and exports
    with its anchor grade."""
    ctx = _Ctx()
    try:
        lg = ctx.log()
        prov_mod.append_provenance(lg, _decision())
        verdict = log_mod._verify(str(ctx.dir / "actions.jsonl"))
        v = prov_mod.validate_provenance(ctx.entries()[0])
        exp = prov_mod.provenance_export(ctx.entries(), None)
        if not (verdict["ok"] and v["ok"] and
                len(exp["traceability_rows"]) == 1):
            return {"verdict": "break",
                    "note": "valid record failed to verify/export"}
        return {"verdict": "stopped",
                "note": "valid v1 record: chain OK, schema OK, export "
                "row present (green closure control)"}
    finally:
        ctx.close()


def main():
    for sid in sorted(SITUATIONS):
        SITUATIONS[sid]()
    n_hold = sum(1 for r in RESULTS if r["verdict"] == "stopped")
    n_miss = sum(1 for r in RESULTS if r["verdict"] not in ("stopped",))
    for r in RESULTS:
        print("%-62s %s  %s" % (r["id"], r["verdict"],
                                r["detail"].get("note", "")))
    print("w73 battery: %d HOLD / %d MISS|ERROR" % (n_hold, n_miss))
    return 1 if n_miss else 0


if __name__ == "__main__":
    sys.exit(main())
