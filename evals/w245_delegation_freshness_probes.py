"""Wave-245 delegation-freshness gate battery (W245-5), red-first.

ADAPT of yunaremaia/agent-capability-attestation (MIT) -- patterns only,
re-expressed in this repo's vocabulary; no upstream code vendored. The
five rules adapted:
  1. TTL metadata -- every attestation carries {capability, state_hash,
     timestamp, ttl}; missing TTL is expired, never silent.
  2. Freshness -- TTL must not have expired at validation time.
  3. State binding -- the state hash must equal the digest of the
     presented capability set.
  4. Monotonic narrowing -- each hop narrows-or-equals the parent's
     capability set (coverage via exact entry, "*", or "<prefix>:*").
  5. Fail closed -- missing/zero/negative/boolean TTL is expired.

Probes:
  ttl-missing-failclosed -- no usable TTL -> delegation-ttl-missing.
  stale-hop-refused -- issued 120s ago, ttl 60 -> delegation-freshness-expired.
  widening-hop-refused -- child capability not covered by parent ->
      delegation-monotonicity-violated.
  state-hash-drift-refused -- state_hash != digest(capabilities) ->
      delegation-state-mismatch.
  bool-ttl-rejected -- ttl=True -> delegation-ttl-missing (True==1 trap).
  fresh-narrowing-chain-passes -- fresh 3-hop narrowing chain validates
      (positive control: the gate does not refuse everything).
  chain-continuity-broken -- child.issuer != parent.subject ->
      delegation-chain-broken.
  excessive-ttl-refused -- ttl 3600 > max_ttl 300 -> delegation-ttl-excessive.
  malformed-attestation-refused -- string capabilities / naive datetime ->
      delegation-attestation-malformed.

Stdlib only. Deterministic (injected `now`). No in-repo git
subprocesses. Depth-1 green checks honor GOV_SKIP_GREEN.
"""

import os
import sys
import traceback
from datetime import datetime, timedelta, timezone

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

HAVE_DF = False
try:
    from gov import delegation_freshness as _df
    HAVE_DF = all(hasattr(_df, n) for n in (
        "CapabilityAttestation", "digest_capabilities", "check_fresh",
        "check_state_binding", "check_hop", "validate_chain",
        "DelegationFreshnessError"))
except ImportError:
    _df = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "ttl-missing-failclosed",
    "stale-hop-refused",
    "widening-hop-refused",
    "state-hash-drift-refused",
    "bool-ttl-rejected",
    "fresh-narrowing-chain-passes",
    "chain-continuity-broken",
    "excessive-ttl-refused",
    "malformed-attestation-refused",
]

RESULTS = []
SITUATIONS = {}


def _sit(sid):
    def deco(fn):
        def wrapper():
            try:
                detail = fn()
                if not isinstance(detail, dict):
                    detail = {"note": str(detail)}
                verdict = detail.pop("verdict", "stopped")
                RESULTS.append({"id": sid, "verdict": verdict,
                                "detail": detail})
            except Exception as e:  # noqa: BLE001 - probe must not die
                RESULTS.append({"id": sid, "verdict": "error",
                                "detail": {"error": "%s: %s"
                                           % (type(e).__name__, e),
                                           "trace": traceback.format_exc(
                                               limit=5)}})
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        SITUATIONS[sid] = wrapper
        return wrapper
    return deco


def _need():
    if not HAVE_DF:
        return {"verdict": "gap", "note": "gov.delegation_freshness missing"}
    return None


NOW = datetime(2026, 9, 30, 16, 0, 0, tzinfo=timezone.utc)


def _att(issuer, subject, caps, issued_at, ttl, state_hash="AUTO"):
    """Build an attestation; state_hash="AUTO" digests the capabilities."""
    if state_hash == "AUTO" and HAVE_DF:
        state_hash = _df.digest_capabilities(caps)
    return _df.CapabilityAttestation(
        issuer=issuer, subject=subject, capabilities=tuple(caps),
        issued_at=issued_at, ttl_seconds=ttl, state_hash=state_hash)


def _assert_code(fn, code):
    try:
        fn()
    except _df.DelegationFreshnessError as e:
        if e.code != code:
            return {"verdict": "gap",
                    "note": "wrong code: %s (wanted %s)" % (e.code, code)}
        return {"verdict": "held"}
    except Exception as e:  # noqa: BLE001
        return {"verdict": "error",
                "note": "wrong exception: %s: %s" % (type(e).__name__, e)}
    return {"verdict": "gap", "note": "no refusal raised"}


@_sit("ttl-missing-failclosed")
def _p_ttl_missing():
    """Attestation with no TTL -> delegation-ttl-missing (never infinite)."""
    need = _need()
    if need:
        return need
    a = _att("agent://planner", "agent://worker", ["tool:read"],
             NOW, None)
    return _assert_code(lambda: _df.check_fresh(a, NOW),
                        "delegation-ttl-missing")


@_sit("stale-hop-refused")
def _p_stale_hop():
    """issued 120s ago, ttl 60 -> delegation-freshness-expired."""
    need = _need()
    if need:
        return need
    a = _att("agent://planner", "agent://worker", ["tool:read"],
             NOW - timedelta(seconds=120), 60)
    return _assert_code(lambda: _df.check_fresh(a, NOW),
                        "delegation-freshness-expired")


@_sit("widening-hop-refused")
def _p_widening_hop():
    """Child capability set wider than parent ->
    delegation-monotonicity-violated."""
    need = _need()
    if need:
        return need
    parent = _att("agent://root", "agent://planner",
                  ["tool:read", "tool:write"], NOW, 300)
    child = _att("agent://planner", "agent://worker",
                 ["tool:read", "tool:write", "tool:exec"], NOW, 300)
    return _assert_code(lambda: _df.validate_chain([parent, child], NOW),
                        "delegation-monotonicity-violated")


@_sit("state-hash-drift-refused")
def _p_state_drift():
    """state_hash not matching digest(capabilities) ->
    delegation-state-mismatch."""
    need = _need()
    if need:
        return need
    a = _att("agent://planner", "agent://worker", ["tool:read"],
             NOW, 300, state_hash="0" * 64)
    return _assert_code(lambda: _df.check_state_binding(a),
                        "delegation-state-mismatch")


@_sit("bool-ttl-rejected")
def _p_bool_ttl():
    """ttl=True must not pass as ttl==1 -> delegation-ttl-missing."""
    need = _need()
    if need:
        return need
    a = _att("agent://planner", "agent://worker", ["tool:read"],
             NOW, True)
    return _assert_code(lambda: _df.check_fresh(a, NOW),
                        "delegation-ttl-missing")


@_sit("fresh-narrowing-chain-passes")
def _p_positive_chain():
    """Fresh 3-hop narrowing chain validates (positive control)."""
    need = _need()
    if need:
        return need
    a0 = _att("agent://root", "agent://planner",
              ["tool:*"], NOW, 300)
    a1 = _att("agent://planner", "agent://worker",
              ["tool:read", "tool:write"], NOW, 200)
    a2 = _att("agent://worker", "agent://leaf",
              ["tool:read"], NOW, 100)
    try:
        recs = _df.validate_chain([a0, a1, a2], NOW)
    except _df.DelegationFreshnessError as e:
        return {"verdict": "gap",
                "note": "fresh narrowing chain refused: %s" % e.code}
    if len(recs) != 3:
        return {"verdict": "gap", "note": "chain record wrong length"}
    return {"verdict": "held"}


@_sit("chain-continuity-broken")
def _p_chain_broken():
    """child.issuer != parent.subject -> delegation-chain-broken."""
    need = _need()
    if need:
        return need
    parent = _att("agent://root", "agent://planner",
                  ["tool:*"], NOW, 300)
    child = _att("agent://stranger", "agent://worker",
                 ["tool:read"], NOW, 300)
    return _assert_code(lambda: _df.validate_chain([parent, child], NOW),
                        "delegation-chain-broken")


@_sit("excessive-ttl-refused")
def _p_excessive_ttl():
    """ttl 3600 over the deployment max_ttl 300 ->
    delegation-ttl-excessive."""
    need = _need()
    if need:
        return need
    a = _att("agent://planner", "agent://worker", ["tool:read"],
             NOW, 3600)
    return _assert_code(lambda: _df.check_fresh(a, NOW, max_ttl=300),
                        "delegation-ttl-excessive")


@_sit("malformed-attestation-refused")
def _p_malformed():
    """String capabilities / naive datetime ->
    delegation-attestation-malformed."""
    need = _need()
    if need:
        return need
    try:
        _df.CapabilityAttestation(
            issuer="agent://planner", subject="agent://worker",
            capabilities="tool:read",
            issued_at=NOW.replace(tzinfo=None), ttl_seconds=60,
            state_hash="0" * 64)
    except _df.DelegationFreshnessError as e:
        if e.code == "delegation-attestation-malformed":
            return {"verdict": "held"}
        return {"verdict": "gap",
                "note": "wrong code: %s" % e.code}
    return {"verdict": "gap", "note": "no refusal raised"}


def run_all():
    held = gap = errors = 0
    for sid in PROBE_NAMES:
        SITUATIONS[sid]()
    for r in RESULTS:
        if r["verdict"] == "held":
            held += 1
        elif r["verdict"] == "gap":
            gap += 1
        else:
            errors += 1
    return held, gap, errors


def green_check_adjacent():
    """Depth-1 green check: adjacent delegation batteries must hold.

    Honors GOV_SKIP_GREEN: a parent's green check records a skip
    instead of spawning nested battery mains.
    """
    if GREEN_SKIP:
        return {"skipped": "GOV_SKIP_GREEN=1 (depth-1 green check)"}
    import subprocess
    repo = os.path.join(os.path.dirname(__file__), "..")
    adj = [
        "evals/delegation_receipt_probes.py",
    ]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    out = {}
    for rel in adj:
        path = os.path.join(repo, rel)
        if not os.path.exists(path):
            out[rel] = "missing"
            continue
        try:
            p = subprocess.run(
                [sys.executable, path], env=env, cwd=repo,
                capture_output=True, text=True, timeout=600)
            out[rel] = "rc=%d" % p.returncode
        except Exception as e:  # noqa: BLE001
            out[rel] = "error: %s" % e
    return out


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md), red-first: the
# lowercase "gap" verdict is this battery's red phase (the exit contract is
# rc=2 on any gap) and maps to BREAK. Raw RESULTS keep the lowercase
# vocabulary (run_all() counts, and the adjacent green check's
# "held=%d gap=%d errors=%d" string, are untouched); the mapping happens at
# emission, following the w72 precedent. Unknown verdicts fall back to BREAK
# (red-first, never greener).
_VERDICT_MAP = {"held": "HELD", "gap": "BREAK", "error": "ERROR",
                "stopped": "HELD"}


def _note_of(row):
    # D2 contract (w72 precedent): the note lives under detail["note"],
    # falling back to detail["error"] for harness exceptions.
    return row["detail"].get("note") or row["detail"].get("error", "")

def main():
    held, gap, errors = run_all()
    rows = [{"id": r["id"],
             "verdict": _VERDICT_MAP.get(r["verdict"], "BREAK"),
             "detail": r["detail"]} for r in RESULTS]
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        [(r["id"], r["verdict"], _note_of(r)) for r in rows],
        gap, held, errors)
    probe_lines.emit_dicts(rows, pid_key="id", note_getter=_note_of)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("w245_delegation_freshness: %d BREAK / %d HELD / %d ERROR"
          % (gap, held, errors))
    green = green_check_adjacent()
    print("adjacent green check: %s" % (green,))
    bad = [k for k, v in green.items()
           if isinstance(v, str) and not v.startswith("rc=0")]
    rc = 0
    if gap or errors or bad:
        rc = 2
    return rc


if __name__ == "__main__":
    sys.exit(main())
