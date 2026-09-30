"""Wave-243 finality-bound revocation probes (red-first).

W243-2 — ADAPT of draft-das-finality-bound-revocation -00 (patterns
only; no draft text, no vendored code): each authorization is bound
at issue to a revocation basis/epoch, and the Finality Sink performs
an ATOMIC check-and-commit against that basis immediately before the
protected consequence commits.

  revoked-between-issue-and-commit-refused -- issue, revoke the
      basis, commit -> refuse revocation-applicable (a sink that
      commits here has the stale-authorization defect).
  live-basis-commits -- issue, no revocation, commit -> committed
      receipt (control).
  mid-check-mutation-refused -- adversarial store injects a
      revocation between the check and the commit decision ->
      refuse revocation-check-unsealed (falsifies TOCTOU).
  non-atomic-store-refused -- store without the atomic check
      protocol -> refuse revocation-sink-nonatomic (the sink fails
      closed rather than check-then-act).
  tampered-binding-refused -- basis_id edited after issue ->
      refuse revocation-basis-tampered (binding not re-derived from
      issuer trust).
  forged-authorization-refused -- hand-built authorization with a
      fabricated digest -> refuse revocation-basis-tampered.
  malformed-basis-refused -- empty basis_id at issue and commit on
      an unknown basis -> refuse revocation-basis-malformed.
  stale-authority-lapse-propagates -- authorization citing a lapsed
      authority with a post-lapse minted_at -> the wave-242
      stale-authority refusal propagates (reuse, not duplicate).
  expired-exception-propagates -- expired exception declaration ->
      gate-undecidable propagates (an expired exception no longer
      shields).

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import traceback
from datetime import datetime, timezone

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_FB = False
try:
    from gov import finality_bound as _fb
    HAVE_FB = all(hasattr(_fb, n) for n in (
        "issue_authorization", "finality_sink_commit",
        "RevocationStore", "FinalityBoundError",
        "REVOCATION_APPLICABLE", "REVOCATION_BASIS_MALFORMED",
        "REVOCATION_BASIS_TAMPERED", "REVOCATION_CHECK_UNSEALED",
        "REVOCATION_SINK_NONATOMIC"))
except ImportError:
    _fb = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "revoked-between-issue-and-commit-refused",
    "live-basis-commits",
    "mid-check-mutation-refused",
    "non-atomic-store-refused",
    "tampered-binding-refused",
    "forged-authorization-refused",
    "malformed-basis-refused",
    "stale-authority-lapse-propagates",
    "expired-exception-propagates",
]


def _run_probe(name, fn, have):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _store(basis="basis-1"):
    store = _fb.RevocationStore()
    store.register_basis(basis)
    return store


def _issue(store, basis="basis-1", now=1000, **kwargs):
    return _fb.issue_authorization(
        "agent-7", "write-file", basis, "issuer-anchor-9",
        store, now, **kwargs)


def _expect(code, fn):
    try:
        fn()
    except _fb.FinalityBoundError as exc:
        assert exc.code == code, "code %r != %r" % (exc.code, code)
        return exc
    raise AssertionError("expected FinalityBoundError %r; allowed" % (code,))


class _RacingStore(_fb.RevocationStore if HAVE_FB else object):
    """Adversarial store: a revocation lands BETWEEN the check and
    the commit decision, falsifying TOCTOU."""

    def __init__(self, race_basis, race_epoch, race_now):
        super(_RacingStore, self).__init__()
        self._race_basis = race_basis
        self._race_epoch = race_epoch
        self._race_now = race_now

    def revocation_epoch(self, basis_id):
        self.revoke(self._race_basis, self._race_epoch, self._race_now)
        return super(_RacingStore, self).revocation_epoch(basis_id)


class _NonAtomicStore(object):
    """A store that cannot offer the atomic check protocol."""

    def __init__(self):
        self._bases = {"basis-1": None}

    def revocation_epoch(self, basis_id):
        return self._bases[basis_id]


def _probe_revoked_between_issue_and_commit_refused():
    store = _store()
    authz = _issue(store, now=1000)
    store.revoke("basis-1", 1500, 1500)
    exc = _expect("revocation-applicable",
                  lambda: _fb.finality_sink_commit(authz, store, 1600))
    assert "basis-1" in exc.detail, exc.detail
    return "revoked basis refused at commit with revocation-applicable"


def _probe_live_basis_commits():
    store = _store()
    authz = _issue(store, now=1000)
    receipt = _fb.finality_sink_commit(authz, store, 1200)
    assert receipt["committed"] is True, receipt
    assert receipt["basis_revocation_epoch"] is None, receipt
    return "live basis commits; receipt carries the atomic sequence"


def _probe_mid_check_mutation_refused():
    store = _RacingStore("basis-1", 1050, 1050)
    store.register_basis("basis-1")
    authz = _issue(store, now=1000)
    exc = _expect("revocation-check-unsealed",
                  lambda: _fb.finality_sink_commit(authz, store, 1100))
    assert "atomic" in exc.detail, exc.detail
    return "mid-check mutation detected; check-and-commit not atomic"


def _probe_non_atomic_store_refused():
    store = _NonAtomicStore()
    store2 = _store()
    authz = _issue(store2, now=1000)
    exc = _expect("revocation-sink-nonatomic",
                  lambda: _fb.finality_sink_commit(authz, store, 1100))
    assert "atomic" in exc.detail.lower(), exc.detail
    return "non-atomic store fails closed; no check-then-act"


def _probe_tampered_binding_refused():
    store = _store()
    authz = _issue(store, now=1000)
    authz["binding"]["basis_id"] = "basis-2"
    exc = _expect("revocation-basis-tampered",
                  lambda: _fb.finality_sink_commit(authz, store, 1100))
    assert "issuer trust" in exc.detail, exc.detail
    return "edited basis_id fails the digest; not re-derived from trust"


def _probe_forged_authorization_refused():
    store = _store()
    forged = {
        "type": "finality-bound-authorization",
        "binding": {
            "subject": "agent-7",
            "action": "write-file",
            "basis_id": "basis-1",
            "revocation_epoch_at_issue": None,
            "issued_at": 1000,
        },
        "issuer_trust_anchor": "issuer-anchor-9",
        "binding_digest": "0" * 64,
    }
    _expect("revocation-basis-tampered",
            lambda: _fb.finality_sink_commit(forged, store, 1100))
    return "hand-built authorization with fabricated digest refused"


def _probe_malformed_basis_refused():
    store = _store()
    _expect("revocation-basis-malformed",
            lambda: _issue(store, basis="", now=1000))
    authz = _issue(store, now=1000)
    authz["binding"]["basis_id"] = "never-registered"
    # Recompute nothing: the digest check runs before the store read, so an
    # unknown basis with a stale digest is tampered first.
    _expect("revocation-basis-tampered",
            lambda: _fb.finality_sink_commit(authz, store, 1100))
    store2 = _store()
    authz2 = _issue(store2, now=1000)
    # Forge a digest-consistent authorization for an unknown basis:
    # recompute the digest the way issue_authorization does.
    import hashlib
    import json
    binding = dict(authz2["binding"])
    binding["basis_id"] = "never-registered"
    canon = json.dumps(
        {"binding": binding, "issuer_trust_anchor": "issuer-anchor-9"},
        sort_keys=True, separators=(",", ":"),
        ensure_ascii=True).encode("utf-8")
    authz2["binding"] = binding
    authz2["binding_digest"] = hashlib.sha256(canon).hexdigest()
    _expect("revocation-basis-malformed",
            lambda: _fb.finality_sink_commit(authz2, store2, 1100))
    return "empty basis at issue and unknown basis at commit fail closed"


def _probe_stale_authority_lapse_propagates():
    from gov import stale_authority as _sa
    store = _store()
    minted = datetime(2026, 10, 14, tzinfo=timezone.utc)
    authz = _issue(
        store, now=1000,
        authority_id="draft-emirdag-scitt-ai-agent-execution-00",
        minted_at=minted)
    try:
        _fb.finality_sink_commit(authz, store, 1100)
    except _sa.StaleAuthorityError as exc:
        assert exc.code == "stale-authority", exc.code
        return "lapsed-authority refusal propagates from the sink"
    raise AssertionError("post-lapse authority passed the sink")


def _probe_expired_exception_propagates():
    from gov import exception_ttl as _et
    from gov import gate_outcomes as _go
    store = _store()
    exc_decl = _et.declare_exception(
        valid_until=1200, reason="maintenance window", scope="sink-1",
        issued_at=1000)
    authz = _issue(store, now=1000)
    try:
        _fb.finality_sink_commit(authz, store, 1300,
                                 exception=exc_decl, scope="sink-1")
    except _go.GateOutcomeError as exc:
        assert exc.code == "gate-undecidable", exc.code
        return "expired exception no longer shields the sink"
    raise AssertionError("expired exception shielded the commit")


_PROBES = {
    "revoked-between-issue-and-commit-refused":
        (_probe_revoked_between_issue_and_commit_refused, HAVE_FB),
    "live-basis-commits":
        (_probe_live_basis_commits, HAVE_FB),
    "mid-check-mutation-refused":
        (_probe_mid_check_mutation_refused, HAVE_FB),
    "non-atomic-store-refused":
        (_probe_non_atomic_store_refused, HAVE_FB),
    "tampered-binding-refused":
        (_probe_tampered_binding_refused, HAVE_FB),
    "forged-authorization-refused":
        (_probe_forged_authorization_refused, HAVE_FB),
    "malformed-basis-refused":
        (_probe_malformed_basis_refused, HAVE_FB),
    "stale-authority-lapse-propagates":
        (_probe_stale_authority_lapse_propagates, HAVE_FB),
    "expired-exception-propagates":
        (_probe_expired_exception_propagates, HAVE_FB),
}


def _run_green_checks():
    """Adjacent-seam sanity: no product-code regression. Depth-1 only;
    honors GOV_SKIP_GREEN=1 (never spawns another battery's main)."""
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    try:
        from gov import decision_codes as _dc
        for code in ("revocation-applicable",
                     "revocation-basis-malformed",
                     "revocation-basis-tampered",
                     "revocation-check-unsealed",
                     "revocation-sink-nonatomic"):
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-243 finality-bound revocation probes (finality_bound: %s)"
          % (HAVE_FB,))
    held = gap = 0
    for name in PROBE_NAMES:
        fn, have = _PROBES[name]
        name_r, status, note = _run_probe(name, fn, have)
        if status == "HELD":
            held += 1
        elif status == "GAP":
            gap += 1
        print("%-42s %s %s" % (name_r, status, note))
    notes = _run_green_checks()
    for note in notes:
        print("green: %s" % note)
    print("summary: %d HELD / %d GAP / %d total"
          % (held, gap, len(PROBE_NAMES)))
    if held != len(PROBE_NAMES):
        raise SystemExit("battery not fully HELD (%d/%d)"
                         % (held, len(PROBE_NAMES)))


if __name__ == "__main__":
    main()
