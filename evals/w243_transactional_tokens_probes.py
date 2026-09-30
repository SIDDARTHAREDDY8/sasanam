"""Wave-243 transactional-token probes (red-first).

W243-3 — ADAPT (patterns only) of
draft-tulshi-oauth-transactional-access-tokens -00: per-transaction
fresh authorization-server policy decisions, with each authorization
scoped by the triple (txn-id binding, very-short-lifetime,
single-resource-server audience) -- the OAuth-native stale-authority answer.

Probes (a verifier that passes a token where it should refuse has the
corresponding defect):

  txn-reuse-refused -- a token issued for txn "t1", presented against
      expected txn "t2" (MAC intact, within lifetime) -> refuse
      transaction-id-mismatch.
  expired-refused -- a token presented after its embedded expiry (per-token
      lifetime, injectable clock) -> refuse transaction-expired. The
      lifetime is a per-token property carried and signed inside the token,
      never a duration config the caller can extend.
  wrong-rs-refused -- a token issued for rs "payments", presented to
      expected rs "ledger" (MAC intact) -> refuse resource-server-mismatch.
  malformed-refused -- non-dict token, dict missing fields, non-string
      txn_id, bool expiry -> refuse transaction-malformed (fail closed).
  tampered-refused -- MAC-intact token with one byte flipped in txn_id ->
      refuse transaction-signature-invalid (the MAC check runs BEFORE any
      binding check, so tampering is never reported as a mere mismatch).
  lifetime-is-per-token -- issue() requires an explicit ttl argument (no
      default a caller could extend); a ttl beyond the very-short cap
      (300s) is refused at issue as transaction-malformed.
  no-key-fails-closed -- an issuer or verifier built without a deployment
      key refuses transaction-key-missing (the dev-key fallback was
      removed; there is no silent insecure default).

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import inspect
import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_TT = False
try:
    from gov import transactional_tokens as _tt
    HAVE_TT = all(hasattr(_tt, n) for n in (
        "TransactionalTokenIssuer", "TransactionalTokenError",
        "TRANSACTION_TTL_MAX_SECONDS", "CODES"))
except ImportError:
    _tt = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_KEY = b"wave243-test-key-0123456789abcdef"

PROBE_NAMES = [
    "txn-reuse-refused",
    "expired-refused",
    "wrong-rs-refused",
    "malformed-refused",
    "tampered-refused",
    "lifetime-is-per-token",
    "no-key-fails-closed",
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


def _issue(now):
    return _tt.TransactionalTokenIssuer(_KEY).issue(
        "txn-1", "https://rs.example", 60, now=now)


def _probe_txn_reuse_refused():
    token = _issue(1_700_000_000)
    try:
        _tt.TransactionalTokenIssuer(_KEY).verify(
            token, "txn-2", "https://rs.example", now=1_700_000_001)
    except _tt.TransactionalTokenError as exc:
        assert exc.code == "transaction-id-mismatch", exc.code
        return "cross-transaction reuse refused with transaction-id-mismatch"
    raise AssertionError("token issued for txn-1 passed against txn-2")


def _probe_expired_refused():
    token = _issue(1_700_000_000)
    try:
        _tt.TransactionalTokenIssuer(_KEY).verify(
            token, "txn-1", "https://rs.example", now=1_700_000_061)
    except _tt.TransactionalTokenError as exc:
        assert exc.code == "transaction-expired", exc.code
        return "past-lifetime presentation refused with transaction-expired"
    raise AssertionError("expired token passed")


def _probe_wrong_rs_refused():
    token = _issue(1_700_000_000)
    try:
        _tt.TransactionalTokenIssuer(_KEY).verify(
            token, "txn-1", "https://rs.example.other", now=1_700_000_001)
    except _tt.TransactionalTokenError as exc:
        assert exc.code == "resource-server-mismatch", exc.code
        return "wrong resource server refused with resource-server-mismatch"
    raise AssertionError("token for rs.example passed against "
                         "rs.example.other")


def _probe_malformed_refused():
    issuer = _tt.TransactionalTokenIssuer(_KEY)
    cases = [
        (None, "non-dict token"),
        ({"v": 1}, "dict missing fields"),
        ("wire-string", "string token"),
        (dict(_issue(1_700_000_000), txn_id=123), "non-string txn_id"),
        (dict(_issue(1_700_000_000), exp=True), "bool expiry"),
    ]
    for token, label in cases:
        try:
            issuer.verify(token, "txn-1", "https://rs.example",
                          now=1_700_000_001)
        except _tt.TransactionalTokenError as exc:
            assert exc.code == "transaction-malformed", (label, exc.code)
            continue
        raise AssertionError("malformed token passed: %s" % label)
    return "5 malformed shapes all fail closed with transaction-malformed"


def _probe_tampered_refused():
    token = dict(_issue(1_700_000_000))
    token["txn_id"] = "txn-2"  # MAC no longer covers the bytes
    try:
        _tt.TransactionalTokenIssuer(_KEY).verify(
            token, "txn-2", "https://rs.example", now=1_700_000_001)
    except _tt.TransactionalTokenError as exc:
        assert exc.code == "transaction-signature-invalid", exc.code
        return "tampered txn_id refused before binding checks"
    raise AssertionError("tampered token passed")


def _probe_lifetime_is_per_token():
    sig = inspect.signature(_tt.TransactionalTokenIssuer.issue)
    ttl_param = sig.parameters.get("ttl_seconds")
    assert ttl_param is not None, "issue() has no ttl_seconds parameter"
    assert ttl_param.default is inspect.Parameter.empty, \
        "issue() ttl_seconds has a caller-extendable default"
    issuer = _tt.TransactionalTokenIssuer(_KEY)
    try:
        issuer.issue("txn-1", "https://rs.example", 3600, now=1_700_000_000)
    except _tt.TransactionalTokenError as exc:
        assert exc.code == "transaction-malformed", exc.code
        return ("ttl is a required per-token argument; 3600s over the "
                "300s very-short cap refused at issue")
    raise AssertionError("3600s ttl issued past the very-short cap")


def _probe_no_key_fails_closed():
    for call in (
            lambda: _tt.TransactionalTokenIssuer(None).issue(
                "txn-1", "https://rs.example", 60, now=1_700_000_000),
            lambda: _tt.TransactionalTokenIssuer(None).verify(
                _issue(1_700_000_000), "txn-1", "https://rs.example",
                now=1_700_000_001),
    ):
        try:
            call()
        except _tt.TransactionalTokenError as exc:
            assert exc.code == "transaction-key-missing", exc.code
            continue
        raise AssertionError("keyless issuer/verifier did not fail closed")
    return "no deployment key -> transaction-key-missing (no dev fallback)"


_PROBES = {
    "txn-reuse-refused": (_probe_txn_reuse_refused, HAVE_TT),
    "expired-refused": (_probe_expired_refused, HAVE_TT),
    "wrong-rs-refused": (_probe_wrong_rs_refused, HAVE_TT),
    "malformed-refused": (_probe_malformed_refused, HAVE_TT),
    "tampered-refused": (_probe_tampered_refused, HAVE_TT),
    "lifetime-is-per-token": (_probe_lifetime_is_per_token, HAVE_TT),
    "no-key-fails-closed": (_probe_no_key_fails_closed, HAVE_TT),
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
        for code in _tt.CODES:
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    try:
        from gov import aauth_egress as _ae
        _ae.check_audience("x", "x")
        notes.append("aauth_egress audience primitive still coherent")
    except Exception as exc:  # noqa: BLE001
        notes.append("aauth coherence check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-243 transactional-token probes (have module: %s)"
          % (HAVE_TT,))
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
