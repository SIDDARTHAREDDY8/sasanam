#!/usr/bin/env python3
"""Wave-212 lane C break-first battery: leased-credential public seam.

ADAPT of the OpenBao dynamic-secret lease lifecycle as a sibling
interface (``gov/leased_credentials.py``). Red-first protocol: this
battery is written and run BEFORE the module exists (pristine RED =
import fails / enforcement absent), then re-run against the
implementation (fixed GREEN).

Hypotheses (diagnosing-bugs loop):
  H1 (rank 1): using a credential whose lease has expired must fail
     closed -- expiry is a revocation promise, not an exfil bound, but
     the proxy must never substitute a dead lease.
  H2 (rank 2): an unknown renewal result (transport error, "lease not
     found", unparseable body) must fail closed -- the lease is marked
     dead and subsequent delivery refuses. Never cache "valid".
  H3 (rank 3): a revoked lease must refuse delivery, even if local
     expiry had not passed.
  H4 (rank 4): renewal past the lease max TTL must be refused (no
     silent lifetime extension).
  H5 (rank 5): the agent-visible handle is a fake_value_<uuid>
     placeholder; the real secret never appears in audit events and
     substitutes only for an authorized host.
  H6 (rank 6): response wrapping is one-use and host-bound: double
     unwrap burns the token; unwrap from a non-authorized host fails
     and burns the token.
  H7 (rank 7): every lifecycle event (issue/renew/renew-fail/revoke/
     expiry-refusal/wrap/unwrap) is audit-logged without secrets.
  H8 (rank 8): no stale "valid" cache across revocation: a guard that
     passed before revocation must fail after it.
  H9 (rank 9): a down transport at issue time fails closed (nothing
     issued, loud error).

$0 spend. No network. stdlib only.
"""

import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        def run():
            try:
                detail = fn()
            except ImportError as e:
                _RESULTS.append((name, "ERROR", "missing module: %s" % e))
                return
            except AssertionError as e:
                _RESULTS.append((name, "ERROR", "assertion: %s"
                                 % str(e)[:300]))
                return
            except Exception as e:  # noqa: BLE001 - hostile-input battery
                _RESULTS.append((name, "ERROR", "%s: %s"
                                 % (type(e).__name__, str(e)[:300])))
                return
            verdict, detail = detail
            assert verdict in ("HELD", "BREAK", "RESIDUAL"), verdict
            _RESULTS.append((name, verdict, detail))
        _PROBE_FNS[name] = run
        return run
    return deco


# ------------------------------------------------------------------ helpers

def _lease_mod():
    from gov import leased_credentials as lc
    return lc


class _Audit(list):
    """In-memory audit log: append(dict) only."""
    def append(self, ev):
        assert isinstance(ev, dict), "audit event must be a dict"
        super().append(ev)


def _mgr(lc, transport, audit, t0):
    clock = [t0]

    def now():
        return clock[0]

    m = lc.LeasedCredentialManager(transport, token="fake-op-token",
                                   audit_log=audit, now=now)
    return m, clock


def _issue(lc, m, **kw):
    kw.setdefault("credential_id", "db-primary-password")
    kw.setdefault("agent_id", "agent-7")
    kw.setdefault("run_id", "run-1")
    kw.setdefault("credential_kind", "db-password")
    kw.setdefault("source_path", "database/creds/app")
    kw.setdefault("inject_hosts", ["db.internal.example.com"])
    kw.setdefault("ttl_s", 600)
    kw.setdefault("max_ttl_s", 3600)
    kw.setdefault("secret", "SYNTHETIC-db-secret-01")
    return m.issue_lease(**kw)


# ------------------------------------------------------------------- probes

@_probe("expired_lease_use_refused")
def p_expired():
    lc = _lease_mod()
    audit = _Audit()
    t, clock = _mgr(lc, lc.FakeLeaseTransport(), audit, 1000.0)
    rec, sentinel = _issue(lc, t, ttl_s=10)
    clock[0] = 1011.0  # past expiry
    try:
        t.deliver(rec.lease_id, sentinel=sentinel,
                  dest_host="db.internal.example.com")
        return ("BREAK",
                "delivery from an expired lease succeeded -- "
                "revocation promise not enforced")
    except lc.LeaseError:
        pass
    evts = [e["action"] for e in audit if e.get("lease_id") == rec.lease_id]
    if "use_refused" not in evts:
        return ("BREAK", "expired use refused but no audit event")
    return ("HELD", "expired lease delivery refused; use_refused audited")


@_probe("unknown_renewal_fails_closed")
def p_unknown_renew():
    lc = _lease_mod()
    audit = _Audit()
    fake = lc.FakeLeaseTransport()
    t, clock = _mgr(lc, fake, audit, 2000.0)
    rec, sentinel = _issue(lc, t, ttl_s=300, max_ttl_s=900)
    # Transport loses the lease out-of-band (unknown to the manager's
    # local record): renew must fail closed, NOT trust the local expiry.
    fake.forget_lease(rec.lease_id)
    try:
        t.renew_lease(rec.lease_id)
        return ("BREAK",
                "renew against an unknown lease succeeded -- status "
                "unknown must fail closed")
    except lc.LeaseError:
        pass
    st = t.lease_status(rec.lease_id)
    if st != "dead":
        return ("BREAK", "lease not marked dead after unknown renewal")
    try:
        t.deliver(rec.lease_id, sentinel=sentinel,
                  dest_host="db.internal.example.com")
        return ("BREAK", "delivery succeeded after unknown renewal")
    except lc.LeaseError:
        pass
    return ("HELD", "unknown renewal marked the lease dead; delivery "
                    "refused fail-closed")


@_probe("revoked_lease_use_refused")
def p_revoked():
    lc = _lease_mod()
    audit = _Audit()
    t, clock = _mgr(lc, lc.FakeLeaseTransport(), audit, 3000.0)
    rec, sentinel = _issue(lc, t, ttl_s=600)
    t.revoke_lease(rec.lease_id, reason="incident-response")
    if t.lease_status(rec.lease_id) != "revoked":
        return ("BREAK", "status not revoked after revoke")
    try:
        t.deliver(rec.lease_id, sentinel=sentinel,
                  dest_host="db.internal.example.com")
        return ("BREAK", "delivery succeeded on a revoked lease")
    except lc.LeaseError:
        pass
    return ("HELD", "revoked lease refuses delivery; status=revoked")


@_probe("no_renew_past_max_ttl")
def p_max_ttl():
    lc = _lease_mod()
    audit = _Audit()
    t, clock = _mgr(lc, lc.FakeLeaseTransport(), audit, 4000.0)
    rec, sentinel = _issue(lc, t, ttl_s=600, max_ttl_s=600)
    try:
        t.renew_lease(rec.lease_id, increment_s=600)
        return ("BREAK", "renew past max_ttl accepted -- silent "
                         "lifetime extension")
    except lc.LeaseError:
        pass
    rec2 = t.lease_record(rec.lease_id)
    if rec2.expires_at != 4600.0:
        return ("BREAK", "expiry mutated by a refused renew")
    return ("HELD", "renew past max_ttl refused; expiry unchanged")


@_probe("sentinel_exfil_resists")
def p_sentinel():
    lc = _lease_mod()
    audit = _Audit()
    t, clock = _mgr(lc, lc.FakeLeaseTransport(), audit, 5000.0)
    rec, sentinel = _issue(lc, t)
    # H5a: the agent-visible handle must be a placeholder, not the secret.
    if not sentinel.startswith("fake_value_"):
        return ("BREAK", "agent handle is not a fake_value placeholder")
    # H5b: no audit event may carry the secret or the sentinel's real value.
    blob = json.dumps([dict(e) for e in audit])
    if "SYNTHETIC-db-secret-01" in blob:
        return ("BREAK", "real secret leaked into the audit log")
    # H5c: delivery to an unauthorized host must fail closed.
    try:
        t.deliver(rec.lease_id, sentinel=sentinel,
                  dest_host="evil.example.net")
        return ("BREAK", "delivery to unauthorized host succeeded")
    except lc.LeaseError:
        pass
    # H5d: delivery to the authorized host returns the secret.
    secret = t.deliver(rec.lease_id, sentinel=sentinel,
                       dest_host="db.internal.example.com")
    if secret != "SYNTHETIC-db-secret-01":
        return ("BREAK", "authorized delivery did not yield the secret")
    return ("HELD", "placeholder handles, no secret in audit, "
                    "host-gated delivery holds")


@_probe("wrap_one_use_host_bound")
def p_wrap():
    lc = _lease_mod()
    audit = _Audit()
    t, clock = _mgr(lc, lc.FakeLeaseTransport(), audit, 6000.0)
    rec, sentinel = _issue(lc, t)
    # H6a: wrap -> authorized unwrap yields the sentinel's secret.
    wrap = t.wrap_for_delivery(rec.lease_id, sentinel=sentinel,
                               dest_host="db.internal.example.com")
    if not wrap.startswith("wrap_"):
        return ("BREAK", "wrap token has wrong shape")
    secret = t.unwrap(wrap, dest_host="db.internal.example.com")
    if secret != "SYNTHETIC-db-secret-01":
        return ("BREAK", "first unwrap failed")
    # H6b: second unwrap of the same token fails (burned).
    try:
        t.unwrap(wrap, dest_host="db.internal.example.com")
        return ("BREAK", "wrap token reused after unwrap -- not one-use")
    except lc.LeaseError:
        pass
    # H6c: unwrap from a non-authorized host fails AND burns the token.
    wrap2 = t.wrap_for_delivery(rec.lease_id, sentinel=sentinel,
                                dest_host="db.internal.example.com")
    try:
        t.unwrap(wrap2, dest_host="evil.example.net")
        return ("BREAK", "unwrap from unauthorized host succeeded")
    except lc.LeaseError:
        pass
    try:
        t.unwrap(wrap2, dest_host="db.internal.example.com")
        return ("BREAK", "token survived a failed hostile unwrap")
    except lc.LeaseError:
        pass
    evts = [e["action"] for e in audit if e.get("lease_id") == rec.lease_id]
    if "unwrap_intercepted" not in evts:
        return ("BREAK", "hostile unwrap not audited as intercepted")
    return ("HELD", "wrapping is one-use, host-bound, interception "
                    "audited")


@_probe("lifecycle_events_audited")
def p_lifecycle():
    lc = _lease_mod()
    audit = _Audit()
    t, clock = _mgr(lc, lc.FakeLeaseTransport(), audit, 7000.0)
    rec, sentinel = _issue(lc, t, ttl_s=5)
    t.renew_lease(rec.lease_id, increment_s=100)
    t.revoke_lease(rec.lease_id, reason="test")
    try:
        t.deliver(rec.lease_id, sentinel=sentinel,
                  dest_host="db.internal.example.com")
    except lc.LeaseError:
        pass
    got = sorted({e["action"] for e in audit
                  if e.get("lease_id") == rec.lease_id})
    for want in ("issue", "renew", "revoke", "use_refused"):
        if want not in got:
            return ("BREAK", "lifecycle event missing: %s (got %s)"
                             % (want, got))
    blob = json.dumps([dict(e) for e in audit])
    if "SYNTHETIC-db-secret-01" in blob or "fake-op-token" in blob:
        return ("BREAK", "secret or operator token in audit events")
    for e in audit:
        if e.get("event") != "lease_lifecycle":
            return ("BREAK", "non-conforming audit event shape: %r" % e)
    return ("HELD", "issue/renew/revoke/use_refused audited, "
                    "no secrets, uniform event shape")


@_probe("no_stale_cache_across_revocation")
def p_no_stale():
    lc = _lease_mod()
    audit = _Audit()
    t, clock = _mgr(lc, lc.FakeLeaseTransport(), audit, 8000.0)
    rec, sentinel = _issue(lc, t, ttl_s=600)
    if t.lease_status(rec.lease_id) != "active":
        return ("BREAK", "fresh lease not active")
    # Out-of-band revocation on the server side only.
    t.transport.request("PUT", "/v1/sys/leases/revoke", {},
                        json.dumps({"lease_id": rec.lease_id}).encode())
    # The guard must not trust the earlier "active" observation: it
    # re-derives state (local record is refreshed by revocation; an
    # operator-side lookup hits the transport).
    if t.lease_status(rec.lease_id, recheck=True) != "revoked":
        return ("BREAK", "stale 'active' survived server-side revocation")
    try:
        t.deliver(rec.lease_id, sentinel=sentinel,
                  dest_host="db.internal.example.com")
        return ("BREAK", "delivery succeeded on a server-revoked lease")
    except lc.LeaseError:
        pass
    return ("HELD", "revocation re-checked; no stale valid cache")


@_probe("issue_transport_down_fails_closed")
def p_issue_down():
    lc = _lease_mod()
    audit = _Audit()
    fake = lc.FakeLeaseTransport(down=True)
    t, clock = _mgr(lc, fake, audit, 9000.0)
    try:
        _issue(lc, t)
        return ("BREAK", "issue succeeded with the transport down")
    except lc.LeaseError:
        pass
    if t.issued_lease_ids():
        return ("BREAK", "manager holds issued leases after failed issue")
    return ("HELD", "issue with down transport fails closed, "
                    "nothing issued")


# ------------------------------------------------------------ determinism

@_probe("determinism")
def p_determinism():
    snapshot = list(_RESULTS)  # results so far; restore before returning
    sigs = []
    for _ in range(2):
        run = []
        for name in list(_PROBE_FNS):
            if name == "determinism":
                continue
            _RESULTS.clear()
            _PROBE_FNS[name]()
            run.append(tuple(_RESULTS))
        sigs.append(tuple(run))
    _RESULTS.clear()
    _RESULTS.extend(snapshot)
    if sigs[0] != sigs[1]:
        return ("BREAK", "non-deterministic battery")
    return ("HELD", "all probes deterministic across 2 passes")


# ------------------------------------------------------------ green check

def _green_check():
    # Depth-1 green check: adjacent unit suites must stay green alongside
    # this battery (each run with GOV_SKIP_GREEN=1 to prevent nesting).
    import subprocess
    for mod in ("tests.test_kms_vault", "tests.test_attestation_release"):
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        r = subprocess.run(
            [sys.executable, "-m", "unittest", mod],
            capture_output=True, text=True, env=env, timeout=600, cwd=REPO)
        ok = r.returncode == 0
        tail = (r.stdout + r.stderr)[-300:]
        _RESULTS.append(("green:" + mod, "HELD" if ok else "ERROR",
                         "adjacent suite %s" % ("green" if ok
                                                else "RED: " + tail)))


def main():
    if not GREEN_SKIP:
        _green_check()
    for name in list(_PROBE_FNS):
        if name == "determinism":
            continue
        _PROBE_FNS[name]()
    _PROBE_FNS["determinism"]()
    n_break = n_held = n_res = n_err = 0
    for name, verdict, detail in _RESULTS:
        print("%-34s %-9s %s" % (name, verdict, detail))
        if verdict == "BREAK":
            n_break += 1
        elif verdict == "HELD":
            n_held += 1
        elif verdict == "RESIDUAL":
            n_res += 1
        else:
            n_err += 1
    print("w212 lease: breaks=%d held=%d residuals=%d errors=%d"
          % (n_break, n_held, n_res, n_err))
    # Red-first battery: on pristine the module is absent, so probes
    # ERROR; a claimed-fixed run must have zero BREAK and zero ERROR.
    bad = any(v not in ("HELD", "RESIDUAL") for _, v, _ in _RESULTS)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
