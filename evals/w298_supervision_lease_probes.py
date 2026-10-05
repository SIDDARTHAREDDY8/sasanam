"""Wave-298 lane 4 battery: supervision<->lease restart composition.

Base: wave-297 merge 5662f8874b63724a1bfd1f4441b470bfe1ba43d8
(verified via git rev-parse HEAD before work).

New product surface (all additive, gov/supervision.py only):
  (a) ChildSpec(..., requires_lease=True) -- declared lease-gated
      children;
  (b) report_crash on a lease-gated child issues a signed,
      digest-bound, single-use, time-boxed ``reacquire_lease``
      obligation referencing the crashed child's old fencing token;
      the old token is recorded dead-on-restart;
  (c) Supervisor.attest_reacquisition verifies the new lease
      (signature via gov.coordination_lease.verify_lease, holder ==
      child, issued AFTER the crash instant, DIFFERENT fencing
      token) and marks the child re-entered -- single use, no
      replays, no re-entry without attestation;
  (d) Supervisor.guard_write refuses coded coord-lease-fencing on
      dead-on-restart tokens (belt and suspenders; the lease
      module's own fencing check stays authoritative);
  (e) expired unsatisfied obligations escalate (supervisor-signed)
      instead of silently stranding the child -- new code
      ``supervision-lease-obligation-expired``; pin 1770 -> 1770; wave-298 merge: pin 1770 -> 1780.

Red-first: on the pristine base the new-API probes BREAK (feature
absent: ChildSpec rejects requires_lease; no attest_reacquisition /
guard_write / sweep_obligations); on the fixed tree they must HELD
with loud coded refusals.

Run:
  mkdir -p /var/tmp/g298-sl && TMPDIR=/var/tmp/g298-sl \
    ~/workspace/.gov-venv/bin/python evals/w298_supervision_lease_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g298-sl2 \
    ~/workspace/.gov-venv/bin/python evals/w298_supervision_lease_probes.py
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 2083 # Wave-298 lane 4: pin 1769 -> 1770 (+1 supervision-lease-obligation-expired); wave-298 merge: pin 1770 -> 1780 (+11 codes); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*) # Wave-334 lane 6: pin 2077 -> 2083 (+6 incident-gpai9-*).



_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    dead battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate code literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "code literals not sorted")
    want = "supervision-lease-obligation-expired"
    if want not in lits:
        return _record("pin-taxonomy", "BREAK",
                       "missing expected code %r" % want)
    _record("pin-taxonomy", "HELD", "1991 raw literals, unique, sorted")




def _import_mods():
    try:
        from gov import supervision
        from gov import coordination_lease
        from gov import ed25519
    except ImportError:
        return None, None, None
    return supervision, coordination_lease, ed25519


def _need(pid):
    sup, lease, ed = _import_mods()
    if sup is None:
        _record(pid, "BREAK", "feature absent on this tree "
                              "(gov.supervision missing)")
        return None, None, None
    return sup, lease, ed


def _seed(tag):
    return hashlib.sha256(("w298-supervision-lease-%s" % tag).encode()).digest()


def _pub(ed, seed):
    return ed.publickey(seed).hex()


def _sup1(sup, ed, strategy="one_for_one", max_restarts=100,
          window_seconds=3600, gated=True):
    """Supervisor with two children; child-a is lease-gated when
    ``gated``. Returns (supervisor, child_seeds, sup_seed)."""
    sup_seed = _seed("sup1")
    c0 = _seed("child-a")
    c1 = _seed("child-b")
    specs = [
        sup.ChildSpec("child-a", _pub(ed, c0), strategy,
                      max_restarts, window_seconds, requires_lease=gated),
        sup.ChildSpec("child-b", _pub(ed, c1), strategy,
                      max_restarts, window_seconds),
    ]
    s = sup.Supervisor("sup-one", specs, sup_seed)
    s.start(at=0)
    return s, {"child-a": c0, "child-b": c1}, sup_seed


def _report(ed, child_seed, child_id, reason, crashed_at):
    body = {"child_id": child_id, "reason_kind": "exit",
            "reason_bytes": reason, "crashed_at": crashed_at}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode()
    sig = ed.sign(child_seed, raw).hex()
    rep = dict(body)
    rep["signature"] = sig
    return rep


def _crash_gated(sup, ed, s, seeds, at=10, reason="boom-1",
                 old_token=None, ttl=None):
    rep = _report(ed, seeds["child-a"], "child-a", reason, at)
    kw = {"old_fencing_tokens": {"child-a": old_token}
          } if old_token is not None else {}
    if ttl is not None:
        kw["obligation_ttl"] = ttl
    return s.report_crash("child-a", rep, at=at, **kw)


def _leases_pair(lease, ed, scope="scope-a", holder="child-a"):
    """Two sequential leases on one scope: old (token 1) then new
    (token 2). Returns (authority_seed, old_lease, new_lease)."""
    auth = _seed("authority")
    old = lease.LeaseManager().acquire(scope, 3600, holder,
                                       authority_seed=auth, issued_at=0)
    mgr = lease.LeaseManager()
    # Re-create the same manager state: acquire old, release, acquire
    # new -- the new generation takes a HIGHER fencing token.
    m2 = lease.LeaseManager()
    o = m2.acquire(scope, 3600, holder, authority_seed=auth, issued_at=0)
    m2.release(scope, o["fencing_token"], holder)
    new = m2.acquire(scope, 3600, holder, authority_seed=auth, issued_at=20)
    return auth, o, new


def _expect(pid, fn, code, note):
    sup, lease, ed = _need(pid)
    if sup is None:
        return
    try:
        fn(sup, lease, ed)
    except (sup.SupervisionError, lease.CoordinationLeaseError) as e:
        if e.code == code:
            return _record(pid, "HELD", note)
        return _record(pid, "BREAK",
                       "wrong code: got %r want %r (%s)" % (e.code, code, note))
    except Exception as e:  # noqa: BLE001
        return _record(pid, "BREAK", "uncoded escape %r (%s)" % (e, note))
    _record(pid, "BREAK", "no refusal at all (%s)" % note)


# -- declaration ---------------------------------------------------------

def p_spec_requires_lease():
    sup, lease, ed = _need("sl-spec-declare")
    if sup is None:
        return
    c = _seed("x")
    try:
        spec = sup.ChildSpec("child-x", _pub(ed, c), "one_for_one",
                             5, 60, requires_lease=True)
    except TypeError:
        return _record("sl-spec-declare", "BREAK",
                       "ChildSpec has no requires_lease kwarg (feature absent)")
    if spec.requires_lease is not True:
        return _record("sl-spec-declare", "BREAK", "requires_lease not stored")
    plain = sup.ChildSpec("child-y", _pub(ed, c), "one_for_one", 5, 60)
    if plain.requires_lease is not False:
        return _record("sl-spec-declare", "BREAK",
                       "requires_lease default must be False")
    try:
        plain.requires_lease = True
    except sup.SupervisionError as e:
        if e.code != "supervision-invalid":
            return _record("sl-spec-declare", "BREAK",
                           "frozen-spec wrong code %r" % (e.code,))
    else:
        return _record("sl-spec-declare", "BREAK",
                       "spec mutation did not refuse")
    _record("sl-spec-declare", "HELD",
            "requires_lease declared, defaults False, spec stays frozen")


def p_spec_requires_lease_bad():
    def _go(sup, lease, ed):
        c = _seed("x")
        sup.ChildSpec("child-x", _pub(ed, c), "one_for_one", 5, 60,
                      requires_lease="yes")
    _expect("sl-spec-badtype", _go, "supervision-invalid",
            "non-bool requires_lease refuses coded")


def p_crash_issues_obligation():
    sup, lease, ed = _need("sl-obligation-issued")
    if sup is None:
        return
    s, seeds, sup_seed = _sup1(sup, ed)
    d = _crash_gated(sup, ed, s, seeds, at=10, old_token=7)
    obls = d.get("lease_obligations")
    if not isinstance(obls, dict) or "child-a" not in obls:
        return _record("sl-obligation-issued", "BREAK",
                       "no lease_obligations for the gated child: %r" % (d,))
    obl = obls["child-a"]
    if obl.get("schema") != "supervision/lease-obligation/v1":
        return _record("sl-obligation-issued", "BREAK",
                       "wrong obligation schema: %r" % (obl,))
    if obl.get("old_fencing_token") != 7 or obl.get("child_id") != "child-a":
        return _record("sl-obligation-issued", "BREAK",
                       "obligation does not bind child/token: %r" % (obl,))
    sig = obl.get("signature")
    body = {k: v for k, v in obl.items() if k != "signature"}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode()
    ok = ed.verify(bytes.fromhex(s.supervisor_pubkey),
                   raw, bytes.fromhex(sig))
    if ok is not True:
        return _record("sl-obligation-issued", "BREAK",
                       "obligation signature does not verify")
    # The non-gated child gets no obligation.
    if "child-b" in obls:
        return _record("sl-obligation-issued", "BREAK",
                       "non-gated child must not get an obligation")
    _record("sl-obligation-issued", "HELD",
            "signed digest-bound obligation issued; non-gated child exempt")


def p_crash_no_obligation_plain():
    sup, lease, ed = _need("sl-no-obligation-plain")
    if sup is None:
        return
    s, seeds, _ = _sup1(sup, ed, gated=False)
    d = s.report_crash("child-a",
                       _report(ed, seeds["child-a"], "child-a", "boom", 10),
                       at=10)
    if d.get("lease_obligations"):
        return _record("sl-no-obligation-plain", "BREAK",
                       "plain child must carry no obligations")
    _record("sl-no-obligation-plain", "HELD",
            "additive: non-gated crash decision unchanged")


# -- attestation ---------------------------------------------------------

def p_attest_happy_path():
    sup, lease, ed = _need("sl-attest-ok")
    if sup is None:
        return
    s, seeds, _ = _sup1(sup, ed)
    auth = _seed("authority")
    mgr = lease.LeaseManager()
    old = mgr.acquire("scope-a", 3600, "child-a",
                      authority_seed=auth, issued_at=0)
    d = _crash_gated(sup, ed, s, seeds, at=10, old_token=old["fencing_token"])
    obl = d["lease_obligations"]["child-a"]
    mgr.release("scope-a", old["fencing_token"], "child-a")
    new = mgr.acquire("scope-a", 3600, "child-a",
                      authority_seed=auth, issued_at=20)
    if s.is_reentered("child-a"):
        return _record("sl-attest-ok", "BREAK",
                       "child re-entered before attestation")
    r = s.attest_reacquisition("child-a", obl, new, _pub(ed, auth), at=30)
    if r.get("action") != "reentered":
        return _record("sl-attest-ok", "BREAK", "bad result %r" % (r,))
    if not s.is_reentered("child-a"):
        return _record("sl-attest-ok", "BREAK", "re-entry not recorded")
    _record("sl-attest-ok", "HELD",
            "issue -> digest -> votes: new lease (post-crash, new token) "
            "re-enters the child")


def p_attest_unknown_obligation():
    def _go(sup, lease, ed):
        s, seeds, _ = _sup1(sup, ed)
        auth = _seed("authority")
        mgr = lease.LeaseManager()
        old = mgr.acquire("scope-a", 3600, "child-a",
                          authority_seed=auth, issued_at=0)
        d = _crash_gated(sup, ed, s, seeds, at=10,
                         old_token=old["fencing_token"])
        obl = dict(d["lease_obligations"]["child-a"])
        # Re-sign under a DIFFERENT supervisor seed: forged obligation.
        forged_seed = _seed("forged-sup")
        body = {k: v for k, v in obl.items() if k != "signature"}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode()
        obl["signature"] = ed.sign(forged_seed, raw).hex()
        mgr.release("scope-a", old["fencing_token"], "child-a")
        new = mgr.acquire("scope-a", 3600, "child-a",
                          authority_seed=auth, issued_at=20)
        s.attest_reacquisition("child-a", obl, new, _pub(ed, auth), at=30)
    _expect("sl-attest-forged", _go, "supervision-invalid",
            "forged obligation signature refuses coded")


def p_attest_replay():
    def _go(sup, lease, ed):
        s, seeds, _ = _sup1(sup, ed)
        auth = _seed("authority")
        mgr = lease.LeaseManager()
        old = mgr.acquire("scope-a", 3600, "child-a",
                          authority_seed=auth, issued_at=0)
        d = _crash_gated(sup, ed, s, seeds, at=10,
                         old_token=old["fencing_token"])
        obl = d["lease_obligations"]["child-a"]
        mgr.release("scope-a", old["fencing_token"], "child-a")
        new = mgr.acquire("scope-a", 3600, "child-a",
                          authority_seed=auth, issued_at=20)
        s.attest_reacquisition("child-a", obl, new, _pub(ed, auth), at=30)
        # Same obligation a second time: replay.
        s.attest_reacquisition("child-a", obl, new, _pub(ed, auth), at=31)
    _expect("sl-attest-replay", _go, "supervision-invalid",
            "obligation replay refuses coded")


def p_attest_same_token():
    def _go(sup, lease, ed):
        s, seeds, _ = _sup1(sup, ed)
        auth = _seed("authority")
        mgr = lease.LeaseManager()
        old = mgr.acquire("scope-a", 3600, "child-a",
                          authority_seed=auth, issued_at=0)
        d = _crash_gated(sup, ed, s, seeds, at=10,
                         old_token=old["fencing_token"])
        obl = d["lease_obligations"]["child-a"]
        mgr.release("scope-a", old["fencing_token"], "child-a")
        new = mgr.acquire("scope-a", 3600, "child-a",
                          authority_seed=auth, issued_at=20)
        # Rewrite the new lease to reuse the OLD fencing token and
        # re-sign under the authority seed (deployment holds it in
        # this probe; the point is the token-rotation check fires).
        evil = dict(new)
        evil["fencing_token"] = old["fencing_token"]
        body = {k: evil[k] for k in ("scope", "holder_id", "issued_at",
                                    "not_after", "fencing_token",
                                    "authority_pubkey")}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode()
        evil["signature"] = ed.sign(auth, raw).hex()
        s.attest_reacquisition("child-a", obl, evil, _pub(ed, auth), at=30)
    _expect("sl-attest-same-token", _go, "supervision-invalid",
            "new lease reusing the crashed fencing token refuses")


def p_attest_lease_before_crash():
    def _go(sup, lease, ed):
        s, seeds, _ = _sup1(sup, ed)
        auth = _seed("authority")
        mgr = lease.LeaseManager()
        old = mgr.acquire("scope-a", 3600, "child-a",
                          authority_seed=auth, issued_at=0)
        d = _crash_gated(sup, ed, s, seeds, at=10,
                         old_token=old["fencing_token"])
        obl = d["lease_obligations"]["child-a"]
        # Present the OLD lease itself as the "new" lease: it was not
        # issued after the crash.
        s.attest_reacquisition("child-a", obl, old, _pub(ed, auth), at=30)
    _expect("sl-attest-stale-lease", _go, "supervision-invalid",
            "lease issued before the crash instant refuses")


def p_attest_wrong_holder():
    def _go(sup, lease, ed):
        s, seeds, _ = _sup1(sup, ed)
        auth = _seed("authority")
        mgr = lease.LeaseManager()
        old = mgr.acquire("scope-a", 3600, "child-a",
                          authority_seed=auth, issued_at=0)
        d = _crash_gated(sup, ed, s, seeds, at=10,
                         old_token=old["fencing_token"])
        obl = d["lease_obligations"]["child-a"]
        mgr.release("scope-a", old["fencing_token"], "child-a")
        other = mgr.acquire("scope-a", 3600, "child-b",
                            authority_seed=auth, issued_at=20)
        s.attest_reacquisition("child-a", obl, other, _pub(ed, auth), at=30)
    _expect("sl-attest-wrong-holder", _go, "supervision-invalid",
            "lease held by another child refuses")


def p_attest_plain_child():
    def _go(sup, lease, ed):
        s, seeds, _ = _sup1(sup, ed, gated=False)
        auth = _seed("authority")
        mgr = lease.LeaseManager()
        new = mgr.acquire("scope-a", 3600, "child-a",
                          authority_seed=auth, issued_at=20)
        s.attest_reacquisition("child-a", {"obligation_id": "x"},
                               new, _pub(ed, auth), at=30)
    _expect("sl-attest-plain-child", _go, "supervision-invalid",
            "attestation for a non-gated child refuses coded")


def p_attest_no_old_token():
    def _go(sup, lease, ed):
        s, seeds, _ = _sup1(sup, ed)
        auth = _seed("authority")
        mgr = lease.LeaseManager()
        # Crash WITHOUT telling the supervisor the old token.
        d = _crash_gated(sup, ed, s, seeds, at=10, old_token=None)
        obl = d["lease_obligations"]["child-a"]
        new = mgr.acquire("scope-a", 3600, "child-a",
                          authority_seed=auth, issued_at=20)
        # Attestation cannot prove token rotation: fail-closed.
        s.attest_reacquisition("child-a", obl, new, _pub(ed, auth), at=30)
    _expect("sl-attest-no-old-token", _go, "supervision-invalid",
            "attestation without a pinned old token refuses (fail-closed)")


# -- dead-token guard ----------------------------------------------------

def p_guard_write_dead():
    def _go(sup, lease, ed):
        s, seeds, _ = _sup1(sup, ed)
        auth = _seed("authority")
        mgr = lease.LeaseManager()
        old = mgr.acquire("scope-a", 3600, "child-a",
                          authority_seed=auth, issued_at=0)
        _crash_gated(sup, ed, s, seeds, at=10,
                     old_token=old["fencing_token"])
        # Zombie write under the dead-on-restart token.
        s.guard_write("child-a", old["fencing_token"], at=11)
    _expect("sl-guard-dead", _go, "coord-lease-fencing",
            "write under the dead-on-restart token refuses coded")


def p_guard_write_live_ok():
    sup, lease, ed = _need("sl-guard-live")
    if sup is None:
        return
    s, seeds, _ = _sup1(sup, ed)
    auth = _seed("authority")
    mgr = lease.LeaseManager()
    old = mgr.acquire("scope-a", 3600, "child-a",
                      authority_seed=auth, issued_at=0)
    _crash_gated(sup, ed, s, seeds, at=10, old_token=old["fencing_token"])
    try:
        ok = s.guard_write("child-a", 999, at=11)
    except sup.SupervisionError as e:
        return _record("sl-guard-live", "BREAK",
                       "live token wrongly refused: %r" % (e.code,))
    if ok is not True:
        return _record("sl-guard-live", "BREAK", "guard did not return True")
    # Unknown child: nothing dead on record, no refusal.
    if s.guard_write("child-zz", 1, at=11) is not True:
        return _record("sl-guard-live", "BREAK", "unknown child guard failed")
    _record("sl-guard-live", "HELD",
            "live tokens pass the belt-and-suspenders guard")


# -- expiry / escalation -------------------------------------------------

def p_obligation_expiry_escalates():
    sup, lease, ed = _need("sl-obligation-expiry")
    if sup is None:
        return
    s, seeds, _ = _sup1(sup, ed)
    d = _crash_gated(sup, ed, s, seeds, at=10, old_token=7, ttl=60)
    obl = d["lease_obligations"]["child-a"]
    if obl.get("expires_at") != 70:
        return _record("sl-obligation-expiry", "BREAK",
                       "obligation not time-boxed: %r" % (obl,))
    n0 = len(s.escalations)
    auth = _seed("authority")
    mgr = lease.LeaseManager()
    new = mgr.acquire("scope-a", 3600, "child-a",
                      authority_seed=auth, issued_at=80)
    try:
        s.attest_reacquisition("child-a", obl, new, _pub(ed, auth), at=100)
    except sup.SupervisionError as e:
        if e.code != "supervision-lease-obligation-expired":
            return _record("sl-obligation-expiry", "BREAK",
                           "wrong code %r" % (e.code,))
    else:
        return _record("sl-obligation-expiry", "BREAK",
                       "expired obligation did not refuse")
    if len(s.escalations) != n0 + 1:
        return _record("sl-obligation-expiry", "BREAK",
                       "expiry did not escalate")
    rec = s.escalations[-1]
    if rec["code"] != "supervision-lease-obligation-expired":
        return _record("sl-obligation-expiry", "BREAK",
                       "escalation code wrong: %r" % (rec,))
    if not s.verify_escalation(rec):
        return _record("sl-obligation-expiry", "BREAK",
                       "escalation signature bad")
    _record("sl-obligation-expiry", "HELD",
            "expired obligation refuses coded AND escalates signed")


def p_sweep_obligations():
    sup, lease, ed = _need("sl-sweep")
    if sup is None:
        return
    s, seeds, _ = _sup1(sup, ed)
    _crash_gated(sup, ed, s, seeds, at=10, old_token=7, ttl=60)
    n0 = len(s.escalations)
    swept = s.sweep_obligations(at=100)
    if swept != 1 or len(s.escalations) != n0 + 1:
        return _record("sl-sweep", "BREAK",
                       "sweep did not escalate exactly once: %r" % (swept,))
    # Second sweep: no double escalation (state is terminal).
    swept2 = s.sweep_obligations(at=200)
    if swept2 != 0 or len(s.escalations) != n0 + 1:
        return _record("sl-sweep", "BREAK",
                       "sweep double-escalated: %r" % (swept2,))
    _record("sl-sweep", "HELD",
            "deployment sweep escalates expired obligations exactly once")


def p_obligation_ttl_bounds():
    def _go(sup, lease, ed):
        s, seeds, _ = _sup1(sup, ed)
        _crash_gated(sup, ed, s, seeds, at=10, old_token=7, ttl=0)
    _expect("sl-obligation-ttl-bounds", _go, "supervision-invalid",
            "unbounded/zero obligation TTL refuses coded")


# -- ed25519 contract ----------------------------------------------------

def p_ed25519_contract():
    sup, lease, ed = _need("sl-ed25519-contract")
    if sup is None:
        return
    import inspect
    src = inspect.getsource(sup)
    if "ed25519.verify(" not in src:
        return _record("sl-ed25519-contract", "BREAK",
                       "no ed25519.verify call sites found")
    # Every verify call site in this module must compare `is True`
    # (wave-243 lesson). Count sites, count `is True` guards.
    sites = src.count("ed25519.verify(")
    guards = len(re.findall(r"ed25519\.verify\([^)]*\)\s*\n?\s*\)?\s*is True",
                            src))
    # Fallback: check each call site's enclosing line region.
    if guards < sites:
        lines = src.splitlines()
        bad = []
        for i, ln in enumerate(lines):
            if "ed25519.verify(" in ln:
                window = "\n".join(lines[i:i + 3])
                if "is True" not in window:
                    bad.append(i + 1)
        if bad:
            return _record("sl-ed25519-contract", "BREAK",
                           "verify() not checked `is True` near lines %r"
                           % (bad,))
    _record("sl-ed25519-contract", "HELD",
            "every ed25519.verify return checked `is True`")


# -- depth-1 green checks --------------------------------------------------

def _green_check(path, name, tolerate=()):
    if SKIP_GREEN:
        return _record("green-%s" % name, "HELD",
                       "skipped (GOV_SKIP_GREEN=1, depth-1)")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    try:
        out = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=600, env=env, cwd=REPO).stdout
    except Exception as e:  # noqa: BLE001
        return _record("green-%s" % name, "ERROR",
                       "green check crashed: %r" % (e,))
    bad = [ln for ln in out.splitlines()
           if ln.strip().startswith("[BREAK]")
           and not any(t in ln for t in tolerate)]
    if bad:
        _record("green-%s" % name, "BREAK",
                "unexpected breaks: %s" % "; ".join(bad[:5]))
    else:
        _record("green-%s" % name, "HELD", "green check held")


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    for pid, fn in [
        ("sl-spec-declare", p_spec_requires_lease),
        ("sl-spec-badtype", p_spec_requires_lease_bad),
        ("sl-obligation-issued", p_crash_issues_obligation),
        ("sl-no-obligation-plain", p_crash_no_obligation_plain),
        ("sl-attest-ok", p_attest_happy_path),
        ("sl-attest-forged", p_attest_unknown_obligation),
        ("sl-attest-replay", p_attest_replay),
        ("sl-attest-same-token", p_attest_same_token),
        ("sl-attest-stale-lease", p_attest_lease_before_crash),
        ("sl-attest-wrong-holder", p_attest_wrong_holder),
        ("sl-attest-plain-child", p_attest_plain_child),
        ("sl-attest-no-old-token", p_attest_no_old_token),
        ("sl-guard-dead", p_guard_write_dead),
        ("sl-guard-live", p_guard_write_live_ok),
        ("sl-obligation-expiry", p_obligation_expiry_escalates),
        ("sl-sweep", p_sweep_obligations),
        ("sl-obligation-ttl-bounds", p_obligation_ttl_bounds),
        ("sl-ed25519-contract", p_ed25519_contract),
    ]:
        _safe(pid, fn)
    _green_check(os.path.join(REPO, "evals", "w297_supervision_probes.py"),
                 "w297-supervision", tolerate=("pin-taxonomy",))
    _green_check(os.path.join(REPO, "evals", "w294_coord_lease_probes.py"),
                 "w294-coord-lease", tolerate=("pin-taxonomy",))
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w298_supervision_lease: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, n_break, n_held, n_err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
