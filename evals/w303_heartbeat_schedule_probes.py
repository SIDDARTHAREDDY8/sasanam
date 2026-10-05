"""Wave-304 lane D battery: default heartbeat scheduling for authority leases.

Base: wave-303 merge c9138cc53888
(verified via git rev-parse HEAD + ls-remote before work).

Residual from the wave-303 merge audit: lane 6
(gov/authority_lifecycle.py) takes an explicit
``heartbeat_interval_seconds`` (<= ttl enforced) but does not
implement the prospectus refined rule
``reverify_at = expires_at - max(fraction * lifetime,
remediation_floor)``. This lane implements the fraction-of-lifetime
schedule as the DEFAULT (explicit interval stays a hard override),
additive to gov/authority_lifecycle.py only. No new decision codes;
pin stays 1827.

Design rule (from the wave-302 part-1 prospectus):
"A heartbeat is a re-proof, not a renewal -- silence revokes, and a
missed proof never extends the lease."

Default schedule:
  interval = max(ceil(heartbeat_fraction * ttl_seconds),
                 remediation_floor_seconds)
clamped to ttl_seconds (the default schedule can never violate the
interval <= ttl contract). heartbeat_fraction default 0.5 (the SPIRE
1/2-of-lifetime convention); remediation_floor_seconds default 60.

Red-first: on the pre-fix tree the default-schedule probes fail
(issue_lease() requires heartbeat_interval_seconds -- TypeError; the
p_absent_before_fix red-first marker records BREAK, the rest record
ERROR via the crash-catching probe wrapper); on the fixed tree they
must HELD with hand-computed literal expectations. All expectations
below are literals worked by hand, never recomputed through the
module.

Run:
  mkdir -p /var/tmp/g304-hb && TMPDIR=/var/tmp/g304-hb \
    ~/workspace/.gov-venv/bin/python evals/w303_heartbeat_schedule_probes.py
Also standalone (clean env):
  mkdir -p /var/tmp/g304-hb2 && env -u GOV_DEPLOYMENT_MODE \
    TMPDIR=/var/tmp/g304-hb2 \
    ~/workspace/.gov-venv/bin/python evals/w303_heartbeat_schedule_probes.py
"""

import hashlib
import os
import re
import subprocess
import sys
import tempfile
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import green_check  # noqa: E402  (wave-305 shared fail-closed green checks)
import probe_lines  # noqa: E402  (canonical probe-line form)

TAXONOMY_PIN = 2083 # Wave-302 merge pin 1820; wave-303 lane 6: pin 1820 -> 1823 (+3 authority-lifecycle-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-304 lane D: pin unchanged (no new codes); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*) # Wave-334 lane 6: pin 2077 -> 2083 (+6 incident-gpai9-*).



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
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "2083/2083/0 sorted")




def p_footer_state():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    m_open = re.findall(r"Open findings: ([A-Za-z0-9, ]*)", text)
    m_next = re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
    # Wave-316 merge footer: F398/F399/F400 CLOSED; F401/F402/F403 OPEN; next F404.
    ok = (m_open and m_open[-1].strip()
          == "F411"
          and m_next and m_next[-1] == "F412")
    _record("footer-state", "HELD" if ok else "BREAK",
            "want open F406 / next free F407")


def _al():
    """Import the module under test; None on pristine base (BREAK)."""
    try:
        from gov import authority_lifecycle as mod
        return mod
    except ImportError:
        return None


def _need(pid):
    mod = _al()
    if mod is None:
        _record(pid, "BREAK",
                "gov.authority_lifecycle absent (pristine base)")
        return None
    return mod


def _seed(tag):
    return hashlib.sha256(("w304hb-" + tag).encode()).digest()


def _hex64(s):
    return hashlib.sha256(s.encode()).hexdigest()


AT = 1_700_000_000


def _mgr(al):
    return al.AuthorityLeaseManager()


def _issue_default(al, mgr, at=AT, ttl=3600, tag="d", **kw):
    """Issue a lease WITHOUT heartbeat_interval_seconds: granter-a ->
    agent-x. Extra kwargs pass through (heartbeat_fraction=,
    remediation_floor_seconds=)."""
    from gov import ed25519
    sg = _seed("granter-" + tag)
    sx = _seed("subject-" + tag)
    pub_x = ed25519.publickey(sx).hex()
    return mgr.issue_lease(
        granter_id="granter-a", granter_seed=sg,
        subject_id="agent-x", subject_pubkey_hex=pub_x,
        scope_digest=_hex64("scope:tool.invoke"),
        issued_at=at, ttl_seconds=ttl, **kw)


def _issue_explicit(al, mgr, interval, at=AT, ttl=3600, tag="e"):
    from gov import ed25519
    sg = _seed("granter-" + tag)
    sx = _seed("subject-" + tag)
    pub_x = ed25519.publickey(sx).hex()
    return mgr.issue_lease(
        granter_id="granter-a", granter_seed=sg,
        subject_id="agent-x", subject_pubkey_hex=pub_x,
        scope_digest=_hex64("scope:tool.invoke"),
        issued_at=at, ttl_seconds=ttl,
        heartbeat_interval_seconds=interval)


def p_absent_before_fix():
    """Red-first marker: on the pre-fix tree issue_lease() requires
    heartbeat_interval_seconds (TypeError); on the fixed tree the
    default schedule issues."""
    al = _need("absent")
    if al is None:
        return
    mgr = _mgr(al)
    try:
        lease = _issue_default(al, mgr)
    except TypeError:
        return _record("absent", "BREAK",
                       "no default schedule: heartbeat_interval_seconds "
                       "still a required argument (pre-fix)")
    assert lease["heartbeat_interval_seconds"] == 1800, lease
    _record("absent", "HELD",
            "default schedule present: ttl=3600 -> interval=1800")


def p_default_fraction_of_lifetime():
    """ttl=3600, defaults: interval = max(ceil(0.5*3600), 60) = 1800."""
    al = _need("default-fraction")
    if al is None:
        return
    mgr = _mgr(al)
    lease = _issue_default(al, mgr, ttl=3600)
    if lease["heartbeat_interval_seconds"] != 1800:
        return _record("default-fraction", "BREAK",
                       "want 1800, got %r"
                       % (lease["heartbeat_interval_seconds"],))
    _record("default-fraction", "HELD", "ttl=3600 -> interval=1800")


def p_floor_wins_for_short_ttl():
    """ttl=100, defaults: interval = max(ceil(0.5*100)=50, 60) = 60."""
    al = _need("floor-wins")
    if al is None:
        return
    mgr = _mgr(al)
    lease = _issue_default(al, mgr, ttl=100)
    if lease["heartbeat_interval_seconds"] != 60:
        return _record("floor-wins", "BREAK",
                       "want 60, got %r"
                       % (lease["heartbeat_interval_seconds"],))
    _record("floor-wins", "HELD", "ttl=100 -> interval=60 (floor)")


def p_floor_clamped_to_ttl():
    """ttl=30, defaults: max(ceil(0.5*30)=15, 60) = 60, but the floor
    must not swallow the ttl -> clamped to 30."""
    al = _need("floor-clamp")
    if al is None:
        return
    mgr = _mgr(al)
    lease = _issue_default(al, mgr, ttl=30)
    if lease["heartbeat_interval_seconds"] != 30:
        return _record("floor-clamp", "BREAK",
                       "want 30 (clamped), got %r"
                       % (lease["heartbeat_interval_seconds"],))
    _record("floor-clamp", "HELD",
            "ttl=30 -> interval=30 (floor clamped to ttl)")


def p_ceil_rounding():
    """ttl=101, floor=10: interval = max(ceil(50.5)=51, 10) = 51 --
    distinguishes ceil from floor/truncation."""
    al = _need("ceil-rounding")
    if al is None:
        return
    mgr = _mgr(al)
    lease = _issue_default(al, mgr, ttl=101, remediation_floor_seconds=10)
    if lease["heartbeat_interval_seconds"] != 51:
        return _record("ceil-rounding", "BREAK",
                       "want 51, got %r"
                       % (lease["heartbeat_interval_seconds"],))
    _record("ceil-rounding", "HELD", "ttl=101 floor=10 -> 51 (ceil)")


def p_custom_fraction_and_floor():
    """ttl=1000, fraction=0.8, floor=120: interval =
    max(ceil(0.8*1000)=800, 120) = 800."""
    al = _need("custom-frac-floor")
    if al is None:
        return
    mgr = _mgr(al)
    lease = _issue_default(al, mgr, ttl=1000, heartbeat_fraction=0.8,
                           remediation_floor_seconds=120)
    if lease["heartbeat_interval_seconds"] != 800:
        return _record("custom-frac-floor", "BREAK",
                       "want 800, got %r"
                       % (lease["heartbeat_interval_seconds"],))
    _record("custom-frac-floor", "HELD", "ttl=1000 f=0.8 floor=120 -> 800")


def p_explicit_interval_still_wins():
    """An explicit interval is a hard override: ttl=3600, interval=600
    -> 600 (pre-fix behavior preserved)."""
    al = _need("explicit-wins")
    if al is None:
        return
    mgr = _mgr(al)
    lease = _issue_explicit(al, mgr, interval=600, ttl=3600)
    if lease["heartbeat_interval_seconds"] != 600:
        return _record("explicit-wins", "BREAK",
                       "want 600, got %r"
                       % (lease["heartbeat_interval_seconds"],))
    _record("explicit-wins", "HELD", "explicit interval=600 honored")


def p_explicit_interval_over_ttl_still_fails_fast():
    """Pre-fix contract preserved: explicit interval > ttl is
    ValueError (fail fast)."""
    al = _need("explicit-over-ttl")
    if al is None:
        return
    mgr = _mgr(al)
    try:
        _issue_explicit(al, mgr, interval=200, ttl=100)
    except ValueError:
        return _record("explicit-over-ttl", "HELD",
                       "explicit interval > ttl still ValueError")
    _record("explicit-over-ttl", "BREAK",
            "explicit interval > ttl no longer fails fast")


def p_fraction_bounds():
    """heartbeat_fraction must be a number in (0, 1]: 0, 1.5, -0.25,
    and True all ValueError; 1 is valid (interval = ttl)."""
    al = _need("fraction-bounds")
    if al is None:
        return
    mgr = _mgr(al)
    bad = 0
    for frac in (0, 1.5, -0.25, True):
        try:
            _issue_default(al, mgr, ttl=3600, heartbeat_fraction=frac)
        except ValueError:
            bad += 1
    if bad != 4:
        return _record("fraction-bounds", "BREAK",
                       "only %d/4 invalid fractions refused" % bad)
    lease = _issue_default(al, mgr, ttl=3600, heartbeat_fraction=1)
    if lease["heartbeat_interval_seconds"] != 3600:
        return _record("fraction-bounds", "BREAK",
                       "fraction=1 should give interval=ttl=3600, got %r"
                       % (lease["heartbeat_interval_seconds"],))
    _record("fraction-bounds", "HELD",
            "invalid fractions ValueError; fraction=1 -> interval=ttl")


def p_floor_bounds():
    """remediation_floor_seconds must be a positive int: 0, -5, and
    "60" all ValueError."""
    al = _need("floor-bounds")
    if al is None:
        return
    mgr = _mgr(al)
    bad = 0
    for floor in (0, -5, "60"):
        try:
            _issue_default(al, mgr, ttl=3600,
                           remediation_floor_seconds=floor)
        except ValueError:
            bad += 1
    if bad != 3:
        return _record("floor-bounds", "BREAK",
                       "only %d/3 invalid floors refused" % bad)
    _record("floor-bounds", "HELD", "invalid floors ValueError")


def _proof(al, lease, counter, at, seed, signer_id="agent-x"):
    return al.make_proof(
        lease_id=lease["lease_id"], subject_id=lease["subject_id"],
        scope_digest=lease["scope_digest"], counter=counter,
        proof_issued_at=at, signer_id=signer_id, signer_seed=seed)


def p_derived_schedule_enforced_in_stream():
    """The derived interval governs the live stream: ttl=3600 ->
    interval 1800. check() at AT+1799 ACTIVE with next_heartbeat_due
    == AT+1800; a heartbeat at AT+1799 is accepted; check() at AT+3600
    (1801s of silence > 1800, still inside ttl) refuses
    authority-lifecycle-heartbeat-lapsed and suspends."""
    al = _need("derived-enforced")
    if al is None:
        return
    mgr = _mgr(al)
    lease = _issue_default(al, mgr, ttl=3600)
    lid = lease["lease_id"]
    v = mgr.check(lid, at=AT + 1799)
    if v["state"] != "ACTIVE" or v["next_heartbeat_due"] != AT + 1800:
        return _record("derived-enforced", "BREAK",
                       "unexpected verdict before the window: %r" % (v,))
    sx = _seed("subject-d")
    acc = mgr.heartbeat(lid, _proof(al, lease, 1, AT + 1799, sx),
                        at=AT + 1799)
    if acc["state"] != "ACTIVE" or acc["counter"] != 1:
        return _record("derived-enforced", "BREAK",
                       "heartbeat inside the derived window refused: %r"
                       % (acc,))
    try:
        mgr.check(lid, at=AT + 3600)
    except Exception as e:
        code = getattr(e, "code", None)
        if code != "authority-lifecycle-heartbeat-lapsed":
            return _record("derived-enforced", "BREAK",
                           "wrong refusal code after lapse: %r" % (code,))
        state = mgr.state_of(lid, at=AT + 3600)
        if state != "SUSPENDED":
            return _record("derived-enforced", "BREAK",
                           "lapse did not suspend (fail-closed): %r"
                           % (state,))
        return _record("derived-enforced", "HELD",
                       "derived interval governs the stream; silence "
                       "suspends fail-closed")
    _record("derived-enforced", "BREAK",
            "1801s of silence inside the derived interval authorized")


def p_schedule_journaled_as_evidence():
    """The lease-issued journal entry carries the schedule parameters
    (the auditor evidence event): derived -> fraction 0.5, floor 60,
    schedule 'derived'; explicit override -> schedule 'explicit'."""
    al = _need("schedule-journaled")
    if al is None:
        return
    mgr = _mgr(al)
    d = _issue_default(al, mgr, ttl=3600, at=AT)
    e = _issue_explicit(al, mgr, interval=600, ttl=3600, at=AT + 1)
    kinds = [x for x in mgr.journal if x["kind"] == "lease-issued"]
    fd = next(x["fields"] for x in kinds
              if x["lease_id"] == d["lease_id"])
    fe = next(x["fields"] for x in kinds
              if x["lease_id"] == e["lease_id"])
    if not (fd.get("heartbeat_fraction") == 0.5
            and fd.get("remediation_floor_seconds") == 60
            and fd.get("schedule") == "derived"
            and fd.get("heartbeat_interval_seconds") == 1800):
        return _record("schedule-journaled", "BREAK",
                       "derived schedule not journaled: %r" % (fd,))
    if not (fe.get("schedule") == "explicit"
            and fe.get("heartbeat_interval_seconds") == 600):
        return _record("schedule-journaled", "BREAK",
                       "explicit schedule not journaled: %r" % (fe,))
    _record("schedule-journaled", "HELD",
            "schedule parameters journaled on lease-issued")


def _green_check(name):
    """Depth-1 green check: the authority-lifecycle unit suite, run
    with GOV_SKIP_GREEN=1 in the child env (never nested). Wave-305:
    delegates to evals/green_check.py (fail-closed contract); the
    staging env the old form set is preserved via extra_env."""
    green_check.check_unittest(
        _record, "green-" + name, "tests.test_authority_lifecycle",
        repo=REPO, extra_env={"GOV_DEPLOYMENT_MODE": "staging"})


def main():
    probes = [
        p_taxonomy_pin,
        p_footer_state,
        p_absent_before_fix,
        p_default_fraction_of_lifetime,
        p_floor_wins_for_short_ttl,
        p_floor_clamped_to_ttl,
        p_ceil_rounding,
        p_custom_fraction_and_floor,
        p_explicit_interval_still_wins,
        p_explicit_interval_over_ttl_still_fails_fast,
        p_fraction_bounds,
        p_floor_bounds,
        p_derived_schedule_enforced_in_stream,
        p_schedule_journaled_as_evidence,
    ]
    for fn in probes:
        _safe(fn.__name__, fn)
    _green_check("authority-lifecycle-units")
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    held = sum(1 for _, v, _ in _results if v == "HELD")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w304 heartbeat-schedule probes: %d BREAK / %d HELD / %d ERROR"
          % (breaks, held, errors))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, breaks, held, errors)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
