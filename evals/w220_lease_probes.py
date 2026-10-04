#!/usr/bin/env python3
"""Wave-220 lane B: ARAP mission-bound permit leases — the
mission-bound-authorization ADAPT.

Seam under test: gov/permit_leases.py — one-use permit leases that bind
an ARAP approval to the exact request ``parameter_digest``:

* permit record {permit_id, parameter_digest, issued_at, expires_at, used}
  (the parameter_digest reuses the wave-219 ARAP ``context_binding``
  HMAC — no second digest scheme for the same context),
* redeem() consumes the lease: second redeem -> ``permit-reused``,
  digest mismatch -> ``permit-digest-mismatch``, expired ->
  ``permit-expired``; unknown permit id -> ``permit-unknown``,
* no-downgrade rule: PermitLease.check_scope(request_scope,
  grant_scope) refuses a request broader than the grant with
  ``permit-downgrade-refused`` (conservative: unknown shapes refuse;
  scope narrowing is accepted),
* check order on redeem: used -> expired -> digest -> scope, so an
  expired or consumed permit leaks no digest-equality oracle,
* additive, tighten-only wiring into gov/arap.py transition() via
  ``lease_registry=None`` (absent registry = legacy byte-identical).

Attack shapes: double-redeem, digest substitution, expiry bypass,
replay-after-expiry oracle, probe-a-used-permit oracle, unknown permit
id, scope widening (action/resource/subject), scope-shape smuggling,
unbound-parameter permit issuance (fail closed), legacy transition
shape drift.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-219 HEAD
4acc49b08064abb9874be6f6465e81b2decaf523.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP — except
the legacy-transition pin, which is verifiable on base.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g220b
  TMPDIR=/var/tmp/g220b ~/workspace/.gov-venv/bin/python evals/w220_lease_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g220b-u \
      ~/workspace/.gov-venv/bin/python evals/w220_lease_probes.py
"""

import os
import secrets
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w220-lease-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g220b-%d" % os.getpid()
os.environ.setdefault("TMPDIR", _TMPDIR_FALLBACK)
try:
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
except OSError:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import permit_leases as pl  # noqa: E402
    from gov import policy_compile as pc  # noqa: E402
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine run has no module
    pl = None
    pc = None
    _IMPORT_OK = False
    _IMPORT_ERR = exc

from gov import arap  # noqa: E402 - present on base (legacy pin)

_RESULTS = []


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md): this battery
# records HELD/GAP/BREAK/ERROR on probes and PASS/SKIP/FAIL on its
# depth-1 green checks; the canonical emission vocabulary is
# BREAK/HELD/ERROR/SKIP, mapped red-first (PASS->HELD, GAP/FAIL->BREAK).
# Probe logic, verdict computation and count code are untouched -- only
# the print loop below maps.
_VERDICT_MAP = {
    "PASS": "HELD", "HELD": "HELD", "GREEN": "HELD",
    "FAIL": "BREAK", "BROKEN": "BREAK", "GAP": "BREAK",
    "RED": "BREAK", "BREAK": "BREAK",
    "ERROR": "ERROR", "SKIP": "SKIP", "SKIPPED": "SKIP",
}
_PROBE_FNS = {}

NOW = 1785000000
_KEY = b"w220-deployment-key-0123456789abcdef"
_CTX = {"amount": 100, "currency": "USD", "counterparty": "alice"}


def _probe(name):
    def deco(fn):
        _PROBE_FNS[name] = fn
        return fn
    return deco


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))


def _held(name, detail=""):
    _record(name, "HELD", detail)


def _break(name, detail=""):
    _record(name, "BREAK", detail)


def _gap(name):
    _record(name, "GAP", "module absent on pristine tree")


def _code_of(exc):
    return getattr(exc, "code", type(exc).__name__)


# ----------------------------------------------------------------------
# Harness helpers (only meaningful when the module is present).
# ----------------------------------------------------------------------

def _audit_sink():
    events = []

    def audit(entry):
        events.append(entry)
    return events, audit


def _req(subject="alice", resource="doc/1", action="read", with_key=True):
    kwargs = {"context": dict(_CTX)} if with_key else {}
    key = _KEY if with_key else None
    return arap.new_request("req-1", subject, resource, action,
                           key=key, **kwargs)


def _expect_refusal(name, code, fn):
    """The attack shape must be refused with exactly this named code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - code is the contract
        got = _code_of(exc)
        if got == code:
            _held(name, "refused with %s" % got)
        else:
            _break(name, "refused with %s, expected %s" % (got, code))
        return
    _break(name, "NOT refused (expected %s)" % code)


# ----------------------------------------------------------------------
# Probes.
# ----------------------------------------------------------------------

@_probe("issue-redeem-exact")
def _p_issue_redeem():
    if not _IMPORT_OK:
        return _gap("issue-redeem-exact")
    events, audit = _audit_sink()
    reg = pl.PermitRegistry(audit=audit, now=lambda: NOW)
    lease = reg.issue_for_arap(_req(), permit_id="p1", ttl_s=3600)
    grant = reg.redeem("p1", lease.parameter_digest,
                       request_scope={"subject": {"alice"},
                                      "resource": {"doc/1"},
                                      "action": {"read"}})
    if grant["permit_id"] == "p1" and lease.used:
        _held("issue-redeem-exact", "grant returned, lease consumed")
    else:
        _break("issue-redeem-exact", "grant malformed or lease not consumed")
    if any(e.get("event") == "permit_redeemed" for e in events):
        _held("issue-redeem-exact", "audit emitted")
    else:
        _break("issue-redeem-exact", "no permit_redeemed audit entry")


@_probe("double-redeem")
def _p_double():
    if not _IMPORT_OK:
        return _gap("double-redeem")
    reg = pl.PermitRegistry(now=lambda: NOW)
    lease = reg.issue_for_arap(_req(), permit_id="p2", ttl_s=3600)
    reg.redeem("p2", lease.parameter_digest)
    _expect_refusal("double-redeem", "permit-reused",
                    lambda: reg.redeem("p2", lease.parameter_digest))


@_probe("digest-mismatch")
def _p_mismatch():
    if not _IMPORT_OK:
        return _gap("digest-mismatch")
    events, audit = _audit_sink()
    reg = pl.PermitRegistry(audit=audit, now=lambda: NOW)
    reg.issue_for_arap(_req(), permit_id="p3", ttl_s=3600)
    # A DIFFERENT context under the same key yields a different binding:
    # the same context+key would (correctly) produce the same digest.
    tampered = pc.compile_arap_context(
        {"amount": 999, "currency": "USD", "counterparty": "alice"},
        key=_KEY)
    _expect_refusal("digest-mismatch", "permit-digest-mismatch",
                    lambda: reg.redeem("p3", tampered.binding))
    if any(e.get("code") == "permit-digest-mismatch" for e in events):
        _held("digest-mismatch", "refusal audited with code")
    else:
        _break("digest-mismatch", "refusal not audited with code")


@_probe("expired")
def _p_expired():
    if not _IMPORT_OK:
        return _gap("expired")
    reg = pl.PermitRegistry(now=lambda: NOW)
    lease = reg.issue_for_arap(_req(), permit_id="p4", ttl_s=60)
    reg2 = pl.PermitRegistry(now=lambda: NOW + 61)
    # Move the same lease into a later-time registry view.
    reg2._leases["p4"] = lease
    _expect_refusal("expired", "permit-expired",
                    lambda: reg2.redeem("p4", lease.parameter_digest))


@_probe("replay-after-expiry")
def _p_replay_expiry():
    if not _IMPORT_OK:
        return _gap("replay-after-expiry")
    # Correct digest against an expired permit must say permit-expired,
    # never confirm or deny the digest (no oracle).
    reg = pl.PermitRegistry(now=lambda: NOW)
    lease = reg.issue_for_arap(_req(), permit_id="p5", ttl_s=60)
    late = pl.PermitRegistry(now=lambda: NOW + 3600)
    late._leases["p5"] = lease
    _expect_refusal("replay-after-expiry", "permit-expired",
                    lambda: late.redeem("p5", lease.parameter_digest))


@_probe("probe-used-permit")
def _p_probe_used():
    if not _IMPORT_OK:
        return _gap("probe-used-permit")
    # Wrong digest against a CONSUMED permit must say permit-reused,
    # never confirm or deny the digest (no oracle).
    reg = pl.PermitRegistry(now=lambda: NOW)
    lease = reg.issue_for_arap(_req(), permit_id="p6", ttl_s=3600)
    reg.redeem("p6", lease.parameter_digest)
    _expect_refusal("probe-used-permit", "permit-reused",
                    lambda: reg.redeem("p6", "sha256:" + "0" * 64))


@_probe("unknown-permit")
def _p_unknown():
    if not _IMPORT_OK:
        return _gap("unknown-permit")
    reg = pl.PermitRegistry(now=lambda: NOW)
    _expect_refusal("unknown-permit", "permit-unknown",
                    lambda: reg.redeem("nope", "sha256:" + "0" * 64))


@_probe("scope-widening")
def _p_widen():
    if not _IMPORT_OK:
        return _gap("scope-widening")
    reg = pl.PermitRegistry(now=lambda: NOW)
    lease = reg.issue_for_arap(_req(), permit_id="p8", ttl_s=3600)
    _expect_refusal(
        "scope-widening", "permit-downgrade-refused",
        lambda: reg.redeem("p8", lease.parameter_digest,
                           request_scope={"subject": {"alice"},
                                          "resource": {"doc/1"},
                                          "action": {"read", "write"}}))


@_probe("scope-narrowing")
def _p_narrow():
    if not _IMPORT_OK:
        return _gap("scope-narrowing")
    reg = pl.PermitRegistry(now=lambda: NOW)
    broad = _req(action="read")
    lease = reg.issue_for_arap(
        broad, permit_id="p9", ttl_s=3600,
        grant_scope={"subject": {"alice"}, "resource": {"doc/1"},
                     "action": {"read", "write"}})
    grant = reg.redeem("p9", lease.parameter_digest,
                       request_scope={"subject": {"alice"},
                                      "resource": {"doc/1"},
                                      "action": {"read"}})
    if grant["permit_id"] == "p9":
        _held("scope-narrowing", "subset scope accepted")
    else:
        _break("scope-narrowing", "subset scope wrongly refused")


@_probe("scope-unknown-shape")
def _p_shape():
    if not _IMPORT_OK:
        return _gap("scope-unknown-shape")
    reg = pl.PermitRegistry(now=lambda: NOW)
    lease = reg.issue_for_arap(_req(), permit_id="p10", ttl_s=3600)
    # Extra dimension not in the grant: conservative refuse.
    _expect_refusal(
        "scope-unknown-shape", "permit-downgrade-refused",
        lambda: reg.redeem("p10", lease.parameter_digest,
                           request_scope={"subject": {"alice"},
                                          "resource": {"doc/1"},
                                          "action": {"read"},
                                          "clearance": {"top-secret"}}))
    # Non-string values: conservative refuse, never TypeError escape.
    _expect_refusal(
        "scope-unknown-shape", "permit-downgrade-refused",
        lambda: pl.PermitLease.check_scope({"action": [{"read"}]},
                                           {"action": {"read"}}))


@_probe("check-scope-direct")
def _p_check_direct():
    if not _IMPORT_OK:
        return _gap("check-scope-direct")
    g = {"subject": {"alice"}, "resource": {"doc/1"}, "action": {"read"}}
    # equal and subset accepted
    if pl.PermitLease.check_scope(dict(g), g) is not True:
        return _break("check-scope-direct", "equal scope refused")
    if pl.PermitLease.check_scope({"action": {"read"}}, g) is not True:
        return _break("check-scope-direct", "narrow scope refused")
    # widened action refused
    try:
        pl.PermitLease.check_scope({"action": {"read", "delete"}}, g)
        return _break("check-scope-direct", "widened action accepted")
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) != "permit-downgrade-refused":
            return _break("check-scope-direct",
                          "wrong code %s" % _code_of(exc))
    # subject swap refused
    try:
        pl.PermitLease.check_scope({"subject": {"mallory"}}, g)
        return _break("check-scope-direct", "subject swap accepted")
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) != "permit-downgrade-refused":
            return _break("check-scope-direct",
                          "wrong code %s" % _code_of(exc))
    _held("check-scope-direct", "equal/narrow ok, widen/swap refused")


@_probe("transition-issues-permit")
def _p_transition_permit():
    if not _IMPORT_OK:
        return _gap("transition-issues-permit")
    events, audit = _audit_sink()
    reg = pl.PermitRegistry(audit=audit, now=lambda: NOW)
    req = _req()
    arap.transition(req, "approved", by="approver-1", audit=audit,
                    lease_registry=reg, lease_ttl_s=600)
    pid = req.get("permit_id")
    if not pid:
        return _break("transition-issues-permit", "no permit issued")
    lease = reg._leases[pid]
    if lease.parameter_digest != req["context_binding"]:
        return _break("transition-issues-permit",
                      "permit not bound to request context_binding")
    grant = reg.redeem(pid, req["context_binding"])
    if grant["permit_id"] != pid:
        return _break("transition-issues-permit", "permit not redeemable")
    if not any(e.get("event") == "permit_issued" for e in events):
        return _break("transition-issues-permit", "no permit_issued audit")
    _held("transition-issues-permit", "permit bound+redeemable+audited")


@_probe("transition-skips-unbound")
def _p_transition_unbound():
    if not _IMPORT_OK:
        return _gap("transition-skips-unbound")
    events, audit = _audit_sink()
    reg = pl.PermitRegistry(audit=audit, now=lambda: NOW)
    req = _req(with_key=False)  # no integrity-bound parameters
    arap.transition(req, "approved", by="approver-1", audit=audit,
                    lease_registry=reg)
    if "permit_id" in req:
        return _break("transition-skips-unbound",
                      "permit issued for unbound parameters")
    if not any(e.get("event") == "arap_permit_skipped" for e in events):
        return _break("transition-skips-unbound", "skip not audited")
    _held("transition-skips-unbound", "no lease for unbound params, loud")


@_probe("legacy-transition-byte-identical")
def _p_legacy():
    # Verifiable on BASE: transition() with default args must produce
    # the exact pristine record shape — no permit keys, no behavior
    # change when leases are unused.
    req = _req()
    arap.transition(req, "approved", by="approver-1")
    expected = {"request_id", "subject", "resource", "action",
                "declared_context", "context_binding", "idempotency_key",
                "authorized_cancellers", "status", "history"}
    if set(req.keys()) != expected:
        _break("legacy-transition-byte-identical",
               "record keys drifted: %s" % sorted(set(req.keys())))
    elif req["status"] != "approved" or len(req["history"]) != 2:
        _break("legacy-transition-byte-identical", "lifecycle drifted")
    else:
        _held("legacy-transition-byte-identical",
              "pristine shape preserved, no permit keys")


@_probe("determinism")
def _p_determinism():
    if not _IMPORT_OK:
        return _gap("determinism")
    r1 = pl.PermitRegistry(now=lambda: NOW)
    l1 = r1.issue_for_arap(_req(), permit_id="d1", ttl_s=60)
    fp1 = (l1.parameter_digest, l1.issued_at, l1.expires_at)
    r2 = pl.PermitRegistry(now=lambda: NOW)
    l2 = r2.issue_for_arap(_req(), permit_id="d1", ttl_s=60)
    fp2 = (l2.parameter_digest, l2.issued_at, l2.expires_at)
    if fp1 == fp2:
        _held("determinism", "identical issues agree")
    else:
        _break("determinism", "nondeterministic issuance")


# ----------------------------------------------------------------------
# Runner.
# ----------------------------------------------------------------------

def _run_once():
    _RESULTS.clear()
    for name in sorted(_PROBE_FNS):
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001 - never lose a probe
            _record(name, "ERROR", "%r" % (exc,))
    return list(_RESULTS)


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green/arap-adjacent", "SKIP", "nested run")]
    return [("green/arap-adjacent", "SKIP",
             "owned by merge; lane runs adjacent suites directly")]


def main():
    first = _run_once()
    second = _run_once()
    det_ok = [v for _, v, _d in first] == [v for _, v, _d in second]
    green = _run_green_checks()
    held = sum(1 for _, v, _d in first if v == "HELD")
    gap = sum(1 for _, v, _d in first if v == "GAP")
    brk = sum(1 for _, v, _d in first if v == "BREAK")
    err = sum(1 for _, v, _d in first if v == "ERROR")
    final = [(n, _VERDICT_MAP[v], d) for n, v, d in _RESULTS]
    # Green-check pids are renamed value-only ("/" -> "_") so every
    # emitted pid stays inside [A-Za-z0-9_.-] (D7).
    final += [(n.replace("/", "_"), _VERDICT_MAP[s], d)
              for n, s, d in green]
    probe_lines.emit(final)
    brk_c = sum(1 for _, v, _ in final if v == "BREAK")
    held_c = sum(1 for _, v, _ in final if v == "HELD")
    err_c = sum(1 for _, v, _ in final if v == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        final, brk_c, held_c, err_c)
    if not _coh_ok:
        print("coherence-WARNING: %s" % ("; ".join(_coh_diags)))
    print("%d BREAK / %d HELD / %d ERROR"
          % (brk_c, held_c, err_c))
    print("w220 lease probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "(%d probes, determinism %s)"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    if not _IMPORT_OK:
        print("import failed (pristine): %r" % (_IMPORT_ERR,))
    if brk or err or not det_ok:
        return 1
    if any(s not in ("PASS", "SKIP") for _, s, _ in green):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
