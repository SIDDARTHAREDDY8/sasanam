"""Wave-241 aauth-rs fail-closed egress primitives probes (W241-3, red-first).

aauth-rs (nolabs-ai, Apache-2.0 -- file-level LICENSE read in the
wave-241 lane: full Apache License 2.0 text, Copyright 2026 nolabs,
inc) re-derived as Sasanam fail-closed primitives. We steal the
primitives, not the protocol; no upstream code is reused.

Probes:
  egress-discovery-before-policy-refused -- scheme resolution without
      a policy, or with a policy that never allowed the scheme,
      refuses aauth-scheme-not-allowed (policy-before-discovery);
      an explicitly allowed scheme resolves (positive control).
  egress-aud-mismatch-refused -- a token whose aud does not match the
      expected audience refuses aauth-aud-mismatch; a matching aud
      passes; a missing aud fails closed.
  egress-stale-created-refused -- an RFC 9421 created timestamp more
      than 60s from now refuses aauth-stale-created (past and future);
      exactly-60s freshness passes.
  egress-loopback-blocked -- egress to loopback, RFC1918, link-local,
      or non-https targets refuses aauth-egress-blocked; https to a
      public IP passes (positive control). DNS rebinding (target IP
      changing after the check) is a documented limitation of any
      pre-connection check, not a claim this module makes.
  egress-iss-mismatch-refused -- a token whose iss does not match the
      expected issuer refuses aauth-iss-mismatch (confused deputy);
      a matching iss passes.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NEW_API = False
try:
    from gov import aauth_egress as _ae
    HAVE_NEW_API = all(hasattr(_ae, n) for n in (
        "SchemePolicy", "resolve_scheme", "check_audience",
        "check_freshness", "check_egress", "verify_issuer",
        "AauthEgressError", "FRESHNESS_WINDOW_SECONDS"))
except ImportError:
    _ae = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "egress-discovery-before-policy-refused",
    "egress-aud-mismatch-refused",
    "egress-stale-created-refused",
    "egress-loopback-blocked",
    "egress-iss-mismatch-refused",
]


def _run_probe(name, fn):
    if not HAVE_NEW_API:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _expect_refusal(fn, code):
    """fn must raise AauthEgressError with .code == code; returns note."""
    try:
        fn()
    except _ae.AauthEgressError as exc:
        assert exc.code == code, "code %r, expected %r" % (exc.code, code)
        return "refused %s" % code
    raise AssertionError("no refusal; expected %s" % code)


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _probe_discovery_before_policy_refused():
    note = _expect_refusal(
        lambda: _ae.resolve_scheme("urn:example:weird-scheme", None),
        "aauth-scheme-not-allowed")
    note2 = _expect_refusal(
        lambda: _ae.resolve_scheme(
            "urn:example:weird-scheme", _ae.SchemePolicy()),
        "aauth-scheme-not-allowed")
    # Positive control: explicitly allowed scheme resolves.
    policy = _ae.SchemePolicy()
    policy.allow_scheme("urn:example:registered-scheme")
    resolved = _ae.resolve_scheme("urn:example:registered-scheme", policy)
    assert resolved == "urn:example:registered-scheme", resolved
    return "%s; %s; explicit allow resolves" % (note, note2)


def _probe_aud_mismatch_refused():
    note = _expect_refusal(
        lambda: _ae.check_audience("service-b.example",
                                  "service-a.example"),
        "aauth-aud-mismatch")
    note2 = _expect_refusal(
        lambda: _ae.check_audience(None, "service-a.example"),
        "aauth-aud-mismatch")
    # Positive control: matching audience passes.
    _ae.check_audience("service-a.example", "service-a.example")
    return "%s; missing-aud %s; match ok" % (note, note2)


def _probe_stale_created_refused():
    now = 1_000_000
    note = _expect_refusal(
        lambda: _ae.check_freshness(now - 61, now),
        "aauth-stale-created")
    note2 = _expect_refusal(
        lambda: _ae.check_freshness(now + 61, now),
        "aauth-stale-created")
    # Boundary: exactly the window still passes.
    _ae.check_freshness(now - _ae.FRESHNESS_WINDOW_SECONDS, now)
    _ae.check_freshness(now, now)
    return "%s; future-stale %s; window-boundary ok" % (note, note2)


def _probe_loopback_blocked():
    for url in ("https://127.0.0.1/hook",
                "https://127.1.2.3/hook",
                "https://10.0.0.5/hook",
                "https://172.16.4.4/hook",
                "https://192.168.1.9/hook",
                "https://169.254.169.254/latest/meta-data",
                "https://[::1]/hook",
                "https://[fe80::1]/hook",
                "https://localhost/hook",
                "http://93.184.216.34/hook"):
        _expect_refusal(lambda u=url: _ae.check_egress(u),
                        "aauth-egress-blocked")
    # Positive control: https to a public IP passes.
    _ae.check_egress("https://93.184.216.34/hook")
    return "loopback/rfc1918/link-local/localhost/non-https all refused"


def _probe_iss_mismatch_refused():
    note = _expect_refusal(
        lambda: _ae.verify_issuer("https://evil.example",
                                 "https://idp.example"),
        "aauth-iss-mismatch")
    note2 = _expect_refusal(
        lambda: _ae.verify_issuer(None, "https://idp.example"),
        "aauth-iss-mismatch")
    # Positive control: matching issuer passes.
    _ae.verify_issuer("https://idp.example", "https://idp.example")
    return "%s; missing-iss %s; match ok" % (note, note2)


_PROBES = {
    "egress-discovery-before-policy-refused":
        _probe_discovery_before_policy_refused,
    "egress-aud-mismatch-refused": _probe_aud_mismatch_refused,
    "egress-stale-created-refused": _probe_stale_created_refused,
    "egress-loopback-blocked": _probe_loopback_blocked,
    "egress-iss-mismatch-refused": _probe_iss_mismatch_refused,
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
        for code in ("aauth-scheme-not-allowed",
                     "aauth-aud-mismatch",
                     "aauth-stale-created",
                     "aauth-egress-blocked",
                     "aauth-iss-mismatch"):
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-241 aauth egress primitives probes (new API: %s)"
          % HAVE_NEW_API)
    results = []
    for name in PROBE_NAMES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for r in results if r[1] == "HELD")
    gap = sum(1 for r in results if r[1] == "GAP")
    bad = sum(1 for r in results if r[1] in ("BREAK", "ERROR"))
    for name, verdict, note in results:
        print("  [%s] %s: %s" % (verdict, name, note.split("\n")[0]))
    for note in _run_green_checks():
        print("  green: %s" % note)
    print("HELD=%d GAP=%d BREAK/ERROR=%d" % (held, gap, bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
