"""Break-first probes for F240/F241/F242 closures (wave-264 lane A).

Targets (base 7fa1114729d3374e71eb0b88e43698c4b919f142, taxonomy pin
1151) -- every probe attacks a PUBLIC seam, never product internals:

- F240: sealed subject binding unenforced at the registry. The fix
  adds an expected-subject presenter parameter to
  ToolRegistry.invoke/list_tools; a presenter mismatch refuses
  machine-coded ``scope-listing-subject-mismatch``.
- F241: no domain separation between scope tickets and consent
  tokens. The fix domain-separates the MAC input per protocol
  (w244's _GRANT_DOMAIN/_POLICY_DOMAIN house pattern), so a
  cross-presented token refuses machine-coded in both directions
  (scope-grant-tampered on the ticket side, scope-consent-forged on
  the consent side) and genuine tokens still verify.
- F242: invoke() consulted the registry before verifying the ticket.
  The fix verifies the sealed ticket FIRST: forged/malformed ->
  scope-grant-tampered for every name, missing -> scope-listing-denied
  for every non-public name, zero-scope (public) tools stay invokable,
  and the deliberate post-auth not-registered-vs-denied residual is
  preserved.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. On the pristine base the attack probes BREAK exactly as the
F240-F242 defect notes describe; post-fix they HELD, in both staging
and `env -u GOV_DEPLOYMENT_MODE`.

Stdlib only. Deterministic. No in-repo git subprocesses (wave-36
supply-chain probe: fail closed). Green check is depth-1 and honors
GOV_SKIP_GREEN=1.
"""

import inspect
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gov import decision_codes
from gov import scoped_tool_listing as stl

TAXONOMY_PIN = 2014 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)



_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


# ---------------------------------------------------------------- world

_SCOPE_KEY = b"w264-scope-ticket-deployment-key-32b!"
_UNIVERSE = frozenset({"files:read", "files:read-admin", "net:fetch",
                       "db:query"})

_PRESENTER_PARAMS = {"subject", "presenter", "subject_digest",
                     "expected_sub", "expected_subject"}


def _world():
    iss = stl.ScopeTicketIssuer(_SCOPE_KEY, _UNIVERSE)
    reg = stl.ToolRegistry(_UNIVERSE).bind_issuer(iss)
    reg.register("read_file", {"files:read"}, "Read a file.")
    reg.register("query_db", {"db:query"}, "Query the database.")
    reg.register("admin_reindex", {"files:read-admin"}, "Rebuild index.")
    reg.register("ping", set(), "Public zero-scope tool.")
    return iss, reg


def _code_of(fn):
    try:
        fn()
    except stl.ScopedListingError as e:
        return e.code
    except Exception as e:  # noqa: BLE001 -- harness reports raw escapes
        return "RAW:%s" % type(e).__name__
    return "EXECUTED"


def _presenter_kw():
    """Find the presenter's keyword on invoke/list_tools, if any."""
    got = set(inspect.signature(stl.ToolRegistry.invoke).parameters)
    got |= set(inspect.signature(stl.ToolRegistry.list_tools).parameters)
    hit = sorted(got & _PRESENTER_PARAMS)
    return hit[0] if hit else None


# ------------------------------------------------------------------ F240


@probe("f240/cross-subject-invoke-bearer")
def _p_f240_invoke():
    """F240: a ticket sealed for alice must not authorize a presenter
    asserting to be bob. Fixed code refuses scope-listing-subject-mismatch."""
    iss, reg = _world()
    ticket_a = iss.seal("alice-subject-digest", {"files:read"}, 1000.0)
    kw = _presenter_kw()
    if kw is None:
        return _break(
            "no presenter parameter on invoke/list_tools: ticket bound "
            "to 'alice-subject-digest' authorizes any holder")
    # Matching presenter still works (positive control).
    ran = reg.invoke(ticket_a, "read_file", lambda: "ran",
                     **{kw: "alice-subject-digest"})
    if ran != "ran":
        return ("ERROR", "matching presenter did not execute")
    # Mismatched presenter must refuse machine-coded.
    code = _code_of(lambda: reg.invoke(
        ticket_a, "read_file", lambda: "ran", **{kw: "bob-subject-digest"}))
    if code == "scope-listing-subject-mismatch":
        return _held("mismatched presenter refused machine-coded")
    if code == "EXECUTED":
        return _break("cross-subject invoke EXECUTED despite presenter "
                      "parameter (binding still unenforced)")
    return ("ERROR", "mismatched presenter gave unexpected code %r" % code)


@probe("f240/cross-subject-listing-bearer")
def _p_f240_listing():
    """F240 listing seam: list_tools must bind the presenter too."""
    iss, reg = _world()
    ticket_a = iss.seal("alice-subject-digest", {"files:read"}, 1000.0)
    kw = _presenter_kw()
    if kw is None:
        return _break("no presenter parameter on list_tools: listing "
                      "for alice's ticket needs no presenter identity")
    code = _code_of(lambda: reg.list_tools(
        ticket_a, **{kw: "mallory-subject-digest"}))
    if code == "scope-listing-subject-mismatch":
        return _held("mismatched presenter listing refused machine-coded")
    if code == "EXECUTED":
        return _break("cross-subject listing returned views despite "
                      "presenter parameter")
    return ("ERROR", "unexpected listing code %r" % code)


@probe("f240/holder-semantics-preserved")
def _p_f240_holder():
    """Control: without a presenter assertion the ticket keeps its
    documented holder-usable semantics (no false positives)."""
    iss, reg = _world()
    ticket_a = iss.seal("alice-subject-digest", {"files:read"}, 1000.0)
    if reg.invoke(ticket_a, "read_file", lambda: "ran") != "ran":
        return ("ERROR", "holder invoke regressed")
    names = [n for n, _ in reg.list_tools(ticket_a)]
    if names != ["ping", "read_file"]:
        return ("ERROR", "holder listing regressed: %r" % names)
    return _held("holder semantics unchanged when no presenter asserted")


# ------------------------------------------------------------------ F241


@probe("f241/consent-token-verifies-as-scope-ticket")
def _p_f241_ticket_side():
    """F241: a consent token presented as a scope ticket (shared key)
    must refuse machine-coded, not verify."""
    iss, _reg = _world()
    ci = stl.ConsentIssuer(_SCOPE_KEY, ttl_seconds=300)
    url = ci.mint_consent_url("appr-1", "query_db", {"db:query"},
                              "human-sub", 1000.0, "https://consent.local/c")
    token = url.split("?ct=", 1)[1]
    try:
        sub, scopes = iss.verify(token)
    except stl.ScopedListingError as e:
        return _held("cross-presented consent token refused: %s" % e.code)
    return _break("consent token VERIFIES as scope ticket (sub=%r "
                  "scopes=%r): no domain separation" % (sub, sorted(scopes)))


@probe("f241/scope-ticket-presented-to-consent")
def _p_f241_consent_side():
    """F241 reverse direction: a scope ticket presented to
    confirm_consent must refuse scope-consent-forged (the correct
    code), not the wrong-reason scope-consent-expired."""
    iss, _reg = _world()
    ci = stl.ConsentIssuer(_SCOPE_KEY, ttl_seconds=300)
    ticket = iss.seal("human-sub", {"db:query"}, 1000.0)
    audit = []
    code = _code_of(lambda: ci.confirm_consent(
        ticket, "appr-9", "query_db", "human-sub", 1100.0, audit.append))
    if code == "scope-consent-forged":
        if audit:
            return ("ERROR", "refused consent was audited")
        return _held("cross-presented scope ticket refused forged")
    if code == "scope-consent-expired":
        return _break("scope ticket refused as EXPIRED (wrong reason): "
                      "the sealed formats carry no type information")
    return ("ERROR", "unexpected consent-side code %r" % code)


@probe("f241/genuine-tokens-still-verify")
def _p_f241_control():
    """Control: genuine consent confirmations and genuine scope
    tickets still verify (no cross-breakage from domain separation)."""
    iss, _reg = _world()
    ci = stl.ConsentIssuer(_SCOPE_KEY, ttl_seconds=300)
    ticket = iss.seal("agent-sub", {"db:query"}, 1000.0)
    sub, scopes = iss.verify(ticket)
    if sub != "agent-sub" or scopes != frozenset({"db:query"}):
        return ("ERROR", "genuine scope ticket broke")
    url = ci.mint_consent_url("appr-1", "query_db", {"db:query"},
                              "human-sub", 1000.0, "https://consent.local/c")
    token = url.split("?ct=", 1)[1]
    audit = []
    ok = ci.confirm_consent(token, "appr-1", "query_db", "human-sub",
                            1100.0, audit.append)
    if not ok or len(audit) != 1:
        return ("ERROR", "genuine consent confirmation broke")
    return _held("genuine ticket verifies; genuine consent confirms")


# ------------------------------------------------------------------ F242


@probe("f242/pre-auth-existence-oracle")
def _p_f242_oracle():
    """F242: with no ticket or a forged ticket, the refusal codes must
    not distinguish absent names from present-but-scoped names."""
    _iss, reg = _world()
    none_ghost = _code_of(lambda: reg.invoke(None, "ghost_tool",
                                             lambda: 1))
    none_real = _code_of(lambda: reg.invoke(None, "read_file",
                                            lambda: 1))
    forged_ghost = _code_of(lambda: reg.invoke("AAAA.BBBB", "ghost_tool",
                                               lambda: 1))
    forged_real = _code_of(lambda: reg.invoke("AAAA.BBBB", "read_file",
                                              lambda: 1))
    detail = ("none: ghost=%s real=%s; forged: ghost=%s real=%s"
              % (none_ghost, none_real, forged_ghost, forged_real))
    want_none = (none_ghost == "scope-listing-denied" and
                 none_real == "scope-listing-denied")
    want_forged = (forged_ghost == "scope-grant-tampered" and
                   forged_real == "scope-grant-tampered")
    if want_none and want_forged:
        return _held("no pre-auth oracle: " + detail)
    return _break("pre-auth existence oracle: " + detail)


@probe("f242/post-auth-distinguishability-residual")
def _p_f242_residual():
    """Control: with a VALID ticket the deliberate residual survives --
    not-registered vs denied stay distinguishable."""
    iss, reg = _world()
    low = iss.seal("agent-sub", set(), 1000.0)
    ghost = _code_of(lambda: reg.invoke(low, "ghost_tool", lambda: 1))
    scoped = _code_of(lambda: reg.invoke(low, "read_file", lambda: 1))
    if ghost == "scope-listing-not-registered" and\
            scoped == "scope-listing-denied":
        return _held("post-auth: not-registered vs denied (deliberate)")
    return ("ERROR", "post-auth codes changed: %s / %s" % (ghost, scoped))


@probe("f242/public-tool-no-ticket")
def _p_f242_public():
    """Control: zero-scope (public) tools stay invokable with no
    ticket, consistent with list_tools(None)."""
    _iss, reg = _world()
    if reg.invoke(None, "ping", lambda: "pong") != "pong":
        return ("ERROR", "public tool invoke regressed")
    names = [n for n, _ in reg.list_tools(None)]
    if names != ["ping"]:
        return ("ERROR", "public listing regressed: %r" % names)
    code = _code_of(lambda: reg.invoke(None, "read_file", lambda: 1))
    if code != "scope-listing-denied":
        return ("ERROR", "scoped tool with no ticket gave %r" % code)
    return _held("public tools invokable; scoped tools denied")


# ------------------------------------------------------------ green check

def _green_check():
    """Depth-1: run adjacent batteries' mains with GOV_SKIP_GREEN=1 in
    the child env (no combinatorial nesting). Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "skipped (GOV_SKIP_GREEN=1)")]
    here = os.path.dirname(os.path.abspath(__file__))
    adjacent = ["w262_scopelist_probes.py", "w263_redteam_probes.py"]
    notes = []
    for battery in adjacent:
        path = os.path.join(here, battery)
        if not os.path.exists(path):
            notes.append((battery, "absent -- skipped"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tempfile.mkdtemp(prefix="w264-green-")
        os.makedirs(env["TMPDIR"], exist_ok=True)
        try:
            proc = subprocess.run(
                [sys.executable, path], env=env, capture_output=True,
                text=True, timeout=600)
        except Exception as e:  # noqa: BLE001
            notes.append((battery, "ERROR: %s" % e))
            continue
        tail = (proc.stdout or "").strip().splitlines()[-1:]
        notes.append((battery, "exit=%d %s"
                      % (proc.returncode,
                         tail[0][:100] if tail else "")))
    return notes


def main():
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        print("PIN MISMATCH: taxonomy has %d keys, pin is %d"
              % (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
        return 2
    held = breaks = baselines = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s"
                               % (type(e).__name__, str(e)[:120]))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        elif verdict == "BASELINE":
            baselines += 1
        else:
            errors += 1
        print("%-8s %-55s %s" % (verdict, name, detail))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("HELD %d / BREAK %d / BASELINE %d / ERROR %d over %d probes"
          % (held, breaks, baselines, errors, len(_PROBES)))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
