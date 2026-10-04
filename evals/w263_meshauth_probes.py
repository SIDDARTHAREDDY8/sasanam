"""Break-first probes for the A2A-style agent-mesh auth contract (wave-263).

A2A ADAPT (pattern only; no A2A code or spec text is read, copied,
imported, or vendored): SecurityScheme declarations on agent cards
(mapped onto OUR credential primitives: SVID, short-lived credential,
scope ticket), per-request auth envelopes verified before routing,
§7.5-style authorization dimensions (who/what/scope/context) at the
call seam, and §7.6-style mid-task escalation to an explicit
AUTH_REQUIRED state (the task pauses; it never fails or silently
continues unauthenticated).

Red-first: on the pristine base these probes GAP (no mesh-auth
contract exists — see RED_RUN.log). Post-fix they must all HELD, in
BOTH deployment modes (staging default below; prod via
`env -u GOV_DEPLOYMENT_MODE`).

Probe shapes (task): scheme confusion (SVID presented where a scope
ticket is required), auth-envelope stripping mid-task, escalation
bypass (proceeding past AUTH_REQUIRED without re-auth),
undeclared-scheme member — plus tiered card disclosure and the
taxonomy pin.

Stdlib only. No network, no in-repo git subprocesses. Green check is
depth-1 and honors GOV_SKIP_GREEN=1.
"""

import hashlib
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

# Wave-263 lane 2: pin -> 1137 (8 new mesh-auth-* codes).
TAXONOMY_PIN = 1991 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)


sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

try:
    import gov.decision_codes as dc
    import gov.mesh_auth as ma
    from gov import svid_issuer as sv
    from gov import scoped_tool_listing as stl
    from gov import short_lived_credentials as slc
    _IMPORT_ERROR = None
except ImportError as e:
    dc = ma = sv = stl = slc = None
    _IMPORT_ERROR = e


def _need_module():
    if _IMPORT_ERROR is not None:
        return False, "GAP: gov.mesh_auth unavailable on pristine base " \
            "(%s)" % _IMPORT_ERROR
    return True, ""

UNIVERSE = frozenset({"files:read", "files:write", "net:fetch"})
TICKET_KEY = b"w263-ticket-key-32-bytes-padded-00"
CRED_KEY = b"w263-cred-key-32-bytes-padded-0000"
ISSUER_SEED = bytes(range(32))
TRUST_DOMAIN = "example.org"
SPIFFE_A = "spiffe://example.org/agent-a"
SPIFFE_B = "spiffe://example.org/agent-b"
NOW = 4000000000.0

NEW_CODES = (
    "mesh-auth-malformed",
    "mesh-auth-envelope-missing",
    "mesh-auth-undeclared-scheme",
    "mesh-auth-scheme-confusion",
    "mesh-auth-scope-uncovered",
    "mesh-auth-subject-mismatch",
    "mesh-auth-task-paused",
    "mesh-auth-escalation-bypass",
)


def _pubkey(tag):
    return hashlib.sha256(("w263-" + tag).encode()).hexdigest()


def _world():
    issuer = sv.TestSvidIssuer(issuer_seed=ISSUER_SEED,
                               key_id="w263-issuer-1")
    verifier = sv.SvidVerifier(
        {"w263-issuer-1": issuer.issuer_public_key}, TRUST_DOMAIN)
    control = sv.MeshControl(verifier, {"allow": [SPIFFE_A, SPIFFE_B]})
    tickets = stl.ScopeTicketIssuer(TICKET_KEY, UNIVERSE)
    creds = slc.CredentialIssuer(
        os.path.join(tempfile.mkdtemp(prefix="w263-creds-"), "j.jsonl"),
        key=CRED_KEY)
    gate = ma.MeshCallGate(svid_control=control,
                           ticket_issuer=tickets,
                           credential_issuer=creds)
    return issuer, gate, tickets, creds


def _svid_envelope(issuer, spiffe_id):
    return {"scheme": "svid",
            "credential": issuer.issue(spiffe_id, _pubkey(spiffe_id),
                                       15, now=NOW)}


def _ticket_envelope(tickets, spiffe_id, scopes):
    sub = hashlib.sha256(spiffe_id.encode()).hexdigest()
    return {"scheme": "scope-ticket",
            "credential": tickets.seal(sub, scopes, NOW)}


def _card(*schemes):
    return ma.MeshAuthCard("agent-b", list(schemes),
                           endpoints={"rpc": "https://b.internal/rpc"},
                           capabilities=["fetch_url"])


def _expect_mesh_auth(fn, want_code):
    try:
        fn()
    except ma.MeshAuthError as e:
        if e.code == want_code:
            return True, "HELD (%s)" % want_code
        return False, "GAP: code %s, wanted %s" % (e.code, want_code)
    return False, "GAP: no refusal (wanted %s)" % want_code


def p_scheme_confusion():
    _ok, _why = _need_module()
    if not _ok:
        return False, _why
    """SVID presented where the call requires a scope ticket: refused.

    Identity (SVID) is not a scope grant; silently substituting one
    scheme's credential for another's is the confusion attack.
    """
    issuer, gate, _, _ = _world()
    card = _card("svid", "scope-ticket")
    env = _svid_envelope(issuer, SPIFFE_A)
    ok, why = _expect_mesh_auth(
        lambda: gate.authorize_call(card, env, required_scheme="scope-ticket",
                                    now=NOW),
        "mesh-auth-scheme-confusion")
    if not ok:
        return False, why
    # Control: the same SVID where svid IS required authorizes fine.
    rec = gate.authorize_call(card, env, required_scheme="svid", now=NOW)
    if rec["subject"] != SPIFFE_A:
        return False, "GAP: legitimate svid call refused"
    return True, "HELD (identity != scope grant; required scheme wins)"


def p_envelope_stripping():
    _ok, _why = _need_module()
    if not _ok:
        return False, _why
    """Stripping the auth envelope mid-task refuses; the task survives."""
    issuer, gate, _, _ = _world()
    card = _card("svid", "scope-ticket")
    tasks = ma.MeshTaskAuth(gate)
    tasks.begin("t1", owner=SPIFFE_A)
    env = _svid_envelope(issuer, SPIFFE_A)
    tasks.call("t1", card, env, now=NOW)  # call 1: fine
    ok, why = _expect_mesh_auth(
        lambda: tasks.call("t1", card, None, now=NOW),
        "mesh-auth-envelope-missing")
    if not ok:
        return False, why
    if tasks.state("t1") != ma.TASK_STATE_ACTIVE:
        return False, "GAP: stripped call killed the task instead of " \
            "refusing the call"
    return True, "HELD (call refused; task still active)"


def p_escalation_bypass():
    _ok, _why = _need_module()
    if not _ok:
        return False, _why
    """AUTH_REQUIRED tasks stay paused until re-auth with the stronger
    scheme; bypassing the escalation is refused."""
    issuer, gate, tickets, _ = _world()
    card = _card("svid", "scope-ticket")
    tasks = ma.MeshTaskAuth(gate)
    tasks.begin("t2", owner=SPIFFE_A)
    svid_env = _svid_envelope(issuer, SPIFFE_A)
    tasks.call("t2", card, svid_env, now=NOW)
    tasks.escalate("t2", required_scheme="scope-ticket",
                   reason="fetch_url needs the net:fetch scope grant",
                   subject=SPIFFE_A, now=NOW)
    if tasks.state("t2") != ma.TASK_STATE_AUTH_REQUIRED:
        return False, "GAP: escalate did not pause the task"
    # (a) plain call with the OLD credential while paused -> refused,
    # task stays paused, never proceeds.
    ok, why = _expect_mesh_auth(
        lambda: tasks.call("t2", card, svid_env, now=NOW),
        "mesh-auth-task-paused")
    if not ok:
        return False, why
    if tasks.state("t2") != ma.TASK_STATE_AUTH_REQUIRED:
        return False, "GAP: refused call unpaused the task"
    # (b) resume with the OLD (weaker) scheme -> escalation-bypass.
    ok, why = _expect_mesh_auth(
        lambda: tasks.resume("t2", card, svid_env, subject=SPIFFE_A,
                             now=NOW),
        "mesh-auth-escalation-bypass")
    if not ok:
        return False, why
    # (c) resume with the required stronger scheme -> active again.
    ticket_env = _ticket_envelope(tickets, SPIFFE_A, {"net:fetch"})
    rec = tasks.resume("t2", card, ticket_env, subject=SPIFFE_A, now=NOW)
    if tasks.state("t2") != ma.TASK_STATE_ACTIVE:
        return False, "GAP: valid re-auth did not resume the task"
    if "net:fetch" not in rec["scopes"]:
        return False, "GAP: resumed record carries no scopes"
    return True, "HELD (pause holds; bypass refused; re-auth resumes)"


def p_undeclared_scheme():
    _ok, _why = _need_module()
    if not _ok:
        return False, _why
    """A scheme the callee's card never declared is refused; a member
    with no declared schemes refuses everything."""
    issuer, gate, tickets, _ = _world()
    card = _card("svid")
    ticket_env = _ticket_envelope(tickets, SPIFFE_A, {"net:fetch"})
    ok, why = _expect_mesh_auth(
        lambda: gate.authorize_call(card, ticket_env, now=NOW),
        "mesh-auth-undeclared-scheme")
    if not ok:
        return False, why
    # Member that declares nothing: even a valid SVID refuses.
    bare = ma.MeshAuthCard("agent-c", [])
    env = _svid_envelope(issuer, SPIFFE_A)
    ok, why = _expect_mesh_auth(
        lambda: gate.authorize_call(bare, env, now=NOW),
        "mesh-auth-undeclared-scheme")
    if not ok:
        return False, why
    # Control: the declared scheme still works.
    rec = gate.authorize_call(card, env, now=NOW)
    if rec["subject"] != SPIFFE_A:
        return False, "GAP: declared svid scheme refused"
    return True, "HELD (undeclared scheme/member refused fail-closed)"


def p_tiered_disclosure():
    _ok, _why = _need_module()
    if not _ok:
        return False, _why
    """Unauthenticated callers see capabilities + scheme names; the
    endpoints surface only on the authenticated view (§6.9 adapt)."""
    card = _card("svid", "scope-ticket")
    public = card.public_view()
    if "endpoints" in public:
        return False, "GAP: public view leaks endpoints"
    if set(public["security_schemes"]) != {"svid", "scope-ticket"}:
        return False, "GAP: public view hides the auth contract"
    authed = card.authenticated_view()
    if authed.get("endpoints", {}).get("rpc") != "https://b.internal/rpc":
        return False, "GAP: authenticated view lacks endpoints"
    return True, "HELD (capabilities public; endpoints gated)"


def p_taxonomy_pin():
    _ok, _why = _need_module()
    if not _ok:
        return False, _why
    """The 8 new mesh-auth-* codes are registered; pin is 1137."""
    missing = [c for c in NEW_CODES if c not in dc.TAXONOMY]
    if missing:
        return False, "GAP: codes missing from taxonomy: %r" % missing
    if len(dc.TAXONOMY) != TAXONOMY_PIN:
        return False, "GAP: taxonomy has %d codes, pin is %d"\
            % (len(dc.TAXONOMY), TAXONOMY_PIN)
    return True, "HELD (pin %d, 8 new codes present)" % TAXONOMY_PIN


PROBES = [
    ("scheme-confusion", p_scheme_confusion),
    ("envelope-stripping", p_envelope_stripping),
    ("escalation-bypass", p_escalation_bypass),
    ("undeclared-scheme", p_undeclared_scheme),
    ("tiered-disclosure", p_tiered_disclosure),
    ("taxonomy-pin", p_taxonomy_pin),
]


def green_check():
    """Depth-1 green check: run the lane's unit tests; honors
    GOV_SKIP_GREEN=1 (parent batteries pass it down; a standalone run
    with the var set records a skip and returns without spawning)."""
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "SKIPPED (GOV_SKIP_GREEN=1)"
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = os.environ.get("TMPDIR", "/tmp")
    r = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_mesh_auth", "-v"],
        cwd=repo, env=env, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise SystemExit("GREEN CHECK FAILED:\n%s\n%s"
                         % (r.stdout[-3000:], r.stderr[-3000:]))
    # unittest -v writes progress to stderr
    return "OK (%d tests)" % r.stderr.count(" ... ok")


def main():
    mode = os.environ.get("GOV_DEPLOYMENT_MODE", "staging")
    held, gap = 0, 0
    print("w263 mesh-auth probes — mode=%s" % mode)
    for name, fn in PROBES:
        try:
            ok, why = fn()
        except Exception as e:  # noqa: BLE001 — a probe error is a GAP
            ok, why = False, "GAP: probe raised %r" % e
        held, gap = held + ok, gap + (not ok)
        print("[%s] %-20s %s" % ("HELD" if ok else "GAP", name, why))
    print("green check: %s" % green_check())
    print("result: %d HELD / %d GAP" % (held, gap))
    return 0 if gap == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
