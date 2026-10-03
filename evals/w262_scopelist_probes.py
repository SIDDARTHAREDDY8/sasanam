"""Break-first probes for scope-gated tool listing (wave-262 lane 1).

MCP D1 ADAPT: the tool registry is an enforcement point — the listing
MAY vary by presented scopes — plus the spec's human-in-the-loop UX
contract and elicitation URL-mode out-of-band consent.

Red-first: on the pristine base these probes GAP (no scope-gated
listing exists — see ../RED_RUN.log). Post-fix they must all HELD,
in BOTH deployment modes (staging default below; prod via
`env -u GOV_DEPLOYMENT_MODE`).

Probe shapes (task): scope-escalation via prefix, unlisted-tool
invocation, listing-enumeration, consent-record forgery, plus
unknown-scope refusal and empty-listing silence.

Stdlib only. No network, no in-repo git subprocesses. Green check is
depth-1 and honors GOV_SKIP_GREEN=1.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

TAXONOMY_PIN = 1857  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import gov.decision_codes as dc
import gov.scoped_tool_listing as stl

UNIVERSE = frozenset({"files:read", "files:write", "files:read-admin",
                      "net:fetch", "db:query"})
ISSUER_KEY = b"w262-probe-key-32-bytes-padded-0000"
CONSENT_KEY = b"w262-consent-key-32-bytes-pad-0000"


def _world():
    iss = stl.ScopeTicketIssuer(ISSUER_KEY, UNIVERSE)
    reg = stl.ToolRegistry(UNIVERSE).bind_issuer(iss)
    reg.register("read_file", {"files:read"}, "Read a file.")
    reg.register("write_file", {"files:write"}, "Write a file.")
    reg.register("admin_reindex", {"files:read-admin"}, "Rebuild index.")
    reg.register("fetch_url", {"net:fetch"}, "Fetch a URL.",
                 needs_consent=True)
    reg.register("query_db", {"db:query"}, "Query the database.")
    ci = stl.ConsentIssuer(CONSENT_KEY, ttl_seconds=300)
    return iss, reg, ci


def _expect(probe, fn, want_code):
    try:
        fn()
    except stl.ScopedListingError as e:
        if e.code == want_code:
            return True, "HELD (%s)" % want_code
        return False, "GAP: code %s, wanted %s" % (e.code, want_code)
    return False, "GAP: no refusal (wanted %s)" % want_code


def p_prefix_escalation():
    """read must not cover read-admin; suffix beyond universe refused."""
    iss, reg, _ = _world()
    t = iss.seal("agent-sub", {"files:read"}, 1000.0)
    ok, why = _expect(
        "prefix", lambda: reg.invoke(t, "admin_reindex", lambda: "ran"),
        "scope-listing-denied")
    if not ok:
        return False, why
    listed = [n for n, _ in reg.list_tools(t)]
    if "admin_reindex" in listed:
        return False, "GAP: read-admin tool leaked into read-only listing"
    try:
        iss.seal("agent-sub", {"files:read-adminX"}, 1000.0)
        return False, "GAP: scope beyond universe was sealed"
    except stl.ScopedListingError as e:
        if e.code != "scope-listing-unknown-scope":
            return False, "GAP: wrong code %s" % e.code
    return True, "HELD (exact-match; read != read-admin)"


def p_unlisted_invocation():
    """Invoking a never-registered tool refuses machine-coded."""
    iss, reg, _ = _world()
    t = iss.seal("agent-sub", set(UNIVERSE), 1000.0)
    return _expect(
        "unlisted", lambda: reg.invoke(t, "ghost_tool", lambda: "ran"),
        "scope-listing-not-registered")


def p_listing_enumeration():
    """An unpermitted tool's existence cannot be confirmed via listing."""
    iss, reg, _ = _world()
    t = iss.seal("agent-sub", {"files:read"}, 1000.0)
    views = reg.list_tools(t)
    blob = repr(views)
    for secret in ("admin_reindex", "fetch_url", "query_db",
                   "files:read-admin", "net:fetch", "db:query"):
        if secret in blob:
            return False, "GAP: %r confirmable from listing" % secret
    if len(views) != 1 or views[0][0] != "read_file":
        return False, "GAP: listing cardinality wrong: %r" % (
            [n for n, _ in views],)
    # empty ticket: empty, never full
    if reg.list_tools(iss.seal("agent-sub", set(), 1000.0)) != []:
        return False, "GAP: empty ticket returned tools"
    if reg.list_tools(None) != []:
        return False, "GAP: None ticket returned tools"
    return True, "HELD (silence: no names, no metadata, no count oracle)"


def p_consent_forgery():
    """Approval recorded without the human step must be impossible."""
    _, reg, ci = _world()
    audit = []
    # forged token (random bytes, well-formed shape)
    try:
        ci.confirm_consent("AAAA.BBBB", "appr-1", "fetch_url",
                           "sub", 1100.0, audit.append)
        return False, "GAP: forged token accepted"
    except stl.ScopedListingError as e:
        if e.code != "scope-consent-forged":
            return False, "GAP: wrong code %s" % e.code
    if audit:
        return False, "GAP: forged consent was audited"
    # genuine token rebound to another approval
    url = ci.mint_consent_url("appr-1", "fetch_url", {"net:fetch"},
                              "sub", 1000.0, "https://consent.local/c")
    token = url.split("ct=")[1]
    try:
        ci.confirm_consent(token, "appr-2", "fetch_url", "sub",
                           1100.0, audit.append)
        return False, "GAP: rebound consent accepted"
    except stl.ScopedListingError as e:
        if e.code != "scope-consent-unbound":
            return False, "GAP: wrong code %s" % e.code
    # no back-door recording API exists
    backdoors = [n for n in dir(stl)
                 if "record" in n.lower() and not n.startswith("_")]
    if backdoors:
        return False, "GAP: recording backdoor API: %r" % backdoors
    # genuine human step still works and audits by digest only
    ok = ci.confirm_consent(token, "appr-1", "fetch_url", "sub",
                            1100.0, audit.append)
    if not ok or len(audit) != 1 or token in repr(audit[0]):
        return False, "GAP: genuine consent mishandled"
    return True, "HELD (forge/unbound refused; no backdoor; digest audit)"


def p_unknown_scope():
    iss, _, _ = _world()
    return _expect(
        "unknown-scope",
        lambda: iss.seal("sub", {"root"}, 1000.0),
        "scope-listing-unknown-scope")


def p_approval_seam():
    """The UX-contract shape hands to ApprovalQueue.queue without dup."""
    _, reg, ci = _world()
    iss = stl.ScopeTicketIssuer(ISSUER_KEY, UNIVERSE)
    t = iss.seal("sub", {"net:fetch"}, 1000.0)
    view = dict(reg.list_tools(t))["fetch_url"]
    shape = stl.build_approval_request(
        "fetch_url", view, {"net:fetch"}, "sub",
        what_it_would_do="Fetch the status endpoint.",
        consent_url="https://consent.local/c?ct=T",
        args={"url": "fake_value_abc"})
    calls = []

    class StubQueue(object):
        def queue(self, action, decision=None, **kw):
            calls.append((action, kw))
            return "appr-7"

    ident = object()
    aid = stl.enqueue_approval(StubQueue(), shape, caller_identity=ident)
    if aid != "appr-7":
        return False, "GAP: seam did not return the queue's approval id"
    action, kw = calls[0]
    if kw.get("caller_identity") is not ident:
        return False, "GAP: caller_identity not passed to the queue"
    if "Fetch the status endpoint." not in kw.get("preview", ""):
        return False, "GAP: human description missing from preview"
    if action.get("tool") != "fetch_url":
        return False, "GAP: tool missing from queued action"
    # missing identity refuses before the queue is touched
    try:
        stl.enqueue_approval(StubQueue(), shape, caller_identity=None)
        return False, "GAP: enqueue without identity did not refuse"
    except stl.ScopedListingError as e:
        if e.code != "scope-listing-denied":
            return False, "GAP: wrong code %s" % e.code
    return True, "HELD (shape -> ApprovalQueue.queue seam; F42 preserved)"


def p_taxonomy_pin():
    n = len(dc.TAXONOMY)
    if n != TAXONOMY_PIN:
        return False, "GAP: taxonomy pin %d, want %d" % (n, TAXONOMY_PIN)
    for c in stl.CODES:
        if c not in dc.TAXONOMY:
            return False, "GAP: new code %s missing from taxonomy" % c
    return True, "HELD (pin %d, 6 new codes present)" % TAXONOMY_PIN


PROBES = [
    ("scope-escalation-prefix", p_prefix_escalation),
    ("unlisted-invocation", p_unlisted_invocation),
    ("listing-enumeration", p_listing_enumeration),
    ("consent-forgery", p_consent_forgery),
    ("unknown-scope", p_unknown_scope),
    ("approval-seam", p_approval_seam),
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
        [sys.executable, "-m", "unittest",
         "tests.test_scoped_tool_listing", "-v"],
        cwd=repo, env=env, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise SystemExit("GREEN CHECK FAILED:\n%s\n%s"
                         % (r.stdout[-3000:], r.stderr[-3000:]))
    # unittest -v writes progress to stderr
    return "OK (%d tests)" % r.stderr.count(" ... ok")


def main():
    mode = os.environ.get("GOV_DEPLOYMENT_MODE", "staging")
    held, gap = 0, 0
    print("w262 scopelist probes — mode=%s" % mode)
    for name, fn in PROBES:
        try:
            ok, why = fn()
        except Exception as e:  # noqa: BLE001 — a probe error is a GAP
            ok, why = False, "GAP: probe raised %r" % e
        held, gap = held + ok, gap + (not ok)
        print("[%s] %-24s %s" % ("HELD" if ok else "GAP", name, why))
    print("green check: %s" % green_check())
    print("result: %d HELD / %d GAP" % (held, gap))
    return 0 if gap == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
