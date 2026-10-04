"""Break-first red-team battery for the wave-262 seams (wave-263 lane).

Targets (base 82c84934027be71083d260520c3b7fb3eab89ffa, taxonomy pin
1129) -- every probe attacks a PUBLIC seam, never product internals:

A. gov/scoped_tool_listing.py (wave-262 feature lane 1):
   - sealed subject binding: the ticket binds the caller's SUBJECT
     DIGEST, but ToolRegistry.invoke/list_tools discard the sub and
     take no presenter identity -- tickets are bearer tokens across
     subjects (F240).
   - cross-protocol confusion: consent tokens and scope tickets share
     one MAC construction with no type tag; under a shared deployment
     key a consent token VERIFIES as a scope ticket (F241). (w244's
     grants use _GRANT_DOMAIN; this module has no domain separation.)
   - pre-auth existence oracle: invoke() consults the tool registry
     BEFORE verifying the ticket, so no-ticket/forged-ticket probes
     distinguish absent vs present-but-scoped names -- beyond the
     documented deliberate post-auth residual (F242).
   - controls (HELD): tampered tickets refuse scope-grant-tampered,
     unknown scopes refuse at seal and at every use, exact-match
     scope coverage, consent forge/rebind/expire refused
     machine-coded, listing stays silent.

B. gov/root_ceremony.py (wave-262 feature lane 3):
   - is_ceremonial classifier audit: 27 adversarial actions; no
     root-touching op classifies routine (HELD).
   - execute-phase bool composition: BallotBox.vote() enforces bool
     at the mouth, so the F237 hook-coercion pattern cannot reach
     threshold_approval._resolve (HELD).
   - extra proposal fields ride outside the ceremony digest
     (BASELINE: journal-only metadata via extra_keys, no decision
     reads them, no contract violated).
   - rehearsal namespace "scratch/../prod" passes the prefix check
     (BASELINE: the check is documented as a syntactic "looks like"
     heuristic; the deployment runs the rehearsal).

C. gov/detectors.py alert discipline (wave-262 feature lane 2):
   - deployment-policy values-overrides were invisible in alert
     records (F243, CLOSED wave-264): records now carry the
     effective exception values + policy revision; the probe is a
     regression pin (HELD when the override is attributable).
   - DetectorEngine.detectors returned live definition dicts (F244,
     CLOSED wave-264): the accessor now returns deep copies; the
     probe is a regression pin (HELD when runtime mutation has no
     effect, BREAK on regression).
   - control (HELD): disabling an exception fails closed to alert and
     journals disabled_but_matched.

D. gov/policy_distribution.py F235 residual: Publisher.sign_bundle
   raises raw RecursionError on recursion-hostile payload (BASELINE:
   the publisher is the documented trusted operator surface; the
   "never raises on hostile input" contract belongs to
   Subscriber.apply, which holds).

E. Cross-checks (dedicated lanes own them -- NOT re-filed): the
   w262 standing pins for F237/F238/F239 are re-run; verdict
   BASELINE means the defect still reproduces (finding remains OPEN).

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Verdicts: HELD (attack refused / gap is a documented
residual), BREAK (genuine defect -> filed F240+), BASELINE (filed-open
finding reproduced, or accepted pre-existing behavior verified on
base -- NOT a new finding), ERROR (harness bug -- fix the harness).

Stdlib only. Deterministic (staging + `env -u GOV_DEPLOYMENT_MODE`).
No in-repo git subprocesses (wave-36 supply-chain probe: fail
closed). Green checks are depth-1 and honor GOV_SKIP_GREEN=1.
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

from gov import ballot_governance as bg
from gov import decision_codes
from gov import detectors as det
from gov import ed25519
from gov import policy_distribution as poldist
from gov import root_ceremony as rc
from gov import scoped_tool_listing as stl

TAXONOMY_PIN = 2020 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*)



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


def _baseline(detail=""):
    return ("BASELINE", detail)


# ---------------------------------------------------------------- scope
# listing world

_SCOPE_KEY = b"w263-scope-ticket-deployment-key-32b!"
_UNIVERSE = frozenset({"files:read", "files:read-admin", "net:fetch",
                       "db:query"})


def _world():
    iss = stl.ScopeTicketIssuer(_SCOPE_KEY, _UNIVERSE)
    reg = stl.ToolRegistry(_UNIVERSE).bind_issuer(iss)
    reg.register("read_file", {"files:read"}, "Read a file.")
    reg.register("query_db", {"db:query"}, "Query the database.")
    reg.register("admin_reindex", {"files:read-admin"}, "Rebuild index.")
    reg.register("fetch_url", {"net:fetch"}, "Fetch a URL.",
                 needs_consent=True)
    return iss, reg


def _code_of(fn):
    try:
        fn()
    except stl.ScopedListingError as e:
        return e.code
    except Exception as e:  # noqa: BLE001 -- unexpected raw escape
        return "RAW:%s" % type(e).__name__
    return "EXECUTED"


@probe("scopelist/cross-subject-ticket-bearer")
def _p_cross_subject():
    """F240: the sealed subject binding is unenforced at the registry.

    The ticket binds the caller's SUBJECT DIGEST (module docstring:
    "Identity binding"), but ToolRegistry.invoke/list_tools discard
    the sub returned by verify() and accept no presenter identity --
    a ticket minted for subject A authorizes any holder.
    """
    iss, reg = _world()
    ticket_a = iss.seal("alice-subject-digest", {"files:read"}, 1000.0)
    sub, _scopes = iss.verify(ticket_a)
    if sub != "alice-subject-digest":
        return ("ERROR", "verify() did not return the bound subject")
    # A presenter who is NOT alice uses alice's ticket: no seam objects.
    ran = reg.invoke(ticket_a, "read_file", lambda: "ran")
    if ran != "ran":
        return ("ERROR", "invoke did not execute")
    params = set(inspect.signature(reg.invoke).parameters)
    params |= set(inspect.signature(reg.list_tools).parameters)
    presenter_params = params & {"subject", "presenter", "subject_digest",
                                "expected_sub", "expected_subject"}
    if presenter_params:
        # A future fix binds the presenter: cross-subject use must
        # then refuse. Re-check with a mismatched presenter.
        return _held("registry binds presenter via %r"
                     % sorted(presenter_params))
    return _break(
        "ticket bound to 'alice-subject-digest' authorized with no "
        "presenter check: invoke/list_tools take no subject identity, "
        "verify()'s sub is discarded -- bearer token across subjects")


@probe("scopelist/consent-token-verifies-as-scope-ticket")
def _p_cross_protocol():
    """F241: no domain separation between the two sealed-token types.

    Scope tickets and consent tokens share the identical MAC
    construction (_seal, no type tag). Under the shared deployment
    key a consent token verifies as a scope ticket -- every consent
    token doubles as a bearer scope ticket for its scopes until exp.
    """
    iss, _reg = _world()
    ci = stl.ConsentIssuer(_SCOPE_KEY, ttl_seconds=300)
    url = ci.mint_consent_url("appr-1", "fetch_url", {"net:fetch"},
                             "human-sub", 1000.0, "https://consent.local/c")
    token = url.split("ct=", 1)[1]
    try:
        sub, scopes = iss.verify(token)
    except stl.ScopedListingError as e:
        return _held("cross-presented consent token refused: %s" % e.code)
    if sub == "human-sub" and scopes == frozenset({"net:fetch"}):
        return _break(
            "consent token VERIFIES as a scope ticket (sub=%r scopes=%r): "
            "no type tag / domain separation between the two sealed "
            "protocols sharing a deployment key" % (sub, sorted(scopes)))
    return ("ERROR", "verify returned unexpected %r %r" % (sub, scopes))


@probe("scopelist/pre-auth-invoke-existence-oracle")
def _p_pre_auth_oracle():
    """F242: invoke() looks up the tool BEFORE verifying the ticket.

    With no ticket (or a forged one) the refusal codes distinguish
    absent names from present-but-scoped names -- an unauthenticated
    existence oracle, beyond the documented deliberate post-auth
    residual.
    """
    _iss, reg = _world()
    none_ghost = _code_of(lambda: reg.invoke(None, "ghost_tool",
                                             lambda: 1))
    none_real = _code_of(lambda: reg.invoke(None, "read_file",
                                            lambda: 1))
    forged_ghost = _code_of(lambda: reg.invoke("AAAA.BBBB", "ghost_tool",
                                               lambda: 1))
    forged_real = _code_of(lambda: reg.invoke("AAAA.BBBB", "read_file",
                                              lambda: 1))
    oracle = (none_ghost != none_real) or (forged_ghost != forged_real)
    detail = ("none: ghost=%s real=%s; forged: ghost=%s real=%s"
              % (none_ghost, none_real, forged_ghost, forged_real))
    if oracle:
        return _break("pre-auth existence oracle: " + detail)
    return _held("no pre-auth oracle: " + detail)


@probe("scopelist/post-auth-distinguishability-residual")
def _p_post_auth_residual():
    """Control: the deliberate post-auth residual is preserved.

    With a VALID ticket the lane deliberately distinguishes
    not-registered (typo'd name) from denied (out of scope). This
    probe pins the residual boundary: distinguishability exists
    ONLY post-auth.
    """
    iss, reg = _world()
    low = iss.seal("agent-sub", set(), 1000.0)
    ghost = _code_of(lambda: reg.invoke(low, "ghost_tool", lambda: 1))
    scoped = _code_of(lambda: reg.invoke(low, "read_file", lambda: 1))
    if ghost == "scope-listing-not-registered" and\
            scoped == "scope-listing-denied":
        return _held("post-auth: not-registered vs denied (deliberate)")
    return ("ERROR", "post-auth codes changed: %s / %s" % (ghost, scoped))


@probe("scopelist/tampered-ticket-refused")
def _p_ticket_tamper():
    """Control: tampered scope tickets refuse machine-coded."""
    iss, reg = _world()
    good = iss.seal("agent-sub", {"files:read"}, 1000.0)
    body, mac = good.split(".")
    bad = body[:-2] + ("AA" if not body.endswith("AA") else "BB") +\
        "." + mac
    code = _code_of(lambda: reg.invoke(bad, "read_file", lambda: 1))
    if code != "scope-grant-tampered":
        return ("ERROR", "tampered ticket gave %s" % code)
    # universe shrink after issuance refuses at every use: the ticket
    # below carries net:fetch, which left iss2's universe
    good2 = iss.seal("agent-sub", {"net:fetch"}, 1000.0)
    iss2 = stl.ScopeTicketIssuer(_SCOPE_KEY, {"files:read"})
    code2 = _code_of(lambda: iss2.verify(good2))
    if code2 != "scope-listing-unknown-scope":
        return ("ERROR", "post-issuance universe shrink gave %s" % code2)
    return _held("tamper -> scope-grant-tampered; universe re-checked")


@probe("scopelist/consent-replay-across-tools-refused")
def _p_consent_replay():
    """Control: consent tokens do not replay across tools/approvals."""
    _iss, _reg = _world()
    ci = stl.ConsentIssuer(_SCOPE_KEY, ttl_seconds=300)
    audit = []
    url = ci.mint_consent_url("appr-1", "fetch_url", {"net:fetch"},
                             "human-sub", 1000.0, "https://consent.local/c")
    token = url.split("ct=", 1)[1]
    cross_tool = _code_of(lambda: ci.confirm_consent(
        token, "appr-1", "read_file", "human-sub", 1100.0, audit.append))
    cross_appr = _code_of(lambda: ci.confirm_consent(
        token, "appr-9", "fetch_url", "human-sub", 1100.0, audit.append))
    cross_sub = _code_of(lambda: ci.confirm_consent(
        token, "appr-1", "fetch_url", "mallory", 1100.0, audit.append))
    expired = _code_of(lambda: ci.confirm_consent(
        token, "appr-1", "fetch_url", "human-sub", 9999.0, audit.append))
    ok = ci.confirm_consent(token, "appr-1", "fetch_url", "human-sub",
                            1100.0, audit.append)
    if (cross_tool, cross_appr, cross_sub, expired) != (
            "scope-consent-unbound", "scope-consent-unbound",
            "scope-consent-unbound", "scope-consent-expired"):
        return ("ERROR", "consent binding codes changed: %r"
                % ((cross_tool, cross_appr, cross_sub, expired),))
    if not ok or len(audit) != 1 or token in repr(audit[0]):
        return ("ERROR", "genuine consent mishandled")
    return _held("cross-tool/approval/subject refused unbound; "
                 "expired refused; genuine audits by digest only")


@probe("scopelist/listing-silence-control")
def _p_listing_silence():
    """Control: the listing seam itself stays silent."""
    iss, reg = _world()
    low = iss.seal("agent-sub", {"files:read"}, 1000.0)
    blob = repr(reg.list_tools(low))
    for secret in ("admin_reindex", "fetch_url", "files:read-admin",
                   "net:fetch", "db:query"):
        if secret in blob:
            return ("ERROR", "listing leaked %r" % secret)
    return _held("listing silent on unpermitted tools")


# ------------------------------------------------------------ ceremony

def _members(n):
    out = []
    seeds = []
    for i in range(n):
        seed = ed25519.generate_seed()
        seeds.append(seed)
        out.append(bg.Member("kh%d" % i, ed25519.publickey(seed),
                            role="keyholder"))
    return out, seeds


def _gov(n=3):
    members, seeds = _members(n)
    path = os.path.join(tempfile.mkdtemp(prefix="w263-ceremony-"),
                        "journal.jsonl")
    return rc.CeremonyGovernor(members, path), seeds


@probe("ceremony/is-ceremonial-classifier-audit")
def _p_classifier():
    """HELD: no root-touching op classifies routine (27 cases)."""
    routine = {"sign-daily": False, "resign-expiry": False,
               "expiry-resign": False, "attest-artifact": False,
               "timestamp-token": False, "log-checkpoint": False,
               "SIGN-DAILY": False, "  sign-daily  ": False}
    ceremonial = {"root-key-generate": True, "root-key-rotate": True,
                  "trust-root-pin-change": True, "root-key-recover": True,
                  "keyholder-add": True, "keyholder-remove": True,
                  "threshold-change": True, "ROOT-KEY-ROTATE": True,
                  "root-sign-daily": True, "sign-daily-root": True,
                  "rotate root key": True, "master-key-rollover": True,
                  "threshold_change": True, "keyholderadd": True,
                  "": True, None: True, 123: True, "mystery-op": True,
                  "daily-sign": True}
    bad = []
    for action, want in list(routine.items()) + list(ceremonial.items()):
        if rc.is_ceremonial(action) != want:
            bad.append((action, want))
    if bad:
        return _break("classifier mismatches: %r" % (bad,))
    # routine_sign enforces the same boundary operationally
    try:
        rc.routine_sign("root-key-rotate", {"x": 1}, os.urandom(32))
        return _break("routine_sign accepted a root-key action")
    except rc.CeremonyRoutinePathRefused:
        pass
    rc.routine_sign("sign-daily", {"x": 1}, os.urandom(32))
    return _held("27/27 classify correctly; routine path refuses root")


def _drive_to_rehearsed(gov, seeds, cid, fp):
    digest = gov.ceremony_digest(cid)
    for i in (0, 1):
        env = rc.review_envelope(cid, "kh%d" % i, digest)
        gov.record_review(cid, "kh%d" % i,
                         {"ceremony_digest": digest,
                          "signature": ed25519.sign(seeds[i], env)})
    rec = rc.make_rehearsal_record(cid, fp, "scratch/r1",
                                   [{"name": "verifies", "passed": True}])
    gov.record_rehearsal(cid, rec)
    return gov.open_execution(cid)


@probe("ceremony/execute-phase-bool-composition")
def _p_execute_bool():
    """HELD: F237's hook-coercion pattern cannot reach the execute
    ballot -- BallotBox.vote() enforces bool at the mouth."""
    gov, seeds = _gov(3)
    fp = "ab" * 32
    cid = gov.propose("rotation", "rotate root", fp, "kh0", threshold=2,
                      review_quorum=2, ceremony_id="crm-w263-bool")
    info = _drive_to_rehearsed(gov, seeds, cid, fp)
    bid, pdg = info["ballot_id"], info["payload_digest"]
    for bad_decision in (1, "yes", None):
        env = bg.vote_envelope(bid, "kh0", True, pdg)
        try:
            gov.sign_execution(cid, "kh0", bad_decision,
                              ed25519.sign(seeds[0], env))
            return _break("non-bool decision %r accepted at execute"
                          % (bad_decision,))
        except bg.BallotMalformedProposal:
            pass
        except Exception as e:  # noqa: BLE001
            return ("ERROR", "unexpected %s for %r"
                    % (type(e).__name__, bad_decision))
    for i, decision in ((0, True), (1, True)):
        env = bg.vote_envelope(bid, "kh%d" % i, decision, pdg)
        gov.sign_execution(cid, "kh%d" % i, decision,
                          ed25519.sign(seeds[i], env))
    out = gov.resolve_execution(cid)
    if out["status"] != "adopted":
        return ("ERROR", "threshold of bools did not adopt")
    return _held("non-bool refused at vote() mouth; bools adopt")


@probe("ceremony/extra-fields-outside-digest")
def _p_extra_digest():
    """BASELINE: extra proposal fields ride outside the ceremony
    digest. They are journal-only metadata (extra_keys); no decision
    reads them and no contract claims digest coverage -- accepted
    pre-existing behavior, not a new finding."""
    gov, _seeds = _gov(3)
    fp = "ab" * 32
    cid = gov.propose("rotation", "rotate root", fp, "kh0", threshold=2,
                      review_quorum=2, ceremony_id="crm-w263-extra",
                      some_extra="unreviewed-value")
    import hashlib
    import json as _json
    core = {"ceremony_id": cid, "event_type": "rotation",
            "change_description": "rotate root",
            "new_key_fingerprint": fp, "old_root_fingerprint": None,
            "proposer": "kh0", "threshold": 2, "review_quorum": 2}
    recomputed = hashlib.sha256(
        _json.dumps(core, sort_keys=True, separators=(",", ":"))
        .encode("utf-8")).hexdigest()
    if gov.ceremony_digest(cid) != recomputed:
        return ("ERROR", "digest covers more than the core fields?")
    return _baseline("extra fields excluded from digest; journal-only "
                     "metadata (extra_keys); no decision reads extra")


@probe("ceremony/rehearsal-namespace-dotdot")
def _p_ns_dotdot():
    """BASELINE: "scratch/../prod" passes the namespace prefix check.
    The check is documented as a syntactic "looks like"
    scratch/staging heuristic; the deployment runs the rehearsal
    (deployment trust) -- accepted pre-existing behavior."""
    gov, seeds = _gov(3)
    fp = "ab" * 32
    cid = gov.propose("rotation", "rotate root", fp, "kh0", threshold=2,
                      review_quorum=2, ceremony_id="crm-w263-ns")
    digest = gov.ceremony_digest(cid)
    for i in (0, 1):
        env = rc.review_envelope(cid, "kh%d" % i, digest)
        gov.record_review(cid, "kh%d" % i,
                         {"ceremony_digest": digest,
                          "signature": ed25519.sign(seeds[i], env)})
    rec = rc.make_rehearsal_record(cid, fp, "scratch/../prod",
                                   [{"name": "verifies", "passed": True}])
    try:
        gov.record_rehearsal(cid, rec)
    except rc.CeremonyRehearsalForged:
        return _held("dotdot namespace refused")
    return _baseline('"scratch/../prod" passes the prefix check '
                     "(documented syntactic heuristic; deployment runs "
                     "the rehearsal)")


# ------------------------------------------------------------ detectors

def _det_base(name="w263-det", **kw):
    d = {"name": name, "version": "1.0.0",
         "description": "w263 probe detector",
         "event_selector": {"type": "probe_event"},
         "predicates": [{"field": "flag", "op": "eq", "value": True}],
         "produces": {"event_name": name + "_fired",
                      "event_schema_version": "1.0.0", "fields": {}},
         "subscribes": [],
         "threat": {"severity": "low", "description": "probe"}}
    d.update(kw)
    return d


def _exc_block(**kw):
    b = {"name": "allow-ci", "description": "probe exception",
         "fields": ["host"], "comps": ["startswith"],
         "values": [["ci.internal.example"]]}
    b.update(kw)
    return b


@probe("detectors/policy-values-override-invisible-in-record")
def _p_override_invisible():
    """F243: a deployment-policy values override that widens an
    exception is invisible in the alert record -- the "never silent"
    promise covers disable (disabled_but_matched) but not override,
    so the rule is silently re-armed."""
    eng = det.DetectorEngine()
    eng.register(_det_base(priority="notice",
                           exceptions=[_exc_block()]))
    # startswith + [""] matches every string host: total re-arm.
    sink = det.AlertSink(
        eng, policy={"exceptions":
                     {"w263-det": {"allow-ci": {"values": [[""]]}}}})
    sink.process({"type": "probe_event", "flag": True,
                  "host": "attacker.example"})
    rec = sink.journal_entries()[-1]
    if rec["record_type"] != "suppressed":
        return ("ERROR", "widening override did not suppress: %r"
                % rec["record_type"])
    exc = rec["exception_decision"]
    visible = any(k in exc for k in ("effective_values", "effective_block",
                                    "policy", "policy_digest",
                                    "override"))
    if visible:
        return _held("override visible in record: %r"
                     % sorted(exc.keys()))
    return _break(
        "widening policy override produced a 'suppressed' record with "
        "no trace of the effective values: keys=%r -- an auditor "
        "holding the registered definition cannot attribute the "
        "suppression to the policy" % sorted(exc.keys()))


@probe("detectors/detectors-accessor-runtime-mutation")
def _p_deep_copy_accessor():
    """F244 (CLOSED wave-264): DetectorEngine.detectors must return
    deep copies -- runtime mutation of the returned structure must
    not change engine/sink behavior. HELD when the accessor is
    fix-verified; BREAK if the live definition leaks through again
    (regression pin for the closure)."""
    eng = det.DetectorEngine()
    eng.register(_det_base(name="w263-mut", priority="critical"))
    sink = det.AlertSink(eng)
    if not sink.may_gate_enforcement("w263-mut"):
        return ("ERROR", "stable detector cannot gate?")
    eng.detectors["w263-mut"]["maturity"] = "experimental"
    if not sink.may_gate_enforcement("w263-mut"):
        # DEFECT (pre-fix): the flip reached the live definition.
        sink.process({"type": "probe_event", "flag": True})
        rec = sink.journal_entries()[-1]
        if rec["record_type"] != "observation":
            return ("ERROR", "expected observation, got %r"
                    % rec["record_type"])
        return _break(
            "runtime maturity flip via detectors[...] flipped gating "
            "True->False and turned an alert into an observation: "
            "the accessor leaks the live definition (F244 regressed)")
    # FIXED: the flip hit a copy; the sink still gates and alerts.
    sink.process({"type": "probe_event", "flag": True})
    rec = sink.journal_entries()[-1]
    if rec["record_type"] != "alert":
        return _break(
            "maturity mutation reached the live definition by another "
            "path: match produced %r instead of alert (F244 regressed)"
            % rec["record_type"])
    # exceptions rewritten at runtime must have no effect either.
    eng2 = det.DetectorEngine()
    eng2.register(_det_base(name="w263-mut2", priority="notice",
                            exceptions=[_exc_block()]))
    sink2 = det.AlertSink(eng2)
    eng2.detectors["w263-mut2"]["exceptions"] = [
        {"name": "allow-ci", "fields": ["host"], "comps": ["startswith"],
         "values": [[""]]}]
    sink2.process({"type": "probe_event", "flag": True,
                   "host": "attacker.example"})
    rec2 = sink2.journal_entries()[-1]
    if rec2["record_type"] == "suppressed":
        return _break(
            "runtime exception rewrite via detectors[...] suppressed "
            "the alert with no validation and no journal (F244 "
            "regressed)")
    if rec2["record_type"] != "alert":
        return ("ERROR", "expected alert, got %r" % rec2["record_type"])
    return _held("F244 closed: DetectorEngine.detectors returns deep "
                 "copies -- runtime maturity flip and exception "
                 "rewrite via the accessor have no effect; sink still "
                 "gates and alerts")


@probe("detectors/disabled-exception-journaled-control")
def _p_disabled_journaled():
    """Control (HELD): disabling an exception fails closed to alert
    and the re-arming is journaled in disabled_but_matched."""
    eng = det.DetectorEngine()
    eng.register(_det_base(name="w263-dis", priority="notice",
                           exceptions=[_exc_block()]))
    sink = det.AlertSink(
        eng, policy={"exceptions":
                     {"w263-dis": {"allow-ci": {"enabled": False}}}})
    sink.process({"type": "probe_event", "flag": True,
                  "host": "ci.internal.example"})
    rec = sink.journal_entries()[-1]
    if rec["record_type"] != "alert":
        return ("ERROR", "disabled exception suppressed: %r"
                % rec["record_type"])
    dbm = rec["exception_decision"].get("disabled_but_matched")
    if dbm != ["allow-ci"]:
        return ("ERROR", "disabled_but_matched wrong: %r" % (dbm,))
    return _held("disable fails closed to alert; re-arming journaled")


# ------------------------------------------------------------------ F235
# residual

@probe("poldist/publisher-sign-bundle-recursionerror")
def _p_publisher_recursion():
    """BASELINE: Publisher.sign_bundle raises raw RecursionError on a
    recursion-hostile payload instead of PublisherError.

    The "never raises on hostile input" contract belongs to
    Subscriber.apply (the refusing seam facing unauthenticated bytes;
    F235 closed it). The publisher is the module's documented trusted
    operator surface ("not the refusing seam"): its inputs are the
    operator's own policy content, and an operator who feeds it a
    20000-deep payload crashes only their own signing call. No
    attacker-reachable boundary is crossed. Recorded as BASELINE with
    a falsifiable close-when for a future lane: catch RecursionError
    alongside (TypeError, ValueError) in sign_bundle's
    canonicalization try, refusing PublisherError; the probe then
    HELDs (PublisherError) instead of raising raw."""
    pub = poldist.Publisher(os.urandom(32))
    deep = "x"
    for _ in range(20000):
        deep = [deep]
    try:
        pub.sign_bundle("policies/app", 1, deep)
    except poldist.PublisherError:
        return _held("PublisherError on recursion-hostile payload")
    except RecursionError:
        return _baseline(
            "raw RecursionError escapes sign_bundle -- trusted operator "
            "surface (module-documented, F235 explicitly out of scope); "
            "Subscriber.apply's never-raises contract holds")
    return ("ERROR", "recursion-hostile payload signed?!")


# ------------------------------------------------------- F237/F238/F239
# cross-checks (dedicated lanes own them -- NOT re-filed)

def _xcheck(name, want_repro):
    import w262_redteam_probes as w262
    fns = dict(w262._PROBES)
    fn = fns[name]
    try:
        verdict, detail = fn()
    except Exception as e:  # noqa: BLE001 -- harness
        return ("ERROR", "%s: %s" % (type(e).__name__, str(e)[:100]))
    if verdict == "BREAK":
        return _baseline(
            "%s still reproduces on base -- finding remains OPEN "
            "(dedicated lane owns it; not re-filed): %s" % (name, detail))
    if verdict == "HELD":
        return _held("%s now HELD -- dedicated lane may have closed it; "
                     "flag to merge" % name)
    return (verdict, detail)


@probe("xcheck/f237-resolve-drops-nonbool-hook-returns")
def _x_f237():
    """Cross-check only: F237 (ballot resolve hook coercion)."""
    v1 = _xcheck("ballot/resolve-drops-nonbool-hook-returns-veto-evaded",
                 True)
    v2 = _xcheck("ballot/resolve-drops-nonbool-hook-returns-yes-lost",
                 True)
    if v1[0] == "BASELINE" and v2[0] == "BASELINE":
        return _baseline("F237 still reproduces (veto-evaded + "
                         "yes-lost); remains OPEN, dedicated lane owns")
    return (v1[0], "F237 cross-check: %s / %s" % (v1[1], v2[1]))


@probe("xcheck/f238-filter-dict-key-not-swept")
def _x_f238():
    """Cross-check only: F238 (filter sweep misses dict keys)."""
    return _xcheck("failaction/filter-offending-bytes-as-dict-key-not-swept",
                   True)


@probe("xcheck/f239-stamp-exfiltrated-via-from-field")
def _x_f239():
    """Cross-check only: F239 (engine stamp exfiltrated via field)."""
    return _xcheck("detectors/stamp-exfiltrated-via-from-field", True)


# ------------------------------------------------------------ green check

def _green_check():
    """Depth-1: run adjacent batteries' mains with GOV_SKIP_GREEN=1 in
    the child env (no combinatorial nesting). Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "skipped (GOV_SKIP_GREEN=1)")]
    here = os.path.dirname(os.path.abspath(__file__))
    adjacent = ["w262_scopelist_probes.py", "w262_ceremony_probes.py",
                "w262_alert_probes.py", "w262_poldist2_probes.py"]
    notes = []
    for battery in adjacent:
        path = os.path.join(here, battery)
        if not os.path.exists(path):
            notes.append((battery, "absent -- skipped"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tempfile.mkdtemp(prefix="w263-green-")
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
