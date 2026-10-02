"""Break-first red-team probes against the wave-263 product code (wave-264).

Targets: gov/recipient_plugins.py (plugin confusion, transplant,
identity binding), gov/mesh_auth.py (scheme enforcement, task
escalation state machine, oidc refusal), gov/provenance_policy.py
(VSA delegation, vacuous policy, hostile input shapes),
Publisher.sign_bundle (deep-nesting RecursionError candidate from the
wave-262 merge report), and the F240-F244 red baseline (closure lanes
own those fixes -- probed here as BASELINE, never re-filed).

Red-first: every probe is written to BREAK on the vulnerable shape and
HELD on the fixed shape, deterministic in both deployment modes
(staging default below; prod via `env -u GOV_DEPLOYMENT_MODE`).

Stdlib only. No network, no in-repo git subprocesses. Green check is
depth-1 and honors GOV_SKIP_GREEN=1.
"""

import hashlib
import inspect
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

# Wave-263 merge: pin -> 1151 (+7 recipient-plugin-*, +8 mesh-auth-*,
# +7 provenance-*).
TAXONOMY_PIN = 1750  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*)

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

try:
    import gov.decision_codes as decision_codes
    from gov import encrypted_envelopes as ee
    from gov import recipient_plugins as rp
    from gov import mesh_auth as ma
    from gov import provenance_policy as pp
    from gov import policy_distribution as poldist
    from gov import svid_issuer as sv
    from gov import scoped_tool_listing as stl
    from gov import short_lived_credentials as slc
    from gov import detectors as det
    _IMPORT_ERROR = None
except ImportError as e:  # noqa: BLE001
    decision_codes = ee = rp = ma = pp = poldist = None
    sv = stl = slc = det = None
    _IMPORT_ERROR = e


def _need_modules():
    if _IMPORT_ERROR is not None:
        return False, "GAP: wave-263 modules unavailable (%s)" % _IMPORT_ERROR
    return True, ""


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


# ---------------------------------------------------------------------------
# Shared worlds
# ---------------------------------------------------------------------------

_MESH_UNIVERSE = frozenset({"files:read", "net:fetch"})
_MESH_TICKET_KEY = b"w264-ticket-key-32-bytes-padded-0"
_MESH_CRED_KEY = b"w264-cred-key-32-bytes-padded-00"
_MESH_ISSUER_SEED = bytes(range(32))
_NOW = 4000000000.0
_SPIFFE_A = "spiffe://example.org/agent-a"


def _mesh_world():
    issuer = sv.TestSvidIssuer(issuer_seed=_MESH_ISSUER_SEED,
                               key_id="w264-issuer-1")
    verifier = sv.SvidVerifier(
        {"w264-issuer-1": issuer.issuer_public_key}, "example.org")
    control = sv.MeshControl(verifier,
                             {"allow": ["spiffe://example.org/agent-a"]})
    tickets = stl.ScopeTicketIssuer(_MESH_TICKET_KEY, _MESH_UNIVERSE)
    creds = slc.CredentialIssuer(
        os.path.join(tempfile.mkdtemp(prefix="w264-creds-"), "j.jsonl"),
        key=_MESH_CRED_KEY)
    gate = ma.MeshCallGate(svid_control=control,
                           ticket_issuer=tickets,
                           credential_issuer=creds)
    return issuer, gate, tickets


def _vsa_world():
    stmt_seed = bytes([5]) * 32
    stmt_pub = pp.ed25519_publickey(stmt_seed)
    vsa_issuer = pp.VSAIssuer("v1", bytes([9]) * 32)
    pol = pp.ProvenancePolicy.from_dict({
        "name": "P", "version": 1,
        "sources": {"allowed": ["s"]},
        "builders": {"allowed": ["b"]},
        "statement_signers": {"s1": stmt_pub.hex()},
        "trusted_verifiers": {"v1": vsa_issuer.public_key_hex}})
    vsa = vsa_issuer.issue("d" * 64, "P", "SLSA_BUILD_LEVEL_3",
                           1000.0, 3600)
    return pol, vsa


def _vault(**kw):
    d = tempfile.mkdtemp(prefix="w264-rp-")
    return ee.EnvelopeVault(os.path.join(d, "j.jsonl"), **kw)


# ---------------------------------------------------------------------------
# F245: provenance_policy hostile input shapes escape as raw exceptions
# (the module promises machine-coded refusals on ANY failure).
# ---------------------------------------------------------------------------

@probe("provenance/unhashable-key-id-raw")
def _p_unhashable_key_id():
    """verify_statement promises provenance-statement-unverified on ANY
    failure (malformed statement included). A signature entry whose
    key_id is unhashable (dict) escapes as a raw TypeError from
    signers.get(key_id) instead."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    stmt = {"format": pp.STATEMENT_FORMAT,
            "subject": {"digest": {"sha256": "a" * 64}},
            "predicate": {"source": {"uri": "x"},
                          "builder": {"id": "b"}},
            "signatures": [{"key_id": {"not": "hashable"},
                            "sig": "ab" * 32}]}
    try:
        pp.verify_statement(stmt, {"k": "b" * 64})
    except pp.ProvenancePolicyError as e:
        return _held("machine-coded refusal: %s" % e.code)
    except Exception as e:  # noqa: BLE001 -- the break under test
        return _break("raw %s escapes verify_statement on unhashable "
                      "key_id (want provenance-statement-unverified)"
                      % type(e).__name__)
    return ("ERROR", "hostile statement verified?!")


@probe("provenance/vsa-nondict-verifier-raw")
def _p_vsa_nondict_verifier():
    """admit_vsa does `verifier.get("id")` on the VSA's verifier field
    with no type check: a truthy non-dict verifier escapes as a raw
    AttributeError instead of provenance-vsa-refused."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    pol, vsa = _vsa_world()
    import copy
    evil = copy.deepcopy(vsa)
    evil["verifier"] = "attacker-string"
    try:
        pol.admit_vsa(evil, "P", "d" * 64, now=2000.0)
    except pp.ProvenancePolicyError as e:
        return _held("machine-coded refusal: %s" % e.code)
    except Exception as e:  # noqa: BLE001 -- the break under test
        return _break("raw %s escapes admit_vsa on non-dict verifier "
                      "(want provenance-vsa-refused)"
                      % type(e).__name__)
    return ("ERROR", "hostile VSA admitted?!")


@probe("provenance/vsa-hostile-now-raw")
def _p_vsa_hostile_now():
    """admit_vsa accepts `now` but never validates it (no F228-shaped
    _validate_now, unlike gov/mesh_auth.py). A non-numeric now reaches
    `issued_at <= now` and escapes as a raw TypeError instead of a
    machine-coded refusal."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    pol, vsa = _vsa_world()
    try:
        pol.admit_vsa(vsa, "P", "d" * 64, now="garbage")
    except pp.ProvenancePolicyError as e:
        return _held("machine-coded refusal: %s" % e.code)
    except Exception as e:  # noqa: BLE001 -- the break under test
        return _break("raw %s escapes admit_vsa on non-numeric now "
                      "(want machine-coded; mesh_auth validates now, "
                      "provenance does not)" % type(e).__name__)
    return ("ERROR", "hostile now admitted?!")


# ---------------------------------------------------------------------------
# F246: MeshTaskAuth.call has no subject parameter -- the task path
# silently drops the scope-ticket subject binding resume() supports.
# ---------------------------------------------------------------------------

@probe("meshauth/task-call-drops-subject-binding")
def _p_task_call_no_subject():
    """resume() accepts subject= (the paired SVID identity for
    subject-bound schemes -- the scope-ticket case), but call() has no
    subject parameter at all: after a subject-bound resume, every
    subsequent task call evaluates scope tickets as Bearer <redacted>,
    and a deployment CANNOT opt into binding on the task path."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    call_params = set(inspect.signature(ma.MeshTaskAuth.call).parameters)
    resume_params = set(inspect.signature(ma.MeshTaskAuth.resume).parameters)
    if "subject" in call_params:
        return _held("MeshTaskAuth.call accepts subject=")
    if "subject" not in resume_params:
        return ("ERROR", "resume lost its subject param?!")
    return _break(
        "MeshTaskAuth.call%s has no subject param while resume%s does: "
        "the task path cannot honor the module's own subject-binding "
        "composition (Bearer <redacted> only, silently)" % (
            sorted(call_params), sorted(resume_params)))


# ---------------------------------------------------------------------------
# F247: MeshTaskAuth.escalate/abandon need no authentication -- any
# holder of a task_id can pause or terminally abandon another's task.
# ---------------------------------------------------------------------------

@probe("meshauth/unauthenticated-task-transitions")
def _p_unauthenticated_transitions():
    """The task state machine has no caller-auth concept: escalate()
    and abandon() take only (task_id, ...) and mutate state. An
    unauthenticated party holding a task_id pauses the task
    (escalate) or kills it terminally (abandon)."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    _issuer, gate, _tickets = _mesh_world()
    tasks = ma.MeshTaskAuth(gate)
    try:
        # Fixed code (F247): begin records the task owner.
        tasks.begin("victim-task", owner=_SPIFFE_A)
    except TypeError:
        # Old code: no owner concept; begin takes only task_id.
        tasks.begin("victim-task")
    # "Attacker": no credential, no envelope, just the task_id.
    try:
        tasks.escalate("victim-task", "svid", "attacker says so",
                       now=_NOW)
    except ma.MeshAuthError as e:
        if e.code == "mesh-auth-not-owner":
            refused = True
        else:
            return _break("wrong code %s (want mesh-auth-not-owner)"
                          % e.code)
    else:
        refused = False
    paused = tasks.state("victim-task") == ma.TASK_STATE_AUTH_REQUIRED
    tasks2 = ma.MeshTaskAuth(gate)
    try:
        tasks2.begin("victim-task-2", owner=_SPIFFE_A)
    except TypeError:
        tasks2.begin("victim-task-2")
    try:
        tasks2.abandon("victim-task-2")
    except ma.MeshAuthError as e:
        if e.code == "mesh-auth-not-owner":
            refused2 = True
        else:
            return _break("wrong code %s (want mesh-auth-not-owner)"
                          % e.code)
    else:
        refused2 = False
    killed = tasks2.state("victim-task-2") == ma.TASK_STATE_ABANDONED
    if paused and killed:
        return _break(
            "unauthenticated escalate() paused a task and "
            "unauthenticated abandon() terminally killed another: "
            "task state transitions need no credential")
    if refused and refused2:
        return _held("unauthenticated transitions refused: "
                     "mesh-auth-not-owner")
    return ("ERROR", "transitions did not take effect?!")


# ---------------------------------------------------------------------------
# Cross-module: F241 propagates through the mesh_auth composition.
# (Root defect is F241 -- not re-filed; probed as inherited break.)
# ---------------------------------------------------------------------------

@probe("meshauth/consent-token-as-scope-ticket")
def _p_consent_via_mesh():
    """A consent token minted for a human approval URL (out-of-band by
    design) authorizes as a mesh-auth scope-ticket credential, because
    MeshCallGate._verify_credential delegates to
    ScopeTicketIssuer.verify -- which inherits F241's missing domain
    separation. Root cause is F241; this probe pins the propagation."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    _issuer, gate, _tickets = _mesh_world()
    consent = stl.ConsentIssuer(_MESH_TICKET_KEY)
    sub = hashlib.sha256(b"human-sub").hexdigest()
    url = consent.mint_consent_url("appr-1", "fetch_url", {"net:fetch"},
                                   sub, _NOW, "https://approve.local/c")
    token = url.split("?ct=")[1]
    card = ma.MeshAuthCard("agent-b", ["scope-ticket"],
                           endpoints={"rpc": "https://b/rpc"},
                           capabilities=["fetch_url"])
    try:
        rec = gate.authorize_call(
            card, {"scheme": "scope-ticket", "credential": token},
            required_scopes={"net:fetch"}, now=_NOW + 100)
    except ma.MeshAuthError as e:
        return _held("mesh gate refuses consent token: %s" % e.code)
    except stl.ScopedListingError as e:
        # Wave-264 merge: F241 closed -- the consent token now refuses
        # scope-grant-tampered at the issuer seam before the mesh gate
        # can wrap it. Fix confirmed at the mesh composition point.
        return _held("mesh composition refuses consent token at the "
                     "issuer seam: %s" % e.code)
    return _break(
        "consent token AUTHORIZED as mesh scope-ticket "
        "(subject=%s scopes=%s): F241's missing domain separation "
        "propagates through the mesh composition"
        % (rec["subject"], rec["scopes"]))


# ---------------------------------------------------------------------------
# Publisher.sign_bundle deep nesting: VERIFIED raw RecursionError, but the
# wave-263 red-team classified it BASELINE (trusted operator surface;
# F235 explicitly scoped the never-raises contract to Subscriber.apply).
# This probe re-verifies the mechanism and the classification.
# ---------------------------------------------------------------------------

@probe("poldist/sign-bundle-deep-nesting")
def _p_sign_bundle_recursion():
    """sign_bundle's try/except catches (TypeError, ValueError) around
    canonical_payload, but json.dumps raises RecursionError (a
    RuntimeError) past ~20k nesting: the raw exception escapes instead
    of PublisherError. Verified real -- but the publisher is an
    operator-invoked surface (no product caller feeds it
    attacker-influenced payloads), the escape is fail-closed, and no
    _last_version state is corrupted (the raise precedes the write).
    BASELINE per the w263 red-team classification; re-file only if the
    surface becomes attacker-reachable."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    pub = poldist.Publisher(bytes(range(32)))
    deep = cur = []
    for _ in range(25000):
        nxt = []
        cur.append(nxt)
        cur = nxt
    try:
        pub.sign_bundle("test.topic", 1, deep)
    except poldist.PublisherError as e:
        return _held("machine-coded refusal: %s" % str(e)[:60])
    except RecursionError:
        return _baseline(
            "raw RecursionError escapes sign_bundle (verified) -- "
            "trusted operator surface, fail-closed, no state "
            "corruption; not attacker-reachable")
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "unexpected %s" % type(e).__name__)
    return ("ERROR", "25k-deep payload signed?!")


# ---------------------------------------------------------------------------
# Recipient-plugin controls (all expected HELD -- regression pins).
# ---------------------------------------------------------------------------

@probe("recipients/evil-plugin-name-claim")
def _p_evil_name_claim():
    """A malicious RecipientPlugin INSTANCE claiming a registered NAME
    must never have its wrap() invoked: _resolve_plugin looks the
    instance's NAME up in the registry and uses the REGISTERED
    plugin."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)

    class EvilPlugin(rp.RecipientPlugin):
        NAME = "symmetric-hmac/v1"
        LABEL_NAMESPACE = "gov1evil"

        def wrap(self, envelope_key, label, identity):
            return [("gov1evil1x", b"E" * 48)]

        def unwrap(self, entries, identity):
            return [(entries[0][0], b"\x00" * 32)]

    v = _vault()
    pr = rp.PluginRecipient("gov1sym1alice", EvilPlugin(),
                            {"key_material": b"alice-key-material-32bytes!!!"})
    try:
        env = v.seal_plugin(b"secret", [pr])
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "seal raised %s: %s"
                % (type(e).__name__, str(e)[:80]))
    try:
        payload, _meta = v.open_plugin(
            env, {"gov1sym1alice":
                  {"key_material": b"alice-key-material-32bytes!!!"}})
    except Exception as e:  # noqa: BLE001
        return _break("evil instance's wrap ran (envelope does not open "
                      "with the legit key): %s" % type(e).__name__)
    if payload == b"secret":
        return _held("registered plugin served the claimed name; the "
                     "evil instance's wrap never ran")
    return ("ERROR", "opened to wrong payload?!")


@probe("recipients/wrap-transplant-across-labels")
def _p_wrap_transplant():
    """A symmetric wrap transplanted under a different label of the
    same namespace must not open: the KDF binds the label and the tag
    is the single authenticity decision."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    v = _vault()
    alice_km = b"alice-key-material-32bytes!!!"
    env = v.seal_plugin(b"secret", [rp.PluginRecipient(
        "gov1sym1alice", "symmetric-hmac/v1",
        {"key_material": alice_km})])
    try:
        payload, _meta = v.open_plugin(
            env, {"gov1sym1alice": {"key_material": b"bob-key-material-32bytes!!!!!"}})
    except ee.EnvelopeRefusal as e:
        return _held("relabeled/wrong-key open refused: %s" % e.code)
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "unexpected %s" % type(e).__name__)
    return _break("envelope opened with the wrong key: %r" % payload[:8])


@probe("recipients/cross-namespace-transplant")
def _p_cross_namespace():
    """Symmetric wrap bytes transplanted under a quorum-namespaced
    label route to the quorum plugin; the share parse + tag must still
    refuse (no cross-plugin wrap confusion)."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    import struct as _struct
    v = _vault()
    env = v.seal_plugin(b"secret", [rp.PluginRecipient(
        "gov1sym1alice", "symmetric-hmac/v1",
        {"key_material": b"alice-key-material-32bytes!!!"})])
    parsed = ee._parse(env)
    rid, wrap = parsed.recipients[0]
    qid = b"gov1quorum1" + b"0" * 16 + b"1" + b"alice"
    old = _struct.pack(">H", len(rid)) + rid
    new = _struct.pack(">H", len(qid)) + qid
    forged = parsed.header.replace(old, new) + parsed.ct + parsed.tag
    try:
        v.open_plugin(forged, {qid.decode():
                               {"shares": {"alice":
                                           b"alice-key-material-32bytes!!!"}}})
    except ee.EnvelopeRefusal as e:
        return _held("cross-namespace transplant refused: %s" % e.code)
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "unexpected %s: %s"
                % (type(e).__name__, str(e)[:60]))
    return _break("cross-namespace transplant OPENED")


@probe("recipients/quorum-share-id-with-ones")
def _p_quorum_ones():
    """Share ids containing '1' (the label separator char) must
    round-trip the fixed-width group parse unambiguously."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    v = _vault()
    shares = {"a1b1": b"s1-key-material-32-bytes!!!!"[:32],
              "11": b"s2-key-material-32-bytes!!!!"[:32],
              "x": b"s3-key-material-32-bytes!!!!"[:32]}
    env = v.seal_plugin(b"secret", [rp.PluginRecipient(
        "quorum-group", "quorum-shamir/v1",
        {"shares": shares, "quorum": 2})])
    labels = [r.decode() for r, _w in ee._parse(env).recipients]
    try:
        payload, _meta = v.open_plugin(
            env, {label: {"shares": shares} for label in labels})
    except Exception as e:  # noqa: BLE001
        return _break("quorum open failed on '1'-heavy share ids: %s"
                      % type(e).__name__)
    if payload == b"secret":
        return _held("share ids %r round-trip" % sorted(shares))
    return ("ERROR", "wrong payload?!")


# ---------------------------------------------------------------------------
# F240-F244 red baseline on the wave-263 base. The closure lanes own the
# fixes; these probes must BREAK here and are never re-filed.
# ---------------------------------------------------------------------------

_SCOPE_KEY = b"w264-scope-key-32-bytes-padded-00"
_SCOPE_UNIVERSE = frozenset({"files:read", "db:query", "net:fetch"})


def _scope_world():
    iss = stl.ScopeTicketIssuer(_SCOPE_KEY, _SCOPE_UNIVERSE)
    reg = stl.ToolRegistry(_SCOPE_UNIVERSE).bind_issuer(iss)
    reg.register("read_file", {"files:read"}, "Read a file.")
    return iss, reg


@probe("scopelist/f240-baseline")
def _p_f240():
    """F240 baseline: ticket bound to alice's subject authorizes with
    no presenter check."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    iss, reg = _scope_world()
    ticket = iss.seal("alice-subject-digest", {"files:read"}, 1000.0)
    ran = reg.invoke(ticket, "read_file", lambda: "ran")
    params = set(inspect.signature(reg.invoke).parameters)
    params |= set(inspect.signature(reg.list_tools).parameters)
    if params & {"subject", "presenter", "subject_digest",
                 "expected_sub", "expected_subject"}:
        return _held("registry binds presenter (F240 fixed)")
    if ran == "ran":
        return _break("F240 still breaks: cross-subject Bearer <redacted> use")
    return ("ERROR", "invoke did not execute?!")


@probe("scopelist/f241-baseline")
def _p_f241():
    """F241 baseline: consent token verifies as a scope ticket."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    iss, _reg = _scope_world()
    ci = stl.ConsentIssuer(_SCOPE_KEY, ttl_seconds=300)
    url = ci.mint_consent_url("appr-1", "fetch_url", {"net:fetch"},
                              "human-sub", 1000.0, "https://consent.local/c")
    token = url.split("?ct=")[1]
    try:
        sub, scopes = iss.verify(token)
    except stl.ScopedListingError as e:
        return _held("cross-presented consent token refused: %s" % e.code)
    return _break("F241 still breaks: consent token verifies as scope "
                  "ticket (sub=%r)" % (sub,))


@probe("scopelist/f242-baseline")
def _p_f242():
    """F242 baseline: pre-auth existence oracle in invoke()."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)

    def code_of(fn):
        try:
            fn()
        except stl.ScopedListingError as e:
            return e.code
        except Exception as e:  # noqa: BLE001
            return "RAW:%s" % type(e).__name__
        return "EXECUTED"

    _iss, reg = _scope_world()
    none_ghost = code_of(lambda: reg.invoke(None, "ghost_tool", lambda: 1))
    none_real = code_of(lambda: reg.invoke(None, "read_file", lambda: 1))
    if none_ghost != none_real:
        return _break("F242 still breaks: pre-auth oracle "
                      "(ghost=%s real=%s)" % (none_ghost, none_real))
    return _held("no pre-auth oracle (F242 fixed)")


def _det_base(name="w264-det", **kw):
    d = {"name": name, "version": "1.0.0",
         "description": "w264 probe detector",
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


@probe("detectors/f243-baseline")
def _p_f243():
    """F243 baseline: policy values-override invisible in the record."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    eng = det.DetectorEngine()
    eng.register(_det_base(priority="notice", exceptions=[_exc_block()]))
    sink = det.AlertSink(
        eng, policy={"exceptions":
                     {"w264-det": {"allow-ci": {"values": [[""]]}}}})
    sink.process({"type": "probe_event", "flag": True,
                  "host": "attacker.example"})
    rec = sink.journal_entries()[-1]
    if rec["record_type"] != "suppressed":
        return ("ERROR", "override did not suppress?!")
    exc = rec["exception_decision"]
    if any(k in exc for k in ("effective_values", "effective_block",
                              "policy", "policy_digest", "override")):
        return _held("override visible in record (F243 fixed)")
    return _break("F243 still breaks: widening override invisible in "
                  "the alert record")


@probe("detectors/f244-baseline")
def _p_f244():
    """F244 baseline: detectors accessor returns live mutable dicts."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    eng = det.DetectorEngine()
    eng.register(_det_base(name="w264-mut", priority="critical"))
    sink = det.AlertSink(eng)
    if not sink.may_gate_enforcement("w264-mut"):
        return ("ERROR", "stable detector cannot gate?!")
    eng.detectors["w264-mut"]["maturity"] = "experimental"
    if sink.may_gate_enforcement("w264-mut"):
        # Wave-264 merge: F244 closed -- detectors returns deep copies,
        # so the runtime mutation correctly has no effect.
        return _held("F244 fixed: runtime mutation via detectors[...] "
                     "had no effect on sink behavior")
    return _break("F244 still breaks: runtime mutation via "
                  "detectors[...] changed sink behavior")


@probe("taxonomy/pin-1151")
def _p_pin():
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    n = len(decision_codes.TAXONOMY)
    if n == TAXONOMY_PIN:
        return _held("taxonomy has %d keys = pin" % n)
    return ("ERROR", "taxonomy has %d keys, pin is %d"
            % (n, TAXONOMY_PIN))


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: run adjacent batteries' mains with GOV_SKIP_GREEN=1 in
    the child env (no combinatorial nesting). Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "skipped (GOV_SKIP_GREEN=1)")]
    here = os.path.dirname(os.path.abspath(__file__))
    adjacent = ["w263_redteam_probes.py", "w263_meshauth_probes.py",
                "w263_provenance_probes.py", "w263_recipient_probes.py"]
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
