"""Break-first closure probes for F245/F246/F247 (wave-265 closure lane).

F245: gov/provenance_policy.py must refuse hostile input shapes with
machine-coded refusals, never raw TypeError/AttributeError:
(1) verify_statement with an unhashable signature key_id ->
provenance-statement-unverified; (2) admit_vsa with a truthy
non-dict verifier field -> provenance-vsa-refused; (3) admit_vsa
with a non-numeric now -> provenance-vsa-refused (F228-shaped
_validate_now, like gov/mesh_auth.py).

F246: MeshTaskAuth.call must accept subject= and thread it into
authorize_call, so the task path honors the module's own
subject-binding composition instead of silently downgrading to
Bearer <redacted> after a subject-bound resume.

F247: MeshTaskAuth task transitions (escalate/abandon/resume) must
bind to the task owner's verified subject, recorded at begin. A
task_id holder with no owner credential gets a machine-coded
mesh-auth-not-owner refusal; ownerless tasks refuse transitions
(they have no authorization anchor). The subject presented here is
the DEPLOYMENT-VERIFIED subject -- the server authenticates the
network caller through authorize_call/MeshControl before threading
it in; this layer compares (constant-time), it does not mint
identities (the F240 expected_subject trust-anchor pattern).

Red-first: on the pristine base the attack probes BREAK; post-fix
they must all HELD, in BOTH deployment modes (staging default
below; clean env via `env -u GOV_DEPLOYMENT_MODE`).

Stdlib only. No network, no in-repo git subprocesses. Green check
is depth-1 and honors GOV_SKIP_GREEN=1.
"""

import copy
import hashlib
import inspect
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

# Wave-265 closure lane: pin -> 1178 (+1 mesh-auth-not-owner).
TAXONOMY_PIN = 1916 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*)

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

try:
    import gov.decision_codes as dc
    from gov import mesh_auth as ma
    from gov import provenance_policy as pp
    from gov import svid_issuer as sv
    from gov import scoped_tool_listing as stl
    from gov import short_lived_credentials as slc
    _IMPORT_ERROR = None
except ImportError as e:  # noqa: BLE001
    dc = ma = pp = sv = stl = slc = None
    _IMPORT_ERROR = e


def _need_modules():
    if _IMPORT_ERROR is not None:
        return False, "module import failed: %s" % _IMPORT_ERROR
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


# ---------------------------------------------------------------------------
# Shared worlds
# ---------------------------------------------------------------------------

_MESH_UNIVERSE = frozenset({"files:read", "net:fetch"})
_MESH_TICKET_KEY = b"w265-ticket-key-32-bytes-padded-0"
_MESH_CRED_KEY = b"w265-cred-key-32-bytes-padded-00"
_MESH_ISSUER_SEED = bytes(range(32))
_NOW = 4000000000.0
SPIFFE_A = "spiffe://example.org/agent-a"
SPIFFE_B = "spiffe://example.org/agent-b"

_SIGNER_SEED = b"w265-provenance-signer-a-0000000"  # 32 bytes
_VERIFIER_ID = "gate-registry"
_VERIFIER_SEED = b"w265-provenance-verifier-0000000"  # 32 bytes


def _mesh_world():
    issuer = sv.TestSvidIssuer(issuer_seed=_MESH_ISSUER_SEED,
                               key_id="w265-issuer-1")
    verifier = sv.SvidVerifier(
        {"w265-issuer-1": issuer.issuer_public_key}, "example.org")
    control = sv.MeshControl(verifier, {"allow": [SPIFFE_A, SPIFFE_B]})
    tickets = stl.ScopeTicketIssuer(_MESH_TICKET_KEY, _MESH_UNIVERSE)
    creds = slc.CredentialIssuer(
        os.path.join(tempfile.mkdtemp(prefix="w265-creds-"), "j.jsonl"),
        key=_MESH_CRED_KEY)
    gate = ma.MeshCallGate(svid_control=control,
                           ticket_issuer=tickets,
                           credential_issuer=creds)
    return issuer, gate, tickets


def _card(*schemes):
    return ma.MeshAuthCard("agent-b", list(schemes),
                           endpoints={"rpc": "https://b.internal/rpc"},
                           capabilities=["fetch_url"])


def _ticket_envelope(tickets, spiffe_id, scopes):
    sub = hashlib.sha256(spiffe_id.encode("utf-8")).hexdigest()
    return {"scheme": "scope-ticket",
            "credential": tickets.seal(sub, scopes, _NOW)}


def _svid_envelope(issuer, spiffe_id):
    pubkey = hashlib.sha256(spiffe_id.encode("utf-8")).hexdigest()
    return {"scheme": "svid",
            "credential": issuer.issue(spiffe_id, pubkey, 15, now=_NOW)}


def _signers():
    pub = pp.ed25519_publickey(_SIGNER_SEED)
    return {pp.key_id_hex(pub): pub.hex()}


def _statement():
    st = {
        "format": "sasanam-provenance-statement/1",
        "subject": {"name": "gate-artifact-bundle.zip",
                    "digest": {"sha256": "c" * 64}},
        "predicate": {
            "source": {"uri": "git@github.com:SIDDARTHAREDDY8/sasanam"},
            "builder": {"id": "https://builder.example/a@v1"},
            "tag": "v1",
            "inputs": {},
        },
    }
    pp.sign_statement(st, _SIGNER_SEED)
    return st


def _policy(name="P"):
    return pp.ProvenancePolicy.from_dict({
        "name": name,
        "version": 1,
        "sources": {"allowed": [
            "git@github.com:SIDDARTHAREDDY8/sasanam"]},
        "builders": {"allowed": ["https://builder.example/a@v1"]},
        "tags": {"mode": "any"},
        "require_signed_statement": True,
        "statement_signers": _signers(),
        "trusted_verifiers": {
            _VERIFIER_ID: pp.ed25519_publickey(
                _VERIFIER_SEED).hex()},
        "vsa_max_age_seconds": 86400,
        "vsa_required_level": "SLSA_BUILD_LEVEL_3",
    })


def _vsa():
    issuer = pp.VSAIssuer(_VERIFIER_ID, _VERIFIER_SEED)
    return issuer.issue("d" * 64, "P", "SLSA_BUILD_LEVEL_3",
                        issued_at=1000.0, ttl_seconds=3600)


def _expect_pp(fn, want_code):
    """pp.ProvenancePolicyError with want_code -> HELD; raw exception
    escaping -> BREAK (the F245 defect); no refusal -> BREAK."""
    try:
        fn()
    except pp.ProvenancePolicyError as e:
        if e.code == want_code:
            return _held("machine-coded refusal: %s" % want_code)
        return _break("wrong code %s (want %s)" % (e.code, want_code))
    except Exception as e:  # noqa: BLE001 -- the break under test
        return _break("raw %s escapes (want machine-coded %s)"
                      % (type(e).__name__, want_code))
    return _break("no refusal at all (want %s)" % want_code)


def _expect_ma(fn, want_code):
    """ma.MeshAuthError with want_code -> HELD; anything else ->
    BREAK (capability absent or wrong refusal)."""
    try:
        fn()
    except ma.MeshAuthError as e:
        if e.code == want_code:
            return _held("machine-coded refusal: %s" % want_code)
        return _break("wrong code %s (want %s)" % (e.code, want_code))
    except Exception as e:  # noqa: BLE001 -- the break under test
        return _break("raw %s escapes (want machine-coded %s)"
                      % (type(e).__name__, want_code))
    return _break("no refusal at all (want %s)" % want_code)


# ---------------------------------------------------------------------------
# F245: hostile input shapes refuse machine-coded
# ---------------------------------------------------------------------------

@probe("f245/unhashable-key-id")
def _p_unhashable_key_id():
    """verify_statement with a signature entry whose key_id is
    unhashable (dict): base raises raw TypeError from
    signers.get(key_id); fixed refuses provenance-statement-unverified."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    st = _statement()
    st["signatures"] = [{"key_id": {"evil": 1}, "sig": "00" * 64}]
    return _expect_pp(
        lambda: pp.verify_statement(st, _signers()),
        "provenance-statement-unverified")


@probe("f245/nondict-verifier")
def _p_nondict_verifier():
    """admit_vsa with a truthy non-dict verifier field: base raises
    raw AttributeError from verifier.get("id"); fixed refuses
    provenance-vsa-refused (unpinned verifier)."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    pol, vsa = _policy(), _vsa()
    evil = copy.deepcopy(vsa)
    evil["verifier"] = "attacker-string"
    return _expect_pp(
        lambda: pol.admit_vsa(evil, "P", "d" * 64, now=2000.0),
        "provenance-vsa-refused")


@probe("f245/list-verifier")
def _p_list_verifier():
    """admit_vsa with a truthy LIST verifier: same escape class as
    the string shape -- must also refuse machine-coded."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    pol, vsa = _policy(), _vsa()
    evil = copy.deepcopy(vsa)
    evil["verifier"] = ["not", "a", "dict"]
    return _expect_pp(
        lambda: pol.admit_vsa(evil, "P", "d" * 64, now=2000.0),
        "provenance-vsa-refused")


@probe("f245/hostile-now")
def _p_hostile_now():
    """admit_vsa with now="garbage": base raises raw TypeError at
    issued_at <= now; fixed refuses machine-coded (F228-shaped
    _validate_now)."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    pol, vsa = _policy(), _vsa()
    return _expect_pp(
        lambda: pol.admit_vsa(vsa, "P", "d" * 64, now="garbage"),
        "provenance-vsa-refused")


@probe("f245/bool-now-refused")
def _p_bool_now():
    """admit_vsa with now=True (bool is not a clock): must refuse
    machine-coded, never branch on a bool clock."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    pol, vsa = _policy(), _vsa()
    return _expect_pp(
        lambda: pol.admit_vsa(vsa, "P", "d" * 64, now=True),
        "provenance-vsa-refused")


@probe("f245/nan-now-refused")
def _p_nan_now():
    """admit_vsa with now=NaN: must refuse machine-coded, never
    compare against a non-finite clock."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    pol, vsa = _policy(), _vsa()
    return _expect_pp(
        lambda: pol.admit_vsa(vsa, "P", "d" * 64,
                              now=float("nan")),
        "provenance-vsa-refused")


@probe("f245/genuine-statement-verifies")
def _p_genuine_statement():
    """Control: a genuine signed statement still verifies (no
    cross-breakage from the new guards)."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    try:
        out = pp.verify_statement(_statement(), _signers())
    except Exception as e:  # noqa: BLE001
        return _break("genuine statement refused: %r" % e)
    if out.get("format") != pp.STATEMENT_FORMAT:
        return _break("genuine statement did not verify")
    return _held("genuine statement verifies")


@probe("f245/genuine-vsa-admits")
def _p_genuine_vsa():
    """Control: a genuine VSA still admits (no cross-breakage)."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    pol, vsa = _policy(), _vsa()
    try:
        admitted = pol.admit_vsa(vsa, "P", "d" * 64, now=2000.0)
    except Exception as e:  # noqa: BLE001
        return _break("genuine VSA refused: %r" % e)
    if admitted is not True:
        return _break("genuine VSA did not admit")
    return _held("genuine VSA admits")


def _resigned_vsa(mutate):
    """A genuine VSA, mutated by ``mutate`` and re-signed so the
    mutation (not the signature) is what admit_vsa judges. Lets
    hostile-shape probes reach the seam under test instead of
    dying earlier at the signature check."""
    vsa = _vsa()
    mutate(vsa)
    body = {k: v for k, v in vsa.items() if k != "signature"}
    sig = pp._ed25519.sign(
        _VERIFIER_SEED, pp._VSA_DOMAIN + pp.canonical_bytes(body))
    body["signature"] = {
        "key_id": pp.ed25519_publickey(_VERIFIER_SEED).hex(),
        "sig": sig.hex()}
    return body


@probe("f245/unhashable-verifier-id")
def _p_unhashable_verifier_id():
    """admit_vsa with a dict verifier whose id is unhashable: base
    raises raw TypeError from trusted_verifiers.get(vid); fixed
    refuses provenance-vsa-refused (two-axis review catch)."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    def mutate(vsa):
        vsa["verifier"] = {"id": {"evil": 1}}
    return _expect_pp(
        lambda: _policy().admit_vsa(
            _resigned_vsa(mutate), "P", "d" * 64, now=2000.0),
        "provenance-vsa-refused")


@probe("f245/nondict-subject")
def _p_nondict_subject():
    """admit_vsa with a truthy non-dict subject field: base raises
    raw AttributeError from .get("digest"); fixed refuses
    provenance-subject-refused (review catch)."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    def mutate(vsa):
        vsa["subject"] = "not-a-dict"
    return _expect_pp(
        lambda: _policy().admit_vsa(
            _resigned_vsa(mutate), "P", "d" * 64, now=2000.0),
        "provenance-subject-refused")


@probe("f245/nondict-subject-digest")
def _p_nondict_subject_digest():
    """admit_vsa with a truthy non-dict subject.digest field: base
    raises raw AttributeError from .get("sha256"); fixed refuses
    provenance-subject-refused (review catch)."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    def mutate(vsa):
        vsa["subject"] = {"digest": "not-a-dict"}
    return _expect_pp(
        lambda: _policy().admit_vsa(
            _resigned_vsa(mutate), "P", "d" * 64, now=2000.0),
        "provenance-subject-refused")


@probe("f245/unhashable-verified-level")
def _p_unhashable_verified_level():
    """admit_vsa with an unhashable verified_level: base raises raw
    TypeError from _VSA_LEVEL_RANK.get(level); fixed refuses
    provenance-vsa-refused (review catch)."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    def mutate(vsa):
        vsa["verified_level"] = {"evil": 1}
    return _expect_pp(
        lambda: _policy().admit_vsa(
            _resigned_vsa(mutate), "P", "d" * 64, now=2000.0),
        "provenance-vsa-refused")


# ---------------------------------------------------------------------------
# F246: MeshTaskAuth.call accepts subject= (no silent Bearer <redacted>
# downgrade on the task path)
# ---------------------------------------------------------------------------

@probe("f246/call-accepts-subject")
def _p_call_subject_param():
    """resume() accepts subject=; call() must too. Signature
    inspection: the seam the module documents must exist on the path
    tasks actually use."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    call_params = set(inspect.signature(ma.MeshTaskAuth.call).parameters)
    resume_params = set(
        inspect.signature(ma.MeshTaskAuth.resume).parameters)
    if "subject" in call_params:
        return _held("MeshTaskAuth.call accepts subject=")
    if "subject" not in resume_params:
        return ("ERROR", "resume lost its subject param?!")
    return _break(
        "MeshTaskAuth.call%s has no subject param while resume%s does"
        % (sorted(call_params), sorted(resume_params)))


@probe("f246/subject-honored-end-to-end")
def _p_subject_end_to_end():
    """Bound resume, then call(subject=): the call authorizes with
    the BOUND subject, not Bearer <redacted>. Base has no subject param ->
    TypeError (BREAK: the composition the module promises is
    unavailable on the task path)."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    _issuer, gate, tickets = _mesh_world()
    card = _card("svid", "scope-ticket")
    tasks = ma.MeshTaskAuth(gate)
    try:
        tasks.begin("t", owner=SPIFFE_A)
        tasks.escalate("t", "scope-ticket", "need the grant",
                       subject=SPIFFE_A, now=_NOW)
        ticket_env = _ticket_envelope(tickets, SPIFFE_A, {"net:fetch"})
        tasks.resume("t", card, ticket_env, subject=SPIFFE_A, now=_NOW)
        rec = tasks.call("t", card, ticket_env, subject=SPIFFE_A,
                         required_scopes={"net:fetch"}, now=_NOW)
    except TypeError as e:
        return _break("capability absent on this code: %s" % e)
    except ma.MeshAuthError as e:
        return _break("owner flow refused: %s" % e.code)
    if rec.get("subject") != SPIFFE_A:
        return _break("call authorized but subject=%r, not the bound "
                      "identity (silent Bearer <redacted> downgrade)"
                      % (rec.get("subject"),))
    return _held("task call honors subject= end-to-end")


@probe("f246/subject-mismatch-refused")
def _p_subject_mismatch():
    """call(subject=wrong-identity) refuses mesh-auth-subject-mismatch:
    the binding is enforced, not advisory."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    _issuer, gate, tickets = _mesh_world()
    card = _card("svid", "scope-ticket")
    tasks = ma.MeshTaskAuth(gate)
    try:
        tasks.begin("t", owner=SPIFFE_A)
        ticket_env = _ticket_envelope(tickets, SPIFFE_A, {"net:fetch"})
        tasks.call("t", card, ticket_env, subject=SPIFFE_B, now=_NOW)
    except TypeError as e:
        return _break("capability absent on this code: %s" % e)
    except ma.MeshAuthError as e:
        if e.code == "mesh-auth-subject-mismatch":
            return _held("wrong subject refused: %s" % e.code)
        return _break("wrong code %s (want mesh-auth-subject-mismatch)"
                      % e.code)
    return _break("call authorized under a mismatched subject")


@probe("f246/bearer-preserved-without-subject")
def _p_bearer_preserved():
    """Control: call WITHOUT subject= keeps the documented Bearer <redacted>
    semantics (ticket:<digest>), so the fix is purely additive."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    _issuer, gate, tickets = _mesh_world()
    card = _card("svid", "scope-ticket")
    tasks = ma.MeshTaskAuth(gate)
    try:
        tasks.begin("t", owner=SPIFFE_A)
    except TypeError:
        tasks.begin("t")  # old code: no owner concept
    try:
        ticket_env = _ticket_envelope(tickets, SPIFFE_A, {"net:fetch"})
        rec = tasks.call("t", card, ticket_env,
                         required_scopes={"net:fetch"}, now=_NOW)
    except ma.MeshAuthError as e:
        return _break("Bearer <redacted> call refused: %s" % e.code)
    want = "ticket:%s" % hashlib.sha256(
        SPIFFE_A.encode("utf-8")).hexdigest()
    if rec.get("subject") != want:
        return _break("Bearer <redacted> semantics changed: subject=%r" %
                      (rec.get("subject"),))
    return _held("Bearer <redacted> semantics preserved without subject=")


# ---------------------------------------------------------------------------
# F247: task transitions bind to the task owner's subject
# ---------------------------------------------------------------------------

@probe("f247/escalate-needs-owner-subject")
def _p_escalate_needs_owner():
    """escalate() with no subject on an owner-bound task: base pauses
    the task (BREAK -- any task_id holder pauses another's task);
    fixed refuses mesh-auth-not-owner."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    _issuer, gate, _tickets = _mesh_world()
    tasks = ma.MeshTaskAuth(gate)
    try:
        tasks.begin("victim", owner=SPIFFE_A)
    except TypeError:
        tasks.begin("victim")  # old code: no owner concept
    try:
        tasks.escalate("victim", "svid", "attacker says so", now=_NOW)
    except ma.MeshAuthError as e:
        if e.code == "mesh-auth-not-owner":
            return _held("unauthenticated escalate refused: %s" % e.code)
        return _break("wrong code %s (want mesh-auth-not-owner)"
                      % e.code)
    if tasks.state("victim") == ma.TASK_STATE_AUTH_REQUIRED:
        return _break("unauthenticated escalate() paused the task: "
                      "transitions need no credential")
    return ("ERROR", "escalate did not pause and did not refuse?!")


@probe("f247/escalate-wrong-subject-refused")
def _p_escalate_wrong_subject():
    """escalate() with a NON-owner subject refuses: only the owner
    may pause their own task."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    _issuer, gate, _tickets = _mesh_world()
    tasks = ma.MeshTaskAuth(gate)
    try:
        tasks.begin("t", owner=SPIFFE_A)
        tasks.escalate("t", "svid", "attacker says so",
                       subject=SPIFFE_B, now=_NOW)
    except TypeError as e:
        return _break("capability absent on this code: %s" % e)
    except ma.MeshAuthError as e:
        if e.code == "mesh-auth-not-owner":
            return _held("non-owner escalate refused: %s" % e.code)
        return _break("wrong code %s (want mesh-auth-not-owner)"
                      % e.code)
    return _break("non-owner escalated the task")


@probe("f247/abandon-needs-owner-subject")
def _p_abandon_needs_owner():
    """abandon() with no subject: base terminally kills the task
    (BREAK); fixed refuses mesh-auth-not-owner."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    _issuer, gate, _tickets = _mesh_world()
    tasks = ma.MeshTaskAuth(gate)
    try:
        tasks.begin("victim", owner=SPIFFE_A)
    except TypeError:
        tasks.begin("victim")  # old code: no owner concept
    try:
        tasks.abandon("victim")
    except ma.MeshAuthError as e:
        if e.code == "mesh-auth-not-owner":
            return _held("unauthenticated abandon refused: %s" % e.code)
        return _break("wrong code %s (want mesh-auth-not-owner)"
                      % e.code)
    if tasks.state("victim") == ma.TASK_STATE_ABANDONED:
        return _break("unauthenticated abandon() terminally killed the "
                      "task: transitions need no credential")
    return ("ERROR", "abandon did not kill and did not refuse?!")


@probe("f247/ownerless-task-refuses-transitions")
def _p_ownerless_refuses():
    """A task begun WITHOUT an owner has no authorization anchor:
    escalate/abandon must refuse (fail-closed), not fall back to
    the old anyone-may-mutate behavior."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    _issuer, gate, _tickets = _mesh_world()
    tasks = ma.MeshTaskAuth(gate)
    tasks.begin("t")  # no owner
    refused_esc = refused_abd = False
    try:
        tasks.escalate("t", "svid", "x", subject=SPIFFE_A, now=_NOW)
    except ma.MeshAuthError as e:
        refused_esc = (e.code == "mesh-auth-not-owner")
    except TypeError:
        pass  # old code: escalate takes no subject -> BREAK below
    try:
        tasks.abandon("t", subject=SPIFFE_A)
    except ma.MeshAuthError as e:
        refused_abd = (e.code == "mesh-auth-not-owner")
    except TypeError:
        pass  # old code: abandon takes no subject -> BREAK below
    if refused_esc and refused_abd:
        return _held("ownerless task refuses transitions")
    return _break("ownerless task allowed a transition "
                  "(escalate_refused=%s abandon_refused=%s)"
                  % (refused_esc, refused_abd))


@probe("f247/owner-end-to-end")
def _p_owner_end_to_end():
    """Control: the owner CAN escalate, resume, and abandon their own
    task end-to-end (the fix must not brick legitimate flows)."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    issuer, gate, tickets = _mesh_world()
    card = _card("svid", "scope-ticket")
    tasks = ma.MeshTaskAuth(gate)
    try:
        tasks.begin("t", owner=SPIFFE_A)
        esc = tasks.escalate("t", "scope-ticket", "need the grant",
                             subject=SPIFFE_A, now=_NOW)
        if esc["state"] != ma.TASK_STATE_AUTH_REQUIRED:
            return _break("owner escalate did not pause")
        ticket_env = _ticket_envelope(tickets, SPIFFE_A, {"net:fetch"})
        tasks.resume("t", card, ticket_env, subject=SPIFFE_A, now=_NOW)
        if tasks.state("t") != ma.TASK_STATE_ACTIVE:
            return _break("owner resume did not reactivate")
        if tasks.abandon("t", subject=SPIFFE_A) !=\
                ma.TASK_STATE_ABANDONED:
            return _break("owner abandon did not terminate")
    except TypeError as e:
        return _break("capability absent on this code: %s" % e)
    except ma.MeshAuthError as e:
        return _break("owner flow refused: %s" % e.code)
    return _held("owner escalate/resume/abandon end-to-end")


@probe("f247/attacker-cannot-resume-others-task")
def _p_attacker_resume():
    """Attacker with their OWN valid credential tries to resume the
    victim's paused task: base lets them (BREAK -- a state transition
    on another party's task); fixed refuses mesh-auth-not-owner and
    the task stays paused."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    issuer, gate, _tickets = _mesh_world()
    card = _card("svid", "scope-ticket")
    tasks = ma.MeshTaskAuth(gate)
    try:
        tasks.begin("t", owner=SPIFFE_A)
    except TypeError:
        tasks.begin("t")
    # Owner pauses the task (on new code with subject=; on old code
    # escalate takes no subject).
    try:
        tasks.escalate("t", "svid", "need stronger auth",
                       subject=SPIFFE_A, now=_NOW)
    except TypeError:
        tasks.escalate("t", "svid", "need stronger auth", now=_NOW)
    attacker_env = _svid_envelope(issuer, SPIFFE_B)
    try:
        tasks.resume("t", card, attacker_env, subject=SPIFFE_B, now=_NOW)
    except TypeError:
        # Old code: resume takes subject but has no owner concept;
        # retry the old-code shape.
        try:
            tasks.resume("t", card, attacker_env, now=_NOW)
        except ma.MeshAuthError as e:
            return _break("old-code resume refused differently: %s"
                          % e.code)
    except ma.MeshAuthError as e:
        if e.code == "mesh-auth-not-owner":
            if tasks.state("t") == ma.TASK_STATE_AUTH_REQUIRED:
                return _held("attacker resume refused; task stays "
                             "paused")
            return _break("refused but task left the paused state")
        return _break("wrong code %s (want mesh-auth-not-owner)"
                      % e.code)
    if tasks.state("t") == ma.TASK_STATE_ACTIVE:
        return _break("attacker resumed another party's paused task "
                      "with their own credential")
    return ("ERROR", "resume neither refused nor resumed?!")


# ---------------------------------------------------------------------------
# Pin
# ---------------------------------------------------------------------------

@probe("pin/taxonomy-1178")
def _p_pin():
    """1178 (the pinned count) includes mesh-auth-not-owner; the new
    literal occurs exactly once in the raw decision_codes source
    (wave-260 lesson)."""
    ok, why = _need_modules()
    if not ok:
        return ("ERROR", why)
    if "mesh-auth-not-owner" not in dc.TAXONOMY:
        return _break("mesh-auth-not-owner missing from taxonomy")
    if len(dc.TAXONOMY) != TAXONOMY_PIN:
        return _break("taxonomy has %d codes, pin is %d"
                      % (len(dc.TAXONOMY), TAXONOMY_PIN))
    import re
    src = open(os.path.join(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))),
        "gov", "decision_codes.py"), encoding="utf-8").read()
    n = len(re.findall(r'"code":\s*["\x27]mesh-auth-not-owner["\x27]',
                      src))
    if n != 1:
        return _break("mesh-auth-not-owner literal occurs %d times "
                      "in raw source (want exactly 1)" % n)
    return _held("pin %d; mesh-auth-not-owner registered once"
                 % TAXONOMY_PIN)


def green_check():
    """Depth-1 green check: adjacent batteries with GOV_SKIP_GREEN=1
    in the child env; honors GOV_SKIP_GREEN=1 by recording a skip."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "SKIPPED (GOV_SKIP_GREEN=1)"
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = os.environ.get("TMPDIR", "/tmp")
    ran = []
    for battery in ("evals/w263_provenance_probes.py",
                    "evals/w263_meshauth_probes.py",
                    "evals/w264_redteam_probes.py"):
        r = subprocess.run(
            [sys.executable, battery], cwd=repo, env=env,
            capture_output=True, text=True, timeout=600)
        ran.append("%s->%d" % (battery, r.returncode))
        if r.returncode != 0:
            raise SystemExit(
                "GREEN CHECK FAILED (%s):\n%s\n%s"
                % (battery, r.stdout[-2000:], r.stderr[-2000:]))
    return "OK (%s)" % ", ".join(ran)


def main():
    mode = os.environ.get("GOV_DEPLOYMENT_MODE", "staging")
    counts = {"HELD": 0, "BREAK": 0, "ERROR": 0}
    print("w265 F245/F246/F247 closure probes — mode=%s" % mode)
    for name, fn in _PROBES:
        try:
            status, why = fn()
        except Exception as e:  # noqa: BLE001 -- a probe error is ERROR
            status, why = "ERROR", "probe raised %r" % e
        counts[status] = counts.get(status, 0) + 1
        print("[%s] %-42s %s" % (status, name, why))
    print("green check: %s" % green_check())
    print("result: %d HELD / %d BREAK / %d ERROR"
          % (counts["HELD"], counts["BREAK"], counts["ERROR"]))
    return 0 if (counts["BREAK"] == 0 and counts["ERROR"] == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
