"""Wave-271 independent red-team battery (break-first post-wave-270 audit).

Breaks the Wave-270 seams at the public API: approval ceremony v2,
per-tool grants (tool_grant), pickle bundle scanning, evidence bundle
v2, evidence-cert provisioner classes, and the F252 output-IFC
issuance-registry closure, plus cross-seam trajectories.

New defects found by this battery (filed 2026-10-01):
  F253 (LOW, CLOSED 2026-10-01, wave-272)  tool_grant: a refused replayed
              PoP proof consumed the victim's max_calls budget BEFORE
              the nonce check refused it. Closed by moving the nonce
              replay check above usage consumption in enforce
              (gov/tool_grant.py); r01 now pins budget-neutrality.
  F254 (LOW, CLOSED 2026-10-01, wave-272)  tool_grant: make_pop_proof's
              default nonce was a digest of (method, uri, now) -- two
              legitimate proofs minted in the same second were
              byte-identical. Closed by requiring the nonce at mint
              time (missing/empty raises GrantError ptgrant-pop-invalid;
              no silent default); r02/r03 now pin the new contract.
  F255 (LOW, CLOSED 2026-10-01, wave-272)  bundle_scan: INST/OBJ/NEWOBJ
              (protocol 0-2 call opcodes) were not modeled -- a stream
              that executes attacker code at load via INST was admitted
              "clean"; the sink rule fired only on REDUCE. Closed by
              the gov/bundle_scan.py sink-rule extension (INST/OBJ/
              NEWOBJ are now call-capable opcodes; the INST opcode
              argument resolves like a GLOBAL); b01/b02/b03/x02a now
              HELD as regression pins (b01: flagged advisory MEDIUM,
              not refused -- builtins.print is not a sink).

The r01/r02/r03 probes pin the F253/F254 closures (2026-10-01, wave-272
lane): r01 asserts replays are budget-neutral; r02 asserts minting
without a nonce is refused; r03 asserts two same-second proofs with
caller-unique nonces both enforce. The b01/b02/b03/x02a probes flipped
to HELD at the F255 closure (2026-10-01, wave-272) and now pin that
closure (the close-when criteria name the flipped assertions).

F252 re-probe: the issuance-registry closure HELD (pinned, not
re-filed). F251 (session binding at the wrong seam) was not
re-probed -- its seam was untouched by wave-270.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; deterministic (fixed seeds, explicit
`now`); fresh unique /var/tmp/g271* TMPDIR (`mkdir -p` first);
depth-1 green checks honoring GOV_SKIP_GREEN=1; no in-repo git
subprocesses; stdlib only.
"""

import base64
import contextlib
import hashlib
import io
import json
import os
import pickle
import pickletools
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Deterministic audit-log key (fixed, not secrets.token_hex).
os.environ.setdefault(
    "GOV_LOG_KEY",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w271-redteam")

_TMP = tempfile.mkdtemp(prefix="g271-redteam-%d-" % os.getpid(),
                        dir="/var/tmp")
os.makedirs(_TMP, exist_ok=True)
os.environ["TMPDIR"] = _TMP

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from gov import approval_ceremony as ac  # noqa: E402
from gov import bundle_scan  # noqa: E402
from gov import corroboration_receipt as cr  # noqa: E402
from gov import ed25519 as _ed  # noqa: E402
from gov import evidence_bundle_v2 as eb2  # noqa: E402
from gov import evidence_certs as ec  # noqa: E402
from gov import output_ifc as ifc  # noqa: E402
from gov import session_binding as sb  # noqa: E402
from gov import skill_admission as sa  # noqa: E402
from gov import tool_grant  # noqa: E402
from gov.agent_identity import did_key_from_pubkey  # noqa: E402
from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402

# Merge pin: 1411 (wave-270 merge). Counted on QUOTED source literals
# ("code": '...') -- the bare '"code": ' substring overcounts by 2.
TAXONOMY_PIN = 1742  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []


def _run(pid, expected, fn):
    """Run one probe; verdict must equal expected (BREAK or HELD)."""
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001 -- probe harness
        verdict, note = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    ok = (verdict == expected)
    _RESULTS.append((pid, expected, verdict, ok, note))
    return ok


def _refused_with(fn, *codes):
    """(verdict, note): HELD iff fn raises with .code in codes."""
    try:
        out = fn()
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        if code in codes:
            return "HELD", "refused %s" % code
        return "ERROR", "%s code=%r" % (type(exc).__name__, code)
    return "BREAK", "not refused: %r" % (out,)


def _pin_check():
    import re
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    literals = re.findall(r'"code": \'([^\']*)\'', src)
    if len(literals) != TAXONOMY_PIN:
        return ("BREAK", "taxonomy pin drift: %d literals, pin %d"
                % (len(literals), TAXONOMY_PIN))
    if len(set(literals)) != len(literals):
        return "BREAK", "duplicate code literals in taxonomy"
    return "HELD", "taxonomy pin 1588: 1588 unique literals"


def _seed(i):
    return bytes([i & 0xFF]) * 32

# ---------------------------------------------------------------------------
# tool_grant fixtures
# ---------------------------------------------------------------------------

_TG_ISS_SEED = _seed(0x01)
_TG_ISS_PUB = _ed.publickey(_TG_ISS_SEED)
_TG_HOLDER_SEED = _seed(0x02)
_TG_HOLDER_PUB = _ed.publickey(_TG_HOLDER_SEED)
_TG_ATTACKER_SEED = _seed(0x03)
_TG_NOW = 1790000000
_TG_AUD = "https://mcp.example.internal/fileserver"
_TG_SUB = "spiffe://trust-domain/ns/prod/sa/agent-7"
_TG_LINK = "sha256:" + "ab" * 32


def _tg_details(tool="read", **kw):
    d = {
        "type": tool_grant.GRANT_TYPE,
        "locations": [_TG_AUD],
        "actions": ["call"],
        "identifier": "fileserver::" + tool,
        "arg_bounds": {
            "path": {"predicate": "prefix",
                     "params": {"prefix": "/data/shared/"}},
        },
        "supply_chain": {"link_digest": _TG_LINK, "delegation_ok": True},
        "max_calls": 3,
    }
    d.update(kw)
    return d


def _tg_issue(details_list, **kw):
    return tool_grant.Issuer(
        tool_grant.GRANT_ISSUER, _TG_ISS_SEED,
        lambda mid: {"version": 1})


def _tg_grant(details_list, **kw):
    params = dict(sub=_TG_SUB, aud=_TG_AUD, proof_pub=_TG_HOLDER_PUB,
                  mandate_id="m1", mandate_version=1,
                  details=details_list, lifetime_s=600, now=_TG_NOW)
    params.update(kw)
    return _tg_issue(details_list, **kw).issue(**params)


def _tg_env(store, **kw):
    env = dict(issuer_pub=_TG_ISS_PUB, server_name="fileserver",
               server_uri=_TG_AUD, tool="read",
               args={"path": "/data/shared/x"}, now=_TG_NOW,
               usage_store=store,
               mandate_version_provider=lambda mid: 1,
               link_verifier=lambda t: _TG_LINK)
    env.update(kw)
    return env


def _tg_proof(grant, seed=_TG_HOLDER_SEED, **kw):
    params = dict(method="POST", uri=_TG_AUD + "/tools/call",
                  now=_TG_NOW)
    params.update(kw)
    return tool_grant.make_pop_proof(seed, grant, **params)


# --- F253: replayed proofs burn budget before the nonce check ---------

def r01_replay_burns_budget():
    """F253: a REFUSED replay decrements the victim's max_calls."""
    grant = _tg_grant([_tg_details()])
    store = tool_grant.UsageStore()
    proof = _tg_proof(grant, nonce="r01-unique-1")
    r1 = tool_grant.enforce(grant, proof=proof, **_tg_env(store))
    assert r1["code"] == "ptgrant-ok", r1
    used1 = store.status(grant["body"]["jti"], 3)["calls_used"]
    r2 = tool_grant.enforce(grant, proof=proof, **_tg_env(store))
    used2 = store.status(grant["body"]["jti"], 3)["calls_used"]
    if r2["code"] == "ptgrant-jti-reused" and used2 == used1 + 1:
        return ("BREAK",
                "F253: refused replay burned budget (used %d -> %d); "
                "consume() runs before the nonce check" % (used1, used2))
    if r2["code"] == "ptgrant-jti-reused" and used2 == used1:
        return "HELD", "replay refused without consuming budget"
    return "ERROR", "unexpected: %r used %d->%d" % (r2["code"], used1, used2)


# --- F254 closure (2026-10-01, wave-272 lane): nonce is required ---------

def r02_default_nonce_collides():
    """F254 CLOSED: there is no silent deterministic default -- minting
    without a nonce is a loud refusal (ptgrant-pop-invalid), never a
    byte-identical same-second proof."""
    grant = _tg_grant([_tg_details()])
    try:
        tool_grant.make_pop_proof(_TG_HOLDER_SEED, grant, method="POST",
                                  uri=_TG_AUD + "/tools/call", now=_TG_NOW)
    except tool_grant.GrantError as exc:
        if getattr(exc, "code", None) == "ptgrant-pop-invalid":
            return ("HELD",
                    "minting without nonce refused ptgrant-pop-invalid; "
                    "no silent same-second collision possible")
        return "ERROR", "wrong refusal code: %r" % (getattr(exc, "code", None),)
    return ("BREAK",
            "F254: minting without nonce silently defaulted -- same-second "
            "proofs can still be byte-identical")


def r03_default_nonce_second_call_refused():
    """F254 CLOSED: caller-supplied unique nonces make two same-second
    proofs distinct -- the second legitimate call enforces ptgrant-ok."""
    grant = _tg_grant([_tg_details()])
    store = tool_grant.UsageStore()
    p1 = _tg_proof(grant, nonce="r03-unique-1")
    p2 = _tg_proof(grant, nonce="r03-unique-2")
    r1 = tool_grant.enforce(grant, proof=p1, **_tg_env(store))
    r2 = tool_grant.enforce(grant, proof=p2, **_tg_env(store))
    if r1["code"] == "ptgrant-ok" and r2["code"] == "ptgrant-ok":
        return ("HELD",
                "two same-second proofs with unique caller nonces both "
                "enforced ptgrant-ok")
    if r2["code"] == "ptgrant-jti-reused":
        return ("BREAK",
                "F254: second legitimate call refused ptgrant-jti-reused")
    return "ERROR", "unexpected: r1=%r r2=%r" % (r1["code"], r2["code"])


# --- tool_grant holds ---------------------------------------------------

def r04_stale_mandate_version():
    grant = _tg_grant([_tg_details()])
    store = tool_grant.UsageStore()
    proof = _tg_proof(grant, nonce="r04-n1")
    r = tool_grant.enforce(
        grant, proof=proof,
        **_tg_env(store, mandate_version_provider=lambda mid: 2))
    if r["code"] == "ptgrant-mandate-drift":
        return "HELD", "stale mandate refused ptgrant-mandate-drift"
    return "BREAK", "stale mandate NOT refused: %r" % r["code"]


def r05_unknown_predicate_refused():
    grant = _tg_grant([_tg_details()])
    try:
        tool_grant.attenuate(
            grant, holder_seed=_TG_HOLDER_SEED, issuer_pub=_TG_ISS_PUB,
            caveats=[{"predicate": "no_such_pred",
                      "params": {"x": 1}}])
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", None) == "ptgrant-predicate-unknown":
            return "HELD", "unknown predicate refused at attenuate"
        return "ERROR", "code=%r" % getattr(exc, "code", None)
    return "BREAK", "unknown predicate caveat minted"


def r06_max_calls_edge():
    grant = _tg_grant([_tg_details(max_calls=1)])
    store = tool_grant.UsageStore()
    r1 = tool_grant.enforce(grant, proof=_tg_proof(grant, nonce="r06-a"),
                            **_tg_env(store))
    r2 = tool_grant.enforce(grant, proof=_tg_proof(grant, nonce="r06-b"),
                            **_tg_env(store))
    if r1["code"] == "ptgrant-ok"\
            and r2["code"] == "ptgrant-max-calls-exhausted":
        return "HELD", "budget edge exact: 1 ok, 2nd exhausted"
    return "BREAK", "edge wrong: %r then %r" % (r1["code"], r2["code"])


def r07_attenuate_without_cnf_key():
    grant = _tg_grant([_tg_details()])
    try:
        tool_grant.attenuate(
            grant, holder_seed=_TG_ATTACKER_SEED, issuer_pub=_TG_ISS_PUB,
            caveats=[{"predicate": "max_calls", "params": {"max_calls": 1}}])
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", None) == "ptgrant-pop-invalid":
            return "HELD", "non-cnf attenuator refused ptgrant-pop-invalid"
        return "ERROR", "code=%r" % getattr(exc, "code", None)
    return "BREAK", "attenuation by non-cnf key minted"


def r08_link_digest_tampering():
    grant = _tg_grant([_tg_details()])
    store = tool_grant.UsageStore()
    r = tool_grant.enforce(
        grant, proof=_tg_proof(grant, nonce="r08-n1"),
        **_tg_env(store, link_verifier=lambda t: "sha256:" + "ff" * 32))
    if r["code"] == "ptgrant-supply-chain-failed":
        return "HELD", "tampered link refused ptgrant-supply-chain-failed"
    return "BREAK", "tampered link NOT refused: %r" % r["code"]


def r09_forged_proof_signature():
    grant = _tg_grant([_tg_details()])
    store = tool_grant.UsageStore()
    proof = _tg_proof(grant, seed=_TG_ATTACKER_SEED, nonce="r09-n1")
    r = tool_grant.enforce(grant, proof=proof, **_tg_env(store))
    if r["code"] == "ptgrant-pop-invalid":
        return "HELD", "forged proof refused ptgrant-pop-invalid"
    return "BREAK", "forged proof NOT refused: %r" % r["code"]

# ---------------------------------------------------------------------------
# approval ceremony fixtures
# ---------------------------------------------------------------------------

_AC_NOW = 1780000000
_AC_PAYLOAD = {"action": "tool.execute", "tool": "shell",
               "args": {"cmd": "ls /tmp"}}


def _ac_signer(i):
    return Ed25519Signer(_seed(i))


def _ac_verifier(signer):
    return Ed25519Verifier(signer.public_key, key_id=signer.key_id)


def _ac_did(signer):
    return did_key_from_pubkey(signer.public_key)


def _ac_digest(payload):
    raw = json.dumps(payload, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _ac_receipt(signer, payload_digest):
    stmt = cr.build_statement(
        _ac_did(signer), payload_digest, ["b" * 64],
        {"action": "approval.resume", "resource": "ceremony-test"},
        "corroborated", "2026-10-01T12:00:00Z", "approval-ceremony",
        "c" * 64)
    env = cr.dsse_envelope(stmt)
    return cr.sign_envelope(env, signer, signer.key_id)


def _ac_gate():
    signer = _ac_signer(0xA1)
    gate = ac.ApprovalGate(ac.MemoryApprovalStore(),
                           {_ac_did(signer): _ac_verifier(signer)})
    return gate, signer


def _ac_request(gate, thread="t1", name="n1", payload=None,
                verdicts=("accept", "ignore", "respond", "edit"),
                **kw):
    params = dict(thread_id=thread, name=name,
                  payload=_AC_PAYLOAD if payload is None else payload,
                  allowed_verdicts=verdicts, now=_AC_NOW)
    params.update(kw)
    return gate.request_approval(**params)


def _ac_resume(gate, signer, approval_id, verdict="accept", arg=None,
               digest=None):
    env = _ac_receipt(signer, digest or _ac_digest(_AC_PAYLOAD))
    return gate.resume_approval(approval_id, verdict, arg, env,
                                now=_AC_NOW)


# --- ceremony probes -----------------------------------------------------

def c01_id_confusion_verdicts():
    """Id key is (thread, lineage, name, payload_digest): a second
    request with DIFFERENT allowed_verdicts gets the FIRST record."""
    gate, _ = _ac_gate()
    r1 = _ac_request(gate, verdicts=["accept"])
    r2 = _ac_request(gate, verdicts=["ignore"])
    if r1["approval_id"] == r2["approval_id"] and\
            r2["allowed_verdicts"] == ["accept"]:
        return ("HELD",
                "by-design idempotency: same 4-tuple -> same approval; "
                "stored verdicts (not the second request's) are surfaced")
    return "BREAK", "id confusion: %r vs %r" % (r1, r2)


def c02_verdict_not_allowed():
    gate, signer = _ac_gate()
    rec = _ac_request(gate, verdicts=["accept"])
    return _refused_with(
        lambda: _ac_resume(gate, signer, rec["approval_id"],
                           verdict="ignore", arg=None),
        "ceremony-v2-verdict-not-allowed")


def c03_stale_lineage():
    gate, signer = _ac_gate()
    rec = _ac_request(gate)
    refired = gate.fork_thread("t1", "lineage-2", now=_AC_NOW)
    if len(refired) != 1 or refired[0] == rec["approval_id"]:
        return "ERROR", "fork did not re-fire under a new id: %r" % refired
    held, note = _refused_with(
        lambda: _ac_resume(gate, signer, rec["approval_id"]),
        "ceremony-v2-stale-lineage")
    if held != "HELD":
        return held, note
    # The re-fired approval in the new lineage resumes fine.
    out = _ac_resume(gate, signer, refired[0])
    if out["approved"] is True:
        return "HELD", "stale lineage refused; re-fired id resumes"
    return "ERROR", "re-fired resume failed: %r" % out


def c04_consumed_not_refired():
    gate, signer = _ac_gate()
    rec = _ac_request(gate)
    _ac_resume(gate, signer, rec["approval_id"])
    refired = gate.fork_thread("t1", "lineage-2", now=_AC_NOW)
    if refired == []:
        return "HELD", "consumed approvals never re-fire across a fork"
    return "BREAK", "consumed approval re-fired: %r" % refired


def c05_once_token_no_replay():
    gate, _ = _ac_gate()
    calls = []

    def fn():
        calls.append(1)
        return {"n": len(calls)}

    a = gate.run_once("t1", "tok-1", fn)
    b = gate.run_once("t1", "tok-1", fn)
    if a == b == {"n": 1} and len(calls) == 1:
        return "HELD", "once-token: fn ran once, cached result returned"
    return "BREAK", "once-token replayed: %r calls=%d" % (b, len(calls))


def c06_once_token_across_fork():
    """Once-tokens are keyed (thread, token), NOT lineage: after a
    fork the old lineage's result is returned without re-running."""
    gate, _ = _ac_gate()
    calls = []

    def fn():
        calls.append(1)
        return "old-lineage-result"

    gate.run_once("t1", "tok-9", fn)
    gate.fork_thread("t1", "lineage-2", now=_AC_NOW)
    out = gate.run_once("t1", "tok-9", fn)
    if out == "old-lineage-result" and len(calls) == 1:
        return ("HELD",
                "by-design: once-token contract is per (thread, token); "
                "fork does not reset pre-gate side-effect gating")
    return "ERROR", "unexpected: %r calls=%d" % (out, len(calls))


def c07_receipt_forgery():
    gate, signer = _ac_gate()
    rec = _ac_request(gate)
    env = _ac_receipt(signer, rec["payload_digest"])
    bad = json.loads(json.dumps(env))
    sigs = bad.get("signatures")
    if isinstance(sigs, list) and sigs and isinstance(sigs[0], dict):
        s = sigs[0].get("sig", "")
        sigs[0]["sig"] = s[:-1] + ("0" if s[-1:] != "0" else "1")
    elif isinstance(bad.get("signature"), str):
        s = bad["signature"]
        bad["signature"] = s[:-1] + ("0" if s[-1:] != "0" else "1")
    else:
        return "ERROR", "unknown envelope shape: %r" % sorted(bad)
    return _refused_with(
        lambda: gate.resume_approval(rec["approval_id"], "accept", None,
                                     bad, now=_AC_NOW),
        "ceremony-v2-receipt-invalid")


def c08_receipt_unregistered_reviewer():
    gate, _ = _ac_gate()
    rec = _ac_request(gate)
    rogue = _ac_signer(0xB2)
    env = _ac_receipt(rogue, rec["payload_digest"])
    return _refused_with(
        lambda: gate.resume_approval(rec["approval_id"], "accept", None,
                                     env, now=_AC_NOW),
        "ceremony-v2-receipt-invalid")


def c09_receipt_wrong_payload_binding():
    gate, signer = _ac_gate()
    rec = _ac_request(gate)
    env = _ac_receipt(signer, "ff" * 32)
    return _refused_with(
        lambda: gate.resume_approval(rec["approval_id"], "accept", None,
                                     env, now=_AC_NOW),
        "ceremony-v2-payload-tampered")


def c10_ambiguous_resume():
    gate, signer = _ac_gate()
    _ac_request(gate, name="n1")
    _ac_request(gate, name="n2")
    env = _ac_receipt(signer, _ac_digest(_AC_PAYLOAD))
    return _refused_with(
        lambda: gate.resume_next("t1", "accept", None, env, now=_AC_NOW),
        "ceremony-v2-ambiguous-resume")


def c11_bare_dict_schema_refused():
    gate, _ = _ac_gate()
    return _refused_with(
        lambda: gate.request_approval("t1", "n1", _AC_PAYLOAD,
                                      response_schema={"type": "object"},
                                      now=_AC_NOW),
        "ceremony-v2-schema-invalid")


def c12_no_schema_passthrough():
    """No response_schema: edit/respond args pass through unvalidated
    (documented honest behavior -- the node gets the raw resume value)."""
    gate, signer = _ac_gate()
    rec = _ac_request(gate, verdicts=["edit"])
    out = _ac_resume(gate, signer, rec["approval_id"], verdict="edit",
                     arg={"x": 1})
    if out["payload"] == {"x": 1}:
        return "HELD", "no-schema edit passes the arg through (pinned)"
    return "ERROR", "unexpected payload: %r" % out


def c13_unknown_approval():
    gate, signer = _ac_gate()
    env = _ac_receipt(signer, _ac_digest(_AC_PAYLOAD))
    return _refused_with(
        lambda: gate.resume_approval("no-such-id", "accept", None, env,
                                     now=_AC_NOW),
        "ceremony-v2-unknown-approval")


def c14_double_resume():
    gate, signer = _ac_gate()
    rec = _ac_request(gate)
    _ac_resume(gate, signer, rec["approval_id"])
    return _refused_with(
        lambda: _ac_resume(gate, signer, rec["approval_id"]),
        "ceremony-v2-already-consumed")

# ---------------------------------------------------------------------------
# bundle_scan probes
# ---------------------------------------------------------------------------

# Protocol-0 INST stream: no GLOBAL opcode at all -- the sink hides in
# the INST argument, which the scanner never inspects.
_BS_INST_PRINT = b"(Vhello-from-inst\ni" + b"builtins\nprint\n" + b"."
_BS_INST_SYSTEM = b"(Vecho-hi\ni" + b"os\nsystem\n" + b"."
# Protocol-0 OBJ stream: MARK, GLOBAL, UNICODE, OBJ (stack discipline:
# markobject classobject arg1 ...). No REDUCE.
_BS_OBJ_PRINT = b"(cbuiltins\nprint\nVhello-from-obj\no."
_BS_OBJ_SYSTEM = b"(cos\nsystem\nVecho-hi\no."


def _bs_reduce_evil():
    class _Evil(object):
        def __reduce__(self):
            import os as _os
            return (_os.system, ("id",))
    return pickle.dumps(_Evil(), protocol=2)


class _BsValueHolder(object):
    def __init__(self):
        self.x = 1


class _BsMangled(object):
    def __reduce__(self):
        return (getattr, (_BsValueHolder(), "sy" + "stem"))


def _bs_mangled_getattr():
    return pickle.dumps(_BsMangled(), protocol=2)


def _bs_truncated():
    return pickle.dumps({"a": 1}, protocol=2)[:6]


def b01_inst_executes_but_clean():
    """F255: INST executes code at load; the scanner says clean."""
    res = bundle_scan.scan_pickle_stream(_BS_INST_PRINT)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        pickle.loads(_BS_INST_PRINT)
    executed = (buf.getvalue() == "hello-from-inst\n")
    if res["verdict"] == "clean" and not res["findings"] and executed:
        return ("BREAK",
                "F255: INST stream executed at load (printed) yet scans "
                "clean with zero findings -- INST/OBJ/NEWOBJ unmodeled")
    return "HELD", "INST stream flagged: %s" % (res["verdict"],)


def b02_inst_sink_admitted():
    """F255: INST naming a curated sink (os.system) is admitted clean."""
    res = bundle_scan.scan_pickle_stream(_BS_INST_SYSTEM)
    if res["verdict"] == "clean" and not res["findings"]:
        return ("BREAK",
                "F255: INST os.system admitted clean -- the sink hides in "
                "the INST argument (no GLOBAL opcode), never inspected")
    return "HELD", "INST sink flagged: %s" % (res["verdict"],)


def b03_obj_sink_not_refused():
    """F255: OBJ + os.system (no REDUCE) is advisory, never refused."""
    res = bundle_scan.scan_pickle_stream(_BS_OBJ_SYSTEM)
    codes = [f["code"] for f in res["findings"]]
    if res["verdict"] != "refuse":
        return ("BREAK",
                "F255: OBJ os.system -> %s %s (advisory, not refused); "
                "the sink rule only fires on REDUCE" % (res["verdict"],
                                                        codes))
    return "HELD", "OBJ sink refused"


def b04_reduce_sink_refused():
    res = bundle_scan.scan_pickle_stream(_bs_reduce_evil())
    codes = [f["code"] for f in res["findings"]]
    if res["verdict"] == "refuse" and any(
            c in ("bundlescan-rce-global", "bundlescan-sink-global")
            for c in codes):
        return "HELD", "REDUCE sink refused (%s)" % (codes,)
    return "BREAK", "REDUCE sink NOT refused: %r %r" % (res["verdict"],
                                                       codes)


def b05_mangled_getattr_advisory():
    """Honest-limit pin: name-mangled gadget -> advisory, never a
    claimed RCE catch."""
    res = bundle_scan.scan_pickle_stream(_bs_mangled_getattr())
    if res["verdict"] == "advisory":
        return "HELD", "mangled gadget advisory (honest limit pinned)"
    return "ERROR", "unexpected verdict: %r" % (res["verdict"],)


def b06_truncated_malformed():
    res = bundle_scan.scan_pickle_stream(_bs_truncated())
    codes = [f["code"] for f in res["findings"]]
    if res["verdict"] == "refuse" and\
            "bundlescan-malformed" in codes:
        return "HELD", "truncated stream refused bundlescan-malformed"
    return "ERROR", "unexpected: %r %r" % (res["verdict"], codes)


def b07_benign_clean():
    import datetime
    res = bundle_scan.scan_pickle_stream(
        pickle.dumps(datetime.datetime(2026, 1, 1), protocol=2))
    if res["verdict"] == "clean":
        return "HELD", "benign datetime clean"
    return "BREAK", "benign false-denial: %r" % (res["verdict"],)


# ---------------------------------------------------------------------------
# evidence_certs provisioner probes
# ---------------------------------------------------------------------------

_EC_NOW = 1790860000
_EC_ARC = "1.3.6.1.4.1.99999"
_EC_PROV_OID = _EC_ARC + ".1.40"
_EC_ISSUER = "https://issuer.example.com"
_EC_APPROVAL = "a" * 32
_EC_INTENT = "b" * 64
_EC_POP_DOMAIN = b"evcert-pop-v1"


def _ec_keypair(seed_byte):
    seed = bytes([seed_byte & 0xFF]) * 32
    return seed, _ed.publickey(seed)


def _ec_make_ca(tmpdir, provisioners=None, **over):
    from gov.kms import FakeKmsProvider
    fake = FakeKmsProvider(["ca-key-1"])
    kw = dict(
        kms_provider=fake,
        ca_key_id="ca-key-1",
        ca_public_key=fake.test_signing_public_key("ca-key-1"),
        issuers=[_EC_ISSUER],
        approval_lookup={_EC_APPROVAL: {"decider": "alice",
                                       "state": "pending"}}.get,
        audit_log_path=os.path.join(tmpdir, "audit.jsonl"),
        anchor_reachable=lambda: True,
        oid_arc=_EC_ARC,
        now=lambda: _EC_NOW)
    if provisioners is not None:
        kw["provisioners"] = provisioners
    kw.update(over)
    return ec.EvidenceCA(**kw)


def _ec_issue(ca, seed_byte=0x01, lifetime_s=None, provisioner=None):
    seed, pub = _ec_keypair(seed_byte)
    chal = (_EC_POP_DOMAIN + _EC_APPROVAL.encode("utf-8")
            + hashlib.sha256(pub).digest())
    req = {"identity_assertion": {"iss": _EC_ISSUER, "sub": "alice",
                                  "exp": _EC_NOW + 3600},
           "ephemeral_pub": pub,
           "pop_sig": _ed.sign(seed, chal),
           "approval_id": _EC_APPROVAL,
           "intent_digest": _EC_INTENT}
    if lifetime_s is not None:
        req["lifetime_s"] = lifetime_s
    if provisioner is not None:
        req["provisioner"] = provisioner
    return ca.issue(**req)


def _ec_refused_with(fn, *codes):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", None) in codes:
            return "HELD", "refused %s" % getattr(exc, "code")
        return "ERROR", "code=%r" % getattr(exc, "code", None)
    return "BREAK", "not refused"


def e01_widening_refused_at_construction():
    try:
        _ec_make_ca(_TMP, provisioners={
            "p": {"min_s": 60, "default_s": 60, "max_s": 7200}},
            max_lifetime_s=3600)
    except ValueError as exc:
        return "HELD", "widening max refused: %s" % (exc,)
    return "BREAK", "widening provisioner max accepted at construction"


def e02_min_under_global_floor():
    try:
        _ec_make_ca(_TMP, provisioners={
            "p": {"min_s": 30, "default_s": 60, "max_s": 3600}})
    except ValueError as exc:
        return "HELD", "sub-floor min refused: %s" % (exc,)
    return "BREAK", "provisioner min under global floor accepted"


def e03_classless_ca_named_provisioner():
    ca = _ec_make_ca(_TMP)
    return _ec_refused_with(
        lambda: _ec_issue(ca, provisioner="p"),
        "evcert-malformed-request")


def e04_class_ca_unknown_provisioner():
    ca = _ec_make_ca(_TMP, provisioners={
        "p": {"min_s": 60, "default_s": 300, "max_s": 900}})
    return _ec_refused_with(
        lambda: _ec_issue(ca, provisioner="nope"),
        "evcert-malformed-request")


def e05_tier_confusion():
    """lifetime inside the GLOBAL bounds but outside the class bounds
    must fail with the class code, not the global code."""
    ca = _ec_make_ca(_TMP, provisioners={
        "p": {"min_s": 60, "default_s": 300, "max_s": 900}})
    held, note = _ec_refused_with(
        lambda: _ec_issue(ca, lifetime_s=1800, provisioner="p"),
        "evcert-provisioner-policy-violated")
    if held != "HELD":
        return held, note
    # And a lifetime inside the class bounds issues fine.
    cert, _ = _ec_issue(ca, seed_byte=0x02, lifetime_s=600,
                        provisioner="p")
    if cert["not_after"] - cert["not_before"] == 600:
        return "HELD", "class bounds enforced with class code; in-class ok"
    return "ERROR", "lifetime wrong: %r" % (cert,)


def e06_class_default_applies():
    ca = _ec_make_ca(_TMP, provisioners={
        "p": {"min_s": 60, "default_s": 300, "max_s": 900}})
    cert, _ = _ec_issue(ca, seed_byte=0x03, provisioner="p")
    if cert["not_after"] - cert["not_before"] == 300:
        return "HELD", "class default lifetime applied"
    return "BREAK", "class default not applied: %r" % (cert,)


def e07_oid_140_recorded():
    ca = _ec_make_ca(_TMP, provisioners={
        "p": {"min_s": 60, "default_s": 300, "max_s": 900}})
    cert, _ = _ec_issue(ca, seed_byte=0x04, provisioner="p")
    ext = cert.get("extensions") or {}
    ca2 = _ec_make_ca(_TMP)
    cert2, _ = _ec_issue(ca2, seed_byte=0x05)
    ext2 = cert2.get("extensions") or {}
    if ext.get(_EC_PROV_OID) == "p" and _EC_PROV_OID not in ext2:
        return "HELD", ".1.40 records the class; classless certs lack it"
    return "BREAK", "OID confusion: %r vs %r" % (ext, ext2)

# ---------------------------------------------------------------------------
# evidence_bundle_v2 probes
# ---------------------------------------------------------------------------

_EB_NOW = 1790860000
_EB_ARC = "1.3.6.1.4.1.99999"
_EB_ISSUER = "https://issuer.example.com"
_EB_APPROVAL = "a" * 32
_EB_INTENT = "b" * 64
_EB_POP_DOMAIN = b"evcert-pop-v1"


def _eb_harness(tmpdir, audit_name="audit.jsonl"):
    from gov.kms import FakeKmsProvider
    fake = FakeKmsProvider(["ca-key-1"])
    ca_pub = fake.test_signing_public_key("ca-key-1")
    ca = ec.EvidenceCA(
        kms_provider=fake, ca_key_id="ca-key-1", ca_public_key=ca_pub,
        issuers=[_EB_ISSUER],
        approval_lookup={_EB_APPROVAL: {"decider": "alice",
                                       "state": "pending"}}.get,
        audit_log_path=os.path.join(tmpdir, audit_name),
        anchor_reachable=lambda: True, oid_arc=_EB_ARC,
        now=lambda: _EB_NOW)
    return ca, ca_pub


def _eb_issue(ca, seed_byte=0x01):
    seed = bytes([seed_byte]) * 32
    pub = _ed.publickey(seed)
    chal = (_EB_POP_DOMAIN + _EB_APPROVAL.encode("utf-8")
            + hashlib.sha256(pub).digest())
    req = {"identity_assertion": {"iss": _EB_ISSUER, "sub": "alice",
                                  "exp": _EB_NOW + 3600},
           "ephemeral_pub": pub,
           "pop_sig": _ed.sign(seed, chal),
           "approval_id": _EB_APPROVAL,
           "intent_digest": _EB_INTENT}
    cert, _ = ca.issue(**req)
    return cert, seed


def _eb_canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _eb_sealed(tmpdir, seed_byte=0x01, body=None):
    ca, ca_pub = _eb_harness(tmpdir)
    cert, seed = _eb_issue(ca, seed_byte)
    body = {"event": "w271-probe", "n": seed_byte} if body is None else body
    sig = _ed.sign(seed, _eb_canonical(body))
    sealed = eb2.seal_evidence(
        artifact_body=body, cert=cert, artifact_signature=sig,
        approval_id=_EB_APPROVAL, intent_digest=_EB_INTENT,
        ca_public_key=ca_pub, verify_time=_EB_NOW)
    return sealed, ca_pub, os.path.join(tmpdir, "audit.jsonl")


def _eb_refused_with(fn, *codes):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", None) in codes:
            return "HELD", "refused %s" % getattr(exc, "code")
        return "ERROR", "code=%r" % getattr(exc, "code", None)
    return "BREAK", "not refused"


def v01_unauthorized_producer():
    sealed, _, _ = _eb_sealed(_TMP, seed_byte=0x11)
    digest = sealed["artifact"]["artifact_digest"]
    log = eb2.make_log(
        producer_auth_verifier=eb2.default_producer_auth_verifier)
    h1, _ = _eb_refused_with(
        lambda: log.submit(digest, producer_auth=None),
        "evbundle-unauthorized-producer")
    if h1 != "HELD":
        return h1, "bare digest not refused"
    h2, _ = _eb_refused_with(
        lambda: log.submit(digest, producer_auth={"kind": "bogus"}),
        "evbundle-unauthorized-producer")
    return (h2, "forged auth refused"
            if h2 == "HELD" else "forged auth: " + h2)


def v02_inclusion_forgery():
    sealed, ca_pub, audit = _eb_sealed(_TMP, seed_byte=0x12)
    digest = sealed["artifact"]["artifact_digest"]
    log = eb2.make_log(
        producer_auth_verifier=eb2.default_producer_auth_verifier,
        now=lambda: _EB_NOW)
    auth = {"kind": "evidence-cert",
            "cert": sealed["cert"],
            "artifact_bytes": _eb_canonical(sealed["artifact"]["body"]),
            "artifact_signature": base64.b64decode(
                sealed["signature_attestation"]["signature"]),
            "approval_id": _EB_APPROVAL, "intent_digest": _EB_INTENT,
            "ca_public_key": ca_pub, "verify_time": _EB_NOW}
    receipt = log.submit(digest, producer_auth=auth)
    bad = json.loads(json.dumps(receipt))
    bad["inclusion_proof"]["hashes"] = ["ff" * 32]
    checkpoint = {"log_id": bad["log_id"], "tree_size": bad["tree_size"],
                  "root": bad["root"],
                  "integrated_time": bad["integrated_time"]}
    return _eb_refused_with(
        lambda: log.verify_inclusion(digest, bad["inclusion_proof"],
                                     checkpoint),
        "evbundle-inclusion-unverified")


def v03_checkpoint_inconsistency():
    log = eb2.make_log(
        producer_auth_verifier=eb2.default_producer_auth_verifier,
        now=lambda: _EB_NOW)
    ca, ca_pub = _eb_harness(_TMP, audit_name="audit-v03.jsonl")
    digests = []
    for i, sb_ in enumerate((0x13, 0x14)):
        cert, seed = _eb_issue(ca, sb_)
        body = {"v03": i}
        sig = _ed.sign(seed, _eb_canonical(body))
        sealed = eb2.seal_evidence(
            artifact_body=body, cert=cert, artifact_signature=sig,
            approval_id=_EB_APPROVAL, intent_digest=_EB_INTENT,
            ca_public_key=ca_pub, verify_time=_EB_NOW)
        digest = sealed["artifact"]["artifact_digest"]
        auth = {"kind": "evidence-cert", "cert": cert,
                "artifact_bytes": _eb_canonical(body),
                "artifact_signature": sig,
                "approval_id": _EB_APPROVAL, "intent_digest": _EB_INTENT,
                "ca_public_key": ca_pub, "verify_time": _EB_NOW}
        log.submit(digest, producer_auth=auth)
        digests.append(digest)
    cp1 = {"log_id": "inprocess", "tree_size": 1,
           "root": log._root(1), "integrated_time": _EB_NOW}
    cp2 = {"log_id": "inprocess", "tree_size": 2,
           "root": log._root(2), "integrated_time": _EB_NOW}
    # Shrinking history must fail.
    return _eb_refused_with(
        lambda: log.verify_consistency(cp2, cp1),
        "evbundle-consistency-invalid")


def v04_join_mismatch():
    sealed, ca_pub, audit = _eb_sealed(_TMP, seed_byte=0x15)
    bad = json.loads(json.dumps(sealed))
    bad["signature_attestation"]["artifact_digest"] = "00" * 32
    return _eb_refused_with(
        lambda: eb2.verify_sealed_bundle(
            sealed=bad, audit_log_path=audit, ca_public_key=ca_pub,
            verify_time=_EB_NOW),
        "evbundle-join-mismatch")


def v05_forged_attestation_signature():
    sealed, ca_pub, audit = _eb_sealed(_TMP, seed_byte=0x16)
    bad = json.loads(json.dumps(sealed))
    bad["signature_attestation"]["signature"] = base64.b64encode(
        b"\x00" * 64).decode("ascii")
    try:
        eb2.verify_sealed_bundle(sealed=bad, audit_log_path=audit,
                                 ca_public_key=ca_pub,
                                 verify_time=_EB_NOW)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", "")
        if isinstance(code, str) and code.startswith("evcert-"):
            return "HELD", "forged attestation sig -> %s" % code
        return "ERROR", "code=%r" % (code,)
    return "BREAK", "forged attestation signature verified"


def v06_detached_issuance():
    # Cert issued against a DIFFERENT audit log: the seal verifies,
    # but the issuance join against this log must fail.
    other = tempfile.mkdtemp(prefix="g271-eb-other-", dir="/var/tmp")
    sealed, ca_pub, _ = _eb_sealed(other, seed_byte=0x17)
    audit = os.path.join(_TMP, "audit-v06.jsonl")
    open(audit, "a").close()
    return _eb_refused_with(
        lambda: eb2.verify_sealed_bundle(
            sealed=sealed, audit_log_path=audit, ca_public_key=ca_pub,
            verify_time=_EB_NOW),
        "evbundle-issuance-unverifiable")


# ---------------------------------------------------------------------------
# output_ifc F252 re-probe (pin the closure; do NOT re-file)
# ---------------------------------------------------------------------------

_IFC_NOW = "2026-10-01T10:00:00Z"
_IFC_PRIV = {"declassification": ["credential"],
             "endorsement": ["user-verified"]}
_IFC_AUTH = {"kind": "human-approval", "ref": "appr-f252"}


def _ifc_grant(registry=None):
    return ifc.issue_grant(privilege=_IFC_PRIV, granted_by="officer",
                           authorization=_IFC_AUTH, ttl_seconds=3600,
                           now=_IFC_NOW, registry=registry)


def _ifc_forge():
    body = {
        "v": 1,
        "privilege": {
            "declassification": sorted(
                _IFC_PRIV.get("declassification", [])),
            "endorsement": sorted(_IFC_PRIV.get("endorsement", [])),
        },
        "granted_by": "attacker",
        "authorization": {"kind": "human-approval", "ref": "fake"},
        "issued_at": _IFC_NOW,
        "expires_at": "2026-10-01T11:00:00Z",
    }
    grant = dict(body)
    grant["grant_digest"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True).encode("utf-8")).hexdigest()
    return grant


def _ifc_label():
    return {"secrecy": [], "integrity": ["tool-external"]}


def _ifc_audit():
    records = []

    def hook(record):
        records.append(record)
    return hook


def _ifc_refused_with(fn, *codes):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", None) in codes:
            return "HELD", "refused %s" % getattr(exc, "code")
        return "ERROR", "code=%r" % getattr(exc, "code", None)
    return "BREAK", "not refused"


def f01_forged_grant_unissued():
    """F252 close-when: a self-minted grant with a VALID public digest
    is refused as unissued (not as tampered)."""
    forged = _ifc_forge()
    h, note = _ifc_refused_with(
        lambda: ifc.exercise_privilege(
            forged, _ifc_label(), "declassify", ["credential"],
            _ifc_audit(), _IFC_NOW),
        "ifc-grant-unissued")
    if h != "HELD":
        return h, "F252 REGRESSION: " + note
    return "HELD", "F252 holds: forged grant -> ifc-grant-unissued"


def f02_revoked_grant_refuses():
    reg = ifc.IssuanceRegistry()
    grant = _ifc_grant(registry=reg)
    reg.revoke(grant["grant_digest"])
    h, note = _ifc_refused_with(
        lambda: ifc.exercise_privilege(
            grant, _ifc_label(), "declassify", ["credential"],
            _ifc_audit(), _IFC_NOW, registry=reg),
        "ifc-grant-unissued")
    if h != "HELD":
        return h, "revoked grant not refused: " + note
    return "HELD", "revoked grant refuses like never-issued"


def f03_issued_grant_exercises():
    grant = _ifc_grant()
    out = ifc.exercise_privilege(
        grant, _ifc_label(), "declassify", ["credential"],
        _ifc_audit(), _IFC_NOW)
    if out.get("label") is not None:
        return "HELD", "issued grant exercises (control)"
    return "ERROR", "exercise failed: %r" % (out,)

# ---------------------------------------------------------------------------
# cross-seam trajectories
# ---------------------------------------------------------------------------

def x01_grant_without_approval():
    """The grant layer never sees the approval ceremony: a grant issued
    with no ceremony involvement enforces fine. Layering pin -- the
    deployment (not the grant) binds approvals to issuance."""
    grant = _tg_grant([_tg_details()])
    store = tool_grant.UsageStore()
    r = tool_grant.enforce(grant, proof=_tg_proof(grant, nonce="x01-n1"),
                           **_tg_env(store))
    if r["code"] == "ptgrant-ok":
        return ("HELD",
                "grant layer is approval-agnostic by design; approval "
                "binding is the deployment's job, not the grant's")
    return "ERROR", "unexpected: %r" % r["code"]


_X02_LAYOUT_ID = "skill/w271-inst-v1"
_X02_CMD = ["fetch-skill", "--src", "skill-src.zip"]
_X02_D1 = hashlib.sha256(b"skill-src-bytes").hexdigest()


def _x02_keys():
    a_seed = _seed(0xC1)
    s_seed = _seed(0xC2)
    return (a_seed, _ed.publickey(a_seed).hex(),
            s_seed, _ed.publickey(s_seed).hex())


def _x02_admit(payload):
    a_seed, a_pub, s_seed, s_pub = _x02_keys()
    digest = hashlib.sha256(payload).hexdigest()
    layout = sa.make_layout(
        _X02_LAYOUT_ID,
        steps=[{"name": "fetch", "command": list(_X02_CMD),
                "signer_pub": s_pub,
                "rules": [("REQUIRE", "skill-src.zip"),
                          ("MATCH", "skill.tar.gz", digest),
                          ("DISALLOW",)]}],
        layout_seed=a_seed)
    link = sa.make_link(
        _X02_LAYOUT_ID, "fetch", list(_X02_CMD),
        materials={"skill-src.zip": _X02_D1},
        products={"skill.tar.gz": digest},
        signer_seed=s_seed)
    return sa.admit(layout, [link], a_pub,
                    artifact_bytes={"skill.tar.gz": payload})


def x02a_inst_payload_admitted():
    """F255 blast radius: an INST os.system payload sails through the
    registry's content scan -- admitted, not refused."""
    verdict = _x02_admit(_BS_INST_SYSTEM)
    if verdict["admitted"] is True:
        return ("BREAK",
                "F255 cross-seam: INST os.system payload ADMITTED by "
                "skill admission (scanner clean) -- the registry would "
                "ingest a load-time RCE")
    return "HELD", "INST payload refused: %s" % verdict["code"]


def x02b_reduce_payload_refused():
    """Control: the REDUCE os.system payload is refused at admission."""
    verdict = _x02_admit(_bs_reduce_evil())
    if verdict["admitted"] is False\
            and verdict["code"] == "bundlescan-rce-global":
        return "HELD", "REDUCE payload refused bundlescan-rce-global"
    return "BREAK", "REDUCE payload NOT refused: %r" % (verdict,)


def _x03_session(sid, signer, provider):
    return sb.Session(sid, signer, signer.public_key, provider)


def x03a_presentation_wrong_session():
    """A session-bound presentation does not verify in another
    session."""
    signer = Ed25519Signer(_seed(0xD1))
    provider = sb.StaticVerifierProvider(
        {signer.key_id: Ed25519Verifier(signer.public_key,
                                       key_id=signer.key_id)})
    sess_a = _x03_session("sess-A", signer, provider)
    sess_b = _x03_session("sess-B", signer, provider)
    sealed, _, _ = _eb_sealed(_TMP, seed_byte=0x21)
    digest = sealed["artifact"]["artifact_digest"]
    pres = sess_a.present(digest, _EB_NOW, 600, b"w271-nonce-1")
    v_ok = sess_a.verify_presentation(pres, digest, _EB_NOW)
    v_wrong = sess_b.verify_presentation(pres, digest, _EB_NOW)
    if v_ok["ok"] is True and v_wrong["ok"] is False\
            and v_wrong["code"] == "sessbind-malformed":
        return "HELD", "presentation verifies in-session; refused cross-session"
    return "BREAK", "binding failure: %r / %r" % (v_ok, v_wrong)


def x03b_stale_presentation_after_transcript_advance():
    """A presentation binds the transcript digest at mint time: after
    the transcript advances, the old presentation fails closed."""
    signer = Ed25519Signer(_seed(0xD2))
    provider = sb.StaticVerifierProvider(
        {signer.key_id: Ed25519Verifier(signer.public_key,
                                       key_id=signer.key_id)})
    sess = _x03_session("sess-C", signer, provider)
    digest = "cd" * 32
    pres = sess.present(digest, _EB_NOW, 600, b"w271-nonce-2")
    sess.append_record("agent", b"transcript advanced")
    v = sess.verify_presentation(pres, digest, _EB_NOW)
    if v["ok"] is False and v["code"] == "sessbind-transcript-mismatch":
        return "HELD", "stale presentation fails closed on transcript drift"
    return "BREAK", "stale presentation accepted: %r" % (v,)


# ---------------------------------------------------------------------------
# green checks (depth-1; honor GOV_SKIP_GREEN=1)
# ---------------------------------------------------------------------------

_GREEN_BATTERIES = [
    "w270_bundlescan_probes.py",
    "w270_ceremony_probes.py",
    "w270_evbundle_probes.py",
    "w270_evcert_provisioner_probes.py",
    "w270_f252_probes.py",
    "w270_ptgrant_probes.py",
]


def _green_checks():
    if GREEN_SKIP:
        return [("green", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 convention)")]
    notes = []
    evals_dir = os.path.join(REPO, "evals")
    for battery in _GREEN_BATTERIES:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        try:
            proc = subprocess.run(
                [sys.executable, os.path.join(evals_dir, battery)],
                env=env, cwd=REPO, capture_output=True, text=True,
                timeout=600)
            tail = (proc.stdout or "").strip().splitlines()[-3:]
            ok = proc.returncode == 0
            notes.append((
                "green", "HELD" if ok else "BREAK",
                "%s rc=%d: %s" % (battery, proc.returncode,
                                  " | ".join(tail))))
        except Exception as exc:  # noqa: BLE001
            notes.append(("green", "ERROR",
                          "%s: %s" % (battery, exc)))
    return notes


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

_PROBES = [
    # (id, expected, fn)
    ("pin-taxonomy", "HELD", _pin_check),
    # tool_grant: F253 + F254 are CLOSED (wave-272 lane) -- r01/r02/r03
    # now pin the closures as HELD; F255 (b01/b02/b03/x02a) still BREAKs.
    ("r01-replay-burns-budget", "HELD", r01_replay_burns_budget),
    ("r02-default-nonce-collides", "HELD", r02_default_nonce_collides),
    ("r03-default-nonce-2nd-call-refused", "HELD",
     r03_default_nonce_second_call_refused),
    ("r04-stale-mandate", "HELD", r04_stale_mandate_version),
    ("r05-unknown-predicate", "HELD", r05_unknown_predicate_refused),
    ("r06-max-calls-edge", "HELD", r06_max_calls_edge),
    ("r07-attenuate-no-cnf", "HELD", r07_attenuate_without_cnf_key),
    ("r08-link-tampering", "HELD", r08_link_digest_tampering),
    ("r09-forged-proof", "HELD", r09_forged_proof_signature),
    # approval ceremony
    ("c01-id-confusion-verdicts", "HELD", c01_id_confusion_verdicts),
    ("c02-verdict-not-allowed", "HELD", c02_verdict_not_allowed),
    ("c03-stale-lineage", "HELD", c03_stale_lineage),
    ("c04-consumed-not-refired", "HELD", c04_consumed_not_refired),
    ("c05-once-token", "HELD", c05_once_token_no_replay),
    ("c06-once-token-across-fork", "HELD", c06_once_token_across_fork),
    ("c07-receipt-forgery", "HELD", c07_receipt_forgery),
    ("c08-unregistered-reviewer", "HELD", c08_receipt_unregistered_reviewer),
    ("c09-wrong-payload-binding", "HELD", c09_receipt_wrong_payload_binding),
    ("c10-ambiguous-resume", "HELD", c10_ambiguous_resume),
    ("c11-bare-dict-schema", "HELD", c11_bare_dict_schema_refused),
    ("c12-no-schema-passthrough", "HELD", c12_no_schema_passthrough),
    ("c13-unknown-approval", "HELD", c13_unknown_approval),
    ("c14-double-resume", "HELD", c14_double_resume),
    # bundle_scan: F255 closed 2026-10-01 (wave-272): b01 flagged
    # (advisory, not clean), b02/b03/x02a now refuse; b04-b07 unchanged.
    ("b01-inst-executes-clean", "HELD", b01_inst_executes_but_clean),
    ("b02-inst-sink-clean", "HELD", b02_inst_sink_admitted),
    ("b03-obj-sink-not-refused", "HELD", b03_obj_sink_not_refused),
    ("b04-reduce-sink-refused", "HELD", b04_reduce_sink_refused),
    ("b05-mangled-advisory", "HELD", b05_mangled_getattr_advisory),
    ("b06-truncated", "HELD", b06_truncated_malformed),
    ("b07-benign", "HELD", b07_benign_clean),
    # evidence-cert provisioner classes
    ("e01-widening-refused", "HELD", e01_widening_refused_at_construction),
    ("e02-min-under-floor", "HELD", e02_min_under_global_floor),
    ("e03-classless-named", "HELD", e03_classless_ca_named_provisioner),
    ("e04-class-unknown", "HELD", e04_class_ca_unknown_provisioner),
    ("e05-tier-confusion", "HELD", e05_tier_confusion),
    ("e06-class-default", "HELD", e06_class_default_applies),
    ("e07-oid-140", "HELD", e07_oid_140_recorded),
    # evidence bundle v2
    ("v01-unauthorized-producer", "HELD", v01_unauthorized_producer),
    ("v02-inclusion-forgery", "HELD", v02_inclusion_forgery),
    ("v03-checkpoint-inconsistency", "HELD",
     v03_checkpoint_inconsistency),
    ("v04-join-mismatch", "HELD", v04_join_mismatch),
    ("v05-forged-attestation-sig", "HELD", v05_forged_attestation_signature),
    ("v06-detached-issuance", "HELD", v06_detached_issuance),
    # output_ifc: F252 re-probe (pin the closure)
    ("f01-forged-grant-unissued", "HELD", f01_forged_grant_unissued),
    ("f02-revoked-grant", "HELD", f02_revoked_grant_refuses),
    ("f03-issued-control", "HELD", f03_issued_grant_exercises),
    # cross-seam
    ("x01-grant-without-approval", "HELD", x01_grant_without_approval),
    ("x02a-inst-payload-admitted", "HELD", x02a_inst_payload_admitted),
    ("x02b-reduce-payload-refused", "HELD", x02b_reduce_payload_refused),
    ("x03a-wrong-session", "HELD", x03a_presentation_wrong_session),
    ("x03b-stale-presentation", "HELD",
     x03b_stale_presentation_after_transcript_advance),
]


def main():
    print("w271 red-team battery: %d probes (TMPDIR=%s)" % (len(_PROBES),
                                                            _TMP))
    failures = 0
    for pid, expected, fn in _PROBES:
        _run(pid, expected, fn)
    for pid, expected, verdict, ok, note in _RESULTS:
        flag = "ok " if ok else "FAIL"
        if not ok:
            failures += 1
        print("[%s] %-34s expected=%-5s got=%-5s %s"
              % (flag, pid, expected, verdict, note))
    print("--- green checks (depth-1) ---")
    for name, verdict, note in _green_checks():
        print("[%s] %s %s" % ("ok " if verdict in ("HELD", "SKIP") else "FAIL",
                              name, note))
        if verdict not in ("HELD", "SKIP"):
            failures += 1
    n_break = sum(1 for r in _RESULTS if r[2] == "BREAK")
    n_held = sum(1 for r in _RESULTS if r[2] == "HELD")
    n_err = sum(1 for r in _RESULTS if r[2] == "ERROR")
    print("probes: %d BREAK / %d HELD / %d ERROR; mismatches: %d"
          % (n_break, n_held, n_err, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
