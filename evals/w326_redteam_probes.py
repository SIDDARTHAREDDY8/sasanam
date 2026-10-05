"""Wave-326 red-team battery (independent red team, lane 5).

Break-first probes against the wave-325 base tree (commit c819b56):
P1 attacks the STANDING-FLIP path (gov/advisory_binding.py +
gov/skill_supply_chain.py) -- forged knowledge injection, flip
suppression, blast-radius poisoning, advisory replay, justification
forgery. P2 re-probes the alert wrapper (gov/monitor_alert.py): F409
is CLOSED (lane 1, wave-326 merge) so P2a must be HELD; F408's P17
must stay HELD. P3 attacks the federated-identity / threshold-VSA /
offline-verifier seams. P4 is the regression section (F409 HELD;
F408/F407/F406 HELD). P5 runs prior batteries in child mode
(GOV_SKIP_GREEN=1). P6 pins the taxonomy (2100) and the footer state.

Filed finding: F411 (MEDIUM) -- federated-mode mint_identity accepts
an unverified dict token_claims, bypassing token authentication
(filed as F410 by lane 5 at 11:29:45 UTC; RENUMBERED F410->F411 at the
wave-326 merge per the wave-272 earliest-filed rule -- lane 4 filed
F410 at 11:19:59 UTC). Probe P3a demonstrates it and is the single
EXPECTED BREAK.

Footer note (wave-305 lesson): the FINDINGS.md footer is now
"open none / next F417" (F414 CLOSED wave-330 lane 1, F415/F416 OPEN
filed wave-330 lane 4). The P5 expected tallies below are the post-merge
tallies with all footer-state probes swept to the final footer.

Every probe is deterministic (fixed seeds, fixed timestamps). The green
check runs adjacent batteries in child mode (GOV_SKIP_GREEN=1) and
honors the skip itself, so nesting stays depth-1.
"""

import copy
import json
import os
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))

TAXONOMY_PIN = 2128 # Wave-339 lane 1: pin 2126 -> 2127 (+1 oci-bundle-not-verifiable).  Wave-327 merge: pin 2035 -> 2044 (+9 policy-channel-*); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)
FOOTER_OPEN = "none"  # All findings CLOSED; F426 closed wave-338 lane 1.
FOOTER_NEXT = "F427"  # Next free finding number.

_results = []
_PROBES = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    return (pid, "HELD", note)


def _break(pid, note):
    return (pid, "BREAK", note)


def probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _safe(pid, fn):
    try:
        _record(*fn())
    except Exception as exc:  # noqa: BLE001
        _record(pid, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3)))


def _expect_code(pid, fn, exc_types, code, note):
    """HELD iff fn() raises one of exc_types with .code == code."""
    try:
        fn()
    except exc_types as exc:
        if exc.code == code:
            return _held(pid, "%s: refused coded %s" % (note, code))
        return _break(pid, "%s: refused coded %s, want %s"
                      % (note, exc.code, code))
    except Exception as exc:  # noqa: BLE001
        return _break(pid, "%s: raised %r, want coded %s" % (note, exc, code))
    return _break(pid, "%s: ACCEPTED, want coded refusal %s" % (note, code))


# ---------------------------------------------------------------------------
# P1: standing-flip path (gov/advisory_binding.py + gov/skill_supply_chain.py).
# ---------------------------------------------------------------------------

def _adv_keypair(seed_byte=11):
    from gov import ed25519 as _ed
    import base64
    seed = bytes([seed_byte]) * 32
    pub = _ed.publickey(seed)
    return seed, pub, base64.b64encode(pub).decode()


def _adv_policy(pub_b64, threshold=1, freshness=3600):
    return {"advisory_policy_input": "test-policy",
            "freshness_seconds": freshness,
            "signature_threshold": threshold,
            "trusted_keys": [pub_b64]}


def _signed_snapshot(flags, version=2, fetched_at=1_700_000_000,
                     seed_byte=11, advisory_id="test-advisory"):
    """Build a signed advisory snapshot (per advisory_binding wire format)."""
    from gov import advisory_binding as ab
    import base64, hashlib
    from gov import ed25519 as _ed
    seed, pub, pub_b64 = _adv_keypair(seed_byte)
    canon = ("advisory|%s|%d|%s" % (advisory_id, version,
                                    sorted(flags.items()))).encode()
    digest = hashlib.sha256(canon).hexdigest()
    sig = _ed.sign(seed, canon)
    return {
        "advisory_id": advisory_id,
        "version": version,
        "issuer": "test-issuer",
        "fetched_at": fetched_at,
        "flags": dict(flags),
        "canonical_bytes": canon,
        "digest": digest,
        "signatures": [{"key": pub_b64,
                        "sig": base64.b64encode(sig).decode()}],
    }


def _pin_snapshot(snapshot, threshold=1, freshness=3600, seed_byte=11):
    from gov import advisory_binding as ab
    _, _, pub_b64 = _adv_keypair(seed_byte)
    policy = _adv_policy(pub_b64, threshold=threshold, freshness=freshness)
    return ab.bind_advisory_input(policy, snapshot, 1_700_000_000)


@probe("P1a-supersede-tie-order-dependent")
def _p1a():
    """Two same-version conflicting snapshots: supersede() refuses LOUD.

    HARDENED (wave-328 lane 2): first-wins made the survivor
    order-dependent. An exact version tie between two DIFFERENT
    presented records is now refused with ``advisory-version-tie`` --
    same-version conflicts must not exist in a well-formed feed, and
    the feed (not the tie-break) is fixed. The identical-object case
    (the same record presented twice) is harmless dedup-able input and
    is NOT refused.
    """
    from gov import advisory_binding as ab
    snap_allow = _signed_snapshot({"pkg-a": "allow"}, version=3)
    snap_flag = _signed_snapshot({"pkg-a": "flagged"}, version=3)
    pinned_allow = _pin_snapshot(snap_allow)
    pinned_flag = _pin_snapshot(snap_flag)
    try:
        ab.supersede([pinned_allow, pinned_flag])
        return _break("P1a-supersede-tie-order-dependent",
                      "same-version tie ACCEPTED (order-dependent survivor)")
    except ab.AdvisoryBindingError as exc:
        if exc.code != "advisory-version-tie":
            return _break("P1a-supersede-tie-order-dependent",
                          "tie refused with wrong code %r" % (exc.code,))
    # Identical object twice: dedup-able, must not refuse.
    try:
        s = ab.supersede([pinned_allow, pinned_allow])
    except ab.AdvisoryBindingError as exc:
        return _break("P1a-supersede-tie-order-dependent",
                      "identical record refused: %r" % (exc.code,))
    # Normal newest-wins still works.
    snap_new = _signed_snapshot({"pkg-a": "flagged"}, version=4)
    pinned_new = _pin_snapshot(snap_new)
    if ab.supersede([pinned_allow, pinned_new]) is not pinned_new:
        return _break("P1a-supersede-tie-order-dependent",
                      "newest-wins regressed")
    return _held("P1a-supersede-tie-order-dependent",
                 "same-version tie refused coded advisory-version-tie; "
                 "dedup + newest-wins intact")


@probe("P1b-forged-advisory-signature-threshold-unmet")
def _p1b():
    """Knowledge injection: snapshot signed by a non-issuer key."""
    from gov import advisory_binding as ab
    # Signed with seed 99, but the pin trusts seed 11's key.
    snap = _signed_snapshot({"pkg-b": "flagged"}, seed_byte=99)
    try:
        pinned = _pin_snapshot(snap, seed_byte=11)
        ab.check_package(pinned, "pkg-b", 1_700_000_100)
    except ab.AdvisoryBindingError as exc:
        if exc.code == "advisory-threshold-unmet":
            return _held("P1b-forged-advisory-signature-threshold-unmet",
                         "forged signature refused coded advisory-threshold-unmet")
        return _held("P1b-forged-advisory-signature-threshold-unmet",
                     "forged signature refused (%s)" % exc.code)
    return _break("P1b-forged-advisory-signature-threshold-unmet",
                  "forged advisory signature ACCEPTED")


@probe("P1c-tampered-flags-digest-mismatch")
def _p1c():
    """Knowledge injection: canonical bytes altered after signing."""
    from gov import advisory_binding as ab
    snap = _signed_snapshot({"pkg-c": "allow"})
    snap["canonical_bytes"] = snap["canonical_bytes"] + b"tampered"
    try:
        _pin_snapshot(snap)
    except ab.AdvisoryBindingError as exc:
        if exc.code == "advisory-malformed":
            return _held("P1c-tampered-flags-digest-mismatch",
                         "tampered bytes refused coded advisory-malformed")
        return _held("P1c-tampered-flags-digest-mismatch",
                     "tampered bytes refused (%s)" % exc.code)
    return _break("P1c-tampered-flags-digest-mismatch",
                  "tampered advisory bytes ACCEPTED")


@probe("P1d-stale-advisory-replay")
def _p1d():
    """Advisory replay: a stale snapshot (beyond freshness) is refused."""
    from gov import advisory_binding as ab
    snap = _signed_snapshot({"pkg-d": "allow"}, fetched_at=1_000_000_000)
    pinned = _pin_snapshot(snap, freshness=3600)
    try:
        ab.check_package(pinned, "pkg-d", 1_700_000_000)
    except ab.AdvisoryBindingError as exc:
        if exc.code == "advisory-chain-source-stale":
            return _held("P1d-stale-advisory-replay",
                         "stale snapshot refused coded advisory-chain-source-stale")
        return _held("P1d-stale-advisory-replay",
                     "stale snapshot refused (%s)" % exc.code)
    return _break("P1d-stale-advisory-replay", "stale advisory ACCEPTED")


@probe("P1e-lifecycle-extra-product-refused")
def _p1e():
    """Blast-radius: a lifecycle link whose products exceed the transition
    spec is refused (no silent blast-radius widening)."""
    from gov import skill_supply_chain as sc
    from gov.signing import Ed25519Signer
    signer = Ed25519Signer(b"w326-p1e-seed".ljust(32, b"0")[:32])
    kid = "k1"
    keys = {kid: {"keytype": "ed25519",
                 "keyval": {"public": signer.public_key.hex()}}}
    layout = {"bundle": "skills/x", "version": 1,
              "expires": "2030-01-01T00:00:00Z",
              "authority": {"keyids": [kid], "threshold": 1},
              "transitions": [
                  {"name": "publish",
                   "signers": {"keyids": [kid], "threshold": 1},
                   "expected_materials": [],
                   "expected_products": [["CREATE", "bundle.tar.gz"]]},
              ]}
    layout_wire = sc.seal_document("layout", layout, [(kid, signer)])
    # Link claims an extra product not in the transition spec.
    link = {"transition": "publish", "materials": {},
            "products": {"bundle.tar.gz": "ab" * 32,
                         "extra-backdoor.tar.gz": "cd" * 32},
            "byproducts": {}, "prev_digest": "0" * 64}
    link_wire = sc.seal_document("link", link, [(kid, signer)])
    try:
        sc.verify_lifecycle(layout_wire, [link_wire], keys, 1_700_000_000.0)
    except sc.SupplyChainError as exc:
        if exc.code == "supplychain-transition-rules-failed":
            return _held("P1e-lifecycle-extra-product-refused",
                         "extra product refused coded supplychain-transition-rules-failed")
        return _held("P1e-lifecycle-extra-product-refused",
                     "extra product refused (%s)" % exc.code)
    except Exception as exc:  # noqa: BLE001
        return _held("P1e-lifecycle-extra-product-refused",
                     "refused (%r)" % (exc,))
    return _break("P1e-lifecycle-extra-product-refused",
                  "extra-product link ACCEPTED")


@probe("P1f-delegation-no-fallthrough")
def _p1f():
    """Justification forgery: the authz statement is signed by a key the
    covering delegation does not authorize -- the failure must NOT fall
    through to another delegation's success. First path-match is
    authoritative."""
    from gov import skill_supply_chain as sc
    from gov.signing import Ed25519Signer
    def _signer(tag):
        return Ed25519Signer((tag + "-seed").ljust(32, "0")[:32].encode())
    r1, p1, mallory = _signer("r1"), _signer("p1"), _signer("mallory")
    def _ki(s):
        return {"keytype": "ed25519",
                "keyval": {"public": s.public_key.hex()}}
    keys = {"r1": _ki(r1), "pay-k1": _ki(p1), "mallory": _ki(mallory)}
    root_trust = {"keys": keys, "root": {"keyids": ["r1"], "threshold": 1}}
    deleg = {"version": 1, "expires": "2030-01-01T00:00:00Z",
             "delegations": [
                 {"name": "payments", "keyids": ["pay-k1"], "threshold": 1,
                  "paths": ["skills/payments/*"], "terminating": False},
                 {"name": "other", "keyids": ["pay-k1"], "threshold": 1,
                  "paths": ["skills/other/*"], "terminating": False},
             ]}
    dwire = sc.seal_document("delegations", deleg, [("r1", r1)])
    # Authz for skills/payments/x signed by MALLORY (not the delegation's key).
    awire = sc.seal_document(
        "link",
        {"skill": "skills/payments/x", "version": 1, "digest": "ab" * 32,
         "expires": "2030-01-01T00:00:00Z"},
        [("mallory", mallory)])
    try:
        sc.verify_delegated_authority(dwire, awire, "skills/payments/x",
                                      root_trust, 1_700_000_000.0)
    except sc.SupplyChainError as exc:
        if exc.code == "supplychain-delegation-signature-invalid":
            return _held("P1f-delegation-no-fallthrough",
                         "forged authz refused coded supplychain-delegation-signature-invalid (no fall-through)")
        return _held("P1f-delegation-no-fallthrough",
                     "forged authz refused (%s)" % exc.code)
    except Exception as exc:  # noqa: BLE001
        return _held("P1f-delegation-no-fallthrough", "refused (%r)" % (exc,))
    return _break("P1f-delegation-no-fallthrough",
                  "mallory-signed authz ACCEPTED")


@probe("P1g-rollback-refused")
def _p1g():
    """Version rollback in the delegation document is refused."""
    from gov import skill_supply_chain as sc
    from gov.signing import Ed25519Signer
    r1 = Ed25519Signer(b"w326-p1g-r1".ljust(32, b"0")[:32])
    keys = {"r1": {"keytype": "ed25519",
                   "keyval": {"public": r1.public_key.hex()}}}
    root_trust = {"keys": keys, "root": {"keyids": ["r1"], "threshold": 1}}
    def _deleg(version):
        doc = {"version": version, "expires": "2030-01-01T00:00:00Z",
               "delegations": [
                   {"name": "t", "keyids": ["r1"], "threshold": 1,
                    "paths": ["skills/t/*"], "terminating": False}]}
        return sc.seal_document("delegations", doc, [("r1", r1)])
    awire = sc.seal_document(
        "link",
        {"skill": "skills/t/x", "version": 1, "digest": "ab" * 32,
         "expires": "2030-01-01T00:00:00Z"},
        [("r1", r1)])
    # First see version 2 (trusted record), then version 1 (rollback).
    trusted = {"delegations_version": 2, "delegations": {"t": 2}}
    try:
        sc.verify_delegated_authority(
            _deleg(1), awire, "skills/t/x", root_trust, 1_700_000_000.0,
            trusted=trusted)
    except sc.SupplyChainError as exc:
        if exc.code == "supplychain-rollback":
            return _held("P1g-rollback-refused",
                         "rollback refused coded supplychain-rollback")
        return _held("P1g-rollback-refused", "refused (%s)" % exc.code)
    except Exception as exc:  # noqa: BLE001
        return _held("P1g-rollback-refused", "refused (%r)" % (exc,))
    return _break("P1g-rollback-refused", "delegation rollback ACCEPTED")


@probe("P1h-handbuilt-pin-inflated-signatures")
def _p1h():
    """Sealed-input lock: check_package refuses hand-built pinned dicts.

    HARDENED (wave-328 lane 2): the pinned snapshot was caller-trusted on
    shape alone, so a hand-built dict with inflated valid_signatures was
    honored. Now only ``bind_advisory_input``-sealed ``PinnedAdvisory``
    records are accepted; anything else is refused LOUD with
    ``advisory-input-unpinned``. The sealed path still verifies normally.
    """
    from gov import advisory_binding as ab
    pinned = {
        "advisory_policy_input": "handbuilt",
        "advisory_id": "handbuilt",
        "version": 9,
        "issuer": "handbuilt",
        "fetched_at": 1_700_000_000,
        "freshness_seconds": 3600,
        "signature_threshold": 1,
        "valid_signatures": 99,  # inflated; caller-asserted
        "flags": {"pkg-h": "allow"},
        "digest": "ab" * 32,
    }
    try:
        ab.check_package(pinned, "pkg-h", 1_700_000_100)
        return _break("P1h-handbuilt-pin-inflated-signatures",
                      "hand-built pinned dict ACCEPTED")
    except ab.AdvisoryBindingError as exc:
        if exc.code != "advisory-input-unpinned":
            return _break("P1h-handbuilt-pin-inflated-signatures",
                          "refused with wrong code %r" % (exc.code,))
    # Sealed path still works.
    sealed = _pin_snapshot(_signed_snapshot({"pkg-h": "allow"}, version=9))
    r = ab.check_package(sealed, "pkg-h", 1_700_000_100)
    if r["verdict"] != "advisory-clear":
        return _break("P1h-handbuilt-pin-inflated-signatures",
                      "sealed path regressed: %r" % (r["verdict"],))
    return _held("P1h-handbuilt-pin-inflated-signatures",
                 "hand-built pin refused coded advisory-input-unpinned; "
                 "sealed path verifies")


# ---------------------------------------------------------------------------
# P2: alert wrapper (gov/monitor_alert.py) -- F409 re-probe + F408 regression.
# Delegates to the wave-325 battery's proven probe functions.
# ---------------------------------------------------------------------------

import w325_redteam_probes as _w325  # noqa: E402


def _relabel(pid, fn):
    _pid, verdict, note = fn()
    return (pid, verdict, note)


@probe("P2a-f409-alert-state-deleted-healthy-window")
def _p2a():
    """F409 (LOW, CLOSED wave-326 lane 1): the re-probe must now be HELD --
    the next outage's 3rd-failure alert is emitted (timestamp-bound
    incident identity), no dedupe collision."""
    return _relabel("P2a-f409-alert-state-deleted-healthy-window",
                    _w325._p1a)


@probe("P2b-f408-p17-stays-held")
def _p2b():
    """F408 (MEDIUM, CLOSED) P17: must stay HELD."""
    return _relabel("P2b-f408-p17-stays-held", _w325._p4a)


# ---------------------------------------------------------------------------
# P3: federated identity / threshold VSA / offline verifier.
# ---------------------------------------------------------------------------

_FI_AUD = "sasanam-policy-engine"
_FI_ISSUER = "test-idp-1"
_FI_NOW = 1_800_000_000


def _fi_keypair(seed_byte=51):
    from gov import ed25519 as _ed
    seed = bytes([seed_byte]) * 32
    return seed, _ed.publickey(seed).hex()


def _fi_setup():
    from gov import federated_identity as fi
    seed, pub = _fi_keypair()
    iss = fi.TokenIssuer(seed, _FI_ISSUER)
    v = fi.TokenVerifier(_FI_AUD)
    v.add_issuer(_FI_ISSUER, pub)
    return fi, iss, v


def _fi_token(iss, now=_FI_NOW, **kw):
    args = dict(agent_id="agent-7", principal="ops", role="reader",
                agent_pubkey_hex=_fi_keypair(52)[1],
                scopes=("read",), now=now)
    args.update(kw)
    return iss.issue_token(**args)


def _fi_executor(verifier):
    """Build a ToolExecutor with federated identity (mirrors w325 dexid)."""
    import sys as _sys
    _sys.path.insert(0, os.path.join(REPO, "tests"))
    from keyfixture import provision_test_key
    provision_test_key(epoch="test")
    from pathlib import Path
    from gov.executor import ToolExecutor
    from gov.policy import PolicyEngine
    from gov.log import ActionLog
    from gov.approvals import ApprovalQueue
    run_dir = Path(tempfile.mkdtemp(prefix="govw326-"))
    (run_dir / "policy.yaml").write_text(
        "version: 2\nroles:\n  operator: [read_file]\npolicies:\n"
        "  - id: allow-all\n    effect: allow\n    match:\n"
        "      tool: [read_file]\n    reason: w326 fixture\n")
    policy = PolicyEngine(str(run_dir / "policy.yaml"))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    kw = dict(ledger_path=run_dir / "egress_ledger.jsonl",
              ungoverned_ack="w326 redteam: synthetic executor")
    if verifier is not None:
        kw["token_verifier"] = verifier
    return ToolExecutor(run_dir, policy, log, approvals, **kw)


@probe("P3a-f411-dict-token-claims-bypass")
def _p3a():
    """F411 (MEDIUM, CLOSED 2026-10-04 wave-327 lane 1; filed as F410,
    renumbered at the wave-326 merge):
    federated-mode mint_identity verifies string tokens but TRUSTS a dict
    token_claims as pre-verified (only shape-checked; signatures never
    verified). verify_token returns a plain dict, so the executor cannot
    distinguish verified from forged. Any in-process caller mints any
    identity without a valid token. CLOSED: the executor honors only
    VerifiedTokenClaims from its own verifier (or the token string);
    a plain dict is refused coded identity-token-tampered."""
    import time as _time
    from gov.executor import IdentityTokenError
    fi, iss, v = _fi_setup()
    ex = _fi_executor(v)
    now = _time.time()
    forged = {"iss": _FI_ISSUER, "sub": "attacker-agent",
              "aud": _FI_AUD,
              "iat": int(now), "exp": int(now) + 300,
              "jti": "forged-jti-w326",
              "principal": "victim-principal", "role": "admin",
              "agent_scope": "all"}
    try:
        ident = ex.mint_identity("attacker-agent", "admin",
                                 "victim-principal",
                                 token_claims=dict(forged))
    except IdentityTokenError as exc:
        return _held("P3a-f411-dict-token-claims-bypass",
                     "F411 closed: forged dict refused (%s)" % exc.code)
    return _break("P3a-f411-dict-token-claims-bypass",
                  "F411 reproduces: forged dict minted %s/%s/%s with no valid token"
                  % (ident.agent_id, ident.role, ident.principal))


@probe("P3b-forged-string-token-refused")
def _p3b():
    """Token forgery via string: signature bytes corrupted after issuance."""
    import base64
    fi, iss, v = _fi_setup()
    token = _fi_token(iss)
    h, p, s = token.split(".")
    # Corrupt the signature (flip bits in the decoded bytes).
    sig = bytearray(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
    sig[0] ^= 0xFF
    s_bad = base64.urlsafe_b64encode(bytes(sig)).decode().rstrip("=")
    bad_token = "%s.%s.%s" % (h, p, s_bad)
    try:
        v.verify_token(bad_token, now=_FI_NOW)
    except fi.FederatedIdentityError as exc:
        if exc.code == "identity-token-tampered":
            return _held("P3b-forged-string-token-refused",
                         "corrupted signature refused coded identity-token-tampered")
        return _held("P3b-forged-string-token-refused",
                     "corrupted signature refused (%s)" % exc.code)
    return _break("P3b-forged-string-token-refused",
                  "corrupted-signature token ACCEPTED")


@probe("P3c-unknown-issuer-refused")
def _p3c():
    """Token from an unpinned issuer is refused."""
    fi, iss, v = _fi_setup()
    other_seed, _ = _fi_keypair(77)
    other_iss = fi.TokenIssuer(other_seed, "evil-idp")
    token = _fi_token(other_iss)
    try:
        v.verify_token(token, now=_FI_NOW)
    except fi.FederatedIdentityError as exc:
        if exc.code == "identity-token-issuer-unknown":
            return _held("P3c-unknown-issuer-refused",
                         "unknown issuer refused coded identity-token-issuer-unknown")
        return _break("P3c-unknown-issuer-refused",
                      "refused coded %s" % exc.code)
    return _break("P3c-unknown-issuer-refused", "unknown-issuer token ACCEPTED")


@probe("P3d-expired-token-refused")
def _p3d():
    """Expired token (beyond skew) is refused."""
    fi, iss, v = _fi_setup()
    token = _fi_token(iss, now=_FI_NOW - 10_000)
    try:
        v.verify_token(token, now=_FI_NOW)
    except fi.FederatedIdentityError as exc:
        if exc.code == "identity-token-expired":
            return _held("P3d-expired-token-refused",
                         "expired token refused coded identity-token-expired")
        return _break("P3d-expired-token-refused", "refused coded %s" % exc.code)
    return _break("P3d-expired-token-refused", "expired token ACCEPTED")


@probe("P3e-replay-refused")
def _p3e():
    """Nonce replay: presenting the same token twice is refused."""
    fi, iss, v = _fi_setup()
    token = _fi_token(iss)
    v.verify_token(token, now=_FI_NOW)
    try:
        v.verify_token(token, now=_FI_NOW + 1)
    except fi.FederatedIdentityError as exc:
        if exc.code == "identity-token-replayed":
            return _held("P3e-replay-refused",
                         "replay refused coded identity-token-replayed")
        return _break("P3e-replay-refused", "refused coded %s" % exc.code)
    return _break("P3e-replay-refused", "replayed token ACCEPTED")


@probe("P3f-audience-mismatch-refused")
def _p3f():
    """Token minted for a different audience is refused."""
    fi, iss, v = _fi_setup()
    other_v = fi.TokenVerifier("other-engine")
    other_v.add_issuer(_FI_ISSUER, _fi_keypair()[1])
    token = _fi_token(iss)  # aud = sasanam-policy-engine
    try:
        other_v.verify_token(token, now=_FI_NOW)
    except fi.FederatedIdentityError as exc:
        if exc.code == "identity-token-audience-mismatch":
            return _held("P3f-audience-mismatch-refused",
                         "audience mismatch refused coded identity-token-audience-mismatch")
        return _break("P3f-audience-mismatch-refused",
                      "refused coded %s" % exc.code)
    return _break("P3f-audience-mismatch-refused",
                  "wrong-audience token ACCEPTED")


@probe("P3g-key-binding-mismatch-refused")
def _p3g():
    """Token bound to a different agent key is refused when the caller
    pins an expected binding."""
    fi, iss, v = _fi_setup()
    token = _fi_token(iss)
    try:
        v.verify_token(token, now=_FI_NOW,
                       expected_key_binding="ff" * 32)
    except fi.FederatedIdentityError as exc:
        if exc.code == "identity-token-key-binding-mismatch":
            return _held("P3g-key-binding-mismatch-refused",
                         "key-binding mismatch refused coded identity-token-key-binding-mismatch")
        return _break("P3g-key-binding-mismatch-refused",
                      "refused coded %s" % exc.code)
    return _break("P3g-key-binding-mismatch-refused",
                  "key-binding-mismatched token ACCEPTED")


@probe("P3h-ttl-exceeded-refused")
def _p3h():
    """Token lifetime exceeding the verifier max TTL is refused."""
    fi, iss, v = _fi_setup()
    # Issuer allows long TTLs; the verifier caps at 100s.
    seed, _ = _fi_keypair()
    long_iss = fi.TokenIssuer(seed, _FI_ISSUER, max_ttl=100_000)
    strict_v = fi.TokenVerifier(_FI_AUD, max_ttl_seconds=100)
    _, pub = _fi_keypair()
    strict_v.add_issuer(_FI_ISSUER, pub)
    token = _fi_token(long_iss, ttl_seconds=50_000)
    try:
        strict_v.verify_token(token, now=_FI_NOW)
    except fi.FederatedIdentityError as exc:
        if exc.code == "identity-token-ttl-exceeded":
            return _held("P3h-ttl-exceeded-refused",
                         "over-TTL token refused coded identity-token-ttl-exceeded")
        return _break("P3h-ttl-exceeded-refused",
                      "refused coded %s" % exc.code)
    return _break("P3h-ttl-exceeded-refused", "over-TTL token ACCEPTED")


@probe("P3i-rotation-grace-then-retired")
def _p3i():
    """Rotation: old key verifies during grace, refused after."""
    fi, iss, v = _fi_setup()
    v2 = fi.TokenVerifier(_FI_AUD, rotation_grace_seconds=100)
    seed1, pub1 = _fi_keypair(51)
    seed2, pub2 = _fi_keypair(52)
    v2.add_issuer(_FI_ISSUER, pub1)
    iss1 = fi.TokenIssuer(seed1, _FI_ISSUER)
    tok_old = _fi_token(iss1, now=_FI_NOW)
    v2.rotate_issuer(_FI_ISSUER, pub2, now=_FI_NOW)
    # During grace: verifies.
    try:
        v2.verify_token(tok_old, now=_FI_NOW + 50)
    except fi.FederatedIdentityError as exc:
        return _break("P3i-rotation-grace-then-retired",
                      "old key refused DURING grace: %s" % exc.code)
    # Past grace: refused.
    try:
        v2.verify_token(tok_old, now=_FI_NOW + 10_000)
    except fi.FederatedIdentityError as exc:
        if exc.code == "identity-issuer-key-retired":
            return _held("P3i-rotation-grace-then-retired",
                         "old key verifies in grace, refused coded identity-issuer-key-retired after")
        return _break("P3i-rotation-grace-then-retired",
                      "refused coded %s after grace" % exc.code)
    return _break("P3i-rotation-grace-then-retired",
                  "retired key ACCEPTED past grace")


@probe("P3j-vsa-transplant-refused")
def _p3j():
    """VSA transplant: a packet issued for decision A presented against a
    trust expecting decision B is refused (subject binding)."""
    from gov import vsa_threshold as vt
    from gov.signing import Ed25519Signer
    s1 = Ed25519Signer(b"w326-vsa-s1".ljust(32, b"0")[:32])
    s2 = Ed25519Signer(b"w326-vsa-s2".ljust(32, b"0")[:32])
    dec_a = "aa" * 32
    dec_b = "bb" * 32
    inputs = {"policy": {"uri": "sasanam:policy/governance/v5",
                         "digest": "c" * 64, "policy_id": "governance",
                         "version": 5},
              "artifact_digests": {"decision-packet": dec_a},
              "evidence_references": []}
    verifs = [{"verifier_id": vid, "verdict": "PASSED",
               "verified_levels": ["decision-evidence-complete"],
               "inputs": inputs, "time_verified": "2023-11-14T12:00:00Z"}
              for vid in ("v1", "v2")]
    signers = [{"verifier_id": vid, "key_id": s.key_id, "sign": s.sign}
               for vid, s in (("v1", s1), ("v2", s2))]
    packet = vt.issue_vsa(dec_a, verifs, signers, 2)
    trust = {"verifier_registry": {"v1": [s1.public_key.hex()],
                                   "v2": [s2.public_key.hex()]},
             "expected_subject_digest": dec_b,  # transplant: wrong subject
             "required_level": "decision-evidence-complete",
             "max_age_seconds": 10_000_000,
             "now": 1_700_000_000,
             "policy_currency": {"policy_id": "governance",
                                 "min_version": 5}}
    try:
        vt.verify_vsa(packet, trust)
    except vt.VSAThresholdError as exc:
        return _held("P3j-vsa-transplant-refused",
                     "transplant refused (%s)" % exc.code)
    except Exception as exc:  # noqa: BLE001
        return _held("P3j-vsa-transplant-refused", "refused (%r)" % (exc,))
    return _break("P3j-vsa-transplant-refused",
                  "transplanted VSA packet ACCEPTED")


@probe("P3k-vsa-shared-key-quorum-note")
def _p3k():
    """Registry-hygiene boundary lock: the same key pinned for two verifier
    ids counts twice (distinct verifier ids, not keys). The docstring is
    honest about this; the deployment must not do it. HELD as designed;
    locks the boundary."""
    from gov import vsa_threshold as vt
    from gov.signing import Ed25519Signer
    s1 = Ed25519Signer(b"w326-vsa-k1".ljust(32, b"0")[:32])
    dec = "cc" * 32
    inputs = {"policy": {"uri": "sasanam:policy/governance/v5",
                         "digest": "c" * 64, "policy_id": "governance",
                         "version": 5},
              "artifact_digests": {"decision-packet": dec},
              "evidence_references": []}
    # One signer makes BOTH attestations (v1 and v2), same key.
    # time_verified must be within [now - max_age, now].
    verifs = [{"verifier_id": vid, "verdict": "PASSED",
               "verified_levels": ["decision-evidence-complete"],
               "inputs": inputs, "time_verified": "2023-11-14T12:00:00Z"}
              for vid in ("v1", "v2")]
    signers = [{"verifier_id": vid, "key_id": s1.key_id, "sign": s1.sign}
               for vid in ("v1", "v2")]
    packet = vt.issue_vsa(dec, verifs, signers, 2)
    pub = s1.public_key.hex()
    trust = {"verifier_registry": {"v1": [pub], "v2": [pub]},
             "expected_subject_digest": dec,
             "required_level": "decision-evidence-complete",
             "max_age_seconds": 10_000_000,
             "now": 1_700_000_000,
             "policy_currency": {"policy_id": "governance",
                                 "min_version": 5}}
    try:
        result = vt.verify_vsa(packet, trust)
        if result.get("ok"):
            return _held("P3k-vsa-shared-key-quorum-note",
                         "same-key-two-verifiers counts twice (registry hygiene boundary locked)")
    except Exception as exc:  # noqa: BLE001
        return _break("P3k-vsa-shared-key-quorum-note",
                      "quorum behavior changed: %r" % (exc,))
    return _break("P3k-vsa-shared-key-quorum-note",
                  "quorum behavior changed")


@probe("P3l-string-token-end-to-end-mint")
def _p3l():
    """String token mints the bound identity end-to-end (positive control)."""
    import time as _time
    fi, iss, v = _fi_setup()
    ex = _fi_executor(v)
    now = _time.time()
    token = iss.issue_token(
        agent_id="agent-7", principal="ops", role="reader",
        agent_pubkey_hex=_fi_keypair(52)[1], scopes=("read",), now=now)
    ident = ex.mint_identity("agent-7", "reader", "ops",
                             token_claims=token)
    if (ident.agent_id, ident.role, ident.principal) == ("agent-7", "reader", "ops"):
        return _held("P3l-string-token-end-to-end-mint",
                     "string token mints the bound identity")
    return _break("P3l-string-token-end-to-end-mint",
                  "minted wrong identity %r" % (ident,))


@probe("P3m-tokenless-mint-refused")
def _p3m():
    """Federated mode: tokenless mint is refused (positive control)."""
    from gov.executor import IdentityTokenError
    fi, iss, v = _fi_setup()
    ex = _fi_executor(v)
    try:
        ex.mint_identity("agent-7", "reader", "ops", token_claims=None)
    except IdentityTokenError as exc:
        if exc.code == "identity-token-required":
            return _held("P3m-tokenless-mint-refused",
                         "tokenless mint refused coded identity-token-required")
        return _break("P3m-tokenless-mint-refused",
                      "refused coded %s" % exc.code)
    return _break("P3m-tokenless-mint-refused",
                  "tokenless mint ACCEPTED in federated mode")


# ---------------------------------------------------------------------------
# P4: regression -- F409 (BREAK), F408/F407/F406 (HELD).
# ---------------------------------------------------------------------------

@probe("P4a-f409-closed")
def _p4a():
    """F409 (LOW, CLOSED wave-326 lane 1): re-probe must be HELD."""
    return _relabel("P4a-f409-closed", _w325._p1a)


@probe("P4b-f408-stays-held")
def _p4b():
    return _relabel("P4b-f408-stays-held", _w325._p4a)


@probe("P4c-f407-stays-held")
def _p4c():
    """F407 (LOW, CLOSED): malformed OCI referrers bodies refuse coded."""
    return _relabel("P4c-f407-stays-held", _w325._p4b)


@probe("P4d-f406-stays-held")
def _p4d():
    """F406 (MEDIUM, CLOSED): ProvenanceSink negation-cue near-misses."""
    import w322_redteam_probes as _w322
    return _relabel("P4d-f406-stays-held", _w322._p3a)


# ---------------------------------------------------------------------------
# P5: prior-battery regression (child mode, GOV_SKIP_GREEN=1).
# ---------------------------------------------------------------------------

def _parse_tally(text):
    import re
    m = re.search(r"(\d+)\s+BREAK\s*/\s*(\d+)\s+HELD\s*/\s*(\d+)\s+ERROR",
                  text)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


# Post-merge tallies: all footer-state probes swept to the final footer
# ("open F412 / next F413"), so the child tallies are the clean
# post-closure counts (F409 HELD everywhere). Child mode (GOV_SKIP_GREEN=1).
_GREEN_EVALS = [
    ("w325-resid", "evals/w325_resid_probes.py", (0, 23, 0)),
    ("w325-dexid", "evals/w325_dexid_probes.py", (0, 26, 0)),
    ("w325-redteam", "evals/w325_redteam_probes.py", (0, 46, 0)),
    ("w324-alert", "evals/w324_alert_probes.py", (0, 18, 0)),
    ("w324-offver", "evals/w324_offver_probes.py", (0, 32, 0)),
    ("w324-vsa", "evals/w324_vsa_probes.py", (0, 22, 0)),
]


def _run_green_eval(name, rel, expect):
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tempfile.mkdtemp(prefix="w326-gc-")
    try:
        p = subprocess.run(
            [sys.executable, os.path.join(REPO, rel)],
            env=env, capture_output=True, text=True, timeout=900)
    except Exception as exc:  # noqa: BLE001
        return (name, "ERROR", "spawn failed: %r" % (exc,))
    tally = _parse_tally(p.stdout or "")
    if tally is None:
        return (name, "ERROR",
                "no tally parsed; rc=%s tail=%r"
                % (p.returncode, (p.stdout or "")[-400:]))
    if tally != expect:
        return (name, "BREAK",
                "tally %s != expected %s" % (tally, expect))
    return (name, "HELD", "%s child tally %d/%d/%d (rc=%d)"
            % ((name,) + tally + (p.returncode,)))


def green_check():
    """Run adjacent batteries in child mode. Honors GOV_SKIP_GREEN so
    nesting stays depth-1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD", "skipped (child mode)")
        return
    for name, rel, expect in _GREEN_EVALS:
        _record(*_run_green_eval(name, rel, expect))


@probe("P5a-green-w325-resid")
def _p5a():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5a-green-w325-resid", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[0])
    return ("P5a-green-w325-resid", verdict, note)


@probe("P5b-green-w325-dexid")
def _p5b():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5b-green-w325-dexid", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[1])
    return ("P5b-green-w325-dexid", verdict, note)


@probe("P5c-green-w325-redteam")
def _p5c():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5c-green-w325-redteam", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[2])
    return ("P5c-green-w325-redteam", verdict, note)


@probe("P5d-green-w324-alert")
def _p5d():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5d-green-w324-alert", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[3])
    return ("P5d-green-w324-alert", verdict, note)


@probe("P5e-green-w324-offver")
def _p5e():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5e-green-w324-offver", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[4])
    return ("P5e-green-w324-offver", verdict, note)


@probe("P5f-green-w324-vsa")
def _p5f():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5f-green-w324-vsa", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[5])
    return ("P5f-green-w324-vsa", verdict, note)


# ---------------------------------------------------------------------------
# P6: taxonomy pin + footer state.
# ---------------------------------------------------------------------------

@probe("P6a-pin-taxonomy-2128-sorted")
def _p6a():
    from gov import decision_codes
    codes = list(decision_codes.TAXONOMY)
    if TAXONOMY_PIN != 2128:
        return _break("P6a-pin-taxonomy-2128-sorted",
                      "TAXONOMY_PIN is %r, want 2128" % (TAXONOMY_PIN,))
    if len(codes) != 2128 or codes != sorted(codes):
        return _break("P6a-pin-taxonomy-2128-sorted",
                      "taxonomy size/order drift: n=%d" % (len(codes),))
    return _held("P6a-pin-taxonomy-2128-sorted", "2128/2128/0 sorted")


@probe("P6b-footer-open-none-next-f427")
def _p6b():
    text = open(os.path.join(REPO, "evals/FINDINGS.md")).read()
    import re
    opens = re.findall(r"\*\*Open findings:\s*([^*]+?)\.\*\*", text)
    nexts = re.findall(r"Next free finding:\s*\*\*([^*]+?)\*\*", text)
    open_line = opens[-1].strip() if opens else ""
    next_free = nexts[-1].strip() if nexts else ""
    if open_line != FOOTER_OPEN:
        return _break("P6b-footer-open-none-next-f427",
                      "open findings %r, want %r" % (open_line, FOOTER_OPEN))
    if next_free != FOOTER_NEXT:
        return _break("P6b-footer-open-none-next-f427",
                      "next free %r, want %r" % (next_free, FOOTER_NEXT))
    return _held("P6b-footer-open-none-next-f427",
                 "footer open none / next F419")


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

def main(argv):
    only = argv[1] if len(argv) > 1 else None
    for pid, fn in _PROBES:
        if only is not None and pid != only:
            continue
        _safe(pid, fn)
    if only is None:
        green_check()
    breaks = errors = 0
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "ERROR":
            errors += 1
    print("w326_redteam battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAK expected: F411 closed 2026-10-04 wave-327 lane 1)"
          % (breaks, len(_results) - breaks - errors, errors))
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
