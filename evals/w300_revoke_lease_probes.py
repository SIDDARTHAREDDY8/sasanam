"""Wave-300 lane 4 battery: revocation<->lease fencing wiring.

Base: wave-299 merge a830f65 (verified via git rev-parse HEAD before work).

New product surface:
  gov/coordination_lease.py -- optional delegation_binding on acquire
  (declared at grant time, stored manager-side); check_write enforces
  it: the presented revocation state must show the bound receipt live
  via gov/delegation_revocation (native receipts through
  assert_live_native, local-shape receipts through is_live). A
  delegation-revoked refusal maps onto coord-lease-fencing; a bound
  grant presented WITHOUT revocation state refuses fail-closed
  coord-lease-fencing. No new codes; pin 1797 lane-local (1812 at wave-300 merge).

Red-first: on the pristine base the binding probes BREAK (feature
absent: acquire() takes no delegation_binding kwarg); on the fixed
tree they must HELD with loud coded refusals.

Run:
  mkdir -p /var/tmp/g300-revoke-lease && TMPDIR=/var/tmp/g300-revoke-lease \
    ~/workspace/.gov-venv/bin/python evals/w300_revoke_lease_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g300-revoke-lease2 \
    ~/workspace/.gov-venv/bin/python evals/w300_revoke_lease_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 2069 # Wave-300 lane 4: no new codes (reuse coord-lease-fencing etc.); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*)



_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    dead battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate code literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "code literals not sorted")
    _record("pin-taxonomy", "HELD", "2069/2069/0 sorted")




def _green_check(path, name, tolerate=()):
    if SKIP_GREEN:
        _record("green-%s" % name, "HELD", "skipped via GOV_SKIP_GREEN=1")
        return
    tmp = tempfile.mkdtemp(prefix="g300-green-")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    try:
        out = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=600, env=env, cwd=REPO).stdout
    except Exception as e:  # noqa: BLE001
        return _record("green-%s" % name, "ERROR",
                       "green check crashed: %r" % (e,))
    bad = [ln for ln in out.splitlines()
           if ln.strip().startswith("[BREAK]")
           and not any(t in ln for t in tolerate)]
    if bad:
        _record("green-%s" % name, "BREAK",
                "unexpected breaks: %s" % "; ".join(bad[:5]))
    else:
        _record("green-%s" % name, "HELD", "green check held")


# ---------------------------------------------------------------------------
# Fixtures (deterministic seeds -- no randomness in probes).
# ---------------------------------------------------------------------------

from gov import coordination_lease as cl  # noqa: E402
from gov import delegation as dg  # noqa: E402
from gov import delegation_revocation as rev  # noqa: E402
from gov import ed25519  # noqa: E402

AT = 1_700_000_000
SEED_A = bytes([0x0A]) * 32
SEED_B = bytes([0x0B]) * 32
SEED_C = bytes([0x0C]) * 32
SEED_EVIL = bytes([0xE1]) * 32
PUB_A = ed25519.publickey(SEED_A).hex()
PUB_B = ed25519.publickey(SEED_B).hex()


def _native_receipt(seed, delegator_id, delegatee_id, delegatee_pub,
                    parent=None, issued_at=AT):
    return dg.issue(seed, delegator_id, delegatee_id, delegatee_pub,
                    ["lease.acquire"], parent=parent, issued_at=issued_at)


def _bound_fixture():
    """A live bound grant + working context. Returns
    (mgr, lease, revoker, chain, ctx, binding)."""
    root = _native_receipt(SEED_A, "authority", "holder", PUB_B)
    revoker = rev.DelegationRevoker(SEED_A, "authority")
    binding = {"receipt_id": root["receipt_id"],
               "revocation_list_digest": revoker.list_digest()}
    mgr = cl.LeaseManager()
    lease = mgr.acquire("probe-scope", 3600, "holder",
                        authority_seed=SEED_A, issued_at=AT,
                        delegation_binding=binding)
    ctx = {"revoker": revoker, "chain": [root], "trust_roots": [PUB_A]}
    return mgr, lease, revoker, [root], ctx, binding


def _needs_binding(pid):
    """Red-first gate: on the pristine base acquire() takes no
    delegation_binding kwarg (TypeError) -> record BREAK and skip
    the probe. On the fixed tree the fixture builds normally."""
    try:
        m = cl.LeaseManager()
        m.acquire("probe-feat", 60, "holder", authority_seed=SEED_A,
                  issued_at=AT,
                  delegation_binding={"receipt_id": "00" * 32,
                                      "revocation_list_digest": "00" * 32})
        return True
    except TypeError:
        _record(pid, "BREAK", "feature absent: acquire() takes no "
                "delegation_binding kwarg on pristine base")
        return False


def _expect_code(pid, fn, code):
    try:
        fn()
    except cl.CoordinationLeaseError as e:
        if e.code == code:
            return _record(pid, "HELD", "refused coded %s" % code)
        return _record(pid, "BREAK",
                       "refused with %r, want %r" % (e.code, code))
    except Exception as e:  # noqa: BLE001
        return _record(pid, "ERROR", "unexpected exception: %r" % (e,))
    return _record(pid, "BREAK", "no refusal (want %s)" % code)


# ---------------------------------------------------------------------------
# Probes.
# ---------------------------------------------------------------------------

def p_acquire_stores_binding():
    if not _needs_binding("acquire-stores-binding"):
        return
    mgr, lease, revoker, chain, ctx, binding = _bound_fixture()
    if lease.get("delegation_binding") == binding:
        _record("acquire-stores-binding", "HELD", "binding on record")
    else:
        _record("acquire-stores-binding", "BREAK",
                "binding missing: %r" % (lease.get("delegation_binding"),))


def p_acquire_rejects_malformed_binding():
    if not _needs_binding("acquire-rejects-malformed"):
        return
    mgr = cl.LeaseManager()
    bads = [
        {"receipt_id": "zz", "revocation_list_digest": "00" * 32},
        {"receipt_id": "00" * 32},  # missing digest
        {"receipt_id": "00" * 32, "revocation_list_digest": "00" * 32,
         "extra": 1},  # unknown key
        "not-a-dict",
        42,
    ]
    for i, bad in enumerate(bads):
        try:
            mgr.acquire("bad-%d" % i, 3600, "holder",
                        authority_seed=SEED_A, issued_at=AT,
                        delegation_binding=bad)
            return _record("acquire-rejects-malformed", "BREAK",
                           "accepted %r" % (bad,))
        except cl.CoordinationLeaseError as e:
            if e.code != "coord-lease-invalid":
                return _record("acquire-rejects-malformed", "BREAK",
                               "wrong code %r for %r" % (e.code, bad))
    _record("acquire-rejects-malformed", "HELD",
            "all malformed bindings refused coord-lease-invalid")


def p_live_bound_write():
    if not _needs_binding("live-bound-write"):
        return
    mgr, lease, revoker, chain, ctx, binding = _bound_fixture()
    ok = mgr.check_write("probe-scope", lease["fencing_token"], "holder",
                         checked_at=AT + 10, delegation_context=ctx)
    if ok is True:
        _record("live-bound-write", "HELD", "live receipt authorizes")
    else:
        _record("live-bound-write", "BREAK", "unexpected %r" % (ok,))


def p_revoked_bound_write_fencing():
    if not _needs_binding("revoked-bound-write"):
        return
    mgr, lease, revoker, chain, ctx, binding = _bound_fixture()
    revoker.revoke(chain[0]["receipt_id"], AT + 5)
    _expect_code(
        "revoked-bound-write",
        lambda: mgr.check_write("probe-scope", lease["fencing_token"],
                                "holder", checked_at=AT + 10,
                                delegation_context=ctx),
        "coord-lease-fencing")


def p_newer_list_same_key_live():
    if not _needs_binding("newer-list-same-key"):
        return
    # The delegator revokes an UNRELATED receipt (list grows, digest
    # changes, same key): the bound grant must keep working, and a
    # revocation of OUR receipt in the newer list must fence.
    mgr, lease, revoker, chain, ctx, binding = _bound_fixture()
    other = _native_receipt(SEED_A, "authority", "other", PUB_B)
    revoker.revoke(other["receipt_id"], AT + 5)
    assert revoker.list_digest() != binding["revocation_list_digest"]
    ok = mgr.check_write("probe-scope", lease["fencing_token"], "holder",
                         checked_at=AT + 10, delegation_context=ctx)
    if ok is not True:
        return _record("newer-list-same-key", "BREAK",
                       "newer delegator list broke a live grant")
    revoker.revoke(chain[0]["receipt_id"], AT + 6)
    _expect_code(
        "newer-list-revoked",
        lambda: mgr.check_write("probe-scope", lease["fencing_token"],
                                "holder", checked_at=AT + 10,
                                delegation_context=ctx),
        "coord-lease-fencing")


def p_missing_context_fencing():
    if not _needs_binding("missing-context"):
        return
    mgr, lease, revoker, chain, ctx, binding = _bound_fixture()
    _expect_code(
        "missing-context",
        lambda: mgr.check_write("probe-scope", lease["fencing_token"],
                                "holder", checked_at=AT + 10),
        "coord-lease-fencing")


def p_wrong_type_revoker_fencing():
    if not _needs_binding("wrong-type-revoker"):
        return
    mgr, lease, revoker, chain, ctx, binding = _bound_fixture()
    bad_ctx = dict(ctx, revoker="not-a-revoker")
    _expect_code(
        "wrong-type-revoker",
        lambda: mgr.check_write("probe-scope", lease["fencing_token"],
                                "holder", checked_at=AT + 10,
                                delegation_context=bad_ctx),
        "coord-lease-fencing")


def p_substituted_revoker_invalid():
    if not _needs_binding("substituted-revoker"):
        return
    # Attacker-controlled revoker, EMPTY list: shares the empty-list
    # digest with the legitimate empty list, so a digest-only check
    # would pass. The delegator-key check must refuse.
    mgr, lease, revoker, chain, ctx, binding = _bound_fixture()
    evil = rev.DelegationRevoker(SEED_EVIL, "authority")
    assert evil.list_digest() == revoker.list_digest()  # both empty
    evil_ctx = {"revoker": evil, "chain": chain, "trust_roots": [PUB_A]}
    _expect_code(
        "substituted-revoker",
        lambda: mgr.check_write("probe-scope", lease["fencing_token"],
                                "holder", checked_at=AT + 10,
                                delegation_context=evil_ctx),
        "coord-lease-invalid")


def p_wrong_delegator_revoker_invalid():
    if not _needs_binding("wrong-delegator-revoker"):
        return
    # Attacker's key is in trust_roots but the delegator_id does not
    # match the chain's root delegator.
    mgr, lease, revoker, chain, ctx, binding = _bound_fixture()
    evil_pub = ed25519.publickey(SEED_EVIL).hex()
    evil = rev.DelegationRevoker(SEED_EVIL, "attacker")
    evil_ctx = {"revoker": evil, "chain": chain,
                "trust_roots": [PUB_A, evil_pub]}
    _expect_code(
        "wrong-delegator-revoker",
        lambda: mgr.check_write("probe-scope", lease["fencing_token"],
                                "holder", checked_at=AT + 10,
                                delegation_context=evil_ctx),
        "coord-lease-invalid")


def p_chain_leaf_mismatch_invalid():
    if not _needs_binding("chain-leaf-mismatch"):
        return
    mgr, lease, revoker, chain, ctx, binding = _bound_fixture()
    other = _native_receipt(SEED_A, "authority", "other", PUB_B)
    bad_ctx = dict(ctx, chain=[other])
    _expect_code(
        "chain-leaf-mismatch",
        lambda: mgr.check_write("probe-scope", lease["fencing_token"],
                                "holder", checked_at=AT + 10,
                                delegation_context=bad_ctx),
        "coord-lease-invalid")


def p_revoked_ancestor_fencing():
    if not _needs_binding("revoked-ancestor"):
        return
    mgr = cl.LeaseManager()
    root = _native_receipt(SEED_A, "authority", "holder", PUB_B)
    child = _native_receipt(SEED_B, "holder", "sub",
                            ed25519.publickey(SEED_C).hex(), parent=root)
    revoker = rev.DelegationRevoker(SEED_A, "authority")
    revoker.revoke(root["receipt_id"], AT + 5)  # revoke the ANCESTOR
    binding = {"receipt_id": child["receipt_id"],
               "revocation_list_digest": revoker.list_digest()}
    lease = mgr.acquire("anc-scope", 3600, "sub",
                        authority_seed=SEED_A, issued_at=AT,
                        delegation_binding=binding)
    ctx = {"revoker": revoker, "chain": [root, child],
           "trust_roots": [PUB_A]}
    _expect_code(
        "revoked-ancestor",
        lambda: mgr.check_write("anc-scope", lease["fencing_token"],
                                "sub", checked_at=AT + 10,
                                delegation_context=ctx),
        "coord-lease-fencing")


def p_expired_receipt_maps_expired():
    if not _needs_binding("expired-receipt"):
        return
    # Local-shape receipt outside its validity window: the
    # delegation-expired refusal maps onto coord-lease-expired.
    local = rev.make_receipt(SEED_A, "authority", "holder", None, 0,
                             ["lease.acquire"], AT, AT + 100)
    revoker = rev.DelegationRevoker(SEED_A, "authority")
    mgr = cl.LeaseManager()
    binding = {"receipt_id": local["receipt_id"],
               "revocation_list_digest": revoker.list_digest()}
    lease = mgr.acquire("exp-scope", 3600, "holder",
                        authority_seed=SEED_A, issued_at=AT,
                        delegation_binding=binding)
    ctx = {"revoker": revoker, "chain": [local],
           "keyring": {"authority": PUB_A}}
    _expect_code(
        "expired-receipt",
        lambda: mgr.check_write("exp-scope", lease["fencing_token"],
                                "holder", checked_at=AT + 200,
                                delegation_context=ctx),
        "coord-lease-expired")


def p_forged_chain_signature_invalid():
    if not _needs_binding("forged-chain-signature"):
        return
    # Receipt signature forged (signed by the wrong key): the
    # delegation-signature-invalid refusal maps onto
    # coord-lease-invalid.
    mgr, lease, revoker, chain, ctx, binding = _bound_fixture()
    forged = dict(chain[0])
    forged["signature"] = dg.issue(
        SEED_EVIL, "authority", "holder", PUB_B,
        ["lease.acquire"], issued_at=AT)["signature"]
    bad_ctx = dict(ctx, chain=[forged])
    _expect_code(
        "forged-chain-signature",
        lambda: mgr.check_write("probe-scope", lease["fencing_token"],
                                "holder", checked_at=AT + 10,
                                delegation_context=bad_ctx),
        "coord-lease-invalid")


def p_local_shape_keyring_live():
    if not _needs_binding("local-shape-keyring"):
        return
    local = rev.make_receipt(SEED_A, "authority", "holder", None, 0,
                             ["lease.acquire"], AT, AT + 3600)
    revoker = rev.DelegationRevoker(SEED_A, "authority")
    mgr = cl.LeaseManager()
    binding = {"receipt_id": local["receipt_id"],
               "revocation_list_digest": revoker.list_digest()}
    lease = mgr.acquire("local-scope", 3600, "holder",
                        authority_seed=SEED_A, issued_at=AT,
                        delegation_binding=binding)
    ctx = {"revoker": revoker, "chain": [local],
           "keyring": {"authority": PUB_A}}
    ok = mgr.check_write("local-scope", lease["fencing_token"], "holder",
                         checked_at=AT + 10, delegation_context=ctx)
    if ok is True:
        _record("local-shape-keyring", "HELD", "local receipts work")
    else:
        _record("local-shape-keyring", "BREAK", "unexpected %r" % (ok,))


def p_keyring_wrong_key_invalid():
    if not _needs_binding("keyring-wrong-key"):
        return
    # Caller-supplied keyring naming the attacker's key: receipt
    # signatures fail under it.
    local = rev.make_receipt(SEED_A, "authority", "holder", None, 0,
                             ["lease.acquire"], AT, AT + 3600)
    revoker = rev.DelegationRevoker(SEED_A, "authority")
    mgr = cl.LeaseManager()
    binding = {"receipt_id": local["receipt_id"],
               "revocation_list_digest": revoker.list_digest()}
    lease = mgr.acquire("kr-scope", 3600, "holder",
                        authority_seed=SEED_A, issued_at=AT,
                        delegation_binding=binding)
    evil_pub = ed25519.publickey(SEED_EVIL).hex()
    evil = rev.DelegationRevoker(SEED_EVIL, "authority")
    ctx = {"revoker": evil, "chain": [local],
           "keyring": {"authority": evil_pub}}
    _expect_code(
        "keyring-wrong-key",
        lambda: mgr.check_write("kr-scope", lease["fencing_token"],
                                "holder", checked_at=AT + 10,
                                delegation_context=ctx),
        "coord-lease-invalid")


def p_unbound_legacy_unchanged():
    if not _needs_binding("unbound-legacy"):
        return
    mgr = cl.LeaseManager()
    lease = mgr.acquire("legacy-scope", 3600, "holder",
                        authority_seed=SEED_A, issued_at=AT)
    if lease.get("delegation_binding") is not None:
        return _record("unbound-legacy", "BREAK",
                       "unbound grant carries a binding")
    ok = mgr.check_write("legacy-scope", lease["fencing_token"], "holder",
                         checked_at=AT + 10)
    if ok is not True:
        return _record("unbound-legacy", "BREAK", "legacy write refused")
    # A stray delegation context on an unbound grant is ignored.
    _, _, revoker, chain, ctx, _ = _bound_fixture()
    ok2 = mgr.check_write("legacy-scope", lease["fencing_token"], "holder",
                          checked_at=AT + 10, delegation_context=ctx)
    if ok2 is True:
        _record("unbound-legacy", "HELD", "legacy path byte-identical")
    else:
        _record("unbound-legacy", "BREAK", "stray context broke legacy")


def p_renew_preserves_binding():
    if not _needs_binding("renew-preserves-binding"):
        return
    mgr, lease, revoker, chain, ctx, binding = _bound_fixture()
    renewed = mgr.renew("probe-scope", lease["fencing_token"], "holder",
                        100, authority_seed=SEED_A, checked_at=AT + 10)
    if renewed.get("delegation_binding") != binding:
        return _record("renew-preserves-binding", "BREAK",
                       "binding lost on renew")
    revoker.revoke(chain[0]["receipt_id"], AT + 11)
    _expect_code(
        "renewed-revoked",
        lambda: mgr.check_write("probe-scope",
                                renewed["fencing_token"], "holder",
                                checked_at=AT + 12,
                                delegation_context=ctx),
        "coord-lease-fencing")


def p_redelegated_grant_works():
    if not _needs_binding("redelegated-grant"):
        return
    # After revocation, a NEW receipt (new id) + NEW binding works.
    mgr, lease, revoker, chain, ctx, binding = _bound_fixture()
    revoker.revoke(chain[0]["receipt_id"], AT + 5)
    # A byte-identical re-issuance would reproduce the revoked
    # receipt_id (no resurrection -- monotonic revocation), so the
    # new grant designates a distinct object.
    root2 = dg.issue(SEED_A, "authority", "holder", PUB_B,
                     ["lease.acquire"], designated_object="ab" * 32,
                     issued_at=AT)
    assert root2["receipt_id"] != chain[0]["receipt_id"]
    binding2 = {"receipt_id": root2["receipt_id"],
                "revocation_list_digest": revoker.list_digest()}
    lease2 = mgr.acquire("redeleg-scope", 3600, "holder",
                         authority_seed=SEED_A, issued_at=AT,
                         delegation_binding=binding2)
    ctx2 = {"revoker": revoker, "chain": [root2], "trust_roots": [PUB_A]}
    ok = mgr.check_write("redeleg-scope", lease2["fencing_token"], "holder",
                         checked_at=AT + 10, delegation_context=ctx2)
    if ok is True:
        _record("redelegated-grant", "HELD", "new receipt, new binding")
    else:
        _record("redelegated-grant", "BREAK", "unexpected %r" % (ok,))


def p_verify_lease_ignores_binding():
    if not _needs_binding("verify-lease-binding"):
        return
    mgr, lease, revoker, chain, ctx, binding = _bound_fixture()
    ok, detail = cl.verify_lease(lease, PUB_A, checked_at=AT + 10)
    if ok is True and detail["fencing_token"] == lease["fencing_token"]:
        _record("verify-lease-binding", "HELD",
                "stateless verification unaffected")
    else:
        _record("verify-lease-binding", "BREAK", "unexpected %r" % (detail,))


def p_no_context_neither_mode_invalid():
    if not _needs_binding("no-mode-context"):
        return
    # Context with a revoker + chain but neither trust_roots nor
    # keyring: refused (the mode is undecidable).
    mgr, lease, revoker, chain, ctx, binding = _bound_fixture()
    bad_ctx = {"revoker": revoker, "chain": chain}
    _expect_code(
        "no-mode-context",
        lambda: mgr.check_write("probe-scope", lease["fencing_token"],
                                "holder", checked_at=AT + 10,
                                delegation_context=bad_ctx),
        "coord-lease-invalid")


def _f379_multihop_fixture():
    """A -> B -> C chain bound at the leaf, with per-delegator revokers."""
    pub_c = ed25519.publickey(SEED_C).hex()
    root = _native_receipt(SEED_A, "authority", "holder", PUB_B)
    child = _native_receipt(SEED_B, "holder", "sub", pub_c, parent=root)
    revoker_a = rev.DelegationRevoker(SEED_A, "authority")
    revoker_b = rev.DelegationRevoker(SEED_B, "holder")
    binding = {"receipt_id": child["receipt_id"],
               "revocation_list_digest": revoker_a.list_digest()}
    mgr = cl.LeaseManager()
    lease = mgr.acquire("f379-scope", 3600, "sub",
                        authority_seed=SEED_A, issued_at=AT,
                        delegation_binding=binding)
    ctx = {"revokers": {"authority": revoker_a, "holder": revoker_b},
           "chain": [root, child], "trust_roots": [PUB_A]}
    return mgr, lease, revoker_a, revoker_b, root, child, ctx


def p_f379_multihop_live_mapping():
    if not _needs_binding("f379-multihop-live"):
        return
    # Positive control: multi-hop chain, every delegator's revoker
    # presented, nothing revoked -> the write goes through.
    mgr, lease, ra, rb, root, child, ctx = _f379_multihop_fixture()
    try:
        ok = mgr.check_write("f379-scope", lease["fencing_token"], "sub",
                             checked_at=AT + 10, delegation_context=ctx)
    except cl.CoordinationLeaseError as e:
        return _record("f379-multihop-live", "BREAK",
                       "per-delegator revokers unsupported on pristine "
                       "base (refused %s)" % (e.code,))
    if ok is True:
        _record("f379-multihop-live", "HELD", "multi-hop live write True")
    else:
        _record("f379-multihop-live", "BREAK", "unexpected %r" % (ok,))


def p_f379_intermediate_revocation_fencing():
    if not _needs_binding("f379-intermediate-revocation"):
        return
    # F379 core: B revokes the bound leaf. Before wave-302 only the
    # root's list was consulted, so this write passed (BREAK on the
    # pristine base); now it must fence.
    mgr, lease, ra, rb, root, child, ctx = _f379_multihop_fixture()
    rb.revoke(child["receipt_id"], AT + 5)
    _expect_code(
        "f379-intermediate-revocation",
        lambda: mgr.check_write("f379-scope", lease["fencing_token"],
                                "sub", checked_at=AT + 10,
                                delegation_context=ctx),
        "coord-lease-fencing")


def p_f379_legacy_single_revoker_multihop_fencing():
    if not _needs_binding("f379-legacy-single-multihop"):
        return
    # Legacy single (root) revoker on a multi-hop chain: the
    # intermediate hop's revocation state cannot be shown, so the
    # write fails closed instead of passing on the root's clean
    # list as wave-300 did.
    mgr, lease, ra, rb, root, child, ctx = _f379_multihop_fixture()
    legacy = {"revoker": ra, "chain": [root, child],
              "trust_roots": [PUB_A]}
    _expect_code(
        "f379-legacy-single-multihop",
        lambda: mgr.check_write("f379-scope", lease["fencing_token"],
                                "sub", checked_at=AT + 10,
                                delegation_context=legacy),
        "coord-lease-fencing")


def p_f379_missing_member_revoker_fencing():
    if not _needs_binding("f379-missing-member-revoker"):
        return
    # Mapping without the intermediate delegator's revoker:
    # incomplete revocation state fails closed.
    mgr, lease, ra, rb, root, child, ctx = _f379_multihop_fixture()
    partial = {"revokers": {"authority": ra},
               "chain": [root, child], "trust_roots": [PUB_A]}
    _expect_code(
        "f379-missing-member-revoker",
        lambda: mgr.check_write("f379-scope", lease["fencing_token"],
                                "sub", checked_at=AT + 10,
                                delegation_context=partial),
        "coord-lease-fencing")


def p_f379_mislabeled_mapping_invalid():
    if not _needs_binding("f379-mislabeled-mapping"):
        return
    # A's revoker filed under B's delegator_id: substitution attempt.
    mgr, lease, ra, rb, root, child, ctx = _f379_multihop_fixture()
    bad = {"revokers": {"authority": ra, "holder": ra},
           "chain": [root, child], "trust_roots": [PUB_A]}
    _expect_code(
        "f379-mislabeled-mapping",
        lambda: mgr.check_write("f379-scope", lease["fencing_token"],
                                "sub", checked_at=AT + 10,
                                delegation_context=bad),
        "coord-lease-invalid")


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("acquire-stores-binding", p_acquire_stores_binding)
    _safe("acquire-rejects-malformed", p_acquire_rejects_malformed_binding)
    _safe("live-bound-write", p_live_bound_write)
    _safe("revoked-bound-write", p_revoked_bound_write_fencing)
    _safe("newer-list-same-key", p_newer_list_same_key_live)
    _safe("missing-context", p_missing_context_fencing)
    _safe("wrong-type-revoker", p_wrong_type_revoker_fencing)
    _safe("substituted-revoker", p_substituted_revoker_invalid)
    _safe("wrong-delegator-revoker", p_wrong_delegator_revoker_invalid)
    _safe("chain-leaf-mismatch", p_chain_leaf_mismatch_invalid)
    _safe("revoked-ancestor", p_revoked_ancestor_fencing)
    _safe("expired-receipt", p_expired_receipt_maps_expired)
    _safe("forged-chain-signature", p_forged_chain_signature_invalid)
    _safe("local-shape-keyring", p_local_shape_keyring_live)
    _safe("keyring-wrong-key", p_keyring_wrong_key_invalid)
    _safe("unbound-legacy", p_unbound_legacy_unchanged)
    _safe("renew-preserves-binding", p_renew_preserves_binding)
    _safe("redelegated-grant", p_redelegated_grant_works)
    _safe("verify-lease-binding", p_verify_lease_ignores_binding)
    _safe("no-mode-context", p_no_context_neither_mode_invalid)
    _safe("f379-multihop-live", p_f379_multihop_live_mapping)
    _safe("f379-intermediate-revocation", p_f379_intermediate_revocation_fencing)
    _safe("f379-legacy-single-multihop", p_f379_legacy_single_revoker_multihop_fencing)
    _safe("f379-missing-member-revoker", p_f379_missing_member_revoker_fencing)
    _safe("f379-mislabeled-mapping", p_f379_mislabeled_mapping_invalid)
    _green_check(os.path.join(REPO, "evals", "w294_coord_lease_probes.py"),
                 "w294_coord_lease")
    _green_check(os.path.join(REPO, "evals", "w299_delegation_revoke_probes.py"),
                 "w299_delegation_revoke")
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w300_revoke_lease: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    for pid, v, note in _results:
        print("[%s] %s: %s" % (v, pid, note.splitlines()[0]))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
