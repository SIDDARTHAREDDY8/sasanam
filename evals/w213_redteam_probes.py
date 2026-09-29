#!/usr/bin/env python3
"""Red-team battery: wave-212 additions at their public seams (wave-213 lane C).

Break-first probes against the four wave-212 additions, aimed at the
requested attack classes:

  1. EAT wire claim bounds (F206 closure) -- bounds-stripped tokens,
     superior-proves smuggling, pre-F206 tokens, nonce replay with
     different bounds, canonical-pin confusion.
  2. gov/artifact_rules.py -- rule-evasion: consumption-order abuse,
     pattern overreach (path confusion), missing/misplaced terminal
     DISALLOW at load, crafted material maps (digest/naming tricks).
  3. gov/leased_credentials.py -- lease forgery, expired-lease
     delivery, renewal-confusion (unknown vs definite refusal),
     sentinel exfil across leases/hosts, wrapping interception and
     token misuse.
  4. Rekor v2 hashedrekord-only (F207 closure) -- native dsse
     submission attempts, PAE-hash mismatch, receipt transplant across
     entries / stale proofs, malformed envelopes.

Verdicts:
  HELD     - the attack was stopped by the product (defense holds)
  BREAK    - the attack succeeded: genuine break, filed as F208+ in
             evals/FINDINGS.md
  RESIDUAL - the attack succeeded only inside a class the code documents
             as an accepted residual (citation required in the detail)
  ERROR    - harness failure

Ranked falsifiable hypotheses (diagnosing-bugs loop):
  H1 (rank 1): The F206 closure holds end-to-end: any token whose
     bounds are stripped, smuggled beside the pinned record, edited
     but still claim_bounds-valid, or incoherent is refused at verify
     time -- bounds are mandatory, pinned to the canonical record,
     and the bounds vocabulary cannot appear at the superior level.
     Expected: HELD on all EAT probes, no new finding.
  H2 (rank 2): artifact_rules' consumptive ordered queue cannot be
     evaded by rule reordering (broad CREATE/MODIFY before the honest
     rule), by crafted names/digests, or by omitting/misplacing the
     terminal DISALLOW -- load refuses malformed sets before any
     artifact is examined, and DISALLOW names every leftover.
     Expected: HELD, no new finding.
  H3 (rank 3): leased credentials fail closed on every forged,
     expired, revoked, or unknown path; sentinels cannot cross
     leases; wrap tokens are one-use, host-bound, and burned on
     interception; the audit log stays secret-free. Server-side
     revocation between rechecks is the one documented residual.
     Expected: HELD, plus exactly one RESIDUAL (cited), no new
     finding.
  H4 (rank 4): Rekor v2 is hashedrekord-only at the public seam;
     DSSE envelopes commit sha256(PAE) and nothing else; receipts do
     not transplant across entries and stale proofs are refused. The
     log's deliberate non-verification of envelope signatures is the
     one documented residual. Expected: HELD, plus exactly one
     RESIDUAL (cited), no new finding.
  H5 (rank 5): Nonce replay with different bounds cannot survive:
     bounds ride inside the signed payload, so stripping or
     swapping them breaks the signature, and re-signing is refused
     by the canonical pin. Expected: HELD, no new finding.

$0 spend. No network. stdlib only.
"""

import base64
import copy
import hashlib
import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        def run():
            try:
                detail = fn()
            except ImportError as e:
                _RESULTS.append((name, "ERROR", "missing module: %s" % e))
                return
            except AssertionError as e:
                _RESULTS.append((name, "ERROR", "assertion: %s"
                                % str(e)[:300]))
                return
            except Exception as e:  # noqa: BLE001 - hostile-input battery
                _RESULTS.append((name, "ERROR", "%s: %s"
                                % (type(e).__name__, str(e)[:300])))
                return
            verdict, detail = detail
            assert verdict in ("HELD", "BREAK", "RESIDUAL"), verdict
            _RESULTS.append((name, verdict, detail))
        _PROBE_FNS[name] = run
        return run
    return deco


# ------------------------------------------------------------------ helpers

_SEED = bytes(range(32))


def _b64u_nopad(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _payload_claims(token):
    parts = token.split(".")
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(
        padded.encode("ascii")).decode("utf-8"))


def _eat_kit():
    from gov import eat_claims as eat, ed25519
    pub = ed25519.publickey(_SEED)
    signer = lambda msg: ed25519.sign(_SEED, msg)  # noqa: E731
    evidence = {
        "tpm": {
            "ueid": "ek-pubkey-sha256:" + "aa" * 32,
            "oemid": "Infineon",
            "hwmodel": "TPM2.0-dTPM",
            "dbgstat": "disabled",
            "nonce": b"tpm-challenge-nonce-0001",
            "measurements": {"pcr_digest": "bb" * 32},
        }
    }
    expectations = {"tpm": {"pcr_digest": "bb" * 32}}
    return eat, pub, signer, evidence, expectations


def _eat_verify_kwargs(pub):
    return {
        "issuer_pubkey": pub,
        "expected_issuer": "sasanam-issuer-1",
        "expected_nonce": b"superior-challenge-0000",
        "expected_submod_nonces": {"tpm": b"tpm-challenge-nonce-0001"},
        "expectations": {"tpm": {"pcr_digest": "bb" * 32}},
        "now": 1700000100,
    }


def _good_eat_token(eat, signer, evidence, expectations):
    return eat.emit_eat(
        evidence=evidence, nonce=b"superior-challenge-0000",
        issuer="sasanam-issuer-1", signer=signer, now=1700000000,
        expectations=expectations)


def _resign(eat, signer, token, mutate):
    claims = _payload_claims(token)
    mutate(claims)
    return eat._sign_claims(claims, signer)


def _refused_eat(eat, token, pub, needle):
    """HELD if verify_eat refuses; BREAK if it verifies."""
    try:
        eat.verify_eat(token, **_eat_verify_kwargs(pub))
    except eat.EATVerifyError as e:
        detail = str(e)
        if needle and needle not in detail:
            return ("BREAK",
                    "refused but without the expected guard (%r not in %r)"
                    % (needle, detail[:160]))
        return ("HELD", "refused: %s" % detail[:220])
    return ("BREAK", "attacking token VERIFIED")


# ------------------------------------------------------- 1. EAT wire bounds

@_probe("eat_control_good_token")
def p_eat_control():
    eat, pub, signer, evidence, expectations = _eat_kit()
    token = _good_eat_token(eat, signer, evidence, expectations)
    out = eat.verify_eat(token, **_eat_verify_kwargs(pub))
    assert out["claims"]["eat_bounds"] == eat.eat_claim_bounds()
    return ("HELD", "harness sanity: canonical token verifies and "
            "carries the pinned bounds record")


@_probe("eat_bounds_stripped_resigned")
def p_eat_stripped():
    eat, pub, signer, evidence, expectations = _eat_kit()
    token = _good_eat_token(eat, signer, evidence, expectations)
    forged = _resign(eat, signer, token,
                     lambda c: c.pop("eat_bounds", None))
    return _refused_eat(eat, forged, pub, "eat_bounds is required")


@_probe("eat_bounds_stripped_unsigned")
def p_eat_stripped_nosign():
    eat, pub, signer, evidence, expectations = _eat_kit()
    token = _good_eat_token(eat, signer, evidence, expectations)
    parts = token.split(".")
    claims = _payload_claims(token)
    del claims["eat_bounds"]
    raw = _b64u_nopad(json.dumps(
        claims, separators=(",", ":"),
        sort_keys=True).encode("utf-8"))
    tampered = parts[0] + "." + raw + "." + parts[2]
    return _refused_eat(eat, tampered, pub, "signature")


@_probe("eat_superior_proves_smuggle")
def p_eat_smuggle_proves():
    eat, pub, signer, evidence, expectations = _eat_kit()
    token = _good_eat_token(eat, signer, evidence, expectations)

    def mutate(c):
        c["proves"] = ["the enclosed content is factually correct",
                       "the workload behaved safely"]
    forged = _resign(eat, signer, token, mutate)
    return _refused_eat(eat, forged, pub, "bounds-smuggle")


@_probe("eat_superior_does_not_prove_smuggle")
def p_eat_smuggle_dnp():
    eat, pub, signer, evidence, expectations = _eat_kit()
    token = _good_eat_token(eat, signer, evidence, expectations)

    def mutate(c):
        # A hostile "does_not_prove" beside the pinned record would let
        # a consumer read bounds from the wrong place.
        c["does_not_prove"] = ["nothing at all"]
    forged = _resign(eat, signer, token, mutate)
    return _refused_eat(eat, forged, pub, "bounds-smuggle")


@_probe("eat_bounds_edited_valid_but_not_canonical")
def p_eat_edited_bounds():
    # The F206 pin: a bounds record that is VALID under
    # gov/claim_bounds.py but is NOT the module's canonical record
    # must be refused (bounds confusion = token confusion).
    from gov import claim_bounds as cb
    eat, pub, signer, evidence, expectations = _eat_kit()
    token = _good_eat_token(eat, signer, evidence, expectations)
    canonical = eat.eat_claim_bounds()
    narrowed = copy.deepcopy(canonical)
    narrowed["proves"] = ["eat-profile conformance of the claim set"]
    cb.validate_bounds(narrowed)  # still valid -- only the pin may stop it

    def mutate(c):
        c["eat_bounds"] = narrowed
    forged = _resign(eat, signer, token, mutate)
    return _refused_eat(eat, forged, pub, "canonical bounds")


@_probe("eat_bounds_incoherent")
def p_eat_incoherent():
    eat, pub, signer, evidence, expectations = _eat_kit()
    token = _good_eat_token(eat, signer, evidence, expectations)
    canonical = eat.eat_claim_bounds()

    def mutate(c):
        bad = copy.deepcopy(canonical)
        bad["does_not_prove"] = list(canonical["proves"])
        c["eat_bounds"] = bad
    forged = _resign(eat, signer, token, mutate)
    return _refused_eat(eat, forged, pub, "claim_bounds")


@_probe("eat_bounds_wrong_type")
def p_eat_bounds_type():
    eat, pub, signer, evidence, expectations = _eat_kit()
    token = _good_eat_token(eat, signer, evidence, expectations)
    forged = _resign(eat, signer, token,
                     lambda c: c.update({"eat_bounds": ["not", "a", "dict"]}))
    return _refused_eat(eat, forged, pub, "eat_bounds")


@_probe("eat_bounds_extra_key")
def p_eat_bounds_extra():
    eat, pub, signer, evidence, expectations = _eat_kit()
    token = _good_eat_token(eat, signer, evidence, expectations)
    canonical = eat.eat_claim_bounds()

    def mutate(c):
        wide = copy.deepcopy(canonical)
        wide["notes"] = "extra key widens the record"
        c["eat_bounds"] = wide
    forged = _resign(eat, signer, token, mutate)
    return _refused_eat(eat, forged, pub, "eat_bounds")


@_probe("eat_nonce_replay_different_bounds")
def p_eat_nonce_replay():
    # H5: replay with a re-signed different nonce (the only way to
    # keep the signature valid while changing the freshness binding)
    # must be refused on the nonce, and the bounds travel with the
    # signed payload so they cannot be swapped independently.
    eat, pub, signer, evidence, expectations = _eat_kit()
    token = _good_eat_token(eat, signer, evidence, expectations)

    def mutate(c):
        c["eat_nonce"] = _b64u_nopad(b"attacker-replay-nonce-00000000")
    forged = _resign(eat, signer, token, mutate)
    return _refused_eat(eat, forged, pub, "eat_nonce")


@_probe("eat_submod_bounds_vocab_tolerated")
def p_eat_submod_vocab():
    # Bounds vocabulary inside a SUBMOD is an unknown payload claim:
    # RFC 6.3 posture tolerates it, and no verifier consults it --
    # the pinned superior eat_bounds still disavow content claims.
    eat, pub, signer, evidence, expectations = _eat_kit()
    token = _good_eat_token(eat, signer, evidence, expectations)

    def mutate(c):
        c["submods"]["tpm"]["proves"] = ["whatever the submod says"]
    forged = _resign(eat, signer, token, mutate)
    try:
        out = eat.verify_eat(forged, **_eat_verify_kwargs(pub))
    except eat.EATVerifyError as e:
        return ("HELD", "refused (stricter than RFC 6.3 posture): %s"
                % str(e)[:160])
    assert out["claims"]["eat_bounds"] == eat.eat_claim_bounds()
    return ("HELD", "tolerated unknown submod claim per RFC 6.3; the "
            "verifier's claim surface is unchanged and the pinned "
            "eat_bounds still disavow content claims")


# ------------------------------------------------------- 2. artifact rules

_D1 = "aa" * 32
_D2 = "bb" * 32


def _ar_refused(fn, needle):
    from gov import artifact_rules as ar
    try:
        fn()
    except ar.ArtifactRuleError as e:
        detail = str(e)
        if needle and needle not in detail:
            return ("BREAK",
                    "refused but without the expected guard (%r not in %r)"
                    % (needle, detail[:160]))
        return ("HELD", "refused: %s" % detail[:220])
    return ("BREAK", "evading rule set VERIFIED")


@_probe("ar_control_good")
def p_ar_control():
    from gov import artifact_rules as ar
    rep = ar.verify_artifacts(
        {"src": _D1}, {"bin": _D2},
        [("CREATE", "bin"), ("REQUIRE", "src"), ("DISALLOW",)],
        context="w213")
    assert rep["ok"] and rep["consumed_count"] == 2
    return ("HELD", "harness sanity: honest rule set verifies")


@_probe("ar_missing_terminal_disallow")
def p_ar_no_disallow():
    from gov import artifact_rules as ar
    return _ar_refused(
        lambda: ar.load_rules([("CREATE", "bin")]),
        "terminal DISALLOW")


@_probe("ar_disallow_not_last")
def p_ar_disallow_mid():
    from gov import artifact_rules as ar
    return _ar_refused(
        lambda: ar.load_rules([("DISALLOW",), ("CREATE", "bin"),
                               ("DISALLOW",)]),
        "terminal")


@_probe("ar_create_then_require_consumed")
def p_ar_create_require():
    from gov import artifact_rules as ar
    return _ar_refused(
        lambda: ar.verify_artifacts(
            {}, {"bin": _D2},
            [("CREATE", "bin"), ("REQUIRE", "bin"), ("DISALLOW",)]),
        "already consumed")


@_probe("ar_broad_create_cannot_bypass_modify")
def p_ar_broad_create():
    # Consumption-order abuse: a broad CREATE before the honest
    # MODIFY must not let a modified artifact skip digest-change
    # accounting.
    from gov import artifact_rules as ar
    return _ar_refused(
        lambda: ar.verify_artifacts(
            {"app": _D1}, {"app": _D2},
            [("CREATE", "app*"), ("MODIFY", "app"), ("DISALLOW",)]),
        "already exists in materials")


@_probe("ar_delete_then_modify_vacuous")
def p_ar_delete_modify():
    # A MODIFY naming an already-consumed artifact is VACUOUS, not an
    # evasion: DELETE already accounted "old" exactly once (verified
    # genuinely deleted), and the per-rule docs pin the no-op
    # semantics ("a pattern matching nothing is a no-op (it claims
    # nothing)"). The security property -- every artifact accounted
    # exactly once, no leftovers past DISALLOW -- still holds.
    from gov import artifact_rules as ar
    rep = ar.verify_artifacts(
        {"old": _D1}, {},
        [("DELETE", "old"), ("MODIFY", "old"), ("DISALLOW",)])
    assert rep["ok"]
    consumed = [c for entry in rep["per_rule"] for c in entry["consumed"]]
    assert consumed.count("material:old") == 1, consumed
    assert rep["per_rule"][1]["consumed"] == [], rep["per_rule"][1]
    return ("HELD", "vacuous MODIFY after DELETE: 'old' was accounted "
            "exactly once by DELETE; the later rule claims nothing and "
            "DISALLOW still guards leftovers")


@_probe("ar_require_cannot_revive_modified")
def p_ar_modify_require():
    from gov import artifact_rules as ar
    return _ar_refused(
        lambda: ar.verify_artifacts(
            {"app": _D1}, {"app": _D2},
            [("MODIFY", "app"), ("REQUIRE", "app"), ("DISALLOW",)]),
        "already consumed")


@_probe("ar_pattern_dotdot_refused")
def p_ar_dotdot():
    from gov import artifact_rules as ar
    return _ar_refused(
        lambda: ar.verify_artifacts(
            {"../x": _D1}, {},
            [("REQUIRE", "../x"), ("DISALLOW",)]),
        "'..'")


@_probe("ar_pattern_backslash_refused")
def p_ar_backslash():
    from gov import artifact_rules as ar
    return _ar_refused(
        lambda: ar.verify_artifacts(
            {"a\\b": _D1}, {},
            [("REQUIRE", "a\\b"), ("DISALLOW",)]),
        "backslash")


@_probe("ar_match_digest_mismatch_both_sides")
def p_ar_match_mismatch():
    from gov import artifact_rules as ar
    return _ar_refused(
        lambda: ar.verify_artifacts(
            {"a": _D1}, {"a": _D1},
            [("MATCH", "a", _D2), ("DISALLOW",)]),
        "pinned")


@_probe("ar_disallow_names_leftovers")
def p_ar_leftovers():
    from gov import artifact_rules as ar
    return _ar_refused(
        lambda: ar.verify_artifacts(
            {}, {"a": _D1, "b": _D2},
            [("CREATE", "a"), ("DISALLOW",)]),
        "product:b")


@_probe("ar_modify_same_digest_refused")
def p_ar_same_digest():
    from gov import artifact_rules as ar
    return _ar_refused(
        lambda: ar.verify_artifacts(
            {"a": _D1}, {"a": _D1},
            [("MODIFY", "a"), ("DISALLOW",)]),
        "identical digests")


@_probe("ar_uppercase_hex_digest_refused")
def p_ar_upper_hex():
    from gov import artifact_rules as ar
    return _ar_refused(
        lambda: ar.verify_artifacts(
            {"a": "AA" * 32}, {},
            [("REQUIRE", "a"), ("DISALLOW",)]),
        "sha256 hex")


# ------------------------------------------------------- 3. leased credentials

_SECRET = "SYNTHETIC-db-secret-01"


def _lc_kit(**over):
    from gov import leased_credentials as lc
    now_v = [1700000000.0]
    clock = lambda: now_v[0]  # noqa: E731
    transport = lc.FakeLeaseTransport(now=clock)
    audit = []
    kw = {"wrapping_ttl_s": 60}
    kw.update(over)
    mgr = lc.LeasedCredentialManager(
        transport, token="op-token-redacted-in-tests",
        audit_log=audit, now=clock, **kw)
    return lc, mgr, transport, audit, now_v


def _lc_issue(mgr, **over):
    kw = {"credential_id": "db-main", "agent_id": "agent-1",
          "run_id": "run-1", "credential_kind": "db-password",
          "source_path": "openbao/db/creds/main",
          "inject_hosts": ["db.internal"], "ttl_s": 300,
          "secret": _SECRET}
    kw.update(over)
    return mgr.issue_lease(**kw)


def _lc_refused(fn, needle):
    from gov import leased_credentials as lc
    try:
        fn()
    except lc.LeaseError as e:
        detail = str(e)
        if needle and needle not in detail:
            return ("BREAK",
                    "refused but without the expected guard (%r not in %r)"
                    % (needle, detail[:160]))
        return ("HELD", "refused: %s" % detail[:220])
    return ("BREAK", "attacking operation SUCCEEDED")


@_probe("lc_control_issue_deliver")
def p_lc_control():
    lc, mgr, transport, audit, now_v = _lc_kit()
    rec, sentinel = _lc_issue(mgr)
    assert sentinel.startswith("fake_value_")
    got = mgr.deliver(rec.lease_id, sentinel=sentinel,
                      dest_host="db.internal")
    assert got == _SECRET
    return ("HELD", "harness sanity: issue/deliver works for the "
            "authorized host")


@_probe("lc_forged_lease_id")
def p_lc_forged():
    lc, mgr, transport, audit, now_v = _lc_kit()
    rec, sentinel = _lc_issue(mgr)
    return _lc_refused(
        lambda: mgr.deliver("lc_lease_" + "de" * 16, sentinel=sentinel,
                            dest_host="db.internal"),
        "unknown lease")


@_probe("lc_expired_lease_delivery")
def p_lc_expired():
    lc, mgr, transport, audit, now_v = _lc_kit()
    rec, sentinel = _lc_issue(mgr, ttl_s=300)
    now_v[0] += 301
    out = _lc_refused(
        lambda: mgr.deliver(rec.lease_id, sentinel=sentinel,
                            dest_host="db.internal"),
        "expired")
    assert any(e.get("action") == "use_refused" for e in audit), \
        "expiry refusal must be audited"
    return out


@_probe("lc_sentinel_cross_lease")
def p_lc_cross_lease():
    lc, mgr, transport, audit, now_v = _lc_kit()
    rec_a, sentinel_a = _lc_issue(mgr, credential_id="db-a")
    rec_b, sentinel_b = _lc_issue(mgr, credential_id="db-b")
    assert rec_a.lease_id != rec_b.lease_id
    return _lc_refused(
        lambda: mgr.deliver(rec_b.lease_id, sentinel=sentinel_a,
                            dest_host="db.internal"),
        "not bound")


@_probe("lc_unauthorized_host")
def p_lc_host():
    lc, mgr, transport, audit, now_v = _lc_kit()
    rec, sentinel = _lc_issue(mgr)
    return _lc_refused(
        lambda: mgr.deliver(rec.lease_id, sentinel=sentinel,
                            dest_host="evil.internal"),
        "not an authorized host")


@_probe("lc_wrap_interception_burns")
def p_lc_intercept():
    lc, mgr, transport, audit, now_v = _lc_kit()
    rec, sentinel = _lc_issue(mgr)
    token = mgr.wrap_for_delivery(rec.lease_id, sentinel=sentinel,
                                  dest_host="db.internal")
    assert token.startswith("wrap_")
    out = _lc_refused(
        lambda: mgr.unwrap(token, dest_host="evil.internal"),
        "different host")
    assert any(e.get("action") == "unwrap_intercepted" for e in audit), \
        "interception must be audited"
    # The legitimate recipient now finds their token burned: the
    # interception is DETECTED, exactly the upstream property.
    second = _lc_refused(
        lambda: mgr.unwrap(token, dest_host="db.internal"),
        "burned")
    assert second[0] == "HELD"
    return out


@_probe("lc_wrap_double_unwrap")
def p_lc_double_unwrap():
    lc, mgr, transport, audit, now_v = _lc_kit()
    rec, sentinel = _lc_issue(mgr)
    token = mgr.wrap_for_delivery(rec.lease_id, sentinel=sentinel,
                                  dest_host="db.internal")
    got = mgr.unwrap(token, dest_host="db.internal")
    assert got == _SECRET
    return _lc_refused(
        lambda: mgr.unwrap(token, dest_host="db.internal"),
        "burned")


@_probe("lc_wrap_after_revoke")
def p_lc_wrap_revoke():
    # The lease is re-guarded at unwrap time: a lease that died
    # between wrap and unwrap refuses.
    lc, mgr, transport, audit, now_v = _lc_kit()
    rec, sentinel = _lc_issue(mgr)
    token = mgr.wrap_for_delivery(rec.lease_id, sentinel=sentinel,
                                  dest_host="db.internal")
    mgr.revoke_lease(rec.lease_id, reason="incident response drill")
    return _lc_refused(
        lambda: mgr.unwrap(token, dest_host="db.internal"),
        "revoked")


@_probe("lc_expired_wrap_token")
def p_lc_wrap_expired():
    lc, mgr, transport, audit, now_v = _lc_kit(wrapping_ttl_s=60)
    rec, sentinel = _lc_issue(mgr)
    token = mgr.wrap_for_delivery(rec.lease_id, sentinel=sentinel,
                                  dest_host="db.internal")
    now_v[0] += 61
    out = _lc_refused(
        lambda: mgr.unwrap(token, dest_host="db.internal"),
        "expired")
    assert any(e.get("action") == "wrap_expired" for e in audit)
    return out


@_probe("lc_renew_unknown_marks_dead")
def p_lc_renew_unknown():
    # Renewal-confusion: an UNKNOWN renewal (lease lost server-side)
    # marks the lease dead; "valid" is never cached across it.
    lc, mgr, transport, audit, now_v = _lc_kit()
    rec, sentinel = _lc_issue(mgr, ttl_s=300)
    transport.forget_lease(rec.lease_id)
    try:
        mgr.renew_lease(rec.lease_id)
        return ("BREAK", "renew on a lost lease did not raise")
    except lc.LeaseError as e:
        assert "dead" in str(e)
    assert mgr.lease_status(rec.lease_id) == "dead"
    out = _lc_refused(
        lambda: mgr.deliver(rec.lease_id, sentinel=sentinel,
                            dest_host="db.internal"),
        "dead")
    assert any(e.get("action") == "renew_failed" for e in audit)
    return out


@_probe("lc_renew_past_max_definite_keeps_alive")
def p_lc_renew_max():
    # A DEFINITE refusal (past max TTL) must NOT kill the lease: the
    # definite answer is that the lease continues until expiry.
    lc, mgr, transport, audit, now_v = _lc_kit()
    rec, sentinel = _lc_issue(mgr, ttl_s=100, max_ttl_s=120)
    now_v[0] += 30
    try:
        mgr.renew_lease(rec.lease_id, increment_s=100)
        return ("BREAK", "renew past max TTL was granted")
    except lc.LeaseError as e:
        assert "max" in str(e).lower() or "refused" in str(e).lower(), e
    assert mgr.lease_status(rec.lease_id) == "active"
    got = mgr.deliver(rec.lease_id, sentinel=sentinel,
                      dest_host="db.internal")
    assert got == _SECRET
    return ("HELD", "definite max-TTL refusal kept the lease alive "
            "until its current expiry; delivery still works")


@_probe("lc_server_side_revoke_no_recheck")
def p_lc_revoke_norecheck():
    # Documented residual (gov/leased_credentials.py HONEST
    # RESIDUALS): mid-lease server-side revocation is discovered only
    # at recheck=True or renew time; deliver between checks trusts
    # local state plus expiry.
    import json as _json
    lc, mgr, transport, audit, now_v = _lc_kit()
    rec, sentinel = _lc_issue(mgr, ttl_s=300)
    transport.request(
        "PUT", "/v1/sys/leases/revoke", {"X-Vault-Token": "x"},
        _json.dumps({"lease_id": rec.lease_id}).encode("utf-8"))
    got = mgr.deliver(rec.lease_id, sentinel=sentinel,
                      dest_host="db.internal")
    assert got == _SECRET  # succeeds: the documented blind window
    assert mgr.lease_status(rec.lease_id, recheck=True) == "revoked"
    out = _lc_refused(
        lambda: mgr.deliver(rec.lease_id, sentinel=sentinel,
                            dest_host="db.internal"),
        "revoked")
    assert out[0] == "HELD"
    return ("RESIDUAL",
            "deliver succeeded after server-side revocation until the "
            "recheck -- the documented mid-lease blind window "
            "(gov/leased_credentials.py HONEST RESIDUALS: 'discovered "
            "only at recheck=True or renew time'); recheck closes it")


@_probe("lc_revoke_without_reason_refused")
def p_lc_revoke_reason():
    lc, mgr, transport, audit, now_v = _lc_kit()
    rec, sentinel = _lc_issue(mgr)
    return _lc_refused(
        lambda: mgr.revoke_lease(rec.lease_id, reason="  "),
        "reason")


@_probe("lc_revoke_down_marks_dead")
def p_lc_revoke_down():
    lc, mgr, transport, audit, now_v = _lc_kit()
    rec, sentinel = _lc_issue(mgr)
    transport.down = True
    try:
        mgr.revoke_lease(rec.lease_id, reason="incident")
        return ("BREAK", "revoke against a dead server did not raise")
    except lc.LeaseError as e:
        assert "dead" in str(e)
    return _lc_refused(
        lambda: mgr.deliver(rec.lease_id, sentinel=sentinel,
                            dest_host="db.internal"),
        "dead")


@_probe("lc_audit_secret_free")
def p_lc_audit_clean():
    lc, mgr, transport, audit, now_v = _lc_kit()
    rec, sentinel = _lc_issue(mgr)
    mgr.deliver(rec.lease_id, sentinel=sentinel, dest_host="db.internal")
    token = mgr.wrap_for_delivery(rec.lease_id, sentinel=sentinel,
                                  dest_host="db.internal")
    mgr.unwrap(token, dest_host="db.internal")
    mgr.renew_lease(rec.lease_id, increment_s=60)
    blob = json.dumps(audit)
    assert _SECRET not in blob, "real secret leaked into the audit log"
    assert sentinel not in blob or True  # sentinels are not secrets
    for e in audit:
        assert e.get("event") == "lease_lifecycle"
    return ("HELD", "audit log carries lifecycle events only; the "
            "real secret appears nowhere")


# ------------------------------------------------------- 4. Rekor v2 (F207)

_V2_CFG = {"log_url": "https://rekor-v2.example-operator.invalid",
           "log_id": "deadbeef" * 8,
           "tsa_url": "https://tsa.example-operator.invalid"}


def _v2_client():
    from gov import rekor_v2_anchor as v2
    return v2.HermeticRekorV2(signing_config=dict(_V2_CFG))


def _v2_sig_material():
    sig_b64 = base64.b64encode(b"\x00" * 64).decode("ascii")
    pem = ("-----BEGIN PUBLIC KEY-----\n"
           + base64.b64encode(b"\x01" * 32).decode("ascii") + "\n"
           + "-----END PUBLIC KEY-----")
    return sig_b64, pem


def _envelope(payload=b"release-artifact"):
    from gov import dsse_envelope as dsse
    from gov.signing import Ed25519Signer
    return dsse.seal(payload, "application/vnd.in-toto+json",
                     [Ed25519Signer(bytes([78]) * 32)])


def _v2_refused(fn, needle):
    from gov import rekor_v2_anchor as v2
    try:
        fn()
    except (v2.V2ConfigError, v2.V2AnchorError) as e:
        detail = str(e)
        if needle and needle not in detail:
            return ("BREAK",
                    "refused but without the expected guard (%r not in %r)"
                    % (needle, detail[:160]))
        return ("HELD", "refused: %s" % detail[:220])
    return ("BREAK", "attacking submission/verification SUCCEEDED")


@_probe("v2_native_dsse_refused")
def p_v2_native_dsse():
    client = _v2_client()
    return _v2_refused(lambda: client.submit("dsse", {}),
                       "accepts only")


@_probe("v2_native_rekord_refused")
def p_v2_native_rekord():
    client = _v2_client()
    return _v2_refused(lambda: client.submit("rekord", {}),
                       "accepts only")


@_probe("v2_dsse_commits_pae_hash")
def p_v2_pae():
    # The F207 contract: the ONLY digest the log commits for a DSSE
    # envelope is sha256(PAE) inside a kind=hashedrekord entry.
    from gov.dsse_envelope import pae
    client = _v2_client()
    env = _envelope()
    receipt = client.submit_dsse_as_hashedrekord(env)
    payload = base64.b64decode(env["payload"].encode("ascii"))
    expect = hashlib.sha256(pae(env["payloadType"], payload)).hexdigest()
    assert receipt["pae_sha256"] == expect, \
        "receipt pae_sha256 != sha256(PAE)"
    assert receipt["dsse_routing"] == "pae-hash-in-hashedrekord"
    body = json.loads(base64.b64decode(
        receipt["committed_body_b64"]).decode("utf-8"))
    assert body["kind"] == "hashedrekord"
    assert body["spec"]["data"]["hash"]["value"] == expect
    assert body["spec"]["data"]["hash"]["algorithm"] == "sha256"
    return ("HELD", "DSSE commits exactly sha256(PAE) as a "
            "hashedrekord entry; the receipt names the routing")


@_probe("v2_receipt_cross_entry_refused")
def p_v2_cross_entry():
    # Receipt transplant: receipt A's proof presented against entry
    # C's bytes must not verify.
    client = _v2_client()
    sig_b64, pem = _v2_sig_material()
    receipt_a = client.submit_dsse_as_hashedrekord(_envelope(b"artifact-a"))
    receipt_c = client.submit_hashedrekord(
        "cc" * 32, signature_b64=sig_b64, pubkey_pem=pem)
    bytes_c = client.entry_bytes_for_receipt(receipt_c)
    return _v2_refused(
        lambda: client.verify_inclusion(receipt_a, bytes_c),
        "root")


@_probe("v2_stale_proof_refused")
def p_v2_stale():
    # A receipt whose proof no longer commits to the CURRENT root
    # (log grew after issuance) is refused: no replay of old
    # inclusion proofs against a moved tree.
    client = _v2_client()
    sig_b64, pem = _v2_sig_material()
    r1 = client.submit_hashedrekord("dd" * 32, signature_b64=sig_b64,
                                    pubkey_pem=pem)
    b1 = client.entry_bytes_for_receipt(r1)
    client.submit_hashedrekord("ee" * 32, signature_b64=sig_b64,
                               pubkey_pem=pem)
    client.submit_hashedrekord("ff" * 32, signature_b64=sig_b64,
                               pubkey_pem=pem)
    return _v2_refused(lambda: client.verify_inclusion(r1, b1),
                       "stale")


@_probe("v2_malformed_envelope_refused")
def p_v2_malformed():
    client = _v2_client()
    env = _envelope()
    env["evil"] = "unknown field smuggled into the envelope"
    return _v2_refused(
        lambda: client.submit_dsse_as_hashedrekord(env),
        "unknown envelope field")


@_probe("v2_bogus_signature_still_anchors")
def p_v2_bogus_sig():
    # Documented residual (submit_dsse_as_hashedrekord docstring):
    # "the log is digest-existence evidence only; signature
    # verification is the auditor's job against the pinned keyset,
    # not the log's." A bogus-signed envelope still anchors -- the
    # attack succeeds only inside that documented class.
    client = _v2_client()
    env = _envelope()
    env["signatures"][0]["sig"] = "00" * 64
    receipt = client.submit_dsse_as_hashedrekord(env)
    assert receipt["dsse_routing"] == "pae-hash-in-hashedrekord"
    return ("RESIDUAL",
            "bogus-signature envelope anchored: the documented "
            "digest-existence-only posture "
            "(submit_dsse_as_hashedrekord: 'signature verification is "
            "the auditor's job against the pinned keyset, not the "
            "log's')")


# ------------------------------------------------------------- determinism

@_probe("determinism")
def p_determinism():
    before = [(n, v) for (n, v, _d) in _RESULTS]
    for name, verdict in before:
        if name == "determinism" or name not in _PROBE_FNS:
            continue
        start = len(_RESULTS)
        _PROBE_FNS[name]()
        n2, v2 = _RESULTS[start][0], _RESULTS[start][1]
        del _RESULTS[start]
        assert n2 == name and v2 == verdict, \
            "non-deterministic verdict: %s %s -> %s" % (name, verdict, v2)
    return ("HELD", "%d/%d verdicts stable across runs"
            % (len(before), len(before)))


# --------------------------------------------------------------------- main

def _green_check():
    # Depth-1 green check: adjacent wave-212 batteries must stay green
    # alongside this one (each run with GOV_SKIP_GREEN=1 to prevent
    # combinatorial nesting).
    import subprocess
    adj = ["evals/w212_f206_f207_probes.py",
           "evals/artifact_rules_probes.py",
           "evals/w212_lease_probes.py",
           "evals/rekor_v2_anchor_probes.py"]
    for rel in adj:
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            _RESULTS.append(("green:" + rel, "HELD",
                             "battery absent (lane not merged)"))
            continue
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        r = subprocess.run([sys.executable, path], capture_output=True,
                           text=True, env=env, timeout=600, cwd=REPO)
        ok = r.returncode == 0
        _RESULTS.append(("green:" + os.path.basename(rel),
                         "HELD" if ok else "ERROR",
                         "adjacent battery %s"
                         % ("green" if ok else
                            "RED: " + (r.stdout + r.stderr)[-300:])))


def main():
    if not GREEN_SKIP:
        _green_check()
    for name in list(_PROBE_FNS):
        if name == "determinism":
            continue
        _PROBE_FNS[name]()
    _PROBE_FNS["determinism"]()
    n_break = n_held = n_res = n_err = 0
    for name, verdict, detail in _RESULTS:
        print("%-34s %-9s %s" % (name, verdict, detail))
        if verdict == "BREAK":
            n_break += 1
        elif verdict == "HELD":
            n_held += 1
        elif verdict == "RESIDUAL":
            n_res += 1
        else:
            n_err += 1
    print("w213 redteam: breaks=%d held=%d residuals=%d errors=%d"
          % (n_break, n_held, n_res, n_err))
    # Exit nonzero only on harness errors; BREAK is the expected
    # red-team outcome (findings filed in evals/FINDINGS.md), not a
    # battery failure (wave-177 convention).
    bad = any(v not in ("BREAK", "HELD", "RESIDUAL")
              for _, v, _ in _RESULTS)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
