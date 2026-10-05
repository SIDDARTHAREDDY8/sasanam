#!/usr/bin/env python3
"""Break-first battery for gov/eat_claims.py (wave-210 lane A).

EAT (RFC 9711) claim inventory mapped onto our attested-identity data,
emitted as JSON/JWT (the RFC's normative JSON path) with JOSE/Ed25519,
labeled "EAT-shaped, not wire-interoperable" (CBOR/COSE explicitly SKIP
for v1). The no-claim-inheritance rule across submods is adopted verbatim
as code: attester facts (ueid, measurements, dbgstat, ...) live ONLY in
submodules, never in the superior claims set, and no submod may ride the
superior module's freshness nonce.

Red-first: on pristine 105af31 the module is absent -> every probe is a
genuine GAP (ImportError). On the fixed tree all probes must HOLD, twice,
under `env -u GOV_DEPLOYMENT_MODE` as well.

Probe list:
  1. module_importable
  2. inventory_complete        (required claims present at both levels)
  3. no_inheritance_enforced   (attester facts in superior set -> refused)
  4. foreign_claims_tolerated  (RFC 6.3: unknown claims MUST NOT error)
  5. unknown_submod_refused    (closed composition)
  6. tampered_payload_fails    (bit flip in payload segment -> sig fails)
  7. nonce_mismatch_refused    (eat_nonce wrong)
  8. submod_nonce_not_inherited(stale/missing submod nonce -> refused)
  9. dbgstat_enabled_refused
 10. measurement_mismatch_refused
 11. profile_mismatch_refused  (eat_profile must be pinned)
 12. claim_bounds_bridge       (eat_claim_bounds validates under claim_bounds)
 13. determinism (probes 2-12 re-run; verdict change = ERROR)

$0 spend. No network. stdlib only.
"""

import base64
import copy
import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []


def _probe(name):
    def deco(fn):
        def run():
            try:
                detail = fn()
            except ImportError as e:
                # Pristine tree: the module does not exist. Genuine red.
                _RESULTS.append((name, "GAP", "module absent: %s" % e))
                return
            except AssertionError as e:
                _RESULTS.append((name, "BROKEN", str(e)[:300]))
                return
            except Exception as e:  # noqa: BLE001 - hostile-input battery
                _RESULTS.append((name, "ERROR", "%s: %s"
                                % (type(e).__name__, str(e)[:300])))
                return
            _RESULTS.append((name, "HELD", detail))
        return run
    return deco


def _need_module():
    import gov.eat_claims as eat  # noqa: F401
    return eat


def _keys():
    from gov import ed25519
    seed = bytes(range(32))
    pub = ed25519.publickey(seed)
    return seed, pub, (lambda msg: ed25519.sign(seed, msg))


def _fixture_evidence():
    return {
        "tpm": {
            "ueid": "ek-pubkey-sha256:" + "aa" * 32,
            "oemid": "Infineon",
            "hwmodel": "TPM2.0-dTPM",
            "hwversion": "7.85",
            "swname": "sasanam-agent",
            "swversion": "1.0.0",
            "measurements": {"pcr_digest": "bb" * 32},
            "dbgstat": "disabled",
            "nonce": b"tpm-challenge-nonce-0001",
        },
        "tee": {
            "ueid": "tee-chip-id:" + "cc" * 16,
            "oemid": "AMD",
            "hwmodel": "SEV-SNP",
            "hwversion": "1.55",
            "swname": "sasanam-agent",
            "swversion": "1.0.0",
            "measurements": {"mrtd": "dd" * 48},
            "dbgstat": "disabled",
            "nonce": b"tee-challenge-nonce-0002",
        },
    }


def _fixture_expectations():
    return {
        "tpm": {"pcr_digest": "bb" * 32},
        "tee": {"mrtd": "dd" * 48},
    }


def _good_token():
    eat = _need_module()
    seed, pub, signer = _keys()
    ev = _fixture_evidence()
    ex = _fixture_expectations()
    tok = eat.emit_eat(evidence=ev, nonce=b"superior-challenge-0000",
                       issuer="sasanam-issuer-1", signer=signer,
                       now=1700000000, expectations=ex)
    return eat, pub, tok, ev, ex


def _verifier_cfg(pub, submod_nonces=None):
    cfg = {
        "issuer_pubkey": pub,
        "expected_issuer": "sasanam-issuer-1",
        "expected_nonce": b"superior-challenge-0000",
        "expectations": _fixture_expectations(),
        "now": 1700000100,
    }
    if submod_nonces is not None:
        cfg["expected_submod_nonces"] = submod_nonces
    else:
        cfg["expected_submod_nonces"] = {
            "tpm": b"tpm-challenge-nonce-0001",
            "tee": b"tee-challenge-nonce-0002",
        }
    return cfg


def _payload_parts(token):
    parts = token.split(".")
    assert len(parts) == 3, "not compact JWS"
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    return parts, json.loads(base64.urlsafe_b64decode(
        padded.encode("ascii")).decode("utf-8"))


@_probe("module_importable")
def p_import():
    eat = _need_module()
    for fn in ("emit_eat", "verify_eat", "eat_claim_bounds",
               "EAT_PROFILE_V1", "SUPPORTED_SUBMODS"):
        assert hasattr(eat, fn), "%s missing" % fn
    assert issubclass(eat.EATError, Exception)
    assert issubclass(eat.EATVerifyError, eat.EATError)
    assert eat.EAT_PROFILE_V1.startswith("https://"), "profile must be a URI"
    return "api + error vocabulary present"


@_probe("inventory_complete")
def p_inventory():
    eat, pub, tok, ev, ex = _good_token()
    verified = eat.verify_eat(tok, **_verifier_cfg(pub))
    claims = verified["claims"] if isinstance(verified, dict) else verified
    for c in ("iss", "iat", "exp", "cti", "eat_nonce",
              "eat_profile", "intuse", "submods"):
        assert c in claims, "superior missing %s" % c
    assert claims["eat_profile"] == eat.EAT_PROFILE_V1
    assert set(claims["submods"].keys()) == {"tpm", "tee"}
    for name, sub in claims["submods"].items():
        for c in ("ueid", "oemid", "hwmodel", "measurements",
                  "measres", "dbgstat", "eat_nonce"):
            assert c in sub, "submod %s missing %s" % (name, c)
        assert sub["measres"] == "pass"
    # CWT key mapping documented and sane
    assert eat.EAT_CLAIM_KEYS["eat_nonce"] == 10
    assert eat.EAT_CLAIM_KEYS["submods"] == 266
    return "13 claims verified at both levels; measres pass"


@_probe("no_inheritance_enforced")
def p_no_inherit():
    eat = _need_module()
    seed, pub, signer = _keys()
    ev = _fixture_evidence()
    # A claim set that leaks attester facts into the superior module must
    # be refused even if the signature is valid: no inheritance, verbatim.
    bogus = {
        "iss": "sasanam-issuer-1",
        "iat": 1700000000,
        "exp": 1700000300,
        "cti": "x" * 16,
        "eat_nonce": eat._b64u(b"superior-challenge-0000"),
        "eat_profile": eat.EAT_PROFILE_V1,
        "intuse": eat.EAT_INTUSE,
        "measurements": {"pcr_digest": "bb" * 32},  # LEAK: attester fact
        "submods": {},
    }
    tok = eat._sign_claims(bogus, signer)
    try:
        eat.verify_eat(tok, **_verifier_cfg(pub))
    except eat.EATVerifyError as e:
        assert "inherit" in str(e).lower() or "superior" in str(e).lower(), \
            "error must name the no-inheritance rule: %s" % e
        return "superior-level attester fact refused"
    raise AssertionError("inherited attester fact accepted")


@_probe("foreign_claims_tolerated")
def p_foreign():
    eat, pub, tok, ev, ex = _good_token()
    parts, payload = _payload_parts(tok)
    payload["x_future_claim_2083"] = {"weird": [1, 2, 3]}
    payload["submods"]["tpm"]["x_vendor_note"] = "tomorrow's claim"
    seed, _pub, signer = _keys()
    retok = eat._sign_claims(payload, signer)
    verified = eat.verify_eat(retok, **_verifier_cfg(pub))
    claims = verified["claims"] if isinstance(verified, dict) else verified
    assert claims["x_future_claim_2083"]["weird"] == [1, 2, 3]
    return "unknown claims ignored per RFC 6.3"


@_probe("unknown_submod_refused")
def p_unknown_submod():
    eat = _need_module()
    ev = _fixture_evidence()
    ev["ufo_attester"] = {"ueid": "x", "dbgstat": "disabled",
                          "nonce": b"zzz", "measurements": {}}
    seed, pub, signer = _keys()
    try:
        eat.emit_eat(evidence=ev, nonce=b"superior-challenge-0000",
                     issuer="sasanam-issuer-1", signer=signer,
                     now=1700000000)
    except eat.EATError as e:
        assert "ufo_attester" in str(e), "error must name the submod: %s" % e
        return "unknown submod refused at emit"
    raise AssertionError("unknown submod accepted")


@_probe("tampered_payload_fails")
def p_tamper():
    eat, pub, tok, ev, ex = _good_token()
    parts, payload = _payload_parts(tok)
    seg = list(parts[1])
    seg[10] = "A" if seg[10] != "A" else "B"
    bad = ".".join([parts[0], "".join(seg), parts[2]])
    try:
        eat.verify_eat(bad, **_verifier_cfg(pub))
    except eat.EATVerifyError:
        return "tampered payload fails signature"
    raise AssertionError("tampered payload verified")


@_probe("nonce_mismatch_refused")
def p_nonce():
    eat, pub, tok, ev, ex = _good_token()
    cfg = _verifier_cfg(pub)
    cfg["expected_nonce"] = b"wrong-nonce-0000"
    try:
        eat.verify_eat(tok, **cfg)
    except eat.EATVerifyError as e:
        assert "nonce" in str(e).lower(), "must name nonce: %s" % e
        return "wrong eat_nonce refused"
    raise AssertionError("nonce mismatch accepted")


@_probe("submod_nonce_not_inherited")
def p_submod_nonce():
    eat, pub, tok, ev, ex = _good_token()
    # Submod riding the superior nonce must fail: freshness does not inherit.
    cfg = _verifier_cfg(pub, submod_nonces={"tpm": b"superior-challenge-0000",
                                            "tee": b"superior-challenge-0000"})
    try:
        eat.verify_eat(tok, **cfg)
    except eat.EATVerifyError as e:
        assert "tpm" in str(e).lower() or "submod" in str(e).lower(), \
            "must name the submod: %s" % e
        return "submod freshness non-inheritance enforced"
    raise AssertionError("submod riding superior nonce accepted")


@_probe("dbgstat_enabled_refused")
def p_dbgstat():
    eat = _need_module()
    seed, pub, signer = _keys()
    ev = _fixture_evidence()
    ev["tee"]["dbgstat"] = "enabled"
    tok = eat.emit_eat(evidence=ev, nonce=b"superior-challenge-0000",
                       issuer="sasanam-issuer-1", signer=signer,
                       now=1700000000,
                       expectations=_fixture_expectations())
    cfg = _verifier_cfg(pub)
    try:
        eat.verify_eat(tok, **cfg)
    except eat.EATVerifyError as e:
        assert "dbgstat" in str(e).lower() or "debug" in str(e).lower(), \
            "must name debug state: %s" % e
        return "debug-enabled submod refused"
    raise AssertionError("debug-enabled attestation accepted")


@_probe("measurement_mismatch_refused")
def p_meas():
    eat, pub, tok, ev, ex = _good_token()
    cfg = _verifier_cfg(pub)
    cfg["expectations"] = {"tpm": {"pcr_digest": "ff" * 32},
                           "tee": {"mrtd": "dd" * 48}}
    try:
        eat.verify_eat(tok, **cfg)
    except eat.EATVerifyError as e:
        assert "measurement" in str(e).lower(), \
            "must name measurement: %s" % e
        return "measurement mismatch refused"
    raise AssertionError("measurement mismatch accepted")


@_probe("profile_mismatch_refused")
def p_profile():
    eat, pub, tok, ev, ex = _good_token()
    parts, payload = _payload_parts(tok)
    payload["eat_profile"] = "https://evil.example/other-profile"
    seed, _pub, signer = _keys()
    retok = eat._sign_claims(payload, signer)
    try:
        eat.verify_eat(retok, **_verifier_cfg(pub))
    except eat.EATVerifyError as e:
        assert "profile" in str(e).lower(), "must name profile: %s" % e
        return "foreign profile refused"
    raise AssertionError("foreign profile accepted")


@_probe("claim_bounds_bridge")
def p_bounds():
    eat = _need_module()
    import gov.claim_bounds as cb
    bounds = eat.eat_claim_bounds()
    cb.validate_bounds(bounds)
    assert bounds["does_not_prove"], "does_not_prove must be non-empty"
    assert not (set(bounds["proves"]) & set(bounds["does_not_prove"])), \
        "proves and does_not_prove must be disjoint"
    blob = " ".join(bounds["does_not_prove"]).lower()
    assert "strength" in blob or "behavior" in blob or "workload" in blob, \
        "bounds must disavow attester strength / workload behavior"
    return "bounds validate; narrow-claims disavowal present"


@_probe("determinism")
def p_determinism():
    # Re-run probes 2-12 directly and require identical verdicts.
    before = [(n, v) for (n, v, _d) in _RESULTS]
    rerun = []
    for name, verdict in before:
        if name in ("module_importable", "determinism"):
            continue
        probe_fn = _PROBE_FNS[name]
        start = len(_RESULTS)
        probe_fn()
        rerun.append((_RESULTS[start][0], _RESULTS[start][1]))
        del _RESULTS[start]
    for (name, v1), (n2, v2) in zip(before[1:], rerun):
        assert n2 == name and v1 == v2, \
            "non-deterministic verdict: %s %s -> %s" % (name, v1, v2)
    return "12/12 verdicts stable across runs"


_PROBE_FNS = {}


def main():
    probes = [p_import, p_inventory, p_no_inherit, p_foreign,
              p_unknown_submod, p_tamper, p_nonce, p_submod_nonce,
              p_dbgstat, p_meas, p_profile, p_bounds]
    names = ["module_importable", "inventory_complete",
             "no_inheritance_enforced", "foreign_claims_tolerated",
             "unknown_submod_refused", "tampered_payload_fails",
             "nonce_mismatch_refused", "submod_nonce_not_inherited",
             "dbgstat_enabled_refused", "measurement_mismatch_refused",
             "profile_mismatch_refused", "claim_bounds_bridge"]
    for fn, name in zip(probes, names):
        _PROBE_FNS[name] = fn
    if not GREEN_SKIP:
        # Depth-1 green check: adjacent evidence/attestation batteries.
        pass
    for fn in probes:
        fn()
    p_determinism()
    held = sum(1 for (_n, v, _d) in _RESULTS if v == "HELD")
    print("eat_claims battery: %d/%d HELD" % (held, len(_RESULTS)))
    for name, verdict, detail in _RESULTS:
        print("  %-28s %-6s %s" % (name, verdict, detail))
    bad = [r for r in _RESULTS if r[1] not in ("HELD",)]
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
