#!/usr/bin/env python3
"""Wave-212 lane A red-first battery: F206 (EAT claim bounds on wire) and
F207 (Rekor v2 hashedrekord-only contract) closure probes.

Red on pristine (c124c928):
  F206: emit_eat writes no bounds field; verify_eat never consults
        eat_claim_bounds(); a re-signed token with superior-level
        proves=[...] verifies cleanly.
  F207: V2_ENTRY_TYPES == {"hashedrekord", "dsse"}; submit_dsse() builds
        kind:"dsse" bodies -- the superseded v2.0.1-era contract. Current
        upstream (sigstore/rekor-tiles CLIENTS.md at commit 5e6ebbad)
        supports ONLY HashedRekordLogEntryV002 / hashedrekord.

Green post-fix:
  F206: emit_eat embeds the canonical bounds record as the superior
        claim "eat_bounds"; verify_eat requires it, validates it through
        gov/claim_bounds.py, pins it to the module's canonical record,
        and refuses superior-level bounds vocabulary ("proves" /
        "does_not_prove" / "verifier_assumptions" / "scope_limits")
        outside "eat_bounds" (bounds-smuggle refusal).
  F207: V2_ENTRY_TYPES == {"hashedrekord"}; submit("dsse", ...) fails
        closed; submit_dsse_as_hashedrekord() strict-parses the DSSE
        envelope and commits sha256(PAE) as a hashedrekord entry
        (kind:"hashedrekord", apiVersion 0.0.2), carrying payload_type,
        payload_sha256 and pae_sha256 on the receipt.

Verdicts: HELD / BREAK / ERROR. Deterministic: every probe runs twice
and verdicts must agree.

Run (fresh UNIQUE /var/tmp TMPDIR per run, mkdir -p first):
  T=/var/tmp/g212a-probes-$$; mkdir -p $T
  TMPDIR=$T ~/workspace/.gov-venv/bin/python evals/w212_f206_f207_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=$T ~/workspace/.gov-venv/bin/python \\
      evals/w212_f206_f207_probes.py

$0 spend, synthetic/local, deterministic, stdlib only. No network.
"""

import base64
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
            assert verdict in ("HELD", "BREAK"), verdict
            _RESULTS.append((name, verdict, detail))
        _PROBE_FNS[name] = run
        return run
    return deco


# ------------------------------------------------------------------ helpers

_SEED = bytes(range(32))


def _eat_keys():
    from gov import ed25519
    pub = ed25519.publickey(_SEED)
    return pub, (lambda msg: ed25519.sign(_SEED, msg))


def _eat_evidence():
    return {
        "tpm": {
            "ueid": "ek-pubkey-sha256:" + "aa" * 32,
            "measurements": {"pcr_digest": "bb" * 32},
            "dbgstat": "disabled",
            "nonce": b"tpm-challenge-nonce-0001",
        },
    }


def _eat_expectations():
    return {"tpm": {"pcr_digest": "bb" * 32}}


def _good_token(eat, signer):
    return eat.emit_eat(
        evidence=_eat_evidence(), nonce=b"superior-challenge-0000",
        issuer="sasanam-issuer-1", signer=signer, now=1700000000,
        expectations=_eat_expectations())


def _eat_verifier_cfg(pub):
    return {
        "issuer_pubkey": pub,
        "expected_issuer": "sasanam-issuer-1",
        "expected_nonce": b"superior-challenge-0000",
        "expectations": _eat_expectations(),
        "now": 1700000100,
        "expected_submod_nonces": {"tpm": b"tpm-challenge-nonce-0001"},
    }


def _payload_claims(token):
    parts = token.split(".")
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(
        padded.encode("ascii")).decode("utf-8"))


_V2_CFG = {"log_url": "https://rekor-v2.example-operator.invalid",
           "log_id": "deadbeef" * 8,
           "tsa_url": "https://tsa.example-operator.invalid"}


def _v2_client(v2):
    return v2.HermeticRekorV2(signing_config=dict(_V2_CFG))


def _envelope():
    from gov import dsse_envelope as dsse
    from gov.signing import Ed25519Signer
    return dsse.seal(b"release-artifact", "application/vnd.in-toto+json",
                     [Ed25519Signer(bytes([78]) * 32)])


def _pae(payload_type, payload_b64):
    payload = base64.b64decode(payload_b64.encode("ascii"), validate=True)
    tb = payload_type.encode("utf-8")
    return (b"DSSEv1 " + str(len(tb)).encode("ascii") + b" " + tb + b" "
            + str(len(payload)).encode("ascii") + b" " + payload)


# ------------------------------------------------------------------ F206


@_probe("f206_bounds_on_wire")
def p_f206_wire():
    """The canonical bounds record rides the wire and the legit token
    still verifies."""
    import gov.eat_claims as eat
    import gov.claim_bounds as cb
    pub, signer = _eat_keys()
    tok = _good_token(eat, signer)
    claims = _payload_claims(tok)
    wire = claims.get("eat_bounds")
    if not isinstance(wire, dict):
        return ("BREAK", "F206: no 'eat_bounds' claim on the wire")
    try:
        canon = cb.validate_bounds(wire, where="eat_claim_bounds")
    except cb.ClaimBoundsError as e:
        return ("BREAK", "F206: wire bounds fail claim_bounds.py: %s" % e)
    expected = eat.eat_claim_bounds()
    if canon != expected:
        return ("BREAK",
                "F206: wire bounds differ from the canonical record")
    try:
        eat.verify_eat(tok, **_eat_verifier_cfg(pub))
    except eat.EATError as e:
        return ("BREAK", "legit token with wire bounds refused: %s" % e)
    return ("HELD", "canonical bounds on wire; legit token verifies")


@_probe("f206_superior_proves_smuggle_refused")
def p_f206_smuggle():
    """A re-signed token with superior-level proves overreach must be
    refused (the w211 repro eat_superior_proves_smuggle)."""
    import gov.eat_claims as eat
    pub, signer = _eat_keys()
    claims = _payload_claims(_good_token(eat, signer))
    claims["proves"] = ["the enclosed content is factually correct",
                        "the workload behaved safely"]
    claims["does_not_prove"] = []
    forged = eat._sign_claims(claims, signer)
    try:
        eat.verify_eat(forged, **_eat_verifier_cfg(pub))
    except eat.EATError:
        return ("HELD", "superior-level proves overreach refused")
    return ("BREAK",
            "F206: superior proves=['the enclosed content is factually "
            "correct', ...] verified OK")


@_probe("f206_bounds_mandatory")
def p_f206_mandatory():
    """A token without the bounds claim is refused fail-closed
    (pre-fix tokens do not verify)."""
    import gov.eat_claims as eat
    pub, signer = _eat_keys()
    claims = _payload_claims(_good_token(eat, signer))
    if "eat_bounds" not in claims:
        return ("BREAK", "F206: no bounds claim on the wire to strip")
    del claims["eat_bounds"]
    forged = eat._sign_claims(claims, signer)
    try:
        eat.verify_eat(forged, **_eat_verifier_cfg(pub))
    except eat.EATError:
        return ("HELD", "bounds-less token refused fail-closed")
    return ("BREAK", "F206: token without bounds verified OK")


@_probe("f206_edited_bounds_refused")
def p_f206_edited():
    """A schema-valid but non-canonical bounds record (key holder
    rewrote proves) is refused: the verifier pins the canonical
    record, exactly as it pins eat_profile."""
    import gov.eat_claims as eat
    pub, signer = _eat_keys()
    claims = _payload_claims(_good_token(eat, signer))
    if "eat_bounds" not in claims:
        return ("BREAK", "F206: no bounds claim on the wire to edit")
    claims["eat_bounds"]["proves"] = \
        list(claims["eat_bounds"]["proves"]) + ["content is correct"]
    forged = eat._sign_claims(claims, signer)
    try:
        eat.verify_eat(forged, **_eat_verifier_cfg(pub))
    except eat.EATError:
        return ("HELD", "non-canonical bounds refused (bounds pinning)")
    return ("BREAK",
            "F206: token with issuer-rewritten bounds verified OK")


# ------------------------------------------------------------------ F207


@_probe("f207_hashedrekord_only")
def p_f207_allowlist():
    """V2 entry-type allowlist is hashedrekord-only."""
    from gov import rekor_v2_anchor as v2
    if v2.V2_ENTRY_TYPES == frozenset({"hashedrekord"}):
        return ("HELD", "V2_ENTRY_TYPES is hashedrekord-only")
    return ("BREAK", "F207: V2_ENTRY_TYPES=%s (superseded v2.0.1-era "
            "contract)" % sorted(v2.V2_ENTRY_TYPES))


@_probe("f207_native_dsse_refused")
def p_f207_native_refused():
    """A native dsse entry is refused fail-closed; the old seam is
    gone."""
    from gov import rekor_v2_anchor as v2
    client = _v2_client(v2)
    if hasattr(client, "submit_dsse"):
        return ("BREAK",
                "F207: submit_dsse() still exists (native dsse kind)")
    try:
        client.submit("dsse", _envelope())
    except v2.V2ConfigError:
        return ("HELD", "native dsse submit fails closed")
    return ("BREAK", "F207: submit('dsse', ...) was accepted")


@_probe("f207_dsse_pae_hash_roundtrip")
def p_f207_pae_roundtrip():
    """DSSE is committed as its PAE hash inside a hashedrekord entry;
    the receipt round-trips through verify_inclusion."""
    from gov import rekor_v2_anchor as v2
    if not hasattr(v2.HermeticRekorV2, "submit_dsse_as_hashedrekord"):
        return ("BREAK", "F207: no submit_dsse_as_hashedrekord seam")
    client = _v2_client(v2)
    env = _envelope()
    try:
        r = client.submit_dsse_as_hashedrekord(env)
    except Exception as e:  # noqa: BLE001
        return ("BREAK", "pae-hash submit raised: %r" % (e,))
    pae = _pae(env["payloadType"], env["payload"])
    pae_sha = hashlib.sha256(pae).hexdigest()
    checks = [
        r.get("verification.source") == "rekor-v2-hermetic",
        r.get("entry_type") == "hashedrekord",
        r.get("payload_type") == "application/vnd.in-toto+json",
        r.get("pae_sha256") == pae_sha,
        r.get("payload_sha256") == hashlib.sha256(
            b"release-artifact").hexdigest(),
    ]
    try:
        body = json.loads(
            client.entry_bytes_for_receipt(r).decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        return ("BREAK", "entry bytes unreadable: %r" % (e,))
    checks += [
        body.get("kind") == "hashedrekord",
        body.get("apiVersion") == "0.0.2",
        body["spec"]["data"]["hash"]["value"] == pae_sha,
    ]
    if not all(checks):
        return ("BREAK", "pae-hash receipt shape wrong: %d/8 checks"
                % sum(checks))
    try:
        ok = client.verify_inclusion(
            r, client.entry_bytes_for_receipt(r))
    except Exception as e:  # noqa: BLE001
        return ("BREAK", "inclusion failed: %r" % (e,))
    if not ok:
        return ("BREAK", "verify_inclusion returned falsy")
    return ("HELD", "dsse->pae-hash->hashedrekord round-trips, "
            "kind:hashedrekord/0.0.2, inclusion holds")


@_probe("f207_dsse_malformed_refused")
def p_f207_malformed():
    """Malformed envelopes are refused by the new DSSE seam."""
    from gov import rekor_v2_anchor as v2
    if not hasattr(v2.HermeticRekorV2, "submit_dsse_as_hashedrekord"):
        return ("BREAK", "F207: no submit_dsse_as_hashedrekord seam")
    client = _v2_client(v2)
    env = _envelope()
    bads = (None, "x", {"payload": "eA=="},
            dict(env, extra_field=1),
            dict(env, payload="!!!not-b64!!!"))
    for bad in bads:
        try:
            client.submit_dsse_as_hashedrekord(bad)
        except v2.V2ConfigError:
            continue
        except Exception as e:  # noqa: BLE001
            return ("BREAK", "wrong error for %r: %r" % (bad, e))
        return ("BREAK", "malformed envelope accepted: %r" % (bad,))
    return ("HELD", "5/5 malformed envelopes refused")


# ------------------------------------------------------------------ runner


def _run_all():
    for name in sorted(_PROBE_FNS):
        _PROBE_FNS[name]()
    for name, verdict, detail in _RESULTS:
        print("  %-34s %-8s %s" % (name, verdict, detail[:160]))
    return list(_RESULTS)


def main():
    if not GREEN_SKIP:
        # Depth-1 green check: this battery is self-contained; no child
        # batteries are spawned. The adjacent-module regression is run
        # by the lane driver as separate commands.
        pass
    first = _run_all()
    _RESULTS.clear()
    second = _run_all()
    det = [(a[0], a[1]) for a in first] == [(b[0], b[1]) for b in second]
    breaks = [n for n, v, d in first if v == "BREAK"]
    errors = [n for n, v, d in first if v == "ERROR"]
    held = [n for n, v, d in first if v == "HELD"]
    print("---")
    print("probes=%d held=%d break=%d error=%d deterministic=%s" % (
        len(first), len(held), len(breaks), len(errors), det))
    if not det:
        print("NONDETERMINISM between runs")
        return 2
    if errors or breaks:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
