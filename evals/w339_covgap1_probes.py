#!/usr/bin/env python3
"""Wave-339 lane 4 battery: decision-code coverage campaign, round 1
(w337 prospectus R14 continuation).

The R14 coverage table (docs/decision-code-coverage.json) listed 241
uncovered codes at pin 2131. This battery asserts 30 of the most
security-critical ones -- deny/refusal/boundary codes on three fresh
seams -- with real behavioral probes (the hostile input is driven
through the public seam and the coded refusal is asserted), never
tautologies:

  C1-C15  mcp-oauth-cimd-* (15): the whole wave-337 CIMD safe-subset
          refusal family was unprobed at pin 2131.
  B1-B6   corroboration-* (6): source-independence refusals in
          gov/corroborated_consumption.py.
  S1-S9   scan_verdict_* (9): emission/verification refusals in
          gov/scan_verdicts.py.
  P0      pin/taxonomy honesty (2140/2140/0 sorted-unique, footer state).
  PZ      green check (depth-1): adjacent suites as children with
          GOV_SKIP_GREEN=1.

Base: f670892a (wave-338 merge). Pin 2127, footer open none / next
F427. No gov/ changes in this lane. Findings: none filed.

Deterministic: fresh random keys per run; no assertion depends on key
material or wall-clock time (all times are injected).
"""

import base64
import json
import os
import subprocess
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

_results = []


def _held(pid, note):
    _results.append((pid, "HELD", note))


def _break(pid, note):
    _results.append((pid, "BREAK", note))


def _error(pid, note):
    _results.append((pid, "ERROR", note))


def _cimd_probe(pid, code, fn):
    from gov.mcp_cimd import CIMDError
    try:
        fn()
    except CIMDError as exc:
        if exc.code == code:
            _held(pid, "refused coded %s" % code)
        else:
            _break(pid, "wrong code: %r, want %r" % (exc.code, code))
    except Exception as exc:  # noqa: BLE001
        _error(pid, "uncoded %s: %s"
               % (type(exc).__name__, str(exc)[:160]))
    else:
        _break(pid, "hostile input was NOT refused")


def _corr_probe(pid, code, fn):
    from gov.corroborated_consumption import CorroboratedConsumptionError
    try:
        fn()
    except CorroboratedConsumptionError as exc:
        if exc.code == code:
            _held(pid, "refused coded %s" % code)
        else:
            _break(pid, "wrong code: %r, want %r" % (exc.code, code))
    except Exception as exc:  # noqa: BLE001
        _error(pid, "uncoded %s: %s"
               % (type(exc).__name__, str(exc)[:160]))
    else:
        _break(pid, "hostile input was NOT refused")


def _sv_probe(pid, code, fn):
    from gov.scan_verdicts import ScanVerdictError
    try:
        fn()
    except ScanVerdictError as exc:
        if code in str(exc):
            _held(pid, "refused %s" % code)
        else:
            _break(pid, "wrong refusal: %r, want %r"
                   % (str(exc)[:120], code))
    except Exception as exc:  # noqa: BLE001
        _error(pid, "uncoded %s: %s"
               % (type(exc).__name__, str(exc)[:160]))
    else:
        _break(pid, "hostile input was NOT refused")


# ----------------------------------------------------------------------
# C1-C15: mcp-oauth-cimd-* refusal family
# ----------------------------------------------------------------------

def _deployment(max_bytes=8):
    return {"trusted_domain_patterns": ["example.com"],
            "timeout_seconds": 5,
            "max_bytes": max_bytes}


def _ok_resolver(host):
    return ["93.184.216.34"]


def run_cimd_probes():
    from gov import mcp_cimd as cimd

    _cimd_probe("C1", "mcp-oauth-cimd-url-not-https",
                lambda: cimd.validate_client_id_url(
                    "http://example.com/client"))
    _cimd_probe("C2", "mcp-oauth-cimd-url-userinfo",
                lambda: cimd.validate_client_id_url(
                    "https://user@example.com/client"))
    _cimd_probe("C3", "mcp-oauth-cimd-url-root-path",
                lambda: cimd.validate_client_id_url(
                    "https://example.com/"))
    _cimd_probe("C4", "mcp-oauth-cimd-url-dot-segment",
                lambda: cimd.validate_client_id_url(
                    "https://example.com/a/../b"))
    _cimd_probe("C5", "mcp-oauth-cimd-url-query",
                lambda: cimd.validate_client_id_url(
                    "https://example.com/c?x=1"))
    _cimd_probe("C6", "mcp-oauth-cimd-url-fragment",
                lambda: cimd.validate_client_id_url(
                    "https://example.com/c#x"))
    _cimd_probe("C7", "mcp-oauth-cimd-binding-mismatch",
                lambda: cimd.check_document_binding(
                    {"client_id": "https://example.com/a"},
                    "https://example.com/b"))
    _cimd_probe("C8", "mcp-oauth-cimd-credential-present",
                lambda: cimd.validate_document_shape(
                    {"client_id": "https://example.com/c",
                     "client_secret": "smuggled"}))
    _cimd_probe("C9", "mcp-oauth-cimd-document-malformed",
                lambda: cimd.validate_document_shape({"nope": 1}))
    _cimd_probe("C10", "mcp-oauth-cimd-redirect-origin-mismatch",
                lambda: cimd.validate_document_shape(
                    {"client_id": "https://example.com/c",
                     "redirect_uris": ["https://evil.test/cb"]}))

    dep = _deployment()

    def _down(url, timeout):
        raise RuntimeError("network down")

    _cimd_probe("C11", "mcp-oauth-cimd-fetch-non200",
                lambda: cimd.onboard_cimd("https://example.com/client",
                                          _down, dep,
                                          resolver=_ok_resolver))

    def _redir(url, timeout):
        return {"status": 301,
                "headers": {"location": "https://example.com/x"},
                "body": b""}

    _cimd_probe("C12", "mcp-oauth-cimd-fetch-redirect",
                lambda: cimd.onboard_cimd("https://example.com/client",
                                          _redir, dep,
                                          resolver=_ok_resolver))

    def _private_resolver(host):
        return ["10.0.0.9"]

    def _never(url, timeout):
        raise AssertionError("fetcher must not run on SSRF refusal")

    _cimd_probe("C13", "mcp-oauth-cimd-fetch-ssrf-range",
                lambda: cimd.onboard_cimd("https://example.com/client",
                                          _never, dep,
                                          resolver=_private_resolver))

    def _slow(url, timeout):
        raise TimeoutError("timed out")

    _cimd_probe("C14", "mcp-oauth-cimd-fetch-timeout",
                lambda: cimd.onboard_cimd("https://example.com/client",
                                          _slow, dep,
                                          resolver=_ok_resolver))

    def _big(url, timeout):
        return {"status": 200, "headers": {}, "body": b"x" * 64}

    _cimd_probe("C15", "mcp-oauth-cimd-fetch-too-large",
                lambda: cimd.onboard_cimd("https://example.com/client",
                                          _big, dep,
                                          resolver=_ok_resolver))

    # Control: a well-formed document validates (the refusals above are
    # shape-specific, not blanket).
    try:
        ok = cimd.validate_document_shape(
            {"client_id": "https://example.com/c",
             "redirect_uris": ["https://example.com/cb"]})
        if ok is True:
            _held("C0", "control: well-formed document validates")
        else:
            _break("C0", "control returned %r" % (ok,))
    except Exception as exc:  # noqa: BLE001
        _error("C0", "control errored: %s" % (exc,))


# ----------------------------------------------------------------------
# B1-B6: corroboration-* source-independence refusals
# ----------------------------------------------------------------------

def _corr_policy(trusted, runtime="ab" * 32, require=("d",)):
    from gov.corroborated_consumption import TrustPolicy
    return TrustPolicy(trusted_keys=trusted, runtime_key_id=runtime,
                       require_dimensions=require)


def _signed_item(ed25519, cc, seed, source_id, dimension="d",
                 state="ok", mutate_after=None):
    pub = ed25519.publickey(seed)
    kid = cc.key_id_of(pub)
    item = {"dimension": dimension, "state": state,
            "source": {"source_id": source_id, "key_id": kid,
                       "signature": "00" * 64}}
    sig = ed25519.sign(seed, cc.canonical_item_bytes(item))
    if mutate_after:
        item[mutate_after] = "tampered"
    item["source"]["signature"] = sig.hex()
    return item, pub, kid


def run_corr_probes():
    from gov import ed25519
    from gov import corroborated_consumption as cc

    runtime = "ab" * 32
    seed_a = ed25519.generate_seed()
    pub_a = ed25519.publickey(seed_a)
    kid_a = cc.key_id_of(pub_a)
    policy = _corr_policy({kid_a: pub_a}, runtime=runtime)

    _corr_probe("B1", "corroboration-malformed",
                lambda: cc.consume({"envelope_id": "e",
                                    "evidence": ["not-a-dict"]},
                                   policy))

    # B2: the runtime's own key attesting its evidence = self-attestation.
    item, _, _ = _signed_item(ed25519, cc, seed_a, "s1")
    policy_self = _corr_policy({kid_a: pub_a}, runtime=kid_a)
    _corr_probe("B2", "corroboration-unattested",
                lambda: cc.consume({"envelope_id": "e",
                                    "evidence": [item]},
                                   policy_self))

    # B3: key not in the consumer's trust policy.
    seed_b = ed25519.generate_seed()
    item_b, _, _ = _signed_item(ed25519, cc, seed_b, "sb")
    _corr_probe("B3", "corroboration-untrusted-source",
                lambda: cc.consume({"envelope_id": "e",
                                    "evidence": [item_b]},
                                   policy))

    # B4: policy-held key but edited after signing.
    item_m, _, _ = _signed_item(ed25519, cc, seed_a, "s1",
                                mutate_after="state")
    _corr_probe("B4", "corroboration-signature-invalid",
                lambda: cc.consume({"envelope_id": "e",
                                    "evidence": [item_m]},
                                   policy))

    # B5: same key_id presented as two distinct sources.
    item1, _, _ = _signed_item(ed25519, cc, seed_a, "s1")
    item2, _, _ = _signed_item(ed25519, cc, seed_a, "s2")
    _corr_probe("B5", "corroboration-key-inequality",
                lambda: cc.consume({"envelope_id": "e",
                                    "evidence": [item1, item2]},
                                   policy))

    # B6: one valid source cannot corroborate itself.
    _corr_probe("B6", "corroboration-uncorroborated",
                lambda: cc.consume({"envelope_id": "e",
                                    "evidence": [item1]},
                                   policy))

    # Control: two independent valid sources corroborate.
    seed_c = ed25519.generate_seed()
    pub_c = ed25519.publickey(seed_c)
    kid_c = cc.key_id_of(pub_c)
    policy2 = _corr_policy({kid_a: pub_a, kid_c: pub_c}, runtime=runtime)
    item_c, _, _ = _signed_item(ed25519, cc, seed_c, "sc")
    try:
        receipt = cc.consume({"envelope_id": "e",
                              "evidence": [item1, item_c]}, policy2)
        if receipt.get("corroborated", {}).get("d"):
            _held("B0", "control: two independent sources corroborate")
        else:
            _break("B0", "control receipt: %r" % (receipt,))
    except Exception as exc:  # noqa: BLE001
        _error("B0", "control errored: %s" % (exc,))


# ----------------------------------------------------------------------
# S1-S9: scan_verdict_* emission/verification refusals
# ----------------------------------------------------------------------

def _sv_emit(sv, signer, scanned_at, expires_at):
    return sv.emit_scan_verdict(
        scanner_name="scanbot", scanner_version="1.2.3",
        scan_target_digest="sha256:" + "ab" * 32, verdict="pass",
        ruleset_digest="sha256:" + "cd" * 32, scanned_at=scanned_at,
        expires_at=expires_at, signer=signer, now=scanned_at)


def run_sv_probes():
    from gov import ed25519
    from gov import dsse_envelope as _dsse
    from gov import scan_verdicts as sv
    from gov.signing import Ed25519Signer, Ed25519Verifier

    signer = Ed25519Signer(ed25519.generate_seed())
    verifier = Ed25519Verifier(signer.public_key)
    now = 1800000000
    env = _sv_emit(sv, signer, now, now + 3600)
    v = [verifier]
    kw = dict(scanner_name="scanbot", scan_target_digest="sha256:" + "ab" * 32)

    _sv_probe("S1", "scan_verdict_stale",
              lambda: sv.verify_scan_verdict(env, verifiers=v,
                                             now=now + 7200, **kw))
    _sv_probe("S2", "scan_verdict_future_scan",
              lambda: sv.verify_scan_verdict(env, verifiers=v,
                                             now=now - 1, **kw))
    _sv_probe("S3", "scan_verdict_target_mismatch",
              lambda: sv.verify_scan_verdict(
                  env, verifiers=v, scanner_name="scanbot",
                  scan_target_digest="sha256:" + "ef" * 32, now=now))
    _sv_probe("S4", "scan_verdict_scanner_mismatch",
              lambda: sv.verify_scan_verdict(
                  env, verifiers=v, scanner_name="otherbot",
                  scan_target_digest="sha256:" + "ab" * 32, now=now))

    wrong = Ed25519Verifier(ed25519.publickey(ed25519.generate_seed()))
    _sv_probe("S5", "scan_verdict_signature_invalid",
              lambda: sv.verify_scan_verdict(env, verifiers=[wrong],
                                             now=now, **kw))

    tampered = dict(env)
    tampered["payloadType"] = "application/vnd.other"
    _sv_probe("S6", "scan_verdict_payload_type",
              lambda: sv.peek_scan_verdict(tampered))
    _sv_probe("S7", "scan_verdict_malformed_envelope",
              lambda: sv.peek_scan_verdict({"nope": 1}))

    bad_json_env = _dsse.seal(b"not-json{",
                              sv.SCAN_VERDICT_PAYLOAD_TYPE, [signer])
    _sv_probe("S8", "scan_verdict_bad_json",
              lambda: sv.peek_scan_verdict(bad_json_env))

    stmt = json.loads(base64.b64decode(env["payload"]).decode("utf-8"))
    noncanonical = json.dumps(stmt, sort_keys=True,
                              separators=(", ", ": ")).encode("utf-8")
    assert noncanonical != base64.b64decode(env["payload"])
    nc_env = _dsse.seal(noncanonical, sv.SCAN_VERDICT_PAYLOAD_TYPE,
                        [signer])
    _sv_probe("S9", "scan_verdict_not_canonical",
              lambda: sv.peek_scan_verdict(nc_env))

    # Control: the valid envelope verifies.
    try:
        out = sv.verify_scan_verdict(env, verifiers=v, now=now, **kw)
        if out["statement"]["verdict"] == "pass":
            _held("S0", "control: valid verdict verifies")
        else:
            _break("S0", "control: %r" % (out,))
    except Exception as exc:  # noqa: BLE001
        _error("S0", "control errored: %s" % (exc,))


# ----------------------------------------------------------------------
# P0: pin + taxonomy + footer honesty
# ----------------------------------------------------------------------

def run_pin_footer_probes():
    import re
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'"code":\s*\'([^\']+)\'', src)
    # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    if len(lits) == TAXONOMY_PIN == 2140 and len(set(lits)) == 2140 \
            and lits == sorted(lits):
        _held("P0a", "taxonomy 2140/2140/0 sorted-unique literals")
    else:
        _break("P0a", "literals %d, unique %d, sorted=%s"
               % (len(lits), len(set(lits)), lits == sorted(lits)))
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)
    # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531) (applies to assertion below)
    # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
    # Wave-372 merge: footer repoint open F606-F611 / next F612 \
    # Wave-374 lane 2: F613 CLOSED
    if "Open findings: F640, F641, F642, F643." in text \
            and "Next free finding: **F644**" in text:  # Wave-356 merge: footer repoint  # Wave-357 merge: F478, F479 CLOSED (next F481); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640
        _held("P0b", "footer open F436 / next F437")
    else:
        _break("P0b", "footer text mismatch")


_EXPECTED_BREAKS = set()


def green_check():
    """Depth-1 green check: adjacent suites as children with
    GOV_SKIP_GREEN=1. Honored skip: records a skipped note."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _held("PZ", "green check skipped (GOV_SKIP_GREEN=1)")
        return
    children = [
        ["-m", "unittest", "test_corroborated_consumption", "-v"],
        ["-m", "unittest", "test_scan_verdicts", "-v"],
    ]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    for child in children:
        proc = subprocess.run(
            [sys.executable] + child,
            cwd=os.path.join(REPO, "tests"), env=env,
            capture_output=True, text=True, timeout=600)
        if proc.returncode != 0:
            _break("PZ", "child %s red:\n%s"
                   % (child, proc.stdout[-800:] + proc.stderr[-800:]))
            return
    _held("PZ", "adjacent children green")


def main():
    try:
        run_cimd_probes()
    except Exception:  # noqa: BLE001
        _error("C*", "harness failure:\n%s" % traceback.format_exc()[-600:])
    try:
        run_corr_probes()
    except Exception:  # noqa: BLE001
        _error("B*", "harness failure:\n%s" % traceback.format_exc()[-600:])
    try:
        run_sv_probes()
    except Exception:  # noqa: BLE001
        _error("S*", "harness failure:\n%s" % traceback.format_exc()[-600:])
    try:
        run_pin_footer_probes()
    except Exception:  # noqa: BLE001
        _error("P0*", "harness failure:\n%s"
               % traceback.format_exc()[-600:])
    try:
        green_check()
    except Exception:  # noqa: BLE001
        _error("PZ", "green check errored:\n%s"
               % traceback.format_exc()[-600:])

    breaks = {p for p, v, _ in _results if v == "BREAK"}
    errors = {p for p, v, _ in _results if v == "ERROR"}
    n_break, n_held, n_err = (sum(1 for _p, v, _n in _results if v == k)
                              for k in ("BREAK", "HELD", "ERROR"))
    print("w339_covgap1: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    for pid, verdict, note in _results:
        if verdict != "HELD":
            print("  %s %s: %s" % (pid, verdict, note[:220]))
    if breaks ^ _EXPECTED_BREAKS or errors:
        print("MISMATCH: breaks=%s errors=%s expected=%s"
              % (sorted(breaks), sorted(errors),
                 sorted(_EXPECTED_BREAKS)))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
