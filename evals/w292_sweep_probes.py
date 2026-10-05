"""Wave-292 lane 6: uncoded-exception sweep of the newest modules.

Red-first battery over the public seams of ``gov/delegation_chain.py``
(wave-291: verify_invocation, narrowing, ceremony binding, root policy)
and ``gov/evidence_provenance.py`` (rebuild recipe / verify_rebuild /
execute_rebuild) plus adjacent verify paths.

Verdict discipline: a probe is HELD when the seam refuses with a CODED
decision code (an exception carrying a truthy string ``.code``); BREAK
when a bare uncoded exception escapes (KeyError/ValueError/TypeError/
IndexError/AttributeError/JSONDecodeError/binascii.Error, code=None) or
the seam silently returns; ERROR when the harness itself fails.

Findings (all LOW, fail-closed contract/robustness):
- F357: seal_provenance AttributeError on non-dict claim["builder"]
- F358: check_rebuild_recipe TypeError on non-sequence material_uris
- F359: digest_of TypeError on non-JSON-serializable body
"""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import delegation_chain as dc  # noqa: E402
from gov import evidence_provenance as ep  # noqa: E402

TAXONOMY_PIN = 2088 # Wave-291 merge: pin 1710 -> 1715 (+5 delegation-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*)



_SEED = bytes(32)
_ANCHOR = "ab" * 32
_VALID_RECIPE = {
    "recipe_format": "sasanam-rebuild/1",
    "inputs": ["u1"],
    "steps": [{"op": "sha256"}],
}


def _coded(exc):
    code = getattr(exc, "code", None)
    return isinstance(code, str) and bool(code)


def _run_probe(fn):
    """Return 'HELD' / 'BREAK' / 'ERROR' for one seam call."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 -- the probe IS the classifier
        return "HELD" if _coded(exc) else "BREAK"
    return "BREAK"  # silent return on a refusal seam is a break


# ---------------------------------------------------------------------------
# Probe registry: (name, callable). BREAK-expected probes are the F357-F359
# defect sites; pin_* probes are adjacent coded-refusal regression pins.
# ---------------------------------------------------------------------------

def _verifier():
    return dc.DelegationVerifier([_ANCHOR])


PROBES = [
    # --- F357: seal_provenance builder-shape escapes (AttributeError) ---
    ("sweep-seal-builder-none",
     lambda: ep.seal_provenance({"builder": None}, _SEED)),
    ("sweep-seal-builder-str",
     lambda: ep.seal_provenance({"builder": "x"}, _SEED)),
    # --- F358: check_rebuild_recipe material_uris escapes (TypeError) ---
    ("sweep-recipe-uris-int",
     lambda: ep.check_rebuild_recipe(dict(_VALID_RECIPE), 5)),
    ("sweep-recipe-uris-unhashable",
     lambda: ep.check_rebuild_recipe(dict(_VALID_RECIPE), [{"u": "1"}])),
    # --- F359: digest_of non-serializable body (TypeError) ---
    ("sweep-digest-typeerror",
     lambda: dc.digest_of({"a": object()})),
    # --- Adjacent coded-refusal pins (must stay HELD) ---
    ("pin-delegate-req-non-dict",
     lambda: dc.delegate(_SEED, None, "x")),
    ("pin-verify-action-none",
     lambda: _verifier().verify([], None)),
    ("pin-invocation-no-proof",
     lambda: _verifier().verify_invocation(
         [], {"with": "a", "can": "b"}, invoker_pubkey_hex=_ANCHOR,
         pop_challenge=None, pop_signature_hex=None)),
    ("pin-verifier-bad-anchor",
     lambda: dc.DelegationVerifier(["zz"])),
    ("pin-make-claim-bad-digest",
     lambda: ep.make_provenance_claim("b1", "k1", "zz", [])),
    ("pin-verify-envelope-none",
     lambda: ep.verify_provenance(
         None, ep.BuilderPolicy("p1", {"b1": "ab" * 32}))),
    ("pin-seal-claim-nondict",
     lambda: ep.seal_provenance("x", _SEED)),
    ("pin-recipe-unknown-op",
     lambda: ep.check_rebuild_recipe(
         {"recipe_format": "sasanam-rebuild/1", "inputs": ["u1"],
          "steps": [{"op": "frobnicate"}, {"op": "sha256"}]}, ["u1"])),
    ("pin-pubkey-unknown",
     lambda: ep.BuilderPolicy("p1", {"b1": "ab" * 32}).pubkey_for("nope")),
    ("pin-anchor-gated-none",
     lambda: ep.anchor_bundle_gated(
         None, "ab" * 32, None,
         ep.BuilderPolicy("p1", {"b1": "ab" * 32}))),
    ("pin-verify-bad-sig-type",
     lambda: ep.verify_provenance(
         {"provenance": {
             "claim_format": "sasanam-provenance/1",
             "builder": {"id": "b1"},
             "artifact": {"digest": "ab" * 32},
             "materials": [], "issued_at": 1},
          "signature": 12345},
         ep.BuilderPolicy("p1", {"b1": "ab" * 32}))),
    ("pin-graph-verify-first",
     lambda: ep.record_provenance_in_graph(
         None,
         {"provenance": {
             "claim_format": "sasanam-provenance/1",
             "builder": {"id": "b1"},
             "artifact": {"digest": "ab" * 32},
             "materials": [], "issued_at": 1},
          "signature": "ab" * 128},
         ep.BuilderPolicy("p1", {"b1": "ab" * 32}))),
]


def run_all():
    results = []
    for name, fn in PROBES:
        try:
            verdict = _run_probe(fn)
        except Exception:  # noqa: BLE001 -- harness-level failure
            verdict = "ERROR"
        results.append((name, verdict))
    return results


import re as _re


def _run_battery_green(battery_file, expected_break):
    """Depth-1 green check: run an adjacent battery's main with
    GOV_SKIP_GREEN=1 (so it does not nest), then parse its summary line."""
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    proc = subprocess.run(
        [sys.executable, os.path.join(here, battery_file)],
        capture_output=True, text=True, env=env, cwd=repo, timeout=600)
    match = _re.search(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR",
                       proc.stdout)
    if not match:
        return (battery_file, "no summary line", proc.returncode,
                proc.stdout[-500:], proc.stderr[-500:])
    nb, nh, ne = (int(g) for g in match.groups())
    ok = (nb == expected_break and ne == 0)
    return (battery_file, "OK" if ok else "UNEXPECTED",
            "%d BREAK / %d HELD / %d ERROR (expected %d BREAK)"
            % (nb, nh, ne, expected_break))


def green_check_w291_delegation():
    """Adjacent delegation battery: 0 BREAK expected (F352-F355 closed)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("w291_delegation", "skipped (GOV_SKIP_GREEN=1)")
    return _run_battery_green("w291_delegation_probes.py", 0)


def green_check_w290_rebuild():
    """Adjacent rebuild battery: 0 BREAK expected."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("w290_rebuild", "skipped (GOV_SKIP_GREEN=1)")
    return _run_battery_green("w290_rebuild_probes.py", 0)


def green_check_w291_redteam():
    """Red-team battery: 2 BREAK expected-open (F356)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("w291_redteam", "skipped (GOV_SKIP_GREEN=1)")
    return _run_battery_green("w291_redteam_probes.py", 2)


class SweepTest(unittest.TestCase):
    def test_probe_count(self):
        self.assertEqual(len(PROBES), 17)

    def test_taxonomy_pin(self):
        from gov import decision_codes
        self.assertEqual(len(decision_codes.TAXONOMY), TAXONOMY_PIN)


def main():
    results = run_all()
    n_break = sum(1 for _, v in results if v == "BREAK")
    n_held = sum(1 for _, v in results if v == "HELD")
    n_err = sum(1 for _, v in results if v == "ERROR")
    for name, verdict in results:
        print("%-28s %s" % (name, verdict))
    print("w292_sweep: %d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    return 0 if (n_break, n_err) == (0, 0) else 1


if __name__ == "__main__":
    if "--probe-only" in sys.argv:
        results = run_all()
        for name, verdict in results:
            print("%-28s %s" % (name, verdict))
        nb = sum(1 for _, v in results if v == "BREAK")
        nh = sum(1 for _, v in results if v == "HELD")
        ne = sum(1 for _, v in results if v == "ERROR")
        print("w292_sweep: %d BREAK / %d HELD / %d ERROR" % (nb, nh, ne))
        sys.exit(0)
    unittest.main(argv=[sys.argv[0]], exit=False)
    checks = [green_check_w291_delegation(), green_check_w290_rebuild(),
              green_check_w291_redteam()]
    for check in checks:
        print(check)
    bad = [c for c in checks if len(c) > 2 and c[1] != "OK"
           and "skipped" not in str(c[1])]
    sys.exit(main() or (1 if bad else 0))
