#!/usr/bin/env python3
"""Wave-344 measurement battery: MCP/skill-registry supply-chain
continuous re-verification posture (driver-signing analogy).

$0 SPEND BY CONSTRUCTION: deterministic pins on public seams only. No
model calls, no network. Do NOT add ModelDriver/SpendLedger usage here.

Adapted from the AIR Security deep-dive steal queue (2026-10-05): AIR's
"continuous re-verification, not scanning" framing and the driver-signing
mental model ("drivers didn't need signatures in the early 2000s; today
every driver tells you who signed it"). This battery measures exactly that
posture on Sasanam's registry track: for each supply-chain component, does
a signed, exact-version artifact gate the action -- and where does it not?

HELD = the signed-provenance mechanism is live on the seam.
BREAK = a gap in the posture (none expected; new gaps would be filed as
findings, not patched).

Surface map (measured, not asserted):
  S1 skill_admission.admit      - build-time in-toto layout admission
  S2 registry_acceptance        - install-time signed manifest gate
  S3 skill_supply_chain         - event-driven lifecycle re-verification
  S4 mcp_discovery_trust        - discovery-plane trust (pins, not DNS)
  S5 oci_registry_gate          - distribution-path trust certification

Honest gaps measured BY INSPECTION (documented, not BREAKs):
  G1 MCP server CODE fetched at runtime is not re-verified against a
     pinned digest by any seam here: check_discovery pins the server
     identity, but the endpoint URL is a locator, never fetched or
     verified (documented in the module docstring: DNS is an UNTRUSTED
     discovery plane). A server that rotates its code under a pinned
     identity is outside the measured posture.
  G2 Shield provider code at ShieldRegistry.attach time carries no
     signature check: registration is declarative (provider_kind,
     run callable) -- the shield's own provenance is not a signed
     artifact. The verdict loop is HMAC-chained (output evidence is
     tamper-evident), but the provider's input provenance is not.
  G3 skill_supply_chain lifecycle re-verification fires on lifecycle
     TRANSITIONS with sealed links; there is no time-based re-verification
     between transitions (no continuous drift detection of an installed
     bundle while it sits idle).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w344_mcp_ecosystem_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import base64
import hashlib
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

from gov import ed25519  # noqa: E402
from gov import skill_admission  # noqa: E402
from gov import registry_acceptance  # noqa: E402
from gov import skill_supply_chain  # noqa: E402
from gov import mcp_discovery_trust  # noqa: E402
from gov import oci_registry_gate  # noqa: E402


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
_AUTH_SEED = bytes(range(32))
_STEP_SEED = bytes([200 + i for i in range(32)])
_WRONG_SEED = bytes([7] * 32)
_AUTH_PUB_HEX = ed25519.publickey(_AUTH_SEED).hex()
_STEP_PUB_HEX = ed25519.publickey(_STEP_SEED).hex()


class _Signer(object):
    """ed25519 signer adapter for skill_supply_chain.seal_document."""

    def __init__(self, seed):
        self._seed = bytes(seed)

    def sign(self, msg):
        return ed25519.sign(self._seed, msg)


def _admission_layout():
    step = {"name": "fetch", "command": ["curl", "https://x.example/p"],
            "signer_pub": _STEP_PUB_HEX, "rules": [("REQUIRE", "src"), ("DISALLOW",)]}
    return skill_admission.make_layout("w344-test", [step], _AUTH_SEED), step


def _accepted_manifest(package_bytes, now, key_seed):
    """Build a valid signed manifest for accept_package."""
    pub = ed25519.publickey(key_seed)
    payload = {
        "name": "w344-skill", "version": "1",
        "digest": hashlib.sha256(package_bytes).hexdigest(),
        "issued_at": now - 60, "valid_until": now + 3600,
    }
    body = registry_acceptance.canonical_manifest_bytes(payload)
    sig = ed25519.sign(key_seed, body)
    manifest = {
        "payload": payload,
        "signatures": [{
            "key": base64.b64encode(pub).decode("ascii"),
            "sig": base64.b64encode(sig).decode("ascii"),
        }],
    }
    policy = {
        "threshold": 1,
        "trusted_keys": [base64.b64encode(pub).decode("ascii")],
    }
    return manifest, policy


def _lifecycle_fixture(tamper_prev=None, expired=False):
    """Minimal one-transition lifecycle fixture."""
    kid = "w344-key"
    pub_hex = ed25519.publickey(_AUTH_SEED).hex()
    keys = {kid: {"keytype": "ed25519",
                  "keyval": {"public": pub_hex}}}
    layout_doc = {
        "bundle": "w344-bundle", "version": 1,
        "expires": "2999-01-01T00:00:00Z" if not expired
                   else "2001-01-01T00:00:00Z",
        "authority": {"keyids": [kid], "threshold": 1},
        "transitions": [{
            "name": "install",
            "signers": {"keyids": [kid], "threshold": 1},
            "expected_materials": [], "expected_products": [],
        }],
    }
    layout_wire = skill_supply_chain.seal_document(
        "layout", layout_doc, [(kid, _Signer(_AUTH_SEED))])
    link_doc = {
        "transition": "install", "materials": {}, "products": {},
        "byproducts": {},
        "prev_digest": "0" * 64 if tamper_prev is None else tamper_prev,
    }
    link_wire = skill_supply_chain.seal_document(
        "link", link_doc, [(kid, _Signer(_AUTH_SEED))])
    return layout_wire, [link_wire], keys, 1700000000


# ---------------------------------------------------------------------------
# probes: every probe returns (held: bool, note: str); the harness turns a
# failed assertion into an ERROR, an explicit False into a BREAK.
# ---------------------------------------------------------------------------
def p1_admit_unsigned_layout():
    signed, _step = _admission_layout()
    tampered = dict(signed)
    tampered["signature"] = "00" * 64
    v = skill_admission.admit(tampered, [], _AUTH_PUB_HEX)
    return (not v["admitted"], "unsigned/tampered layout refused: %s"
            % v["code"])


def p2_admit_wrong_authority():
    signed, _step = _admission_layout()
    v = skill_admission.admit(signed, [], ed25519.publickey(_WRONG_SEED).hex())
    return (not v["admitted"], "wrong-authority layout refused: %s"
            % v["code"])


def p3_accept_untrusted_signature():
    pkg = b"w344-package-bytes"
    now = 1700000000
    pub = ed25519.publickey(_AUTH_SEED)
    payload = {
        "name": "w344-skill", "version": "1",
        "digest": hashlib.sha256(pkg).hexdigest(),
        "issued_at": now - 60, "valid_until": now + 3600,
    }
    body = registry_acceptance.canonical_manifest_bytes(payload)
    # signed by a key NOT in the deployment's trusted_keys
    other = ed25519.publickey(_WRONG_SEED)
    manifest = {"payload": payload, "signatures": [{
        "key": base64.b64encode(other).decode("ascii"),
        "sig": base64.b64encode(ed25519.sign(_WRONG_SEED, body)).decode("ascii"),
    }]}
    policy = {"threshold": 1,
              "trusted_keys": [base64.b64encode(pub).decode("ascii")]}
    try:
        registry_acceptance.accept_package(manifest, pkg, policy, now)
    except registry_acceptance.RegistryAcceptanceError as exc:
        return (True, "untrusted-key install refused: %s" % exc.args[0])
    return (False, "install accepted with untrusted signature")


def p4_accept_digest_mismatch():
    pkg = b"w344-package-bytes"
    tampered = b"w344-package-bytes-TAMPERED"
    now = 1700000000
    manifest, policy = _accepted_manifest(pkg, now, _AUTH_SEED)
    try:
        registry_acceptance.accept_package(manifest, tampered, policy, now)
    except registry_acceptance.RegistryAcceptanceError as exc:
        code = exc.args[0].split(":")[0]
        return (code == "package-digest-mismatch",
                "tampered bytes refused: %s" % code)
    return (False, "install accepted despite digest mismatch")


def p5_accept_expired_manifest():
    pkg = b"w344-package-bytes"
    now = 1700000000
    manifest, policy = _accepted_manifest(pkg, now, _AUTH_SEED)
    stale_now = now + 7200  # past valid_until
    try:
        registry_acceptance.accept_package(manifest, pkg, policy, stale_now)
    except registry_acceptance.RegistryAcceptanceError as exc:
        code = exc.args[0].split(":")[0]
        return (code == "package-stale",
                "stale manifest refused: %s" % code)
    return (False, "install accepted with stale manifest")


def p6_lifecycle_valid():
    layout_wire, link_wires, keys, eval_start = _lifecycle_fixture()
    report = skill_supply_chain.verify_lifecycle(
        layout_wire, link_wires, keys, eval_start)
    return (report.get("ok") is True, "valid lifecycle chain verifies")


def p7_lifecycle_broken_chain():
    layout_wire, link_wires, keys, eval_start = _lifecycle_fixture(
        tamper_prev="ff" * 32)
    try:
        skill_supply_chain.verify_lifecycle(
            layout_wire, link_wires, keys, eval_start)
    except skill_supply_chain.SupplyChainError as exc:
        return (True, "broken prev_digest chain refused: %s" % exc.args[0])
    return (False, "lifecycle accepted despite broken chain")


def p8_lifecycle_expired_layout():
    layout_wire, link_wires, keys, eval_start = _lifecycle_fixture(
        expired=True)
    try:
        skill_supply_chain.verify_lifecycle(
            layout_wire, link_wires, keys, eval_start)
    except skill_supply_chain.SupplyChainError as exc:
        return (True, "expired layout refused: %s" % exc.args[0])
    return (False, "lifecycle accepted with expired layout")


def p9_discovery_unpinned():
    discovery = {"name": "evil-mcp", "endpoint": "https://evil.example/mcp",
                 "identity": "did:example:evil", "source": "marketplace"}
    try:
        mcp_discovery_trust.check_discovery(discovery, {"other": "x"})
    except mcp_discovery_trust.McpDiscoveryTrustError as exc:
        return (True, "unpinned discovery refused: %s" % exc.args[0])
    return (False, "unpinned discovery accepted")


def p10_discovery_identity_mismatch():
    discovery = {"name": "mcp-a", "endpoint": "https://a.example/mcp",
                 "identity": "did:example:rotated", "source": "marketplace"}
    try:
        mcp_discovery_trust.check_discovery(
            discovery, {"mcp-a": "did:example:original"})
    except mcp_discovery_trust.McpDiscoveryTrustError as exc:
        return (True, "identity-mismatch discovery refused: %s"
                % exc.args[0])
    return (False, "rotated-identity discovery accepted")


def p11_registry_out_matrix():
    def _transport(request):
        # healthy Referrers API: 200 + valid index body
        return (200, {"content-type": "application/vnd.oci.image.index.v1+json"},
                b'{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "referrers": []}')
    v = oci_registry_gate.onboard_registry(
        _transport, "https://ghcr.io", "w344/repo",
        registry_kind="ghcr")
    return (v.get("verdict") == "refused",
            "OUT-matrix registry (ghcr) refused despite healthy probe: %s"
            % v.get("verdict"))


PROBES = [
    ("S1-admit-unsigned-layout", p1_admit_unsigned_layout),
    ("S1-admit-wrong-authority", p2_admit_wrong_authority),
    ("S2-install-untrusted-sig", p3_accept_untrusted_signature),
    ("S2-install-digest-mismatch", p4_accept_digest_mismatch),
    ("S2-install-stale-manifest", p5_accept_expired_manifest),
    ("S3-lifecycle-valid-chain", p6_lifecycle_valid),
    ("S3-lifecycle-broken-chain", p7_lifecycle_broken_chain),
    ("S3-lifecycle-expired-layout", p8_lifecycle_expired_layout),
    ("S4-discovery-unpinned", p9_discovery_unpinned),
    ("S4-discovery-identity-mismatch", p10_discovery_identity_mismatch),
    ("S5-registry-out-matrix", p11_registry_out_matrix),
]

EXPECTED_BREAKS = set()


def _green_check():
    """Depth-1 green check: the previous supply-chain batteries only, with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w342_attack_probes.py",):
        tmp = "/var/tmp/g344-green-%s" % script.replace(".py", "")
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        tail = (r.stdout + r.stderr)[-300:]
        notes.append("%s rc=%d %s" % (script, r.returncode, tail.strip()))
        if r.returncode != 0:
            raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None)
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()

    breaks = 0
    helds = 0
    errors = 0
    broken = []
    for pid, fn in PROBES:
        if args.only and args.only != pid:
            continue
        try:
            held, note = fn()
        except Exception as exc:  # noqa: BLE001
            errors += 1
            print("ERROR %s: %r" % (pid, exc))
            continue
        if held:
            helds += 1
            print("HELD  %s: %s" % (pid, note))
        else:
            breaks += 1
            broken.append(pid)
            print("BREAK %s: %s" % (pid, note))
    unexpected = set(broken) - EXPECTED_BREAKS
    print("result: %d BREAK / %d HELD / %d ERROR" % (breaks, helds, errors))
    if not args.skip_green:
        print("green check: %s" % _green_check())
    if unexpected or errors:
        raise SystemExit("UNEXPECTED: breaks=%r errors=%d"
                         % (sorted(unexpected), errors))


if __name__ == "__main__":
    main()
