"""F138 break probes: wall re-pinning has no authorship bar (filed 2026-09-23).

Gap: ``WallComponentInventory.install()`` re-pins a widened wall policy
through a bare function call. The receipt is sha256(manifest bytes) —
self-consistent, not operator-anchored (F136 R10). There is no human
authorship evidence on any pin, and no pin history: after a re-pin, the
prior policy digest is unrecoverable.

Break-first: these probes run against the UNFIXED code and must return
BREAK. After the fix (roster-human Ed25519 authorship tokens + chained
pin records), the bare re-pin is refused and the same probes return
CLOSED. The file is written to run in both eras: when the fix is
present, ``WallPinRefused`` exists and the bare call raises it.

Verdicts: CLOSED (gap unreachable) / BREAK (gap reachable — investigate)
/ CONTROL (positive control must keep holding) / ERROR (probe problem).

Run: TMPDIR=/tmp/gov-f138-<pid> ~/workspace/.gov-venv/bin/python evals/f138_break.py
"""

import json
import os
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.egress_launcher import (  # noqa: E402
    WallComponentInventory,
    install_simulated_wall,
)

try:
    from gov.egress_launcher import WallPinRefused  # noqa: E402
except ImportError:  # pre-fix era: the refusal type does not exist yet
    WallPinRefused = None


def _tmpdir():
    base = os.environ.get("TMPDIR", "/tmp")
    return tempfile.mkdtemp(prefix="f138break-", dir=base)


def _component_paths(sim):
    conf = os.path.join(sim, "conf")
    return {
        "nft_ruleset": os.path.join(conf, "agent0.nft.sim"),
        "proxy_allowlist": os.path.join(conf, "allowlist.txt"),
        "dns_config": os.path.join(conf, "dns_config.txt"),
        "dns_zone": os.path.join(conf, "dns_hosts.txt"),
        "proxy_impl": os.path.join(conf, "proxy_impl.txt"),
        "seccomp_config": os.path.join(conf, "seccomp_config.txt"),
    }


def _fresh_wall():
    tmp = _tmpdir()
    sim = os.path.join(tmp, "wall")
    inv, paths = install_simulated_wall(sim, wall_id="f138break")
    return tmp, sim, inv, paths


# ---------------------------------------------------------------- P1

def probe_bare_repin_widens_policy_no_authorship():
    """F138 core: an unauthorized caller widens the allowlist and
    re-pins via the bare install() call. No human authorship evidence
    is required, produced, or checked."""
    tmp, sim, inv, paths = _fresh_wall()
    manifest_path = os.path.join(sim, "wall_pins.json")
    receipt_path = os.path.join(sim, "wall_receipt.json")
    # Attacker widens the policy: allowlist now includes evil.example.
    allow = os.path.join(sim, "conf", "allowlist.txt")
    with open(allow, "a", encoding="utf-8") as f:
        f.write("evil.example:443\n")
    try:
        WallComponentInventory.install(
            _component_paths(sim), manifest_path, receipt_path)
    except Exception as e:
        if WallPinRefused is not None and isinstance(e, WallPinRefused) \
                and "pin_authorship_invalid" in str(e):
            return ("CLOSED",
                    "bare install() refused: %s" % e)
        return ("ERROR", "unexpected install failure: %r" % (e,))
    # The bare call succeeded. Does the new manifest carry ANY human
    # authorship evidence?
    manifest = json.load(open(manifest_path, encoding="utf-8"))
    blob = json.dumps(manifest)
    authorship_markers = ("author", "signature", "sig", "key_id",
                          "human", "approval", "pin_record", "prev")
    if any(m in blob.lower() for m in authorship_markers):
        return ("ERROR",
                "re-pin succeeded but manifest unexpectedly carries "
                "authorship markers")
    # And the launcher-side inventory verifies it without question.
    inv2 = WallComponentInventory(manifest_path, receipt_path)
    try:
        inv2.verify()
    except Exception as e:
        return ("ERROR", "re-pinned wall failed verify: %r" % (e,))
    allow_digests = [e["digests"]["sha256"]
                     for e in manifest["components"]
                     if e["name"] == "proxy_allowlist"]
    return ("BREAK",
            "unauthorized re-pin of widened allowlist verified cleanly; "
            "manifest carries zero authorship evidence "
            "(allowlist sha256=%s)" % (allow_digests[0][:16] if allow_digests else "?"))


# ---------------------------------------------------------------- P2

def probe_repin_erases_pin_history():
    """After an unauthorized re-pin, no record of the prior pin exists:
    no ledger, no prev-link, no way to detect the policy changed."""
    tmp, sim, inv, paths = _fresh_wall()
    manifest_path = os.path.join(sim, "wall_pins.json")
    receipt_path = os.path.join(sim, "wall_receipt.json")
    manifest_before = json.load(open(manifest_path, encoding="utf-8"))
    before_digests = {e["name"]: e["digests"]["sha256"]
                      for e in manifest_before["components"]}
    allow = os.path.join(sim, "conf", "allowlist.txt")
    with open(allow, "a", encoding="utf-8") as f:
        f.write("evil.example:443\n")
    try:
        WallComponentInventory.install(
            _component_paths(sim), manifest_path, receipt_path)
    except Exception as e:
        if WallPinRefused is not None and isinstance(e, WallPinRefused):
            return ("CLOSED",
                    "re-pin refused, history question moot: %s" % e)
        return ("ERROR", "unexpected install failure: %r" % (e,))
    manifest_after = json.load(open(manifest_path, encoding="utf-8"))
    # Is the prior pin referenced anywhere? Manifest, receipt, or any
    # adjacent history file?
    prior_ref = before_digests["proxy_allowlist"]
    haystack = json.dumps(manifest_after)
    receipt = open(receipt_path, encoding="utf-8").read()
    adjacent = os.listdir(sim)
    history_files = [f for f in adjacent
                     if "pinlog" in f.lower() or "history" in f.lower()
                     or "ledger" in f.lower()]
    if prior_ref in haystack or prior_ref in receipt or history_files:
        return ("ERROR",
                "re-pin succeeded but prior pin is still referenced "
                "(unexpected)")
    return ("BREAK",
            "prior pin digest %s... unrecoverable after re-pin: no "
            "ledger file, no prev-link in manifest, receipt only binds "
            "the NEW manifest" % prior_ref[:16])


# ---------------------------------------------------------------- P3

def probe_receipt_is_self_consistent_not_anchored():
    """The receipt is sha256(manifest bytes): anyone who can write the
    pin dir can mint a valid receipt. The 'trust anchor' is procedural
    file custody, not cryptography."""
    import hashlib
    tmp, sim, inv, paths = _fresh_wall()
    manifest_path = os.path.join(sim, "wall_pins.json")
    receipt_path = os.path.join(sim, "wall_receipt.json")
    blob = open(manifest_path, "rb").read()
    receipt = json.load(open(receipt_path, encoding="utf-8"))
    recomputed = hashlib.sha256(blob).hexdigest()
    if receipt.get("manifest_sha256") != recomputed:
        return ("ERROR", "receipt does not match sha256(manifest bytes)")
    if WallPinRefused is not None:
        # Fix present: the receipt alone was never the anchor. The
        # question is whether pins are now human-anchored.
        manifest = json.load(open(manifest_path, encoding="utf-8"))
        if "pin_record" in manifest and \
                manifest["pin_record"].get("author_key_ids"):
            return ("CLOSED",
                    "receipt still self-consistent, but pins are now "
                    "human-anchored via pin_record (residual: receipt "
                    "custody remains procedural)")
        return ("ERROR", "fix present but no pin_record in manifest")
    # No key material, signature, or human identity anywhere in the
    # receipt or manifest: minting a receipt needs no secret.
    if any(k in receipt for k in ("signature", "author", "key_id")):
        return ("ERROR", "receipt unexpectedly carries authorship")
    try:
        WallComponentInventory(manifest_path, receipt_path).verify()
    except Exception as e:
        return ("ERROR", "fresh wall failed verify: %r" % (e,))
    return ("BREAK",
            "receipt = sha256(manifest bytes), mintable by anyone with "
            "write access; no secret or human identity involved")


# ------------------------------------------------------------- CONTROL

def probe_control_honest_install_verifies():
    """Positive control: an honest install verifies cleanly."""
    try:
        tmp, sim, inv, paths = _fresh_wall()
        manifest, checked = inv.verify()
    except Exception as e:
        return ("ERROR", "honest install failed verify: %r" % (e,))
    if WallPinRefused is not None and "pin_record" not in manifest:
        return ("ERROR", "fix present but honest install lacks pin_record")
    return ("CONTROL", "honest install verifies")


_PROBES = [
    ("bare_repin_widens_policy_no_authorship",
     probe_bare_repin_widens_policy_no_authorship),
    ("repin_erases_pin_history", probe_repin_erases_pin_history),
    ("receipt_is_self_consistent_not_anchored",
     probe_receipt_is_self_consistent_not_anchored),
    ("control_honest_install_verifies",
     probe_control_honest_install_verifies),
]


def main():
    results = []
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001
            verdict, detail = "ERROR", "probe raised: %r" % (e,)
        results.append((name, verdict, detail))
        print("%-42s %-8s %s" % (name, verdict, detail))
    n_break = sum(1 for _, v, _ in results if v == "BREAK")
    n_closed = sum(1 for _, v, _ in results if v == "CLOSED")
    n_error = sum(1 for _, v, _ in results if v == "ERROR")
    print("---")
    print("BREAK=%d CLOSED=%d ERROR=%d" % (n_break, n_closed, n_error))
    return 1 if (n_break or n_error) else 0


if __name__ == "__main__":
    sys.exit(main())
