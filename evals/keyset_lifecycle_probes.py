#!/usr/bin/env python3
"""Wave-199 lane A red-team probes: Tink keyset-lifecycle (DISABLED/DESTROYED).

Break-first battery per the diagnosing-bugs skill. Pattern lineage:
tink-crypto/tink-py ``Keyset{primary_key_id, keys with
ENABLED/DISABLED/DESTROYED status}`` + ``KeysetInfo`` (Apache-2.0,
pattern-only -- no Tink code vendored; stdlib only, $0 spend).

The pristine tree's keyset model (``gov.keyset``) has
active/verify-only/revoked but NO intermediate DISABLED state and NO
terminal DESTROYED state, and its only serialization is the full
``to_dict()`` document (public keys + authorization signatures). Each
probe attacks that gap:

  L1 DISABLED_WARN   a winding-down key verifies but warns LOUD
                     (warn-and-rotate) and can never mint a signer
  L2 DESTROYED_DEAD  a destroyed key is refused on EVERY verification
                     path, including forensics (pristine's terminal
                     state, revoked, still verifies via forensics --
                     no fully-dead state exists)
  L3 INFO_MATERIAL   the audit projection (KeysetInfo-style) carries
                     zero key bytes (pristine's to_dict() leaks
                     public_key_hex + sigs into any snapshot built
                     from it)
  L4 NO_SIGN         no non-primary version can mint a signing handle
  L5 CHANGE_AUTH     disable/destroy are primary-authorized ceremonies;
                     misuse fails closed
  L6 KMS_STATUS      the KMS key-registry entry carries the lifecycle
                     status; DESTROYED refuses wrap/unwrap/describe
  L7 AUDIT_EVENT     the lifecycle audit event carries only the
                     material-free projection

On the pristine tree L1/L2/L5/L7 (keyset parts) report GAP ("capability
absent"), L3 reports GAP ("snapshot leaks material"), L4 is partial
(verify-only/revoked sub-checks HELD, disabled/destroyed inexpressible),
L6 reports GAP. After the fix all must flip to HELD.

Verdicts: HELD (defense held), GAP (gap demonstrated -- the red phase),
ERROR only on harness failure (a verdict changing between the two
deterministic runs, an unexpected exception).

Deterministic: all key material derives from SHA256(probe tags); every
probe runs twice and a verdict change is an ERROR. Synthetic/local only.
``GOV_SKIP_GREEN=1`` is honored (green check records a skip instead of
spawning sub-batteries).
"""

import contextlib
import hashlib
import io
import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

from gov import keyset as _ks  # noqa: E402
from gov import ed25519 as _ed  # noqa: E402
from gov.kms import FakeKmsProvider, KmsError, KeyDescription  # noqa: E402
from gov.signing import ed25519_key_id  # noqa: E402


def _seed(tag):
    """Deterministic 32-byte seed per probe tag."""
    return hashlib.sha256(("wave199-keyset-lifecycle:" + tag).encode()).digest()


def _v2_keyset():
    """A two-version keyset: v1 verify-only, v2 active primary."""
    ks, _s1 = _ks.new_keyset(_seed("v1"))
    ks, _s2 = _ks.rotate_keyset(ks, _seed("v2"), _seed("v1"))
    return ks


def _entry_signed_by(seed, version):
    pub = _ed.publickey(seed)
    kid = ed25519_key_id(pub)
    body = b"audit-entry-body"
    sig = _ed.sign(seed, body)
    return {"sig_key_id": kid, "sig_key_version": version,
            "body": body, "sig": sig}


def _material_strings(ks):
    """Every key-material hex string in the full keyset document."""
    doc = ks.to_dict()
    out = set()
    for v in doc["versions"]:
        out.add(v["public_key_hex"])
    for rec in doc.get("rotation_lineage", []):
        out.add(rec["to_public_key_hex"])
        out.add(rec["sig"])
    for rec in doc.get("revocations", []):
        out.add(rec["sig"])
    for rec in doc.get("status_changes", []):
        out.add(rec["sig"])
    return out


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str)


def _forbidden_keys(obj, forbidden, path="$"):
    """All paths where a forbidden dict key appears."""
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in forbidden:
                hits.append("%s.%s" % (path, k))
            hits.extend(_forbidden_keys(v, forbidden, "%s.%s" % (path, k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits.extend(_forbidden_keys(v, forbidden, "%s[%d]" % (path, i)))
    return hits


# ---------------------------------------------------------------------------
# Probes: each returns (held: bool, detail: str)
# ---------------------------------------------------------------------------

def _probe_l1_disabled_warn():
    """L1: DISABLED verifies + warns loudly + never mints."""
    if not hasattr(_ks, "disable_version") \
            or not hasattr(_ks, "STATUS_DISABLED"):
        return (False, "GAP: no DISABLED state / disable_version ritual; "
                       "a winding-down key is either silent verify-only or "
                       "dead-on-the-standard-path -- no warn-and-rotate")
    ks = _v2_keyset()
    ks = _ks.disable_version(ks, 1, "winding down", _seed("v2"))
    kv = ks.version(1)
    if kv.status != _ks.STATUS_DISABLED:
        return (False, "disable_version did not set DISABLED status")
    entry = _entry_signed_by(_seed("v1"), 1)
    _ks._warned_disabled.clear()
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        found, reason = ks.find_verifying_key(entry)
    warned = "DISABLED" in buf.getvalue() and "GOVERNANCE WARNING" in buf.getvalue()
    if found is None:
        return (False, "DISABLED key refused standard verification "
                       "(must be verify-only): %s" % reason)
    if "disabled" not in reason.lower():
        return (False, "DISABLED verify reason does not say so: %r" % reason)
    if not warned:
        return (False, "no loud DISABLED warning on stderr")
    try:
        _ks.keyset_signer_for_version(ks, 1, _seed("v1"))
        return (False, "minted a signing handle for a DISABLED version")
    except _ks.KeysetError:
        pass
    return (True, "DISABLED verifies + warns loudly + never mints")


def _probe_l2_destroyed_dead():
    """L2: DESTROYED refused on every path incl. forensics."""
    if not hasattr(_ks, "destroy_version") \
            or not hasattr(_ks, "STATUS_DESTROYED"):
        # Pristine gap, demonstrated concretely: the terminal state
        # (revoked) still verifies on the forensics path -- there is no
        # state in which a key is fully dead.
        ks = _v2_keyset()
        ks = _ks.revoke_version(ks, 1, "compromised", _seed("v2"))
        entry = _entry_signed_by(_seed("v1"), 1)
        found, _reason = ks.find_verifying_key_for_forensics(entry)
        detail = ("GAP: no DESTROYED state; pristine's terminal state "
                  "(revoked) still verifies via forensics "
                  "(forensics returned a key: %s)" % (found is not None))
        return (False, detail)
    ks = _v2_keyset()
    ks = _ks.destroy_version(ks, 1, "compromised", _seed("v2"))
    if ks.version(1).status != _ks.STATUS_DESTROYED:
        return (False, "destroy_version did not set DESTROYED status")
    entry = _entry_signed_by(_seed("v1"), 1)
    found, reason = ks.find_verifying_key(entry)
    if found is not None:
        return (False, "DESTROYED key verified on the standard path: %s"
                % reason)
    found_f, reason_f = ks.find_verifying_key_for_forensics(entry)
    if found_f is not None:
        return (False, "DESTROYED key verified on the forensics path: %s"
                % reason_f)
    try:
        _ks.keyset_signer_for_version(ks, 1, _seed("v1"))
        return (False, "minted a signing handle for a DESTROYED version")
    except _ks.KeysetError:
        pass
    return (True, "DESTROYED refused on standard + forensics paths; "
                  "never mints")


def _probe_l3_info_material():
    """L3: the audit projection carries zero key bytes."""
    ks = _v2_keyset()
    if not hasattr(ks, "keyset_info"):
        # Pristine gap: the only snapshot available is to_dict(),
        # which embeds public_key_hex per version.
        snap = _canonical(ks.to_dict())
        leaked = [m for m in _material_strings(ks) if m in snap]
        return (False, "GAP: no material-free projection; to_dict() "
                       "snapshot leaks %d key-material strings "
                       "(public keys + auth sigs)" % len(leaked))
    info = ks.keyset_info()
    snap = _canonical(info)
    leaked = [m for m in _material_strings(ks) if m in snap]
    if leaked:
        return (False, "keyset_info() leaks %d key-material strings"
                % len(leaked))
    bad_keys = _forbidden_keys(info, {"public_key_hex", "sig",
                                      "to_public_key_hex"})
    if bad_keys:
        return (False, "projection carries material fields: %s"
                % sorted(bad_keys))
    kids = [v["key_id"] for v in info["versions"]]
    if not kids or any(k not in snap for k in kids):
        return (False, "projection does not name the key ids")
    statuses = {v["status"] for v in info["versions"]}
    if statuses != {"verify-only", "active"}:
        return (False, "projection statuses wrong: %s" % sorted(statuses))
    return (True, "keyset_info() names key ids + statuses, zero key bytes")


def _probe_l4_no_sign_non_primary():
    """L4: no non-primary version can mint a signing handle."""
    cases = []  # (label, keyset, version, seed)
    base = _v2_keyset()
    cases.append(("verify-only", base, 1, _seed("v1")))
    ks = base
    missing = set()
    if hasattr(_ks, "disable_version"):
        ks = _ks.disable_version(ks, 1, "winding down", _seed("v2"))
        cases.append(("disabled", ks, 1, _seed("v1")))
    else:
        missing.add("disabled")
    if hasattr(_ks, "destroy_version"):
        ks = _ks.destroy_version(ks, 1, "compromised", _seed("v2"))
        cases.append(("destroyed", ks, 1, _seed("v1")))
    else:
        missing.add("destroyed")
    ks_r = _ks.revoke_version(_v2_keyset(), 1, "compromised", _seed("v2"))
    cases.append(("revoked", ks_r, 1, _seed("v1")))
    minted = []
    for label, kset, ver, seed in cases:
        try:
            _ks.keyset_signer_for_version(kset, ver, seed)
            minted.append(label)
        except _ks.KeysetError:
            pass
    if minted:
        return (False, "minted signers for non-primary: %s" % minted)
    if missing:
        return (False, "GAP: statuses inexpressible on pristine: %s"
                % sorted(missing))
    return (True, "no non-primary version mints (active-only)")


def _probe_l5_change_auth():
    """L5: disable/destroy are primary-authorized; misuse fails closed."""
    if not hasattr(_ks, "disable_version"):
        return (False, "GAP: no disable/destroy ceremonies to authorize")
    ks = _v2_keyset()
    # Wrong seed.
    try:
        _ks.disable_version(ks, 1, "x", _seed("wrong"))
        return (False, "disable_version accepted a wrong primary seed")
    except _ks.KeysetError:
        pass
    # Disabling the primary.
    try:
        _ks.disable_version(ks, 2, "x", _seed("v2"))
        return (False, "disable_version allowed disabling the primary")
    except _ks.KeysetError:
        pass
    # Double-disable.
    ks = _ks.disable_version(ks, 1, "winding down", _seed("v2"))
    try:
        _ks.disable_version(ks, 1, "again", _seed("v2"))
        return (False, "disable_version allowed a redundant transition")
    except _ks.KeysetError:
        pass
    # Tampered authorization record.
    doc = ks.to_dict()
    doc["status_changes"][0]["reason"] = "tampered"
    try:
        bad = _ks.Keyset.from_dict(doc)
    except _ks.KeysetError:
        return (True, "disable/destroy ceremonies fail closed")
    ok, _err = bad.verify()
    if ok:
        return (False, "tampered status_changes record still verifies")
    # Destroying the primary is refused.
    try:
        _ks.destroy_version(ks, 2, "x", _seed("v2"))
        return (False, "destroy_version allowed destroying the primary")
    except _ks.KeysetError:
        pass
    return (True, "disable/destroy ceremonies fail closed")


def _probe_l6_kms_status():
    """L6: the KMS registry entry carries lifecycle status."""
    prov = FakeKmsProvider(["k1"])
    if not hasattr(prov, "destroy_key"):
        return (False, "GAP: KMS registry has no DESTROYED state "
                       "(only enabled/disabled)")
    desc = prov.describe_key("k1").describe()
    if "status" not in desc:
        return (False, "KeyDescription.describe() lacks a status field")
    prov.destroy_key("k1")
    for op in (lambda: prov.wrap_data_key("k1", b"x" * 32),
               lambda: prov.unwrap_data_key("k1", b"junk"),
               lambda: prov.describe_key("k1")):
        try:
            op()
            return (False, "DESTROYED KMS key still usable")
        except KmsError:
            pass
    # Disabled behavior is unchanged (adjacent suite pins it).
    prov2 = FakeKmsProvider(["k2"])
    prov2.disable_key("k2")
    d2 = prov2.describe_key("k2").describe()
    if d2.get("status") != "disabled" or d2.get("enabled") is not False:
        return (False, "disabled KeyDescription wrong: %r" % d2)
    return (True, "KMS registry: destroyed refuses all ops; "
                  "status vocabulary on describe")


def _probe_l7_audit_event():
    """L7: the lifecycle audit event carries only the projection."""
    if not hasattr(_ks, "keyset_status_changed_event"):
        return (False, "GAP: no material-free lifecycle audit event")
    ks = _v2_keyset()
    ks = _ks.disable_version(ks, 1, "winding down", _seed("v2"))
    # from_status is derived from the signed status-change chain, not
    # caller-supplied -- the event cannot misstate the prior status.
    evt = _ks.keyset_status_changed_event(ks, 1, "winding down")
    snap = _canonical(evt)
    leaked = [m for m in _material_strings(ks) if m in snap]
    if leaked:
        return (False, "lifecycle audit event leaks %d key-material "
                       "strings" % len(leaked))
    tr = evt.get("transition", {})
    if tr.get("from_status") != "verify-only" \
            or tr.get("to_status") != "disabled":
        return (False, "event transition wrong: %r" % tr)
    return (True, "lifecycle audit event: projection only, zero key bytes")


_PROBES = (
    ("L1", "DISABLED_WARN", _probe_l1_disabled_warn),
    ("L2", "DESTROYED_DEAD", _probe_l2_destroyed_dead),
    ("L3", "INFO_MATERIAL", _probe_l3_info_material),
    ("L4", "NO_SIGN", _probe_l4_no_sign_non_primary),
    ("L5", "CHANGE_AUTH", _probe_l5_change_auth),
    ("L6", "KMS_STATUS", _probe_l6_kms_status),
    ("L7", "AUDIT_EVENT", _probe_l7_audit_event),
)


def main():
    results = []
    for tag, name, fn in _PROBES:
        run1 = fn()
        run2 = fn()
        if run1[0] != run2[0]:
            print("%s %s: ERROR (verdict changed between runs: %r vs %r)"
                  % (tag, name, run1, run2))
            results.append("ERROR")
            continue
        held, detail = run1
        print("%s %s: %s -- %s" % (tag, name,
                                   "HELD" if held else "GAP", detail))
        results.append("HELD" if held else "GAP")
    held_n = results.count("HELD")
    print("keyset-lifecycle: %d/%d HELD" % (held_n, len(results)))
    return 0 if held_n == len(results) else 1


def _green_check():
    """Depth-1 green check: adjacent unit suites only (never nested
    battery mains). Honors GOV_SKIP_GREEN by recording a skip."""
    import subprocess
    if _SKIP_GREEN:
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    for suite in ("tests.test_keyset", "tests.test_kms",
                  "tests.test_audit_entry_signing"):
        r = subprocess.run(
            [sys.executable, "-m", "unittest", suite, "-v"],
            cwd=REPO, env=env, capture_output=True, text=True, timeout=600)
        tail = (r.stderr or r.stdout).strip().splitlines()[-3:]
        print("GREEN CHECK %s: rc=%d %s" % (suite, r.returncode,
                                            " | ".join(tail)))
        if r.returncode != 0:
            return False
    return True


if __name__ == "__main__":
    rc = main()
    print("---")
    ok = _green_check()
    sys.exit(rc if ok else 2)
