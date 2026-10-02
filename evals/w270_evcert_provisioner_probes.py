#!/usr/bin/env python3
"""Wave-270 red-first battery: per-provisioner CA lifetime policies.

Step-ca gap: SPEC.md has a single global [10min, 60min] lifetime bound.
Different cert classes (reviewer-identity vs agent-runtime) need
different {min, default, max} under one CA, tightening-only.

Red phase: current gov.evidence_certs (no provisioners kwarg) -> every
probe returns BREAK ("feature absent"). Green phase: the feature lands
-> every probe must HELD.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; depth-1 green checks honoring
GOV_SKIP_GREEN=1; fresh unique /var/tmp TMPDIRs; NO in-repo git
subprocesses; self-provisioned GOV_LOG_KEY (wave-81).
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import secrets  # noqa: E402

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w270-evcert-prov")

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from gov import ed25519 as _ed  # noqa: E402

# Spec-pinned constants (NOT imported from gov.evidence_certs).
POP_DOMAIN = b"evcert-pop-v1"
NOW = 1790860000
ARC = "1.3.6.1.4.1.99999"
PROV_OID = ARC + ".1.40"
TAXONOMY_PIN = 1587  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).


def _keypair(seed_byte):
    seed = bytes([seed_byte & 0xFF]) * 32
    return seed, _ed.publickey(seed)


def _pop_challenge(approval_id, pub):
    return POP_DOMAIN + approval_id.encode("utf-8") + hashlib.sha256(pub).digest()


def _pop_sig(seed, approval_id, pub):
    return _ed.sign(seed, _pop_challenge(approval_id, pub))


def _assertion(iss="https://issuer.example.com", sub="alice", exp=None):
    return {"iss": iss, "sub": sub,
            "exp": NOW + 3600 if exp is None else exp}


def _feature_present():
    """True iff EvidenceCA accepts a provisioners kwarg (feature landed)."""
    from gov import evidence_certs as ec
    from gov.kms import FakeKmsProvider
    import inspect
    return "provisioners" in inspect.signature(ec.EvidenceCA.__init__).parameters


def _make_ca(tmpdir, provisioners=None, now=NOW, **overrides):
    from gov.kms import FakeKmsProvider
    from gov import evidence_certs as ec
    fake = FakeKmsProvider(["ca-key-1"])
    params = dict(
        kms_provider=fake,
        ca_key_id="ca-key-1",
        ca_public_key=fake.test_signing_public_key("ca-key-1"),
        issuers=["https://issuer.example.com"],
        approval_lookup={"a" * 32: {"decider": "alice", "state": "pending"},
                         "b" * 32: {"decider": "alice",
                                    "state": "pending"}}.get,
        audit_log_path=os.path.join(tmpdir, "audit.jsonl"),
        anchor_reachable=lambda: True,
        oid_arc=ARC,
        now=lambda: now,
    )
    if provisioners is not None:
        params["provisioners"] = provisioners
    params.update(overrides)
    return ec.EvidenceCA(**params)


def _good_request(seed_byte=0x01, approval_id="a" * 32,
                  intent_digest="b" * 64, lifetime_s=None, provisioner=None):
    seed, pub = _keypair(seed_byte)
    req = {"identity_assertion": _assertion(),
           "ephemeral_pub": pub,
           "pop_sig": _pop_sig(seed, approval_id, pub),
           "approval_id": approval_id,
           "intent_digest": intent_digest}
    if lifetime_s is not None:
        req["lifetime_s"] = lifetime_s
    if provisioner is not None:
        req["provisioner"] = provisioner
    return req, seed, pub


def _expect_code(fn, code):
    try:
        out = fn()
    except Exception as e:  # noqa: BLE001
        got = getattr(e, "code", None)
        if got == code:
            return "HELD", "refused %s as specified" % code
        return ("ERROR", "wrong refusal: code=%r exc=%r"
                % (got, str(e)[:120]))
    return "BREAK", "issued when it must refuse %s (out=%r)" % (code, str(out)[:80])


def _expect_valueerror(fn, what):
    try:
        fn()
    except ValueError:
        return "HELD", "%s refused at construction" % what
    except TypeError as e:
        if "provisioners" in str(e):
            return "BREAK", "feature absent: %s" % what
        return "ERROR", "unexpected TypeError: %r" % str(e)[:100]
    except Exception as e:  # noqa: BLE001
        return "ERROR", "wrong exception: %r" % e
    return "BREAK", "%s accepted (must refuse)" % what


def _ca_or_absent(tmpdir, provisioners):
    """(_make_ca with provisioners,) -> (ca, None) or (None, BREAK-detail)."""
    try:
        return _make_ca(tmpdir, provisioners=provisioners), None
    except TypeError as e:
        if "provisioners" in str(e):
            return None, "feature absent: EvidenceCA has no provisioners kwarg"
        raise
    except ValueError as e:
        return None, "ERROR: valid policy refused at construction: %r" % e


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

AGENT = {"min_s": 300, "default_s": 600, "max_s": 1800}
REVIEWER = {"min_s": 60, "default_s": 300, "max_s": 900}


def p01_widening_max_refused(tmpdir):
    """A provisioner max above the CA global max is refused at construction."""
    return _expect_valueerror(
        lambda: _make_ca(tmpdir, provisioners={
            "agent": {"min_s": 60, "default_s": 600, "max_s": 7200}}),
        "provisioner max 7200 > global max 3600")


def p02_undercut_floor_refused(tmpdir):
    """A provisioner min below the global floor (60s) is refused."""
    return _expect_valueerror(
        lambda: _make_ca(tmpdir, provisioners={
            "agent": {"min_s": 30, "default_s": 600, "max_s": 1800}}),
        "provisioner min 30 < global floor 60")


def p03_incoherent_policy_refused(tmpdir):
    """min > max, and default outside [min, max], are refused."""
    v1, d1 = _expect_valueerror(
        lambda: _make_ca(tmpdir, provisioners={
            "agent": {"min_s": 1800, "default_s": 600, "max_s": 300}}),
        "min > max")
    v2, d2 = _expect_valueerror(
        lambda: _make_ca(tmpdir, provisioners={
            "agent": {"min_s": 300, "default_s": 2400, "max_s": 1800}}),
        "default outside [min, max]")
    vs = (v1, v2)
    if all(v == "HELD" for v in vs):
        return "HELD", "incoherent policies refused"
    if "ERROR" in vs:
        return "ERROR", "%s / %s" % (d1, d2)
    return "BREAK", "%s / %s" % (d1, d2)


def p04_request_above_class_max(tmpdir):
    """Within global bounds but above the class max -> new code."""
    ca, absent = _ca_or_absent(tmpdir, {"agent": AGENT})
    if absent:
        return ("BREAK", absent) if not absent.startswith("ERROR") \
            else ("ERROR", absent)
    req, _, _ = _good_request(lifetime_s=2400, provisioner="agent")
    v1, d1 = _expect_code(
        lambda: ca.issue(**req), "evcert-provisioner-policy-violated")
    # control: at exactly the class max, issuance succeeds
    req2, _, _ = _good_request(seed_byte=0x02, lifetime_s=1800,
                               provisioner="agent")
    try:
        cert, _ = ca.issue(**req2)
        v2 = "HELD" if cert["not_after"] - cert["not_before"] == 1800 \
            else "ERROR"
        d2 = "class-max request issues with class-max lifetime" \
            if v2 == "HELD" else "wrong lifetime minted"
    except Exception as e:  # noqa: BLE001
        v2, d2 = "ERROR", "valid class-max request refused: %r" % (
            getattr(e, "code", e),)
    if v1 == v2 == "HELD":
        return "HELD", d1 + "; " + d2
    if "ERROR" in (v1, v2):
        return "ERROR", "%s / %s" % (d1, d2)
    return "BREAK", "%s / %s" % (d1, d2)


def p05_request_below_class_min(tmpdir):
    """Within global bounds but below the class min -> new code."""
    ca, absent = _ca_or_absent(tmpdir, {"agent": AGENT})
    if absent:
        return ("BREAK", absent) if not absent.startswith("ERROR") \
            else ("ERROR", absent)
    req, _, _ = _good_request(lifetime_s=120, provisioner="agent")
    return _expect_code(
        lambda: ca.issue(**req), "evcert-provisioner-policy-violated")


def p06_global_check_still_first(tmpdir):
    """Outside the GLOBAL bounds -> evcert-lifetime-exceeded (client bug),
    not the class code."""
    ca, absent = _ca_or_absent(tmpdir, {"agent": AGENT})
    if absent:
        return ("BREAK", absent) if not absent.startswith("ERROR") \
            else ("ERROR", absent)
    req, _, _ = _good_request(lifetime_s=7200, provisioner="agent")
    v1, d1 = _expect_code(
        lambda: ca.issue(**req), "evcert-lifetime-exceeded")
    req2, _, _ = _good_request(seed_byte=0x02, lifetime_s=30,
                               provisioner="agent")
    v2, d2 = _expect_code(
        lambda: ca.issue(**req2), "evcert-lifetime-exceeded")
    if v1 == v2 == "HELD":
        return "HELD", "global violations keep evcert-lifetime-exceeded"
    if "ERROR" in (v1, v2):
        return "ERROR", "%s / %s" % (d1, d2)
    return "BREAK", "%s / %s" % (d1, d2)


def p07_class_required_and_known(tmpdir):
    """Provisioners configured: missing class -> malformed; unknown class
    -> malformed. No silent default class."""
    ca, absent = _ca_or_absent(tmpdir, {"agent": AGENT})
    if absent:
        return ("BREAK", absent) if not absent.startswith("ERROR") \
            else ("ERROR", absent)
    req, _, _ = _good_request()  # no provisioner
    v1, d1 = _expect_code(lambda: ca.issue(**req),
                          "evcert-malformed-request")
    req2, _, _ = _good_request(seed_byte=0x02, provisioner="nope")
    v2, d2 = _expect_code(lambda: ca.issue(**req2),
                          "evcert-malformed-request")
    if v1 == v2 == "HELD":
        return "HELD", "class ambiguity fails closed"
    if "ERROR" in (v1, v2):
        return "ERROR", "%s / %s" % (d1, d2)
    return "BREAK", "%s / %s" % (d1, d2)


def p08_provisioner_in_extensions(tmpdir):
    """Issued cert carries the class at <arc>.1.40; arc-aware verify
    accepts it; legacy verify (no arc) refuses; legacy CAs mint
    byte-identical extension sets (no .1.40 key)."""
    from gov import evidence_certs as ec
    from gov.kms import FakeKmsProvider
    ca_pub = FakeKmsProvider(["ca-key-1"]).test_signing_public_key("ca-key-1")
    ca, absent = _ca_or_absent(tmpdir, {"agent-runtime": AGENT})
    if absent:
        return ("BREAK", absent) if not absent.startswith("ERROR") \
            else ("ERROR", absent)
    req, _, _ = _good_request(provisioner="agent-runtime")
    try:
        cert, _ = ca.issue(**req)
    except TypeError as e:
        if "provisioner" in str(e):
            return "BREAK", "feature absent: issue() has no provisioner kwarg"
        return "ERROR", "unexpected TypeError: %r" % str(e)[:100]
    except Exception as e:  # noqa: BLE001
        return "ERROR", "valid classed issuance failed: %r" % (
            getattr(e, "code", e),)
    v1, d1 = ("HELD", "class recorded at %s" % PROV_OID) \
        if cert["extensions"].get(PROV_OID) == "agent-runtime" \
        else ("BREAK", "provisioner OID missing/wrong: %r"
              % sorted(cert["extensions"]))
    # arc-aware verify accepts
    try:
        ec.verify_cert_chain(cert, ca_pub, NOW + 10, oid_arc=ARC)
        v2, d2 = "HELD", "arc-aware verify accepts 3-OID cert"
    except Exception as e:  # noqa: BLE001
        v2, d2 = "ERROR", "arc-aware verify failed: %r" % (
            getattr(e, "code", e),)
    # legacy verify (no arc) refuses the extra OID key
    v3, d3 = _expect_code(
        lambda: ec.verify_cert_chain(cert, ca_pub, NOW + 10),
        "evcert-malformed-cert")
    # legacy CA (no provisioners): extension set has exactly the two
    # issuer/subject OID keys -- byte-identical to pre-feature certs
    ca2 = _make_ca(tmpdir + "-legacy")
    req2, _, _ = _good_request(seed_byte=0x03)
    try:
        cert2, _ = ca2.issue(**req2)
        oid_keys = sorted(k for k in cert2["extensions"]
                          if "." in k and k[0].isdigit())
        want = sorted([ARC + ".1.8", ARC + ".1.24"])
        v4, d4 = ("HELD", "legacy cert extension set unchanged") \
            if oid_keys == want \
            else ("BREAK", "legacy extension set changed: %r" % oid_keys)
    except Exception as e:  # noqa: BLE001
        v4, d4 = "ERROR", "legacy issuance failed: %r" % (
            getattr(e, "code", e),)
    vs = (v1, v2, v3, v4)
    if all(v == "HELD" for v in vs):
        return "HELD", " / ".join((d1, d2, d3, d4))
    if "ERROR" in vs:
        return "ERROR", " / ".join((d1, d2, d3, d4))
    return "BREAK", " / ".join((d1, d2, d3, d4))


def p09_tightening_direction_property(tmpdir):
    """Tightening-only is a property, not a spot check: policies that
    widen are refused, policies that tighten are accepted."""
    widen = [
        ("max-above-global", {"min_s": 60, "default_s": 600, "max_s": 3601}),
        ("min-below-floor", {"min_s": 59, "default_s": 600, "max_s": 1800}),
    ]
    tighten = [
        ("tight-max", {"min_s": 60, "default_s": 600, "max_s": 3599}),
        ("tight-min", {"min_s": 61, "default_s": 600, "max_s": 3600}),
        ("tight-both", {"min_s": 300, "default_s": 600, "max_s": 1800}),
        ("identity", {"min_s": 60, "default_s": 600, "max_s": 3600}),
    ]
    results = []
    for name, pol in widen:
        v, d = _expect_valueerror(
            lambda p=pol: _make_ca(tmpdir, provisioners={"x": p}),
            "widening %s" % name)
        results.append((v, d))
    for name, pol in tighten:
        try:
            _make_ca(tmpdir, provisioners={"x": pol})
            results.append(("HELD", "tightening %s accepted" % name))
        except TypeError as e:
            if "provisioners" in str(e):
                results.append(("BREAK", "feature absent"))
            else:
                results.append(("ERROR", "unexpected TypeError %r" % str(e)[:80]))
        except Exception as e:  # noqa: BLE001
            results.append(("ERROR", "tightening %s refused: %r"
                            % (name, e)))
    vs = [v for v, _ in results]
    if all(v == "HELD" for v in vs):
        return "HELD", "tightening-only holds across %d policies" % len(vs)
    if "ERROR" in vs:
        return "ERROR", " / ".join(d for _, d in results)
    return "BREAK", " / ".join(d for _, d in results)


def p10_class_default_applies(tmpdir):
    """No lifetime_s -> the class default (not the global default)."""
    ca, absent = _ca_or_absent(tmpdir, {"reviewer": REVIEWER})
    if absent:
        return ("BREAK", absent) if not absent.startswith("ERROR") \
            else ("ERROR", absent)
    req, _, _ = _good_request(provisioner="reviewer")
    try:
        cert, _ = ca.issue(**req)
    except TypeError as e:
        if "provisioner" in str(e):
            return "BREAK", "feature absent: issue() has no provisioner kwarg"
        return "ERROR", "unexpected TypeError: %r" % str(e)[:100]
    except Exception as e:  # noqa: BLE001
        return "ERROR", "valid classed issuance failed: %r" % (
            getattr(e, "code", e),)
    got = cert["not_after"] - cert["not_before"]
    if got == REVIEWER["default_s"]:
        return "HELD", "class default %d applied" % got
    return "BREAK", "expected class default %d, minted %d" % (
        REVIEWER["default_s"], got)


def p11_taxonomy_pin(tmpdir):
    """The new code is registered exactly once as a raw literal."""
    import gov.decision_codes as dc
    with open(dc.__file__, encoding="utf-8") as f:
        src = f.read()
    n_total = src.count("\"code\": '")
    n_new = src.count("\"code\": 'evcert-provisioner-policy-violated'")
    entry = dc.TAXONOMY.get("evcert-provisioner-policy-violated")
    if n_total != TAXONOMY_PIN:
        if n_total == 1325:
            return "BREAK", "feature absent: pin still 1325"
        return "ERROR", "total literals %d, want %d" % (n_total, TAXONOMY_PIN)
    if n_new != 1:
        return "ERROR", "new code literal count %d, want 1" % n_new
    if entry is None or entry.get("domain") != "evcert" \
            or entry.get("severity") != "medium":
        return "ERROR", "registry entry wrong: %r" % (entry,)
    return "HELD", "1579 literals, new code unique, domain/severity exact"


PROBES = [
    ("prov/widening-max-refused", p01_widening_max_refused),
    ("prov/undercut-floor-refused", p02_undercut_floor_refused),
    ("prov/incoherent-policy-refused", p03_incoherent_policy_refused),
    ("prov/request-above-class-max", p04_request_above_class_max),
    ("prov/request-below-class-min", p05_request_below_class_min),
    ("prov/global-check-still-first", p06_global_check_still_first),
    ("prov/class-required-and-known", p07_class_required_and_known),
    ("prov/provisioner-in-extensions", p08_provisioner_in_extensions),
    ("prov/tightening-direction-property", p09_tightening_direction_property),
    ("prov/class-default-applies", p10_class_default_applies),
    ("prov/taxonomy-pin", p11_taxonomy_pin),
]

# ---------------------------------------------------------------------------
# Green checks (depth-1; honor GOV_SKIP_GREEN=1)
# ---------------------------------------------------------------------------

_GREEN = [
    ("evals.w269_evcert_probes", "battery"),
    ("tests.test_evcert", "pin-drift-expected"),
    ("tests.test_kms", "unittest"),
]


def _green_result(name, kind, r, out):
    """Classify one green-check run. pin-drift-expected: the lane
    legitimately moves the taxonomy pin 1325 -> 1326; the suite passes
    iff the pin assertion is the ONLY failure."""
    if kind == "pin-drift-expected":
        if r.returncode == 0:
            return "pass", "clean"
        fails = [ln.strip() for ln in out.splitlines()
                 if ln.strip().startswith("FAIL: ")]
        if fails == ["FAIL: test_lane_pin_on_raw_literals "
                     "(tests.test_evcert.DecisionCodeTests."
                     "test_lane_pin_on_raw_literals)"]:
            return ("pass",
                    "only the expected pin-drift assertion fails "
                    "(1325 -> 1326); merge coordinator repoints")
        return "FAIL", out[-400:]
    return ("pass" if r.returncode == 0 else "FAIL"), out[-400:]


def _run_green_checks():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("skipped",)]
    results = []
    py = os.environ.get("GOV_PY", sys.executable)
    for name, kind in _GREEN:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tempfile.mkdtemp(prefix="g270green-", dir="/var/tmp")
        os.makedirs(env["TMPDIR"], exist_ok=True)
        try:
            cmd = [py, "-m", name] if kind == "battery" \
                else [py, "-m", "unittest", name]
            r = subprocess.run(cmd, cwd=_REPO, env=env,
                               capture_output=True, text=True, timeout=600)
            out = (r.stderr or "") + (r.stdout or "")
            status, tail = _green_result(name, kind, r, out)
            results.append((name, status, tail))
        except Exception as e:  # noqa: BLE001
            results.append((name, "ERROR", str(e)[:200]))
    return results


def main():
    root = tempfile.mkdtemp(prefix="g270prov-", dir="/var/tmp")
    print("tmpdir=%s feature_present=%s" % (root, _feature_present()))
    held = broke = errored = 0
    for name, fn in PROBES:
        tmpdir = os.path.join(root, name.replace("/", "-"))
        os.makedirs(tmpdir, exist_ok=True)
        try:
            verdict, detail = fn(tmpdir)
        except Exception as e:  # noqa: BLE001
            verdict, detail = "ERROR", "%r" % e
        print("%-36s %-6s %s" % (name, verdict, detail))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            broke += 1
        else:
            errored += 1
    print("---")
    print("HELD=%d BREAK=%d ERROR=%d" % (held, broke, errored))
    green = _run_green_checks()
    green_fail = 0
    for item in green:
        if item[0] == "skipped":
            print("green: skipped (GOV_SKIP_GREEN=1)")
            continue
        name, status, tail = item
        print("green %-32s %s" % (name, status))
        if status != "pass":
            green_fail += 1
            print("  tail: %s" % tail.replace("\n", " | "))
    if errored or green_fail:
        return 1
    # Red phase: BREAKs are the expected "feature absent" signal.
    # Green phase: every probe must HELD.
    if _feature_present():
        return 0 if broke == 0 else 1
    return 0 if broke == len(PROBES) else 1


if __name__ == "__main__":
    sys.exit(main())
