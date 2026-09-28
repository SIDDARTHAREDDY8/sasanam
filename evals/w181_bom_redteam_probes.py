#!/usr/bin/env python3
"""Wave-181 red-team probes: the Decision BOM surface (gov/decision_bom.py
+ the BOM cross-checks in gov/decision_packet.py::_verify).

Break-first battery per the diagnosing-bugs skill. Each probe attacks a
concrete seam of wave-180 lane A's Decision BOM and reports BREAK (gap
demonstrated), HELD (defense held), or HELD* (held, with a documented
residual or limitation worth naming). The product code is UNMODIFIED;
every probe runs against the pristine tree at 94c8f84.

Public seams probed: ``build_bom`` / ``verify_decision_packet`` /
``verify_bom``. Threat model: a key-holding producer (F196's own model --
able to mint and re-sign arbitrary packets) for the tamper/transplant
probes; a keyless attacker for the malformed-shape probes. Targets:

  T1 BOM/policy-section disagreement (id, version, digest)
  T2 BOM evidence.head_digest vs packet evidence.head_digest
  T3 BOM principal fields vs packet identity section
  T4 Pin confusion (BOM names pins, packet names no skill; wrong pin
     digest; the on-demand verify_bom leg)
  T5 Approval provenance (approval_id without record digest at build;
     tampered record_digest at every seam)
  T6 Malformed BOM shapes (build loud, verify fail-closed, never raise)
  T7 Signature stripping (section removed / replaced, re-signed or not)
  T8 The BOM mandate on every packet-building path (no BOM-less packet
     may verify)
  T9 Cross-packet BOM replay (transplanted valid BOM, partial and full)
  T10 The offline trio (decision_packet.py + decision_bom.py +
     ed25519.py copied standalone): the cross-checks must hold there too

Deterministic (every probe runs twice; a verdict change is an ERROR),
synthetic/local only, $0. Exit nonzero only on harness ERRORs -- BREAK
is the expected red-team outcome (a filed finding), not a battery
failure.
"""

import copy
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

TREE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TREE))

from gov import decision_packet as _dp
from gov import decision_bom as _bom

_records = []


def _record(pid, verdict, detail):
    _records.append((pid, verdict, detail))
    print("%-4s %-7s %s" % (pid, verdict, detail), flush=True)


def _fresh_tmp():
    os.makedirs("/var/tmp", exist_ok=True)
    return tempfile.mkdtemp(prefix="w181bom-", dir="/var/tmp")


_PROBES = []


def probe(pid, name):
    def deco(fn):
        _PROBES.append((pid, name, fn))
        return fn
    return deco


def _run_probe(pid, name, fn):
    try:
        v1, d1 = fn()
        v2, d2 = fn()
    except Exception as e:  # noqa: BLE001 -- harness must not die
        _record(pid, "ERROR", "%s: %s" % (type(e).__name__, e))
        return
    if v1 != v2:
        _record(pid, "ERROR",
                "non-deterministic: %r vs %r" % ((v1, d1), (v2, d2)))
        return
    _record(pid, v1, d1)


# ---------------------------------------------------------------------------
# Fixtures: one honest, internally-consistent packet (+BOM)
# ---------------------------------------------------------------------------

_POLICY_BYTES = b"w181-probe-policy-bundle-v1"
_POLICY_DIGEST = hashlib.sha256(_POLICY_BYTES).hexdigest()
_POLICY_ID = "pol"
_POLICY_VERSION = "1"
_HEAD = "aa" * 32
_IDENT = {"agent_id": "ag", "role": "coder",
          "principal": "p", "run_id": "run1"}
_APPROVAL_ID = "A1"
_RECORD_DIGEST = hashlib.sha256(
    b"w181-probe-approval-record-A1").hexdigest()
_SEED = bytes.fromhex("ab" * 32)
_SKILL_ID = "skill-x"
_SKILL_DIGEST = hashlib.sha256(b"w181-probe-skill-x").hexdigest()
_ISSUED = "2026-09-28T00:00:00+00:00"


def _honest_bom(**over):
    kw = dict(policy_id=_POLICY_ID, policy_version=_POLICY_VERSION,
              policy_digest=_POLICY_DIGEST,
              evidence_head_digest=_HEAD, principal=dict(_IDENT),
              approval_id=_APPROVAL_ID,
              approval_record_digest=_RECORD_DIGEST)
    kw.update(over)
    return _bom.build_bom(**kw)


def _packet_kwargs(bom, **over):
    kw = dict(decision="allow", boundary_declared=False,
              policy_id=_POLICY_ID, policy_version=_POLICY_VERSION,
              matched_rules=["r1"], policy_flag=None,
              decision_digest="dd" * 32,
              canonical_target="/x",
              preview_digest=hashlib.sha256(b"p").hexdigest(),
              capability_manifest_digest=None, skill_id=None,
              evidence_head_digest=_HEAD,
              identity=dict(_IDENT),
              approval_id=_APPROVAL_ID, decision_seq=1,
              bill_of_materials=bom,
              policy_bundle_digest=_POLICY_DIGEST,
              issued_at=_ISSUED)
    kw.update(over)
    return kw


def _sign(bom, **over):
    body = _dp.build_decision_packet(**_packet_kwargs(bom, **over))
    return _dp.sign_packet(body, _SEED)


def _honest_packet():
    return _sign(_honest_bom())


@probe("P0", "honest packet verifies (sanity)")
def _p0():
    ok, reason = _dp.verify_decision_packet(_honest_packet())
    if ok:
        return "HELD", "honest BOM-bound packet verifies"
    return "BREAK", "honest packet failed: %s" % reason


# ---------------------------------------------------------------------------
# T1: BOM / policy-section disagreement
# ---------------------------------------------------------------------------

@probe("P1a", "BOM policy_id disagrees with the packet's policy section")
def _p1a():
    bom = _honest_bom(policy_id="pol-evil")
    pkt = _sign(bom)
    ok, reason = _dp.verify_decision_packet(pkt)
    if not ok and "policy_id" in reason:
        return "HELD", "refused: %s" % reason
    return "BREAK", "verified despite policy_id disagreement: %s" % reason


@probe("P1b", "BOM policy_version disagrees with the packet's policy "
              "section")
def _p1b():
    bom = _honest_bom(policy_version="2")
    pkt = _sign(bom)
    ok, reason = _dp.verify_decision_packet(pkt)
    if not ok and "policy_version" in reason:
        return "HELD", "refused: %s" % reason
    return "BREAK", \
        "verified despite policy_version disagreement: %s" % reason


@probe("P1c", "BOM policy digest disagrees with packet policy_bundle_digest")
def _p1c():
    bom = _honest_bom(policy_digest="de" * 32)
    pkt = _sign(bom)
    ok, reason = _dp.verify_decision_packet(pkt)
    if not ok and "policy digest" in reason:
        return "HELD", "refused: %s" % reason
    return "BREAK", "verified despite digest disagreement: %s" % reason


@probe("P1d", "packet policy_bundle_digest=None skips the digest "
              "cross-check")
def _p1d():
    # The None hatch is DOCUMENTED in decision_packet.py ("the
    # cross-check is then skipped") and unreachable via the executor
    # (build_bom raises on a non-hex policy digest before the packet is
    # built), so this is a direct-builder-only residual, not a break.
    bom = _honest_bom(policy_digest="de" * 32)
    pkt = _sign(bom, policy_bundle_digest=None)
    ok, reason = _dp.verify_decision_packet(pkt)
    if ok:
        return ("HELD*",
                "verifies with digest disagreement SKIPPED (bundle None): "
                "residual -- a direct builder can dodge the packet-level "
                "digest check; the on-demand verify_bom leg (P1e) still "
                "re-derives")
    return "HELD", "refused: %s" % reason


@probe("P1e", "consistent lie in BOM+packet section caught by verify_bom "
              "re-derivation")
def _p1e():
    # The key-holding producer lies consistently: the SAME bogus digest
    # in the BOM and in the packet's policy_bundle_digest. The packet
    # cross-check cannot see it -- the on-demand audit leg must.
    bogus = "de" * 32
    bom = _honest_bom(policy_digest=bogus)
    pkt = _sign(bom, policy_bundle_digest=bogus)
    ok, _r = _dp.verify_decision_packet(pkt)
    if not ok:
        return "HELD", "packet verify itself refused the consistent lie"
    ok2, r2 = _bom.verify_bom(bom, policy_bundle_bytes=_POLICY_BYTES)
    if not ok2 and "re-derive" in r2:
        return "HELD", ("packet verifies (consistent lie) but verify_bom "
                        "re-derivation fails closed: %s" % r2)
    return "BREAK", "consistent policy lie survives verify_bom: %s" % r2


# ---------------------------------------------------------------------------
# T2: head mismatch
# ---------------------------------------------------------------------------

@probe("P2", "BOM head_digest disagrees with packet evidence head_digest")
def _p2():
    bom = _honest_bom(evidence_head_digest="bb" * 32)
    pkt = _sign(bom)
    ok, reason = _dp.verify_decision_packet(pkt)
    if not ok and "head_digest" in reason:
        return "HELD", "refused: %s" % reason
    return "BREAK", "verified despite head disagreement: %s" % reason


# ---------------------------------------------------------------------------
# T3: principal mismatch
# ---------------------------------------------------------------------------

@probe("P3", "each BOM principal field disagrees in turn")
def _p3():
    bad = []
    for field in ("agent_id", "role", "principal", "run_id"):
        ident = dict(_IDENT)
        ident[field] = "evil-" + field
        bom = _honest_bom(principal=ident)
        pkt = _sign(bom)
        ok, reason = _dp.verify_decision_packet(pkt)
        if ok:
            bad.append(field)
    if not bad:
        return "HELD", "all four principal-field disagreements refused"
    return "BREAK", "verified despite principal.%s disagreement" % bad


# ---------------------------------------------------------------------------
# T4: pin confusion
# ---------------------------------------------------------------------------

def _skilled_packet(bom):
    return _sign(bom, skill_id=_SKILL_ID,
                 capability_manifest_digest=_SKILL_DIGEST)


@probe("P4a", "BOM names pins but the packet names no skill")
def _p4a():
    bom = _honest_bom(pin_digests={_SKILL_ID: _SKILL_DIGEST})
    pkt = _sign(bom)  # skill_id=None
    ok, reason = _dp.verify_decision_packet(pkt)
    if not ok and "no skill" in reason:
        return "HELD", "refused: %s" % reason
    return "BREAK", "verified despite orphan pins: %s" % reason


@probe("P4b", "wrong pin digest for the packet's named skill")
def _p4b():
    bom = _honest_bom(pin_digests={_SKILL_ID: "ff" * 32})
    pkt = _skilled_packet(bom)
    ok, reason = _dp.verify_decision_packet(pkt)
    if not ok and "pin digest" in reason:
        return "HELD", "refused: %s" % reason
    return "BREAK", "verified despite wrong pin digest: %s" % reason


@probe("P4c", "packet names a skill but the BOM names no pins")
def _p4c():
    bom = _honest_bom()  # pins = {}
    pkt = _skilled_packet(bom)
    ok, reason = _dp.verify_decision_packet(pkt)
    if not ok and "pin digest" in reason:
        return "HELD", "refused: %s" % reason
    return "BREAK", "verified despite missing pin entry: %s" % reason


@probe("P4d", "extra pins beyond the packet's named skill pass the "
              "packet-level check")
def _p4d():
    # Residual (documented): the packet-level cross-check binds only the
    # packet's named skill. Extra pins are shape-valid and must be
    # audited via verify_bom + the pin registry on demand.
    bom = _honest_bom(pin_digests={_SKILL_ID: _SKILL_DIGEST,
                                   "skill-y": "ee" * 32})
    pkt = _skilled_packet(bom)
    ok, reason = _dp.verify_decision_packet(pkt)
    if ok:
        return ("HELD*",
                "verifies: cross-check covers the named skill only; "
                "extra pins are BOM-shape-valid and need verify_bom + "
                "registry to audit")
    return "HELD", "refused: %s" % reason


@probe("P4e", "verify_bom re-derives the named pin against the registry")
def _p4e():
    bom = _honest_bom(pin_digests={_SKILL_ID: "ff" * 32})
    ok, reason = _bom.verify_bom(
        bom, pin_digests={_SKILL_ID: _SKILL_DIGEST})
    if not ok and "registry" in reason:
        return "HELD", "refused: %s" % reason
    return "BREAK", "swapped pin survives verify_bom: %s" % reason


# ---------------------------------------------------------------------------
# T5: approval provenance
# ---------------------------------------------------------------------------

@probe("P5a", "approval_id with no record digest refuses at build")
def _p5a():
    try:
        _bom.build_bom(
            policy_id=_POLICY_ID, policy_version=_POLICY_VERSION,
            policy_digest=_POLICY_DIGEST,
            evidence_head_digest=_HEAD, principal=dict(_IDENT),
            approval_id=_APPROVAL_ID, approval_record_digest=None)
    except _bom.BomError as e:
        return "HELD", "BomError: %s" % e
    return "BREAK", "build_bom accepted an approval_id with no record digest"


@probe("P5b", "tampered record_digest fails verify_bom when the auditor supplies approval records (F200)")
def _p5b():
    # F200 close-when: verify_bom accepts approval_records and
    # re-derives the BOM's approval record_digest against them, failing
    # closed on mismatch -- the MATCH rule for the BOM->approval edge.
    # A key-holding producer's swapped digest now fails on the
    # on-demand audit path. (verify_decision_packet still does not
    # re-derive: the finding's close-when scopes the fix to
    # verify_bom; the packet seam stays attestation-only by design.)
    tampered = "00" * 32
    assert tampered != _RECORD_DIGEST
    bom = _honest_bom(approval_record_digest=tampered)
    ok, reason = _bom.verify_bom(
        bom, policy_bundle_bytes=_POLICY_BYTES, pin_digests={},
        approval_records={_APPROVAL_ID: _RECORD_DIGEST})
    if not ok and "approval" in reason.lower():
        return "HELD", "tampered record_digest refused: %s" % reason
    return ("BREAK",
            "tampered record_digest survived verify_bom with records "
            "supplied: %r" % ((ok, reason),))


@probe("P5c", "no-approval decisions build honestly (approval None/None)")
def _p5c():
    bom = _honest_bom(approval_id=None, approval_record_digest=None)
    pkt = _sign(bom, approval_id=None)
    ok, reason = _dp.verify_decision_packet(pkt)
    if ok:
        return "HELD", "honest no-approval packet verifies"
    return "BREAK", "honest no-approval packet failed: %s" % reason


@probe("P5d", "approval leg reported UNVERIFIED when records not supplied")
def _p5d():
    # F200 close-when, second half: a BOM naming an approval, verified
    # WITHOUT approval_records, must not present its approval leg as
    # verified. Honest reporting, not a pass.
    bom = _honest_bom()
    ok, reason = _bom.verify_bom(bom, policy_bundle_bytes=_POLICY_BYTES,
                                 pin_digests={})
    if ok and "unverified" in reason.lower() \
            and "approval" in reason.lower():
        return "HELD", "approval leg honestly UNVERIFIED: %s" % reason
    return ("BREAK",
            "approval leg not reported UNVERIFIED: %r" % ((ok, reason),))


# ---------------------------------------------------------------------------
# T6: malformed BOM shapes
# ---------------------------------------------------------------------------

def _malformed_boms():
    good = _honest_bom()
    cases = {}
    cases["not-a-dict"] = "x"
    cases["none"] = None
    cases["list"] = []
    v = copy.deepcopy(good)
    v["bom_version"] = "1"
    cases["bom_version-str"] = v
    v = copy.deepcopy(good)
    del v["inputs"]
    cases["inputs-missing"] = v
    v = copy.deepcopy(good)
    v["inputs"]["policy"]["policy_id"] = ""
    cases["empty-policy-id"] = v
    v = copy.deepcopy(good)
    v["inputs"]["policy"]["policy_version"] = ""
    cases["empty-policy-version"] = v
    v = copy.deepcopy(good)
    v["inputs"]["policy"]["digest"] = "ZZ" * 32
    cases["nonhex-digest"] = v
    v = copy.deepcopy(good)
    v["inputs"]["policy"]["digest"] = _POLICY_DIGEST.upper()
    cases["uppercase-digest"] = v
    v = copy.deepcopy(good)
    v["inputs"]["policy"]["digest"] = _POLICY_DIGEST[:32]
    cases["short-digest"] = v
    v = copy.deepcopy(good)
    v["inputs"]["pins"] = ["skill-x"]
    cases["pins-not-dict"] = v
    v = copy.deepcopy(good)
    v["inputs"]["pins"] = {_SKILL_ID: "not-hex"}
    cases["pin-nonhex"] = v
    v = copy.deepcopy(good)
    v["inputs"]["evidence"] = {}
    cases["evidence-empty"] = v
    v = copy.deepcopy(good)
    v["inputs"]["principal"] = "ag"
    cases["principal-not-dict"] = v
    v = copy.deepcopy(good)
    v["inputs"]["approval"]["approval_id"] = ""
    cases["approval-id-empty"] = v
    v = copy.deepcopy(good)
    v["inputs"]["approval"]["record_digest"] = "zz" * 32
    cases["record-nonhex"] = v
    return cases


@probe("P6a", "check_bom_shape rejects every malformed shape")
def _p6a():
    bad = [name for name, bom in _malformed_boms().items()
           if _bom.check_bom_shape(bom)[0]]
    if not bad:
        return "HELD", "16/16 malformed shapes rejected"
    return "BREAK", "shape-valid malformed BOMs: %s" % bad


@probe("P6b", "build_bom is loud on malformed inputs")
def _p6b():
    def kw(**over):
        base = dict(policy_id=_POLICY_ID, policy_version=_POLICY_VERSION,
                    policy_digest=_POLICY_DIGEST,
                    evidence_head_digest=_HEAD, principal=dict(_IDENT))
        base.update(over)
        return base
    cases = {
        "empty-policy-id": kw(policy_id=""),
        "empty-policy-version": kw(policy_version=""),
        "nonhex-digest": kw(policy_digest="zz" * 32),
        "none-digest": kw(policy_digest=None),
        "empty-head": kw(evidence_head_digest=""),
        "principal-not-dict": kw(principal="ag"),
        "pin-bad-digest": kw(pin_digests={"s": "zz"}),
        "pin-empty-id": kw(pin_digests={"": _SKILL_DIGEST}),
        "approval-empty-id": kw(approval_id="",
                                approval_record_digest=_RECORD_DIGEST),
        "approval-bad-record": kw(approval_id="A1",
                                  approval_record_digest="zz"),
    }
    bad = []
    for name, k in cases.items():
        try:
            _bom.build_bom(**k)
        except _bom.BomError:
            continue
        bad.append(name)
    if not bad:
        return "HELD", "10/10 malformed builds raise BomError"
    return "BREAK", "build_bom accepted: %s" % bad


@probe("P6e", "build_bom raises BomError (not a bare builtin) for "
              "non-dict pin_digests")
def _p6e():
    # The docstring contract: "Every required input is validated LOUD
    # ... raises BomError". But `dict(pin_digests)` runs BEFORE the
    # isinstance check, so a non-mapping iterable raises bare
    # ValueError and a non-iterable raises bare TypeError. Filed as
    # F201 (F198-shaped: error-type contract deviation).
    def kw(**over):
        base = dict(policy_id=_POLICY_ID, policy_version=_POLICY_VERSION,
                    policy_digest=_POLICY_DIGEST,
                    evidence_head_digest=_HEAD, principal=dict(_IDENT))
        base.update(over)
        return base
    leaks = []
    for name, val in (("list", ["x"]), ("str", "ab"), ("int", 5)):
        try:
            _bom.build_bom(**kw(pin_digests=val))
        except _bom.BomError:
            continue
        except Exception as e:  # noqa: BLE001
            leaks.append("%s->%s" % (name, type(e).__name__))
            continue
        leaks.append("%s->accepted" % name)
    if not leaks:
        return "HELD", "non-dict pin_digests raises BomError"
    return "BREAK", "wrong exception type escapes build_bom: %s" % leaks


@probe("P6c", "verify_bom never raises on garbage")
def _p6c():
    garbage = [None, "x", [], {}, {"inputs": {}},
               {"bom_version": 1, "inputs": None}]
    for g in garbage:
        try:
            ok, _r = _bom.verify_bom(g)
        except Exception as e:  # noqa: BLE001
            return "BREAK", "verify_bom raised on %r: %s" % (g, e)
        if ok:
            return "BREAK", "verify_bom accepted %r" % (g,)
    try:
        ok, _r = _bom.verify_bom(_honest_bom(),
                                 policy_bundle_bytes="not-bytes")
    except Exception as e:  # noqa: BLE001
        return "BREAK", "verify_bom raised on str bytes: %s" % e
    if not ok:
        return "HELD", "garbage -> (False, ...) always, never raises"
    return "BREAK", "verify_bom accepted str policy_bundle_bytes"


@probe("P6d", "packet build refuses a missing or malformed BOM")
def _p6d():
    refused = 0
    for bom in (None, {"garbage": 1}, "x", _honest_bom()):
        if bom is None or not isinstance(bom, dict) or \
                not _bom.check_bom_shape(bom)[0]:
            try:
                _dp.build_decision_packet(**_packet_kwargs(bom))
            except _dp.PacketError:
                refused += 1
                continue
            return "BREAK", \
                "build_decision_packet accepted BOM %r" % (bom,)
    # the honest BOM must build (else the probe is vacuous)
    try:
        _dp.build_decision_packet(**_packet_kwargs(_honest_bom()))
    except _dp.PacketError as e:
        return "BREAK", "honest BOM refused at build: %s" % e
    if refused == 3:
        return "HELD", "missing/malformed BOM refused at build (PacketError)"
    return "BREAK", "only %d/3 refused" % refused


# ---------------------------------------------------------------------------
# T7: signature stripping
# ---------------------------------------------------------------------------

@probe("P7a", "signature stripped -> verify fails")
def _p7a():
    pkt = _honest_packet()
    pkt2 = {k: v for k, v in pkt.items() if k != "signature"}
    ok, reason = _dp.verify_decision_packet(pkt2)
    if not ok:
        return "HELD", "refused: %s" % reason
    return "BREAK", "signature-less packet verified"


@probe("P7b", "BOM section deleted (no re-sign) -> verify fails")
def _p7b():
    pkt = _honest_packet()
    pkt2 = copy.deepcopy(pkt)
    del pkt2["bill_of_materials"]
    ok, reason = _dp.verify_decision_packet(pkt2)
    if not ok:
        return "HELD", "refused: %s" % reason
    return "BREAK", "BOM-less packet verified"


@probe("P7c", "BOM replaced with a valid-but-disagreeing BOM, re-signed "
              "with the same key -> verify fails")
def _p7c():
    # A valid BOM for a DIFFERENT decision (different head/approval/
    # principal), transplanted, then re-signed by the key holder.
    other_bom = _honest_bom(
        evidence_head_digest="cc" * 32, approval_id="A9",
        approval_record_digest="dd" * 32,
        principal={"agent_id": "other", "role": "coder",
                   "principal": "p", "run_id": "run9"})
    pkt = _sign(other_bom)  # packet sections still name A1/aa/ag
    ok, reason = _dp.verify_decision_packet(pkt)
    if not ok:
        return "HELD", "refused: %s" % reason
    return "BREAK", "transplanted disagreeing BOM verified"


@probe("P7d", "attacker-key re-sign of a consistently-lying packet "
              "verifies (trust-root residual)")
def _p7d():
    # Residual (documented): verify_decision_packet authenticates the
    # packet to the key IN the packet's authority block; it does not
    # bind that key to a trusted root. A caller that treats True as
    # "the executor said this" without pinning the expected kid/pubkey
    # out-of-band is misusing the seam. Chain linkage (entries) is the
    # in-protocol trust anchor.
    bogus = "de" * 32
    bom = _honest_bom(policy_digest=bogus)
    body = _dp.build_decision_packet(**_packet_kwargs(
        bom, policy_bundle_digest=bogus))
    attacker = _dp.sign_packet(body, bytes.fromhex("cd" * 32))
    ok, reason = _dp.verify_decision_packet(attacker)
    if ok:
        return ("HELD*",
                "verifies under the attacker's own key: residual -- the "
                "verifier has no trust-root input; callers must pin the "
                "expected kid/pubkey out-of-band")
    return "HELD", "refused: %s" % reason


# ---------------------------------------------------------------------------
# T8: the BOM mandate on every packet-building path
# ---------------------------------------------------------------------------

@probe("P8a", "direct builder: no BOM-less packet can be built")
def _p8a():
    try:
        _dp.build_decision_packet(**_packet_kwargs(None))
    except _dp.PacketError as e:
        return "HELD", "PacketError: %s" % e
    return "BREAK", "build_decision_packet built a BOM-less packet"


@probe("P8b", "hand-stripped + re-signed BOM-less packet fails verify")
def _p8b():
    pkt = _honest_packet()
    body = {k: v for k, v in pkt.items()
            if k not in ("signature", "bill_of_materials")}
    pkt2 = _dp.sign_packet(body, _SEED)
    ok, reason = _dp.verify_decision_packet(pkt2)
    if not ok:
        return "HELD", "refused: %s" % reason
    return "BREAK", "re-signed BOM-less packet verified"


@probe("P8c", "BOM section present but value None fails verify")
def _p8c():
    pkt = _honest_packet()
    body = {k: v for k, v in pkt.items() if k != "signature"}
    body["bill_of_materials"]["value"] = None
    pkt2 = _dp.sign_packet(body, _SEED)
    ok, reason = _dp.verify_decision_packet(pkt2)
    if not ok:
        return "HELD", "refused: %s" % reason
    return "BREAK", "None-BOM packet verified"


@probe("P8d", "empty principal dict is shape-valid and verifies "
              "(builder-side laxity)")
def _p8d():
    # Residual (documented): build_bom requires principal to be a dict
    # but not to carry any fields; the cross-check agrees on None ==
    # None. The executor always fills the real identity, so this is a
    # direct-builder-only shape. Not a finding: no claim is made that
    # build_bom enforces principal completeness.
    bom = _honest_bom(principal={})
    pkt = _sign(bom, identity={})
    ok, reason = _dp.verify_decision_packet(pkt)
    if ok:
        return ("HELD*",
                "verifies with an all-None principal: residual -- "
                "build_bom does not require principal fields; the "
                "executor always fills them")
    return "HELD", "refused: %s" % reason


# ---------------------------------------------------------------------------
# T9: cross-packet BOM replay
# ---------------------------------------------------------------------------

@probe("P9a", "valid BOM from packet A transplanted into an otherwise "
              "honest packet B fails")
def _p9a():
    # A's BOM (approval A1, head aa, principal ag/run1) transplanted
    # into B, whose own sections name approval A2, head bb, a different
    # principal. B is re-signed by the key holder.
    bom_a = _honest_bom()
    pkt_b = _sign(bom_a, approval_id="A2", evidence_head_digest="bb" * 32,
                  identity={"agent_id": "ag2", "role": "coder",
                            "principal": "p", "run_id": "run2"})
    ok, reason = _dp.verify_decision_packet(pkt_b)
    if not ok:
        return "HELD", "refused: %s" % reason
    return "BREAK", "transplanted BOM verified: %s" % reason


@probe("P9b", "full-lie replay (B's sections rewritten to match A's BOM) "
              "is caught by the F196 decision_digest re-derivation")
def _p9b():
    # The attacker rewrites B's sections to agree with A's BOM
    # everywhere the BOM binds, re-signs -- but the packet still
    # answers a DIFFERENT chained decision entry. With entries
    # supplied, the F196 MATCH re-derives decision_digest from the
    # entry at the stated head and the replay fails.
    policy_decision = {"policy_id": _POLICY_ID, "decision": "allow"}
    real_dd = hashlib.sha256(
        _dp.canonical_bytes(policy_decision)).hexdigest()
    bom_a = _honest_bom()
    pkt_b = _sign(bom_a, decision_digest="ff" * 32)  # bogus, answers A
    digest_b = _dp.packet_digest(pkt_b)
    entries = [
        {"event": "decision", "hash": _HEAD, "prev_hash": "GENESIS",
         "policy_decision": policy_decision},
        {"event": "decision_packet", "hash": "h1", "prev_hash": _HEAD,
         "packet_digest": digest_b, "approval_id": _APPROVAL_ID,
         "decision_seq": 1},
    ]
    assert real_dd != "ff" * 32
    ok, reason = _dp.verify_decision_packet(pkt_b, entries)
    if not ok and "F196" in reason:
        return "HELD", "refused: %s" % reason
    return "BREAK", "full-lie replay verified: %s" % reason


# ---------------------------------------------------------------------------
# T10: the offline trio (standalone copies, no gov package)
# ---------------------------------------------------------------------------

_OFFLINE_MAIN = textwrap.dedent('''
    import copy, hashlib, sys
    sys.path.insert(0, __import__("sys").argv[1])
    import decision_packet as dp
    import decision_bom as bom

    POL = b"w181-probe-policy-bundle-v1"
    PDIG = hashlib.sha256(POL).hexdigest()
    IDENT = {"agent_id": "ag", "role": "coder",
             "principal": "p", "run_id": "run1"}
    SEED = bytes.fromhex("ab" * 32)

    b = bom.build_bom(policy_id="pol", policy_version="1",
                      policy_digest=PDIG, evidence_head_digest="aa" * 32,
                      principal=dict(IDENT), approval_id="A1",
                      approval_record_digest="11" * 32)
    body = dp.build_decision_packet(
        decision="allow", boundary_declared=False,
        policy_id="pol", policy_version="1", matched_rules=["r1"],
        decision_digest="dd" * 32, canonical_target="/x",
        preview_digest=hashlib.sha256(b"p").hexdigest(),
        evidence_head_digest="aa" * 32, identity=dict(IDENT),
        approval_id="A1", decision_seq=1, bill_of_materials=b,
        policy_bundle_digest=PDIG, issued_at="2026-09-28T00:00:00+00:00")
    pkt = dp.sign_packet(body, SEED)
    ok, r = dp.verify_decision_packet(pkt)
    assert ok, "offline honest packet failed: %s" % r

    # Tampered BOM (disagreeing policy version), re-signed: the
    # cross-check must fail even in the standalone copy.
    b2 = copy.deepcopy(b)
    b2["inputs"]["policy"]["policy_version"] = "9"
    body2 = dict(body)
    body2["bill_of_materials"] = dict(body2["bill_of_materials"])
    body2["bill_of_materials"]["value"] = b2
    pkt2 = dp.sign_packet(body2, SEED)
    ok2, r2 = dp.verify_decision_packet(pkt2)
    assert not ok2 and "policy_version" in r2, \
        "offline tampered BOM verified: %s" % r2

    # verify_bom re-derivation works standalone too.
    ok3, r3 = bom.verify_bom(b, policy_bundle_bytes=POL)
    assert ok3, "offline verify_bom failed: %s" % r3
    ok4, r4 = bom.verify_bom(b, policy_bundle_bytes=b"other")
    assert not ok4, "offline verify_bom accepted wrong bytes"
    print("offline-trio OK")
''')


@probe("P10", "offline trio: cross-checks hold in the standalone copy")
def _p10():
    tmp = _fresh_tmp()
    for name in ("decision_packet.py", "decision_bom.py", "ed25519.py"):
        shutil.copy(str(TREE / "gov" / name), str(Path(tmp) / name))
    main = Path(tmp) / "offline_main.py"
    main.write_text(_OFFLINE_MAIN, encoding="utf-8")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    proc = subprocess.run(
        [sys.executable, str(main), tmp],
        capture_output=True, text=True, env=env, cwd=tmp, timeout=300)
    if proc.returncode == 0 and "offline-trio OK" in proc.stdout:
        return "HELD", "standalone copy: honest verifies, tampered fails"
    return "BREAK", "offline trio failed: rc=%d out=%r err=%r" % (
        proc.returncode, proc.stdout[-300:], proc.stderr[-300:])


# ---------------------------------------------------------------------------
# Green check (depth-1) + main
# ---------------------------------------------------------------------------

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green_check", "SKIP",
                "GOV_SKIP_GREEN=1; standalone run still checks itself")
        return
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    # Adjacent suites: the BOM and packet unit tests must stay green
    # (no product code changed in this lane; this is a no-collateral
    # check).
    proc = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_decision_bom", "tests.test_decision_packet"],
        capture_output=True, text=True, env=env,
        cwd=str(TREE), timeout=600)
    tail = (proc.stdout + proc.stderr)[-300:]
    _record("green_check_adjacent",
            "PASS" if proc.returncode == 0 else "FAIL",
            "exit=%d tail=%r" % (proc.returncode, tail))
    if proc.returncode != 0:
        raise SystemExit("green check failed")


def main():
    _green_check()
    for pid, name, fn in _PROBES:
        _run_probe(pid, name, fn)
    brk = [p for p, v, _d in _records if v == "BREAK"]
    err = [p for p, v, _d in _records if v == "ERROR"]
    held = [p for p, v, _d in _records if v == "HELD"]
    helddoc = [p for p, v, _d in _records if v == "HELD*"]
    print("breaks=%d held=%d held_documented=%d errors=%d"
          % (len(brk), len(held), len(helddoc), len(err)))
    if brk:
        print("BREAK: %s" % ", ".join(brk))
    if helddoc:
        print("HELD*: %s" % ", ".join(helddoc))
    sys.exit(1 if err else 0)


if __name__ == "__main__":
    main()
