"""Break-first red-team battery for continuous skill/MCP bundle
supply-chain verification (wave-267 feature lane: TUF + in-toto pair).

Target: gov/skill_supply_chain.py -- event-driven lifecycle
verification: TUF-half delegation-aware targets authority (path-scoped
delegations, terminating, revocation-by-absence, threshold signatures,
pinned eval-start expiry, rollback protection, snapshot binding) and
in-toto-half lifecycle layouts (ordered transitions, signer
thresholds, chained link records, artifact rules via
gov/artifact_rules with a single terminal DISALLOW).

Every probe attacks a PUBLIC seam, never product internals. The
battery imports the implementation via GOV_SUPPCHAIN_IMPL (default
"gov.skill_supply_chain"); against the permissive stub
(GOV_SUPPCHAIN_IMPL=stub) every attack probe must BREAK, proving the
probes are real. Against the real module every probe must HELD, in
staging and under `env -u GOV_DEPLOYMENT_MODE`.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. A probe returns (held, detail); held=True means HELD
(refused with the expected machine code / gap is a documented
residual), held=False means BREAK (genuine defect) or harness ERROR.

Stdlib only. Deterministic (fixed seeds, fixed epochs). No in-repo
git subprocesses (wave-36 supply-chain probe: fail closed). Green
checks are depth-1 and honor GOV_SKIP_GREEN=1.
"""

import hashlib
import importlib
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

TAXONOMY_PIN = 1743  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete)

_IMPL = os.environ.get("GOV_SUPPCHAIN_IMPL", "gov.skill_supply_chain")
_STUB_DIR = "/tmp/w267_suppchain_stub"

_STUB_SRC = '''"""Permissive stub: authorizes everything, checks nothing,
reports vacuous ok with empty coverage. Every attack probe must BREAK
against this."""
import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

CODES = (
    "supplychain-delegation-path-unauthorized",
    "supplychain-delegation-revoked",
    "supplychain-delegation-signature-invalid",
    "supplychain-eval-start-invalid",
    "supplychain-frozen",
    "supplychain-layout-expired",
    "supplychain-layout-signature-invalid",
    "supplychain-link-chain-broken",
    "supplychain-link-unauthorized",
    "supplychain-malformed",
    "supplychain-rollback",
    "supplychain-snapshot-mismatch",
    "supplychain-transition-rules-failed",
)


class SupplyChainError(Exception):
    def __init__(self, code, detail=""):
        super(SupplyChainError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def seal_document(kind, doc, signers):
    return b"stub"


def verify_delegated_authority(delegation_wire, authz_wire, skill_path,
                               root_trust, eval_start, trusted=None,
                               parent_pin=None):
    return {"ok": True, "kind": "delegated-authority",
            "skill": skill_path, "version": 1, "digest": "0" * 64,
            "delegation": "stub", "delegation_version": 1,
            "eval_start": eval_start, "checked": [],
            "out_of_scope": [], "evidence_digest": "0" * 64}


def verify_lifecycle(layout_wire, link_wires, keys, eval_start):
    return {"ok": True, "kind": "lifecycle", "bundle": "stub",
            "layout_version": 1, "eval_start": eval_start,
            "transitions": [], "checked": [], "out_of_scope": [],
            "evidence_digest": "0" * 64}


def to_evidence(report):
    return {"kind": "supplychain-verdict", "subject": "stub",
            "verdict": "stub", "evidence_digest": "0" * 64,
            "record_digest": "0" * 64}
'''


def _load_impl():
    if _IMPL == "stub":
        os.makedirs(_STUB_DIR, exist_ok=True)
        path = os.path.join(_STUB_DIR, "suppchain_stub.py")
        with open(path, "w") as f:
            f.write(_STUB_SRC)
        sys.path.insert(0, _STUB_DIR)
        return importlib.import_module("suppchain_stub")
    return importlib.import_module(_IMPL)


dc = _load_impl()

# Fixed fixtures: deterministic keys and epochs.
from gov.signing import Ed25519Signer  # noqa: E402
from gov.bundle_refresh import tuf_canonical_json  # noqa: E402

def _seed(tag):
    return (tag + "-seed").ljust(32, "0")[:32].encode("ascii")


_R1 = Ed25519Signer(_seed("r1-root"))
_P1 = Ed25519Signer(_seed("p1-payments"))
_P2 = Ed25519Signer(_seed("p2-payments"))
_C1 = Ed25519Signer(_seed("c1-core"))
_M1 = Ed25519Signer(_seed("m1-attacker"))

EVAL_START = 1700000000.0
FUTURE = "2030-01-01T00:00:00Z"
PAST = "2020-01-01T00:00:00Z"


def _keyinfo(signer):
    return {"keytype": "ed25519",
            "keyval": {"public": signer.public_key.hex()}}


_KEYS = {
    "r1": _keyinfo(_R1),
    "pay-k1": _keyinfo(_P1),
    "pay-k2": _keyinfo(_P2),
    "core-k1": _keyinfo(_C1),
    "mallory": _keyinfo(_M1),
}

_ROOT_TRUST = {
    "keys": _KEYS,
    "root": {"keyids": ["r1"], "threshold": 1},
}


def _seal(kind, doc, signers):
    return dc.seal_document(kind, doc,
                           [(kid, s) for kid, s in signers])


def _delegation_doc(version, delegations, expires=FUTURE):
    return {"version": version, "expires": expires,
            "delegations": delegations}


def _delegation(name, keyids, threshold, paths, terminating=False):
    return {"name": name, "keyids": keyids, "threshold": threshold,
            "paths": paths, "terminating": terminating}


def _authz(skill, version, digest, expires=FUTURE):
    return {"skill": skill, "version": version, "digest": digest,
            "expires": expires}


def _digests(*names):
    return {n: hashlib.sha256(("content:" + n).encode()).hexdigest()
            for n in names}


def _expect(code, fn):
    """Run fn; HELD iff it raises SupplyChainError with exactly code."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - probe harness
        got = getattr(exc, "code", None)
        if got == code:
            return True, "HELD with %s" % code
        return False, "BREAK: expected %s, got %s: %s" % (
            code, got, str(exc)[:160])
    return False, "BREAK: expected %s refusal, call succeeded: %r" % (
        code, str(result)[:120])


# ---------------------------------------------------------------------------
# TUF-half probes
# ---------------------------------------------------------------------------

def p_delegation_path_escape():
    """Attacker gets a payments-team signature on an admin-path authz.
    No delegation covers skills/admin/* -> must refuse."""
    deleg = _delegation_doc(1, [_delegation(
        "payments-team", ["pay-k1"], 1, ["skills/payments/*"])])
    dwire = _seal("delegations", deleg, [("r1", _R1)])
    awire = _seal("link", _authz("skills/admin/backdoor", 1,
                                 "ab" * 32),
                  [("pay-k1", _P1)])
    return _expect("supplychain-delegation-path-unauthorized",
                   lambda: dc.verify_delegated_authority(
                       dwire, awire, "skills/admin/backdoor",
                       _ROOT_TRUST, EVAL_START))


def p_delegation_terminating_stop():
    """Terminating payments delegation matches but its authz signature
    is bad; a later core delegation would verify. The first path-match
    is authoritative -> signature-invalid, not fall-through."""
    deleg = _delegation_doc(1, [
        _delegation("payments-team", ["pay-k1"], 1,
                    ["skills/payments/*"], terminating=True),
        _delegation("core-team", ["core-k1"], 1, ["skills/*"]),
    ])
    dwire = _seal("delegations", deleg, [("r1", _R1)])
    awire = _seal("link", _authz("skills/payments/x", 1, "ab" * 32),
                  [("core-k1", _C1)])
    return _expect("supplychain-delegation-signature-invalid",
                   lambda: dc.verify_delegated_authority(
                       dwire, awire, "skills/payments/x",
                       _ROOT_TRUST, EVAL_START))


def p_delegation_threshold():
    deleg = _delegation_doc(1, [_delegation(
        "payments-team", ["pay-k1", "pay-k2"], 2,
        ["skills/payments/*"])])
    dwire = _seal("delegations", deleg, [("r1", _R1)])
    awire = _seal("link", _authz("skills/payments/x", 1, "ab" * 32),
                  [("pay-k1", _P1)])  # only 1 of 2
    return _expect("supplychain-delegation-signature-invalid",
                   lambda: dc.verify_delegated_authority(
                       dwire, awire, "skills/payments/x",
                       _ROOT_TRUST, EVAL_START))


def p_delegation_revoked():
    deleg = _delegation_doc(3, [_delegation(
        "payments-team", ["pay-k1"], 1, ["skills/payments/*"])])
    dwire = _seal("delegations", deleg, [("r1", _R1)])
    awire = _seal("link", _authz("skills/payments/x", 1, "ab" * 32),
                  [("pay-k1", _P1)])
    trusted = {"delegations_version": 2,
               "delegations": {"old-team": 1, "payments-team": 1}}
    return _expect("supplychain-delegation-revoked",
                   lambda: dc.verify_delegated_authority(
                       dwire, awire, "skills/payments/x",
                       _ROOT_TRUST, EVAL_START, trusted=trusted))


def p_delegation_rollback():
    deleg = _delegation_doc(2, [_delegation(
        "payments-team", ["pay-k1"], 1, ["skills/payments/*"])])
    dwire = _seal("delegations", deleg, [("r1", _R1)])
    awire = _seal("link", _authz("skills/payments/x", 1, "ab" * 32),
                  [("pay-k1", _P1)])
    trusted = {"delegations_version": 3}
    return _expect("supplychain-rollback",
                   lambda: dc.verify_delegated_authority(
                       dwire, awire, "skills/payments/x",
                       _ROOT_TRUST, EVAL_START, trusted=trusted))


def p_delegation_frozen():
    deleg = _delegation_doc(1, [_delegation(
        "payments-team", ["pay-k1"], 1, ["skills/payments/*"])],
        expires=PAST)
    dwire = _seal("delegations", deleg, [("r1", _R1)])
    awire = _seal("link", _authz("skills/payments/x", 1, "ab" * 32),
                  [("pay-k1", _P1)])
    return _expect("supplychain-frozen",
                   lambda: dc.verify_delegated_authority(
                       dwire, awire, "skills/payments/x",
                       _ROOT_TRUST, EVAL_START))


def p_delegation_eval_start_pinned():
    """Same inputs, same eval_start -> identical verdict; expiry is
    exclusive (expires == eval_start is frozen)."""
    deleg = _delegation_doc(1, [_delegation(
        "payments-team", ["pay-k1"], 1, ["skills/payments/*"])],
        expires="2020-01-01T00:00:00Z")
    dwire = _seal("delegations", deleg, [("r1", _R1)])
    awire = _seal("link", _authz("skills/payments/x", 1, "ab" * 32),
                  [("pay-k1", _P1)])
    # boundary: expires(1577836800) == eval_start -> frozen
    held, detail = _expect(
        "supplychain-frozen",
        lambda: dc.verify_delegated_authority(
            dwire, awire, "skills/payments/x",
            _ROOT_TRUST, 1577836800.0))
    if not held:
        return False, "boundary: " + detail
    # determinism on the legit path
    deleg2 = _delegation_doc(1, [_delegation(
        "payments-team", ["pay-k1"], 1, ["skills/payments/*"])])
    d2 = _seal("delegations", deleg2, [("r1", _R1)])
    r1 = dc.verify_delegated_authority(d2, awire, "skills/payments/x",
                                       _ROOT_TRUST, EVAL_START)
    r2 = dc.verify_delegated_authority(d2, awire, "skills/payments/x",
                                       _ROOT_TRUST, EVAL_START)
    if r1["evidence_digest"] != r2["evidence_digest"]:
        return False, "BREAK: evidence digest not deterministic"
    if not r1["checked"]:
        return False, "BREAK: empty coverage on legit path"
    return True, "HELD: boundary frozen + deterministic, %d checks" % len(
        r1["checked"])


def p_delegation_root_threshold():
    deleg = _delegation_doc(1, [_delegation(
        "payments-team", ["pay-k1"], 1, ["skills/payments/*"])])
    dwire = _seal("delegations", deleg, [("mallory", _M1)])
    awire = _seal("link", _authz("skills/payments/x", 1, "ab" * 32),
                  [("pay-k1", _P1)])
    return _expect("supplychain-delegation-signature-invalid",
                   lambda: dc.verify_delegated_authority(
                       dwire, awire, "skills/payments/x",
                       _ROOT_TRUST, EVAL_START))


def p_delegation_snapshot_mismatch():
    deleg = _delegation_doc(1, [_delegation(
        "payments-team", ["pay-k1"], 1, ["skills/payments/*"])])
    dwire = _seal("delegations", deleg, [("r1", _R1)])
    awire = _seal("link", _authz("skills/payments/x", 1, "ab" * 32),
                  [("pay-k1", _P1)])
    return _expect("supplychain-snapshot-mismatch",
                   lambda: dc.verify_delegated_authority(
                       dwire, awire, "skills/payments/x",
                       _ROOT_TRUST, EVAL_START, parent_pin="ff" * 32))


def p_delegation_legit_control():
    deleg = _delegation_doc(1, [_delegation(
        "payments-team", ["pay-k1", "pay-k2"], 2,
        ["skills/payments/*"])])
    dwire = _seal("delegations", deleg, [("r1", _R1)])
    awire = _seal("link", _authz("skills/payments/x", 2, "ab" * 32),
                  [("pay-k1", _P1), ("pay-k2", _P2)])
    pin = hashlib.sha256(dwire).hexdigest()
    try:
        rep = dc.verify_delegated_authority(
            dwire, awire, "skills/payments/x", _ROOT_TRUST,
            EVAL_START, parent_pin=pin)
    except Exception as exc:  # noqa: BLE001
        return False, "BREAK: legit control refused: %s" % str(exc)[:160]
    if rep.get("delegation") != "payments-team" or not rep.get("ok"):
        return False, "BREAK: bad legit report: %r" % (rep,)
    ev = dc.to_evidence(rep)
    if ev["evidence_digest"] != rep["evidence_digest"]:
        return False, "BREAK: evidence link broken"
    return True, "HELD: legit delegation authorized, evidence linked"

# ---------------------------------------------------------------------------
# in-toto-half fixtures and probes
# ---------------------------------------------------------------------------

_D = _digests("bundle.tar.gz", "manifest.json", "unpacked/skill.py",
              "installed.marker", "evil.sh")

_LAYOUT_TRANSITIONS = [
    {"name": "publish",
     "signers": {"keyids": ["pay-k1"], "threshold": 1},
     "expected_materials": [],
     "expected_products": [["CREATE", "bundle.tar.gz"],
                           ["REQUIRE", "manifest.json"]]},
    {"name": "fetch",
     "signers": {"keyids": ["pay-k1"], "threshold": 1},
     "expected_materials": [["MATCH", "bundle.tar.gz",
                             _D["bundle.tar.gz"]],
                            ["MATCH", "manifest.json",
                             _D["manifest.json"]]],
     "expected_products": [["CREATE", "unpacked/skill.py"]]},
    {"name": "install",
     "signers": {"keyids": ["pay-k1"], "threshold": 1},
     "expected_materials": [["MATCH", "unpacked/skill.py",
                             _D["unpacked/skill.py"]]],
     "expected_products": [["CREATE", "installed.marker"]]},
]


def _layout(expires=FUTURE, signer_kid="r1", signer=_R1):
    doc = {"bundle": "skills/payments/x", "version": 1,
           "expires": expires,
           "authority": {"keyids": ["r1"], "threshold": 1},
           "transitions": _LAYOUT_TRANSITIONS}
    return _seal("layout", doc, [(signer_kid, signer)])


def _link_doc(transition, materials, products, prev_digest):
    return {"transition": transition, "materials": materials,
            "products": products, "byproducts": {},
            "prev_digest": prev_digest}


def _good_links(signer_kid="pay-k1", signer=_P1):
    """Three correctly chained links, correctly signed."""
    l0 = _link_doc("publish", {},
                   {"bundle.tar.gz": _D["bundle.tar.gz"],
                    "manifest.json": _D["manifest.json"]},
                   "0" * 64)
    h0 = hashlib.sha256(tuf_canonical_json(l0)).hexdigest()
    l1 = _link_doc("fetch",
                   {"bundle.tar.gz": _D["bundle.tar.gz"],
                    "manifest.json": _D["manifest.json"]},
                   {"unpacked/skill.py": _D["unpacked/skill.py"]}, h0)
    h1 = hashlib.sha256(tuf_canonical_json(l1)).hexdigest()
    l2 = _link_doc("install",
                   {"unpacked/skill.py": _D["unpacked/skill.py"]},
                   {"installed.marker": _D["installed.marker"]}, h1)
    return [_seal("link", l, [(signer_kid, signer)]) for l in (l0, l1, l2)]


def _seal_links(docs, signer_kid="pay-k1", signer=_P1):
    return [_seal("link", d, [(signer_kid, signer)]) for d in docs]


def p_lifecycle_chain_break():
    """Tamper the fetch link's prev_digest -> chain broken."""
    l0 = _link_doc("publish", {},
                   {"bundle.tar.gz": _D["bundle.tar.gz"],
                    "manifest.json": _D["manifest.json"]}, "0" * 64)
    l1 = _link_doc("fetch",
                   {"bundle.tar.gz": _D["bundle.tar.gz"],
                    "manifest.json": _D["manifest.json"]},
                   {"unpacked/skill.py": _D["unpacked/skill.py"]},
                   "ff" * 32)  # tampered
    h1 = hashlib.sha256(tuf_canonical_json(l1)).hexdigest()
    l2 = _link_doc("install",
                   {"unpacked/skill.py": _D["unpacked/skill.py"]},
                   {"installed.marker": _D["installed.marker"]}, h1)
    wires = _seal_links([l0, l1, l2])
    return _expect("supplychain-link-chain-broken",
                   lambda: dc.verify_lifecycle(
                       _layout(), wires, _KEYS, EVAL_START))


def p_lifecycle_unauthorized_signer():
    wires = _good_links()
    # re-seal the fetch link with the attacker's key
    l1 = _link_doc("fetch",
                   {"bundle.tar.gz": _D["bundle.tar.gz"],
                    "manifest.json": _D["manifest.json"]},
                   {"unpacked/skill.py": _D["unpacked/skill.py"]},
                   hashlib.sha256(tuf_canonical_json(_link_doc(
                       "publish", {},
                       {"bundle.tar.gz": _D["bundle.tar.gz"],
                        "manifest.json": _D["manifest.json"]},
                       "0" * 64))).hexdigest())
    bad = _seal_links([l1], signer_kid="mallory", signer=_M1)
    wires = [wires[0], bad[0], wires[2]]
    # fix the install link's prev to chain from the ATTACKER's link, so
    # the only failure is the signer check, not the chain
    l2 = _link_doc("install",
                   {"unpacked/skill.py": _D["unpacked/skill.py"]},
                   {"installed.marker": _D["installed.marker"]},
                   hashlib.sha256(tuf_canonical_json(l1)).hexdigest())
    wires[2] = _seal("link", l2, [("pay-k1", _P1)])
    return _expect("supplychain-link-unauthorized",
                   lambda: dc.verify_lifecycle(
                       _layout(), wires, _KEYS, EVAL_START))


def p_lifecycle_rules_leftover():
    """A smuggled file in install products -> terminal DISALLOW."""
    l0 = _link_doc("publish", {},
                   {"bundle.tar.gz": _D["bundle.tar.gz"],
                    "manifest.json": _D["manifest.json"]}, "0" * 64)
    h0 = hashlib.sha256(tuf_canonical_json(l0)).hexdigest()
    l1 = _link_doc("fetch",
                   {"bundle.tar.gz": _D["bundle.tar.gz"],
                    "manifest.json": _D["manifest.json"]},
                   {"unpacked/skill.py": _D["unpacked/skill.py"]}, h0)
    h1 = hashlib.sha256(tuf_canonical_json(l1)).hexdigest()
    l2 = _link_doc("install",
                   {"unpacked/skill.py": _D["unpacked/skill.py"]},
                   {"installed.marker": _D["installed.marker"],
                    "evil.sh": _D["evil.sh"]}, h1)
    wires = _seal_links([l0, l1, l2])
    return _expect("supplychain-transition-rules-failed",
                   lambda: dc.verify_lifecycle(
                       _layout(), wires, _KEYS, EVAL_START))


def p_lifecycle_layout_sig():
    return _expect("supplychain-layout-signature-invalid",
                   lambda: dc.verify_lifecycle(
                       _layout(signer_kid="mallory", signer=_M1),
                       _good_links(), _KEYS, EVAL_START))


def p_lifecycle_layout_expired():
    return _expect("supplychain-layout-expired",
                   lambda: dc.verify_lifecycle(
                       _layout(expires=PAST), _good_links(),
                       _KEYS, EVAL_START))


def p_lifecycle_order_violation():
    wires = _good_links()
    wires = [wires[1], wires[0], wires[2]]
    return _expect("supplychain-malformed",
                   lambda: dc.verify_lifecycle(
                       _layout(), wires, _KEYS, EVAL_START))


def p_lifecycle_cross_transition_match():
    """Bytes swapped between fetch and install: fetch's product digest
    no longer matches install's material MATCH pin."""
    l0 = _link_doc("publish", {},
                   {"bundle.tar.gz": _D["bundle.tar.gz"],
                    "manifest.json": _D["manifest.json"]}, "0" * 64)
    h0 = hashlib.sha256(tuf_canonical_json(l0)).hexdigest()
    l1 = _link_doc("fetch",
                   {"bundle.tar.gz": _D["bundle.tar.gz"],
                    "manifest.json": _D["manifest.json"]},
                   {"unpacked/skill.py": _D["unpacked/skill.py"]}, h0)
    h1 = hashlib.sha256(tuf_canonical_json(l1)).hexdigest()
    swapped = _digests("swapped-skill.py")["swapped-skill.py"]
    l2 = _link_doc("install",
                   {"unpacked/skill.py": swapped},
                   {"installed.marker": _D["installed.marker"]}, h1)
    wires = _seal_links([l0, l1, l2])
    return _expect("supplychain-transition-rules-failed",
                   lambda: dc.verify_lifecycle(
                       _layout(), wires, _KEYS, EVAL_START))


def p_lifecycle_missing_transition():
    wires = _good_links()[:2]
    return _expect("supplychain-malformed",
                   lambda: dc.verify_lifecycle(
                       _layout(), wires, _KEYS, EVAL_START))


def p_lifecycle_genesis():
    l0 = _link_doc("publish", {},
                   {"bundle.tar.gz": _D["bundle.tar.gz"],
                    "manifest.json": _D["manifest.json"]}, "ff" * 32)
    h0 = hashlib.sha256(tuf_canonical_json(l0)).hexdigest()
    l1 = _link_doc("fetch",
                   {"bundle.tar.gz": _D["bundle.tar.gz"],
                    "manifest.json": _D["manifest.json"]},
                   {"unpacked/skill.py": _D["unpacked/skill.py"]}, h0)
    h1 = hashlib.sha256(tuf_canonical_json(l1)).hexdigest()
    l2 = _link_doc("install",
                   {"unpacked/skill.py": _D["unpacked/skill.py"]},
                   {"installed.marker": _D["installed.marker"]}, h1)
    wires = _seal_links([l0, l1, l2])
    return _expect("supplychain-link-chain-broken",
                   lambda: dc.verify_lifecycle(
                       _layout(), wires, _KEYS, EVAL_START))


def p_lifecycle_legit_control():
    try:
        rep = dc.verify_lifecycle(_layout(), _good_links(),
                                  _KEYS, EVAL_START)
    except Exception as exc:  # noqa: BLE001
        return False, "BREAK: legit control refused: %s" % str(exc)[:160]
    if not rep.get("ok") or len(rep.get("transitions", [])) != 3:
        return False, "BREAK: bad legit report: %r" % (rep,)
    if not rep.get("checked") or not rep.get("out_of_scope"):
        return False, "BREAK: missing honest coverage"
    rep2 = dc.verify_lifecycle(_layout(), _good_links(),
                               _KEYS, EVAL_START)
    if rep["evidence_digest"] != rep2["evidence_digest"]:
        return False, "BREAK: evidence digest not deterministic"
    return True, "HELD: legit lifecycle verified, %d checks" % len(
        rep["checked"])


_PROBES = [
    ("delegation/path-escape", p_delegation_path_escape),
    ("delegation/terminating-stop", p_delegation_terminating_stop),
    ("delegation/threshold", p_delegation_threshold),
    ("delegation/revoked", p_delegation_revoked),
    ("delegation/rollback", p_delegation_rollback),
    ("delegation/frozen", p_delegation_frozen),
    ("delegation/eval-start-pinned", p_delegation_eval_start_pinned),
    ("delegation/root-threshold", p_delegation_root_threshold),
    ("delegation/snapshot-mismatch", p_delegation_snapshot_mismatch),
    ("delegation/legit-control", p_delegation_legit_control),
    ("lifecycle/chain-break", p_lifecycle_chain_break),
    ("lifecycle/unauthorized-signer", p_lifecycle_unauthorized_signer),
    ("lifecycle/rules-leftover", p_lifecycle_rules_leftover),
    ("lifecycle/layout-sig", p_lifecycle_layout_sig),
    ("lifecycle/layout-expired", p_lifecycle_layout_expired),
    ("lifecycle/order-violation", p_lifecycle_order_violation),
    ("lifecycle/cross-transition-match", p_lifecycle_cross_transition_match),
    ("lifecycle/missing-transition", p_lifecycle_missing_transition),
    ("lifecycle/genesis", p_lifecycle_genesis),
    ("lifecycle/legit-control", p_lifecycle_legit_control),
]


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "SKIP (GOV_SKIP_GREEN=1): adjacent batteries not re-run"
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    here = os.path.dirname(os.path.abspath(__file__))
    notes = []
    for battery in ("bundle_refresh_probes.py",
                    "w248_skill_admission_probes.py"):
        path = os.path.join(here, battery)
        if not os.path.exists(path):
            notes.append("%s: not found, skipped" % battery)
            continue
        proc = subprocess.run(
            [sys.executable, path], env=env, capture_output=True,
            text=True, timeout=600, cwd=here)
        notes.append("%s: exit %d" % (battery, proc.returncode))
        if proc.returncode != 0:
            notes.append("STDERR: " + proc.stderr[-800:])
            return "FAIL: " + "; ".join(notes)
    return "OK: " + "; ".join(notes)


def main():
    from gov import decision_codes
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        print("FAIL taxonomy pin: TAXONOMY has %d codes, expected %d" % (
            len(decision_codes.TAXONOMY), TAXONOMY_PIN))
        return 1
    held = broke = errors = 0
    for name, probe in _PROBES:
        try:
            ok, detail = probe()
        except Exception as exc:  # noqa: BLE001 - harness error
            errors += 1
            print("ERROR %-38s %s: %s" % (name, type(exc).__name__,
                                          str(exc)[:160]))
            continue
        if ok:
            held += 1
            print("HELD  %-38s %s" % (name, detail))
        else:
            broke += 1
            print("BREAK %-38s %s" % (name, detail))
    print("TOTAL: %d HELD / %d BREAK / %d ERROR" % (held, broke, errors))
    print("green-check: " + _green_check())
    return 0 if (broke == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
