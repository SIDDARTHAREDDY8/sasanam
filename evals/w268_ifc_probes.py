"""Break-first red-team battery for the tool-output IFC seam
(wave-268 feature lane: Oak IFC labels, STEAL the code).

Target: gov/output_ifc.py -- information-flow labels on tool
outputs. Every tool output is assigned an integrity/secrecy label;
sinks (egress, journal, approval-queue, execution) declare the
labels they accept; declassification/endorsement are privilege
ceremonies that must be authorized AND audit-logged, never silent.

The battery imports the implementation via GOV_IFC_IMPL (default
"gov.output_ifc"); against the permissive stub
(GOV_IFC_IMPL=stub) every attack probe must BREAK, proving the
probes are real. Against the real module every probe must HELD, in
staging and under `env -u GOV_DEPLOYMENT_MODE`.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. A probe returns (ok, detail); ok=True means HELD (the seam
behaves per its contract), ok=False means BREAK (genuine defect) or
harness ERROR.

Stdlib only. Deterministic. No in-repo git subprocesses (wave-36
supply-chain probe: fail closed). Green checks are depth-1 and honor
GOV_SKIP_GREEN=1.
"""

import importlib
import os
import re
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

TAXONOMY_PIN = 2128 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)


_IMPL = os.environ.get("GOV_IFC_IMPL", "gov.output_ifc")

_STUB_SRC = '''"""Permissive stub: accepts unendorsed trust claims, allows
every flow, exercises privileges silently. Every attack probe must
BREAK against this."""
import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

CODES = ()


class OutputIFCError(Exception):
    def __init__(self, code, detail=""):
        super(OutputIFCError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def assign_label(tool_name, provenance=None, registry=None):
    prov = provenance or {}
    return {"secrecy": list(prov.get("secrecy", [])),
            "integrity": list(prov.get("integrity", []))}


def check_sink(labeled, sink):
    name = sink if isinstance(sink, str) else sink.get("name")
    return {"allowed": True, "sink": name, "label": labeled}


def combine_outputs(*labeled):
    sec, integ = set(), set()
    for lab in labeled:
        sec |= set(lab.get("secrecy", []))
        integ |= set(lab.get("integrity", []))
    return {"secrecy": sorted(sec), "integrity": sorted(integ)}


def issue_grant(privilege, granted_by, authorization, ttl_seconds,
               now):
    return {"grant": "stub"}


def exercise_privilege(grant, label, operation, tags, audit, now):
    return {"label": label, "audit_record": None}
'''


def _load_impl():
    if _IMPL == "stub":
        d = tempfile.mkdtemp(prefix="w268_ifc_stub_")
        p = os.path.join(d, "stub_ifc.py")
        with open(p, "w") as f:
            f.write(_STUB_SRC)
        sys.path.insert(0, d)
        return importlib.import_module("stub_ifc")
    return importlib.import_module(_IMPL)


ifc = _load_impl()

# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

NOW = "2026-10-01T10:00:00Z"
LATER = "2026-10-01T10:01:00Z"
MUCH_LATER = "2026-10-01T12:00:00Z"

PRIV_FULL = {"declassification": ["credential"],
             "endorsement": ["user-verified"]}
PRIV_EMPTY = {"declassification": [], "endorsement": []}
PRIV_PUBLIC_ONLY = {"declassification": ["public"],
                    "endorsement": []}

AUTH_HUMAN = {"kind": "human-approval", "ref": "appr-1234"}
AUTH_ROLE = {"kind": "deployment-role", "ref": "ifc-officer"}
AUTH_BAD = {"kind": "self-asserted", "ref": "me"}

PROBES = []


def probe(name):
    def deco(fn):
        PROBES.append((name, fn))
        return fn
    return deco


def _code_of(fn, *args, **kwargs):
    """Run fn; return the machine code raised, or None, or 'NO-RAISE'."""
    try:
        fn(*args, **kwargs)
    except Exception as e:  # noqa: BLE001 - probing
        return getattr(e, "code", None)
    return "NO-RAISE"


def _grant(**kw):
    args = {"privilege": PRIV_FULL, "granted_by": "officer",
            "authorization": AUTH_HUMAN, "ttl_seconds": 3600,
            "now": NOW}
    args.update(kw)
    return ifc.issue_grant(**args)


def _audit_collector():
    records = []

    def audit(record):
        records.append(record)
    return records, audit


# ------------------------------------------------------------------
# Assignment probes
# ------------------------------------------------------------------

@probe("ifc/assign-default-untrusted")
def _p_assign_default():
    lab = ifc.assign_label("web_fetch")
    if lab.get("integrity") != ["tool-external"]:
        return False, "default integrity not tool-external: %r" % (lab,)
    if lab.get("secrecy") != []:
        return False, "default secrecy not empty: %r" % (lab,)
    return True, "default label is untrusted/external"


@probe("ifc/assign-self-claimed-trust-refused")
def _p_self_claim():
    code = _code_of(ifc.assign_label, "web_fetch",
                    {"integrity": ["user-verified"]})
    if code != "ifc-privilege-denied":
        return False, "unendorsed trust claim not refused: %r" % (code,)
    return True, "self-claimed user-verified refused"


@probe("ifc/assign-malformed-tool")
def _p_bad_tool():
    code = _code_of(ifc.assign_label, 123)
    if code != "ifc-label-malformed":
        return False, "non-str tool not malformed: %r" % (code,)
    return True, "non-str tool fails closed"


@probe("ifc/assign-malformed-tags")
def _p_bad_tags():
    code = _code_of(ifc.assign_label, "t", {"integrity": [123]})
    if code != "ifc-label-malformed":
        return False, "non-str tag not malformed: %r" % (code,)
    return True, "non-str tag fails closed"


@probe("ifc/assign-malformed-registry")
def _p_bad_registry():
    code = _code_of(ifc.assign_label, "t", None, registry="nope")
    if code != "ifc-label-malformed":
        return False, "malformed registry not refused: %r" % (code,)
    return True, "malformed registry fails closed"


@probe("ifc/assign-self-declared-secrecy-ok")
def _p_secrecy_self():
    # Declaring MORE secrecy is the fail-closed direction: allowed.
    lab = ifc.assign_label("db_read", {"secrecy": ["credential"]})
    if lab.get("secrecy") != ["credential"]:
        return False, "secrecy self-declaration dropped: %r" % (lab,)
    return True, "secrecy self-declaration honored"


# ------------------------------------------------------------------
# Sink probes
# ------------------------------------------------------------------

@probe("ifc/sink-untrusted-to-execution-refused")
def _p_exec_refused():
    lab = ifc.assign_label("web_fetch")
    code = _code_of(ifc.check_sink, lab, "execution")
    if code != "ifc-integrity-flow-denied":
        return False, "untrusted to execution not refused: %r" % (code,)
    return True, "untrusted output refused at execution sink"


@probe("ifc/sink-secret-to-egress-refused")
def _p_egress_refused():
    lab = ifc.assign_label("db_read", {"secrecy": ["credential"]})
    code = _code_of(ifc.check_sink, lab, "egress")
    if code != "ifc-secrecy-flow-denied":
        return False, "secret to egress not refused: %r" % (code,)
    return True, "secret output refused at egress sink"


@probe("ifc/sink-unknown-name")
def _p_unknown_sink():
    lab = ifc.assign_label("t")
    code = _code_of(ifc.check_sink, lab, "moon-base")
    if code != "ifc-sink-unmapped":
        return False, "unknown sink not refused: %r" % (code,)
    return True, "unknown sink fails closed"


@probe("ifc/sink-malformed-policy")
def _p_bad_sink():
    lab = ifc.assign_label("t")
    code = _code_of(ifc.check_sink, lab, {"name": 1})
    if code != "ifc-label-malformed":
        return False, "malformed sink not refused: %r" % (code,)
    return True, "malformed sink fails closed"


@probe("ifc/sink-public-egress-allowed")
def _p_egress_ok():
    lab = ifc.assign_label("web_fetch")
    try:
        r = ifc.check_sink(lab, "egress")
    except Exception as e:  # noqa: BLE001
        return False, "public egress raised: %r" % (e,)
    if not r.get("allowed"):
        return False, "public egress not allowed: %r" % (r,)
    return True, "public data flows to egress"


@probe("ifc/sink-endorsed-to-execution-allowed")
def _p_endorsed_exec():
    lab = ifc.assign_label("agent_draft")
    grant = _grant()
    records, audit = _audit_collector()
    try:
        res = ifc.exercise_privilege(grant, lab, "endorse",
                                     ["user-verified"], audit, LATER)
    except Exception as e:  # noqa: BLE001
        return False, "endorsement raised: %r" % (e,)
    try:
        r = ifc.check_sink(res["label"], "execution")
    except Exception as e:  # noqa: BLE001
        return False, "endorsed execution raised: %r" % (e,)
    if not r.get("allowed"):
        return False, "endorsed output refused at execution: %r" % (r,)
    return True, "endorsed output flows to execution"


# ------------------------------------------------------------------
# Taint / combination probes
# ------------------------------------------------------------------

@probe("ifc/combine-taint-integrity")
def _p_combine_integ():
    clean = ifc.assign_label("agent_draft")
    grant = _grant()
    records, audit = _audit_collector()
    endorsed = ifc.exercise_privilege(
        grant, clean, "endorse", ["user-verified"], audit,
        LATER)["label"]
    dirty = ifc.assign_label("web_fetch")
    combo = ifc.combine_outputs(endorsed, dirty)
    code = _code_of(ifc.check_sink, combo, "execution")
    if code != "ifc-integrity-flow-denied":
        return False, "tainted combination reached execution: %r" % (code,)
    return True, "integrity intersection refuses tainted combination"


@probe("ifc/combine-taint-secrecy")
def _p_combine_sec():
    secret = ifc.assign_label("db_read", {"secrecy": ["credential"]})
    public = ifc.assign_label("web_fetch")
    combo = ifc.combine_outputs(secret, public)
    code = _code_of(ifc.check_sink, combo, "egress")
    if code != "ifc-secrecy-flow-denied":
        return False, "secret taint lost in combination: %r" % (code,)
    return True, "secrecy union propagates through combination"


# ------------------------------------------------------------------
# Privilege ceremony probes
# ------------------------------------------------------------------

@probe("ifc/declassify-without-privilege")
def _p_declass_none():
    grant = _grant(privilege=PRIV_EMPTY)
    lab = ifc.assign_label("db_read", {"secrecy": ["credential"]})
    records, audit = _audit_collector()
    code = _code_of(ifc.exercise_privilege, grant, lab,
                    "declassify", ["credential"], audit, LATER)
    if code != "ifc-privilege-denied":
        return False, "privilege-less declassify not refused: %r" % (code,)
    return True, "privilege-less declassification refused"


@probe("ifc/declassify-scope-exceeded")
def _p_declass_scope():
    grant = _grant(privilege=PRIV_PUBLIC_ONLY)
    lab = ifc.assign_label("db_read", {"secrecy": ["credential"]})
    records, audit = _audit_collector()
    code = _code_of(ifc.exercise_privilege, grant, lab,
                    "declassify", ["credential"], audit, LATER)
    if code != "ifc-privilege-scope-denied":
        return False, "out-of-scope declassify not refused: %r" % (code,)
    return True, "out-of-scope declassification refused"


@probe("ifc/endorse-without-privilege")
def _p_endorse_none():
    grant = _grant(privilege=PRIV_EMPTY)
    lab = ifc.assign_label("agent_draft")
    records, audit = _audit_collector()
    code = _code_of(ifc.exercise_privilege, grant, lab,
                    "endorse", ["user-verified"], audit, LATER)
    if code != "ifc-privilege-denied":
        return False, "privilege-less endorse not refused: %r" % (code,)
    return True, "privilege-less endorsement refused"


@probe("ifc/privilege-expired-grant")
def _p_expired():
    grant = _grant(ttl_seconds=60)
    lab = ifc.assign_label("db_read", {"secrecy": ["credential"]})
    records, audit = _audit_collector()
    code = _code_of(ifc.exercise_privilege, grant, lab,
                    "declassify", ["credential"], audit, MUCH_LATER)
    if code != "ifc-privilege-expired":
        return False, "expired grant not refused: %r" % (code,)
    return True, "expired grant refused"


@probe("ifc/privilege-bad-authorization")
def _p_bad_auth():
    code = _code_of(_grant, authorization=AUTH_BAD)
    if code != "ifc-privilege-unauthorized":
        return False, "bad authorization kind not refused: %r" % (code,)
    code = _code_of(_grant, authorization={"kind": "human-approval",
                                           "ref": ""})
    if code != "ifc-privilege-unauthorized":
        return False, "empty authorization ref not refused: %r" % (code,)
    return True, "unauthorized grants refused at issuance"


@probe("ifc/privilege-no-audit-refused")
def _p_no_audit():
    grant = _grant()
    lab = ifc.assign_label("db_read", {"secrecy": ["credential"]})
    code = _code_of(ifc.exercise_privilege, grant, lab,
                    "declassify", ["credential"], None, LATER)
    if code != "ifc-audit-required":
        return False, "audit-less exercise not refused: %r" % (code,)
    return True, "privilege exercise without audit refused (never silent)"


@probe("ifc/privilege-exercise-audited")
def _p_audited():
    grant = _grant()
    lab = ifc.assign_label("db_read", {"secrecy": ["credential"]})
    records, audit = _audit_collector()
    try:
        res = ifc.exercise_privilege(grant, lab, "declassify",
                                     ["credential"], audit, LATER)
    except Exception as e:  # noqa: BLE001
        return False, "exercise raised: %r" % (e,)
    if len(records) != 1:
        return False, "expected exactly one audit record, got %d"\
            % len(records)
    rec = records[0]
    for key in ("event", "operation", "tags", "grant_digest",
                "label_before", "label_after", "granted_by", "at"):
        if key not in rec:
            return False, "audit record missing %r" % (key,)
    if res["label"].get("secrecy") != []:
        return False, "declassification did not clear tag: %r"\
            % (res["label"],)
    return True, "exercise leaves complete audit evidence"


@probe("ifc/declassify-then-egress")
def _p_declass_egress():
    lab = ifc.assign_label("db_read", {"secrecy": ["credential"]})
    grant = _grant()
    records, audit = _audit_collector()
    try:
        res = ifc.exercise_privilege(grant, lab, "declassify",
                                     ["credential"], audit, LATER)
        r = ifc.check_sink(res["label"], "egress")
    except Exception as e:  # noqa: BLE001
        return False, "declassify-then-egress raised: %r" % (e,)
    if not r.get("allowed") or len(records) != 1:
        return False, "legit declassify flow broken: %r %d"\
            % (r, len(records))
    return True, "authorized declassification unblocks egress with evidence"


@probe("ifc/privilege-tampered-grant")
def _p_tampered():
    grant = _grant()
    grant = dict(grant)
    grant["privilege"] = {"declassification": ["everything"],
                          "endorsement": ["everything"]}
    lab = ifc.assign_label("db_read", {"secrecy": ["credential"]})
    records, audit = _audit_collector()
    code = _code_of(ifc.exercise_privilege, grant, lab,
                    "declassify", ["everything"], audit, LATER)
    if code != "ifc-privilege-unauthorized":
        return False, "tampered grant not refused: %r" % (code,)
    return True, "tampered grant detected via digest"


# ------------------------------------------------------------------
# Determinism + pin
# ------------------------------------------------------------------

@probe("ifc/deterministic")
def _p_determ():
    a1 = ifc.assign_label("web_fetch")
    a2 = ifc.assign_label("web_fetch")
    if a1 != a2:
        return False, "assignment non-deterministic"
    g1 = _grant()
    g2 = _grant()
    if g1 != g2:
        return False, "grant non-deterministic"
    return True, "A==B deterministic"


@probe("ifc/pin-1299")
def _p_pin():
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(repo, "gov", "decision_codes.py")).read()
    lits = re.findall(r'"code":\s*\'([^\']+)\'', src)
    if len(lits) != TAXONOMY_PIN:
        return False, "literal count %d != pin %d" % (len(lits),
                                                     TAXONOMY_PIN)
    if len(set(lits)) != len(lits):
        return False, "duplicate code literals"
    return True, "pin 1299, literals unique"


# ------------------------------------------------------------------
# Green check (depth-1) and main
# ------------------------------------------------------------------

def green_check():
    """Depth-1: this seam has no adjacent battery; verify the module
    imports cleanly and its code vocabulary is live. Honors
    GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", True, "skipped (GOV_SKIP_GREEN=1)")]
    codes = getattr(ifc, "CODES", ())
    missing = [c for c in ("ifc-secrecy-flow-denied",
                           "ifc-integrity-flow-denied",
                           "ifc-privilege-denied",
                           "ifc-audit-required")
               if c not in codes]
    if missing:
        return [("green-check", False,
                 "codes not live: %r" % (missing,))]
    return [("green-check", True, "module imports; refusal codes live")]


def main():
    results = []
    for name, fn in PROBES:
        try:
            ok, detail = fn()
            results.append((name, bool(ok), str(detail)))
        except Exception as e:  # noqa: BLE001
            results.append((name, False, "ERROR: %r" % (e,)))
    results.extend(green_check())
    held = sum(1 for _, ok, _ in results if ok)
    broke = sum(1 for _, ok, _ in results if not ok)
    for name, ok, detail in results:
        print("%s %s: %s" % ("HELD" if ok else "BREAK", name, detail))
    print("TOTAL: %d HELD / %d BREAK / 0 ERROR" % (held, broke))
    return 0 if broke == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
