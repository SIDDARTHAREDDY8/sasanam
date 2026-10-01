"""Wave-264 merge red-first closure audit.

Re-verifies F240-F244 closures at the public seams on the MERGED tree, and
confirms F245-F247 still BREAK (honestly OPEN). Standing post-wave audit.
Taxonomy pin: 1178.
"""
import copy
import inspect
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_codes

TAXONOMY_PIN = 1274  # Wave-267 merge: pin -> 1274.

if os.environ.get("GOV_SKIP_GREEN") != "1":
    def _green():
        import subprocess, sys
        for b in ("evals/w264_f240f241f242_probes.py",
                  "evals/w264_f243f244_probes.py",
                  "evals/w264_redteam_probes.py"):
            r = subprocess.run([sys.executable, b],
                               env={**os.environ, "GOV_SKIP_GREEN": "1"})
            assert r.returncode == 0, f"green check failed: {b}"
        print("GREEN CHECK: adjacent lane batteries green")
    _green()

assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN, "taxonomy pin 1178"

results = []


def check(name, held, detail=""):
    results.append((name, "HELD" if held else "BREAK", detail))


def _code_of(fn, *a, **kw):
    try:
        fn(*a, **kw)
        return "NO-REFUSAL"
    except Exception as e:  # noqa: BLE001 - asserting refusal contract
        return getattr(e, "code", type(e).__name__)


# ---------------- F240: presenter binding ----------------
from gov.scoped_tool_listing import ScopeTicketIssuer, ToolRegistry, ConsentIssuer

KEY = b"merge-audit-key-32bytes-0123456789ab"
UNIVERSE = {"read:file", "net:fetch"}
issuer = ScopeTicketIssuer(KEY, UNIVERSE)
reg = ToolRegistry(UNIVERSE).bind_issuer(issuer)
reg.register("read_file", {"read:file"}, "Read a file")
reg.register("public_tool", set(), "Zero-scope public tool")
ALICE = "alice-subject-digest"
BOB = "bob-subject-digest"
ticket_alice = issuer.seal(ALICE, {"read:file"})
OK = lambda: "ok"

check("f240/cross-subject-refused",
      _code_of(reg.invoke, ticket_alice, "read_file", OK,
               expected_subject=BOB) == "scope-listing-subject-mismatch",
      "cross-subject invoke must refuse scope-listing-subject-mismatch")
check("f240/matching-subject-allowed",
      _code_of(reg.invoke, ticket_alice, "read_file", OK,
               expected_subject=ALICE) == "NO-REFUSAL",
      "control: matching presenter invokes")
check("f240/holder-semantics-preserved",
      _code_of(reg.invoke, ticket_alice, "read_file", OK) == "NO-REFUSAL",
      "control: no presenter asserted -> holder semantics still work")

# ---------------- F241: domain separation ----------------
consent = ConsentIssuer(KEY)
curl = consent.mint_consent_url("approval-1", "read_file", {"read:file"},
                                "human-sub", 1000.0, "https://consent.example")
ctok = curl.split("ct=", 1)[1]
audited = []
sink = lambda e: audited.append(e)
check("f241/consent-as-ticket-refused",
      _code_of(issuer.verify, ctok) == "scope-grant-tampered",
      "consent token presented as scope ticket")
st = issuer.seal("sub", {"read:file"})
check("f241/ticket-as-consent-refused",
      _code_of(consent.confirm_consent, st, "approval-1", "read_file",
               "human-sub", 1000.0, sink) == "scope-consent-forged",
      "scope ticket presented as consent token")
check("f241/genuine-ticket-verifies",
      issuer.verify(ticket_alice)[1] == frozenset({"read:file"}),
      "control: genuine ticket verifies")
check("f241/genuine-consent-verifies",
      consent.confirm_consent(ctok, "approval-1", "read_file",
                              "human-sub", 1000.0, sink) is True
      and audited and audited[0]["event"] == "scope-consent-confirmed",
      "control: genuine consent confirms")

# ---------------- F242: invoke order-of-checks ----------------
check("f242/forged-no-oracle",
      _code_of(reg.invoke, "AAAA.BBBB", "ghost_tool", OK) == "scope-grant-tampered"
      and _code_of(reg.invoke, "AAAA.BBBB", "read_file", OK) == "scope-grant-tampered",
      "forged ticket: ghost and real names both tampered")
check("f242/missing-no-oracle",
      _code_of(reg.invoke, None, "ghost_tool", OK) == "scope-listing-denied"
      and _code_of(reg.invoke, None, "read_file", OK) == "scope-listing-denied",
      "missing ticket: ghost and real names both denied")
check("f242/public-still-invokable",
      _code_of(reg.invoke, None, "public_tool", OK) == "NO-REFUSAL",
      "control: zero-scope public tool invokable with no ticket")
check("f242/post-auth-residual-preserved",
      _code_of(reg.invoke, ticket_alice, "ghost_tool", OK) == "scope-listing-not-registered"
      and _code_of(reg.invoke, ticket_alice, "read_file", OK) == "NO-REFUSAL",
      "control: valid ticket keeps not-registered vs denied distinction")

# ---------------- F243: override visibility ----------------
from gov.detectors import DetectorEngine, AlertSink


def _det_base(name, **kw):
    d = {"name": name, "version": "1.0.0",
         "description": "merge audit detector",
         "event_selector": {"type": "probe_event"},
         "predicates": [{"field": "flag", "op": "eq", "value": True}],
         "produces": {"event_name": name + "_fired",
                      "event_schema_version": "1.0.0", "fields": {}},
         "subscribes": [],
         "threat": {"severity": "low", "description": "audit"},
         "priority": "notice",
         "exceptions": [{"name": "allow-ci", "description": "probe exception",
                         "fields": ["host"], "comps": ["startswith"],
                         "values": [["ci.internal.example"]]}]}
    d.update(kw)
    return d


eng = DetectorEngine()
eng.register(_det_base("d243"))
# startswith + [""] matches every string host: total re-arm.
sink = AlertSink(eng, policy={"exceptions":
                              {"d243": {"allow-ci": {"values": [[""]]}}}})
sink.process({"type": "probe_event", "flag": True,
              "host": "ci.evil.example"})
rec = sink.journal_entries()[-1]
exc = rec.get("exception_decision", {})
eff = exc.get("effective_values", {}).get("allow-ci", {})
check("f243/override-attributable",
      rec.get("record_type") == "suppressed"
      and eff.get("values") == [[""]] and eff.get("policy_overridden") is True
      and isinstance(exc.get("policy_revision"), int),
      f"type={rec.get('record_type')}, values={eff.get('values')}, "
      f"overridden={eff.get('policy_overridden')}, rev={exc.get('policy_revision')}")

# ---------------- F244: deep-copy accessor ----------------
eng2 = DetectorEngine()
eng2.register(_det_base("d244", priority="critical"))
sink2 = AlertSink(eng2)
gate_before = sink2.may_gate_enforcement("d244")
eng2.detectors["d244"]["maturity"] = "experimental"
eng2.detectors["d244"]["exceptions"] = [{"name": "e", "fields": ["host"],
                                        "comps": ["eq"],
                                        "values": [["y"]]}]
check("f244/runtime-mutation-no-effect",
      gate_before is True and sink2.may_gate_enforcement("d244") is True,
      "mutating the returned structure changes nothing")

# ---------------- F245-F247: still BREAK (honestly OPEN) ----------------
# Delegated to the w264 red-team battery's own probes (break-first on the
# pristine base by the lane; this confirms they still BREAK on merged code).
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "w264_redteam_probes",
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "w264_redteam_probes.py"))
_rt = importlib.util.module_from_spec(_spec)
_sys_rt = sys.modules.get("w264_redteam_probes")
sys.modules["w264_redteam_probes"] = _rt
try:
    _spec.loader.exec_module(_rt)
finally:
    if _sys_rt is not None:
        sys.modules["w264_redteam_probes"] = _sys_rt
_rt_probes = dict(_rt._PROBES)
for _pname, _label in (
        ("provenance/unhashable-key-id-raw", "f245/unhashable-key-id"),
        ("provenance/vsa-nondict-verifier-raw", "f245/nondict-verifier"),
        ("provenance/vsa-hostile-now-raw", "f245/hostile-now"),
        ("meshauth/task-call-drops-subject-binding", "f246/call-drops-subject"),
        ("meshauth/unauthenticated-task-transitions", "f247/no-auth-transitions")):
    _verdict, _detail = _rt_probes[_pname]()
    check(_label, _verdict == "BREAK",
          f"lane probe verdict={_verdict}: {_detail[:100]}")

# ---------------- report ----------------
# Semantics: HELD = audit expectation met. For F240-F244 the expectation is
# "closure effective on merged code"; for F245-F247 the expectation is
# "still BREAKs (honestly OPEN)" -- so a HELD row there means the defect
# is still present as filed.
breaks = [n for n, v, _ in results if v == "BREAK"]
for n, v, d in results:
    print(f"{v:5} {n}  {d}")
print(f"\n{len(results) - len(breaks)}/{len(results)} audit expectations met; "
      f"unmet: {breaks}")
assert not breaks, f"merge audit FAILED: unmet expectations {breaks}"
print("AUDIT PASS: F240-F244 closures verified on merged code; "
      "F245-F247 still BREAK (honestly OPEN)")
