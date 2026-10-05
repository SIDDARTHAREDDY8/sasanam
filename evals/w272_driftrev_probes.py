"""Wave-272 prospectus build lane #2: drift-report event schema + content-digest
revision binding (red-first battery).

Context (wave-271 prospectus): OPA's decision logs are telemetry, not a
replayable/tamper-evident audit mechanism -- Sasanam's gate_hardening
audit-scanner analog reports "what protect would deny today" but emits
no structured drift events; drift observation is report-only. And the
replay manifest's tool_digest_pin is verified per-manifest, never bound
to the chain revision it executed at.

What this battery pins (target API):
  gov/drift_report.py
    - DriftLog: in-memory hash-chained event log (tamper-evident).
      append(event) -> record with seq/prev_digest/event_digest;
      verify() raises DriftReportError("drift-log-corrupt") on tamper.
    - DriftReporter(scanner): record_baseline(requests) emits
      "drift-baseline-updated"; rescan(requests) emits one
      "drift-detected" event per newly-denying item (baseline allow ->
      now deny), deterministic request_id order. Event schema:
      {seq, ts, event, request_id, then_decision, now_decision,
       then_code, now_code, gate_digest, prev_digest, event_digest}.
  gov/revision_binding.py
    - PinRegistry: register_revision(revision, manifest) builds
      (revision, tool_id, seq) -> content_digest bindings from a sealed,
      verified manifest (tampered manifests refused at registration).
    - verify_replay(manifest, *, revision, registry): every replayed
      tool_call's pin is checked against the binding for that revision;
      a mismatch raises RevisionBindingError("revbind-content-mismatch")
      unless the manifest carries an explicit content_equivalence link
      covering (tool_id, bound -> presented), which is accepted and
      reported as "revbind-equivalence-accepted". Unbound revisions are
      reported loudly, never refused.
  gov/replay_manifest.py (additive):
    - ReplayManifestBuilder(..., chain_revision=None): tool_call links
      record revision_binding {revision, content_digest} -- the pin is
      bound to the chain revision it executed at.
    - record_content_equivalence(*, tool_id, from_digest, to_digest,
      reason): first-class annotation link; empty reason refused at
      record time; verified structurally by verify_manifest.

Red phase (GOV_DRIFTREV_IMPL=stub): the stub foil emits no drift
events, never detects tampering, and accepts every replay -- all
attack probes BREAK. Green phase: all probes HELD in staging and under
`env -u GOV_DEPLOYMENT_MODE`, deterministic A==B.

Conventions: module-level staging default; fresh unique /var/tmp/g272*
TMPDIR (mkdir -p); depth-1 green checks honoring GOV_SKIP_GREEN=1;
no in-repo git subprocesses; stdlib only.
"""

import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault(
    "GOV_LOG_KEY",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w272-driftrev")

_TMP = tempfile.mkdtemp(prefix="g272-driftrev-%d-" % os.getpid(),
                        dir="/var/tmp")
os.makedirs(_TMP, exist_ok=True)
os.environ["TMPDIR"] = _TMP

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from gov import gate_hardening as gh  # noqa: E402
from gov import replay_manifest as rm  # noqa: E402

IMPL = os.environ.get("GOV_DRIFTREV_IMPL", "real")

if IMPL == "stub":
    # -- permissive foil: emits nothing, detects nothing, accepts all --
    class _StubLog(object):
        def __init__(self, now=None):
            self._recs = []

        def append(self, event):
            rec = dict(event)
            rec["seq"] = len(self._recs)
            self._recs.append(rec)
            return rec

        def records(self):
            return list(self._recs)

        def verify(self):
            return True

    class _StubReporter(object):
        def __init__(self, scanner, now=None, gate_digest=None):
            self._scanner = scanner
            self._log = _StubLog(now=now)

        def record_baseline(self, requests):
            return {"baseline_digest": "stub", "items": len(requests)}

        def rescan(self, requests):
            return {"newly_denying": [], "resolved": [],
                    "scanned": len(requests), "events": 0}

        def events(self):
            return self._log.records()

    class _StubRegistry(object):
        def register_revision(self, revision, manifest):
            return "stub"

        def bound(self, revision, tool_id, seq):
            return None

        def revisions(self):
            return []

    def _stub_verify_replay(manifest, revision, registry):
        return {"verified": True, "revision": revision, "held": 0,
                "equivalence_accepted": 0, "unbound": 0, "detail": []}

    _drift_mod = type("stub", (), {
        "DriftLog": _StubLog, "DriftReporter": _StubReporter,
        "gate_policy_digest": lambda g: "stub",
        "DriftReportError": type("DriftReportError",
                                 (Exception,), {}),
    })
    _rev_mod = type("stub", (), {
        "PinRegistry": _StubRegistry,
        "verify_replay": _stub_verify_replay,
        "RevisionBindingError": type("RevisionBindingError",
                                     (Exception,), {}),
    })
else:
    from gov import drift_report as _drift_mod  # noqa: E402
    from gov import revision_binding as _rev_mod  # noqa: E402

# Merge pin: 1443 = 1411 (wave-271 merge) + 32 (8 prodauth + 7 drift/revbind + 9 ingest + 8 oidc).
# Counted on QUOTED source literals ("code": '...').
TAXONOMY_PIN = 2100 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*).



_RESULTS = []
_NOW = 1700000000


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _refused_with_code(fn, *codes):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 -- probe harness
        code = getattr(exc, "code", None)
        if code in codes:
            return "HELD", "refused with %s" % code
        return "ERROR", "wrong refusal: %r (%s)" % (code, exc)
    return "BREAK", "not refused (expected one of %s)" % (codes,)


def _gate(predicate, policies_extra=()):
    g = gh.Gate(mode="protect", global_deadline_s=5.0,
                now=lambda: _NOW, clock=lambda: 0.0)
    g.register_policy(gh.compile_policy({
        "policy_id": "p1-base", "predicate_name": "deny-flag",
        "predicate": predicate, "host_callbacks": []}))
    for spec in policies_extra:
        g.register_policy(gh.compile_policy(spec))
    return g


def _allow_all(runtime):
    return not runtime.request.get("deny", False)


def _requests(*ids, deny=()):
    return [{"request_id": i, "deny": i in deny} for i in ids]


def _manifest_with_tool_call(tool_digest, revision=None, chain_revision=None,
                             equivalences=()):
    pol = rm.InMemoryPinRegistry()
    pol.register("tool-a", tool_digest)
    b = rm.ReplayManifestBuilder(
        "spiffe://test/workload", now=lambda: _NOW,
        code_pin_policy=pol, chain_revision=chain_revision)
    b.record_environment_snapshot({"os": "linux"})
    b.record_tool_call(tool_id="tool-a",
                       input_digest="ab" * 32, output_digest="cd" * 32,
                       tool_digest_pin=tool_digest, seed=7)
    for (td, fd, td2, reason) in equivalences:
        b.record_content_equivalence(tool_id=td, from_digest=fd,
                                     to_digest=td2, reason=reason)
    return b.seal()


# ---------------------------------------------------------------------------
# attack probes: drift events
# ---------------------------------------------------------------------------

def d01_policy_tightened_drift():
    """Baseline allows r2; a tightened policy denies r2 on rescan ->
    exactly one drift-detected event with the full schema."""
    g = _gate(_allow_all)
    rep = _drift_mod.DriftReporter(g, now=lambda: _NOW)
    rep.record_baseline(_requests("r1", "r2", "r3"))
    g.register_policy(gh.compile_policy({
        "policy_id": "p2-tight", "predicate_name": "deny-r2",
        "predicate": lambda rt: rt.request.get("request_id") != "r2",
        "host_callbacks": []}))
    report = rep.rescan(_requests("r1", "r2", "r3"))
    if len(report["newly_denying"]) != 1:
        return "BREAK", "expected 1 newly-denying, got %d" % len(
            report["newly_denying"])
    ev = rep.events()[-1]
    want = {"request_id": "r2", "then_decision": "allow",
            "now_decision": "deny", "event": "drift-detected"}
    for k, v in want.items():
        if ev.get(k) != v:
            return "BREAK", "event field %r = %r, want %r" % (
                k, ev.get(k), v)
    for k in ("seq", "ts", "then_code", "now_code", "gate_digest",
              "prev_digest", "event_digest"):
        if k not in ev:
            return "BREAK", "event missing schema field %r" % k
    if ev["now_code"] != "gatehard-policy-denied":
        return "BREAK", "now_code = %r" % ev.get("now_code")
    return "HELD", "drift-detected emitted with full schema"


def d02_tampered_event_breaks_chain():
    """Editing a drift event breaks verify_log() fail-closed (public seam)."""
    g = _gate(_allow_all)
    rep = _drift_mod.DriftReporter(g, now=lambda: _NOW)
    rep.record_baseline(_requests("r1"))
    g.register_policy(gh.compile_policy({
        "policy_id": "p2-denyall", "predicate_name": "deny",
        "predicate": lambda rt: False, "host_callbacks": []}))
    rep.rescan(_requests("r1"))
    recs = rep.events()
    if not recs:
        return "BREAK", "no drift events recorded"
    recs[-1]["now_decision"] = "allow"  # tamper in place (live dicts)
    def _v():
        rep.verify_log()
    return _refused_with_code(_v, "drift-log-corrupt")


def d03_deterministic_order():
    """Two identical drift runs emit byte-identical event sequences."""
    def _run():
        g = _gate(_allow_all)
        rep = _drift_mod.DriftReporter(g, now=lambda: _NOW)
        rep.record_baseline(_requests("r3", "r1", "r2"))
        g.register_policy(gh.compile_policy({
            "policy_id": "p2-denyall", "predicate_name": "deny",
            "predicate": lambda rt: False, "host_callbacks": []}))
        rep.rescan(_requests("r2", "r3", "r1"))
        return [json.dumps(e, sort_keys=True) for e in rep.events()]
    a, b = _run(), _run()
    if not a:
        return "BREAK", "no drift events recorded (foil emits nothing)"
    if a != b:
        return "BREAK", "runs differ"
    ids = [json.loads(e)["request_id"] for e in a
           if json.loads(e)["event"] == "drift-detected"]
    if ids != sorted(ids):
        return "BREAK", "events not in request_id order: %r" % ids
    return "HELD", "deterministic, request_id-ordered"


def d04_baseline_updated_event():
    """record_baseline emits drift-baseline-updated into the chain."""
    g = _gate(_allow_all)
    rep = _drift_mod.DriftReporter(g, now=lambda: _NOW)
    rep.record_baseline(_requests("r1"))
    kinds = [e["event"] for e in rep.events()]
    if "drift-baseline-updated" not in kinds:
        return "BREAK", "no drift-baseline-updated; events=%r" % kinds
    return "HELD", "baseline event recorded"


def d05_argument_shape_refused_coded():
    """Argument-shape refusals use drift-malformed, not the tamper code."""
    log = _drift_mod.DriftLog(now=lambda: _NOW)
    def _v1():
        log.append("not-a-dict")
    v1, n1 = _refused_with_code(_v1, "drift-malformed")
    def _v2():
        _drift_mod.DriftReporter(object(), now=lambda: _NOW)
    v2, n2 = _refused_with_code(_v2, "drift-malformed")
    if v1 != "HELD" or v2 != "HELD":
        return "BREAK", "append=%s (%s); scanner=%s (%s)" % (v1, n1, v2, n2)
    return "HELD", "argument-shape refusals coded drift-malformed"


# ---------------------------------------------------------------------------
# attack probes: revision binding
# ---------------------------------------------------------------------------

_V1 = "11" * 32
_V2 = "22" * 32


def r01_revision_mismatch_refused():
    """Replay pins tool v2 against a registry bound to v1 at the same
    revision -> revbind-content-mismatch."""
    try:
        reg = _rev_mod.PinRegistry()
        reg.register_revision("rev-7", _manifest_with_tool_call(_V1))
        replay = _manifest_with_tool_call(_V2)
    except (TypeError, AttributeError) as e:
        return "BREAK", "revision-binding API absent on base: %s" % e
    def _v():
        _rev_mod.verify_replay(replay, revision="rev-7", registry=reg)
    return _refused_with_code(_v, "revbind-content-mismatch")


def r02_equivalence_annotation_accepted():
    """Same mismatch + an explicit content_equivalence link covering
    (tool-a, v1 -> v2) -> accepted, reported as equivalence-accepted."""
    try:
        reg = _rev_mod.PinRegistry()
        reg.register_revision("rev-7", _manifest_with_tool_call(_V1))
        replay = _manifest_with_tool_call(
            _V2, equivalences=[("tool-a", _V1, _V2, "v1->v2 rollout")])
    except (TypeError, AttributeError) as e:
        return "BREAK", "revision-binding API absent on base: %s" % e
    try:
        report = _rev_mod.verify_replay(replay, revision="rev-7",
                                        registry=reg)
    except Exception as exc:  # noqa: BLE001
        return "BREAK", "refused despite equivalence: %s" % exc
    if report.get("equivalence_accepted") != 1:
        return "BREAK", "not reported equivalence-accepted: %r" % report
    return "HELD", "equivalence annotation accepted and reported"


def r07_empty_revision_refused_coded():
    """Empty revision labels are an argument-shape refusal
    (revbind-malformed), not a content mismatch."""
    try:
        reg = _rev_mod.PinRegistry()
    except (TypeError, AttributeError) as e:
        return "BREAK", "revision-binding API absent on base: %s" % e
    def _v():
        reg.register_revision("", _manifest_with_tool_call(_V1))
    return _refused_with_code(_v, "revbind-malformed")


def r03_forged_equivalence_refused():
    """An annotation whose from_digest does not match the bound digest
    is not an equivalence -> refused."""
    try:
        reg = _rev_mod.PinRegistry()
        reg.register_revision("rev-7", _manifest_with_tool_call(_V1))
        forged = "33" * 32
        replay = _manifest_with_tool_call(
            _V2, equivalences=[("tool-a", forged, _V2, "v1->v2 rollout")])
    except (TypeError, AttributeError) as e:
        return "BREAK", "revision-binding API absent on base: %s" % e
    def _v():
        _rev_mod.verify_replay(replay, revision="rev-7", registry=reg)
    return _refused_with_code(_v, "revbind-content-mismatch")


def r04_tampered_manifest_not_bound():
    """register_revision on a chain-tampered manifest refuses first
    (verify_manifest runs before any binding is recorded)."""
    reg = _rev_mod.PinRegistry()
    try:
        m = _manifest_with_tool_call(_V1)
    except (TypeError, AttributeError) as e:
        return "BREAK", "manifest API absent on base: %s" % e
    m = json.loads(json.dumps(m))
    m["links"][1]["ts"] = m["links"][1]["ts"] + 1  # break link hash
    def _r():
        reg.register_revision("rev-7", m)
    try:
        _r()
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        if code in ("replay-broken-chain",):
            return "HELD", "tampered manifest refused at registration"
        return "ERROR", "wrong refusal: %r" % code
    return "BREAK", "tampered manifest was bound"


def r05_equivalence_without_reason_refused():
    """A content-equivalence annotation with an empty reason is refused
    at record time (fail closed, never carried as free text)."""
    pol = rm.InMemoryPinRegistry()
    pol.register("tool-a", _V1)
    try:
        b = rm.ReplayManifestBuilder(
            "spiffe://test/workload", now=lambda: _NOW, code_pin_policy=pol)
        b.record_content_equivalence  # noqa: B018 -- API probe
    except (TypeError, AttributeError) as e:
        return "BREAK", "equivalence API absent on base: %s" % e
    def _r():
        b.record_content_equivalence(tool_id="tool-a", from_digest=_V1,
                                     to_digest=_V2, reason="")
    return _refused_with_code(_r, "replay-malformed")


def r06_revision_binding_block_recorded():
    """With chain_revision set, each tool_call link binds its pin to the
    chain revision it executed at: revision_binding {revision,
    content_digest}."""
    try:
        m = _manifest_with_tool_call(_V1, chain_revision="rev-7")
    except (TypeError, AttributeError) as e:
        return "BREAK", "chain_revision API absent on base: %s" % e
    link = m["links"][1]
    rb_block = link.get("revision_binding")
    if not isinstance(rb_block, dict):
        return "BREAK", "no revision_binding block on tool_call link"
    if rb_block.get("revision") != "rev-7":
        return "BREAK", "revision = %r" % rb_block.get("revision")
    if rb_block.get("content_digest") != _V1:
        return "BREAK", "content_digest mismatch"
    return "HELD", "revision_binding recorded on the link"


# ---------------------------------------------------------------------------
# control probes (must HELD in both phases)
# ---------------------------------------------------------------------------

def c1_no_drift_clean():
    """Rescan with no policy change emits no drift events (no false
    positives), but the baseline event is present."""
    if IMPL == "stub":
        return "HELD", "vacuous on foil (foil emits nothing)"
    g = _gate(_allow_all)
    rep = _drift_mod.DriftReporter(g, now=lambda: _NOW)
    rep.record_baseline(_requests("r1", "r2"))
    report = rep.rescan(_requests("r1", "r2"))
    if report["newly_denying"]:
        return "BREAK", "false drift: %r" % report["newly_denying"]
    if report["events"] != 1:  # only the baseline event
        return "BREAK", "unexpected events: %d" % report["events"]
    return "HELD", "no drift on unchanged policy"


def c2_revision_match_held():
    """A replay whose pins match the revision binding verifies cleanly."""
    if IMPL == "stub":
        return "HELD", "vacuous on foil (foil accepts everything)"
    reg = _rev_mod.PinRegistry()
    reg.register_revision("rev-7", _manifest_with_tool_call(_V1))
    replay = _manifest_with_tool_call(_V1)
    try:
        report = _rev_mod.verify_replay(replay, revision="rev-7",
                                        registry=reg)
    except Exception as exc:  # noqa: BLE001
        return "BREAK", "matching replay refused: %s" % exc
    if not report.get("verified"):
        return "BREAK", "report not verified: %r" % report
    return "HELD", "matching replay verifies"


def c3_unbound_revision_reported():
    """A revision with no binding is reported as unbound -- loudly, not
    refused (first-run bootstrapping is normal)."""
    if IMPL == "stub":
        return "HELD", "vacuous on foil (foil reports nothing)"
    reg = _rev_mod.PinRegistry()
    replay = _manifest_with_tool_call(_V1)
    try:
        report = _rev_mod.verify_replay(replay, revision="rev-9",
                                        registry=reg)
    except Exception as exc:  # noqa: BLE001
        return "BREAK", "unbound revision refused: %s" % exc
    if report.get("unbound") != 1:
        return "BREAK", "unbound not reported: %r" % report
    return "HELD", "unbound revision reported, not refused"


def c4_pin_check():
    """Raw quoted-literal taxonomy pin (green phase only)."""
    with open(os.path.join(REPO, "gov", "decision_codes.py")) as f:
        src = f.read()
    codes = re.findall(
        r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    if len(codes) != TAXONOMY_PIN or len(set(codes)) != TAXONOMY_PIN:
        return "BREAK", "pin: %d literals / %d unique, want %d" % (
            len(codes), len(set(codes)), TAXONOMY_PIN)
    return "HELD", "pin %d/%d/0" % (len(codes), len(set(codes)))


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------

_PROBES = [
    # attacks: BREAK on the stub foil, HELD on the real modules
    ("d01-policy-tightened-drift", "attack", d01_policy_tightened_drift),
    ("d02-tampered-event-breaks-chain", "attack",
     d02_tampered_event_breaks_chain),
    ("d03-deterministic-order", "attack", d03_deterministic_order),
    ("d04-baseline-updated-event", "attack", d04_baseline_updated_event),
    ("d05-argument-shape-refused-coded", "attack",
     d05_argument_shape_refused_coded),
    ("r01-revision-mismatch-refused", "attack",
     r01_revision_mismatch_refused),
    ("r02-equivalence-annotation-accepted", "attack",
     r02_equivalence_annotation_accepted),
    ("r03-forged-equivalence-refused", "attack",
     r03_forged_equivalence_refused),
    ("r04-tampered-manifest-not-bound", "attack",
     r04_tampered_manifest_not_bound),
    ("r05-equivalence-without-reason-refused", "attack",
     r05_equivalence_without_reason_refused),
    ("r06-revision-binding-block-recorded", "attack",
     r06_revision_binding_block_recorded),
    ("r07-empty-revision-refused-coded", "attack",
     r07_empty_revision_refused_coded),
    # controls: HELD in both phases
    ("c1-no-drift-clean", "control", c1_no_drift_clean),
    ("c2-revision-match-held", "control", c2_revision_match_held),
    ("c3-unbound-revision-reported", "control",
     c3_unbound_revision_reported),
]

if IMPL == "real":
    _PROBES.append(("c4-pin-1458", "control", c4_pin_check))


def _run(pid, kind, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001 -- probe harness
        verdict, note = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    expected = "HELD" if (kind == "control" or IMPL == "real") else "BREAK"
    ok = (verdict == expected)
    _RESULTS.append((pid, expected, verdict, ok, note))
    print("PROBE %-38s expected=%-5s got=%-5s" % (pid, expected, verdict))
    return ok


def _green_checks():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-checks-skipped", True, "GOV_SKIP_GREEN=1")]
    if IMPL != "real":
        return [("green-checks-red-phase", True, "SKIP (stub phase)")]
    results = []
    # Determinism: run this battery's own main twice under the real
    # impl and compare the PROBE verdict signature (A == B).
    for tag in ("A", "B"):
        env = dict(os.environ)
        env["GOV_DRIFTREV_IMPL"] = "real"
        env["GOV_SKIP_GREEN"] = "1"
        p = subprocess.run([sys.executable, __file__],
                           capture_output=True, text=True, env=env,
                           cwd=REPO)
        sig = [ln for ln in p.stdout.splitlines()
               if ln.startswith("PROBE ")]
        results.append(("determinism-%s" % tag, p.returncode == 0, sig))
    ok = (results[0][1] and results[1][1]
          and results[0][2] == results[1][2])
    results.append(("determinism-A==B", ok, len(results[0][2])))
    return results


def main():
    print("w272 driftrev battery (impl=%s): %d probes (TMPDIR=%s)"
          % (IMPL, len(_PROBES), _TMP))
    failures = 0
    for pid, kind, fn in _PROBES:
        if not _run(pid, kind, fn):
            failures += 1
    print("--- green checks (depth-1) ---")
    for name, ok, note in _green_checks():
        print("[%s] %s %s" % ("ok " if ok else "FAIL", name, note))
        if not ok:
            failures += 1
    n_break = sum(1 for r in _RESULTS if r[2] == "BREAK")
    n_held = sum(1 for r in _RESULTS if r[2] == "HELD")
    n_err = sum(1 for r in _RESULTS if r[2] == "ERROR")
    print("probes: %d BREAK / %d HELD / %d ERROR; mismatches: %d"
          % (n_break, n_held, n_err, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
