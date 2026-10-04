"""Break-first battery: behavioral-signature v2 (wave-267).

The product already has behavioral signatures (wave-175,
``gov/behavioral_sigs.py``): hardcoded tables with Python match
functions. This battery probes the v2 ADAPT of the Falco discipline
(wave-266 prospectus, Falco section):

* signature packs as DATA (rule/macro/list), schema-validated, with
  author-shaped exception tuples, maturity graduation, and
  append/override tuning that can never be edited in place;
* a closed, NON-TEMPORAL condition language over ENRICHED agent-shape
  fields (enrichment-before-match; raw text is never matched);
* pack signatures: trust material required up front, fail closed
  (cosign lesson); malformed packs refused loudly, never silently
  passed;
* unknown-field rules disabled LOUDLY (skip-if-unknown analog), never
  silently passed;
* the key architectural lesson: burst / ratio / cross-session evasion
  is UNADDRESSED in the condition language -- it needs a STATEFUL
  CORRELATOR above the predicates, which emits journaled advisory
  signals (never silent denials, never blocks).

Modes: ``GOV_BEHSIG_UNDER_TEST=stub`` runs the probes against a
permissive stub that loads any pack and never fires (red phase:
attack/refusal probes MUST break). Default (module) runs them against
``gov.behavioral_sig_packs`` (green phase: attacks MUST be refused or
flagged, calibration probes MUST stay quiet).

Probes inapplicable to the stub report BASELINE (no claim either way).

Depth-1 green check honoring ``GOV_SKIP_GREEN``; no in-repo git
subprocesses; stdlib only.
"""

import copy
import hashlib
import json
import os
import secrets
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w267-behsig")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

MODE = os.environ.get("GOV_BEHSIG_UNDER_TEST", "module")

try:
    from gov import behavioral_sig_packs as _bsp
    from gov import decision_codes
    from gov import ed25519
    HAVE_MODULE = True
except Exception:  # red phase: module not written yet
    _bsp = None
    decision_codes = None
    ed25519 = None
    HAVE_MODULE = False

TAXONOMY_PIN = 2056 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*)


# pin 1222 -> 1229 (+7 behsig-*).

EXPECTED_CODES = (
    "behsig-correlator-advisory",
    "behsig-pack-malformed",
    "behsig-pack-untrusted",
    "behsig-rule-disabled",
    "behsig-rule-eval-failed",
    "behsig-tuning-applied",
    "behsig-tuning-rejected",
)


def _impl():
    if MODE == "stub":
        return _Stub()
    if not HAVE_MODULE:
        raise RuntimeError("module not present")
    return _bsp


# ------------------------------------------------------------------
# Test signing material (deployment-owned keys, test-local only).
# ------------------------------------------------------------------

def _test_keys():
    seed = ed25519.generate_seed()
    return {"seed": seed,
            "pub": ed25519.publickey(seed),
            "keyid": "test-key-1"}


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _sign_pack(pack, keys):
    sig = ed25519.sign(keys["seed"], _canon(pack))
    return {"pack": pack,
            "signatures": [{"keyid": keys["keyid"], "sig": sig.hex()}]}


def _pack_bytes(pack, keys):
    return json.dumps(_sign_pack(pack, keys),
                      sort_keys=True).encode()


# ------------------------------------------------------------------
# Fixture packs.
# ------------------------------------------------------------------

def _core_pack():
    return {
        "pack_format": "sasanam.behavioral-sig-pack/v1",
        "pack_id": "test-core",
        "pack_version": "1.0.0",
        "engine_version": "1",
        "macros": [
            {"name": "export_actions",
             "def": {"op": "in", "field": "tool.action",
                     "values": ["db.dump", "file.export"]}},
        ],
        "lists": [
            {"name": "benign_backup_hosts",
             "values": ["backup.internal"]},
        ],
        "rules": [
            {
                "name": "test.credential_then_export",
                "desc": "credential-shaped arg class then export action",
                "condition": {
                    "op": "and",
                    "args": [
                        {"op": "eq", "field": "arg.class",
                         "value": "credential"},
                        {"macro": "export_actions"},
                    ],
                },
                "output": "credential arg with export action by "
                          "%principal%",
                "priority": "high",
                "enabled": True,
                "source": "agent_event",
                "tags": ["maturity_stable", "exfiltration"],
                "maturity": "stable",
                # Author-shaped exception TUPLE: actor+target shape,
                # not "process name only". The tuple excepts only
                # when BOTH triples hold (AND); the deployment may
                # add values for these (field, comparator) slots but
                # may not invent new shapes.
                "exceptions": [
                    {"and": [
                        {"field": "principal", "comparator": "eq",
                         "value": "svc-backup"},
                        {"field": "tool.target", "comparator": "eq",
                         "value": "backup.internal"},
                    ]},
                ],
                "capture": {"window_events": 4},
                "params": {"min_export_bytes": 1024},
            },
            {
                "name": "test.sandbox_noisy",
                "desc": "sandbox-maturity canary rule",
                "condition": {"op": "eq", "field": "tool.action",
                              "value": "canary.action"},
                "output": "canary fired",
                "priority": "low",
                "enabled": True,
                "source": "agent_event",
                "tags": ["maturity_sandbox"],
                "maturity": "sandbox",
                "exceptions": [],
                "capture": {"window_events": 2},
            },
        ],
    }


def _event(**kw):
    base = {"ts": 1000.0, "actor_id": "agent-1",
            "principal": "agent-1", "session_id": "sess-1",
            "tool": "db.dump", "target": "prod-db",
            "args": {"table": "users"}}
    base.update(kw)
    return base


# ------------------------------------------------------------------
# Permissive stub (red phase): loads anything, fires never.
# ------------------------------------------------------------------

class _StubPack(object):
    def __init__(self):
        self.rules = {}
        self.disabled_rules = []


class _Stub(object):
    class PackRefused(Exception):
        def __init__(self, code="stub"):
            self.code = code

    def load_pack(self, pack_bytes, **kw):
        return _StubPack()

    def apply_tuning(self, pack, tuning, **kw):
        return pack

    def enrich_event(self, raw):
        return dict(raw)

    def match_pack(self, pack, events, **kw):
        return []

    class StatefulCorrelator(object):
        def __init__(self, config, **kw):
            pass

        def observe(self, event, alerts):
            return []


# ------------------------------------------------------------------
# Probe framework.
# ------------------------------------------------------------------

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _run_probe(name, fn):
    try:
        return (name,) + fn()
    except Exception as e:  # noqa: BLE001 - battery must not die
        return (name, "ERROR", "%s: %s" % (type(e).__name__, e))


def _journal():
    records = []

    def _j(rec):
        records.append(rec)
        return rec

    _j.records = records
    return _j


# ------------------------------------------------------------------
# Pack validation probes (must REFUSE loudly).
# ------------------------------------------------------------------

@probe("pack/malformed-rule-missing-name")
def _p_malformed_name():
    if MODE == "stub":
        return ("BREAK", "stub loads a nameless rule silently")
    keys = _test_keys()
    pack = _core_pack()
    del pack["rules"][0]["name"]
    try:
        _impl().load_pack(_pack_bytes(pack, keys),
                          trust_keys={keys["keyid"]: keys["pub"]})
    except Exception as e:
        code = getattr(e, "code", "")
        ok = code == "behsig-pack-malformed"
        return ("HELD" if ok else "BREAK", "code=%r" % (code,))
    return ("BREAK", "nameless rule loaded without refusal")


@probe("pack/unknown-comparator-refused")
def _p_unknown_comparator():
    if MODE == "stub":
        return ("BREAK", "stub accepts an unknown comparator")
    keys = _test_keys()
    pack = _core_pack()
    pack["rules"][0]["condition"]["args"][0] = {
        "op": "fuzzy-ish", "field": "arg.class", "value": "credential"}
    try:
        _impl().load_pack(_pack_bytes(pack, keys),
                          trust_keys={keys["keyid"]: keys["pub"]})
    except Exception as e:
        code = getattr(e, "code", "")
        ok = code == "behsig-pack-malformed"
        return ("HELD" if ok else "BREAK", "code=%r" % (code,))
    return ("BREAK", "unknown comparator loaded without refusal")


@probe("pack/engine-version-gate")
def _p_engine_version():
    if MODE == "stub":
        return ("BREAK", "stub ignores the engine version pin")
    keys = _test_keys()
    pack = _core_pack()
    pack["engine_version"] = "999"
    try:
        _impl().load_pack(_pack_bytes(pack, keys),
                          trust_keys={keys["keyid"]: keys["pub"]})
    except Exception as e:
        code = getattr(e, "code", "")
        ok = code == "behsig-pack-malformed"
        return ("HELD" if ok else "BREAK", "code=%r" % (code,))
    return ("BREAK", "foreign-engine pack loaded")


@probe("pack/tampered-signature-refused")
def _p_tampered():
    if MODE == "stub":
        return ("BREAK", "stub loads a tampered pack")
    keys = _test_keys()
    blob = _pack_bytes(_core_pack(), keys)
    doc = json.loads(blob.decode())
    doc["pack"]["rules"][0]["priority"] = "critical"
    tampered = json.dumps(doc, sort_keys=True).encode()
    try:
        _impl().load_pack(tampered,
                          trust_keys={keys["keyid"]: keys["pub"]})
    except Exception as e:
        code = getattr(e, "code", "")
        ok = code == "behsig-pack-untrusted"
        return ("HELD" if ok else "BREAK", "code=%r" % (code,))
    return ("BREAK", "tampered pack loaded without refusal")


@probe("pack/unsigned-refused-when-trust-configured")
def _p_unsigned():
    if MODE == "stub":
        return ("BREAK", "stub loads an unsigned pack")
    keys = _test_keys()
    pack = _core_pack()
    blob = json.dumps({"pack": pack, "signatures": []},
                      sort_keys=True).encode()
    try:
        _impl().load_pack(blob,
                          trust_keys={keys["keyid"]: keys["pub"]})
    except Exception as e:
        code = getattr(e, "code", "")
        ok = code == "behsig-pack-untrusted"
        return ("HELD" if ok else "BREAK", "code=%r" % (code,))
    return ("BREAK", "unsigned pack loaded without refusal")


@probe("pack/no-trust-material-fails-closed")
def _p_no_trust():
    if MODE == "stub":
        return ("BASELINE", "trust-material gate is a module property")
    keys = _test_keys()
    try:
        _impl().load_pack(_pack_bytes(_core_pack(), keys),
                          trust_keys={})
    except Exception as e:
        code = getattr(e, "code", "")
        ok = code == "behsig-pack-untrusted"
        return ("HELD" if ok else "BREAK", "code=%r" % (code,))
    return ("BREAK", "empty trust material accepted a signed pack")


@probe("pack/unknown-field-rule-disabled-loudly")
def _p_unknown_field():
    if MODE == "stub":
        return ("BREAK", "stub has no unknown-field discipline")
    keys = _test_keys()
    pack = _core_pack()
    pack["rules"][0]["condition"] = {
        "op": "eq", "field": "proc.nonexistent_field", "value": "x"}
    journal = _journal()
    loaded = _impl().load_pack(
        _pack_bytes(pack, keys),
        trust_keys={keys["keyid"]: keys["pub"]}, journal=journal)
    disabled = [n for n, _r in loaded.disabled_rules]
    loud = any(r.get("code") == "behsig-rule-disabled"
               for r in journal.records)
    still_there = "test.sandbox_noisy" in loaded.rules
    ok = ("test.credential_then_export" in disabled and loud
          and still_there)
    return ("HELD" if ok else "BREAK",
            "disabled=%r loud=%r sibling=%r"
            % (disabled, loud, still_there))


@probe("pack/valid-pack-loads-and-fires")
def _p_valid_loads():
    if MODE == "stub":
        return ("BASELINE", "firing is a module property")
    keys = _test_keys()
    journal = _journal()
    loaded = _impl().load_pack(
        _pack_bytes(_core_pack(), keys),
        trust_keys={keys["keyid"]: keys["pub"]}, journal=journal)
    enriched = [_impl().enrich_event(
        _event(args={"password": "hunter2", "table": "users"}))]
    alerts = _impl().match_pack(loaded, enriched, journal=journal)
    names = [a.rule_name for a in alerts]
    ok = names == ["test.credential_then_export"]
    return ("HELD" if ok else "BREAK", "fired=%r" % (names,))


# ------------------------------------------------------------------
# Tuning discipline probes (append/override, never edit-in-place).
# ------------------------------------------------------------------

def _load(keys, journal=None):
    return _impl().load_pack(
        _pack_bytes(_core_pack(), keys),
        trust_keys={keys["keyid"]: keys["pub"]},
        journal=journal if journal is not None else _journal())


@probe("tuning/lowering-below-floor-refused")
def _p_tuning_floor():
    if MODE == "stub":
        return ("BREAK", "stub accepts floor-violating tuning")
    keys = _test_keys()
    journal = _journal()
    loaded = _load(keys, journal)
    tuning = {"pack_id": "test-core",
              "rule_tuning": {
                  "test.credential_then_export": {
                      "params": {"min_export_bytes": 1}}}}
    try:
        _impl().apply_tuning(loaded, tuning, journal=journal)
    except Exception as e:
        code = getattr(e, "code", "")
        ok = code == "behsig-tuning-rejected"
        return ("HELD" if ok else "BREAK", "code=%r" % (code,))
    return ("BREAK", "tuning below author floor accepted")


@probe("tuning/disabling-stable-rule-needs-justification")
def _p_tuning_disable_stable():
    if MODE == "stub":
        return ("BREAK", "stub silently disables a stable rule")
    keys = _test_keys()
    journal = _journal()
    loaded = _load(keys, journal)
    tuning = {"pack_id": "test-core",
              "rule_tuning": {
                  "test.credential_then_export": {"disable": True}}}
    try:
        _impl().apply_tuning(loaded, tuning, journal=journal)
    except Exception as e:
        code = getattr(e, "code", "")
        ok = code == "behsig-tuning-rejected"
        return ("HELD" if ok else "BREAK", "code=%r" % (code,))
    return ("BREAK", "stable rule disabled without justification")


@probe("tuning/justified-stable-disable-is-loud")
def _p_tuning_disable_loud():
    if MODE == "stub":
        return ("BASELINE", "loud journaling is a module property")
    keys = _test_keys()
    journal = _journal()
    loaded = _load(keys, journal)
    tuning = {"pack_id": "test-core",
              "rule_tuning": {
                  "test.credential_then_export": {
                      "disable": True,
                      "justification": "retired after incident review "
                                       "INC-42"}}}
    tuned = _impl().apply_tuning(loaded, tuning, journal=journal)
    loud = any(r.get("code") == "behsig-tuning-rejected"
               or "disable" in str(r.get("detail", ""))
               for r in journal.records)
    gone = "test.credential_then_export" not in tuned.rules
    ok = gone and loud
    return ("HELD" if ok else "BREAK",
            "disabled=%r loud=%r" % (gone, loud))


@probe("tuning/adding-exception-is-allowed")
def _p_tuning_add_exception():
    if MODE == "stub":
        return ("BASELINE", "exception composition is a module property")
    keys = _test_keys()
    journal = _journal()
    loaded = _load(keys, journal)
    tuning = {"pack_id": "test-core",
              "rule_tuning": {
                  "test.credential_then_export": {
                      "exceptions_add": [
                          {"and": [
                              {"field": "principal",
                               "comparator": "eq",
                               "value": "svc-nightly"},
                              {"field": "tool.target",
                               "comparator": "eq",
                               "value": "backup.internal"},
                          ]}]}}}
    tuned = _impl().apply_tuning(loaded, tuning, journal=journal)
    # Deployment supplies VALUES for the author-declared shape:
    # full tuple holds -> excepted.
    enriched = [_impl().enrich_event(
        _event(principal="svc-nightly", target="backup.internal",
               args={"password": "hunter2"}))]
    alerts = _impl().match_pack(tuned, enriched, journal=journal)
    ok = alerts == []
    return ("HELD" if ok else "BREAK",
            "alerts=%d" % (len(alerts),))


@probe("tuning/novel-exception-shape-refused")
def _p_tuning_novel_shape():
    if MODE == "stub":
        return ("BREAK", "stub accepts novel exception shapes")
    keys = _test_keys()
    journal = _journal()
    loaded = _load(keys, journal)
    # (principal, ne) was never declared by the rule author: the
    # author owns exceptable shapes, the deployment supplies values.
    tuning = {"pack_id": "test-core",
              "rule_tuning": {
                  "test.credential_then_export": {
                      "exceptions_add": [
                          {"and": [
                              {"field": "principal",
                               "comparator": "ne",
                               "value": "anyone"},
                          ]}]}}}
    try:
        _impl().apply_tuning(loaded, tuning, journal=journal)
    except Exception as e:
        code = getattr(e, "code", "")
        ok = code == "behsig-tuning-rejected"
        return ("HELD" if ok else "BREAK", "code=%r" % (code,))
    return ("BREAK", "novel exception shape accepted")


@probe("tuning/exception-unknown-field-refused")
def _p_tuning_unknown_field():
    if MODE == "stub":
        return ("BREAK", "stub accepts unknown exception fields")
    keys = _test_keys()
    journal = _journal()
    loaded = _load(keys, journal)
    # An exception on an unknown field would resolve to None and,
    # with comparator 'ne', permanently suppress the rule. Tuning
    # checks fields exactly as load does: refuse loudly.
    tuning = {"pack_id": "test-core",
              "rule_tuning": {
                  "test.credential_then_export": {
                      "exceptions_add": [
                          {"and": [
                              {"field": "principal",
                               "comparator": "eq",
                               "value": "svc-x"},
                              {"field": "proc.evil",
                               "comparator": "ne",
                               "value": "nope"},
                          ]}]}}}
    try:
        _impl().apply_tuning(loaded, tuning, journal=journal)
    except Exception as e:
        code = getattr(e, "code", "")
        ok = code == "behsig-tuning-rejected"
        return ("HELD" if ok else "BREAK", "code=%r" % (code,))
    return ("BREAK", "unknown-field exception accepted")


# ------------------------------------------------------------------
# Enrichment-before-match and maturity probes.
# ------------------------------------------------------------------

@probe("enrich/raw-text-never-matched")
def _p_raw_text():
    if MODE == "stub":
        return ("BASELINE", "enrichment is a module property")
    keys = _test_keys()
    journal = _journal()
    loaded = _load(keys, journal)
    # Raw text mentions dump-like words, but the ENRICHED action is a
    # read: a raw-text matcher would fire; the enriched matcher must
    # not.
    enriched = [_impl().enrich_event(
        _event(tool="db.read", target="prod-db",
               args={"note": "please dump the summary for me"}))]
    alerts = _impl().match_pack(loaded, enriched, journal=journal)
    ok = alerts == []
    return ("HELD" if ok else "BREAK",
            "alerts=%d" % (len(alerts),))


@probe("enrich/exception-tuple-excludes-benign")
def _p_exception():
    if MODE == "stub":
        return ("BASELINE", "exceptions are a module property")
    keys = _test_keys()
    journal = _journal()
    loaded = _load(keys, journal)
    # Full tuple holds (actor+target): excepted.
    benign = [_impl().enrich_event(
        _event(principal="svc-backup", target="backup.internal",
               args={"password": "hunter2"}))]
    # Only the actor triple holds: AND semantics -> still fires.
    partial = [_impl().enrich_event(
        _event(principal="svc-backup", target="prod-db",
               args={"password": "hunter2"}))]
    other = [_impl().enrich_event(
        _event(principal="agent-9", args={"password": "hunter2"}))]
    ok = (_impl().match_pack(loaded, benign, journal=journal) == []
          and len(_impl().match_pack(loaded, partial,
                                     journal=journal)) == 1
          and len(_impl().match_pack(loaded, other,
                                     journal=journal)) == 1)
    return ("HELD" if ok else "BREAK", "exception honored=%r" % (ok,))


@probe("maturity/min-maturity-filters-sandbox")
def _p_maturity():
    if MODE == "stub":
        return ("BASELINE", "maturity filtering is a module property")
    keys = _test_keys()
    journal = _journal()
    loaded = _impl().load_pack(
        _pack_bytes(_core_pack(), keys),
        trust_keys={keys["keyid"]: keys["pub"]}, journal=journal,
        min_maturity="stable")
    sandbox_present = "test.sandbox_noisy" in loaded.rules
    enriched = [_impl().enrich_event(_event(tool="canary.action"))]
    alerts = _impl().match_pack(loaded, enriched, journal=journal)
    ok = (not sandbox_present) and alerts == []
    return ("HELD" if ok else "BREAK",
            "sandbox_loaded=%r alerts=%d" % (sandbox_present,
                                             len(alerts)))


# ------------------------------------------------------------------
# Stateful correlator probes (the above-the-predicates component).
# ------------------------------------------------------------------

def _correlator(journal, queue=None):
    config = {
        "burst": {"window_s": 60, "min_events": 20},
        "fire_storm": {"window_s": 300, "min_fires": 4},
        "slow_drip": {"window_s": 3600, "min_sessions": 3,
                      "join_key": "tool.target"},
        "ratio": {"window_s": 300, "min_events": 10,
                  "export_ratio": 0.5},
    }
    kw = {"journal": journal}
    if queue is not None:
        kw["queue"] = queue
    return _impl().StatefulCorrelator(config, **kw)


def _stream(n, **kw):
    out = []
    for i in range(n):
        ev = _event(ts=1000.0 + i * 2.0, **kw)
        out.append(ev)
    return out


@probe("correlator/burst-below-per-event-threshold")
def _p_burst():
    if MODE == "stub":
        return ("BREAK", "stub never advises on bursts")
    journal = _journal()
    corr = _correlator(journal)
    advisories = []
    # 25 individually-benign events inside 60 s: no single rule
    # fires, but the burst correlator must advise.
    for raw in _stream(25, tool="file.read", target="docs",
                       args={"path": "/docs/a"}):
        enriched = _impl().enrich_event(raw)
        advisories.extend(corr.observe(enriched, []))
    loud = any(r.get("code") == "behsig-correlator-advisory"
               for r in journal.records)
    ok = len(advisories) >= 1 and loud
    return ("HELD" if ok else "BREAK",
            "advisories=%d loud=%r" % (len(advisories), loud))


@probe("correlator/slow-drip-cross-session")
def _p_slow_drip():
    if MODE == "stub":
        return ("BREAK", "stub never advises on cross-session drips")
    keys = _test_keys()
    journal = _journal()
    loaded = _load(keys, journal)
    corr = _correlator(journal)
    advisories = []
    # Same actor, same target, export-class arg on 3 distinct
    # sessions spread over an hour: each session alone is quiet-ish,
    # the fuzzy join on tool.target must reunite them.
    for s in ("sess-a", "sess-b", "sess-c"):
        raw = _event(ts=1000.0 + (ord(s[-1]) - 97) * 1500.0,
                     session_id=s, tool="file.export",
                     target="vault-archive",
                     args={"dest": "ext.example.com"})
        enriched = _impl().enrich_event(raw)
        alerts = _impl().match_pack(loaded, [enriched],
                                    journal=journal)
        advisories.extend(corr.observe(enriched, alerts))
    kinds = {a.kind for a in advisories}
    ok = "slow_drip" in kinds
    return ("HELD" if ok else "BREAK", "kinds=%r" % (sorted(kinds),))


@probe("correlator/ratio-padding-defeated")
def _p_ratio():
    if MODE == "stub":
        return ("BREAK", "stub never advises on padded ratios")
    journal = _journal()
    corr = _correlator(journal)
    advisories = []
    # 6 exports padded with 6 benign reads: per-event view is mixed,
    # the windowed export ratio (0.5) must still advise.
    raws = []
    for i in range(6):
        raws.append(_event(ts=1000.0 + i * 10.0, tool="file.export",
                           target="vault", args={"dest": "ext"}))
        raws.append(_event(ts=1000.0 + i * 10.0 + 5.0,
                           tool="file.read", target="docs",
                           args={"path": "/docs/a"}))
    for raw in raws:
        enriched = _impl().enrich_event(raw)
        advisories.extend(corr.observe(enriched, []))
    kinds = {a.kind for a in advisories}
    ok = "ratio" in kinds
    return ("HELD" if ok else "BREAK", "kinds=%r" % (sorted(kinds),))


@probe("correlator/cross-kind-windows-independent")
def _p_cross_kind_windows():
    if MODE == "stub":
        return ("BREAK", "stub never correlates")
    # Burst's narrow window must not eat fire_storm's wide window:
    # 3 alert-carrying events 100 s apart -> fire_storm fires on its
    # 300 s window, burst stays quiet on its 60 s window.
    journal = _journal()
    corr = _impl().StatefulCorrelator(
        {"burst": {"window_s": 60, "min_events": 3},
         "fire_storm": {"window_s": 300, "min_fires": 2}},
        journal=journal)
    loaded = _load(_test_keys(), journal)
    advisories = []
    for i in range(3):
        raw = _event(ts=float(i) * 100.0, tool="db.dump", target="t",
                     args={"password": "hunter2"})
        enriched = _impl().enrich_event(raw)
        alerts = _impl().match_pack(loaded, [enriched],
                                    journal=journal)
        advisories.extend(corr.observe(enriched, alerts))
    kinds = {a.kind for a in advisories}
    ok = "fire_storm" in kinds and "burst" not in kinds
    return ("HELD" if ok else "BREAK", "kinds=%r" % (sorted(kinds),))


@probe("correlator/benign-traffic-quiet")
def _p_corr_quiet():
    if MODE == "stub":
        return ("BASELINE", "quiet calibration is a module property")
    journal = _journal()
    corr = _correlator(journal)
    advisories = []
    # 5 benign reads over 5 minutes: under every correlator gate.
    for raw in _stream(5, tool="file.read", target="docs",
                       args={"path": "/docs/a"}):
        raw = dict(raw)
        raw["ts"] = 1000.0 + (raw["ts"] - 1000.0) * 30.0
        enriched = _impl().enrich_event(raw)
        advisories.extend(corr.observe(enriched, []))
    ok = advisories == []
    return ("HELD" if ok else "BREAK",
            "advisories=%d" % (len(advisories),))


@probe("correlator/advisory-never-denies")
def _p_never_denies():
    if MODE == "stub":
        return ("BREAK", "stub produces no advisory to check")
    queued = []
    journal = _journal()
    corr = _correlator(journal, queue=queued.append)
    advisories = []
    for raw in _stream(25, tool="file.read", target="docs",
                       args={"path": "/docs/a"}):
        enriched = _impl().enrich_event(raw)
        advisories.extend(corr.observe(enriched, []))
    # Advisory output must be journal + optional queue, never a
    # denial: observe() returns data, raises nothing, and the queue
    # receives a hold REQUEST (the deployment decides), not a block.
    ok = (len(advisories) >= 1 and len(queued) >= 1
          and all(q.get("decision") != "deny" for q in queued))
    return ("HELD" if ok else "BREAK",
            "advisories=%d queued=%d" % (len(advisories),
                                         len(queued)))


@probe("alert/evidence-on-fire-carries-window")
def _p_evidence():
    if MODE == "stub":
        return ("BASELINE", "evidence capture is a module property")
    keys = _test_keys()
    journal = _journal()
    loaded = _load(keys, journal)
    events = [_impl().enrich_event(
        _event(ts=1000.0 + i, tool="file.read", target="docs",
               args={"path": "/docs/%d" % i}))
        for i in range(4)]
    events.append(_impl().enrich_event(
        _event(ts=1005.0, args={"password": "hunter2"})))
    alerts = _impl().match_pack(loaded, events, journal=journal)
    ok = (len(alerts) == 1 and len(alerts[0].capture) >= 4
          and all("digest" in c for c in alerts[0].capture))
    return ("HELD" if ok else "BREAK",
            "capture=%d" % (len(alerts[0].capture) if alerts else -1,))


@probe("control/empty-stream-quiet")
def _p_empty():
    if MODE == "stub":
        return ("BASELINE", "empty-stream behavior is a module property")
    keys = _test_keys()
    journal = _journal()
    loaded = _load(keys, journal)
    corr = _correlator(journal)
    ok = (_impl().match_pack(loaded, [], journal=journal) == []
          and corr.observe(
              _impl().enrich_event(_event(tool="file.read",
                                          target="docs",
                                          args={"path": "/x"})),
              []) == [])
    return ("HELD" if ok else "BREAK", "quiet=%r" % (ok,))


@probe("pin/taxonomy-pin")
def _p_pin():
    if MODE == "stub":
        return ("BASELINE", "pin is a module property")
    ok_len = len(decision_codes.TAXONOMY) == TAXONOMY_PIN
    missing = [c for c in EXPECTED_CODES
               if c not in decision_codes.TAXONOMY]
    ok = ok_len and not missing
    return ("HELD" if ok else "BREAK",
            "len=%d missing=%r"
            % (len(decision_codes.TAXONOMY), missing))


@probe("w_adjacent_green")
def _p_adjacent():
    # Depth-1 green check: adjacent suites stay green.
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("BASELINE", "green check skipped (depth-1)")
    if MODE == "stub":
        return ("BASELINE", "green check runs in module mode")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = "/var/tmp/g267behsig-adj"
    os.makedirs(env["TMPDIR"], exist_ok=True)
    checks = [
        ([sys.executable, "evals/w175_behsig_probes.py"]
         if os.path.exists(os.path.join(REPO_ROOT,
                                         "evals/w175_behsig_probes.py"))
         else None),
    ]
    for item in checks:
        if item is None:
            continue
        p = subprocess.run(item, cwd=REPO_ROOT, env=env,
                           capture_output=True, text=True, timeout=600)
        if p.returncode != 0:
            return ("BREAK", "adjacent battery rc=%d" % (p.returncode,))
    p = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_behavioral_sigs", "-v"], cwd=REPO_ROOT, env=env,
        capture_output=True, text=True, timeout=600)
    if p.returncode != 0:
        return ("BREAK", "test_behavioral_sigs rc=%d" % (p.returncode,))
    return ("HELD", "adjacent suites green")


def main():
    results = [_run_probe(name, fn) for name, fn in _PROBES]
    held = sum(1 for _, v, _ in results if v == "HELD")
    broken = sum(1 for _, v, _ in results if v == "BREAK")
    baseline = sum(1 for _, v, _ in results if v == "BASELINE")
    errors = sum(1 for _, v, _ in results if v == "ERROR")
    print("mode=%s probes=%d" % (MODE, len(results)))
    for name, verdict, detail in results:
        print("%-44s %-8s %s" % (name, verdict, detail))
    print("HELD=%d BREAK=%d BASELINE=%d ERROR=%d"
          % (held, broken, baseline, errors))
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
