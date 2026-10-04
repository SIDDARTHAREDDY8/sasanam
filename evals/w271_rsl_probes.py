#!/usr/bin/env python3
"""Wave-271 red-first battery: skill-bundle Revision State Log (RSL).

gittuf-pattern adaptation (pattern only, nothing copied): an append-only,
hash-chained per-bundle state log with fork detection (multi-parent check),
revocation-by-annotation (skip), explicit rollback refusal, ordered
delegations with an always-last terminal allow-rule, principal/threshold
validated at rule-creation time, and transition authorizations
(<bundle>/<from>-<to>) authorizing the UPGRADE, not the blob.

Red phase:  RSL_IMPL=stub  -> permissive StubRSL foil. Every attack probe
must BREAK (the stub accepts what it must refuse); a probe that HELDs on
the stub is vacuous and is flagged.
Green phase: default (gov.bundle_rsl) -> every probe must HELD.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; depth-1 green checks honoring
GOV_SKIP_GREEN=1; fresh unique /var/tmp TMPDIRs; NO in-repo git
subprocesses.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from gov import ed25519 as _ed  # noqa: E402
from gov.durable_journal import Journal  # noqa: E402

IMPL = os.environ.get("RSL_IMPL", "real")

NOW = 1790860000  # fixed test clock
DAY = 86400


# ---------------------------------------------------------------------------
# Deterministic key fixtures (spec-pinned constructions, not from the module)
# ---------------------------------------------------------------------------

def _seed(byte):
    return bytes([byte & 0xFF]) * 32


def _pub_hex(seed):
    return _ed.publickey(seed).hex()


def _digest(tag):
    return hashlib.sha256(b"bundle-state:" + tag.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Permissive stub foil (red phase): same record shape, zero checks.
# ---------------------------------------------------------------------------

class _StubLog(object):
    def __init__(self, path, rule):
        self._j = Journal(path)
        self._rule = rule

    def authorize_transition(self, bundle, from_digest, to_digest,
                             delegation, seeds):
        self._j.append("rsl-transition", {
            "bundle": bundle, "from_digest": from_digest,
            "to_digest": to_digest, "delegation": delegation,
            "signatures": {}, "statement_id": "stub"})
        return "stub"

    def record_state(self, bundle, state_digest, custom_fields=None):
        self._j.append("rsl-state", {
            "bundle": bundle, "state_digest": state_digest, "seq": 0,
            "prev_digest": None, "transition": "stub",
            "custom_fields": custom_fields or {}})
        return 0

    def skip_annotate(self, bundle, seq, reason, seeds):
        self._j.append("rsl-skip", {
            "bundle": bundle, "target_seq": seq, "reason": reason,
            "signatures": {}})

    def verify(self, bundle, at_digest=None):
        return {"ok": True, "code": None, "detail": "stub accepts all"}


class _StubModule(object):
    @staticmethod
    def make_rule_file(rule_id, bundle, principals, delegations,
                       terminal_key_id, terminal_seed, expires, now):
        # Foil: no threshold check, no terminal-signature check, no expiry
        # check. Accepts everything, including the unsigned.
        return json.dumps({
            "schema_version": 1, "rule_id": rule_id, "bundle": bundle,
            "principals": principals, "delegations": delegations,
            "terminal": {"key_id": terminal_key_id}, "expires": expires,
            "signatures": {}})

    @staticmethod
    def open_log(journal_path, rule_wire, now):
        return _StubLog(journal_path, json.loads(rule_wire))


if IMPL == "stub":
    _mod = _StubModule
else:
    from gov import bundle_rsl as _mod  # noqa: E402


# ---------------------------------------------------------------------------
# Scenario builders (identical for both impls)
# ---------------------------------------------------------------------------

def _principals():
    s1, s2, s3, st = _seed(1), _seed(2), _seed(3), _seed(9)
    return ({"k1": {"pub": _pub_hex(s1)},
             "k2": {"pub": _pub_hex(s2)},
             "k3": {"pub": _pub_hex(s3)},
             "k-deploy": {"pub": _pub_hex(st)}},
            {"k1": s1, "k2": s2, "k3": s3, "k-deploy": st})


def _std_delegations():
    return [{"name": "releasers", "key_ids": ["k1", "k2"], "threshold": 2},
            {"name": "security", "key_ids": ["k3"], "threshold": 1}]


def _make_wire(principals, delegations, terminal_kid, terminal_seed,
               expires=NOW + 30 * DAY, bundle="skill.acme"):
    return _mod.make_rule_file(
        rule_id="rsl-rules/skill.acme", bundle=bundle,
        principals=principals, delegations=delegations,
        terminal_key_id=terminal_kid, terminal_seed=terminal_seed,
        expires=expires, now=NOW)


def _open(tmpdir, wire):
    return _mod.open_log(os.path.join(tmpdir, "rsl.jsonl"), wire, NOW)


def _genesis(log, seeds, bundle="skill.acme", tag="v1"):
    d = _digest(tag)
    log.authorize_transition(bundle, None, d, "releasers", seeds)
    log.record_state(bundle, d)
    return d


def _fork_bodies(bundle, tip_digest, tip_seq, tag_a, tag_b):
    da, db = _digest(tag_a), _digest(tag_b)
    body_a = {"bundle": bundle, "state_digest": da, "seq": tip_seq + 1,
              "prev_digest": tip_digest, "transition": "stub-inject",
              "custom_fields": {}}
    body_b = {"bundle": bundle, "state_digest": db, "seq": tip_seq + 1,
              "prev_digest": tip_digest, "transition": "stub-inject",
              "custom_fields": {}}
    return body_a, body_b


def _inject_fork(journal_path, bundle, tip_digest, tip_seq):
    """Hand-write two sibling state entries sharing one parent, bypassing
    the prevent-time append path -- the verify-time fork detector must
    catch what the writer let through."""
    j = Journal(journal_path)
    a, b = _fork_bodies(bundle, tip_digest, tip_seq, "fork-a", "fork-b")
    j.append("rsl-state", a)
    j.append("rsl-state", b)


# ---------------------------------------------------------------------------
# Probe harness
# ---------------------------------------------------------------------------

_RESULTS = []


def _probe(pid, name, fn):
    tmpdir = tempfile.mkdtemp(prefix="w271rsl-")
    try:
        outcome, detail = fn(tmpdir)
    except Exception as e:  # noqa: BLE001
        outcome, detail = "ERROR", "%r" % e
    _RESULTS.append((pid, name, outcome, detail))
    return outcome


def _attack(pid, name, fn, expect_code):
    """Attack probe: on the stub it must BREAK (vulnerability present);
    on the real impl it must HELD with the expected machine code."""
    def run(tmpdir):
        attack_outcome, got = fn(tmpdir)
        if IMPL == "stub":
            if attack_outcome == "BREAK":
                return "BREAK", got
            return "ERROR", "vacuous on stub: %s" % got
        if attack_outcome == "HELD" and got == expect_code:
            return "HELD", got
        return "ERROR", "expected HELD/%s, got %s/%s" % (
            expect_code, attack_outcome, got)
    return _probe(pid, name, run)


def _control(pid, name, fn):
    """Control: valid flows must HELD on BOTH impls."""
    def run(tmpdir):
        ok, detail = fn(tmpdir)
        return ("HELD" if ok else "ERROR"), detail
    return _probe(pid, name, run)


# ---------------------------------------------------------------------------
# Attack probes (6 falsifiable + 2 extra)
# ---------------------------------------------------------------------------

def p01_forked_log_detected(tmpdir):
    principals, seeds = _principals()
    wire = _make_wire(principals, _std_delegations(), "k-deploy",
                      seeds["k-deploy"])
    log = _open(tmpdir, wire)
    d1 = _genesis(log, [seeds["k1"], seeds["k2"]])
    _inject_fork(os.path.join(tmpdir, "rsl.jsonl"), "skill.acme", d1, 0)
    v = log.verify("skill.acme")
    if v["ok"]:
        return "BREAK", "forked log verified ok"
    return "HELD", v["code"]


def p02_skipped_entry_fails_verification(tmpdir):
    principals, seeds = _principals()
    wire = _make_wire(principals, _std_delegations(), "k-deploy",
                      seeds["k-deploy"])
    log = _open(tmpdir, wire)
    _genesis(log, [seeds["k1"], seeds["k2"]])
    log.skip_annotate("skill.acme", 0, "key compromise suspected",
                      [seeds["k1"]])
    v = log.verify("skill.acme")
    if v["ok"]:
        return "BREAK", "skipped entry verified ok"
    return "HELD", v["code"]


def p03_rollback_refused(tmpdir):
    principals, seeds = _principals()
    wire = _make_wire(principals, _std_delegations(), "k-deploy",
                      seeds["k-deploy"])
    log = _open(tmpdir, wire)
    d1 = _genesis(log, [seeds["k1"], seeds["k2"]])
    d2 = _digest("v2")
    log.authorize_transition("skill.acme", d1, d2, "releasers",
                             [seeds["k1"], seeds["k2"]])
    log.record_state("skill.acme", d2)
    # (a) verify-time: pinning an ancestor as current
    v = log.verify("skill.acme", at_digest=d1)
    if v["ok"]:
        return "BREAK", "ancestor pinned as current verified ok"
    if v["code"] != "rsl-rollback-attempt":
        return "ERROR", "wrong code: %s" % v["code"]
    # (b) prevent-time: re-recording an ancestor digest
    try:
        log.authorize_transition("skill.acme", d2, d1, "releasers",
                                 [seeds["k1"], seeds["k2"]])
        log.record_state("skill.acme", d1)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "rsl-rollback-attempt":
            return "HELD", code
        return "ERROR", "wrong code: %r" % code
    return "BREAK", "ancestor re-recorded without refusal"


def p04_terminal_rule_requires_signature(tmpdir):
    principals, seeds = _principals()
    try:
        wire = _make_wire(principals, _std_delegations(), "k-deploy",
                          None)  # unsigned terminal
    except Exception as e:  # noqa: BLE001
        return "HELD", getattr(e, "code", None)
    try:
        _open(tmpdir, wire)
    except Exception as e:  # noqa: BLE001
        return "HELD", getattr(e, "code", None)
    return "BREAK", "unsigned terminal rule accepted"


def p05_threshold_gt_principals_rejected_at_creation(tmpdir):
    principals, seeds = _principals()
    bad = [{"name": "releasers", "key_ids": ["k1", "k2"], "threshold": 3}]
    try:
        _make_wire(principals, bad, "k-deploy", seeds["k-deploy"])
    except Exception as e:  # noqa: BLE001
        return "HELD", getattr(e, "code", None)
    return "BREAK", "threshold 3 > 2 principals accepted at creation"


def p06_unauthorized_transition_refused(tmpdir):
    principals, seeds = _principals()
    wire = _make_wire(principals, _std_delegations(), "k-deploy",
                      seeds["k-deploy"])
    log = _open(tmpdir, wire)
    try:
        # No authorize_transition call: the upgrade was never authorized.
        log.record_state("skill.acme", _digest("rogue"))
    except Exception as e:  # noqa: BLE001
        return "HELD", getattr(e, "code", None)
    return "BREAK", "unauthorized state transition recorded"


def p07_expired_rule_refused(tmpdir):
    principals, seeds = _principals()
    try:
        wire = _make_wire(principals, _std_delegations(), "k-deploy",
                          seeds["k-deploy"], expires=NOW - 1)
    except Exception as e:  # noqa: BLE001
        return "HELD", getattr(e, "code", None)
    try:
        _open(tmpdir, wire)
    except Exception as e:  # noqa: BLE001
        return "HELD", getattr(e, "code", None)
    return "BREAK", "expired rule file accepted"


def p08_forged_transition_signature_refused(tmpdir):
    principals, seeds = _principals()
    wire = _make_wire(principals, _std_delegations(), "k-deploy",
                      seeds["k-deploy"])
    log = _open(tmpdir, wire)
    rogue = _seed(77)
    try:
        log.authorize_transition("skill.acme", None, _digest("rogue"),
                                 "releasers", [rogue, _seed(78)])
    except Exception as e:  # noqa: BLE001
        return "HELD", getattr(e, "code", None)
    return "BREAK", "transition signed by unknown keys accepted"


# ---------------------------------------------------------------------------
# Controls (valid flows HELD on both impls)
# ---------------------------------------------------------------------------

def c01_valid_genesis_flow(tmpdir):
    principals, seeds = _principals()
    wire = _make_wire(principals, _std_delegations(), "k-deploy",
                      seeds["k-deploy"])
    log = _open(tmpdir, wire)
    d1 = _genesis(log, [seeds["k1"], seeds["k2"]])
    v = log.verify("skill.acme")
    if not v["ok"]:
        return False, "valid genesis failed verify: %s" % v
    v2 = log.verify("skill.acme", at_digest=d1)
    if not v2["ok"]:
        return False, "valid at_digest pin failed: %s" % v2
    return True, "genesis ok"


def c02_authorized_upgrade_flow(tmpdir):
    principals, seeds = _principals()
    wire = _make_wire(principals, _std_delegations(), "k-deploy",
                      seeds["k-deploy"])
    log = _open(tmpdir, wire)
    d1 = _genesis(log, [seeds["k1"], seeds["k2"]])
    d2 = _digest("v2")
    log.authorize_transition("skill.acme", d1, d2, "releasers",
                             [seeds["k1"], seeds["k2"]])
    log.record_state("skill.acme", d2, {"release": "2.0"})
    v = log.verify("skill.acme")
    if not v["ok"]:
        return False, "authorized upgrade failed verify: %s" % v
    return True, "upgrade ok"


def c03_single_principal_security_delegation(tmpdir):
    principals, seeds = _principals()
    wire = _make_wire(principals, _std_delegations(), "k-deploy",
                      seeds["k-deploy"])
    log = _open(tmpdir, wire)
    d1 = _genesis(log, [seeds["k1"], seeds["k2"]])
    d2 = _digest("hotfix")
    log.authorize_transition("skill.acme", d1, d2, "security",
                             [seeds["k3"]])
    log.record_state("skill.acme", d2)
    v = log.verify("skill.acme")
    return (v["ok"], "security-delegation upgrade ok" if v["ok"]
            else "failed: %s" % v)


# ---------------------------------------------------------------------------
# Green-only soundness probes (real impl)
# ---------------------------------------------------------------------------

def g01_determinism(tmpdir):
    if IMPL == "stub":
        return "SKIP", "stub"
    principals, seeds = _principals()
    paths = []
    for i in range(2):
        sub = os.path.join(tmpdir, "run%d" % i)
        os.makedirs(sub)
        wire = _make_wire(principals, _std_delegations(), "k-deploy",
                          seeds["k-deploy"])
        log = _mod.open_log(os.path.join(sub, "rsl.jsonl"), wire, NOW)
        d1 = _digest("v1")
        log.authorize_transition("skill.acme", None, d1, "releasers",
                                 [seeds["k1"], seeds["k2"]])
        log.record_state("skill.acme", d1)
        paths.append(os.path.join(sub, "rsl.jsonl"))
    a = open(paths[0], "rb").read()
    b = open(paths[1], "rb").read()
    return ("HELD" if a == b else "ERROR"), "byte-identical logs"


def g02_unknown_bundle_fails_closed(tmpdir):
    if IMPL == "stub":
        return "SKIP", "stub"
    principals, seeds = _principals()
    wire = _make_wire(principals, _std_delegations(), "k-deploy",
                      seeds["k-deploy"])
    log = _open(tmpdir, wire)
    v = log.verify("skill.nonexistent")
    if v["ok"]:
        return "ERROR", "unknown bundle verified ok"
    if v["code"] != "rsl-transition-unauthorized":
        return "ERROR", "wrong code: %s" % v["code"]
    return "HELD", v["code"]


def g03_pin_on_raw_literals(tmpdir):
    if IMPL == "stub":
        return "SKIP", "stub"
    import re
    from gov import decision_codes as _dc
    src = open(os.path.join(_REPO, "gov", "decision_codes.py")).read()
    lits = re.findall(r"\"code\":\s*'([a-z][a-z0-9-_.]*)'", src)
    new = [c for c in lits if c.startswith("rsl-")]
    ok = (len(lits) == len(set(lits)) == TAXONOMY_PIN
          and len(new) == 8 and all(lits.count(c) == 1 for c in new))
    return ("HELD" if ok else "ERROR",
            "lits=%d unique=%d rsl=%d" % (len(lits), len(set(lits)),
                                         len(new)))


TAXONOMY_PIN = 2018 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded)




def green_check():
    """Depth-1 green check: adjacent bundle-scan unit suite stays green."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green-check: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    r = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_bundle_scan",
         "-v"], cwd=_REPO, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        timeout=600)
    ok = r.returncode == 0
    print("green-check test_bundle_scan: %s" % ("OK" if ok else "FAIL"))
    if not ok:
        print(r.stdout[-2000:])
    return ok


def main():
    attacks = [
        ("p01", "forked log detected", p01_forked_log_detected,
         "rsl-fork-detected"),
        ("p02", "skipped entry fails verification",
         p02_skipped_entry_fails_verification, "rsl-skipped-revoked"),
        ("p03", "rollback refused", p03_rollback_refused,
         "rsl-rollback-attempt"),
        ("p04", "terminal rule requires signature",
         p04_terminal_rule_requires_signature,
         "rsl-terminal-rule-unsigned"),
        ("p05", "threshold>principals rejected at creation",
         p05_threshold_gt_principals_rejected_at_creation,
         "rsl-threshold-invalid"),
        ("p06", "unauthorized transition refused",
         p06_unauthorized_transition_refused,
         "rsl-transition-unauthorized"),
        ("p07", "expired rule refused", p07_expired_rule_refused,
         "rsl-rule-expired"),
        ("p08", "forged transition signature refused",
         p08_forged_transition_signature_refused,
         "rsl-transition-unauthorized"),
    ]
    for pid, name, fn, code in attacks:
        _attack(pid, name, fn, code)
    _control("c01", "valid genesis flow", c01_valid_genesis_flow)
    _control("c02", "authorized upgrade flow", c02_authorized_upgrade_flow)
    _control("c03", "single-principal security delegation",
             c03_single_principal_security_delegation)
    for pid, name, fn in [("g01", "determinism", g01_determinism),
                          ("g02", "unknown bundle fails closed",
                           g02_unknown_bundle_fails_closed),
                          ("g03", "pin on raw literals",
                           g03_pin_on_raw_literals)]:
        _probe(pid, name, lambda t, f=fn: f(t))

    held = sum(1 for _, _, o, _ in _RESULTS if o == "HELD")
    brk = sum(1 for _, _, o, _ in _RESULTS if o == "BREAK")
    err = sum(1 for _, _, o, _ in _RESULTS if o == "ERROR")
    skip = sum(1 for _, _, o, _ in _RESULTS if o == "SKIP")
    print("impl=%s  HELD=%d BREAK=%d SKIP=%d ERROR=%d" %
          (IMPL, held, brk, skip, err))
    for pid, name, o, d in _RESULTS:
        print("  [%s] %s %s -- %s" % (o, pid, name, d))
    gc = green_check()
    ok = (err == 0 and gc)
    if IMPL == "stub":
        ok = ok and brk == 8 and held == 3
    else:
        ok = ok and brk == 0 and held == 14
    print("RESULT " + ("OK" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
