"""Wave-273 lane-B closure battery: F272 / F273 / F274 / F275 / F279.

Red-first closure probes at the public seams for the five findings
this lane closes (renumbered at the wave-272 merge; filed by the
wave-272 red-team battery as F256 / F257 / F258 / F259 / F263):

  F272  replay_manifest: verify_manifest's documented "raises coded
        ReplayManifestError on any failure" contract leaked raw
        TypeError/AttributeError for hostile shapes (non-str
        manifest_digest, non-dict presentations/receipts), and
        record_environment_snapshot leaked RecursionError on deeply
        nested env dicts. Fixed: shape validation at the seam, coded
        replay-malformed for every hostile shape.
  F273  bundle_rsl: _parse_rule raised raw AttributeError/TypeError
        for malformed rule wires, not the module-contract ValueError
        ("malformed caller input raises ValueError"). Fixed: shape
        validation of terminal / signatures / principals / expires
        before any attribute access; every malformed wire shape
        raises ValueError.
  F274  bundle_rsl: a malformed rsl-skip record (missing
        target_digest, or a non-int target_seq) appended to the
        journal folded verify() into rsl-log-corrupt -- one junk
        record bricked verification of the whole bundle,
        contradicting _verify_skip_sigs' documented "cannot be used
        to DoS verification". Fixed: malformed skips are dishonored
        (skipped) without failing the bundle; forged-but-well-formed
        skips stay dishonored per the existing contract.
  F275  bundle_rsl: expiry was enforced against the frozen open-time
        `now` value, so a long-lived handle authorized transitions
        after wall-clock expiry despite the documented "checked ...
        on every operation" claim. Fixed: `now` may be a callable
        clock sampled on every operation; the frozen-int default is
        kept for determinism and the honest limit is documented in
        the module docstring.
  F279  evidence_bundle_v2: verify_inclusion leaked a raw TypeError
        for hostile inclusion-proof shapes (None / float hash
        element) instead of a coded EvidenceBundleV2Error. Fixed:
        up-front per-element shape validation (64-char hex str or
        32 raw bytes), coded evbundle-malformed for the
        non-coercible; the RFC 6962 verifier's errors are also
        folded to the coded error defense-in-depth.

The probes are written red-first: each asserts the CLOSED behavior
at the public seam and returns BREAK if the pre-fix defect is still
present. Controls pin the honest-behavior contracts (honest
attribution, never-raises verify, forged skips dishonored).

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; deterministic (fixed seeds, explicit
`now`); fresh unique /var/tmp/g273* TMPDIR (`mkdir -p` first);
depth-1 green checks honoring GOV_SKIP_GREEN=1; no in-repo git
subprocesses; stdlib only.
"""

import hashlib
import json
import os
import re
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Deterministic audit-log key (fixed, not secrets.token_hex).
os.environ.setdefault(
    "GOV_LOG_KEY",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w273-laneb")

_TMP = tempfile.mkdtemp(prefix="g273-laneb-%d-" % os.getpid(), dir="/var/tmp")
os.makedirs(_TMP, exist_ok=True)
os.environ["TMPDIR"] = _TMP

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import gov.replay_manifest as rm                     # noqa: E402
import gov.bundle_rsl as rsl                          # noqa: E402
import gov.evidence_bundle_v2 as eb2                  # noqa: E402
import gov.ed25519 as _ed                             # noqa: E402
from gov.durable_journal import Journal               # noqa: E402
from gov import durable_journal as dj                 # noqa: E402

TAXONOMY_PIN = 2106 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).


GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []


def _seed(i):
    return bytes([i & 0xFF]) * 32


def _run(pid, expected, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001
        verdict, note = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    ok = (verdict == expected)
    _RESULTS.append((pid, expected, verdict, ok, note))


def _pin_check():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    literals = re.findall(r'"code": \'([^\']*)\'', src)
    if len(literals) != TAXONOMY_PIN:
        return ("BREAK", "taxonomy pin drift: %d literals, pin %d"
                % (len(literals), TAXONOMY_PIN))
    if len(set(literals)) != len(literals):
        return "BREAK", "duplicate code literals in taxonomy"
    return "HELD", "taxonomy pin 1588: 1588 unique literals"


# ---------------------------------------------------------------------------
# F272: replay_manifest coded-error contract
# ---------------------------------------------------------------------------

_RM_NOW = 1792000000


def _rm_builder():
    return rm.ReplayManifestBuilder("spiffe://example/w273",
                                    now=lambda: _RM_NOW)


def rm01_nonstring_digest_coded():
    """F272: a non-str manifest_digest must raise coded
    ReplayManifestError (replay-malformed), never a raw TypeError."""
    bad = dict(_rm_builder().seal())
    bad["manifest_digest"] = 123
    try:
        rm.verify_manifest(bad)
    except rm.ReplayManifestError as e:
        if e.code == "replay-malformed":
            return "HELD", "coded: %s" % e.code
        return "BREAK", "coded but wrong code: %s" % e.code
    except TypeError as e:
        return ("BREAK",
                "F272 still open: raw TypeError escapes verify_manifest "
                "for non-str digest: %s" % (e,))
    return "ERROR", "no exception at all"


def rm02_nonobject_presentations_coded():
    """F272: a non-dict presentations map must raise coded
    ReplayManifestError, never a raw AttributeError."""
    b = _rm_builder()
    b.record_presentation(presented_bytes=b"w273-bytes", purpose="audit")
    m = b.seal()
    try:
        rm.verify_manifest(m, presentations=["not-a-dict"])
    except rm.ReplayManifestError as e:
        return "HELD", "coded: %s" % e.code
    except AttributeError as e:
        return ("BREAK",
                "F272 still open: raw AttributeError escapes "
                "verify_manifest for non-dict presentations: %s" % (e,))
    return "ERROR", "no exception at all"


def rm03_nonobject_receipts_coded():
    """F272: a non-dict receipts map must raise coded
    ReplayManifestError, never a raw AttributeError."""
    b = _rm_builder()
    b.record_approval_received(approval_id="ap1",
                               approval_receipt_ref="ab" * 32,
                               decision_digest="cd" * 32)
    m = b.seal()
    try:
        rm.verify_manifest(m, receipts=["not-a-dict"],
                           receipt_checker=lambda link, stmt: True)
    except rm.ReplayManifestError as e:
        return "HELD", "coded: %s" % e.code
    except AttributeError as e:
        return ("BREAK",
                "F272 still open: raw AttributeError escapes "
                "verify_manifest for non-dict receipts: %s" % (e,))
    return "ERROR", "no exception at all"


def rm04_deep_env_coded():
    """F272: a deeply-nested env must raise coded replay-malformed,
    never a raw RecursionError."""
    d = "x"
    for _ in range(20000):
        d = [d]
    try:
        _rm_builder().record_environment_snapshot({"deep": d})
    except rm.ReplayManifestError as e:
        if e.code == "replay-malformed":
            return "HELD", "coded: %s" % e.code
        return "BREAK", "coded but wrong code: %s" % e.code
    except RecursionError:
        return ("BREAK",
                "F272 still open: raw RecursionError escapes "
                "record_environment_snapshot on deeply-nested env")
    return "ERROR", "no exception at all"


def rm05_valid_manifest_verifies():
    """Control: a well-formed manifest still verifies clean."""
    b = _rm_builder()
    b.record_tool_call(tool_id="t1", input_digest="aa" * 32,
                       output_digest="bb" * 32,
                       tool_digest_pin="cc" * 32, seed=1)
    v = rm.verify_manifest(b.seal())
    if v["verified"] is True:
        return "HELD", "valid manifest verifies"
    return "BREAK", "unexpected: %r" % (v,)


# ---------------------------------------------------------------------------
# F273: bundle_rsl malformed-wire ValueError contract
# ---------------------------------------------------------------------------

_RSL_NOW = 1792000000
_RSL_BUNDLE = "bundle-w273"


def _rsl_rule_path(tag, expires=None):
    """Write a valid 2-principal 1-of-2 rule file; return (path, wire)."""
    seeds = [_seed(0x31), _seed(0x32)]
    principals = {"p1": {"pub": _ed.publickey(seeds[0]).hex()},
                  "p2": {"pub": _ed.publickey(seeds[1]).hex()}}
    wire = rsl.make_rule_file(
        rule_id="rule-w273", bundle=_RSL_BUNDLE,
        principals=principals,
        delegations=[{"name": "releasers", "key_ids": ["p1", "p2"],
                      "threshold": 1}],
        terminal_key_id="p1", terminal_seed=seeds[0],
        expires=expires if expires is not None else _RSL_NOW + 3600,
        now=_RSL_NOW)
    path = os.path.join(_TMP, "rsl-%s.jsonl" % tag)
    if os.path.exists(path):
        os.remove(path)
    return path, wire, seeds


def rsl01a_nonobject_terminal_valueerror():
    """F273: a non-dict 'terminal' wire must raise ValueError (the
    module-contract error), never a raw AttributeError."""
    path, wire, _seeds = _rsl_rule_path("rsl01a")
    obj = json.loads(wire)
    obj["terminal"] = "not-a-dict"
    try:
        rsl.open_log(path, json.dumps(obj), _RSL_NOW)
    except ValueError:
        return "HELD", "ValueError as contracted"
    except AttributeError as e:
        return ("BREAK",
                "F273 still open: raw AttributeError from open_log for "
                "non-dict terminal: %s" % (e,))
    return "ERROR", "no exception at all"


def rsl01b_nonobject_signatures_terminal_valueerror():
    """F273: signatures.terminal as a non-dict must raise ValueError,
    never a raw AttributeError."""
    path, wire, _seeds = _rsl_rule_path("rsl01b")
    obj = json.loads(wire)
    obj["signatures"] = {"terminal": "not-a-dict"}
    try:
        rsl.open_log(path, json.dumps(obj), _RSL_NOW)
    except ValueError:
        return "HELD", "ValueError as contracted"
    except AttributeError as e:
        return ("BREAK",
                "F273 still open: raw AttributeError from open_log for "
                "non-dict signatures.terminal: %s" % (e,))
    return "ERROR", "no exception at all"


def rsl01c_nonobject_principals_and_str_expires_valueerror():
    """F273: non-dict principals and non-int expires must raise
    ValueError (the module-contract error), never raw TypeError."""
    notes = []
    for tag, mutate, expect in (
            ("rsl01c1", lambda o: o.update(principals=["p1"]),
             "non-dict principals"),
            ("rsl01c2", lambda o: o.update(expires="tomorrow"),
             "str expires")):
        path, wire, _seeds = _rsl_rule_path(tag)
        obj = json.loads(wire)
        mutate(obj)
        try:
            rsl.open_log(path, json.dumps(obj), _RSL_NOW)
        except ValueError:
            notes.append("%s: ValueError" % expect)
        except rsl.RSLError as e:
            # Pre-fix: some malformed wires folded into a coded RSLError
            # instead of the contracted ValueError (still the wrong
            # error class per the module contract).
            return ("BREAK",
                    "F273 still open: coded-but-wrong RSLError(%s) "
                    "escapes open_log for %s" % (e.code, expect))
        except (TypeError, AttributeError) as e:
            return ("BREAK",
                    "F273 still open: raw %s escapes open_log for %s: %s"
                    % (type(e).__name__, expect, e))
        else:
            return "ERROR", "no exception at all for %s" % expect
    return "HELD", "; ".join(notes)


def rsl02_valid_wire_opens():
    """Control: a well-formed rule wire still opens and authorizes."""
    path, wire, seeds = _rsl_rule_path("rsl02valid")
    log = rsl.open_log(path, wire, _RSL_NOW)
    d1 = hashlib.sha256(b"w273-v1").hexdigest()
    log.authorize_transition(_RSL_BUNDLE, None, d1, "releasers",
                             [seeds[0]])
    seq = log.record_state(_RSL_BUNDLE, d1)
    if seq == 0:
        return "HELD", "valid wire opens, authorizes, records"
    return "BREAK", "unexpected seq %r" % (seq,)


# ---------------------------------------------------------------------------
# F274: malformed skip must not DoS verify()
# ---------------------------------------------------------------------------

def s01_malformed_skip_dishonored():
    """F274: a malformed rsl-skip (dict missing target_digest)
    appended by anyone with journal write access must be dishonored --
    verify() stays ok, never folds to rsl-log-corrupt."""
    path, wire, seeds = _rsl_rule_path("s01")
    log = rsl.open_log(path, wire, _RSL_NOW)
    d1 = hashlib.sha256(b"s01-v1").hexdigest()
    log.authorize_transition(_RSL_BUNDLE, None, d1, "releasers",
                             [seeds[0]])
    log.record_state(_RSL_BUNDLE, d1)
    Journal(path).append("rsl-skip",
                         {"bundle": _RSL_BUNDLE, "target_seq": 0})
    v = log.verify(_RSL_BUNDLE)
    if v["ok"] is True:
        return "HELD", "malformed skip dishonored, verify ok"
    if v["ok"] is False and v["code"] == "rsl-log-corrupt":
        return ("BREAK",
                "F274 still open: malformed rsl-skip DoSes verify() -> "
                "rsl-log-corrupt (whole bundle unverifiable)")
    return "ERROR", "unexpected: %r" % (v,)


def s01b_str_target_seq_skip_dishonored():
    """F274: a skip with a non-int target_seq must also be dishonored
    (the bound comparison would otherwise raise TypeError and brick
    the whole bundle)."""
    path, wire, seeds = _rsl_rule_path("s01b")
    log = rsl.open_log(path, wire, _RSL_NOW)
    d1 = hashlib.sha256(b"s01b-v1").hexdigest()
    log.authorize_transition(_RSL_BUNDLE, None, d1, "releasers",
                             [seeds[0]])
    log.record_state(_RSL_BUNDLE, d1)
    Journal(path).append("rsl-skip",
                         {"bundle": _RSL_BUNDLE, "target_seq": "0",
                          "target_digest": d1, "reason": "junk"})
    v = log.verify(_RSL_BUNDLE)
    if v["ok"] is True:
        return "HELD", "non-int target_seq skip dishonored, verify ok"
    if v["ok"] is False and v["code"] == "rsl-log-corrupt":
        return ("BREAK",
                "F274 still open: string target_seq DoSes verify() -> "
                "rsl-log-corrupt")
    return "ERROR", "unexpected: %r" % (v,)


def s01c_forged_wellformed_skip_still_dishonored():
    """Control: a forged-but-well-formed skip (bad signature) remains
    dishonored per the existing contract -- not honored, and it does
    not fail verification either."""
    path, wire, seeds = _rsl_rule_path("s01c")
    log = rsl.open_log(path, wire, _RSL_NOW)
    d1 = hashlib.sha256(b"s01c-v1").hexdigest()
    log.authorize_transition(_RSL_BUNDLE, None, d1, "releasers",
                             [seeds[0]])
    log.record_state(_RSL_BUNDLE, d1)
    Journal(path).append("rsl-skip",
                         {"bundle": _RSL_BUNDLE, "target_seq": 0,
                          "target_digest": d1, "reason": "forged",
                          "signatures": {"p1": {"sig": "00" * 64,
                                               "key_id": "p1"}}})
    v = log.verify(_RSL_BUNDLE)
    if v["ok"] is True:
        return "HELD", "forged skip dishonored, verify ok"
    return "BREAK", "unexpected: %r" % (v,)


def _raw_append(path, rtype, body):
    """Simulate raw journal-file append access (the F274 threat model):
    a correctly chain-hashed record written straight to the file,
    bypassing Journal.append's API-level shape checks."""
    last = None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                last = json.loads(line)
    seq = last["seq"] + 1
    prev = last["hash"]
    h = dj._record_hash(seq, prev, None, rtype, body)
    rec = {"seq": seq, "prev": prev, "txn": None,
           "type": rtype, "body": body, "hash": h}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True,
                           separators=(",", ":")) + "\n")


def s01d_nondict_skip_body_dishonored():
    """F274 (guard-ordering): an rsl-skip record with a NON-DICT body
    (e.g. a list) must be dishonored -- the isinstance guard must run
    before any .get on the body, or the raw AttributeError bricks
    whole-bundle verification (the exact DoS class F274 closes)."""
    path, wire, seeds = _rsl_rule_path("s01d")
    log = rsl.open_log(path, wire, _RSL_NOW)
    d1 = hashlib.sha256(b"s01d-v1").hexdigest()
    log.authorize_transition(_RSL_BUNDLE, None, d1, "releasers",
                             [seeds[0]])
    log.record_state(_RSL_BUNDLE, d1)
    _raw_append(path, "rsl-skip", ["not", "a", "dict"])
    v = log.verify(_RSL_BUNDLE)
    if v["ok"] is True:
        return "HELD", "non-dict skip body dishonored, verify ok"
    return ("BREAK",
            "F274 still open: non-dict skip body bricks verify(): %r"
            % (v,))


# ---------------------------------------------------------------------------
# F275: live clock for expiry
# ---------------------------------------------------------------------------

def s02_live_clock_refuses_post_expiry():
    """F275: a handle opened with a callable clock observes expiry on
    every operation -- a transition authorized just inside the window
    is refused with rsl-rule-expired once the clock passes expiry."""
    E = _RSL_NOW + 100
    path, wire, seeds = _rsl_rule_path("s02live", expires=E)
    tick = [E - 1]
    try:
        log = rsl.open_log(path, wire, lambda: tick[0])
    except TypeError:
        return ("BREAK",
                "F275 still open: now does not accept a callable clock; "
                "expiry is read from the frozen open-time value")
    d1 = hashlib.sha256(b"s02live-v1").hexdigest()
    log.authorize_transition(_RSL_BUNDLE, None, d1, "releasers",
                             [seeds[0]])
    log.record_state(_RSL_BUNDLE, d1)
    tick[0] = E + 1  # wall clock passes expiry
    d2 = hashlib.sha256(b"s02live-v2").hexdigest()
    try:
        log.authorize_transition(_RSL_BUNDLE, d1, d2, "releasers",
                                 [seeds[0]])
    except rsl.RSLError as e:
        if e.code == "rsl-rule-expired":
            return ("HELD",
                    "live clock: post-expiry transition refused with "
                    "rsl-rule-expired")
        return "BREAK", "wrong refusal code: %s" % e.code
    return "BREAK", "F275 still open: post-expiry transition authorized"


def s02b_frozen_int_determinism_documented():
    """F275 control: the frozen-int default keeps the deterministic
    discipline (same now -> same behavior) and the honest limit is
    documented in the module docstring."""
    E = _RSL_NOW + 100
    path1, wire1, _seeds = _rsl_rule_path("s02f1", expires=E)
    path2, wire2, _seeds = _rsl_rule_path("s02f2", expires=E)
    log1 = rsl.open_log(path1, wire1, E - 1)
    log2 = rsl.open_log(path2, wire2, E - 1)
    # Both handles read the same frozen value: deterministic.
    log1._check_expiry()
    log2._check_expiry()
    doc = rsl.__doc__ or ""
    if "long-lived" not in doc or "without a clock" not in doc:
        return "BREAK", "honest limit not documented in module docstring"
    return ("HELD",
            "frozen-int handles deterministic; honest limit documented")


def s02c_expired_at_open_refused():
    """Control: an already-expired rule is refused at open with
    rsl-rule-expired (unchanged contract)."""
    E = _RSL_NOW + 100
    path, wire, _seeds = _rsl_rule_path("s02exp", expires=E)
    try:
        rsl.open_log(path, wire, E + 1)
    except rsl.RSLError as e:
        if e.code == "rsl-rule-expired":
            return "HELD", "expired-at-open refused with rsl-rule-expired"
        return "BREAK", "wrong code: %s" % e.code
    return "ERROR", "no exception at all"


def s02d_float_clock_accepted():
    """F275: a float-returning clock (the shape of time.time, which the
    module docstring names as the example) is accepted -- truncated to
    int seconds to keep the int-epoch discipline -- and expiry is
    enforced against it."""
    E = _RSL_NOW + 100
    path, wire, seeds = _rsl_rule_path("s02d", expires=E)
    tick = [float(E - 1)]
    try:
        log = rsl.open_log(path, wire, lambda: tick[0])
    except (TypeError, ValueError) as exc:
        return ("BREAK",
                "F275 still open: float clock refused (%s: %s); the "
                "docstring's own time.time example fails" % (
                    type(exc).__name__, exc))
    d1 = hashlib.sha256(b"s02d-v1").hexdigest()
    log.authorize_transition(_RSL_BUNDLE, None, d1, "releasers",
                             [seeds[0]])
    tick[0] = float(E + 1)
    d2 = hashlib.sha256(b"s02d-v2").hexdigest()
    try:
        log.authorize_transition(_RSL_BUNDLE, d1, d2, "releasers",
                                 [seeds[0]])
    except rsl.RSLError as e:
        if e.code == "rsl-rule-expired":
            return ("HELD",
                    "float clock accepted; post-expiry refused with "
                    "rsl-rule-expired")
        return "BREAK", "wrong refusal code: %s" % e.code
    return "BREAK", "F275 still open: post-expiry transition authorized"


# ---------------------------------------------------------------------------
# F279: verify_inclusion coded-error contract
# ---------------------------------------------------------------------------

_TL_DIGEST = "ab" * 32


def _tl_checkpoint(root_hex):
    return {"log_id": "inprocess", "tree_size": 1, "root": root_hex}


def _tl_verify(digest, inclusion_proof, checkpoint):
    return eb2.InProcessTransparencyLog(now=lambda: 1791000000)\
        .verify_inclusion(digest, inclusion_proof, checkpoint)


def _tl_single_leaf_root(digest_hex):
    # RFC 6962 single-leaf root: sha256(0x00 || leaf_data).
    return hashlib.sha256(b"\x00" + bytes.fromhex(digest_hex)).hexdigest()


def tl01_none_proof_element_coded():
    """F279: a None hash element must raise coded
    EvidenceBundleV2Error (evbundle-malformed), never a raw
    TypeError."""
    try:
        _tl_verify(_TL_DIGEST, {"leaf_index": 0, "hashes": [None]},
                   _tl_checkpoint(_tl_single_leaf_root(_TL_DIGEST)))
    except eb2.EvidenceBundleV2Error as e:
        return "HELD", "coded: %s" % e.code
    except TypeError as e:
        return ("BREAK",
                "F279 still open: raw TypeError escapes verify_inclusion "
                "for a None proof element: %s" % (e,))
    return "ERROR", "no exception at all"


def tl02_float_proof_element_coded():
    """F279: a float hash element must raise coded
    EvidenceBundleV2Error, never a raw TypeError."""
    try:
        _tl_verify(_TL_DIGEST, {"leaf_index": 0, "hashes": [1.5]},
                   _tl_checkpoint(_tl_single_leaf_root(_TL_DIGEST)))
    except eb2.EvidenceBundleV2Error as e:
        return "HELD", "coded: %s" % e.code
    except TypeError as e:
        return ("BREAK",
                "F279 still open: raw TypeError escapes verify_inclusion "
                "for a float proof element: %s" % (e,))
    return "ERROR", "no exception at all"


def tl03_valid_proof_verifies():
    """Control: a valid single-leaf inclusion proof still verifies."""
    root = _tl_single_leaf_root(_TL_DIGEST)
    v = _tl_verify(_TL_DIGEST, {"leaf_index": 0, "hashes": []},
                   _tl_checkpoint(root))
    if v is True:
        return "HELD", "valid proof verifies"
    return "BREAK", "unexpected: %r" % (v,)


def tl04_forged_root_unverified_coded():
    """Control: a proof against a forged root raises the coded
    evbundle-inclusion-unverified (not a raw exception, and not a
    silent False)."""
    try:
        _tl_verify(_TL_DIGEST, {"leaf_index": 0, "hashes": []},
                   _tl_checkpoint("ff" * 32))
    except eb2.EvidenceBundleV2Error as e:
        if e.code == "evbundle-inclusion-unverified":
            return "HELD", "coded: %s" % e.code
        return "BREAK", "wrong code: %s" % e.code
    return "ERROR", "no exception at all"


# ---------------------------------------------------------------------------
# probe table
# ---------------------------------------------------------------------------

_PROBES = [
    ("pin-taxonomy-1458", "HELD", _pin_check),
    # F272 (replay_manifest coded errors).
    ("rm01-nonstring-digest-coded", "HELD", rm01_nonstring_digest_coded),
    ("rm02-nonobject-presentations-coded", "HELD",
     rm02_nonobject_presentations_coded),
    ("rm03-nonobject-receipts-coded", "HELD", rm03_nonobject_receipts_coded),
    ("rm04-deep-env-coded", "HELD", rm04_deep_env_coded),
    ("rm05-valid-manifest-verifies", "HELD", rm05_valid_manifest_verifies),
    # F273 (bundle_rsl malformed-wire ValueError).
    ("rsl01a-nonobject-terminal-valueerror", "HELD",
     rsl01a_nonobject_terminal_valueerror),
    ("rsl01b-nonobject-signatures-terminal-valueerror", "HELD",
     rsl01b_nonobject_signatures_terminal_valueerror),
    ("rsl01c-nonobject-principals-str-expires-valueerror", "HELD",
     rsl01c_nonobject_principals_and_str_expires_valueerror),
    ("rsl02-valid-wire-opens", "HELD", rsl02_valid_wire_opens),
    # F274 (malformed skip dishonored).
    ("s01-malformed-skip-dishonored", "HELD", s01_malformed_skip_dishonored),
    ("s01b-str-target-seq-skip-dishonored", "HELD",
     s01b_str_target_seq_skip_dishonored),
    ("s01c-forged-wellformed-skip-still-dishonored", "HELD",
     s01c_forged_wellformed_skip_still_dishonored),
    ("s01d-nondict-skip-body-dishonored", "HELD",
     s01d_nondict_skip_body_dishonored),
    # F275 (live clock).
    ("s02-live-clock-refuses-post-expiry", "HELD",
     s02_live_clock_refuses_post_expiry),
    ("s02b-frozen-int-determinism-documented", "HELD",
     s02b_frozen_int_determinism_documented),
    ("s02c-expired-at-open-refused", "HELD", s02c_expired_at_open_refused),
    ("s02d-float-clock-accepted", "HELD", s02d_float_clock_accepted),
    # F279 (verify_inclusion coded errors).
    ("tl01-none-proof-element-coded", "HELD", tl01_none_proof_element_coded),
    ("tl02-float-proof-element-coded", "HELD",
     tl02_float_proof_element_coded),
    ("tl03-valid-proof-verifies", "HELD", tl03_valid_proof_verifies),
    ("tl04-forged-root-unverified-coded", "HELD",
     tl04_forged_root_unverified_coded),
]


# ---------------------------------------------------------------------------
# green checks (depth-1; honor GOV_SKIP_GREEN=1)
# ---------------------------------------------------------------------------

_GREEN_BATTERIES = [
    "w272_redteam_probes.py",
    "w271_replay_probes.py",
    "w271_rsl_probes.py",
]


def _green_checks():
    if GREEN_SKIP:
        return [("green", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 convention)")]
    notes = []
    evals_dir = os.path.join(REPO, "evals")
    for battery in _GREEN_BATTERIES:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        try:
            import subprocess
            proc = subprocess.run(
                [sys.executable, os.path.join(evals_dir, battery)],
                env=env, cwd=REPO, capture_output=True, text=True,
                timeout=600)
            tail = (proc.stdout or "").strip().splitlines()[-3:]
            ok = proc.returncode == 0
            notes.append((
                "green", "HELD" if ok else "BREAK",
                "%s rc=%d: %s" % (battery, proc.returncode,
                                  " | ".join(tail))))
        except Exception as exc:  # noqa: BLE001
            notes.append(("green", "ERROR",
                          "%s: %s" % (battery, exc)))
    return notes


def main():
    print("w273 lane-B closure battery: %d probes (TMPDIR=%s)"
          % (len(_PROBES), _TMP))
    failures = 0
    for pid, expected, fn in _PROBES:
        _run(pid, expected, fn)
    for pid, expected, verdict, ok, note in _RESULTS:
        flag = "ok " if ok else "FAIL"
        if not ok:
            failures += 1
        print("[%s] %-48s expected=%-5s got=%-5s %s"
              % (flag, pid, expected, verdict, note))
    print("--- green checks (depth-1) ---")
    for name, verdict, note in _green_checks():
        print("[%s] %s %s" % ("ok " if verdict in ("HELD", "SKIP") else "FAIL",
                              name, note))
        if verdict not in ("HELD", "SKIP"):
            failures += 1
    n_break = sum(1 for r in _RESULTS if r[2] == "BREAK")
    n_held = sum(1 for r in _RESULTS if r[2] == "HELD")
    n_err = sum(1 for r in _RESULTS if r[2] == "ERROR")
    print("probes: %d BREAK / %d HELD / %d ERROR; mismatches: %d"
          % (n_break, n_held, n_err, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
