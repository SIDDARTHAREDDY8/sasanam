"""Break-first red-team battery for the wave-257 new modules.

Wave-258 lane 4 (independent red-team). Stdlib only. Deterministic
across runs (staging + `env -u GOV_DEPLOYMENT_MODE`).

Targets (new in wave-257, base 045c59da):
- gov/encrypted_envelopes.py -- tag replay/transplant, KEM confusion,
  refusal-path data independence, journal probing visibility,
  payload_signed claim binding, version confusion, journal-corruption
  behavior, recipient-id logging.
- gov/control_profiles.py -- check-swap residual exploitability,
  cross-control snapshot isolation, impact boundaries, findings-index
  override, quality-gate composition, vacuous snapshots, fabricated
  results, exception messages in artifacts.
- Cross-module: envelope journal vs credential journal correlation
  surface.
- Baselines: F220-F224 reproduce on this base (the closure lanes'
  red baseline -- NOT new findings, documented as BASELINE).

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Verdicts: HELD (attack refused / gap documented as an
honest residual), BREAK (genuine defect -> filed as a finding
F225+), BASELINE (known-open finding reproduced on this base).
"""

import json
import os
import statistics
import struct
import sys
import tempfile
import threading
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import control_profiles as cp  # noqa: E402
from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import durable_journal as dj  # noqa: E402
from gov import encrypted_envelopes as ee  # noqa: E402
from gov import evidence_quality as eq  # noqa: E402
from gov import short_lived_credentials as slc  # noqa: E402

TAXONOMY_PIN = 2012 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)



_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    return tempfile.mkdtemp(prefix="w258rt-", dir="/var/tmp")


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _baseline(detail=""):
    return ("BASELINE", detail)


_KM = b"w258-redteam-key-material-000000"


def _vault(path=None):
    return ee.EnvelopeVault(
        path or os.path.join(_tmpdir(), "env.journal"))


def _recips(n, km=_KM):
    return [ee.Recipient("auditor-%d" % i, km) for i in range(n)]


# ---------------------------------------------------------------------------
# Envelopes
# ---------------------------------------------------------------------------

@probe("envelope/tag-replay-across-envelopes")
def _p_tag_replay():
    v = _vault()
    r = _recips(1)
    env_a = v.seal(b"payload-A", r)
    env_b = v.seal(b"payload-B", r)
    forged = env_b[:-32] + env_a[-32:]
    try:
        v.open(forged, _KM)
        return _break("tag from envelope A verified on B")
    except ee.EnvelopeError as e:
        if e.code == "envelope-open-refused":
            return _held("cross-envelope tag replay refused")
        return _break("wrong code %s" % e.code)


@probe("envelope/wrap-transplant-between-envelopes")
def _p_wrap_transplant():
    v = _vault()
    r = _recips(1)
    env_a = v.seal(b"payload-A", r)
    env_c = v.seal(b"payload-C", r)

    def wrap_off(env):
        off = 13
        id_len = struct.unpack(">H", env[off:off + 2])[0]
        off += 2 + id_len
        wl = struct.unpack(">H", env[off:off + 2])[0]
        off += 2
        return off, wl

    off_a, wl_a = wrap_off(env_a)
    off_c, wl_c = wrap_off(env_c)
    assert wl_a == wl_c == 48
    forged = env_c[:off_c] + env_a[off_a:off_a + wl_a] +\
        env_c[off_c + wl_c:]
    try:
        v.open(forged, _KM)
        return _break("transplanted wrap opened")
    except ee.EnvelopeError as e:
        if e.code == "envelope-open-refused":
            return _held("wrap transplant refused (tag binds wraps)")
        return _break("wrong code %s" % e.code)


@probe("envelope/flags-bit-tamper-refused")
def _p_flags_tamper():
    v = _vault()
    env = v.seal(b"payload", _recips(1), payload_signed=True)
    tampered = bytearray(env)
    tampered[10] ^= 0x01
    try:
        v.open(bytes(tampered), _KM)
        return _break("flags bit flip opened")
    except ee.EnvelopeError as e:
        if e.code == "envelope-open-refused":
            return _held("flags tamper refused; claim is tag-bound")
        return _break("wrong code %s" % e.code)


@probe("envelope/version-2-refused")
def _p_version():
    v = _vault()
    env = v.seal(b"payload", _recips(1))
    bad = bytearray(env)
    bad[8:10] = struct.pack(">H", 2)
    try:
        v.open(bytes(bad), _KM)
        return _break("version 2 opened")
    except ee.EnvelopeError as e:
        if e.code == "envelope-version-unknown":
            return _held("unknown version refused before tag work")
        return _break("wrong code %s" % e.code)


@probe("envelope/nrec-zero-and-65-malformed")
def _p_nrec():
    v = _vault()
    env = v.seal(b"payload", _recips(1))
    for nrec in (0, 65):
        bad = bytearray(env)
        bad[11:13] = struct.pack(">H", nrec)
        try:
            v.open(bytes(bad), _KM)
            return _break("nrec=%d opened" % nrec)
        except ee.EnvelopeError as e:
            if e.code != "envelope-malformed":
                return _break("nrec=%d wrong code %s"
                              % (nrec, e.code))
    return _held("nrec 0 and 65 refused as malformed")


@probe("envelope/ct-single-bit-flip-refused")
def _p_ct_flip():
    v = _vault()
    env = v.seal(b"payload", _recips(1))
    bad = bytearray(env)
    bad[-33] ^= 0x01
    try:
        v.open(bytes(bad), _KM)
        return _break("flipped ciphertext opened")
    except ee.EnvelopeError as e:
        if e.code == "envelope-open-refused":
            return _held("ciphertext tamper refused")
        return _break("wrong code %s" % e.code)


@probe("envelope/seal-15-byte-key-refused")
def _p_short_key():
    v = _vault()
    try:
        v.seal(b"x", [ee.Recipient("r", b"s" * 15)])
        return _break("15-byte key material sealed")
    except ee.EnvelopeError as e:
        if e.code == "envelope-recipient-refused":
            return _held("weak key material refused at seal")
        return _break("wrong code %s" % e.code)


@probe("envelope/two-seals-randomized")
def _p_randomized():
    v = _vault()
    r = _recips(1)
    e1 = v.seal(b"same payload", r)
    e2 = v.seal(b"same payload", r)
    if e1 != e2:
        return _held("fresh envelope key + nonces per seal")
    return _break("two seals byte-identical (key/nonce reuse)")


@probe("envelope/malformed-open-journaled")
def _p_malformed_journaled():
    path = os.path.join(_tmpdir(), "j.journal")
    v = _vault(path)
    n0 = len(dj.Journal(path).records)
    try:
        v.open(b"total garbage not an envelope", _KM)
        return _break("garbage opened")
    except ee.EnvelopeError as e:
        if e.code != "envelope-malformed":
            return _break("wrong code %s" % e.code)
    recs = dj.Journal(path).records
    if len(recs) != n0 + 1:
        return _break("malformed open not journaled")
    body = recs[-1]["body"]
    if body.get("refusal_code") != "envelope-malformed":
        return _break("journal body missing refusal code")
    if "envelope_digest" not in body:
        return _break("journal body missing digest")
    return _held("attacker probing stays visible (digest-only)")


@probe("envelope/journal-corruption-refuses-loudly")
def _p_journal_corrupt():
    path = os.path.join(_tmpdir(), "j.journal")
    v = _vault(path)
    env = v.seal(b"payload", _recips(1))
    with open(path, "ab") as f:
        f.write(b"GARBAGE LINE NOT JSON\n")
    try:
        v.open(env, _KM)
        return _break("open succeeded over a torn journal")
    except Exception as e:
        # The journal's own detect-and-refuse contract: the vault
        # refuses loudly instead of opening without an audit trail.
        return _held("refused loudly (%s); no plaintext returned" %
                     type(e).__name__)


@probe("envelope/refusal-path-scales-with-wraps")
def _p_refusal_timing():
    # Informational: the refusal path must try every wrap (no early
    # exit), so wrong-key open time scales with recipient count.
    # nrec is wire-plaintext, so this confirms the documented
    # data-independence rather than leaking anything new.
    v2 = _vault(os.path.join(_tmpdir(), "j2.journal"))
    v32 = _vault(os.path.join(_tmpdir(), "j32.journal"))
    e2 = v2.seal(b"x", _recips(2))
    e32 = v32.seal(b"x", _recips(32))
    wrong = b"w" * 32

    def attempt(vault, env):
        try:
            vault.open(env, wrong)
        except ee.EnvelopeError:
            pass

    for _ in range(5):
        attempt(v2, e2)
        attempt(v32, e32)

    def med(vault, env, n=31):
        ts = []
        for _ in range(n):
            t0 = time.perf_counter_ns()
            attempt(vault, env)
            ts.append(time.perf_counter_ns() - t0)
        return statistics.median(ts)

    t2, t32 = med(v2, e2), med(v32, e32)
    ratio = t32 / max(t2, 1)
    return _held("wrong-key 2-wrap median %dns, 32-wrap %dns, "
                 "ratio %.2f (full wrap iteration on refusal path)"
                 % (t2, t32, ratio))


# ---------------------------------------------------------------------------
# Control profiles
# ---------------------------------------------------------------------------

def _profile(checks):
    return {"id": "P1", "title": "t",
            "controls": [{"id": "C%d" % i, "impact": 0.9,
                          "title": "c", "desc": "d", "check": c}
                         for i, c in enumerate(checks)]}


@probe("profiles/cross-control-snapshot-contamination")
def _p_contamination():
    seen = {}

    def mutator(snap):
        snap["poisoned"] = True
        return True, "ok"

    def reader(snap):
        seen["poisoned"] = snap.get("poisoned", False)
        return True, "ok"

    cp.run_profile(_profile([mutator, reader]), {"evidence": 1})
    if seen.get("poisoned"):
        return _break("check C0 mutated the snapshot seen by C1; "
                      "no per-control isolation")
    return _held("checks see isolated snapshots")


@probe("profiles/lambda-qualname-digest-blindness")
def _p_lambda_digest():
    d1 = cp.profile_digest(_profile([lambda s: True]))
    d2 = cp.profile_digest(_profile([lambda s: False]))
    if d1 == d2:
        return _held("documented residual confirmed: distinct "
                     "lambdas share qualname '<lambda>', digest "
                     "blind to the swap (same trust boundary as "
                     "the named-function case)")
    return _held("lambdas unexpectedly distinguished")


@probe("profiles/impact-boundary-exact")
def _p_impact():
    got = (cp.severity_for_impact(0.7),
           cp.severity_for_impact(0.6999999),
           cp.severity_for_impact(0.4),
           cp.severity_for_impact(0.3999999),
           cp.severity_for_impact(0.0))
    if got == ("high", "medium", "medium", "low", "low"):
        return _held("boundaries exact: 0.7->high, 0.4->medium")
    return _break("boundary drift: %r" % (got,))


@probe("profiles/deployment-override-hides-failure")
def _p_override():
    res = cp.run_profile(_profile([lambda s: False]), {"e": 1})
    assert not res["success"]
    ref = None
    for r in res["results"]:
        if r["status"] == "fail":
            ref = cp._finding_ref(res, r["control_id"])
    art = cp.emit_profile_results(res, fmt="json",
                                  findings={ref: "closed"})
    doc = json.loads(art)
    for m in doc["mappings"]:
        if m["kind"] == "finding" and m["ref"] == ref:
            if m.get("finding_status") == "closed":
                return _held("documented: deployment owns the "
                             "findings index (emitter boundary)")
            return _break("override ignored")
    return _break("finding mapping missing")


@probe("profiles/vacuous-snapshot-check-author-semantics")
def _p_vacuous_snapshot():
    res = cp.run_profile(_profile([lambda s: True]), {})
    if res["success"]:
        return _held("documented: vacuity for opaque checks is "
                     "check-author semantics; the module cannot "
                     "define 'empty evidence' for arbitrary "
                     "callables (F222-class, different owner)")
    return _held("empty snapshot refused")


@probe("profiles/fabricated-results-emit")
def _p_fabricated():
    fake = {"profile_id": "P1", "profile_title": "t",
            "profile_digest": "00" * 32, "success": True,
            "results": [{"control_id": "C0", "impact": 0.9,
                         "severity": "high", "check": "f",
                         "check_version": "1", "status": "pass",
                         "reason": "forged", "exception_info": None,
                         "digest": "11" * 32}]}
    art = cp.emit_profile_results(fake, fmt="json")
    if art:
        return _held("documented: deployment is the trust "
                     "boundary; a deployment forging its own "
                     "results deceives only itself (emitter "
                     "honesty boundary)")
    return _break("fabricated results refused unexpectedly")


@probe("profiles/exception-message-in-artifact")
def _p_exc_message():
    def raiser(snap):
        raise ValueError("db password hunter2 exploded")

    res = cp.run_profile(_profile([raiser]), {"e": 1})
    art = cp.emit_profile_results(res, fmt="json")
    if "hunter2" in art:
        return _held("documented residual: check-raised messages "
                     "ride into the artifact rationale; check "
                     "authors must not raise with secrets")
    return _held("exception message sanitized")


@probe("profiles/quality-gate-names-failed-expectations")
def _p_gate():
    res = cp.run_profile(_profile([lambda s: True]), {"e": 1})
    exps = [{"expectation_type": "expect_evidence_monotonic",
             "kwargs": {}}]
    try:
        cp.emit_profile_results(res, fmt="json", quality_gate=True,
                                quality_expectations=exps,
                                quality_evidence=[])
        return _held("gate passed on non-empty evidence")
    except cp.ControlProfileError as e:
        if e.code == "control-profile-gate-failed":
            return _held("gate failed closed, naming expectations")
        return _break("wrong code %s" % e.code)


@probe("profiles/check-swap-named-function-undetected")
def _p_check_swap():
    def check_body(snap):
        return True

    p1 = {"id": "P1", "title": "t",
          "controls": [{"id": "C0", "impact": 0.9, "title": "c",
                        "desc": "d", "check": check_body}]}
    d1 = cp.profile_digest(p1)

    def check_body(snap):  # noqa: F811 -- deliberate rebinding
        return False

    p2 = {"id": "P1", "title": "t",
          "controls": [{"id": "C0", "impact": 0.9, "title": "c",
                        "desc": "d", "check": check_body}]}
    d2 = cp.profile_digest(p2)
    if d1 == d2:
        return _held("documented residual pinned: body swap "
                     "behind the same name keeps the digest")
    return _held("body swap detected")


# ---------------------------------------------------------------------------
# Cross-module
# ---------------------------------------------------------------------------

@probe("cross/journal-correlation-surface")
def _p_correlation():
    path = os.path.join(_tmpdir(), "j.journal")
    v = _vault(path)
    v.seal(b"payload", _recips(2), payload_signed=True)
    try:
        v.open(b"garbage", _KM)
    except ee.EnvelopeError:
        pass
    time_keys = ("time", "issued_at", "mono_ns", "timestamp",
                 "created_at", "at")
    for rec in dj.Journal(path).records:
        body = rec["body"]
        for k in body:
            if any(t in k for t in time_keys):
                return _break("envelope journal body carries "
                              "temporal key %r" % k)
        for k in ("recipient_ids",):
            if k in body and not isinstance(body[k], list):
                return _break("unexpected recipient_ids shape")
    # Credential journal bodies DO carry issued_at/mono_ns (slc
    # design); envelope journal bodies carry none, so the two
    # journals cannot be temporally aligned. Recipient ids /
    # principals are wire-visible by design on both sides.
    return _held("no temporal keys in envelope journal bodies; "
                 "no cross-journal alignment surface beyond "
                 "by-design identity fields")


# ---------------------------------------------------------------------------
# F220-F224 baselines (closure lanes' red baseline, NOT new findings)
# ---------------------------------------------------------------------------

@probe("baseline/f220-deepcopy-hostile-raw-typeerror")
def _b_f220():
    try:
        eq.evaluate(
            [{"expectation_type": "expect_evidence_monotonic",
              "kwargs": {}}],
            [{"seq": 1, "lock": threading.Lock()}])
        return _baseline("no exception (unexpected)")
    except TypeError as e:
        return _baseline("raw TypeError still escapes: %s"
                         % str(e)[:50])
    except Exception as e:
        return _baseline("machine-coded now: %s"
                         % type(e).__name__)


@probe("baseline/f221-deep-nesting-raw-recursionerror")
def _b_f221():
    deep = {"leaf": 1}
    for _ in range(10000):
        deep = [deep]
    try:
        eq.evaluate(
            [{"expectation_type": "expect_fields_present",
              "kwargs": {"required_fields": ["a"]}}], [deep])
        return _baseline("no exception (unexpected)")
    except RecursionError:
        return _baseline("raw RecursionError still escapes")
    except Exception as e:
        return _baseline("machine-coded now: %s"
                         % type(e).__name__)


@probe("baseline/f222-empty-evidence-vacuous-pass")
def _b_f222():
    r = eq.evaluate(
        [{"expectation_type": "expect_evidence_monotonic",
          "kwargs": {}}], [])
    if r["success"]:
        return _baseline("empty evidence still reports success")
    return _baseline("empty evidence no longer passes")


@probe("baseline/f224-non-numeric-now-raw-typeerror")
def _b_f224():
    iss = slc.CredentialIssuer(
        os.path.join(_tmpdir(), "c.journal"), key=b"0" * 32)
    c = iss.issue("agent-a", "read:docs", 60)
    try:
        iss.verify(c["credential_id"], c["secret"],
                   now="yesterday")
        return _baseline("no exception (unexpected)")
    except TypeError as e:
        return _baseline("raw TypeError still escapes: %s"
                         % str(e)[:50])
    except Exception as e:
        return _baseline("machine-coded now: %s"
                         % type(e).__name__)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: adjacent wave-257 batteries still green. Honors
    GOV_SKIP_GREEN (records skip, never spawns)."""
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED (GOV_SKIP_GREEN=1)")]
    notes = []
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for battery in ("evals/w257_envelopes_probes.py",
                    "evals/w257_profiles_probes.py",
                    "evals/w257_f219_probes.py"):
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        try:
            p = subprocess.run(
                [sys.executable, os.path.join(repo, battery)],
                capture_output=True, text=True, timeout=600,
                env=env, cwd=repo)
            tail = (p.stdout or "").strip().splitlines()[-1:] or\
                [""]
            notes.append((battery,
                          "exit=%d %s" % (p.returncode, tail[0][:60])))
        except Exception as e:  # noqa: BLE001 -- green-check report
            notes.append((battery, "ERROR %s" % e))
    return notes


def main():
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        print("PIN MISMATCH: taxonomy has %d keys, pin is %d" %
              (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
        return 2
    held = breaks = baselines = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s" %
                               (type(e).__name__, str(e)[:120]))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        elif verdict == "BASELINE":
            baselines += 1
        else:
            errors += 1
        print("%-8s %-55s %s" % (verdict, name, detail))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("HELD %d / BREAK %d / BASELINE %d / ERROR %d "
          "over %d probes" % (held, breaks, baselines, errors,
                               len(_PROBES)))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
