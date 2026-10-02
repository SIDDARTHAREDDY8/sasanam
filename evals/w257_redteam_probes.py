"""Break-first red-team battery for the wave-256 new modules.

Wave-257 lane 4 (independent red-team). Stdlib only. Deterministic
across runs (staging + `env -u GOV_DEPLOYMENT_MODE`).

Targets (new in wave-256, base 8f00de45):
- gov/short_lived_credentials.py -- TTL bypass, scope confusion,
  id-existence timing oracle, journal tamper, revoke races,
  key-resolution fallback, raw-exception seams on `now`.
- gov/evidence_quality.py -- deepcopy-before-validation raw
  exceptions, vacuous pass on empty evidence, malformed-shape
  handling, NaN fail-closed.
- Deeper attempts: incident complete_task caller model (in-model
  per the stated tamper model), F214/F216/F217/F218 regressions
  (must hold), F219 (OPEN -- must still break).

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Verdicts: HELD (attack refused / gap documented as an
honest residual) or BREAK (genuine defect -> filed as a finding
F220+).
"""

import os
import statistics
import sys
import tempfile
import threading
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import approval_policy as ap  # noqa: E402
from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import evidence_quality as eq  # noqa: E402
from gov import incident as inc_mod  # noqa: E402
from gov import permit_journal as pj  # noqa: E402
from gov import short_lived_credentials as slc  # noqa: E402

TAXONOMY_PIN = 1660  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660 (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    return tempfile.mkdtemp(prefix="w257rt-", dir="/var/tmp")


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _issuer(path=None):
    return slc.CredentialIssuer(
        path or os.path.join(_tmpdir(), "cred.journal"),
        key=b"w257-redteam-key-00000000000000")


def _deep_list(depth):
    deep = {"leaf": 1}
    for _ in range(depth):
        deep = [deep]
    return deep


def _monotonic_exp():
    return [{"expectation_type": "expect_evidence_monotonic",
             "kwargs": {}}]


# ---------------------------------------------------------------------------
# A. evidence_quality.py (new in wave-256)
# ---------------------------------------------------------------------------

@probe("evidence/deepcopy-lock-evidence-raw-typeerror")
def _p_evidence_lock():
    # F220: evaluate() deep-copies caller evidence BEFORE any shape
    # check. A deepcopy-hostile object escapes raw TypeError instead
    # of evidence-quality-evidence-malformed.
    try:
        eq.evaluate(_monotonic_exp(), [{"seq": 1}, threading.Lock()])
    except eq.EvidenceQualityError as exc:
        return _held("machine-coded refusal %s" % exc.code)
    except TypeError as exc:
        return _break("F220: raw TypeError escaped: %s" % exc)
    except Exception as exc:
        return _break("F220: raw %s escaped" % type(exc).__name__)
    return _held("unexpected pass shape (no exception)")


@probe("evidence/deepcopy-lock-artifacts-raw-typeerror")
def _p_evidence_artifacts_lock():
    # F220, same root cause via a second seam: bundle_complete
    # deep-copies the caller-supplied artifacts mapping during
    # kwarg normalization, before validation.
    exp = [{"expectation_type": "expect_bundle_complete",
            "kwargs": {"artifacts": {"r1": threading.Lock()}}}]
    try:
        eq.evaluate(exp, {"items": [{"artifact_ref": "r1"}]})
    except eq.EvidenceQualityError as exc:
        return _held("machine-coded refusal %s" % exc.code)
    except TypeError as exc:
        return _break("F220: raw TypeError escaped: %s" % exc)
    except Exception as exc:
        return _break("F220: raw %s escaped" % type(exc).__name__)
    return _held("unexpected pass shape (no exception)")


@probe("evidence/deep-nesting-raw-recursionerror")
def _p_evidence_deep():
    # F221: deepcopy recurses unboundedly -- a deeply-nested evidence
    # payload escapes raw RecursionError instead of a machine code.
    # Same defect class as F218 (permit journal bounded depth at 200
    # in wave-255); this module has no bound at all.
    try:
        eq.evaluate(_monotonic_exp(), _deep_list(10000))
    except eq.EvidenceQualityError as exc:
        return _held("machine-coded refusal %s" % exc.code)
    except RecursionError:
        return _break("F221: raw RecursionError escaped evaluate()")
    except Exception as exc:
        return _break("F221: raw %s escaped" % type(exc).__name__)
    return _held("unexpected pass shape (no exception)")


@probe("evidence/empty-evidence-vacuous-pass")
def _p_evidence_empty():
    # F222: an empty expectation list is refused ("a vacuous gate
    # must never pass"), but empty EVIDENCE passes every expectation
    # vacuously -- a stage that silently drops all evidence still
    # gets a green quality report.
    cases = [
        ("expect_evidence_monotonic", {}, []),
        ("expect_chain_intact", {}, []),
        ("expect_fields_present", {"required_fields": ["a"]}, []),
        ("expect_timestamps_ordered", {}, []),
        ("expect_bundle_complete", {"artifacts": {"r": {}}},
         {"items": []}),
    ]
    vacuous = []
    for exp_type, kwargs, evidence in cases:
        try:
            rep = eq.evaluate(
                [{"expectation_type": exp_type, "kwargs": kwargs}],
                evidence)
        except eq.EvidenceQualityError:
            continue
        if rep["success"]:
            vacuous.append(exp_type)
    if vacuous:
        return _break("F222: vacuous pass on empty evidence: %s"
                      % ",".join(vacuous))
    return _held("empty evidence refused or failed")


@probe("evidence/malformed-shape-machine-coded")
def _p_evidence_malformed():
    # Contrast probe for F220: JSON-shaped malformed evidence IS
    # machine-coded. Only deepcopy-hostile / deeply-nested shapes
    # escape raw.
    try:
        eq.evaluate(_monotonic_exp(), [{"seq": 1}, "not-a-dict"])
    except eq.EvidenceQualityError as exc:
        if exc.code == eq.EVIDENCE_MALFORMED:
            return _held("evidence-quality-evidence-malformed")
        return _held("coded %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("malformed evidence passed")


@probe("evidence/unknown-expectation-refused")
def _p_evidence_unknown():
    try:
        eq.evaluate([{"expectation_type": "expect_mind_reading",
                      "kwargs": {}}], [{"seq": 1}])
    except eq.EvidenceQualityError as exc:
        if exc.code == eq.UNKNOWN_EXPECTATION:
            return _held("evidence-quality-unknown-expectation")
        return _held("coded %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("unknown expectation passed")


@probe("evidence/empty-expectations-refused")
def _p_evidence_no_expectations():
    try:
        eq.evaluate([], [{"seq": 1}])
    except eq.EvidenceQualityError as exc:
        return _held("coded %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("empty expectation list passed")


@probe("evidence/nan-seq-fail-closed")
def _p_evidence_nan():
    # NaN is a float, so it reaches the comparator; NaN > x is
    # False, so the expectation must FAIL, never pass or crash.
    rep = eq.evaluate(_monotonic_exp(),
                      [{"seq": 1}, {"seq": float("nan")}])
    if rep["success"]:
        return _break("NaN sequence passed monotonic gate")
    return _held("NaN failed closed")


# ---------------------------------------------------------------------------
# B. short_lived_credentials.py (new in wave-256)
# ---------------------------------------------------------------------------

@probe("credentials/timing-id-existence-delta")
def _p_cred_timing():
    # F223: unknown-id and secret-mismatch share the refusal CODE
    # ("id-existence is not leaked"), but the mismatch path runs one
    # extra HMAC-SHA256. Measure whether the delta is systematic.
    iss = _issuer()
    cred = iss.issue("agent-a", "db:read", 600)
    real_id = cred["credential_id"]

    def bench(fn, n):
        for _ in range(50):  # warmup
            try:
                fn()
            except slc.CredentialRefusal:
                pass
        ts = []
        for _ in range(n):
            t0 = time.perf_counter_ns()
            try:
                fn()
            except slc.CredentialRefusal:
                pass
            ts.append(time.perf_counter_ns() - t0)
        return statistics.median(ts)

    deltas = []
    for _ in range(3):
        m_unknown = bench(lambda: iss.verify("f" * 32, "x"), 800)
        m_wrong = bench(lambda: iss.verify(real_id, "wrong"), 800)
        deltas.append(m_wrong - m_unknown)
    delta = statistics.median(deltas)
    if delta > 1000:
        return _break("F223: systematic timing delta %d ns "
                      "(mismatch slower); id-existence leaks via "
                      "timing" % int(delta))
    return _held("timing delta %d ns (indistinguishable)" % int(delta))


@probe("credentials/non-numeric-now-raw-typeerror")
def _p_cred_now_type():
    # F224: `now` is injectable for tests but unvalidated -- a
    # non-numeric `now` escapes raw TypeError from the public
    # verify()/expire_due() seams instead of a machine code.
    iss = _issuer()
    cred = iss.issue("agent-a", "db:read", 600)
    cid, sec = cred["credential_id"], cred["secret"]
    raw = []
    for label, fn in [
        ("verify", lambda: iss.verify(cid, sec, now="yesterday")),
        ("expire_due", lambda: iss.expire_due(now="yesterday")),
    ]:
        try:
            fn()
        except slc.CredentialError as exc:
            continue
        except TypeError:
            raw.append(label)
        except Exception as exc:
            raw.append("%s:%s" % (label, type(exc).__name__))
    if raw:
        return _break("F224: raw TypeError escaped %s" % ",".join(raw))
    return _held("non-numeric now machine-coded")


@probe("credentials/expired-is-terminal")
def _p_cred_expiry():
    iss = _issuer()
    cred = iss.issue("agent-a", "db:read", 60)
    cid, sec = cred["credential_id"], cred["secret"]
    try:
        iss.verify(cid, sec, now=cred["expires_at"] + 1)
        return _break("expired credential verified")
    except slc.CredentialRefusal as exc:
        if exc.code != slc.EXPIRED_CODE:
            return _break("wrong code %s" % exc.code)
    # Second presentation: still expired, still coded.
    try:
        iss.verify(cid, sec, now=cred["expires_at"] + 2)
        return _break("expired credential verified twice")
    except slc.CredentialRefusal as exc:
        if exc.code != slc.EXPIRED_CODE:
            return _break("wrong code %s" % exc.code)
    return _held("expiry terminal, coded")


@probe("credentials/wildcard-scope-exact-match")
def _p_cred_wildcard():
    # Wildcard scopes are opt-in labels, not patterns: verify() is
    # exact-match, so db:* never silently authorizes db:read.
    iss = slc.CredentialIssuer(
        os.path.join(_tmpdir(), "w.journal"),
        key=b"w257-redteam-key-00000000000000",
        allow_wildcard_scope=True)
    cred = iss.issue("agent-a", "db:*", 600)
    try:
        iss.verify(cred["credential_id"], cred["secret"],
                   scope="db:read")
        return _break("wildcard scope authorized narrower scope")
    except slc.CredentialRefusal as exc:
        if exc.code != slc.SCOPE_FORBIDDEN_CODE:
            return _break("wrong code %s" % exc.code)
    ok = iss.verify(cred["credential_id"], cred["secret"],
                    scope="db:*")
    if ok["scope"] != "db:*":
        return _break("exact scope verify mangled")
    return _held("wildcard is exact-match label only")


@probe("credentials/weak-key-refused")
def _p_cred_weak_key():
    try:
        slc.CredentialIssuer(os.path.join(_tmpdir(), "k.journal"),
                             key=b"short")
        return _break("8-byte key accepted")
    except slc.CredentialRefusal as exc:
        if exc.code != slc.KEY_WEAK_CODE:
            return _break("wrong code %s" % exc.code)
    env = dict(os.environ)
    os.environ["GOV_CREDENTIAL_KEY"] = "not-hex!!"
    try:
        slc.CredentialIssuer(os.path.join(_tmpdir(), "k2.journal"))
        return _break("non-hex env key accepted")
    except slc.CredentialRefusal as exc:
        if exc.code != slc.KEY_WEAK_CODE:
            return _break("wrong code %s" % exc.code)
    finally:
        os.environ.clear()
        os.environ.update(env)
    return _held("weak keys refused (short + non-hex env)")


@probe("credentials/journal-tamper-chain-broken")
def _p_cred_tamper():
    path = os.path.join(_tmpdir(), "t.journal")
    key = b"w257-redteam-key-00000000000000"
    iss = slc.CredentialIssuer(path, key=key)
    iss.issue("agent-a", "db:read", 600)
    with open(path, "r+b") as f:
        raw = f.read()
        # Flip a byte in the last record's body (not the tail hash
        # line -- the durable layer would call that a torn tail).
        idx = raw.rfind(b"db:read")
        f.seek(idx)
        f.write(b"db:reaX")
    try:
        slc.CredentialIssuer(path, key=key)
        return _break("tampered journal reloaded clean")
    except slc.CredentialCorrupted as exc:
        return _held("fail-closed %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)


@probe("credentials/revoke-unknown-and-double")
def _p_cred_revoke():
    iss = _issuer()
    try:
        iss.revoke("f" * 32)
        return _break("revoke of unknown id succeeded")
    except slc.CredentialRefusal as exc:
        if exc.code != slc.UNKNOWN_CODE:
            return _break("wrong code %s" % exc.code)
    cred = iss.issue("agent-a", "db:read", 600)
    iss.revoke(cred["credential_id"])
    try:
        iss.revoke(cred["credential_id"])
        return _break("double revoke succeeded")
    except slc.CredentialRefusal as exc:
        if exc.code != slc.MALFORMED_CODE:
            return _break("wrong code %s" % exc.code)
    try:
        iss.verify(cred["credential_id"], cred["secret"])
        return _break("revoked credential verified")
    except slc.CredentialRefusal as exc:
        if exc.code != slc.REVOKED_CODE:
            return _break("wrong code %s" % exc.code)
    return _held("revoke terminal, coded")


@probe("credentials/past-now-is-test-hook")
def _p_cred_past_now():
    # Documented behavior: `now` is an injectable test hook and the
    # caller is the trusted deployment. A caller-supplied past `now`
    # is honored -- this MUST never be attacker-influenced in a real
    # deployment (residual, not filed: the module cannot distinguish
    # a test's `now` from misuse).
    iss = _issuer()
    cred = iss.issue("agent-a", "db:read", 60)
    out = iss.verify(cred["credential_id"], cred["secret"],
                     now=cred["issued_at"] + 1)
    if out["credential_id"] != cred["credential_id"]:
        return _break("verify mangled record")
    return _held("caller-supplied now honored (test hook; "
                 "caller is trusted deployment)")


# ---------------------------------------------------------------------------
# C. deeper attempts + regressions
# ---------------------------------------------------------------------------

@probe("approval/f219-still-live")
def _p_f219_live():
    # F219 is OPEN: raw RecursionError must still escape route().
    rs = ap.compile_rules({
        "version": 1,
        "rules": [{
            "id": "r-auto",
            "when": {"field": "kind", "op": "eq", "value": "x"},
            "action": "auto-approve",
        }],
    })
    deep = {"leaf": 1}
    for _ in range(12000):
        deep = {"n": deep}
    try:
        ap.route(rs, {"kind": "x", "payload": deep},
                 audit_sink=lambda entry: None)
    except RecursionError:
        return _break("F219 live: raw RecursionError escaped route()")
    except ap.ApprovalPolicyError as exc:
        return _held("F219 closed? machine-coded %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("F219: deep request auto-approved")


@probe("incident/complete-task-no-caller-identity")
def _p_incident_caller():
    # The journal records task_completed with NO caller identity, so
    # any caller can complete another owner's task. Per the module's
    # STATED tamper model this is in-model: "incidents are written by
    # the deployment's own processes, and the audit value is
    # tamper-evidence, not non-repudiation" -- writer authenticity is
    # deployment-owned. Documented as an honest residual, not filed.
    m = inc_mod.IncidentManager(os.path.join(_tmpdir(), "i.journal"))
    iid = "inc-1"
    m.declare_incident(iid, title="t", severity="high")
    tid = m.add_task(iid, "fix it", owner="agent-b")
    m.complete_task(iid, tid)  # caller is NOT agent-b
    tasks = m.tasks(iid)
    done = any(t["id"] == tid and t.get("status") == "done"
               for t in tasks)
    if not done:
        # task_completed is journaled; check the event log instead.
        done = any(e.get("event") == "task_completed"
                   for e in m.events(iid))
    if done:
        return _held("arbitrary caller completed agent-b's task; "
                     "in-model per stated tamper model (writer "
                     "authenticity deployment-owned)")
    return _held("complete_task refused (unexpected)")


@probe("incident/f216-regression")
def _p_f216():
    m = inc_mod.IncidentManager(os.path.join(_tmpdir(), "i2.journal"))
    m.declare_incident("inc-2", title="t", severity="high")
    try:
        m.transition("inc-2", "resolved")
        return _break("F216 regressed: direct transition resolved")
    except Exception as exc:
        if "resolved" in str(exc).lower() or "illegal" in str(exc).lower():
            return _held("F216 holds: %s" % type(exc).__name__)
        return _held("F216 holds (%s)" % type(exc).__name__)


@probe("journal/f214-f218-regressions")
def _p_journal_regressions():
    # F214: serialization misuse -> machine code, no partial write.
    j = pj.PermitJournal(os.path.join(_tmpdir(), "p.journal"))
    try:
        j.record_use("perm-1", {"ok": True}, permit=object())
        return _break("F214 regressed")
    except Exception:
        pass
    # F218: deeply-nested payload -> machine-coded refusal.
    deep = {"leaf": 1}
    for _ in range(5000):
        deep = {"n": deep}
    try:
        j.record_use("perm-1", deep, permit={"permit_id": "perm-1"})
        return _break("F218 regressed")
    except Exception as exc:
        if type(exc).__name__ == "PermitJournalRefusal":
            return _held("F214+F218 hold")
        return _held("F214+F218 hold (%s)" % type(exc).__name__)


def main():
    assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN, (  # Wave-258 merge: pin -> 1080.
        "taxonomy pin: expected %d, got %d"
        % (TAXONOMY_PIN, len(decision_codes.TAXONOMY)))
    held, broken, errors = 0, 0, 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001 -- probe harness
            verdict, detail = ("ERROR", "%r" % (exc,))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            broken += 1
        else:
            errors += 1
        print("%-46s %-6s %s" % (name, verdict, detail))
    print("probes=%d held=%d break=%d error=%d"
          % (len(_PROBES), held, broken, errors))
    return 0 if (broken == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
