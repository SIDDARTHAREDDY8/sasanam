"""Wave-297 lane 1 red-first battery: approval-request schema.

Builds gov/approval_request.py (GerritCodeReview/gerrit STEAL +
spinnaker manualJudgment STEAL, Apache-2.0, mechanism only, stdlib
only; standing design rule: "An approval is a signed, time-boxed,
quorum-counted vote on a digest -- never a button, never a silence,
never a snapshot").

An ApprovalRequest is a bounded, frozen, signed declaration of WHAT
the human is being asked to approve: action digest (digest-bound,
never a snapshot reference), requesting agent identity, full context
digests, an expiry (silence refuses), a typed approver-data schema,
and the requester's signature. issue() validates shape and freezes;
verify_request checks signature, expiry at every use (pre-decay
fail-closed), and digest-binding completeness. Coded refusals:
approval-request-expired / -invalid / -digest-missing / -forgery.

Base: wave-296 merge 5fd40f0 (verified via git rev-parse HEAD before
work). Pristine base: 15+ BREAK (feature absent).

Pin 1757 -> 1757 (+4 approval-request-*); the repoint is tree-wide
(value-token-only, code/comment splitter, history comments extended),
so adjacent batteries' own pin probes stay green.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g297-ar && TMPDIR=/var/tmp/g297-ar \
    ~/workspace/.gov-venv/bin/python evals/w297_approval_request_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g297-arb \
    ~/workspace/.gov-venv/bin/python evals/w297_approval_request_probes.py
"""

import os
import subprocess
import sys
import time

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-297 lane 1: pin 1757 -> 1757 (+4 approval-request-digest-missing,
# approval-request-expired, approval-request-forgery,
# approval-request-invalid).
TAXONOMY_PIN = 2018 # Wave-296 merge: pin 1757 (lane-local repoint base); Wave-297 merge: pin 1812 (+16 codes, approval-request-expired shared); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded)



try:
    from gov import approval_request as AR
    from gov import decision_codes
    from gov import ed25519 as _ed
except ImportError:
    AR = None
    decision_codes = None
    _ed = None


class _Break(Exception):
    """A probe that fails because the feature is absent or wrong."""


def _need():
    if AR is None or decision_codes is None or _ed is None:
        raise _Break("gov.approval_request absent on this tree")


_SEED = bytes(range(32))
_SEED2 = bytes([255 - b for b in range(32)])
_NOW = 1798765432  # fixed synthetic clock; never wall-clock in probes


def _issue(**kw):
    _need()
    base = {
        "action_digest": "ab" * 32,
        "requester_agent_id": "agent-a",
        "requester_principal": "principal-a",
        "requester_pubkey_hex": _ed.publickey(_SEED).hex(),
        "context_digests": {"inputs": "cd" * 32, "policy": "ef" * 32},
        "approver_schema": [
            {"name": "blast_radius", "type": "enum",
             "values": ["canary-5pct", "full"], "required": True},
            {"name": "note", "type": "string", "required": False},
        ],
        "ttl_seconds": 3600,
        "issued_at": _NOW,
        "requester_seed": _SEED,
    }
    base.update(kw)
    return AR.issue(**base)


def _refused(fn, code):
    try:
        fn()
    except Exception as e:  # noqa: BLE001 -- assert coded refusal
        got = getattr(e, "code", None)
        if got != code:
            raise _Break("expected code %r, got %r (%s)"
                         % (code, got, e))
        return
    raise _Break("expected coded refusal %r, nothing raised" % (code,))


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def p_module_present():
    _need()
    for fn in ("issue", "verify_request", "matches_action", "is_expired",
               "validate_approver_data", "action_digest_for",
               "ApprovalRequestError"):
        if not hasattr(AR, fn):
            raise _Break("missing public API: %s" % fn)


def p_pin_count():
    _need()
    n = len(decision_codes.TAXONOMY)
    if n != TAXONOMY_PIN:
        raise _Break("taxonomy %d != pin %d" % (n, TAXONOMY_PIN))


def p_pin_raw_literals():
    _need()
    import re
    src = open(os.path.join(REPO, "gov", "decision_codes.py")).read()
    codes = re.findall(r'''"code": '([^']+)'|"code": "([^"]+)"''', src)
    codes = [a or b for a, b in codes]
    if len(codes) != len(set(codes)):
        raise _Break("duplicate raw code literals")
    if codes != sorted(codes):
        raise _Break("raw code literals not sorted")
    if len(codes) != TAXONOMY_PIN:
        raise _Break("raw literals %d != pin %d" % (len(codes),
                                                    TAXONOMY_PIN))


def p_issue_freeze_roundtrip():
    env = _issue()
    body = AR.verify_request(env, now=_NOW)
    if body["action_digest"] != "ab" * 32:
        raise _Break("roundtrip lost the action digest")
    if body["schema"] != "approval-request/v1":
        raise _Break("roundtrip lost the schema marker")


def p_post_freeze_mutation_is_forgery():
    env = _issue()
    env["request"]["context_digests"]["inputs"] = "00" * 32
    _refused(lambda: AR.verify_request(env, now=_NOW),
             "approval-request-forgery")


def p_expired_request_refuses():
    env = _issue(ttl_seconds=100, issued_at=_NOW)
    _refused(lambda: AR.verify_request(env, now=_NOW + 101),
             "approval-request-expired")


def p_silence_is_not_consent():
    # A request verified far past expiry refuses even with a valid
    # signature: silence refuses, never consents.
    env = _issue(ttl_seconds=60, issued_at=_NOW)
    ok = AR.verify_request(env, now=_NOW + 59)
    if not ok:
        raise _Break("valid request refused inside its window")
    _refused(lambda: AR.verify_request(env, now=_NOW + 10 ** 6),
             "approval-request-expired")


def p_forged_signature():
    env = _issue()
    # Re-sign the same body with a DIFFERENT key: the requester's
    # pubkey no longer matches the signature.
    body = env["request"]
    env2 = {"request": body,
            "signature": _ed.sign(_SEED2, AR._canonical(body)).hex()}
    _refused(lambda: AR.verify_request(env2, now=_NOW),
             "approval-request-forgery")


def p_digest_missing_empty_context():
    _refused(lambda: _issue(context_digests={}),
             "approval-request-digest-missing")


def p_digest_missing_bad_action_digest():
    _refused(lambda: _issue(action_digest="not-a-digest"),
             "approval-request-digest-missing")


def p_invalid_shape_envelope():
    _refused(lambda: AR.verify_request({"nope": 1}, now=_NOW),
             "approval-request-invalid")
    _refused(lambda: AR.verify_request(None, now=_NOW),
             "approval-request-invalid")


def p_invalid_shape_circular():
    circ = {}
    circ["self"] = circ
    _refused(lambda: _issue(context_digests={"loop": circ}),
             "approval-request-invalid")


def p_replan_resets_binding():
    # Gerrit version-reset: the request binds digest D; a re-planned
    # action with digest D' must NOT verify against it.
    env = _issue(action_digest="ab" * 32)
    _refused(lambda: AR.verify_request(env, expected_action_digest="ff" * 32,
                                       now=_NOW),
             "approval-request-digest-missing")
    # Flip: byte-identical re-submission of D still verifies.
    body = AR.verify_request(env, expected_action_digest="ab" * 32,
                             now=_NOW)
    if body["action_digest"] != "ab" * 32:
        raise _Break("identical digest re-submission refused")


def p_requester_pubkey_pin():
    env = _issue()
    other = _ed.publickey(_SEED2).hex()
    _refused(lambda: AR.verify_request(
        env, expected_requester_pubkey_hex=other, now=_NOW),
        "approval-request-forgery")
    body = AR.verify_request(
        env, expected_requester_pubkey_hex=_ed.publickey(_SEED).hex(),
        now=_NOW)
    if not body:
        raise _Break("pinned requester pubkey refused a valid request")


def p_future_issued_at_invalid():
    env = _issue(issued_at=_NOW + 3600)
    _refused(lambda: AR.verify_request(env, now=_NOW),
             "approval-request-invalid")


def p_matches_action_and_expiry_helpers():
    # matches_action uses the wall clock: issue against the real now.
    base = int(time.time())
    env = _issue(action_digest="ab" * 32, ttl_seconds=3600,
                 issued_at=base)
    if not AR.matches_action(env, "ab" * 32):
        raise _Break("matches_action false on identical digest")
    if AR.matches_action(env, "ff" * 32):
        raise _Break("matches_action true on different digest")
    if AR.is_expired(env, now=base + 50):
        raise _Break("is_expired true inside the window")
    if not AR.is_expired(env, now=base + 3601):
        raise _Break("is_expired false past the window")


def p_approver_schema_validation():
    schema = [
        {"name": "blast_radius", "type": "enum",
         "values": ["canary-5pct", "full"], "required": True},
        {"name": "note", "type": "string", "required": False},
        {"name": "retries", "type": "integer", "required": False},
    ]
    ok = AR.validate_approver_data(
        schema, {"blast_radius": "canary-5pct", "retries": 2})
    if ok["blast_radius"] != "canary-5pct":
        raise _Break("valid approver data refused")
    _refused(lambda: AR.validate_approver_data(
        schema, {"blast_radius": "planet"}), "approval-request-invalid")
    _refused(lambda: AR.validate_approver_data(
        schema, {}), "approval-request-invalid")  # required missing
    _refused(lambda: AR.validate_approver_data(
        schema, {"blast_radius": "full", "sneaky": 1}),
        "approval-request-invalid")  # unknown field


def p_queue_composition_stamps_and_decide_refuses():
    _need()
    import copy
    import shutil
    import tempfile
    from gov import approvals as AP
    from gov.identity import AgentIdentity
    from gov.log import ActionLog
    import tests.keyfixture as keyfixture
    keyfixture.provision_test_key()
    tmp = tempfile.mkdtemp(prefix="w297q")
    try:
        run_dir = os.path.join(tmp, "run")
        os.makedirs(run_dir)
        log = ActionLog(os.path.join(run_dir, "actions.jsonl"))
        q = AP.ApprovalQueue(run_dir, log)
        # F42: queue() requires the executor-installed identity
        # verifier; the test installs the minted-identity check the
        # executor would install.
        q.set_identity_verifier(
            lambda ident: isinstance(ident, AgentIdentity))
        ident = AgentIdentity(agent_id="agent-a", role="worker",
                              run_id=q.run_id, principal="principal-a")
        action = {"tool": "shell", "args": {"cmd": "ls"},
                  "redactions": []}
        decision = type("D", (), {"policy_id": "p", "reason": "r"})()
        wall = int(time.time())
        env = _issue(
            action_digest=AR.action_digest_for(action),
            requester_agent_id="agent-a",
            requester_principal="principal-a",
            issued_at=wall, ttl_seconds=3600)
        rec_id = q.queue(action, decision,
                         caller_identity=ident,
                         approval_request=env)
        rec = q.get(rec_id)
        if rec.get("approval_request") != env:
            raise _Break("approval request not stamped on the queue record")
        # Decide inside the window: succeeds (no coded refusal).
        q.decide(rec_id, True, "ok", decided_by="human-1")
        # A dead-on-arrival request (already expired) is refused at
        # queue time: silence refuses before the queue, too.
        old = copy.deepcopy(env["request"])
        old["issued_at"] = wall - 7200
        old["ttl_seconds"] = 60
        env2 = {"request": old,
                "signature": _ed.sign(
                    _SEED, AR._canonical(old)).hex()}
        _refused(lambda: q.queue(action, decision,
                                 caller_identity=ident,
                                 approval_request=env2),
                 "approval-request-expired")
        # The Spinnaker timeout case: valid at queue time, expired
        # while pending. The decision must refuse coded.
        env3 = _issue(
            action_digest=AR.action_digest_for(action),
            requester_agent_id="agent-a",
            requester_principal="principal-a",
            issued_at=wall, ttl_seconds=3600)
        rec_id3 = q.queue(action, decision,
                          caller_identity=ident,
                          approval_request=env3)
        from unittest import mock
        with mock.patch("time.time", return_value=wall + 3700):
            _refused(lambda: q.decide(rec_id3, True, "ok",
                                      decided_by="human-1"),
                     "approval-request-expired")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


PROBES = [
    ("module_present", p_module_present),
    ("pin_count", p_pin_count),
    ("pin_raw_literals", p_pin_raw_literals),
    ("issue_freeze_roundtrip", p_issue_freeze_roundtrip),
    ("post_freeze_mutation_is_forgery", p_post_freeze_mutation_is_forgery),
    ("expired_request_refuses", p_expired_request_refuses),
    ("silence_is_not_consent", p_silence_is_not_consent),
    ("forged_signature", p_forged_signature),
    ("digest_missing_empty_context", p_digest_missing_empty_context),
    ("digest_missing_bad_action_digest", p_digest_missing_bad_action_digest),
    ("invalid_shape_envelope", p_invalid_shape_envelope),
    ("invalid_shape_circular", p_invalid_shape_circular),
    ("replan_resets_binding", p_replan_resets_binding),
    ("requester_pubkey_pin", p_requester_pubkey_pin),
    ("future_issued_at_invalid", p_future_issued_at_invalid),
    ("matches_action_and_expiry_helpers", p_matches_action_and_expiry_helpers),
    ("approver_schema_validation", p_approver_schema_validation),
    ("queue_composition_stamps_and_decide_refuses",
     p_queue_composition_stamps_and_decide_refuses),
]


def _green_check(battery):
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    # Wave-134/173: fresh unique TMPDIR per suite run, mkdir -p first.
    tmp = "/var/tmp/g297-green-%s" % os.getpid()
    os.makedirs(tmp, exist_ok=True)
    env["TMPDIR"] = tmp
    path = os.path.join(REPO, "evals", battery)
    try:
        out = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            env=env, timeout=600)
    except Exception as e:  # noqa: BLE001 -- green check harness
        return ("ERROR", "%s" % (e,))
    summary = (out.stdout.strip().splitlines() or ["no output"])[0]
    if "0 BREAK" in out.stdout and "0 ERROR" in out.stdout:
        return ("HELD", summary)
    return ("BREAK", summary)


def main():
    brk = held = err = 0
    failures = []
    for name, fn in PROBES:
        try:
            fn()
        except _Break as e:
            brk += 1
            failures.append((name, "BREAK: %s" % (e,)))
        except AssertionError as e:
            brk += 1
            failures.append((name, "BREAK(assert): %s" % (e,)))
        except Exception as e:  # noqa: BLE001 -- probe harness
            err += 1
            failures.append((name, "ERROR: %r" % (e,)))
        else:
            held += 1
    print("w297_approval_request: %d BREAK / %d HELD / %d ERROR "
          "over %d probes" % (brk, held, err, len(PROBES)))
    for name, why in failures:
        print("  %s -> %s" % (name, why))
    if not SKIP_GREEN:
        for battery in ("w296_decision_trace_probes.py",
                        "w294_filter_pipeline_probes.py"):
            status, summary = _green_check(battery)
            print("green-check %-32s %s: %s" % (battery, status, summary))
    if brk or err:
        sys.exit(1)


if __name__ == "__main__":
    main()
