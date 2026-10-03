#!/usr/bin/env python3
"""Wave-217 lane A: step-scoped quorum break-first battery.

Seam under test: ``gov.quorum_policy`` — step-scoped quorum
{step_name, authorized_keyids[], threshold} over independently-signed
AGREEING link records. Admission requires a THRESHOLD of records that
AGREE on the asserted statement digest (not merely threshold
signatures anywhere), and the expected_command field is DIAGNOSTIC
ONLY (a compromised functionary can forge it, so command equality is
never an enforcement control).

Verdicts: HELD / BREAK / ERROR (GAP mapped to BREAK per D1, wave-315;
the "GAP:" note prefix preserves the gap-demonstrated evidence). Any
BREAK = genuine break of the quorum discipline (file as F209+).
Exit 1 on any BREAK/ERROR.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g217a
  TMPDIR=/var/tmp/g217a ~/workspace/.gov-venv/bin/python evals/w217_quorum_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g217a-u \
      ~/workspace/.gov-venv/bin/python evals/w217_quorum_probes.py
"""

import hashlib
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/var/tmp/g217a-%d" % os.getpid())

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import quorum_policy as qp  # noqa: E402
    from gov.signing import (  # noqa: E402
        Ed25519Signer, Ed25519Verifier)
    _ABSENT = False
except ImportError as _exc:  # noqa: E402
    qp = None
    _ABSENT = True
    _IMPORT_ERROR = _exc

_RESULTS = []
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        _PROBE_FNS[name] = fn
        return fn
    return deco


def _record(name, verdict, detail):
    _RESULTS.append((name, verdict, detail))


_SEEDS = {
    "A": bytes.fromhex("a1" * 32),
    "B": bytes.fromhex("b2" * 32),
    "C": bytes.fromhex("c3" * 32),
    "D": bytes.fromhex("d4" * 32),  # attacker / unauthorized
}

_DIGEST_X = hashlib.sha256(b"fact-X").hexdigest()
_DIGEST_Y = hashlib.sha256(b"fact-Y").hexdigest()


def _signers():
    return {k: Ed25519Signer(s) for k, s in _SEEDS.items()}


def _keyset(signers, *names):
    return {signers[n].key_id: Ed25519Verifier(signers[n].public_key)
            for n in names}


def _require_module(name):
    if _ABSENT:
        # D1 (wave-315): GAP maps to BREAK; the "GAP:" prefix keeps the
        # gap-demonstrated evidence in the note.
        _record(name, "BREAK", "GAP: module absent (%s)" % _IMPORT_ERROR)
        return None
    return True


@_probe("honest-quorum")
def p_honest_quorum():
    name = "honest-quorum"
    if not _require_module(name):
        return
    signers = _signers()
    step = qp.load_quorum_step({
        "step_name": "build",
        "authorized_keyids": [signers["A"].key_id,
                              signers["B"].key_id,
                              signers["C"].key_id],
        "threshold": 2,
    })
    links = [qp.make_link_record("build", _DIGEST_X, signers[n],
                                 expected_command="make all")
             for n in ("A", "B")]
    report = qp.verify_quorum(step, links,
                              _keyset(signers, "A", "B", "C"))
    if (report["statement_digest"] == _DIGEST_X
            and sorted(report["signer_keyids"])
            == sorted([signers["A"].key_id, signers["B"].key_id])):
        _record(name, "HELD", "2-of-3 agreeing quorum admitted")
    else:
        _record(name, "BREAK", "honest quorum refused: %r" % report)


@_probe("quorum-met-but-disagree")
def p_quorum_met_but_disagree():
    name = "quorum-met-but-disagree"
    if not _require_module(name):
        return
    signers = _signers()
    step = qp.load_quorum_step({
        "step_name": "build",
        "authorized_keyids": [signers["A"].key_id,
                              signers["B"].key_id,
                              signers["C"].key_id],
        "threshold": 3,
    })
    # 3 valid signatures (naive quorum "met") but no agreeing group
    # reaches threshold: A->X, C->X, B->Y.
    links = [
        qp.make_link_record("build", _DIGEST_X, signers["A"]),
        qp.make_link_record("build", _DIGEST_Y, signers["B"]),
        qp.make_link_record("build", _DIGEST_X, signers["C"]),
    ]
    try:
        report = qp.verify_quorum(step, links,
                                  _keyset(signers, "A", "B", "C"))
    except qp.QuorumPolicyError as exc:
        _record(name, "HELD", "refused: %s" % exc)
    else:
        _record(name, "BREAK", "disagreeing quorum admitted: %r" % report)


@_probe("threshold-1-short")
def p_threshold_1_short():
    name = "threshold-1-short"
    if not _require_module(name):
        return
    signers = _signers()
    step = qp.load_quorum_step({
        "step_name": "build",
        "authorized_keyids": [signers["A"].key_id, signers["B"].key_id],
        "threshold": 2,
    })
    links = [qp.make_link_record("build", _DIGEST_X, signers["A"])]
    try:
        report = qp.verify_quorum(step, links,
                                  _keyset(signers, "A", "B"))
    except qp.QuorumPolicyError as exc:
        _record(name, "HELD", "refused: %s" % exc)
    else:
        _record(name, "BREAK", "1-of-2 quorum admitted: %r" % report)


@_probe("unauthorized-functionary")
def p_unauthorized_functionary():
    name = "unauthorized-functionary"
    if not _require_module(name):
        return
    signers = _signers()
    step = qp.load_quorum_step({
        "step_name": "build",
        "authorized_keyids": [signers["A"].key_id, signers["B"].key_id],
        "threshold": 2,
    })
    # Attacker D signs with a valid signature; keyset carries D's
    # verifier (compromised-verifier posture) but D is NOT authorized
    # for the step.
    links = [
        qp.make_link_record("build", _DIGEST_X, signers["A"]),
        qp.make_link_record("build", _DIGEST_X, signers["D"]),
    ]
    try:
        report = qp.verify_quorum(step, links,
                                  _keyset(signers, "A", "B", "D"))
    except qp.QuorumPolicyError as exc:
        _record(name, "HELD", "refused: %s" % exc)
    else:
        _record(name, "BREAK",
                "unauthorized functionary counted: %r" % report)


@_probe("authorized-but-unpinned")
def p_authorized_but_unpinned():
    name = "authorized-but-unpinned"
    if not _require_module(name):
        return
    signers = _signers()
    step = qp.load_quorum_step({
        "step_name": "build",
        "authorized_keyids": [signers["A"].key_id, signers["B"].key_id],
        "threshold": 1,
    })
    links = [qp.make_link_record("build", _DIGEST_X, signers["B"])]
    # B is authorized but the deployment keyset pins only A.
    try:
        report = qp.verify_quorum(step, links, _keyset(signers, "A"))
    except qp.QuorumPolicyError as exc:
        _record(name, "HELD", "refused: %s" % exc)
    else:
        _record(name, "BREAK",
                "unpinned authorized keyid admitted: %r" % report)


@_probe("mixed-keyid-replay")
def p_mixed_keyid_replay():
    name = "mixed-keyid-replay"
    if not _require_module(name):
        return
    signers = _signers()
    step = qp.load_quorum_step({
        "step_name": "build",
        "authorized_keyids": [signers["A"].key_id],
        "threshold": 1,
    })
    # Record claims signer_keyid=A but the signature was made by B.
    body = qp.canonical_link_body("build", _DIGEST_X, "make all",
                                  signers["A"].key_id)
    bad = {
        "step_name": "build",
        "statement_digest": _DIGEST_X,
        "expected_command": "make all",
        "signer_keyid": signers["A"].key_id,
        "signature": signers["B"].sign(body).hex(),
    }
    try:
        report = qp.verify_quorum(step, [bad],
                                  _keyset(signers, "A", "B"))
    except qp.QuorumPolicyError as exc:
        _record(name, "HELD", "refused: %s" % exc)
    else:
        _record(name, "BREAK", "mixed-keyid replay admitted: %r" % report)


@_probe("keyid-label-lie")
def p_keyid_label_lie():
    name = "keyid-label-lie"
    if not _require_module(name):
        return
    signers = _signers()
    step = qp.load_quorum_step({
        "step_name": "build",
        "authorized_keyids": [signers["A"].key_id, signers["B"].key_id],
        "threshold": 1,
    })
    # Attacker builds a body naming B (authorized, pinned) but signs
    # with D's (unauthorized) key, then stamps signer_keyid=B.
    body = qp.canonical_link_body("build", _DIGEST_X, "make all",
                                  signers["B"].key_id)
    lie = {
        "step_name": "build",
        "statement_digest": _DIGEST_X,
        "expected_command": "make all",
        "signer_keyid": signers["B"].key_id,
        "signature": signers["D"].sign(body).hex(),
    }
    try:
        report = qp.verify_quorum(step, [lie],
                                  _keyset(signers, "A", "B", "D"))
    except qp.QuorumPolicyError as exc:
        _record(name, "HELD", "refused: %s" % exc)
    else:
        _record(name, "BREAK", "keyid label lie admitted: %r" % report)


@_probe("functionary-equivocation")
def p_functionary_equivocation():
    name = "functionary-equivocation"
    if not _require_module(name):
        return
    signers = _signers()
    step = qp.load_quorum_step({
        "step_name": "build",
        "authorized_keyids": [signers["A"].key_id, signers["B"].key_id],
        "threshold": 1,
    })
    # A validly signs two different facts: double-voting.
    links = [
        qp.make_link_record("build", _DIGEST_X, signers["A"]),
        qp.make_link_record("build", _DIGEST_Y, signers["A"]),
    ]
    try:
        report = qp.verify_quorum(step, links,
                                  _keyset(signers, "A", "B"))
    except qp.QuorumPolicyError as exc:
        _record(name, "HELD", "refused: %s" % exc)
    else:
        _record(name, "BREAK",
                "equivocating functionary admitted: %r" % report)


@_probe("quorum-ambiguous")
def p_quorum_ambiguous():
    name = "quorum-ambiguous"
    if not _require_module(name):
        return
    signers = _signers()
    step = qp.load_quorum_step({
        "step_name": "build",
        "authorized_keyids": [signers["A"].key_id, signers["B"].key_id],
        "threshold": 1,
    })
    # Two threshold-reaching groups on DIFFERENT facts: genuinely
    # ambiguous, must fail closed rather than pick one.
    links = [
        qp.make_link_record("build", _DIGEST_X, signers["A"]),
        qp.make_link_record("build", _DIGEST_Y, signers["B"]),
    ]
    try:
        report = qp.verify_quorum(step, links,
                                  _keyset(signers, "A", "B"))
    except qp.QuorumPolicyError as exc:
        _record(name, "HELD", "refused: %s" % exc)
    else:
        _record(name, "BREAK", "ambiguous quorum admitted: %r" % report)


@_probe("command-diagnostic-only")
def p_command_diagnostic_only():
    name = "command-diagnostic-only"
    if not _require_module(name):
        return
    signers = _signers()
    step = qp.load_quorum_step({
        "step_name": "build",
        "authorized_keyids": [signers["A"].key_id, signers["B"].key_id],
        "threshold": 2,
    })
    # Same fact, DIFFERENT claimed commands: the quorum must still
    # pass (commands are diagnostic), with command_agreement=False in
    # the report. Denying here would make command equality an
    # enforcement control, which it must never be.
    links = [
        qp.make_link_record("build", _DIGEST_X, signers["A"],
                            expected_command="make all"),
        qp.make_link_record("build", _DIGEST_X, signers["B"],
                            expected_command="make install"),
    ]
    try:
        report = qp.verify_quorum(step, links,
                                  _keyset(signers, "A", "B"))
    except qp.QuorumPolicyError as exc:
        _record(name, "BREAK",
                "command mismatch wrongly enforced: %s" % exc)
    else:
        if (report["statement_digest"] == _DIGEST_X
                and report.get("command_agreement") is False):
            _record(name, "HELD",
                    "passed with command_agreement=False (diagnostic)")
        else:
            _record(name, "BREAK",
                    "unexpected report shape: %r" % report)


@_probe("command-match-not-enforcement")
def p_command_match_not_enforcement():
    name = "command-match-not-enforcement"
    if not _require_module(name):
        return
    signers = _signers()
    step = qp.load_quorum_step({
        "step_name": "build",
        "authorized_keyids": [signers["A"].key_id, signers["B"].key_id],
        "threshold": 2,
    })
    # IDENTICAL claimed commands but different facts: command match
    # must NOT admit anything.
    links = [
        qp.make_link_record("build", _DIGEST_X, signers["A"],
                            expected_command="make all"),
        qp.make_link_record("build", _DIGEST_Y, signers["B"],
                            expected_command="make all"),
    ]
    try:
        report = qp.verify_quorum(step, links,
                                  _keyset(signers, "A", "B"))
    except qp.QuorumPolicyError as exc:
        _record(name, "HELD", "refused: %s" % exc)
    else:
        _record(name, "BREAK",
                "command-match admitted disagreement: %r" % report)


@_probe("malformed-record")
def p_malformed_record():
    name = "malformed-record"
    if not _require_module(name):
        return
    signers = _signers()
    step = qp.load_quorum_step({
        "step_name": "build",
        "authorized_keyids": [signers["A"].key_id],
        "threshold": 1,
    })
    bad = {"step_name": "build", "signer_keyid": signers["A"].key_id}
    try:
        report = qp.verify_quorum(step, [bad], _keyset(signers, "A"))
    except (qp.QuorumPolicyError, ValueError) as exc:
        _record(name, "HELD", "refused: %s" % exc)
    else:
        _record(name, "BREAK",
                "malformed record admitted: %r" % report)


@_probe("bad-digest-hex")
def p_bad_digest_hex():
    name = "bad-digest-hex"
    if not _require_module(name):
        return
    signers = _signers()
    step = qp.load_quorum_step({
        "step_name": "build",
        "authorized_keyids": [signers["A"].key_id],
        "threshold": 1,
    })
    body = qp.canonical_link_body("build", _DIGEST_X, "make all",
                                  signers["A"].key_id)
    bad = {
        "step_name": "build",
        "statement_digest": "not-a-digest",
        "expected_command": "make all",
        "signer_keyid": signers["A"].key_id,
        "signature": signers["A"].sign(body).hex(),
    }
    try:
        report = qp.verify_quorum(step, [bad], _keyset(signers, "A"))
    except (qp.QuorumPolicyError, ValueError) as exc:
        _record(name, "HELD", "refused: %s" % exc)
    else:
        _record(name, "BREAK",
                "non-hex digest admitted: %r" % report)


@_probe("load-step-validation")
def p_load_step_validation():
    name = "load-step-validation"
    if not _require_module(name):
        return
    kid = "kid-1"
    bads = [
        {"step_name": "s", "authorized_keyids": [kid], "threshold": 0},
        {"step_name": "s", "authorized_keyids": [kid], "threshold": 2},
        {"step_name": "s", "authorized_keyids": [], "threshold": 1},
        {"step_name": "", "authorized_keyids": [kid], "threshold": 1},
        {"step_name": "s", "authorized_keyids": [kid, kid],
         "threshold": 1},
        {"step_name": "s", "authorized_keyids": [kid], "threshold": 1,
         "bogus_key": True},
        "not-a-dict",
    ]
    refused = 0
    for spec in bads:
        try:
            qp.load_quorum_step(spec)
        except (qp.QuorumPolicyError, ValueError, TypeError):
            refused += 1
    if refused == len(bads):
        _record(name, "HELD", "%d/%d malformed specs refused" % (
            refused, len(bads)))
    else:
        _record(name, "BREAK", "only %d/%d refused" % (refused,
                                                      len(bads)))


@_probe("duplicate-record-single-vote")
def p_duplicate_record_single_vote():
    name = "duplicate-record-single-vote"
    if not _require_module(name):
        return
    signers = _signers()
    step = qp.load_quorum_step({
        "step_name": "build",
        "authorized_keyids": [signers["A"].key_id, signers["B"].key_id],
        "threshold": 2,
    })
    # Same functionary's record twice must not count twice.
    links = [
        qp.make_link_record("build", _DIGEST_X, signers["A"]),
        qp.make_link_record("build", _DIGEST_X, signers["A"]),
    ]
    try:
        report = qp.verify_quorum(step, links,
                                  _keyset(signers, "A", "B"))
    except qp.QuorumPolicyError as exc:
        _record(name, "HELD", "refused: %s" % exc)
    else:
        _record(name, "BREAK",
                "duplicate counted twice: %r" % report)


@_probe("promote-wiring")
def p_promote_wiring():
    name = "promote-wiring"
    if not _require_module(name):
        return
    from gov import sign_deploy_namespaces as sdn  # noqa: E402
    signers = _signers()
    verifiers = [Ed25519Verifier(s.public_key) for s in
                 (signers["A"], signers["B"])]
    reg = sdn.NamespaceRegistry(verifiers=verifiers, threshold=1)
    reg.stage("skill/q", b"bytes")
    reg.sign("skill/q", [signers["A"]])
    step = qp.load_quorum_step({
        "step_name": "promote",
        "authorized_keyids": [s.key_id for s in
                              (signers["A"], signers["B"])],
        "threshold": 2,
    })
    honest = [qp.make_link_record("promote", _DIGEST_X, signers[n])
              for n in ("A", "B")]
    ok = True
    # (a) configured policy + absent links must fail closed
    try:
        reg.promote("skill/q", operator_ids=["op1", "op2"],
                    quorum_policy=step)
        ok = False
    except sdn.NamespaceError as exc:
        if exc.code != "quorum-gate-refused":
            ok = False
    # (b) honest quorum links must admit
    try:
        reg.promote("skill/q", operator_ids=["op1", "op2"],
                    quorum_policy=step, quorum_links=honest)
    except sdn.NamespaceError:
        ok = False
    # (c) disagreeing links must deny
    reg2 = sdn.NamespaceRegistry(verifiers=verifiers, threshold=1)
    reg2.stage("skill/q2", b"bytes2")
    reg2.sign("skill/q2", [signers["A"]])
    bad_links = [
        qp.make_link_record("promote", _DIGEST_X, signers["A"]),
        qp.make_link_record("promote", _DIGEST_Y, signers["B"]),
    ]
    denied = False
    try:
        reg2.promote("skill/q2", operator_ids=["op1", "op2"],
                     quorum_policy=step, quorum_links=bad_links)
    except sdn.NamespaceError as exc:
        denied = exc.code == "quorum-gate-refused"
    ok = ok and denied
    _record(name, "HELD" if ok else "BREAK",
            "absent=fail-closed, honest=admit, disagree=deny" if ok
            else "promote wiring misbehaved")


def _green_check():
    if GREEN_SKIP:
        _record("green-check", "HELD", "skipped (GOV_SKIP_GREEN=1)")
        return
    if _ABSENT:
        # D1 (wave-315): GAP maps to BREAK; the "GAP:" prefix keeps the
        # gap-demonstrated evidence in the note.
        _record("green-check", "BREAK", "GAP: module absent; nothing to check")
        return
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = "/var/tmp/g217a-green-%d" % os.getpid()
    import subprocess  # noqa: E402
    os.makedirs(env["TMPDIR"], exist_ok=True)
    suites = ["tests.test_sign_deploy_namespaces", "tests.test_quorum_policy"]
    ok = True
    for suite in suites:
        path = os.path.join(REPO, suite.replace(".", "/") + ".py")
        if not os.path.exists(path):
            _record("green-check", "HELD",
                    "%s absent (not yet merged)" % suite)
            continue
        try:
            proc = subprocess.run([sys.executable, "-m", "unittest", suite],
                                  cwd=REPO, env=env, capture_output=True,
                                  text=True, timeout=600)
            if proc.returncode != 0:
                ok = False
                _record("green-check", "ERROR",
                        "%s -> rc=%d" % (suite, proc.returncode))
        except Exception as exc:  # noqa: BLE001
            ok = False
            _record("green-check", "ERROR", "%s -> %s" % (suite, exc))
    if ok:
        _record("green-check", "HELD", "adjacent suites green")


def main():
    print("Wave-217 quorum break-first battery: step-scoped quorum "
          "over agreeing link records")
    for name in sorted(_PROBE_FNS):
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001
            _record(name, "ERROR", "%s: %s" % (type(exc).__name__, exc))
    first = [(n, v, d) for (n, v, d) in _RESULTS]
    # Determinism pass: run everything again, verdicts identical.
    _RESULTS[:] = []
    for name in sorted(_PROBE_FNS):
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001
            _record(name, "ERROR", "%s: %s" % (type(exc).__name__, exc))
    if [(n, v) for (n, v, d) in _RESULTS] != [(n, v)
                                             for (n, v, d) in first]:
        print("DETERMINISM: FAIL")
        return 2
    print("DETERMINISM: PASS (%d/%d probes verdict-identical)"
          % (len(_RESULTS), len(first)))
    _green_check()
    held = sum(1 for _n, v, _d in _RESULTS if v == "HELD")
    breaks = sum(1 for _n, v, _d in _RESULTS if v == "BREAK")
    errors = sum(1 for _n, v, _d in _RESULTS if v == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _RESULTS, breaks, held, errors)
    probe_lines.emit(_RESULTS)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
