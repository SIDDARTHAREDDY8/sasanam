#!/usr/bin/env python3
"""Wave-217 lane C: authorization-receipt battery — the EMILIA ADAPT
three-digests-three-jobs discipline.

Seam under test: gov/authorization_receipts.py — an authorization
receipt binds three digests to three jobs (subject = WHAT,
authorization-payload = WHO/WHY, statement-entry = envelope locator),
references standing grants by hash (never inlined), and is signed by
a caller-owned issuer key. Attack shapes: digest conflation,
unknown/revoked grant refs, expired receipts, tampered payloads,
key-swap, missing digests.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-216 HEAD
2d5b92722c76a6f2fcc3e78ed44596887ebb1e29.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g217c
  TMPDIR=/var/tmp/g217c ~/workspace/.gov-venv/bin/python evals/w217_receipt_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g217c-u \\
      ~/workspace/.gov-venv/bin/python evals/w217_receipt_probes.py
"""

import copy
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w217-receipt-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g217c-%d" % os.getpid()
os.environ.setdefault("TMPDIR", _TMPDIR_FALLBACK)
try:
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
except OSError:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import authorization_receipts as ar  # noqa: E402
    from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402
    from gov.policy import PolicyDecision  # noqa: E402
    from gov.log import ActionLog  # noqa: E402
    from gov.identity import AgentIdentity  # noqa: E402
    from gov.approvals import ApprovalQueue  # noqa: E402
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine run has no module
    ar = None
    _IMPORT_OK = False
    _IMPORT_ERR = exc

_RESULTS = []
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        _PROBE_FNS[name] = fn
        return fn
    return deco


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))


def _held(name, detail=""):
    _record(name, "HELD", detail)


def _break(name, detail=""):
    _record(name, "BREAK", detail)


def _gap(name):
    _record(name, "GAP", "module absent on pristine tree")


# ----------------------------------------------------------------------
# Harness helpers (only meaningful when the module is present).
# ----------------------------------------------------------------------

def _seed(i):
    return bytes([i]) * 32


def _harness():
    signer = Ed25519Signer(_seed(7))
    verifier = Ed25519Verifier(signer.public_key, key_id=signer.key_id)
    grants = ar.GrantRegistry()
    issuer = ar.ReceiptIssuer(signer, "issuer-ops", grants)
    return signer, verifier, grants, issuer


def _digests():
    s = ar.SubjectDigest.from_bytes(b"tool:write_file path:/data/x")
    p = ar.AuthorizationPayloadDigest.from_bytes(
        b"op-1 approved: verified diff")
    e = ar.StatementEntryDigest.from_bytes(b"audit-entry-0001")
    return s, p, e


def _queue_and_approve(receipt_config=None, grant_fn=None):
    run_dir = tempfile.mkdtemp(prefix="gov-receipt-test-")
    log = ActionLog(os.path.join(run_dir, "actions.jsonl"))
    if receipt_config is None:
        q = ApprovalQueue(run_dir, log)
    else:
        q = ar.ReceiptEmittingApprovalQueue(
            run_dir, log, receipt_config=receipt_config)
    # Battery identity discipline: this harness mints its own test
    # identity and installs the matching verifier on ITS OWN queue
    # (same form as evals/goal_resolution_probes.py) -- the F31
    # write-once property is the product's, not the test's.
    ident = AgentIdentity("agent-1", "researcher", os.path.basename(run_dir),
                          "user-1")
    q.set_identity_verifier(lambda _ident: True)
    action = {"tool": "write_file",
              "args": {"path": "/tmp/x.txt", "content": "hello"},
              "agent_justification": "receipt unit",
              "redactions": []}
    aid = q.queue(action,
                  PolicyDecision("require_approval", "receipt unit",
                                 policy_id="receipt-unit", flag="b"),
                  "agent_direct", "preview", caller_identity=ident)
    target, entry = q.decide(aid, True, "verified the diff",
                             decided_by="op-rios")
    return q, target, entry, run_dir


def _expect_refused(name, fn, codes=None):
    """The call must raise AuthorizationReceiptError (optionally with
    one of the expected codes); anything else is a BREAK."""
    try:
        fn()
    except ar.AuthorizationReceiptError as exc:
        if codes is not None and exc.code not in codes:
            _break(name, "refused but wrong code %r (want one of %s)"
                   % (exc.code, codes))
        else:
            _held(name, "refused: %s" % exc.code)
        return
    except Exception as exc:  # noqa: BLE001
        _break(name, "wrong exception type: %s: %s"
               % (type(exc).__name__, exc))
        return
    _break(name, "NOT refused -- attack shape accepted")


# ----------------------------------------------------------------------
# Probes.
# ----------------------------------------------------------------------

@_probe("happy-path-issue-verify")
def _p_happy():
    if not _IMPORT_OK:
        return _gap("happy-path-issue-verify")
    signer, verifier, grants, issuer = _harness()
    gh = grants.register({"grant_id": "g1", "scope": "write_file"})
    s, p, e = _digests()
    env = issuer.issue(s, p, e, grant_hashes=[gh], now=1700000000)
    body = ar.verify_receipt(env, verifier, grants, now=1700000000)
    if (body["subject_digest"] == s.hex
            and body["authorization_payload_digest"] == p.hex
            and body["statement_entry_digest"] == e.hex
            and body["grant_refs"] == [gh]):
        _held("happy-path-issue-verify", "round trip binds all three")
    else:
        _break("happy-path-issue-verify", "round trip lost bindings")


@_probe("digest-conflation-refused")
def _p_conflation():
    if not _IMPORT_OK:
        return _gap("digest-conflation-refused")
    _signer, _verifier, grants, issuer = _harness()
    s, p, e = _digests()
    # A subject digest presented in the authorization-payload slot.
    _expect_refused(
        "digest-conflation-refused",
        lambda: issuer.issue(s, s, e, now=1700000000),
        codes=("digest-role-mismatch",))


@_probe("unknown-grant-hash-refused")
def _p_unknown_grant():
    if not _IMPORT_OK:
        return _gap("unknown-grant-hash-refused")
    _signer, _verifier, grants, issuer = _harness()
    s, p, e = _digests()
    _expect_refused(
        "unknown-grant-hash-refused",
        lambda: issuer.issue(s, p, e,
                             grant_hashes=["ab" * 32],
                             now=1700000000),
        codes=("unknown-grant",))


@_probe("revoked-grant-refused")
def _p_revoked_grant():
    if not _IMPORT_OK:
        return _gap("revoked-grant-refused")
    signer, verifier, grants, issuer = _harness()
    gh = grants.register({"grant_id": "g2", "scope": "write_file"})
    s, p, e = _digests()
    env = issuer.issue(s, p, e, grant_hashes=[gh], now=1700000000)
    grants.revoke(gh)
    # Issue-time refusal for a revoked grant.
    _expect_refused(
        "revoked-grant-refused",
        lambda: issuer.issue(s, p, e, grant_hashes=[gh],
                             now=1700000001),
        codes=("grant-revoked",))
    # Verify-time refusal for a receipt issued before revocation.
    try:
        ar.verify_receipt(env, verifier, grants, now=1700000002)
    except ar.AuthorizationReceiptError as exc:
        if exc.code == "grant-revoked":
            _held("revoked-grant-refused",
                  "revocation enforced at issue and verify")
        else:
            _break("revoked-grant-refused",
                   "verify refused with wrong code %r" % exc.code)
    except Exception as exc:  # noqa: BLE001
        _break("revoked-grant-refused",
               "wrong exception: %s" % type(exc).__name__)
    else:
        _break("revoked-grant-refused",
               "pre-revocation receipt still verifies after revoke")


@_probe("expired-receipt-refused")
def _p_expired():
    if not _IMPORT_OK:
        return _gap("expired-receipt-refused")
    _signer, verifier, grants, issuer = _harness()
    s, p, e = _digests()
    env = issuer.issue(s, p, e, now=1700000000, ttl_seconds=100)
    # Boundary: now == expires is expired; expires-1 is valid.
    try:
        ar.verify_receipt(env, verifier, grants, now=1700000100)
    except ar.AuthorizationReceiptError as exc:
        ok = exc.code == "receipt-expired"
    else:
        ok = False
    try:
        ar.verify_receipt(env, verifier, grants, now=1700000099)
    except ar.AuthorizationReceiptError:
        ok = False
    if ok:
        _held("expired-receipt-refused", "boundary [issued, expires)")
    else:
        _break("expired-receipt-refused", "expiry boundary wrong")


@_probe("tampered-payload-digest-refused")
def _p_tamper():
    if not _IMPORT_OK:
        return _gap("tampered-payload-digest-refused")
    _signer, verifier, grants, issuer = _harness()
    s, p, e = _digests()
    env = issuer.issue(s, p, e, now=1700000000)
    bad = copy.deepcopy(env)
    bad["receipt"]["authorization_payload_digest"] = "cd" * 32
    _expect_refused(
        "tampered-payload-digest-refused",
        lambda: ar.verify_receipt(bad, verifier, grants,
                                  now=1700000000),
        codes=("signature-invalid",))


@_probe("key-swap-refused")
def _p_keyswap():
    if not _IMPORT_OK:
        return _gap("key-swap-refused")
    _signer, verifier, grants, issuer = _harness()
    s, p, e = _digests()
    env = issuer.issue(s, p, e, now=1700000000)
    attacker = Ed25519Signer(_seed(9))
    attacker_verifier = Ed25519Verifier(attacker.public_key,
                                       key_id=attacker.key_id)
    # Envelope re-labeled to the attacker's key id: verifier pins the
    # deployment key, so this must fail on the kid, not the signature.
    try:
        ar.verify_receipt(env, attacker_verifier, grants,
                          now=1700000000)
    except ar.AuthorizationReceiptError as exc:
        if exc.code == "key-swap-refused":
            _held("key-swap-refused", "kid mismatch refused")
        else:
            _break("key-swap-refused",
                   "wrong code %r" % exc.code)
    except Exception as exc:  # noqa: BLE001
        _break("key-swap-refused", "wrong exception %s"
               % type(exc).__name__)
    else:
        _break("key-swap-refused", "wrong-key verifier accepted")


@_probe("missing-digest-refused")
def _p_missing():
    if not _IMPORT_OK:
        return _gap("missing-digest-refused")
    _signer, _verifier, grants, issuer = _harness()
    s, p, e = _digests()
    _expect_refused(
        "missing-digest-refused",
        lambda: issuer.issue(None, p, e, now=1700000000),
        codes=("missing-digest",))


@_probe("malformed-digest-hex-refused")
def _p_malformed():
    if not _IMPORT_OK:
        return _gap("malformed-digest-hex-refused")
    try:
        ar.SubjectDigest("ZZZ-not-hex")
    except ar.AuthorizationReceiptError as exc:
        if exc.code == "digest-malformed":
            _held("malformed-digest-hex-refused", "refused at type")
        else:
            _break("malformed-digest-hex-refused",
                   "wrong code %r" % exc.code)
    except Exception as exc:  # noqa: BLE001
        _break("malformed-digest-hex-refused",
               "wrong exception %s" % type(exc).__name__)
    else:
        _break("malformed-digest-hex-refused", "bad hex accepted")


@_probe("grant-never-inlined")
def _p_no_inline():
    if not _IMPORT_OK:
        return _gap("grant-never-inlined")
    _signer, _verifier, grants, issuer = _harness()
    secret_grant = {"grant_id": "g-secret",
                    "scope": "write_file",
                    "notes": "standing grant contents"}
    gh = grants.register(secret_grant)
    s, p, e = _digests()
    env = issuer.issue(s, p, e, grant_hashes=[gh], now=1700000000)
    flat = str(env)
    if "g-secret" in flat or "standing grant contents" in flat:
        _break("grant-never-inlined", "grant contents leaked into receipt")
    elif env["receipt"]["grant_refs"] == [gh]:
        _held("grant-never-inlined", "receipt carries hash only")
    else:
        _break("grant-never-inlined", "grant_refs malformed")


@_probe("queue-legacy-byte-identical")
def _p_legacy():
    if not _IMPORT_OK:
        return _gap("queue-legacy-byte-identical")
    q, target, entry, run_dir = _queue_and_approve()
    try:
        events = [e.get("event") for e in _read_actions(run_dir)
                  if isinstance(e, dict)]
        if (target["status"] == "approved"
                and "authorization_receipt_emitted" not in events
                and not hasattr(q, "emitted_receipts")):
            _held("queue-legacy-byte-identical",
                  "no config: no receipts, no new events")
        else:
            _break("queue-legacy-byte-identical",
                   "legacy queue changed behavior")
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


def _read_actions(run_dir):
    from gov.log import read_entries  # noqa: E402
    return list(read_entries(os.path.join(run_dir, "actions.jsonl")))


@_probe("queue-emits-receipt-on-approve")
def _p_emit():
    if not _IMPORT_OK:
        return _gap("queue-emits-receipt-on-approve")
    signer, verifier, grants, issuer = _harness()
    gh = grants.register({"grant_id": "g-approve", "scope": "write_file"})
    cfg = ar.ReceiptConfig(issuer,
                           grant_hashes_for=lambda target: [gh])
    q, target, entry, run_dir = _queue_and_approve(
        receipt_config=cfg)
    try:
        if len(q.emitted_receipts) != 1:
            _break("queue-emits-receipt-on-approve",
                   "expected 1 receipt, got %d"
                   % len(q.emitted_receipts))
            return
        body = ar.verify_receipt(q.emitted_receipts[0], verifier,
                                 grants, now=int(time.time()))
        events = [e.get("event") for e in _read_actions(run_dir)
                  if isinstance(e, dict)]
        if ("authorization_receipt_emitted" in events
                and body["grant_refs"] == [gh]
                and body["issuer"] == "issuer-ops"):
            _held("queue-emits-receipt-on-approve",
                  "receipt emitted, audited, verifies")
        else:
            _break("queue-emits-receipt-on-approve",
                   "receipt or audit event malformed")
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


@_probe("emission-failure-is-loud")
def _p_loud():
    if not _IMPORT_OK:
        return _gap("emission-failure-is-loud")
    _signer, _verifier, grants, issuer = _harness()
    cfg = ar.ReceiptConfig(issuer,
                           grant_hashes_for=lambda target: ["ff" * 32])
    run_dir = tempfile.mkdtemp(prefix="gov-receipt-test-")
    try:
        log = ActionLog(os.path.join(run_dir, "actions.jsonl"))
        q = ar.ReceiptEmittingApprovalQueue(run_dir, log,
                                            receipt_config=cfg)
        ident = AgentIdentity("agent-1", "researcher",
                              os.path.basename(run_dir), "user-1")
        q.set_identity_verifier(lambda _ident: True)
        action = {"tool": "write_file",
                  "args": {"path": "/tmp/y.txt"},
                  "agent_justification": "loud unit",
                  "redactions": []}
        aid = q.queue(action,
                      PolicyDecision("require_approval", "loud unit",
                                     policy_id="loud-unit", flag="b"),
                      "agent_direct", "preview", caller_identity=ident)
        try:
            q.decide(aid, True, "try approve", decided_by="op-rios")
        except ar.AuthorizationReceiptError as exc:
            events = [e.get("event") for e in _read_actions(run_dir)
                      if isinstance(e, dict)]
            target = [r for r in q.all() if r["id"] == aid][0]
            if ("authorization_receipt_failed" in events
                    and target["status"] == "approved"):
                _held("emission-failure-is-loud",
                      "decision stands; failure loud (%s)" % exc.code)
            else:
                _break("emission-failure-is-loud",
                       "failure not audited or decision lost")
        except Exception as exc:  # noqa: BLE001
            _break("emission-failure-is-loud",
                   "wrong exception %s" % type(exc).__name__)
        else:
            _break("emission-failure-is-loud",
                   "emission with unknown grant did not raise")
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


def _green_check():
    if not _IMPORT_OK:
        _record("green-check", "GAP", "module absent on pristine tree")
        return
    if GREEN_SKIP:
        _record("green-check", "HELD", "skipped (GOV_SKIP_GREEN=1)")
        return
    import subprocess
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    adj = [
        ["evals/w216_jail_policy_probes.py"],
        ["evals/w216_verdict_binding_probes.py"],
    ]
    ok = True
    for battery in adj:
        try:
            r = subprocess.run(
                [sys.executable, battery[0]], cwd=REPO, env=env,
                capture_output=True, text=True, timeout=600)
            if r.returncode != 0:
                ok = False
                _record("green-check", "ERROR",
                        "%s -> rc %d" % (battery[0], r.returncode))
        except Exception as exc:  # noqa: BLE001
            ok = False
            _record("green-check", "ERROR",
                    "%s -> %s" % (battery[0], exc))
    if ok:
        _record("green-check", "HELD", "2 adjacent batteries green")


def main():
    print("Authorization-receipt battery: three-digests-three-jobs")
    for name in sorted(_PROBE_FNS):
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001
            _record(name, "ERROR", "%s: %s" % (type(exc).__name__, exc))
    first = [(n, v) for (n, v, d) in _RESULTS]
    _RESULTS[:] = []
    for name in sorted(_PROBE_FNS):
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001
            _record(name, "ERROR", "%s: %s" % (type(exc).__name__, exc))
    if [(n, v) for (n, v, d) in _RESULTS] != first:
        print("DETERMINISM: FAIL")
        return 2
    print("DETERMINISM: PASS (%d/%d probes verdict-identical)"
          % (len(_RESULTS), len(first)))
    _green_check()
    held = sum(1 for _n, v, _d in _RESULTS if v == "HELD")
    gaps = sum(1 for _n, v, _d in _RESULTS if v == "GAP")
    breaks = sum(1 for _n, v, _d in _RESULTS if v == "BREAK")
    errors = sum(1 for _n, v, _d in _RESULTS if v == "ERROR")
    res = sum(1 for _n, v, _d in _RESULTS if v == "RESIDUAL")
    print("SUMMARY: %d HELD / %d GAP / %d BREAK / %d RESIDUAL / %d ERROR"
          % (held, gaps, breaks, res, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
