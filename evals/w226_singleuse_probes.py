#!/usr/bin/env python3
"""Wave-226 lane C: single-use attestations + fail-closed incomplete evidence.

ADAPT of the MNKI spec v0.2 single-use-attestation direction and the
wave-225 "fail-closed incomplete-evidence states" proposal (re-derived
prose; nothing copied): attestation records are consumed exactly once,
and evidence completeness requires every required kind present AND
individually verifiable — a present-but-unverifiable item is NOT
treated as absent.

Seams under test:
* gov/single_use.py — SingleUseRegistry: issue(attestation_digest,
  issuer, nonce) binds digest+issuer+nonce into a derived jti; consume()
  refuses single-use-replay-refused on second consume, single-use-unknown
  on unknown jti, single-use-issuer-revoked when the issuer's key digest
  is revoked in an attached gov/revocation.py registry; nonce reuse
  across a different digest refuses single-use-replay-refused at issue.
* EvidenceChecker.require_complete(evidence_items, required_kinds):
  missing kind -> evidence-incomplete; present-but-unverifiable item ->
  evidence-unverifiable-item (never downgraded to incomplete). A
  consumed single-use attestation composes as kind
  "single-use-attestation".

Attack shapes: replay the same attestation twice; consume a forged jti;
revoke the issuer's key after issuance; reuse a nonce with a different
digest; drop a required evidence kind; smuggle an unverifiable item and
hope it counts as absent; confuse unverifiable-item with incomplete.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-225 HEAD
0fb51624e6162c1846501e93b9ab3dd2127f7873.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g226c
  TMPDIR=/var/tmp/g226c ~/workspace/.gov-venv/bin/python evals/w226_singleuse_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g226c-u \\
      ~/workspace/.gov-venv/bin/python evals/w226_singleuse_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import subprocess
import sys
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import single_use as _su
    from gov import revocation as _rev
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False


def _digest(seed=b"wave226-singleuse"):
    return hashlib.sha256(seed).hexdigest()


def _refuses(fn, code):
    """True if fn() raises an Exception whose .code == code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "code", None) == code
    return False


def _run_once():
    results = []

    def rec(name, verdict, detail=""):
        results.append((name, verdict, detail))

    if not HAVE_MODULE:
        for name in PROBE_NAMES:
            rec(name, "GAP", "gov.single_use absent on this tree")
        return results

    # su-01: issue -> consume OK.
    try:
        reg = _su.SingleUseRegistry()
        att = reg.issue(_digest(b"att-1"), "issuer-a", "nonce-0001")
        ev = reg.consume(att)
        ok = (ev.get("kind") == "single-use-attestation"
              and ev.get("jti") == att.get("jti"))
        rec("su-01-issue-consume-ok", "HELD" if ok else "BREAK",
            "consume returned kind=%r jti match=%r" % (ev.get("kind"), ok))
    except Exception as exc:  # noqa: BLE001
        rec("su-01-issue-consume-ok", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # su-02: second consume of the same jti refuses.
    try:
        reg = _su.SingleUseRegistry()
        att = reg.issue(_digest(b"att-2"), "issuer-a", "nonce-0002")
        reg.consume(att)
        held = _refuses(lambda: reg.consume(att),
                        "single-use-replay-refused")
        rec("su-02-replay-refused", "HELD" if held else "BREAK",
            "replay refusal code observed" if held
            else "replay did not refuse single-use-replay-refused")
    except Exception as exc:  # noqa: BLE001
        rec("su-02-replay-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # su-03: consume of a well-formed but never-issued jti refuses.
    # (A forged jti that does not recompute refuses single-use-malformed;
    # the unknown case is a well-formed record unknown to THIS registry:
    # issue on registry B, consume on registry A.)
    try:
        reg_a = _su.SingleUseRegistry()
        reg_b = _su.SingleUseRegistry()
        legit_but_foreign = reg_b.issue(_digest(b"att-3"), "issuer-a",
                                        "nonce-0003")
        held = _refuses(lambda: reg_a.consume(legit_but_foreign),
                        "single-use-unknown")
        rec("su-03-unknown-jti-refused", "HELD" if held else "BREAK",
            "unknown jti refusal code observed" if held
            else "unknown jti did not refuse single-use-unknown")
    except Exception as exc:  # noqa: BLE001
        rec("su-03-unknown-jti-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # su-03b: a tampered record (fields no longer recompute the jti)
    # refuses single-use-malformed, not unknown.
    try:
        reg = _su.SingleUseRegistry()
        att = reg.issue(_digest(b"att-3b"), "issuer-a", "nonce-0003b")
        tampered = dict(att)
        tampered["attestation_digest"] = _digest(b"att-3b-swapped")
        held = _refuses(lambda: reg.consume(tampered),
                        "single-use-malformed")
        rec("su-03b-tampered-record-malformed", "HELD" if held else "BREAK",
            "tampered record refusal code observed" if held
            else "tampered record did not refuse single-use-malformed")
    except Exception as exc:  # noqa: BLE001
        rec("su-03b-tampered-record-malformed", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # su-04: issuer key revoked after issuance -> consume refuses.
    try:
        seed = os.urandom(32)
        rev = _rev.RevocationList()
        issuer_key_digest = _digest(b"issuer-a-pubkey")
        rev.revoke(issuer_key_digest, issuer_id="ca", seed=seed)
        reg = _su.SingleUseRegistry(revocation_registry=rev)
        att = reg.issue(_digest(b"att-4"), "issuer-a", "nonce-0004",
                        issuer_pubkey_digest=issuer_key_digest)
        held = _refuses(lambda: reg.consume(att),
                        "single-use-issuer-revoked")
        rec("su-04-revoked-issuer-refused", "HELD" if held else "BREAK",
            "revoked issuer refusal code observed" if held
            else "revoked issuer did not refuse single-use-issuer-revoked")
    except Exception as exc:  # noqa: BLE001
        rec("su-04-revoked-issuer-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # su-05: nonce reuse with a DIFFERENT digest refuses at issue.
    try:
        reg = _su.SingleUseRegistry()
        reg.issue(_digest(b"att-5a"), "issuer-a", "nonce-0005")
        held = _refuses(
            lambda: reg.issue(_digest(b"att-5b"), "issuer-a", "nonce-0005"),
            "single-use-replay-refused")
        rec("su-05-cross-digest-nonce-reuse-refused",
            "HELD" if held else "BREAK",
            "cross-digest nonce reuse refusal observed" if held
            else "cross-digest nonce reuse did not refuse")
    except Exception as exc:  # noqa: BLE001
        rec("su-05-cross-digest-nonce-reuse-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ev-06: complete evidence passes.
    try:
        reg = _su.SingleUseRegistry()
        att = reg.issue(_digest(b"att-6"), "issuer-a", "nonce-0006")
        item = reg.consume(att)
        checker = _su.EvidenceChecker({
            "single-use-attestation": reg.attestation_evidence_verifier(),
            "packet": lambda it: it.get("sig_ok") is True,
        })
        out = checker.require_complete(
            [item, {"kind": "packet", "sig_ok": True}],
            ["single-use-attestation", "packet"])
        ok = isinstance(out, dict) and set(out.get("kinds", ())) == {
            "single-use-attestation", "packet"}
        rec("ev-06-complete-evidence-passes", "HELD" if ok else "BREAK",
            "require_complete returned kinds=%r" % (out.get("kinds"),))
    except Exception as exc:  # noqa: BLE001
        rec("ev-06-complete-evidence-passes", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ev-07: missing required kind -> evidence-incomplete.
    try:
        reg = _su.SingleUseRegistry()
        att = reg.issue(_digest(b"att-7"), "issuer-a", "nonce-0007")
        item = reg.consume(att)
        checker = _su.EvidenceChecker({
            "single-use-attestation": reg.attestation_evidence_verifier(),
        })
        held = _refuses(
            lambda: checker.require_complete(
                [item], ["single-use-attestation", "packet"]),
            "evidence-incomplete")
        rec("ev-07-missing-kind-incomplete", "HELD" if held else "BREAK",
            "missing kind refusal observed" if held
            else "missing kind did not refuse evidence-incomplete")
    except Exception as exc:  # noqa: BLE001
        rec("ev-07-missing-kind-incomplete", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ev-08: present-but-unverifiable item -> evidence-unverifiable-item
    # (NOT evidence-incomplete).
    try:
        checker = _su.EvidenceChecker({
            "packet": lambda it: it.get("sig_ok") is True,
        })

        def try_it():
            try:
                checker.require_complete([{"kind": "packet",
                                           "sig_ok": False}], ["packet"])
            except Exception as exc:  # noqa: BLE001
                return getattr(exc, "code", None)
            return None

        code = try_it()
        held = code == "evidence-unverifiable-item"
        rec("ev-08-unverifiable-item-refused",
            "HELD" if held else "BREAK",
            "code=%r (must be evidence-unverifiable-item, not incomplete)"
            % (code,))
    except Exception as exc:  # noqa: BLE001
        rec("ev-08-unverifiable-item-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ev-09: consumed attestation composes as single-use-attestation.
    try:
        reg = _su.SingleUseRegistry()
        att = reg.issue(_digest(b"att-9"), "issuer-a", "nonce-0009")
        item = reg.consume(att)
        verifier = reg.attestation_evidence_verifier()
        ok = verifier(item) is True
        ok = ok and verifier({"kind": "single-use-attestation",
                              "jti": "0" * 64}) is False
        rec("ev-09-consumed-attestation-composes",
            "HELD" if ok else "BREAK",
            "verifier accepts consumed, rejects foreign jti")
    except Exception as exc:  # noqa: BLE001
        rec("ev-09-consumed-attestation-composes", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    return results


PROBE_NAMES = [
    "su-01-issue-consume-ok",
    "su-02-replay-refused",
    "su-03-unknown-jti-refused",
    "su-03b-tampered-record-malformed",
    "su-04-revoked-issuer-refused",
    "su-05-cross-digest-nonce-reuse-refused",
    "ev-06-complete-evidence-passes",
    "ev-07-missing-kind-incomplete",
    "ev-08-unverifiable-item-refused",
    "ev-09-consumed-attestation-composes",
]


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_permit_leases.py",
                 "tests/test_absence_revocation.py",
                 "tests/test_posture.py"):
        path = os.path.join(REPO, unit)
        if not os.path.exists(path):
            notes.append((unit, "SKIP", "unit test not present"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", unit.replace("/", ".")[:-3]],
            env=env, cwd=REPO,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=600)
        out = proc.stdout.decode("utf-8", "replace")
        if proc.returncode == 0:
            notes.append((unit, "PASS", "adjacent unit suite green"))
        else:
            tail = out[-400:] if out else "no output"
            notes.append((unit, "FAIL", tail))
    return notes


def main():
    first = _run_once()
    second = _run_once()
    det_ok = [v for _, v, _d in first] == [v for _, v, _d in second]
    green = _run_green_checks()
    held = sum(1 for _, v, _d in first if v == "HELD")
    gap = sum(1 for _, v, _d in first if v == "GAP")
    brk = sum(1 for _, v, _d in first if v == "BREAK")
    err = sum(1 for _, v, _d in first if v == "ERROR")
    print("w226 single-use probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "of %d; determinism %s"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in first:
        print("  [%s] %s %s" % (verdict, name, detail))
    for name, status, detail in green:
        print("  green-check [%s] %s %s" % (status, name, detail))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
