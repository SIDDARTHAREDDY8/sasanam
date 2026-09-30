#!/usr/bin/env python3
"""Wave-224 lane A: agent action capsules (per-verdict digest-committed evidence).

ADAPT of the draft-mih-scitt-agent-action-capsule-05 pattern (re-derived
prose; nothing copied): every agent verdict — admit OR refusal — seals a
digest-committed JSON capsule so an auditor can verify what was decided
and what actually happened. A blocked or denied capsule is the
auditor-grade evidence that a gate worked. The capsule separates the
ATTEMPT (what was requested) from the EFFECT (what actually happened),
binds both by digest, and is committed with a capsule_digest over
canonical (JCS-style: sorted keys, no whitespace) JSON bytes. JCS-only:
non-canonical input refuses ``capsule-noncanonical``. A capsule is
evidence, never authorization.

Seams under test:
* gov/action_capsule.py — seal_capsule(verdict_record) -> dict
  {v, capsule_digest, verdict_digest, effect_digest, jcs_json};
  capsule_digest = sha256 of the canonical JSON bytes of the capsule
  body; verdict_digest = sha256 of the canonical ATTEMPT bytes;
  effect_digest = sha256 of the canonical EFFECT bytes.
* seal_capsule_json(raw: bytes) — strict JCS input gate: non-UTF8,
  duplicate keys, unsorted keys all refuse ``capsule-noncanonical``;
  the raw bytes must BE the canonical encoding.
* verify_capsule(capsule) — recomputes capsule_digest; tampered
  capsule refuses ``capsule-digest-mismatch``; malformed refuses
  ``capsule-malformed``.
* Attempt/effect binding: attempt==effect (conflated) refuses
  ``capsule-attempt-effect-diverged``; an effect that claims an
  outcome without evidence refuses the same code.
* capsule_from_refusal(refusal_code, subject_digest) — seals a
  refusal verdict binding the named refusal code; the refusal is
  first-class evidence.
* capsule_carries_no_authority(verdict_record) — a verdict smuggling
  authority-shaped fields (grant/authorization/authority/permit/
  capability/scope) refuses ``capsule-not-authorization``.

Attack shapes: tampered capsule bytes; conflated attempt/effect;
evidence-free effect claim; non-canonical JSON (dup keys, unsorted,
non-UTF8); refusal offered without evidence; authority smuggled
into evidence; capsule replayed as an authorization.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-223 HEAD
28db79fcbf5b8415cc0ba2b20e48d52530cfcc81.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g224a
  TMPDIR=/var/tmp/g224a ~/workspace/.gov-venv/bin/python evals/w224_capsule_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g224a-u \\
      ~/workspace/.gov-venv/bin/python evals/w224_capsule_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import json
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import action_capsule as ac
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine base has no module
    ac = None
    _IMPORT_OK = False
    _IMPORT_ERR = exc

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))


def _expect_code(name, fn, code):
    """HELD if fn raises ac.CapsuleError with .code == code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        got = getattr(exc, "code", None)
        if isinstance(exc, ac.CapsuleError) and got == code:
            _record(name, "HELD", "refused %s" % code)
        else:
            _record(name, "BREAK",
                    "wrong refusal: %r code=%r" % (exc, got))
    else:
        _record(name, "GAP", "no refusal raised")


def _admit_verdict():
    return {
        "attempt": {"action": "write_file",
                    "params_digest": "sha256:" + "a1" * 32},
        "effect": {"status": "admitted",
                   "evidence": "sha256:" + "b2" * 32,
                   "observed": "file written at 2026-09-30T04:00:00Z"},
    }


def _refusal_verdict():
    return {
        "attempt": {"action": "write_file",
                    "params_digest": "sha256:" + "a1" * 32},
        "effect": {"status": "refused",
                   "code": "permit-revoked",
                   "evidence": "sha256:" + "c3" * 32,
                   "observed": "redeem refused; nothing executed"},
    }


def _run_once():
    del _RESULTS[:]

    if not _IMPORT_OK:
        for name in _PROBE_NAMES:
            _record(name, "GAP", "module absent on base")
        return list(_RESULTS)

    # p01 — admit verdict seals; digests bind attempt and effect.
    try:
        cap = ac.seal_capsule(_admit_verdict())
        body = json.loads(cap["jcs_json"].encode("utf-8"))
        ok = (cap["capsule_digest"]
              == hashlib.sha256(cap["jcs_json"].encode("utf-8")).hexdigest()
              and cap["verdict_digest"]
              == hashlib.sha256(
                  json.dumps(_admit_verdict()["attempt"],
                             sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")).hexdigest()
              and cap["effect_digest"]
              == hashlib.sha256(
                  json.dumps(_admit_verdict()["effect"],
                             sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")).hexdigest()
              and body["attempt"]["action"] == "write_file")
        _record("p01-admit-seals", "HELD" if ok else "BREAK",
                "digests bind attempt+effect")
    except Exception as exc:  # noqa: BLE001
        _record("p01-admit-seals", "ERROR", "%r" % (exc,))

    # p02 — refusal verdict seals as first-class evidence.
    try:
        cap = ac.seal_capsule(_refusal_verdict())
        body = json.loads(cap["jcs_json"].encode("utf-8"))
        ok = (body["effect"]["status"] == "refused"
              and body["effect"]["code"] == "permit-revoked"
              and cap["capsule_digest"]
              == hashlib.sha256(cap["jcs_json"].encode("utf-8")).hexdigest())
        _record("p02-refusal-seals", "HELD" if ok else "BREAK",
                "refusal is auditor-grade evidence")
    except Exception as exc:  # noqa: BLE001
        _record("p02-refusal-seals", "ERROR", "%r" % (exc,))

    # p03 — attempt and effect digests are distinct and bound.
    try:
        cap = ac.seal_capsule(_admit_verdict())
        ok = (cap["verdict_digest"] != cap["effect_digest"]
              and len(cap["verdict_digest"]) == 64
              and len(cap["effect_digest"]) == 64)
        _record("p03-attempt-effect-bound", "HELD" if ok else "BREAK",
                "attempt != effect, both digest-bound")
    except Exception as exc:  # noqa: BLE001
        _record("p03-attempt-effect-bound", "ERROR", "%r" % (exc,))

    # p04 — conflated attempt/effect refuses.
    conflated = {"attempt": {"action": "x"},
                 "effect": {"action": "x"}}
    _expect_code("p04-conflated-refused",
                 lambda: ac.seal_capsule(conflated),
                 "capsule-attempt-effect-diverged")

    # p05 — effect claimed without evidence refuses.
    no_evidence = {"attempt": {"action": "x"},
                   "effect": {"status": "admitted", "observed": "done"}}
    _expect_code("p05-effect-no-evidence",
                 lambda: ac.seal_capsule(no_evidence),
                 "capsule-attempt-effect-diverged")

    # p06 — noncanonical input: duplicate keys refuse.
    dup = b'{"attempt": {"action": "x"}, "attempt": {"action": "y"}, ' \
          b'"effect": {"status": "refused", "evidence": "e"}}'
    _expect_code("p06-dup-keys-refused",
                 lambda: ac.seal_capsule_json(dup),
                 "capsule-noncanonical")

    # p07 — noncanonical input: unsorted keys refuse.
    unsorted = b'{"effect": {"status": "refused", "evidence": "e"}, ' \
               b'"attempt": {"action": "x"}}'
    _expect_code("p07-unsorted-keys-refused",
                 lambda: ac.seal_capsule_json(unsorted),
                 "capsule-noncanonical")

    # p08 — noncanonical input: non-UTF8 bytes refuse.
    nonutf8 = b'{"attempt": {"action": "\xff\xfe"}, "effect": ' \
              b'{"status": "refused", "evidence": "e"}}'
    _expect_code("p08-nonutf8-refused",
                 lambda: ac.seal_capsule_json(nonutf8),
                 "capsule-noncanonical")

    # p09 — tampered capsule digest refuses on verify.
    try:
        cap = ac.seal_capsule(_admit_verdict())
        tampered = dict(cap)
        tampered["jcs_json"] = cap["jcs_json"].replace("admitted",
                                                      "refusedX")
        try:
            ac.verify_capsule(tampered)
            _record("p09-tamper-refused", "GAP", "no refusal raised")
        except Exception as exc:  # noqa: BLE001
            got = getattr(exc, "code", None)
            if isinstance(exc, ac.CapsuleError) \
                    and got == "capsule-digest-mismatch":
                _record("p09-tamper-refused", "HELD",
                        "tamper detected by digest")
            else:
                _record("p09-tamper-refused", "BREAK",
                        "wrong refusal: %r code=%r" % (exc, got))
    except Exception as exc:  # noqa: BLE001
        _record("p09-tamper-refused", "ERROR", "%r" % (exc,))

    # p10 — capsule_from_refusal binds the named code.
    try:
        cap = ac.capsule_from_refusal("admission-digest-mismatch",
                                      "sha256:" + "d4" * 32)
        body = ac.verify_capsule(cap)
        ok = (body["effect"]["code"] == "admission-digest-mismatch"
              and body["effect"]["status"] == "refused"
              and body["attempt"]["subject_digest"] == "sha256:" + "d4" * 32)
        _record("p10-refusal-helper", "HELD" if ok else "BREAK",
                "named refusal code bound as evidence")
    except Exception as exc:  # noqa: BLE001
        _record("p10-refusal-helper", "ERROR", "%r" % (exc,))

    # p11 — authority smuggled into evidence refuses.
    smuggled = {"attempt": {"action": "x"},
                "effect": {"status": "admitted", "evidence": "e"},
                "grant": {"scope": "everything"}}
    _expect_code("p11-no-authority-smuggle",
                 lambda: ac.seal_capsule(smuggled),
                 "capsule-not-authorization")

    # p12 — canonical JSON input seals (round trip through strict gate).
    try:
        canonical = (b'{"attempt":{"action":"x"},"effect":{"code":"test-refusal",'
                     b'"evidence":"e","status":"refused"}}')
        cap = ac.seal_capsule_json(canonical)
        ok = ac.verify_capsule(cap)["effect"]["status"] == "refused"
        _record("p12-canonical-roundtrip", "HELD" if ok else "BREAK",
                "strict gate admits true canonical form")
    except Exception as exc:  # noqa: BLE001
        _record("p12-canonical-roundtrip", "ERROR", "%r" % (exc,))

    # p13 — unknown top-level fields fail closed, never silently dropped.
    extra = {"attempt": {"action": "x"},
             "effect": {"status": "admitted", "evidence": "e"},
             "extra_claim": "uncommitted"}
    _expect_code("p13-unknown-field-refused",
                 lambda: ac.seal_capsule(extra),
                 "capsule-unknown-field")

    return list(_RESULTS)


# NOTE (wave-224 merge): the lane's "no tracked-file modifications" pin
# originally spawned `git status --porcelain` here. That is a git-spawning
# call site inside the repo, which the standing wave-36 supply-chain
# probe (redteam.supplychain.gitspawn_no_git_subprocess_in_repo) refuses
# -- a hostile repo-local .git/config's core.fsmonitor could fire on any
# in-repo git invocation, so the registry gate fails closed on it. The
# add-only property is enforced instead at merge time, by direct
# byte-verification of every lane file against its lane commit
# (906ce16 for this lane). No git subprocess may be reintroduced here.


_PROBE_NAMES = [
    "p01-admit-seals", "p02-refusal-seals", "p03-attempt-effect-bound",
    "p04-conflated-refused", "p05-effect-no-evidence",
    "p06-dup-keys-refused", "p07-unsorted-keys-refused",
    "p08-nonutf8-refused", "p09-tamper-refused", "p10-refusal-helper",
    "p11-no-authority-smuggle", "p12-canonical-roundtrip",
    "p13-unknown-field-refused",
]


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_posture.py",
                 "tests/test_absence_revocation.py",
                 "tests/test_permit_leases.py",
                 "tests/test_admission.py",
                 "tests/test_decision_packet.py"):
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
    print("w224 capsule probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "(%d probes, determinism %s)"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in _RESULTS:
        print("  %-32s %s %s" % (name, verdict, detail))
    for name, status, detail in green:
        print("  %-32s %s %s" % (name, status, detail))
    if not _IMPORT_OK:
        print("import failed (pristine): %r" % (_IMPORT_ERR,))
    if brk or err or not det_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
