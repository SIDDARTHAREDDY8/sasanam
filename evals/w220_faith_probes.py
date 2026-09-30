#!/usr/bin/env python3
"""Wave-220 lane A: presentation-faithfulness battery — the EMILIA STEAL.

Seam under test: gov/presentation.py + gov/approval_render.py.

EMILIA lesson: the approver must see a FAITHFUL rendering of what is
being signed. display != hash is a named attack (code
``display-hash-mismatch``). This module makes the presentation binding
explicit and fail-closed:

* ``gov/approval_render.render_approval`` produces the approver-facing
  rendering WITH its digest attached (``{"text", "digest"}``), derived
  from the same ``canonical_packet`` display surface the queue path
  shows the human;
* ``gov/approval_render.seal_approval`` binds
  ``{approval_id, artifact_digest, presentation_digest,
  presentation_text, signer}`` at the signing ceremony;
* ``gov/approval_render.verify_seal`` refuses (named
  ``display-hash-mismatch``) when the presentation text was tampered,
  the signed artifact changed, or the record drifted since the
  presentation was rendered — fail closed, never silent;
* ``gov/presentation.py`` carries the mission-bound ARAP ADAPT:
  approvals bind the request's ``parameter_digest``; one-use permit
  leases refuse replay (``permit-reused``), digest change
  (``mission-binding-mismatch``), and relaxed matching
  (``downgrade-refused`` — the no-downgrade rule).

Attack shapes: swapped display (show A, sign B), tampered render
between view and sign, truncated render, missing presentation, legacy
approval without the seam (byte-identical pass-through), permit
replay, digest change, relaxed match.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-219 HEAD
4acc49b08064abb9874be6f6465e81b2decaf523.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (modules absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g220a
  TMPDIR=/var/tmp/g220a ~/workspace/.gov-venv/bin/python evals/w220_faith_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g220a-u \\
      ~/workspace/.gov-venv/bin/python evals/w220_faith_probes.py
"""

import os
import secrets
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w220-faith-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g220a-%d" % os.getpid()
os.environ.setdefault("TMPDIR", _TMPDIR_FALLBACK)
try:
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
except OSError:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import presentation as pres  # noqa: E402
    from gov import approval_render as ar  # noqa: E402
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine run has no modules
    pres = None
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


def _code_of(exc):
    return getattr(exc, "code", type(exc).__name__)


def _record_fixture(**over):
    """Minimal approval record exercising the canonical packet seam."""
    rec = {
        "id": "appr-0001",
        "tool": "write_file",
        "args": {"path": "/etc/app/config.yaml", "mode": "overwrite"},
        "preview": "write /etc/app/config.yaml (overwrite)",
        "agent_id": "agent-7",
        "role": "executor",
        "principal": "principal:agent-7",
        "policy_id": "pol-9",
        "policy_version": 3,
        "matched_rules": ["rule-write"],
        "policy_flag": None,
        "packet_risk_score": 55,
        "packet_risk_factors": ["writes-outside-sandbox"],
        "shield_tier": "standard",
        "persuasion_score": 0,
        "persuasion_markers": [],
        "policy_context": {"path_resolved": "/etc/app/config.yaml",
                           "memory_provenance": [],
                           "attachment_carriers": []},
        "deferred_effect": None,
    }
    rec.update(over)
    return rec


class _StubQueue:
    """Minimal queue seam: records decide() calls, no side effects."""

    def __init__(self, record):
        self._record = record
        self.decide_calls = []

    def get(self, approval_id):
        if approval_id != self._record.get("id"):
            raise KeyError(approval_id)
        return self._record

    def decide(self, approval_id, approved, reason, **kw):
        self.decide_calls.append((approval_id, approved, reason, kw))
        return ("decided", {"id": approval_id, "approved": approved,
                            "reason": reason, "extra": kw})


@_probe("p1-swapped-display")
def _p1():
    # Attack: render record A, then use that sealed presentation to
    # authorize record B (show A, sign B).
    rec_a = _record_fixture(id="appr-A", tool="read_file",
                            args={"path": "/public/notes.txt"})
    rec_b = _record_fixture(id="appr-B", tool="delete_file",
                            args={"path": "/etc/passwd"})
    presentation = ar.render_approval(rec_a)
    sealed = ar.seal_approval(rec_b, presentation, signer="op-1")
    try:
        ar.verify_seal(rec_b, sealed)
    except pres.FaithfulnessError as exc:
        if _code_of(exc) == "display-hash-mismatch":
            _held("p1-swapped-display", "refused display-hash-mismatch")
        else:
            _break("p1-swapped-display",
                   "wrong refusal code %r" % _code_of(exc))
    else:
        _break("p1-swapped-display", "swapped display verified OK")


@_probe("p2-tampered-render")
def _p2():
    # Attack: presentation text edited between view and sign (digest
    # recorded at view time no longer covers the text).
    rec = _record_fixture()
    presentation = ar.render_approval(rec)
    sealed = ar.seal_approval(rec, presentation, signer="op-1")
    sealed = dict(sealed)
    sealed["presentation_text"] = (sealed["presentation_text"]
                                   + "\n# do not delete /etc/app")
    try:
        ar.verify_seal(rec, sealed)
    except pres.FaithfulnessError as exc:
        if _code_of(exc) == "display-hash-mismatch":
            _held("p2-tampered-render", "refused display-hash-mismatch")
        else:
            _break("p2-tampered-render",
                   "wrong refusal code %r" % _code_of(exc))
    else:
        _break("p2-tampered-render", "tampered render verified OK")


@_probe("p3-truncated-render")
def _p3():
    # Attack: the render is truncated after sealing (the approver saw
    # less than the text that now circulates).
    rec = _record_fixture()
    presentation = ar.render_approval(rec)
    sealed = ar.seal_approval(rec, presentation, signer="op-1")
    sealed = dict(sealed)
    text = sealed["presentation_text"]
    sealed["presentation_text"] = text[:max(1, len(text) // 2)]
    try:
        ar.verify_seal(rec, sealed)
    except pres.FaithfulnessError as exc:
        if _code_of(exc) == "display-hash-mismatch":
            _held("p3-truncated-render", "refused display-hash-mismatch")
        else:
            _break("p3-truncated-render",
                   "wrong refusal code %r" % _code_of(exc))
    else:
        _break("p3-truncated-render", "truncated render verified OK")


@_probe("p4-faithful-render")
def _p4():
    # Control: an untampered render verifies cleanly.
    rec = _record_fixture()
    presentation = ar.render_approval(rec)
    if presentation["digest"] != pres.presentation_digest(
            presentation["text"]):
        _break("p4-faithful-render", "digest does not cover text")
        return
    sealed = ar.seal_approval(rec, presentation, signer="op-1")
    try:
        ok = ar.verify_seal(rec, sealed)
    except pres.FaithfulnessError as exc:
        _break("p4-faithful-render", "faithful render refused: %r"
               % _code_of(exc))
    else:
        if ok is True:
            _held("p4-faithful-render", "faithful render verifies")
        else:
            _break("p4-faithful-render", "verify returned %r" % (ok,))


@_probe("p5-legacy-untouched")
def _p5():
    # The seam is opt-in: with no sealed presentation, guarded_decide
    # must call the underlying decide() byte-identically — no
    # presentation fields added, identical args, identical result.
    rec = _record_fixture()
    stub = _StubQueue(rec)
    direct = ("decided", {"id": "appr-0001", "approved": True,
                          "reason": "ok", "extra": {}})
    got = ar.guarded_decide(stub, "appr-0001", True, "ok", sealed=None)
    if got != direct:
        _break("p5-legacy-untouched",
               "guarded result differs from direct decide: %r" % (got,))
        return
    if stub.decide_calls != [("appr-0001", True, "ok", {})]:
        _break("p5-legacy-untouched",
               "underlying decide got different args: %r"
               % (stub.decide_calls,))
        return
    _held("p5-legacy-untouched", "pass-through byte-identical")


@_probe("p6-sealed-accepted")
def _p6():
    # An approval of the exact artifact digest, with the faithful
    # presentation digest attached and the mission parameter_digest
    # bound, is accepted (both checks in one ceremony).
    rec = _record_fixture()
    presentation = ar.render_approval(rec)
    sealed = ar.seal_approval(rec, presentation, signer="op-1")
    param_digest = pres.parameter_digest({"subject": "agent-7",
                                          "resource": "/etc/app/config.yaml",
                                          "action": "write_file",
                                          "args": rec["args"]})
    bound = pres.mission_bind_approval(sealed, param_digest)
    try:
        ar.verify_seal(rec, bound)
        pres.verify_mission_binding(bound, param_digest)
    except pres.FaithfulnessError as exc:
        _break("p6-sealed-accepted", "refused: %r" % _code_of(exc))
    else:
        _held("p6-sealed-accepted", "exact digest + mission bind accepted")


@_probe("p7-permit-replay")
def _p7():
    # One-use permit leases: the second consume is refused as
    # permit-reused (replay of the authorization is impossible).
    reg = pres.MissionPermitRegistry()
    digest = pres.parameter_digest({"subject": "s", "resource": "r",
                                    "action": "a"})
    lease = reg.issue("appr-0001", digest)
    reg.consume(lease["lease_id"], digest)
    try:
        reg.consume(lease["lease_id"], digest)
    except pres.FaithfulnessError as exc:
        if _code_of(exc) == "permit-reused":
            _held("p7-permit-replay", "replay refused permit-reused")
        else:
            _break("p7-permit-replay",
                   "wrong refusal code %r" % _code_of(exc))
    else:
        _break("p7-permit-replay", "permit consumed twice")


@_probe("p8-digest-change")
def _p8():
    # The request parameters changed after the permit was issued: the
    # permit cannot be retargeted (mission-binding-mismatch).
    reg = pres.MissionPermitRegistry()
    digest = pres.parameter_digest({"subject": "s", "resource": "r",
                                    "action": "a"})
    other = pres.parameter_digest({"subject": "s", "resource": "r",
                                   "action": "a", "args": {"x": 1}})
    lease = reg.issue("appr-0001", digest)
    try:
        reg.consume(lease["lease_id"], other)
    except pres.FaithfulnessError as exc:
        if _code_of(exc) == "mission-binding-mismatch":
            _held("p8-digest-change",
                  "retarget refused mission-binding-mismatch")
        else:
            _break("p8-digest-change",
                   "wrong refusal code %r" % _code_of(exc))
    else:
        _break("p8-digest-change", "changed digest consumed")


@_probe("p9-relaxed-match")
def _p9():
    # No-downgrade rule: any attempt to consume a permit with a
    # relaxed (non-exact) match is refused as downgrade-refused.
    reg = pres.MissionPermitRegistry()
    digest = pres.parameter_digest({"subject": "s", "resource": "r",
                                    "action": "a"})
    lease = reg.issue("appr-0001", digest)
    try:
        reg.consume(lease["lease_id"], digest, match="prefix")
    except pres.FaithfulnessError as exc:
        if _code_of(exc) == "downgrade-refused":
            _held("p9-relaxed-match",
                  "relaxed match refused downgrade-refused")
        else:
            _break("p9-relaxed-match",
                   "wrong refusal code %r" % _code_of(exc))
    else:
        _break("p9-relaxed-match", "relaxed match consumed")


@_probe("p10-missing-presentation")
def _p10():
    # verify_seal with no (or malformed) presentation fails closed as
    # presentation-missing — never "there was nothing to check".
    rec = _record_fixture()
    for bad in (None, {}, {"presentation_text": "x"}):
        try:
            ar.verify_seal(rec, bad)
        except pres.FaithfulnessError as exc:
            if _code_of(exc) != "presentation-missing":
                _break("p10-missing-presentation",
                       "wrong refusal code %r for %r"
                       % (_code_of(exc), bad))
                return
        else:
            _break("p10-missing-presentation",
                   "missing presentation verified OK for %r" % (bad,))
            return
    _held("p10-missing-presentation", "fail-closed presentation-missing")


@_probe("p11-mission-bound-seal")
def _p11():
    # Mission-bound seals: a seal stamped with the request's
    # parameter_digest is accepted when the authorization path
    # presents the same digest, and refused when it presents a
    # different one (retargeting onto other parameters). The refusal
    # must fire BEFORE decide.
    rec = _record_fixture()
    digest = pres.parameter_digest({"subject": "agent-7",
                                    "resource": "/etc/app/config.yaml",
                                    "action": "write_file"})
    other = pres.parameter_digest({"subject": "other"})
    sealed = ar.seal_approval(rec, ar.render_approval(rec), signer="op-1",
                             parameter_digest=digest)
    queue = _StubQueue(rec)
    got = ar.guarded_decide(queue, rec["id"], True, "ok", sealed=sealed,
                            parameter_digest=digest)
    assert got[0] == "decided"
    queue2 = _StubQueue(rec)
    try:
        ar.guarded_decide(queue2, rec["id"], True, "ok", sealed=sealed,
                          parameter_digest=other)
    except pres.FaithfulnessError as exc:
        if _code_of(exc) != "mission-binding-mismatch":
            _break("p11-mission-bound-seal",
                   "wrong refusal code %r" % _code_of(exc))
            return
    else:
        _break("p11-mission-bound-seal",
               "retargeted parameter_digest was not refused")
        return
    if queue2.decide_calls:
        _break("p11-mission-bound-seal", "decide ran before the refusal")
        return
    _held("p11-mission-bound-seal",
          "matching binding accepted; retarget refused mission-binding-mismatch")


# ----------------------------------------------------------------------
# Runner.
# ----------------------------------------------------------------------

def _run_green_checks():
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_presentation_faith.py",
                 "tests/test_arap.py"):
        path = os.path.join(REPO, unit)
        if not os.path.exists(path):
            notes.append((unit, "SKIP", "unit test not present"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", unit.replace("/", ".")[:-3]],
            env=env, cwd=REPO,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        out = proc.stdout.decode("utf-8", "replace")
        if proc.returncode == 0:
            notes.append((unit, "PASS", "adjacent unit suite green"))
        else:
            tail = out[-400:] if out else "no output"
            notes.append((unit, "FAIL", tail))
    return [("green-check", status, "%s: %s" % (name, detail))
            for name, status, detail in notes]


def _run_once():
    _RESULTS.clear()
    names = sorted(_PROBE_FNS)
    if not _IMPORT_OK:
        for name in names:
            _gap(name)
        return [(n, "GAP") for n in names]
    for name in names:
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001 - probe harness
            _record(name, "ERROR", "%s: %s" % (type(exc).__name__, exc))
    return [(n, v) for n, v, _ in _RESULTS]


def main():
    first = _run_once()
    second = _run_once()
    det_ok = [v for _, v in first] == [v for _, v in second]
    green = _run_green_checks()
    held = sum(1 for _, v in first if v == "HELD")
    gap = sum(1 for _, v in first if v == "GAP")
    brk = sum(1 for _, v in first if v == "BREAK")
    err = sum(1 for _, v in first if v == "ERROR")
    print("w220 faithfulness probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "(%d probes, determinism %s)"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in _RESULTS:
        print("  %-55s %s %s" % (name, verdict, detail))
    for name, status, detail in green:
        print("  %-55s %s %s" % (name, status, detail))
    if not _IMPORT_OK:
        print("import failed (pristine): %r" % (_IMPORT_ERR,))
    if brk or err or not det_ok:
        return 1
    if any(s not in ("PASS", "SKIP") for _, s, _ in green):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
