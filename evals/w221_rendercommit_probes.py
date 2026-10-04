#!/usr/bin/env python3
"""Wave-221 lane A: approval rendering commitments — the mission-bound STEAL.

Seam under test: gov/render_commit.py (new) + gov/approval_render.py
(additive wiring only).

mission-bound lesson: a ``consent_rendering_hash`` is a hash-anchored,
replayable commitment to EXACTLY what the approver was shown —
explicitly non-authorizing. This lane binds it into the wave-220
approval pipeline:

* ``gov/render_commit.commit(render_bytes, artifact_digest,
  renderer_id)`` returns a ``RenderingCommitment``
  ``{artifact_digest, render_hash, rendered_at, renderer_id,
  render_policy_digest}`` with ``render_hash = sha256:<hex>`` over the
  exact bytes the approver saw. The commitment NEVER carries
  authority — it is a replayable record, not a grant.
* ``gov/render_commit.verify(commitment, replay_bytes)`` replays:
  recomputes the hash and refuses with the named code
  ``rendering-commitment-broken`` on mismatch.
* ``gov/approval_render.seal_approval(..., rendering_commitment=None)``
  ATTACHES the commitment to the sealed envelope; with the option
  absent the envelope keys are byte-identical to wave-220 (legacy).
* ``gov/approval_render.verify_seal`` replays the commitment against
  the sealed presentation text; a commitment whose render_hash does
  not match the replay refuses with the existing wave-220 code
  ``display-hash-mismatch``.

Attack shapes: tampered replay bytes, cross-artifact replay, forged
presentation with a stale commitment, commitment offered as an
authority (permit redeem), legacy approval byte-identity.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-220 HEAD
c0c25caa5d7cfd83b2cb0fcf92bd305d65fb34b4.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (modules absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g221a
  TMPDIR=/var/tmp/g221a ~/workspace/.gov-venv/bin/python evals/w221_rendercommit_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g221a-u \\
      ~/workspace/.gov-venv/bin/python evals/w221_rendercommit_probes.py
"""

import hashlib
import os
import secrets
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w221-rendercommit-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g221a-%d" % os.getpid()
os.environ.setdefault("TMPDIR", _TMPDIR_FALLBACK)
try:
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
except OSError:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import render_commit as rc  # noqa: E402
    from gov import approval_render as ar  # noqa: E402
    from gov import presentation as pres  # noqa: E402
    from gov import permit_leases as pl  # noqa: E402
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine run has no modules
    rc = None
    ar = None
    pres = None
    pl = None
    _IMPORT_OK = False
    _IMPORT_ERR = exc


_RESULTS = []


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md): this battery
# records HELD/GAP/BREAK/ERROR on probes and PASS/SKIP/FAIL on its
# depth-1 green checks; the canonical emission vocabulary is
# BREAK/HELD/ERROR/SKIP, mapped red-first (PASS->HELD, GAP/FAIL->BREAK).
# Probe logic, verdict computation and count code are untouched -- only
# the print loop below maps.
_VERDICT_MAP = {
    "PASS": "HELD", "HELD": "HELD", "GREEN": "HELD",
    "FAIL": "BREAK", "BROKEN": "BREAK", "GAP": "BREAK",
    "RED": "BREAK", "BREAK": "BREAK",
    "ERROR": "ERROR", "SKIP": "SKIP", "SKIPPED": "SKIP",
}

def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))


def _held(name, detail=""):
    _record(name, "HELD", detail)


def _gap(name):
    _record(name, "GAP", "module absent on pristine tree")


def _break(name, detail):
    _record(name, "BREAK", detail)


def _code_of(exc):
    return getattr(exc, "code", None)


def _record_fixture(**over):
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


class _StubQueue(object):
    def __init__(self, record):
        self._record = record
        self.decide_calls = []

    def get(self, approval_id):
        return dict(self._record)

    def decide(self, approval_id, approved, reason, **kw):
        self.decide_calls.append((approval_id, approved, reason, kw))
        return ("decided", approval_id, approved, reason)


def _seal_with_commitment(record, signer="op-1", tamper=None):
    """Render, commit the render bytes, seal with the commitment.

    ``tamper`` is an optional dict of sealed-envelope overrides applied
    AFTER sealing (attacker step).
    """
    presentation = ar.render_approval(record)
    commitment = rc.commit(presentation["text"].encode("utf-8"),
                           pres.artifact_digest(record),
                           renderer_id="queue-view")
    sealed = ar.seal_approval(record, presentation, signer=signer,
                              rendering_commitment=commitment)
    if tamper:
        for key, value in tamper.items():
            sealed[key] = value
    return record, presentation, commitment, sealed


_PROBE_FNS = {}


def probe(fn):
    _PROBE_FNS[fn.__name__] = fn
    return fn


@probe
def p01_commit_verify_exact_replay():
    render_bytes = b"APPROVAL appr-0001\naction: write_file\n"
    artifact = "sha256:" + hashlib.sha256(b"packet").hexdigest()
    commitment = rc.commit(render_bytes, artifact, renderer_id="op-1")
    expected_keys = {"artifact_digest", "render_hash", "rendered_at",
                     "renderer_id", "render_policy_digest"}
    if set(commitment) != expected_keys:
        _break("p01-commit-verify-exact-replay",
               "commitment keys %s != %s" % (sorted(commitment), sorted(expected_keys)))
        return
    want = "sha256:" + hashlib.sha256(render_bytes).hexdigest()
    if commitment["render_hash"] != want:
        _break("p01-commit-verify-exact-replay",
               "render_hash %r != independently computed %r"
               % (commitment["render_hash"], want))
        return
    if not rc.verify(commitment, render_bytes):
        _break("p01-commit-verify-exact-replay",
               "exact replay refused")
        return
    _held("p01-commit-verify-exact-replay", "fields pinned; exact replay verifies")


@probe
def p02_tampered_replay_refused():
    commitment = rc.commit(b"seen bytes", "sha256:" + "0" * 64,
                           renderer_id="op-1")
    try:
        rc.verify(commitment, b"seen bytes!")
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "rendering-commitment-broken":
            _held("p02-tampered-replay-refused",
                  "tampered replay refused rendering-commitment-broken")
            return
        _break("p02-tampered-replay-refused",
               "wrong refusal code %r" % (_code_of(exc),))
        return
    _break("p02-tampered-replay-refused", "tampered replay verified")


@probe
def p03_cross_artifact_replay_refused():
    art_a = "sha256:" + hashlib.sha256(b"packet-A").hexdigest()
    commitment = rc.commit(b"render of A", art_a, renderer_id="op-1")
    try:
        rc.verify(commitment, b"render of B")
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "rendering-commitment-broken":
            _held("p03-cross-artifact-replay-refused",
                  "render of B does not replay commitment over render of A")
            return
        _break("p03-cross-artifact-replay-refused",
               "wrong refusal code %r" % (_code_of(exc),))
        return
    _break("p03-cross-artifact-replay-refused",
           "cross-artifact replay verified")


@probe
def p04_malformed_commitment_refused():
    try:
        rc.verify({"render_hash": "sha256:" + "0" * 64}, b"bytes")
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "rendering-commitment-broken":
            _held("p04-malformed-commitment-refused",
                  "malformed commitment refused rendering-commitment-broken")
            return
        _break("p04-malformed-commitment-refused",
               "wrong refusal code %r" % (_code_of(exc),))
        return
    _break("p04-malformed-commitment-refused",
           "malformed commitment verified")


@probe
def p05_commit_rejects_nonbytes():
    try:
        rc.commit("not bytes", "sha256:" + "0" * 64, renderer_id="op-1")
    except (TypeError, ValueError):
        _held("p05-commit-rejects-nonbytes",
              "authoring misuse raises TypeError/ValueError")
        return
    _break("p05-commit-rejects-nonbytes", "non-bytes render accepted")


@probe
def p06_seal_attaches_commitment():
    record = _record_fixture()
    _, presentation, commitment, sealed = _seal_with_commitment(record)
    carried = sealed.get("rendering_commitment")
    if carried is None:
        _break("p06-seal-attaches-commitment",
               "sealed envelope carries no rendering_commitment")
        return
    if carried["render_hash"] != presentation["digest"]:
        _break("p06-seal-attaches-commitment",
               "carried render_hash does not match presentation digest")
        return
    if carried["artifact_digest"] != pres.artifact_digest(record):
        _break("p06-seal-attaches-commitment",
               "carried artifact_digest does not match record digest")
        return
    _held("p06-seal-attaches-commitment",
          "seal carries the commitment, digests bound")


@probe
def p07_verify_seal_replays_commitment():
    record = _record_fixture()
    _, _, _, sealed = _seal_with_commitment(record)
    try:
        ok = ar.verify_seal(record, sealed)
    except Exception as exc:  # noqa: BLE001
        _break("p07-verify-seal-replays-commitment",
               "faithful seal with commitment refused: %r" % (exc,))
        return
    if ok is not True:
        _break("p07-verify-seal-replays-commitment",
               "verify_seal returned %r, not True" % (ok,))
        return
    _held("p07-verify-seal-replays-commitment",
          "faithful seal with commitment verifies")


@probe
def p08_forged_presentation_stale_commitment():
    # Attacker re-renders the presentation for a DIFFERENT record but
    # keeps the original commitment: the replay must refuse.
    record = _record_fixture()
    _, _, commitment, _ = _seal_with_commitment(record)
    other = _record_fixture(id="appr-0002", tool="delete_file")
    presentation2 = ar.render_approval(other)
    forged = ar.seal_approval(other, presentation2, signer="op-1")
    forged["rendering_commitment"] = commitment  # stale: commits to record A
    try:
        ar.verify_seal(other, forged)
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "display-hash-mismatch":
            _held("p08-forged-presentation-stale-commitment",
                  "stale commitment refused display-hash-mismatch")
            return
        _break("p08-forged-presentation-stale-commitment",
               "wrong refusal code %r" % (_code_of(exc),))
        return
    _break("p08-forged-presentation-stale-commitment",
           "forged presentation with stale commitment verified")


@probe
def p09_legacy_seal_byte_identical():
    # With rendering_commitment=None the sealed envelope keeps the exact
    # wave-220 key set: the new seam changes nothing by default.
    record = _record_fixture()
    presentation = ar.render_approval(record)
    sealed = ar.seal_approval(record, presentation, signer="op-1")
    expected = {"approval_id", "artifact_digest", "presentation_digest",
                "presentation_text", "signer", "at"}
    if set(sealed) != expected:
        _break("p09-legacy-seal-byte-identical",
               "sealed keys %s != wave-220 set %s"
               % (sorted(sealed), sorted(expected)))
        return
    queue = _StubQueue(record)
    got = ar.guarded_decide(queue, record["id"], True, "ok", sealed=None)
    if got != ("decided", record["id"], True, "ok"):
        _break("p09-legacy-seal-byte-identical",
               "guarded_decide sealed=None did not pass through: %r" % (got,))
        return
    _held("p09-legacy-seal-byte-identical",
          "legacy envelope and guarded_decide pass-through unchanged")


@probe
def p10_commitment_grants_nothing():
    # A rendering commitment is a replayable record, not an authority:
    # its digest cannot redeem a permit lease, and it carries no
    # authorization fields.
    render_bytes = b"APPROVAL appr-0001\n"
    commitment = rc.commit(render_bytes, "sha256:" + "0" * 64,
                           renderer_id="op-1")
    authy = {"permit_id", "grant", "scope", "authority", "params_digest"}
    if set(commitment) & authy:
        _break("p10-commitment-grants-nothing",
               "commitment carries authorization-shaped fields: %s"
               % (sorted(set(commitment) & authy),))
        return
    lease = pl.PermitLease.issue("perm-1",
                                 params_digest="sha256:" + "1" * 64,
                                 grant_scope={"subject": ["agent-7"],
                                              "action": ["write_file"]})
    try:
        lease.redeem(commitment["render_hash"])
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "permit-digest-mismatch":
            _held("p10-commitment-grants-nothing",
                  "commitment digest redeems nothing: permit-digest-mismatch")
            return
        _break("p10-commitment-grants-nothing",
               "wrong refusal code %r" % (_code_of(exc),))
        return
    _break("p10-commitment-grants-nothing",
           "a rendering commitment redeemed a permit")


def _run_green_checks():
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_presentation_faith.py",
                 "tests/test_permit_leases.py"):
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
    status = "PASS" if all(s in ("PASS", "SKIP") for _, s, _ in notes) else "FAIL"
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
    final = [(n, _VERDICT_MAP[v], d) for n, v, d in _RESULTS]
    # Green-check pids are renamed value-only ("/" -> "_") so every
    # emitted pid stays inside [A-Za-z0-9_.-] (D7).
    final += [(n.replace("/", "_"), _VERDICT_MAP[s], d)
              for n, s, d in green]
    probe_lines.emit(final)
    brk_c = sum(1 for _, v, _ in final if v == "BREAK")
    held_c = sum(1 for _, v, _ in final if v == "HELD")
    err_c = sum(1 for _, v, _ in final if v == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        final, brk_c, held_c, err_c)
    if not _coh_ok:
        print("coherence-WARNING: %s" % ("; ".join(_coh_diags)))
    print("%d BREAK / %d HELD / %d ERROR"
          % (brk_c, held_c, err_c))
    print("w221 rendering-commitment probes: %d HELD / %d GAP / %d BREAK / "
          "%d ERROR (%d probes, determinism %s)"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    if not _IMPORT_OK:
        print("import failed (pristine): %r" % (_IMPORT_ERR,))
    if brk or err or not det_ok:
        return 1
    if any(s not in ("PASS", "SKIP") for _, s, _ in green):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
