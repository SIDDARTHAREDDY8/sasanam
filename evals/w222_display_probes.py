#!/usr/bin/env python3
"""Wave-222 lane A: deterministic display attestation — the PIP-010 ADAPT.

Seam under test: gov/display_attest.py (new). No existing-file changes.

Pattern (re-derived prose, not EMILIA text): rendering is a PURE
DETERMINISTIC FUNCTION of the signed bytes. A ``DisplayAttestation``
``{artifact_digest, render_policy_digest, renderer_id,
render_bytes_digest, attested_at}`` records what the approver was
shown; ``verify_attestation(attestation, artifact_bytes)`` re-derives
the render from the signed artifact bytes under the pinned render
policy and refuses fail-closed with the named code
``display-rederivation-failed`` on any mismatch.

Commitment composition (wave-221 ``gov/render_commit``): an attestation
that claims a renderer (non-empty ``renderer_id``) MUST be backed by a
rendering commitment, or verification fails closed with the named code
``display-no-render-commitment``. Legacy attestations
(``renderer_id == ""``) stay verifiable by pure re-derivation — no
backward break.

Honest caveat (module docstring): this proves the RENDERING is
deterministic from signed bytes; it does NOT solve WYSIWYS — whether
the approver looked at / understood the display is a deployment
boundary. An attestation never authorizes.

Attack shapes: tampered artifact bytes, tampered / swapped / unknown
render policy, renderer claim without commitment, stale commitment,
attestation offered as an authority, non-deterministic policy
registration, legacy seal byte-identity.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-221 HEAD
194588b78321b7d8b9bc454799c55a32ca2756e3.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g222a
  TMPDIR=/var/tmp/g222a ~/workspace/.gov-venv/bin/python evals/w222_display_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g222a-u \\
      ~/workspace/.gov-venv/bin/python evals/w222_display_probes.py
"""

import hashlib
import os
import secrets
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w222-display-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g222a-%d" % os.getpid()
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
    from gov import display_attest as da  # noqa: E402
    from gov import approval_render as ar  # noqa: E402
    from gov import presentation as pres  # noqa: E402
    from gov import render_commit as rc  # noqa: E402
    from gov import permit_leases as pl  # noqa: E402
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine run has no module
    da = None
    ar = None
    pres = None
    rc = None
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


def _attest_pair(record, renderer_id="", commitment=None):
    """Build (attestation, artifact_bytes, render_bytes) for a fixture."""
    artifact_bytes = da.approval_render_input(record)
    artifact_digest = "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
    render_bytes = ar.render_approval(record)["text"].encode("utf-8")
    attestation = da.attest_display(
        artifact_digest, da.APPROVAL_DISPLAY_V1_DIGEST, renderer_id,
        render_bytes, rendering_commitment=commitment)
    return attestation, artifact_bytes, render_bytes


_PROBE_FNS = {}


def probe(fn):
    _PROBE_FNS[fn.__name__] = fn
    return fn


@probe
def p01_attest_fields_and_legacy_verify():
    attestation, artifact_bytes, _ = _attest_pair(_record_fixture())
    expected = {"artifact_digest", "render_policy_digest", "renderer_id",
                "render_bytes_digest", "attested_at"}
    if set(attestation) != expected:
        _break("p01-attest-fields-and-legacy-verify",
               "attestation keys %s != %s"
               % (sorted(attestation), sorted(expected)))
        return
    if not attestation["render_bytes_digest"].startswith("sha256:"):
        _break("p01-attest-fields-and-legacy-verify",
               "render_bytes_digest %r is not sha256:<hex>"
               % (attestation["render_bytes_digest"],))
        return
    try:
        ok = da.verify_attestation(attestation, artifact_bytes)
    except Exception as exc:  # noqa: BLE001
        _break("p01-attest-fields-and-legacy-verify",
               "legacy attestation refused: %r" % (exc,))
        return
    if ok is not True:
        _break("p01-attest-fields-and-legacy-verify",
               "verify_attestation returned %r, not True" % (ok,))
        return
    _held("p01-attest-fields-and-legacy-verify",
          "fields pinned; legacy (renderer_id='') verifies by re-derivation")


@probe
def p02_rederivation_matches_real_renderer():
    # The re-derivation mirror must agree byte-for-byte with the REAL
    # renderer across fixture variants: independent implementation of
    # the same render, so agreement is meaningful (catches drift in
    # either). This is the PIP-010 core property.
    variants = [
        _record_fixture(),
        _record_fixture(id="appr-0002", tool="delete_file",
                        args={"path": "/var/data/x"},
                        packet_risk_score=90,
                        packet_risk_factors=["destructive", "irreversible"]),
        _record_fixture(id="appr-0003", tool="read_file",
                        args={"path": "/etc/motd"},
                        packet_risk_score=5, packet_risk_factors=[],
                        policy_context={"path_resolved": "/etc/motd",
                                        "memory_provenance": ["m1"],
                                        "attachment_carriers": ["voice-memo"]}),
    ]
    for rec in variants:
        artifact_bytes = da.approval_render_input(rec)
        want = ar.render_approval(rec)["text"].encode("utf-8")
        try:
            got = da.rederive(artifact_bytes, da.APPROVAL_DISPLAY_V1_DIGEST)
        except Exception as exc:  # noqa: BLE001
            _break("p02-rederivation-matches-real-renderer",
                   "rederive raised for %s: %r" % (rec["id"], exc))
            return
        if got != want:
            _break("p02-rederivation-matches-real-renderer",
                   "re-derivation diverged from real renderer for %s "
                   "(%d vs %d bytes)" % (rec["id"], len(got), len(want)))
            return
    _held("p02-rederivation-matches-real-renderer",
          "re-derivation byte-identical to real renderer, 3 variants")


@probe
def p03_tampered_artifact_bytes_refused():
    record = _record_fixture()
    attestation, artifact_bytes, _ = _attest_pair(record)
    # Flip a byte inside a JSON string value: stays parseable, changes
    # the signed bytes.
    tampered = artifact_bytes.replace(b"appr-0001", b"appr-0002")
    if tampered == artifact_bytes:
        _break("p03-tampered-artifact-bytes-refused",
               "fixture lacks the expected marker bytes")
        return
    try:
        da.verify_attestation(attestation, tampered)
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "display-rederivation-failed":
            _held("p03-tampered-artifact-bytes-refused",
                  "tampered artifact bytes refused "
                  "display-rederivation-failed")
            return
        _break("p03-tampered-artifact-bytes-refused",
               "wrong refusal code %r" % (_code_of(exc),))
        return
    _break("p03-tampered-artifact-bytes-refused",
           "tampered artifact bytes verified")


@probe
def p04_unknown_policy_digest_refused():
    attestation, artifact_bytes, _ = _attest_pair(_record_fixture())
    forged = dict(attestation)
    forged["render_policy_digest"] = "sha256:" + "ff" * 32
    try:
        da.verify_attestation(forged, artifact_bytes)
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "display-policy-unknown":
            _held("p04-unknown-policy-digest-refused",
                  "unknown policy digest fails closed display-policy-unknown")
            return
        _break("p04-unknown-policy-digest-refused",
               "wrong refusal code %r" % (_code_of(exc),))
        return
    _break("p04-unknown-policy-digest-refused",
           "unknown policy digest verified")


@probe
def p05_swapped_policy_refused():
    # Attacker substitutes a different registered policy's digest into
    # the attestation: re-derivation under the wrong policy must fail.
    alt_digest = "sha256:" + "ab" * 32
    da.register_render_policy("test-alt-policy", alt_digest,
                              lambda b: b"ALT RENDER")
    try:
        attestation, artifact_bytes, _ = _attest_pair(_record_fixture())
        forged = dict(attestation)
        forged["render_policy_digest"] = alt_digest
        try:
            da.verify_attestation(forged, artifact_bytes)
        except Exception as exc:  # noqa: BLE001
            if _code_of(exc) == "display-rederivation-failed":
                _held("p05-swapped-policy-refused",
                      "policy substitution refused "
                      "display-rederivation-failed")
                return
            _break("p05-swapped-policy-refused",
                   "wrong refusal code %r" % (_code_of(exc),))
            return
        _break("p05-swapped-policy-refused",
               "substituted policy verified")
    finally:
        da.unregister_render_policy(alt_digest)


@probe
def p06_renderer_without_commitment_refused():
    record = _record_fixture()
    artifact_bytes = da.approval_render_input(record)
    artifact_digest = "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
    render_bytes = ar.render_approval(record)["text"].encode("utf-8")
    attestation = da.attest_display(artifact_digest,
                                    da.APPROVAL_DISPLAY_V1_DIGEST,
                                    "queue-view", render_bytes)
    try:
        da.verify_attestation(attestation, artifact_bytes)
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "display-no-render-commitment":
            _held("p06-renderer-without-commitment-refused",
                  "renderer claim without commitment fails closed "
                  "display-no-render-commitment")
            return
        _break("p06-renderer-without-commitment-refused",
               "wrong refusal code %r" % (_code_of(exc),))
        return
    _break("p06-renderer-without-commitment-refused",
           "renderer claim without commitment verified")


@probe
def p07_commitment_backed_attestation_verifies():
    record = _record_fixture()
    artifact_bytes = da.approval_render_input(record)
    artifact_digest = "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
    render_bytes = ar.render_approval(record)["text"].encode("utf-8")
    commitment = rc.commit(render_bytes, artifact_digest,
                           renderer_id="queue-view",
                           render_policy_digest=da.APPROVAL_DISPLAY_V1_DIGEST)
    attestation = da.attest_display(artifact_digest,
                                    da.APPROVAL_DISPLAY_V1_DIGEST,
                                    "queue-view", render_bytes,
                                    rendering_commitment=commitment)
    try:
        ok = da.verify_attestation(attestation, artifact_bytes,
                                   rendering_commitment=commitment)
    except Exception as exc:  # noqa: BLE001
        _break("p07-commitment-backed-attestation-verifies",
               "commitment-backed attestation refused: %r" % (exc,))
        return
    if ok is not True:
        _break("p07-commitment-backed-attestation-verifies",
               "verify_attestation returned %r, not True" % (ok,))
        return
    _held("p07-commitment-backed-attestation-verifies",
          "renderer claim + backing commitment verifies end to end")


@probe
def p08_stale_commitment_refused():
    record = _record_fixture()
    attestation, artifact_bytes, render_bytes = _attest_pair(
        record, renderer_id="queue-view")
    stale = rc.commit(b"some other render", attestation["artifact_digest"],
                      renderer_id="queue-view")
    try:
        da.verify_attestation(attestation, artifact_bytes,
                              rendering_commitment=stale)
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "display-rederivation-failed":
            _held("p08-stale-commitment-refused",
                  "stale commitment refused display-rederivation-failed")
            return
        _break("p08-stale-commitment-refused",
               "wrong refusal code %r" % (_code_of(exc),))
        return
    _break("p08-stale-commitment-refused",
           "stale commitment verified")


@probe
def p09_attestation_grants_nothing():
    # An attestation is a replayable record, not an authority: its
    # digest cannot redeem a permit lease, and it carries no
    # authorization fields.
    attestation, _, _ = _attest_pair(_record_fixture())
    authy = {"permit_id", "grant", "scope", "authority", "params_digest"}
    if set(attestation) & authy:
        _break("p09-attestation-grants-nothing",
               "attestation carries authorization-shaped fields: %s"
               % (sorted(set(attestation) & authy),))
        return
    lease = pl.PermitLease.issue("perm-1",
                                 params_digest="sha256:" + "1" * 64,
                                 grant_scope={"subject": ["agent-7"],
                                              "action": ["write_file"]})
    try:
        lease.redeem(attestation["render_bytes_digest"])
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "permit-digest-mismatch":
            _held("p09-attestation-grants-nothing",
                  "attestation digest redeems nothing: "
                  "permit-digest-mismatch")
            return
        _break("p09-attestation-grants-nothing",
               "wrong refusal code %r" % (_code_of(exc),))
        return
    _break("p09-attestation-grants-nothing",
           "a display attestation redeemed a permit")


@probe
def p10_nondeterministic_policy_rejected():
    def flaky(artifact_bytes):
        return b"render@" + str(time.time_ns()).encode("ascii")

    try:
        da.register_render_policy("test-flaky", "sha256:" + "cd" * 32, flaky)
    except (TypeError, ValueError):
        _held("p10-nondeterministic-policy-rejected",
              "non-deterministic render_fn refused at registration")
        return
    _break("p10-nondeterministic-policy-rejected",
           "non-deterministic render_fn registered")


@probe
def p11_attest_with_mismatched_commitment_refused():
    record = _record_fixture()
    artifact_bytes = da.approval_render_input(record)
    artifact_digest = "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
    render_bytes = ar.render_approval(record)["text"].encode("utf-8")
    foreign = rc.commit(b"another render entirely", artifact_digest,
                        renderer_id="queue-view")
    try:
        da.attest_display(artifact_digest, da.APPROVAL_DISPLAY_V1_DIGEST,
                          "queue-view", render_bytes,
                          rendering_commitment=foreign)
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "rendering-commitment-broken":
            _held("p11-attest-with-mismatched-commitment-refused",
                  "attaching a foreign commitment fails closed at attest "
                  "time: rendering-commitment-broken")
            return
        _break("p11-attest-with-mismatched-commitment-refused",
               "wrong refusal code %r" % (_code_of(exc),))
        return
    _break("p11-attest-with-mismatched-commitment-refused",
           "foreign commitment attached to attestation")


@probe
def p12_legacy_seal_paths_unchanged():
    # This lane modifies no existing files (additive-only): the
    # wave-220 seal envelope key set and the guarded_decide
    # pass-through are pinned here as a regression tripwire. Legacy
    # byte-identity holds by construction (empty diff on existing
    # files); this probe guards the seams, not the bytes.
    record = _record_fixture()
    presentation = ar.render_approval(record)
    sealed = ar.seal_approval(record, presentation, signer="op-1")
    expected = {"approval_id", "artifact_digest", "presentation_digest",
                "presentation_text", "signer", "at"}
    if set(sealed) != expected:
        _break("p12-legacy-seal-paths-unchanged",
               "sealed keys %s != wave-220 set %s"
               % (sorted(sealed), sorted(expected)))
        return

    class _StubQueue(object):
        def __init__(self, record):
            self._record = record

        def get(self, approval_id):
            return dict(self._record)

        def decide(self, approval_id, approved, reason, **kw):
            return ("decided", approval_id, approved, reason)

    got = ar.guarded_decide(_StubQueue(record), record["id"], True, "ok",
                            sealed=None)
    if got != ("decided", record["id"], True, "ok"):
        _break("p12-legacy-seal-paths-unchanged",
               "guarded_decide sealed=None did not pass through: %r" % (got,))
        return
    _held("p12-legacy-seal-paths-unchanged",
          "legacy envelope key set and pass-through unchanged; lane is "
          "additive-only (no existing files modified)")


def _run_green_checks():
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_render_commit.py",
                 "tests/test_presentation_faith.py"):
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
    print("w222 display-attestation probes: %d HELD / %d GAP / %d BREAK / "
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
