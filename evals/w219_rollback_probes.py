#!/usr/bin/env python3
"""Wave-219 lane C: anti-rollback-beyond-expiry battery — the in-toto/TUF ADAPT.

Seam under test: gov/version_manifest.py — a durable seen-version
registry with atomic version manifests. In-memory version floors (jail
and measurement registries) die with the process; a deployment rolled
back to an OLDER-YET-STILL-VALID policy/trust bundle would accept it.
This module makes that rollback loud:

* atomic version manifests pinning {policy_name: {version, digest}}
  (all-or-nothing; a partial manifest is refused and commits nothing),
* distinct refusal codes: rollback-detected vs policy-expired vs
  policy-unknown,
* a seen-version registry recording the highest version ever seen per
  policy name (durable across the deployment's restarts),
* explicit bootstrap ceremony (registry starts empty only via
  bootstrap, with an audit entry),
* tighten-only opt-in wiring into JailPolicyRegistry.activate,
  MeasurementPolicyRegistry.activate, and promote()'s quorum gate
  (absent guard = legacy byte-identical).

Attack shapes: cross-restart rollback to an older-but-valid policy,
rollback-vs-expiry code confusion, partial-manifest commit, manifest
re-signing by a rogue key, double bootstrap, manifest downgrade,
same-version digest tamper, replay confusion, downgrade-after-upgrade.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-218 HEAD
7548a27826096ddb47058e8e77c570fc5a0f6931.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g219c
  TMPDIR=/var/tmp/g219c ~/workspace/.gov-venv/bin/python evals/w219_rollback_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g219c-u \\
      ~/workspace/.gov-venv/bin/python evals/w219_rollback_probes.py
"""

import hashlib
import json
import os
import re
import secrets
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w219-rollback-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g219c-%d" % os.getpid()
os.environ.setdefault("TMPDIR", _TMPDIR_FALLBACK)
try:
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
except OSError:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import version_manifest as vm  # noqa: E402
    from gov import jail_policy as jp  # noqa: E402
    from gov import measurement_policy as mp  # noqa: E402
    from gov import quorum_policy as qp  # noqa: E402
    from gov import sign_deploy_namespaces as sdn  # noqa: E402
    from gov import ed25519 as _ed  # noqa: E402
    from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine run has no module
    vm = None
    _IMPORT_OK = False
    _IMPORT_ERR = exc

_RESULTS = []
_PROBE_FNS = {}

NOW = 1785000000
FULL = {"timeout", "rlimit", "netns", "pidns", "pivot_root", "seccomp",
        "privdrop"}


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


# ----------------------------------------------------------------------
# Harness helpers (only meaningful when the module is present).
# ----------------------------------------------------------------------

def _issuer():
    seed = _ed.generate_seed()
    return seed, _ed.publickey(seed)


def _manifest_signer():
    return Ed25519Signer(bytes.fromhex("a1" * 32))


def _rogue_signer():
    return Ed25519Signer(bytes.fromhex("b2" * 32))


def _digest_for(name, version):
    return "sha256:" + hashlib.sha256(
        ("policy-%s-v%d" % (name, version)).encode("utf-8")).hexdigest()


def _entries(*pairs):
    return {name: {"version": v, "digest": _digest_for(name, v)}
            for name, v in pairs}


def _guard_with(entries, audit=None):
    """A bootstrapped SeenVersionRegistry over the given entries."""
    signer = _manifest_signer()
    manifest = vm.make_manifest(entries, signer)
    guard = vm.SeenVersionRegistry()
    guard.bootstrap(manifest, signer.public_key, audit=audit, now=NOW)
    return guard


def _jail_envelope(policy_name, version, seed, not_before=NOW - 3600,
                   not_after=NOW + 3600):
    body = jp.make_policy_body(policy_name=policy_name, version=version,
                                writable_dirs=["/output"], timeout_s=5,
                                not_before=not_before, not_after=not_after)
    norm = jp.validate_policy_body(body)
    return ({"body": norm, "signature": jp.sign_policy(seed, norm)},
            "sha256:" + hashlib.sha256(
                jp.policy_signing_bytes(norm)).hexdigest())


def _measurement_envelope(policy_name, version, seed,
                          not_before=NOW - 3600, not_after=NOW + 3600):
    body = mp.make_policy_body(policy_name=policy_name, version=version,
                               required_measurements=[("os", "ab" * 32)],
                               not_before=not_before, not_after=not_after,
                               signer_kid="issuer-1")
    return body, mp.sign_policy(seed, body), \
        "sha256:" + hashlib.sha256(
            mp.policy_signing_bytes(body)).hexdigest()


# ----------------------------------------------------------------------
# Probes.
# ----------------------------------------------------------------------

@_probe("rollback_older_valid_refused_with_rollback_code")
def _p_rollback():
    guard = _guard_with(_entries(("tool-python", 5)))
    # v5 is seen first (durable history), then a rollback to v3 which is
    # still inside its validity window.
    guard.authorize_activation("tool-python", 5,
                               digest=_digest_for("tool-python", 5),
                               not_after=NOW + 3600, now=NOW)
    try:
        guard.authorize_activation("tool-python", 3,
                                   digest=_digest_for("tool-python", 3),
                                   not_after=NOW + 3600, now=NOW)
    except vm.VersionManifestError as exc:
        if _code_of(exc) == "rollback-detected":
            _held("rollback_older_valid_refused_with_rollback_code",
                  "v3 < seen v5 refused as rollback-detected")
        else:
            _break("rollback_older_valid_refused_with_rollback_code",
                   "wrong code: %r (want rollback-detected)" % _code_of(exc))
    else:
        _break("rollback_older_valid_refused_with_rollback_code",
               "older-valid policy ACCEPTED after newer seen")


@_probe("expiry_has_distinct_code")
def _p_expiry():
    guard = _guard_with(_entries(("tool-python", 5)))
    try:
        guard.authorize_activation("tool-python", 4,
                                   digest=_digest_for("tool-python", 4),
                                   not_after=NOW - 1, now=NOW)
    except vm.VersionManifestError as exc:
        if _code_of(exc) == "policy-expired":
            _held("expiry_has_distinct_code",
                  "expired candidate refused as policy-expired")
        else:
            _break("expiry_has_distinct_code",
                   "wrong code: %r (want policy-expired)" % _code_of(exc))
    else:
        _break("expiry_has_distinct_code", "expired policy ACCEPTED")


@_probe("unknown_name_refused")
def _p_unknown():
    guard = _guard_with(_entries(("tool-python", 5)))
    try:
        guard.authorize_activation("tool-rust", 1,
                                   digest=_digest_for("tool-rust", 1),
                                   not_after=NOW + 3600, now=NOW)
    except vm.VersionManifestError as exc:
        if _code_of(exc) == "policy-unknown":
            _held("unknown_name_refused",
                  "unpinned name refused as policy-unknown")
        else:
            _break("unknown_name_refused",
                   "wrong code: %r (want policy-unknown)" % _code_of(exc))
    else:
        _break("unknown_name_refused", "unpinned name ACCEPTED")


@_probe("partial_manifest_commits_nothing")
def _p_partial():
    signer = _manifest_signer()
    bad_entries = {"tool-python": {"version": 5,
                                   "digest": _digest_for("tool-python", 5)},
                   "tool-rust": {"version": 1}}  # missing digest: partial
    guard = vm.SeenVersionRegistry()
    try:
        guard.bootstrap(vm.make_manifest(bad_entries, signer),
                        signer.public_key, now=NOW)
    except vm.VersionManifestError as exc:
        if _code_of(exc) != "manifest-refused":
            _break("partial_manifest_commits_nothing",
                   "wrong code: %r" % _code_of(exc))
            return
    else:
        _break("partial_manifest_commits_nothing",
               "partial manifest ACCEPTED")
        return
    # Atomicity: nothing was committed — the registry is still empty and a
    # good manifest bootstraps cleanly afterwards.
    guard2 = vm.SeenVersionRegistry()
    guard2.bootstrap(vm.make_manifest(_entries(("ok", 1)), signer),
                     signer.public_key, now=NOW)
    try:
        guard.authorize_activation("tool-python", 5,
                                   digest=_digest_for("tool-python", 5),
                                   not_after=NOW + 3600, now=NOW)
    except vm.VersionManifestError as exc:
        if _code_of(exc) == "bootstrap-required":
            _held("partial_manifest_commits_nothing",
                  "partial manifest refused; registry un-bootstrapped")
        else:
            _break("partial_manifest_commits_nothing",
                   "registry polluted: %r" % _code_of(exc))
    else:
        _break("partial_manifest_commits_nothing",
               "registry polluted by refused manifest")


@_probe("rogue_key_manifest_refused")
def _p_rogue():
    signer = _manifest_signer()
    rogue = _rogue_signer()
    guard = vm.SeenVersionRegistry()
    try:
        guard.bootstrap(vm.make_manifest(_entries(("tool-python", 5)), rogue),
                        signer.public_key, now=NOW)
    except vm.VersionManifestError as exc:
        if _code_of(exc) == "manifest-refused":
            _held("rogue_key_manifest_refused",
                  "rogue-signed manifest refused")
        else:
            _break("rogue_key_manifest_refused",
                   "wrong code: %r" % _code_of(exc))
    else:
        _break("rogue_key_manifest_refused",
               "rogue-signed manifest ACCEPTED")


@_probe("bootstrap_audited_and_single")
def _p_bootstrap():
    signer = _manifest_signer()
    audit = []
    guard = vm.SeenVersionRegistry()
    guard.bootstrap(vm.make_manifest(_entries(("tool-python", 5)), signer),
                    signer.public_key, audit=audit, now=NOW)
    bootstraps = [e for e in audit
                  if e.get("event") == "rollback-guard-bootstrap"]
    if not bootstraps:
        _break("bootstrap_audited_and_single", "bootstrap not audited")
        return
    try:
        guard.bootstrap(vm.make_manifest(_entries(("tool-python", 6)),
                                         signer),
                        signer.public_key, audit=audit, now=NOW)
    except vm.VersionManifestError as exc:
        if _code_of(exc) == "already-bootstrapped":
            _held("bootstrap_audited_and_single",
                  "bootstrap audited; second bootstrap refused")
        else:
            _break("bootstrap_audited_and_single",
                   "wrong code: %r" % _code_of(exc))
    else:
        _break("bootstrap_audited_and_single",
               "second bootstrap ACCEPTED (history rewritable)")


@_probe("manifest_update_atomic_and_no_downgrade")
def _p_update():
    signer = _manifest_signer()
    audit = []
    guard = _guard_with(_entries(("tool-python", 5)), audit=audit)
    # A bad update commits nothing: the old manifest still governs.
    bad = {"tool-python": {"version": 6, "digest": "not-a-digest"}}
    try:
        guard.update_manifest(vm.make_manifest(bad, signer),
                              signer.public_key, audit=audit, now=NOW)
    except vm.VersionManifestError as exc:
        if _code_of(exc) != "manifest-refused":
            _break("manifest_update_atomic_and_no_downgrade",
                   "wrong code: %r" % _code_of(exc))
            return
    else:
        _break("manifest_update_atomic_and_no_downgrade",
               "bad update ACCEPTED")
        return
    # A manifest downgrade (lower expected version) is refused distinctly.
    try:
        guard.update_manifest(
            vm.make_manifest(_entries(("tool-python", 4)), signer),
            signer.public_key, audit=audit, now=NOW)
    except vm.VersionManifestError as exc:
        if _code_of(exc) != "manifest-downgrade-refused":
            _break("manifest_update_atomic_and_no_downgrade",
                   "wrong code: %r" % _code_of(exc))
            return
    else:
        _break("manifest_update_atomic_and_no_downgrade",
               "manifest downgrade ACCEPTED")
        return
    # A good update (bump + new name) is accepted and audited.
    guard.update_manifest(
        vm.make_manifest(_entries(("tool-python", 6), ("tool-rust", 1)),
                         signer),
        signer.public_key, audit=audit, now=NOW)
    updates = [e for e in audit
               if e.get("event") == "rollback-guard-manifest-update"]
    rep = guard.authorize_activation(
        "tool-rust", 1, digest=_digest_for("tool-rust", 1),
        not_after=NOW + 3600, now=NOW)
    if updates and rep["version"] == 1:
        _held("manifest_update_atomic_and_no_downgrade",
              "bad update inert; downgrade refused; good update applied")
    else:
        _break("manifest_update_atomic_and_no_downgrade",
               "good update did not take effect")


@_probe("same_version_replay_accepted")
def _p_replay():
    guard = _guard_with(_entries(("tool-python", 5)))
    first = guard.authorize_activation(
        "tool-python", 5, digest=_digest_for("tool-python", 5),
        not_after=NOW + 3600, now=NOW)
    second = guard.authorize_activation(
        "tool-python", 5, digest=_digest_for("tool-python", 5),
        not_after=NOW + 3600, now=NOW)
    if first["version"] == 5 and second["version"] == 5 \
            and second.get("replay"):
        _held("same_version_replay_accepted",
              "identical (name, version, digest) replay accepted")
    else:
        _break("same_version_replay_accepted",
               "legitimate replay refused: %r" % (second,))


@_probe("same_version_digest_tamper_refused")
def _p_tamper():
    guard = _guard_with(_entries(("tool-python", 5)))
    guard.authorize_activation("tool-python", 5,
                               digest=_digest_for("tool-python", 5),
                               not_after=NOW + 3600, now=NOW)
    tampered = "sha256:" + "00" * 32
    try:
        guard.authorize_activation("tool-python", 5, digest=tampered,
                                   not_after=NOW + 3600, now=NOW)
    except vm.VersionManifestError as exc:
        if _code_of(exc) == "digest-mismatch":
            _held("same_version_digest_tamper_refused",
                  "same version, different bytes refused")
        else:
            _break("same_version_digest_tamper_refused",
                   "wrong code: %r" % _code_of(exc))
    else:
        _break("same_version_digest_tamper_refused",
               "digest-swapped replay ACCEPTED")


@_probe("upgrade_then_downgrade_refused")
def _p_upgrade_downgrade():
    guard = _guard_with(_entries(("tool-python", 5)))
    guard.authorize_activation("tool-python", 5,
                               digest=_digest_for("tool-python", 5),
                               not_after=NOW + 3600, now=NOW)
    up = guard.authorize_activation("tool-python", 7,
                                    digest=_digest_for("tool-python", 7),
                                    not_after=NOW + 3600, now=NOW)
    try:
        guard.authorize_activation("tool-python", 6,
                                   digest=_digest_for("tool-python", 6),
                                   not_after=NOW + 3600, now=NOW)
    except vm.VersionManifestError as exc:
        if _code_of(exc) == "rollback-detected" and up["floor"] == 7:
            _held("upgrade_then_downgrade_refused",
                  "v7 raised floor; v6 refused as rollback-detected")
        else:
            _break("upgrade_then_downgrade_refused",
                   "wrong code: %r" % _code_of(exc))
    else:
        _break("upgrade_then_downgrade_refused",
               "downgrade after upgrade ACCEPTED")


@_probe("authorize_before_bootstrap_refused")
def _p_pre_bootstrap():
    guard = vm.SeenVersionRegistry()
    try:
        guard.authorize_activation("tool-python", 5,
                                   digest=_digest_for("tool-python", 5),
                                   not_after=NOW + 3600, now=NOW)
    except vm.VersionManifestError as exc:
        if _code_of(exc) == "bootstrap-required":
            _held("authorize_before_bootstrap_refused",
                  "un-bootstrapped registry refuses all activation")
        else:
            _break("authorize_before_bootstrap_refused",
                   "wrong code: %r" % _code_of(exc))
    else:
        _break("authorize_before_bootstrap_refused",
               "un-bootstrapped registry ACCEPTED activation")


@_probe("jail_wiring_cross_restart_rollback_refused")
def _p_jail():
    seed, pub = _issuer()
    env5, digest5 = _jail_envelope("tool-python", 5, seed)
    env3, digest3 = _jail_envelope("tool-python", 3, seed)
    guard = _guard_with({"tool-python": {"version": 5, "digest": digest5}})
    # First lifetime: v5 activates through the guard.
    reg1 = jp.JailPolicyRegistry(pub)
    reg1.activate(env5, now=NOW, features=FULL, rollback_guard=guard)
    # Simulated restart: a FRESH registry (in-memory floor gone) with the
    # same durable guard. v3 is still valid but must be refused.
    reg2 = jp.JailPolicyRegistry(pub)
    try:
        reg2.activate(env3, now=NOW, features=FULL, rollback_guard=guard)
    except Exception as exc:  # noqa: BLE001 - wrapped module error
        if _code_of(exc) == "rollback-detected":
            _held("jail_wiring_cross_restart_rollback_refused",
                  "cross-restart v3 refused with rollback code")
        else:
            _break("jail_wiring_cross_restart_rollback_refused",
                   "wrong code: %r" % _code_of(exc))
    else:
        _break("jail_wiring_cross_restart_rollback_refused",
               "cross-restart rollback ACCEPTED")


@_probe("measurement_wiring_cross_restart_rollback_refused")
def _p_measurement():
    seed, pub = _issuer()
    body5, sig5, digest5 = _measurement_envelope("attest-os", 5, seed)
    body3, sig3, digest3 = _measurement_envelope("attest-os", 3, seed)
    guard = _guard_with({"attest-os": {"version": 5, "digest": digest5}})
    reg1 = mp.MeasurementPolicyRegistry(pub)
    reg1.activate(body5, sig5, now=NOW, rollback_guard=guard)
    reg2 = mp.MeasurementPolicyRegistry(pub)
    try:
        reg2.activate(body3, sig3, now=NOW, rollback_guard=guard)
    except Exception as exc:  # noqa: BLE001 - wrapped module error
        if _code_of(exc) == "rollback-detected":
            _held("measurement_wiring_cross_restart_rollback_refused",
                  "cross-restart v3 refused with rollback code")
        else:
            _break("measurement_wiring_cross_restart_rollback_refused",
                   "wrong code: %r" % _code_of(exc))
    else:
        _break("measurement_wiring_cross_restart_rollback_refused",
               "cross-restart rollback ACCEPTED")


@_probe("quorum_wiring_rollback_refused")
def _p_quorum():
    fseed_a = bytes.fromhex("51" * 32)
    fseed_b = bytes.fromhex("52" * 32)
    signers = [Ed25519Signer(fseed_a), Ed25519Signer(fseed_b)]
    verifiers = [Ed25519Verifier(s.public_key) for s in signers]
    step = qp.load_quorum_step({
        "step_name": "promote",
        "authorized_keyids": [s.key_id for s in signers],
        "threshold": 2,
    })
    step_digest = "sha256:" + hashlib.sha256(json.dumps(
        {"step_name": step.step_name,
         "authorized_keyids": list(step.authorized_keyids),
         "threshold": step.threshold},
        sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    guard = _guard_with({"quorum:promote": {"version": 5,
                                            "digest": step_digest}})
    guard.authorize_activation("quorum:promote", 5, digest=step_digest,
                               now=NOW)

    def _reg_with_links():
        reg = sdn.NamespaceRegistry(verifiers=verifiers, threshold=1)
        reg.stage("skill/q", b"bytes")
        reg.sign("skill/q", [signers[0]])
        links = [qp.make_link_record("promote", "ab" * 32, s)
                 for s in signers]
        return reg, links

    reg, links = _reg_with_links()
    try:
        reg.promote("skill/q", operator_ids=["op1", "op2"],
                    quorum_policy=step, quorum_links=links,
                    quorum_policy_version=3,
                    quorum_rollback_guard=guard)
    except sdn.NamespaceError as exc:
        if exc.code != "quorum-rollback-refused":
            _break("quorum_wiring_rollback_refused",
                   "wrong code: %r" % exc.code)
            return
    else:
        _break("quorum_wiring_rollback_refused",
               "quorum rollback ACCEPTED")
        return
    # Absent guard: legacy byte-identical (no version required, promotes).
    reg2, links2 = _reg_with_links()
    promoted = reg2.promote("skill/q", operator_ids=["op1", "op2"],
                            quorum_policy=step, quorum_links=links2)
    if promoted["status"] == "promoted" \
            and "rollback" not in reg2.audit[-1]["detail"]:
        _held("quorum_wiring_rollback_refused",
              "rollback refused with code; absent guard byte-identical")
    else:
        _break("quorum_wiring_rollback_refused",
               "legacy promote path changed")


@_probe("legacy_paths_byte_identical_without_guard")
def _p_legacy():
    seed, pub = _issuer()
    env5, _digest5 = _jail_envelope("tool-python", 5, seed)
    reg = jp.JailPolicyRegistry(pub)
    body = reg.activate(dict(env5), now=NOW, features=FULL)
    reg_noguard = jp.JailPolicyRegistry(pub)
    body2 = reg_noguard.activate(dict(env5), now=NOW, features=FULL,
                                 rollback_guard=None)
    body5, sig5, _d5 = _measurement_envelope("attest-os", 5, seed)
    mreg = mp.MeasurementPolicyRegistry(pub)
    mreg.activate(dict(body5), sig5, now=NOW)
    mreg2 = mp.MeasurementPolicyRegistry(pub)
    mreg2.activate(dict(body5), sig5, now=NOW, rollback_guard=None)
    if body == body2 and mreg.known_policies() == mreg2.known_policies():
        _held("legacy_paths_byte_identical_without_guard",
              "guard=None activates identically to the legacy call")
    else:
        _break("legacy_paths_byte_identical_without_guard",
               "guard=None changed activation results")


@_probe("determinism")
def _p_determinism():
    def _run():
        codes = []
        guard = _guard_with(_entries(("tool-python", 5)))
        guard.authorize_activation("tool-python", 5,
                                   digest=_digest_for("tool-python", 5),
                                   not_after=NOW + 3600, now=NOW)
        for version, want in ((3, "rollback-detected"),
                              (5, None),
                              (9, None)):
            try:
                guard.authorize_activation(
                    "tool-python", version,
                    digest=_digest_for("tool-python", version),
                    not_after=NOW + 3600, now=NOW)
                codes.append(None)
            except vm.VersionManifestError as exc:
                codes.append(_code_of(exc))
        return codes
    if _run() == _run():
        _held("determinism", "two identical runs agree")
    else:
        _break("determinism", "nondeterministic guard")


# ----------------------------------------------------------------------
# Runner.
# ----------------------------------------------------------------------

def _run_green_checks():
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for battery in ("evals/w217_quorum_probes.py",
                    "evals/w218_admissibility_probes.py"):
        path = os.path.join(REPO, battery)
        if not os.path.exists(path):
            notes.append((battery, "SKIP", "battery not present"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        proc = subprocess.run(
            [sys.executable, path], env=env, cwd=REPO,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        out = proc.stdout.decode("utf-8", "replace")
        real_break = re.search(r"/ ([1-9][0-9]*) BREAK", out) \
            or re.search(r"^  \S+ +BREAK[ \n]", out, re.M)
        if proc.returncode == 0 and not real_break:
            notes.append((battery, "PASS", "adjacent battery green"))
        else:
            notes.append((battery, "FAIL",
                          out[-500:] if out else "no output"))
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
    print("w219 rollback probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
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
