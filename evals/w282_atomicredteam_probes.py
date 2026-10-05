"""Wave-282 lane 5 red-first battery: atomic test manifests (atomic-red-team ADAPT).

Gap (base a858be2): the wave-280 battery language has committed replayable
manifests (plugin x strategy x grader) but no atomic-test discipline: no
stable GUID replay identity, no typed input_arguments validated before run,
no dependency self-check with auto-remediation (setup assumes a clean
environment), and no guaranteed cleanup_command (a failing break can leave
hygiene residue for the next run -- the real-sandboxing stream needs this).

Red-first: on base every probe BREAKs (gov.battery_lang has no atomic
layer). After the build: stable GUIDs, typed args validated before run,
prereq self-check + auto-remediation, guaranteed cleanup that is LOUD on
failure, a CI schema gate at registration, and committed-manifest drift
detection.

Pattern lineage: redcanaryco/atomic-red-team (MIT) -- auto_generated_guid,
typed input_arguments, dependencies{prereq_command, get_prereq_command},
executor{command, cleanup_command, elevation_required}, and the
validate-atomics.yml CI schema gate. Mechanism only, no code vendored;
the name is trademarked (pattern, not brand). Executors are Python
callables here (deterministic, $0, no network), not shell commands.
"""

import json
import os
import re
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe_lines  # noqa: E402  (canonical probe-line form)

TAXONOMY_PIN = 2106 # Wave-282 lane 5: pin 1563 -> 1569 (+6 atomic-*).; Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).



_RESULTS = []


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict, "note": note})


def _needs_atomic(probe_id):
    try:
        from gov import battery_lang as bl
    except ImportError:
        _record(probe_id, "BREAK", "gov.battery_lang absent on base")
        return None
    for name in ("ATOMIC_MANIFEST_FORMAT", "ATOMIC_ARG_TYPES",
                 "AtomicError", "AtomicCleanupError",
                 "validate_atomic_spec", "atomic_guid",
                 "register_atomic", "validate_atomic_args",
                 "run_atomic", "generate_atomic_manifest",
                 "load_atomic_manifest", "bind_atomic_manifest",
                 "atomic_rows"):
        if not hasattr(bl, name):
            _record(probe_id, "BREAK",
                    "gov.battery_lang missing atomic API %r" % name)
            return None
    return bl


# -- fixture callables (module-level so inspect.getsource works) ----------

_REMEDIATION_STATE = {"fixed": False}
_RUN_LOG = []


def _ok_prereq():
    return True


def _fail_prereq():
    return False


def _remediate_ok():
    _REMEDIATION_STATE["fixed"] = True
    return True


def _remediated_prereq():
    return _REMEDIATION_STATE["fixed"]


def _remediate_fail():
    return False


def _run_ok(ctx):
    _RUN_LOG.append(("run", dict(ctx)))
    return ("HELD", "executor ran clean")


def _run_boom(ctx):
    _RUN_LOG.append(("run", dict(ctx)))
    raise RuntimeError("executor exploded")


def _cleanup_ok(ctx, outcome):
    _RUN_LOG.append(("cleanup", outcome["verdict"]))


def _cleanup_boom(ctx, outcome):
    _RUN_LOG.append(("cleanup", outcome["verdict"]))
    raise RuntimeError("cleanup exploded")


def _base_spec(**over):
    spec = {
        "name": "atomic-fixture",
        "description": "fixture atomic test",
        "input_arguments": {
            "target": {"type": "str", "description": "what to hit"},
            "retries": {"type": "int", "default": 1,
                        "description": "attempt count"},
            "mode": {"type": "enum", "choices": ["fast", "slow"],
                     "default": "fast", "description": "speed"},
        },
        "dependencies": [
            {"name": "env-ready", "prereq": _ok_prereq,
             "description": "environment ready"},
        ],
        "executor": {"run": _run_ok, "cleanup": _cleanup_ok,
                     "elevation_required": False},
    }
    spec.update(over)
    return spec


# -- probes ---------------------------------------------------------------

def p_atomic_api_present():
    bl = _needs_atomic("p_atomic_api_present")
    if bl is None:
        return
    if bl.ATOMIC_MANIFEST_FORMAT != "sasanam-atomic-manifest/1":
        _record("p_atomic_api_present", "BREAK",
                "bad manifest format %r" % bl.ATOMIC_MANIFEST_FORMAT)
        return
    if not {"str", "int", "float", "bool", "enum"} <= set(bl.ATOMIC_ARG_TYPES):
        _record("p_atomic_api_present", "BREAK", "arg type vocabulary short")
        return
    _record("p_atomic_api_present", "HELD", "atomic API present")


def p_guid_stability():
    bl = _needs_atomic("p_guid_stability")
    if bl is None:
        return
    g1 = bl.atomic_guid(_base_spec())
    g2 = bl.atomic_guid(_base_spec())
    if g1 != g2 or len(g1) != 64:
        _record("p_guid_stability", "BREAK",
                "guid not stable: %r vs %r" % (g1, g2))
        return
    reg = {}
    r1 = bl.register_atomic(reg, _base_spec())
    r2 = bl.register_atomic(reg, _base_spec())
    if r1 != r2 or r1 != g1:
        _record("p_guid_stability", "BREAK", "registry guid mismatch")
        return
    _record("p_guid_stability", "HELD", "guid stable %s..." % g1[:12])


def p_guid_collision_refused():
    bl = _needs_atomic("p_guid_collision_refused")
    if bl is None:
        return
    reg = {}
    guid = bl.register_atomic(reg, _base_spec())
    other = _base_spec()
    other["guid"] = guid  # force same identity...
    other["description"] = "a DIFFERENT test wearing the same guid"
    try:
        bl.register_atomic(reg, other)
    except bl.AtomicError as exc:
        if exc.code == "atomic-guid-collision":
            _record("p_guid_collision_refused", "HELD",
                    "same guid + different spec refused")
            return
        _record("p_guid_collision_refused", "BREAK",
                "wrong code %r" % exc.code)
        return
    _record("p_guid_collision_refused", "BREAK",
            "guid collision silently accepted")


def p_arg_typing():
    bl = _needs_atomic("p_arg_typing")
    if bl is None:
        return
    spec = bl.validate_atomic_spec(_base_spec())

    def _expect_refuse(args, why):
        try:
            bl.validate_atomic_args(spec, args)
        except bl.AtomicError as exc:
            if exc.code == "atomic-arg-refused":
                return True
            _record("p_arg_typing", "BREAK",
                    "%s: wrong code %r" % (why, exc.code))
            return None
        _record("p_arg_typing", "BREAK", "%s: silently accepted" % why)
        return None

    for args, why in (
            ({"target": "x", "bogus": 1}, "unknown arg"),
            ({"target": 42}, "wrong type str<-int"),
            ({"target": "x", "retries": True}, "bool is not int"),
            ({"target": "x", "mode": "warp"}, "enum outside choices"),
            ({"retries": 2}, "missing required arg")):
        if _expect_refuse(args, why) is None:
            return
    got = bl.validate_atomic_args(spec, {"target": "x"})
    if got != {"target": "x", "retries": 1, "mode": "fast"}:
        _record("p_arg_typing", "BREAK", "defaults not applied: %r" % (got,))
        return
    _record("p_arg_typing", "HELD", "typed args validated before run")


def p_prereq_self_check():
    bl = _needs_atomic("p_prereq_self_check")
    if bl is None:
        return
    spec = _base_spec()
    spec["dependencies"] = [{"name": "never-ready", "prereq": _fail_prereq,
                             "description": "always fails"}]
    try:
        bl.run_atomic(spec, {"target": "x"})
    except bl.AtomicError as exc:
        if exc.code == "atomic-dependency-refused":
            _record("p_prereq_self_check", "HELD",
                    "failed prereq refused LOUD, not skipped")
            return
        _record("p_prereq_self_check", "BREAK", "wrong code %r" % exc.code)
        return
    _record("p_prereq_self_check", "BREAK",
            "failed prereq silently skipped or ran")


def p_prereq_auto_remediate():
    bl = _needs_atomic("p_prereq_auto_remediate")
    if bl is None:
        return
    _REMEDIATION_STATE["fixed"] = False
    del _RUN_LOG[:]
    spec = _base_spec()
    spec["dependencies"] = [{"name": "fixable",
                             "prereq": _remediated_prereq,
                             "get_prereq": _remediate_ok,
                             "description": "remediable"}]
    res = bl.run_atomic(spec, {"target": "x"})
    if res["verdict"] != "ok" or ("run", {"target": "x", "retries": 1,
                                          "mode": "fast"}) not in _RUN_LOG:
        _record("p_prereq_auto_remediate", "BREAK",
                "remediation did not lead to a run: %r" % (res,))
        return
    dep = res["dep_results"][0]
    if not (dep["prereq_ok"] is False and dep["remediated"] is True
            and dep["final_ok"] is True):
        _record("p_prereq_auto_remediate", "BREAK",
                "dep trace wrong: %r" % (dep,))
        return
    _record("p_prereq_auto_remediate", "HELD",
            "prereq failed -> remediated -> re-checked -> ran")


def p_prereq_remediation_failed_loud():
    bl = _needs_atomic("p_prereq_remediation_failed_loud")
    if bl is None:
        return
    spec = _base_spec()
    spec["dependencies"] = [{"name": "unfixable", "prereq": _fail_prereq,
                             "get_prereq": _remediate_fail,
                             "description": "remediation fails"}]
    try:
        bl.run_atomic(spec, {"target": "x"})
    except bl.AtomicError as exc:
        if exc.code == "atomic-dependency-refused":
            _record("p_prereq_remediation_failed_loud", "HELD",
                    "failed remediation refused LOUD")
            return
        _record("p_prereq_remediation_failed_loud", "BREAK",
                "wrong code %r" % exc.code)
        return
    _record("p_prereq_remediation_failed_loud", "BREAK",
            "failed remediation silently skipped")


def p_cleanup_on_failure():
    bl = _needs_atomic("p_cleanup_on_failure")
    if bl is None:
        return
    del _RUN_LOG[:]
    spec = _base_spec()
    spec["executor"] = {"run": _run_boom, "cleanup": _cleanup_ok,
                        "elevation_required": False}
    res = bl.run_atomic(spec, {"target": "x"})
    kinds = [k for k, _ in _RUN_LOG]
    if kinds != ["run", "cleanup"]:
        _record("p_cleanup_on_failure", "BREAK",
                "cleanup did not run after executor failure: %r" % (kinds,))
        return
    if res["verdict"] != "executor-error" or res["cleanup"] != "ok":
        _record("p_cleanup_on_failure", "BREAK",
                "bad result shape: %r" % (res,))
        return
    _record("p_cleanup_on_failure", "HELD",
            "cleanup guaranteed even when executor raises")


def p_cleanup_failure_loud():
    bl = _needs_atomic("p_cleanup_failure_loud")
    if bl is None:
        return
    del _RUN_LOG[:]
    spec = _base_spec()
    spec["executor"] = {"run": _run_boom, "cleanup": _cleanup_boom,
                        "elevation_required": False}
    try:
        bl.run_atomic(spec, {"target": "x"})
    except bl.AtomicCleanupError as exc:
        if exc.code != "atomic-cleanup-failed":
            _record("p_cleanup_failure_loud", "BREAK",
                    "wrong code %r" % exc.code)
            return
        if not getattr(exc, "outcome", None):
            _record("p_cleanup_failure_loud", "BREAK",
                    "cleanup error swallowed the executor outcome")
            return
        _record("p_cleanup_failure_loud", "HELD",
                "cleanup failure LOUD, outcome carried")
        return
    except bl.AtomicError as exc:  # noqa: BLE001 -- must be the subclass
        _record("p_cleanup_failure_loud", "BREAK",
                "cleanup failure raised base AtomicError, not LOUD subclass")
        return
    _record("p_cleanup_failure_loud", "BREAK",
            "cleanup failure silently swallowed")


def p_elevation_declared():
    bl = _needs_atomic("p_elevation_declared")
    if bl is None:
        return
    spec = _base_spec()
    spec["executor"] = {"run": _run_ok, "cleanup": _cleanup_ok,
                        "elevation_required": True}
    try:
        bl.run_atomic(spec, {"target": "x"})
    except bl.AtomicError as exc:
        if exc.code == "atomic-elevation-required":
            res = bl.run_atomic(spec, {"target": "x"},
                                elevation_granted=True)
            if res["verdict"] != "ok":
                _record("p_elevation_declared", "BREAK",
                        "granted elevation did not run: %r" % (res,))
                return
            _record("p_elevation_declared", "HELD",
                    "elevation_required refuses unless granted")
            return
        _record("p_elevation_declared", "BREAK", "wrong code %r" % exc.code)
        return
    _record("p_elevation_declared", "BREAK",
            "elevation_required silently ignored")


def p_schema_gate():
    bl = _needs_atomic("p_schema_gate")
    if bl is None:
        return
    bad_specs = [
        {"name": "no-executor", "input_arguments": {}, "dependencies": []},
        {"name": "bad-arg-type", "input_arguments":
            {"x": {"type": "quantum"}}, "dependencies": [],
         "executor": {"run": _run_ok}},
        {"name": "enum-no-choices", "input_arguments":
            {"x": {"type": "enum"}}, "dependencies": [],
         "executor": {"run": _run_ok}},
        {"name": "non-callable-prereq", "input_arguments": {},
         "dependencies": [{"name": "d", "prereq": "not-a-callable"}],
         "executor": {"run": _run_ok}},
        {"name": "non-callable-run", "input_arguments": {},
         "dependencies": [], "executor": {"run": 42}},
        "not-a-dict",
    ]
    for i, bad in enumerate(bad_specs):
        try:
            bl.validate_atomic_spec(bad)
        except bl.AtomicError as exc:
            if exc.code != "atomic-spec-invalid":
                _record("p_schema_gate", "BREAK",
                        "spec %d: wrong code %r" % (i, exc.code))
                return
            continue
        _record("p_schema_gate", "BREAK",
                "spec %d silently accepted: %r" % (i, bad))
        return
    _record("p_schema_gate", "HELD", "CI schema gate refuses malformed specs")


def p_manifest_drift():
    bl = _needs_atomic("p_manifest_drift")
    if bl is None:
        return
    reg = {}
    guid = bl.register_atomic(reg, _base_spec())
    d = tempfile.mkdtemp(prefix="atomic-manifest-",
                         dir=os.environ.get("TMPDIR", "/tmp"))
    path = os.path.join(d, "atomics.json")
    manifest = bl.generate_atomic_manifest(reg)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(manifest, sort_keys=True) + "\n")
    loaded = bl.load_atomic_manifest(path)
    bl.bind_atomic_manifest(reg, loaded)  # honest round-trip must not refuse
    # Now drift: same guid, different spec digest in the committed file.
    manifest["tests"][0]["spec_digest"] = "0" * 64
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(manifest, sort_keys=True) + "\n")
    loaded = bl.load_atomic_manifest(path)
    try:
        bl.bind_atomic_manifest(reg, loaded)
    except bl.AtomicError as exc:
        if exc.code == "atomic-guid-collision":
            _record("p_manifest_drift", "HELD",
                    "committed drift refused: %s..." % guid[:12])
            return
        _record("p_manifest_drift", "BREAK", "wrong code %r" % exc.code)
        return
    _record("p_manifest_drift", "BREAK",
            "drifted manifest silently bound")


def p_raw_guid_dict_not_trusted():
    bl = _needs_atomic("p_raw_guid_dict_not_trusted")
    if bl is None:
        return
    # A raw dict merely containing a "guid" key must NOT be trusted as
    # normalized: the schema gate must still run (fail-closed AtomicError,
    # never a bare KeyError).
    raw = {"guid": "a" * 64, "name": "unvalidated",
           "input_arguments": {}, "dependencies": []}  # no executor
    try:
        bl.run_atomic(raw, {})
    except bl.AtomicError as exc:
        if exc.code == "atomic-spec-invalid":
            _record("p_raw_guid_dict_not_trusted", "HELD",
                    "raw guid-keyed dict still schema-gated")
            return
        _record("p_raw_guid_dict_not_trusted", "BREAK",
                "wrong code %r" % exc.code)
        return
    except Exception as exc:  # noqa: BLE001 -- must be a coded refusal
        _record("p_raw_guid_dict_not_trusted", "BREAK",
                "uncoded %r escaped" % (exc,))
        return
    _record("p_raw_guid_dict_not_trusted", "BREAK",
            "unvalidated spec silently ran")


def p_atomic_rows_shape():
    bl = _needs_atomic("p_atomic_rows_shape")
    if bl is None:
        return
    del _RUN_LOG[:]
    res = bl.run_atomic(_base_spec(), {"target": "x"})
    rows = bl.atomic_rows([res])
    if not isinstance(rows, list) or len(rows) != 1:
        _record("p_atomic_rows_shape", "BREAK", "rows not a 1-list")
        return
    row = rows[0]
    for key in ("atomic_guid", "name", "executor_verdict",
                "grading_result", "note_digest"):
        if key not in row:
            _record("p_atomic_rows_shape", "BREAK",
                    "row missing %r" % key)
            return
    _record("p_atomic_rows_shape", "HELD", "machine-readable rows emitted")


def p_taxonomy_pin():
    bl = _needs_atomic("p_taxonomy_pin")
    if bl is None:
        return
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    lits = re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)
    if len(lits) != TAXONOMY_PIN:
        _record("p_taxonomy_pin", "BREAK",
                "taxonomy pin drift: %d literals, want %d"
                % (len(lits), TAXONOMY_PIN))
        return
    if len(set(lits)) != len(lits):
        _record("p_taxonomy_pin", "BREAK", "duplicate literals")
        return
    if lits != sorted(lits):
        _record("p_taxonomy_pin", "BREAK", "literals unsorted")
        return
    _record("p_taxonomy_pin", "HELD", "%d/%d/0 sorted" % (len(lits),
                                                         TAXONOMY_PIN))


PROBE_METADATA = {
    "p_atomic_api_present": ("supply-chain", "direct", "held-vs-expected"),
    "p_guid_stability": ("supply-chain", "direct", "held-vs-expected"),
    "p_guid_collision_refused": ("policy-drift", "version-drift",
                                 "held-vs-expected"),
    "p_arg_typing": ("supply-chain", "schema-bypass", "held-vs-expected"),
    "p_prereq_self_check": ("supply-chain", "direct", "held-vs-expected"),
    "p_prereq_auto_remediate": ("supply-chain", "direct", "held-vs-expected"),
    "p_prereq_remediation_failed_loud": ("supply-chain", "direct",
                                         "held-vs-expected"),
    "p_cleanup_on_failure": ("supply-chain", "direct", "held-vs-expected"),
    "p_cleanup_failure_loud": ("supply-chain", "direct", "held-vs-expected"),
    "p_elevation_declared": ("supply-chain", "direct", "held-vs-expected"),
    "p_schema_gate": ("supply-chain", "schema-bypass", "held-vs-expected"),
    "p_manifest_drift": ("policy-drift", "version-drift", "held-vs-expected"),
    "p_raw_guid_dict_not_trusted": ("supply-chain", "schema-bypass",
                                     "held-vs-expected"),
    "p_atomic_rows_shape": ("supply-chain", "direct", "held-vs-expected"),
    "p_taxonomy_pin": ("closure-repin", "regression", "held-vs-expected"),
}

PROBES = [(pid, "HELD", globals()[pid]) for pid in PROBE_METADATA]


def _green_checks():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "SKIP", "GOV_SKIP_GREEN=1")
        return
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    for target in ("evals/w280_batterylang_probes.py",):
        try:
            r = subprocess.run(
                [sys.executable, os.path.join(repo, target)],
                env=env, capture_output=True, timeout=600, cwd=repo)
            ok = r.returncode == 0
        except Exception as e:  # noqa: BLE001
            _record("green-check", "BREAK",
                    "green check failed: %r" % (e,))
            return
        _record("green-check", "HELD" if ok else "BREAK",
                "%s rc=%d" % (target, r.returncode if ok else r.returncode))


def main():
    os.makedirs(os.environ.get("TMPDIR", "/tmp"), exist_ok=True)
    for _, _, fn in PROBES:
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - battery must never die
            _record(fn.__name__, "ERROR", "%r" % (e,))
    _green_checks()
    n_break = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    n_err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    n_held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    print("w282_atomicredteam: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    probe_lines.emit_dicts(_RESULTS, verdict_key="verdict",
                           pid_key="probe_id", note_key="note")
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
