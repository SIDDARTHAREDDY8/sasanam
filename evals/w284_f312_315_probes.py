"""Wave-284 red-first closure battery: F312-F315 (discovery-scan + atomic).

F312: a forged ``_atomic_normalized`` marker must refuse LOUD with a
coded AtomicError (never skip schema validation).
F313: a dead audit sink must fail LOUD (discovery-emit-failed), never
silently swallow drift events.
F314: tool names carrying the "|" pin-store separator are rejected
LOUD at the observation trust boundary (and tool keys are validated
at check_at_use / request_repin / approve_repin).
F315: observe_one receives the FULL 4-part tool key; an observed
definition whose name mismatches the pinned identity refuses LOUD.

Red-first: every probe BREAKs on the pristine wave-283 base and
HELDs after the lane fixes.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import re
import sys
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe_lines  # noqa: E402  (canonical probe-line form)

from gov import battery_lang as bl
from gov import decision_codes
from gov import discovery_scan as ds

TAXONOMY_PIN = 1900 # Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*)


def _check(name, fn):
    try:
        ok, note = fn()
    except Exception:  # noqa: BLE001 - a probe error is a BREAK, loud
        return (name, "BREAK", "probe raised: %s"
                % traceback.format_exc(limit=3).replace("\n", " | "))
    return (name, "HELD" if ok else "BREAK", note)


# ---------------------------------------------------------------------------
# Pin / taxonomy
# ---------------------------------------------------------------------------

def _pin():
    src = open(decision_codes.__file__).read()
    codes = re.findall(r'"code":\s*\'([^\']+)\'', src)
    raw, unique = len(codes), len(set(codes))
    ordered = codes == sorted(codes)
    ok = (raw == TAXONOMY_PIN and unique == TAXONOMY_PIN
          and raw - unique == 0 and ordered)
    return ok, ("raw=%d unique=%d sorted=%s" % (raw, unique, ordered))


# ---------------------------------------------------------------------------
# F312
# ---------------------------------------------------------------------------

def _f312_forged_marker():
    # A forged plain-True marker must refuse LOUD with a coded
    # AtomicError, not skip validation (pre-fix: bare KeyError).
    try:
        bl.run_atomic({"name": "x", "_atomic_normalized": True}, {})
    except bl.AtomicError as e:
        return (e.code == "atomic-spec-invalid",
                "coded refusal: %s" % (e,))
    except Exception as e:
        return (False, "uncoded escape: %s: %s"
                % (type(e).__name__, e))
    return (False, "forged spec RAN: validation fully skipped")


def _f312_valid_spec_still_runs():
    # A genuinely normalized spec must still skip re-validation and
    # run (the sentinel path works).
    def run(args):
        return ("HELD", "fine")
    spec = {"name": "t", "description": "d", "input_arguments": {},
            "dependencies": [],
            "executor": {"run": run, "cleanup": None,
                         "elevation_required": False}}
    norm = bl.validate_atomic_spec(spec)
    if norm.get("_atomic_normalized") is True:
        return (False, "marker is still the forgeable plain-True value")
    out = bl.run_atomic(norm, {})
    return (out.get("verdict") == "ok",
            "normalized spec ran: %r" % (out.get("verdict"),))


# ---------------------------------------------------------------------------
# F313
# ---------------------------------------------------------------------------

def _mk_registry_with_pin():
    reg = ds.ToolDefinitionRegistry()
    comp = {"scope": "system", "agent_host": "h",
            "component_type": "tool", "source_path": "/p",
            "component_id": "c",
            "definitions": [{"name": "tool", "description": "d",
                             "schema": {}}]}
    reg.register_observation(comp)
    key = ("system", "h", "c", "tool")
    return reg, key


def _f313_dead_sink_loud():
    reg, key = _mk_registry_with_pin()
    reg.set_emit(lambda event: (_ for _ in ()).throw(RuntimeError("dead")))
    drifted = {"name": "tool", "description": "d2", "schema": {}}
    try:
        reg.check_at_use(key, observe_one=lambda k: drifted)
    except ds.DiscoveryEmitFailed as e:
        return (e.code == "discovery-emit-failed",
                "loud coded refusal: %s" % (e,))
    except ds.DiscoveryScanError as e:
        return (False, "wrong coded refusal: %s" % (e,))
    except Exception as e:
        return (False, "uncoded escape: %s: %s"
                % (type(e).__name__, e))
    return (False, "emit failure SWALLOWED: no loud refusal")


def _f313_in_memory_list_kept():
    # The event must still land in the in-memory drift list even when
    # the sink dies (the local record survives a dead sink).
    reg, key = _mk_registry_with_pin()
    reg.set_emit(lambda event: (_ for _ in ()).throw(RuntimeError("dead")))
    drifted = {"name": "tool", "description": "d2", "schema": {}}
    try:
        reg.check_at_use(key, observe_one=lambda k: drifted)
    except ds.DiscoveryEmitFailed:
        pass
    kinds = [e.get("event") for e in reg.drift_events]
    return ("definition_drift" in kinds,
            "in-memory drift events: %r" % (kinds,))


# ---------------------------------------------------------------------------
# F314
# ---------------------------------------------------------------------------

def _f314_pipe_name_rejected():
    reg = ds.ToolDefinitionRegistry()
    comp = {"scope": "system", "agent_host": "h",
            "component_type": "tool", "source_path": "/p",
            "component_id": "c",
            "definitions": [{"name": "evil|tool", "description": "d",
                             "schema": {}}]}
    try:
        reg.register_observation(comp)
    except ds.DiscoveryResultMalformed as e:
        return (e.code == "discovery-result-malformed",
                "loud refusal: %s" % (e,))
    except Exception as e:
        return (False, "uncoded escape: %s: %s"
                % (type(e).__name__, e))
    return (False, "pipe name ACCEPTED at the trust boundary")


def _f314_pipe_key_refused():
    reg, key = _mk_registry_with_pin()
    bad = ("system", "h", "c", "evil|tool")
    try:
        reg.check_at_use(bad, observe_one=lambda k: None)
    except ds.DiscoveryResultMalformed as e:
        return (e.code == "discovery-result-malformed",
                "loud refusal: %s" % (e,))
    except Exception as e:
        return (False, "uncoded escape: %s: %s"
                % (type(e).__name__, e))
    return (False, "pipe tool key ACCEPTED")


# ---------------------------------------------------------------------------
# F315
# ---------------------------------------------------------------------------

def _f315_observe_one_gets_full_key():
    # observe_one must receive the full 4-part key, not the name.
    reg, key = _mk_registry_with_pin()
    seen = []

    def obs(k):
        seen.append(k)
        return {"name": "tool", "description": "d", "schema": {}}

    ok, code, _ = reg.check_at_use(key, observe_one=obs)
    return (ok and code == "ok" and seen == [key],
            "observed with: %r (ok=%r code=%r)" % (seen, ok, code))


def _f315_name_shadow_refused():
    # Same-name shadow: observer serves a definition naming a
    # DIFFERENT tool than the pinned identity -> loud refusal.
    reg, key = _mk_registry_with_pin()

    def obs(k):
        return {"name": "other", "description": "d", "schema": {}}

    ok, code, detail = reg.check_at_use(key, observe_one=obs)
    return ((not ok) and code == "discovery-result-malformed"
            and "identity mismatch" in detail,
            "ok=%r code=%r detail=%r" % (ok, code, detail))


def _f315_repin_binds_identity():
    # approve_repin binds to the fresh observation of the FULL key;
    # an observer keyed by name alone cannot satisfy the contract.
    reg, key = _mk_registry_with_pin()
    drifted = {"name": "tool", "description": "d2", "schema": {}}
    reg.check_at_use(key, observe_one=lambda k: drifted)
    reg.request_repin(key)
    new_digest = ds.definition_digest(drifted)
    seen = []

    def obs(k):
        seen.append(k)
        return drifted

    out = reg.approve_repin(key, new_digest, observe_one=obs)
    return (out is True and seen == [key],
            "approved=%r observed-with=%r" % (out, seen))


PROBES = [
    ("pin-1588", _pin),
    ("f312-forged-marker", _f312_forged_marker),
    ("f312-valid-spec-runs", _f312_valid_spec_still_runs),
    ("f313-dead-sink-loud", _f313_dead_sink_loud),
    ("f313-in-memory-kept", _f313_in_memory_list_kept),
    ("f314-pipe-name-rejected", _f314_pipe_name_rejected),
    ("f314-pipe-key-refused", _f314_pipe_key_refused),
    ("f315-full-key-to-observer", _f315_observe_one_gets_full_key),
    ("f315-name-shadow-refused", _f315_name_shadow_refused),
    ("f315-repin-binds-identity", _f315_repin_binds_identity),
]


def _green_checks():
    # Depth-1 only: honor GOV_SKIP_GREEN; never spawn nested mains.
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-checks", "SKIP", "GOV_SKIP_GREEN=1")]
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    results = []
    for battery in ("w282_agentscan_probes.py", "w283_redteam_probes.py"):
        path = os.path.join(here, battery)
        if not os.path.exists(path):
            # D7-family rename: "green:<battery>" -> "green_<battery>"
            # (pid class [A-Za-z0-9_.\-]+); value-only.
            results.append(("green_" + battery, "SKIP", "absent"))
            continue
        p = subprocess.run([sys.executable, path], capture_output=True,
                           text=True, env=env, timeout=600,
                           cwd=os.path.join(here, ".."))
        out = (p.stdout + p.stderr).replace("\n", " | ")
        # D1: GREEN->HELD, RED->BREAK (red by this battery's own exit
        # contract: 1 if (breaks or reds) else 0).
        verdict = "HELD" if p.returncode == 0 else "BREAK"
        results.append(("green_" + battery, verdict,
                        "rc=%d %s" % (p.returncode, out[-300:])))
    return results


def main():
    results = [_check(name, fn) for name, fn in PROBES]
    results += _green_checks()
    # D1: reds folded into BREAK (old exit was 1 if (breaks or reds)
    # else 0 -- exit-equivalent).
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    errors = sum(1 for _, v, _ in results if v == "ERROR")
    print("w284_f312_315: %d BREAK / %d HELD / %d ERROR"
          % (breaks, held, errors))
    probe_lines.emit(results)
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
