"""Wave-245 open-paths battery (W245-9): pre-trust config-stripping probes
for the W244-1 session-trust battery, plus anti-flake calibration.

Design input (ADAPT, threat-model only): the wave-244 prospectus GitSpawn
update -- the two session-startup trust paths still open in the wild are
the ``core.hooksPath``-class hook enumeration and Claude Code's
``ultrareview`` sink (2.1.252, researchers withheld the sink-trigger key,
status honest-unverified). Hermes Agent (CVE-2026-71963, PR #101483,
2026-09-02) and Qwen Code (PR #11669, 2026-09-12) are fixed; their fixed
versions are ANTI-FLAKE CALIBRATION inputs -- the old true-positive
signal must go silent on the fix, or the battery cannot be trusted on
the bug.

Probes:
  hookspath-pretrust-refused -- untrusted repo with
      ``core.hooksPath=<attacker-dir>`` -> ``checked_spawn`` refuses
      ``repo-hook-pretrust-refused`` and the spawn callable is never
      invoked (trust consulted first; the hooksPath class joins the
      fsmonitor class at the pre-trust seam).
  hookspath-trusted-still-denied -- ``verified-allowed`` repo with a
      ``core.hooksPath`` config -> ``gitspawn-hostile-config`` (trust
      is not a config bypass; the exec-sink key stays deny-listed).
  hookspath-stripping-vs-preserving -- ``strip_unknown_config_keys``
      observably differs from silent preservation: the hooksPath line
      lands in ``stripped``, never in ``kept`` (falsifies a stripping
      routine that is secretly a no-op).
  ultrareview-sink-pretrust-refused -- unregistered ``ultrareview``
      sink name -> refused ``repo-hook-pretrust-refused`` pre-trust
      (the sink never resolves, never executes).
  ultrareview-renamed-sink-refused -- renames of a registered sink
      (``ultra-review``, ``ultrareviews``, ``u1trarev1ew``,
      case-variant ``ULTRAREVIEW``) -> ALL refused pre-trust
      (falsifies denylist thinking: evasion-by-rename cannot beat a
      closed allowlist).
  sink-allowlist-positive -- a registered sink resolves to its
      registration (positive control: the list is consulted, not
      bypassed-in-reverse).
  calibration-hermes-fixed-silent -- hostile fsmonitor config +
      Hermes-fixed startup shape (trust-first routing) -> the
      true-positive signal stays SILENT and the refusal is the
      pre-trust code (anti-flake calibration, fixed 2026-09-02).
  calibration-qwen-fixed-silent -- same shape, Qwen-fixed input
      (fixed 2026-09-12).
  calibration-legacy-signal-fires -- the pre-fix (legacy) startup
      shape on the same hostile repo -> the signal FIRES and spawn is
      invoked (positive control: the battery still detects the bug;
      silence-on-fixed is calibration, not deafness).

Stdlib + in-repo gov only. Deterministic. No in-repo git
subprocesses (fake ``.git`` trees are plain files; the git binary is
never executed).
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

HAVE_ST = False
HAVE_SS = False
try:
    from gov import session_trust as _st
    HAVE_ST = all(hasattr(_st, n) for n in (
        "TrustRegistry", "checked_spawn", "SessionTrustError",
        "raise_refusal", "UNTRUSTED", "ALLOWED", "MALFORMED"))
except ImportError:
    _st = None
try:
    from gov import startup_sinks as _ss
    HAVE_SS = all(hasattr(_ss, n) for n in (
        "StartupSinkRegistry", "strip_unknown_config_keys",
        "UNREGISTERED"))
except ImportError:
    _ss = None
try:
    import gov.git_sanitize as _gs
except ImportError:
    _gs = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "hookspath-pretrust-refused",
    "hookspath-trusted-still-denied",
    "hookspath-stripping-vs-preserving",
    "ultrareview-sink-pretrust-refused",
    "ultrareview-renamed-sink-refused",
    "sink-allowlist-positive",
    "calibration-hermes-fixed-silent",
    "calibration-qwen-fixed-silent",
    "calibration-legacy-signal-fires",
]

RESULTS = []
SITUATIONS = {}

# Anti-flake calibration inputs (wave-244 prospectus, GitSpawn update):
# the fixed versions whose startup shape must keep the battery silent.
FIXED_VERSIONS = [
    {"agent": "hermes", "fixed_in": "PR #101483", "fixed_on": "2026-09-02",
     "advisory": "CVE-2026-71963"},
    {"agent": "qwen-code", "fixed_in": "PR #11669",
     "fixed_on": "2026-09-12", "advisory": None},
]


def _sit(sid):
    def deco(fn):
        def wrapper():
            try:
                detail = fn()
                if not isinstance(detail, dict):
                    detail = {"note": str(detail)}
                verdict = detail.pop("verdict", "stopped")
                RESULTS.append({"id": sid, "verdict": verdict,
                                "detail": detail})
            except Exception as e:  # noqa: BLE001 - probe must not die
                RESULTS.append({"id": sid, "verdict": "error",
                                "detail": {"error": "%s: %s"
                                           % (type(e).__name__, e),
                                           "trace": traceback.format_exc(
                                               limit=5)}})
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        SITUATIONS[sid] = wrapper
        return wrapper
    return deco


def _need():
    if not HAVE_ST:
        return {"verdict": "gap", "note": "gov.session_trust missing"}
    if not HAVE_SS:
        return {"verdict": "gap", "note": "gov.startup_sinks missing"}
    if _gs is None:
        return {"verdict": "gap", "note": "gov.git_sanitize missing"}
    return None


def _repo(parent, name, *, config=None):
    root = os.path.join(parent, name)
    git = os.path.join(root, ".git")
    os.makedirs(git, exist_ok=True)
    with open(os.path.join(git, "HEAD"), "w") as f:
        f.write("ref: refs/heads/main\n")
    if config is not None:
        with open(os.path.join(git, "config"), "w") as f:
            f.write(config)
    return root


def _spawner(calls):
    def spawn(argv, env=None, cwd=None):
        calls.append((argv, env, cwd))
        return {"rc": 0}
    return spawn


def _assert_code(fn, code):
    try:
        fn()
    except _st.SessionTrustError as e:
        if e.code != code:
            return {"verdict": "gap",
                    "note": "wrong code: %s (wanted %s)" % (e.code, code)}
        return {"verdict": "held"}
    except Exception as e:  # noqa: BLE001
        return {"verdict": "error",
                "note": "wrong exception: %s: %s" % (type(e).__name__, e)}
    return {"verdict": "gap", "note": "no refusal raised"}


def _legacy_startup(repo, spawn):
    """Pre-fix agent shape: session-startup git runs with NO trust
    consult; the startup consumes the repo config directly."""
    hostile = False
    try:
        _gs.deny_config_keys(repo)
    except Exception:  # noqa: BLE001 - any hostile-config error
        hostile = True
    spawn(["git", "status"], cwd=repo)
    return hostile  # True == the attack signal fired


def _fixed_startup(repo, registry, spawn):
    """Fixed agent shape (Hermes-fixed / Qwen-fixed): session-startup
    routes through checked_spawn; on an untrusted workspace the
    refusal lands pre-trust, so the legacy signal stays silent."""
    try:
        _st.checked_spawn(["status"], repo, registry, spawn=spawn)
    except _st.SessionTrustError as e:
        if e.code != "repo-hook-pretrust-refused":
            raise
        return False  # silent: startup aborted before any config read
    return None  # spawned: only reachable on a trusted workspace


@_sit("hookspath-pretrust-refused")
def _p_hookspath_pretrust():
    """Untrusted repo + core.hooksPath -> pre-trust refusal."""
    need = _need()
    if need:
        return need
    tmp = os.environ.get("TMPDIR", "/tmp")
    cfg = "[core]\n\thooksPath = /tmp/evil-hooks\n"
    root = _repo(tmp, "w245-hookspath", config=cfg)
    reg = _st.TrustRegistry()
    calls = []
    res = _assert_code(
        lambda: _st.checked_spawn(["status"], root, reg,
                                  spawn=_spawner(calls)),
        "repo-hook-pretrust-refused")
    if res["verdict"] != "held":
        return res
    if calls:
        return {"verdict": "gap",
                "note": "spawn invoked %d times pre-trust" % len(calls)}
    return {"verdict": "held"}


@_sit("hookspath-trusted-still-denied")
def _p_hookspath_trusted():
    """Verified-allowed + core.hooksPath -> hostile-config denial."""
    need = _need()
    if need:
        return need
    tmp = os.environ.get("TMPDIR", "/tmp")
    cfg = "[core]\n\thooksPath = /tmp/evil-hooks\n"
    root = _repo(tmp, "w245-hookspath-trusted", config=cfg)
    reg = _st.TrustRegistry()
    reg.record_trust(root, _st.ALLOWED, decided_by="operator")
    calls = []
    try:
        _st.checked_spawn(["status"], root, reg, spawn=_spawner(calls))
    except Exception as e:  # noqa: BLE001 - cross-module error type
        code = getattr(e, "code", type(e).__name__)
        if code != "gitspawn-hostile-config":
            return {"verdict": "gap",
                    "note": "wrong code for trusted+hooksPath: %s" % code}
        if calls:
            return {"verdict": "gap",
                    "note": "spawn ran despite hooksPath config"}
        return {"verdict": "held"}
    return {"verdict": "gap",
            "note": "hooksPath config spawned when trusted"}


@_sit("hookspath-stripping-vs-preserving")
def _p_stripping():
    """Stripping observably differs from silent preservation."""
    need = _need()
    if need:
        return need
    cfg = ("[core]\n"
           "\thooksPath = /tmp/evil-hooks\n"
           "\tbare = false\n"
           "# a comment\n")
    res = _ss.strip_unknown_config_keys(cfg, {"core.bare"})
    kept_blob = "\n".join(res["kept"])
    stripped_blob = "\n".join(res["stripped"])
    if "hooksPath" not in stripped_blob:
        return {"verdict": "gap",
                "note": "hooksPath line not stripped"}
    if "hooksPath" in kept_blob:
        return {"verdict": "gap",
                "note": "hooksPath line survived stripping"}
    # Positive control: the known key is kept.
    if "bare" not in kept_blob:
        return {"verdict": "gap",
                "note": "known key core.bare was stripped"}
    # The preserving baseline (what a vulnerable session does): the
    # hooksPath line is still present and live.
    preserved = cfg.splitlines()
    if not any("hooksPath" in ln for ln in preserved):
        return {"verdict": "gap",
                "note": "baseline lost the hooksPath line"}
    # Malformed inputs fail closed, not silent.
    bad = _assert_code(lambda: _ss.strip_unknown_config_keys(
        123, {"core.bare"}), "session-trust-malformed")
    if bad["verdict"] != "held":
        return {"verdict": "gap",
                "note": "non-string config not refused: %s" % (bad,)}
    return {"verdict": "held", "stripped": len(res["stripped"])}


@_sit("ultrareview-sink-pretrust-refused")
def _p_ultrareview():
    """Unregistered 'ultrareview' sink -> pre-trust refusal."""
    need = _need()
    if need:
        return need
    reg = _ss.StartupSinkRegistry()
    res = _assert_code(lambda: reg.resolve("ultrareview"),
                       "repo-hook-pretrust-refused")
    if res["verdict"] != "held":
        return res
    if "ultrareview" in reg.registered_names():
        return {"verdict": "gap",
                "note": "refused sink leaked onto the list"}
    return {"verdict": "held"}


@_sit("ultrareview-renamed-sink-refused")
def _p_ultrareview_renamed():
    """Renames of a registered sink are ALL refused pre-trust."""
    need = _need()
    if need:
        return need
    reg = _ss.StartupSinkRegistry()
    reg.register_sink("review", declared_by="operator")
    renames = ["ultra-review", "ultrareviews", "u1trarev1ew",
               "ULTRAREVIEW", "ultrareview "]
    for name in renames:
        res = _assert_code(lambda n=name: reg.resolve(n),
                           "repo-hook-pretrust-refused")
        if res["verdict"] != "held":
            return {"verdict": "gap",
                    "note": "renamed sink %r evaded the list: %s"
                    % (name, res)}
    if reg.registered_names() != ["review"]:
        return {"verdict": "gap",
                "note": "registry mutated: %r" % reg.registered_names()}
    return {"verdict": "held", "renames": len(renames)}


@_sit("sink-allowlist-positive")
def _p_sink_positive():
    """A registered sink resolves (positive control)."""
    need = _need()
    if need:
        return need
    reg = _ss.StartupSinkRegistry()
    reg.register_sink("review", declared_by="operator")
    out = reg.resolve("review")
    if out["name"] != "review" or out["declared_by"] != "operator":
        return {"verdict": "gap", "note": "registration not returned"}
    bad = _assert_code(
        lambda: reg.register_sink("Bad Name!", declared_by="operator"),
        "session-trust-malformed")
    if bad["verdict"] != "held":
        return {"verdict": "gap",
                "note": "malformed sink name not refused: %s" % (bad,)}
    return {"verdict": "held"}


def _calibration_probe(version):
    need = _need()
    if need:
        return need
    tmp = os.environ.get("TMPDIR", "/tmp")
    cfg = "[core]\n\tfsmonitor = /bin/touch CALIB-CANARY\n"
    root = _repo(tmp, "w245-calib-%s" % version["agent"], config=cfg)
    reg = _st.TrustRegistry()  # untrusted: the session-startup case
    calls = []
    signal = _fixed_startup(root, reg, _spawner(calls))
    if signal is not False:
        return {"verdict": "gap",
                "note": "signal not silent on fixed version: %r" % signal}
    if calls:
        return {"verdict": "gap",
                "note": "spawn invoked %d times on fixed version"
                % len(calls)}
    if os.path.exists(os.path.join(root, "CALIB-CANARY")):
        return {"verdict": "gap", "note": "payload canary file exists"}
    return {"verdict": "held", "agent": version["agent"],
            "fixed_on": version["fixed_on"]}


@_sit("calibration-hermes-fixed-silent")
def _p_calib_hermes():
    """Hermes-fixed startup shape: hostile config, signal stays silent."""
    return _calibration_probe(FIXED_VERSIONS[0])


@_sit("calibration-qwen-fixed-silent")
def _p_calib_qwen():
    """Qwen-fixed startup shape: hostile config, signal stays silent."""
    return _calibration_probe(FIXED_VERSIONS[1])


@_sit("calibration-legacy-signal-fires")
def _p_calib_legacy():
    """Pre-fix (legacy) startup shape: the signal FIRES."""
    need = _need()
    if need:
        return need
    tmp = os.environ.get("TMPDIR", "/tmp")
    cfg = "[core]\n\tfsmonitor = /bin/touch LEGACY-CANARY\n"
    root = _repo(tmp, "w245-calib-legacy", config=cfg)
    calls = []
    signal = _legacy_startup(root, _spawner(calls))
    if signal is not True:
        return {"verdict": "gap",
                "note": "legacy signal did not fire: %r" % signal}
    if not calls:
        return {"verdict": "gap",
                "note": "legacy startup did not spawn"}
    # The battery proves it is not deaf: silence-on-fixed is
    # calibration, detection still works.
    return {"verdict": "held"}


def run_all():
    for sid in PROBE_NAMES:
        SITUATIONS[sid]()
    held = sum(1 for r in RESULTS if r["verdict"] == "held")
    gap = sum(1 for r in RESULTS if r["verdict"] == "gap")
    errors = sum(1 for r in RESULTS if r["verdict"] == "error")
    return held, gap, errors


def green_check_adjacent():
    """Depth-1 green check: the W244-1 session-trust probes hold.

    Runs the adjacent battery's probes IN-PROCESS (never spawns another
    battery's main: no subprocess nesting, no TMPDIR sharing). The
    adjacent probes run against a FRESH TMPDIR so this battery's own
    probe layouts cannot flake them (the wave-134/wave-173 lesson).

    Honored GOV_SKIP_GREEN: a parent's green check records a skip
    instead of running the adjacent probes.
    """
    if GREEN_SKIP:
        return {"skipped": "GOV_SKIP_GREEN=1 (depth-1 green check)"}
    import importlib.util
    repo = os.path.join(os.path.dirname(__file__), "..")
    path = os.path.join(repo, "evals", "w244_session_trust_ordering_probes.py")
    if not os.path.exists(path):
        return {"w244_session_trust_ordering_probes": "missing"}
    adj_tmp = os.environ.get("TMPDIR", "/tmp") + "-adj"
    # Recreate (not just makedirs): a stale layout from an earlier
    # adjacent run (e.g. the symlink-escape probe's swapped .git)
    # would flake this one -- the wave-134/wave-173 lesson again.
    import shutil
    shutil.rmtree(adj_tmp, ignore_errors=True)
    os.makedirs(adj_tmp, exist_ok=True)
    old_tmp = os.environ.get("TMPDIR")
    os.environ["TMPDIR"] = adj_tmp
    try:
        spec = importlib.util.spec_from_file_location("w244_adj_probes",
                                                      path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        held, gap, errors = mod.run_all()
    except Exception as e:  # noqa: BLE001
        return {"w244_session_trust_ordering_probes":
                "error: %s: %s" % (type(e).__name__, e)}
    finally:
        if old_tmp is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = old_tmp
    return {"w244_session_trust_ordering_probes":
            "held=%d gap=%d errors=%d" % (held, gap, errors)}


def _green_ok(green):
    """A green-check entry passes when it is a skip note or an
    explicit all-held result."""
    for v in green.values():
        if not isinstance(v, str):
            return False
        if v.startswith("GOV_SKIP_GREEN=1"):
            continue
        if v == "held=9 gap=0 errors=0":
            continue
        return False
    return True


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md), red-first: the
# lowercase "gap" verdict is this battery's red phase (the exit contract is
# rc=2 on any gap) and maps to BREAK. Raw RESULTS keep the lowercase
# vocabulary (run_all() counts, and the adjacent green check's
# "held=%d gap=%d errors=%d" string, are untouched); the mapping happens at
# emission, following the w72 precedent. Unknown verdicts fall back to BREAK
# (red-first, never greener).
_VERDICT_MAP = {"held": "HELD", "gap": "BREAK", "error": "ERROR",
                "stopped": "HELD"}


def _note_of(row):
    # D2 contract (w72 precedent): the note lives under detail["note"],
    # falling back to detail["error"] for harness exceptions.
    return row["detail"].get("note") or row["detail"].get("error", "")

def main():
    held, gap, errors = run_all()
    rows = [{"id": r["id"],
             "verdict": _VERDICT_MAP.get(r["verdict"], "BREAK"),
             "detail": r["detail"]} for r in RESULTS]
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        [(r["id"], r["verdict"], _note_of(r)) for r in rows],
        gap, held, errors)
    probe_lines.emit_dicts(rows, pid_key="id", note_getter=_note_of)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("w245_gitspawn_open_path: %d BREAK / %d HELD / %d ERROR"
          % (gap, held, errors))
    green = green_check_adjacent()
    print("adjacent green check: %s" % (green,))
    rc = 0
    if gap or errors or not _green_ok(green):
        rc = 2
    return rc


if __name__ == "__main__":
    sys.exit(main())
