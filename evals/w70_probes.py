"""Wave-70 break-first probes (2026-09-22): deployment_mode kwarg wiring.

Wave-69's design says "explicit deployment_mode= kwarg wins" but only
resolve_active_key() had the kwarg. Wave-70 wires it end-to-end
(keyword-only deployment_mode=None on ActionLog.__init__ and
keys.require_key()). Each probe attacks the wiring; every probe must
FAIL CLOSED (verdict "stopped"):

  KWARG AUTHORITY (kwarg-vs-env conflicts — the documented precedence):
    kwarg_wins_over_env            — env=production + dev opt-in, kwarg
                                     staging -> staging wins (dev key,
                                     loud); env must NOT override the
                                     explicit kwarg
    kwarg_production_contradiction  — env=staging + dev opt-in, kwarg
                                     production -> wave-69 contradiction
                                     refuses LOUD at append
  FAIL-FAST:
    kwarg_unknown_mode_failfast     — deployment_mode="bogus" ->
                                     ValueError at CONSTRUCTION (before
                                     any log operation)
  NO FALLBACK RESURRECTION:
    kwarg_none_production_no_key_refused — no kwarg, production env, no
                                     key configured -> loud refusal,
                                     never dev fallback
  REQUIRE_KEY WIRING:
    require_key_kwarg_contradiction — require_key(deployment_mode=
                                     "production") with staging env +
                                     dev opt-in -> contradiction refuses
  LEGITIMATE PATH (closure pin):
    kwarg_env_key_still_wins        — GOV_LOG_KEY set + kwarg staging ->
                                     provider order unchanged (env key
                                     resolves); the mode declaration
                                     does not disturb key selection

All runs synthetic/local, $0. Deterministic except wall-clock ts
(never asserted on). Env hygiene restores every mutated variable and
the gov.log dev flags in finally.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stderr
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
# Import the test harness WITHOUT running tests/__init__.py (which flips
# on the dev-key opt-in process-wide); dev keys are enabled per-probe
# with _dev_keys() instead, and restored afterwards.
sys.path.insert(0, str(REPO_ROOT / "tests"))

import harness  # noqa: E402
from gov import keys as keys_mod  # noqa: E402
from gov import log as log_mod  # noqa: E402
from gov.keys import NoKeyConfiguredError  # noqa: E402

RESULTS = []
SITUATIONS = {}

_KEY_ENV = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE",
            "GOV_DEV_KEYS", "GOV_DEPLOYMENT_MODE", "GOV_KEYRING_FILE")


@contextlib.contextmanager
def _env(**pairs):
    saved = {k: os.environ.get(k) for k in pairs}
    had = {k: k in os.environ for k in pairs}
    for k, v in pairs.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k in pairs:
            if had[k]:
                os.environ[k] = saved[k]
            else:
                os.environ.pop(k, None)


@contextlib.contextmanager
def _dev_keys(enabled=True):
    """Per-probe dev-key opt-in (in-code factor only; env set by hand)."""
    prev = log_mod._dev_enabled
    log_mod._dev_enabled = enabled
    try:
        yield
    finally:
        log_mod._dev_enabled = prev


@contextlib.contextmanager
def _clean_key_env():
    with _env(**{k: None for k in _KEY_ENV}):
        prev_enabled = log_mod._dev_enabled
        prev_warned = log_mod._dev_warned
        log_mod._dev_enabled = False
        log_mod._dev_warned = False
        try:
            yield
        finally:
            log_mod._dev_enabled = prev_enabled
            log_mod._dev_warned = prev_warned


@contextlib.contextmanager
def _govrun():
    old = os.environ.get("TMPDIR")
    old_cached = tempfile.tempdir
    os.environ["TMPDIR"] = "/tmp/gov-run"
    tempfile.tempdir = None
    run_tmp = tempfile.mkdtemp(prefix="w70probe-")
    try:
        yield run_tmp
    finally:
        if old is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = old
        tempfile.tempdir = old_cached
        import shutil
        shutil.rmtree(run_tmp, ignore_errors=True)


def _sit(sid):
    def deco(fn):
        def wrapper():
            try:
                with _govrun():
                    detail = fn()
                if not isinstance(detail, dict):
                    detail = {"note": str(detail)}
                verdict = detail.pop("verdict", "stopped")
                RESULTS.append({"id": sid, "verdict": verdict,
                                "detail": detail})
            except Exception as e:  # noqa: BLE001 - probe must not die
                RESULTS.append({"id": sid, "verdict": "error",
                                "detail": {"error": "%s: %s"
                                           % (type(e).__name__, e)}})
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        SITUATIONS[sid] = wrapper
        return wrapper
    return deco


def _fresh_log(deployment_mode=None, name="actions.jsonl"):
    d = tempfile.mkdtemp(prefix="w70probe-")
    if deployment_mode is None:
        return log_mod.ActionLog(os.path.join(d, name))
    return log_mod.ActionLog(os.path.join(d, name),
                             deployment_mode=deployment_mode)


def _entry_epoch(log):
    with open(str(log.path), encoding="utf-8") as f:
        return json.loads(f.readline()).get("key_epoch")


# ----------------------------------------------------------------------
# Kwarg authority
# ----------------------------------------------------------------------

@_sit("redteam.keymgmt_w70.kwarg_wins_over_env")
def sit_kwarg_wins_over_env():
    """Env declares production with the dev opt-in fully armed; the
    explicit kwarg says staging. The kwarg must be authoritative: the
    staging dev key resolves (loudly) — the environment must not
    override an explicit declaration."""
    with _clean_key_env():
        with _env(GOV_DEPLOYMENT_MODE="production", GOV_DEV_KEYS="1"):
            with _dev_keys(True):
                buf = io.StringIO()
                with redirect_stderr(buf):
                    log = _fresh_log(deployment_mode="staging")
                    log.append({"event": "kwarg-wins"})
                warned = "PUBLIC development key" in buf.getvalue()
    if _entry_epoch(log) == "dev" and warned:
        return {"verdict": "stopped",
                "note": "explicit kwarg authoritative over env; loud"}
    return {"verdict": "break",
            "note": "kwarg did not win over env"}


@_sit("redteam.keymgmt_w70.kwarg_production_contradiction")
def sit_kwarg_production_contradiction():
    """Env declares staging with the dev opt-in fully armed; the
    explicit kwarg declares production. The wave-69 contradiction must
    refuse LOUD at append — a production declaration with dev-key
    enabling active is misconfigured, whichever side declared what."""
    with _clean_key_env():
        with _env(GOV_DEPLOYMENT_MODE="staging", GOV_DEV_KEYS="1"):
            with _dev_keys(True):
                log = _fresh_log(deployment_mode="production")
                try:
                    with redirect_stderr(io.StringIO()):
                        log.append({"event": "must-not-write"})
                except NoKeyConfiguredError:
                    return {"verdict": "stopped",
                            "note": "contradiction refused loud"}
    return {"verdict": "break",
            "note": "production kwarg + dev opt-in appended anyway"}


# ----------------------------------------------------------------------
# Fail-fast
# ----------------------------------------------------------------------

@_sit("redteam.keymgmt_w70.kwarg_unknown_mode_failfast")
def sit_kwarg_unknown_mode_failfast():
    """An unknown mode string via the kwarg must fail fast AT
    CONSTRUCTION — a misconfigured mode must not survive to first
    append (where 'unknown' could otherwise mean 'unguarded')."""
    with _clean_key_env():
        try:
            _fresh_log(deployment_mode="bogus")
        except ValueError:
            return {"verdict": "stopped",
                    "note": "unknown mode failed fast at construction"}
    return {"verdict": "break",
            "note": "unknown mode kwarg survived construction"}


# ----------------------------------------------------------------------
# No fallback resurrection
# ----------------------------------------------------------------------

@_sit("redteam.keymgmt_w70.kwarg_none_production_no_key_refused")
def sit_kwarg_none_production_no_key_refused():
    """No kwarg (falls through to env -> production default), no key
    configured, no opt-in: loud refusal, never a silent dev fallback."""
    with _clean_key_env():
        with _env(GOV_DEPLOYMENT_MODE="production"):
            log = _fresh_log()
            try:
                log.append({"event": "must-not-write"})
            except NoKeyConfiguredError:
                return {"verdict": "stopped",
                        "note": "loud refusal, no dev fallback"}
    return {"verdict": "break",
            "note": "production with no key did not refuse"}


# ----------------------------------------------------------------------
# require_key wiring
# ----------------------------------------------------------------------

@_sit("redteam.keymgmt_w70.require_key_kwarg_contradiction")
def sit_require_key_kwarg_contradiction():
    """require_key(deployment_mode='production') with staging env and
    the dev opt-in fully armed: the kwarg wins and the contradiction
    refuses loud."""
    with _clean_key_env():
        with _env(GOV_DEPLOYMENT_MODE="staging", GOV_DEV_KEYS="1"):
            with _dev_keys(True):
                try:
                    keys_mod.require_key(deployment_mode="production")
                except NoKeyConfiguredError:
                    return {"verdict": "stopped",
                            "note": "require_key kwarg contradiction "
                                    "refused loud"}
    return {"verdict": "break",
            "note": "require_key kwarg contradiction not applied"}


# ----------------------------------------------------------------------
# Legitimate path (closure pin)
# ----------------------------------------------------------------------

@_sit("redteam.keymgmt_w70.kwarg_env_key_still_wins")
def sit_kwarg_env_key_still_wins():
    """A configured env key still wins regardless of the mode kwarg:
    the mode declaration governs the dev-fallback/contradiction rule,
    not provider order. Legitimate configured deployments are
    undisturbed by the new kwarg."""
    with _clean_key_env():
        with _env(GOV_LOG_KEY="wave70-probe-env-key-32-bytes-min!!",
                  GOV_DEPLOYMENT_MODE="production"):
            with _dev_keys(False):
                log = _fresh_log(deployment_mode="staging")
                log.append({"event": "env-key"})
                v = log_mod._verify(str(log.path))
    if v["ok"]:
        return {"verdict": "stopped",
                "note": "env key resolves; chain verifies; kwarg inert"}
    return {"verdict": "break",
            "note": "env-key path disturbed by kwarg: %r" % (v,)}


def _main():
    for sid in sorted(SITUATIONS):
        SITUATIONS[sid]()
    stopped = [r for r in RESULTS if r["verdict"] == "stopped"]
    broken = [r for r in RESULTS if r["verdict"] not in ("stopped",)]
    print("wave-70 probes: %d stopped / %d total"
          % (len(stopped), len(RESULTS)))
    for r in RESULTS:
        print("  %-55s %s" % (r["id"], r["verdict"]))
        if r["verdict"] != "stopped":
            print("    %r" % (r["detail"],))
    return 0 if not broken else 1


if __name__ == "__main__":
    sys.exit(_main())
