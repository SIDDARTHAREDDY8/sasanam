"""Wave-71 break-first probes (2026-09-22): in-memory key zeroization
+ the EgressLedger deployment_mode follow-up.

ZEROIZATION — each probe attacks the wave-71 mechanism; every probe
must FAIL CLOSED (verdict "stopped"):

  WIPE VERIFICATION:
    zeroize_wipes_reachable_buffer — provider buffer holds the key;
      destroy() -> the SAME buffer object reads all zeros (an
      attacker reading the discarded buffer recovers nothing)
    double_wipe_safe              — destroy() twice: no error, still
      wiped (idempotent)
  USE-AFTER-WIPE (the forgery footgun):
    use_after_wipe_fails_loud      — HMAC with a destroyed material
      raises TypeError (never a silent all-zero-key MAC); a
      destroyed ring cannot activate (raises loud)
  EXCEPTION PATH:
    exception_skips_wipe           — raising consumer inside
      key_buffer: the wipe still happens (finally discipline)
  ANTI-THEATER:
    immutable_wipe_theater_refused  — zeroize(b"...") / zeroize("...")
      raise TypeError: "wiping" an immutable is refused loud, never
      silently pretended
  COPY CENSUS:
    census_wipable_gone            — refcount census: after destroy()
      exactly one holder of the buffer remains (the probe frame);
      the HMAC object retained no Python-level key reference
  BOUNDARY PIN (documented residual, not a finding):
    env_str_residual_documented    — os.environ str values are
      immutable: zeroize refuses loud and the str persists. The
      residual is named in the verdict detail.

EGRESS LEDGER follow-up (wave-70 loose end — "forking mode semantics
vs the SAME-key-epochs-as-the-log contract", resolved ONE way: the
ledger NEVER declares its own mode; it inherits the process-level
resolution, so the same-epoch contract cannot fork):

    ledger_inherits_env_mode       — GOV_DEPLOYMENT_MODE=staging +
      dev opt-in: ActionLog and EgressLedger entries land under the
      SAME epoch ("dev") — the contract holds, one declaration moves
      both together
    ledger_no_fork_kwarg           — EgressLedger(path,
      deployment_mode="staging") raises TypeError: per-ledger mode
      forking is not expressible
    ledger_kwarg_mismatch_fails_loud — ActionLog(deployment_mode=
      "staging") with unset env mode: the log resolves staging/dev
      while the ledger resolves production -> the ledger REFUSES
      LOUD (production+dev contradiction), never silently forks
      epochs. Operator-alignment boundary, documented.

All runs synthetic/local, $0. Deterministic except wall-clock ts
(never asserted on). Env hygiene restores every mutated variable and
the gov.log dev flags in finally.
"""

import contextlib
import hashlib
import hmac
import io
import json
import os
import secrets
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
from gov.egress_ledger import EgressLedger  # noqa: E402
from gov.keys import KeyMaterial, KeyRing, NoKeyConfiguredError  # noqa: E402
from gov.zeroize import zeroize, key_buffer  # noqa: E402

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
    run_tmp = tempfile.mkdtemp(prefix="w71probe-")
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


# ----------------------------------------------------------------------
# Zeroization
# ----------------------------------------------------------------------

@_sit("redteam.zeroize_w71.zeroize_wipes_reachable_buffer")
def sit_zeroize_wipes_reachable_buffer():
    """Attacker reads the provider's key buffer after discard: the
    SAME buffer object must read all zeros — destroy() wiped it."""
    canary = secrets.token_bytes(32)
    mat = KeyMaterial("epoch-p1", canary)
    buf = mat.key
    assert bytes(buf) == canary
    # use it the way the log path does, then discard
    hmac.new(mat.key, b"probe", hashlib.sha256).hexdigest()
    mat.destroy()
    if bytes(buf) == b"\x00" * len(canary) and mat.key is None:
        return {"verdict": "stopped",
                "note": "discarded provider buffer reads all zeros"}
    return {"verdict": "break",
            "note": "buffer still holds key material after destroy()"}


@_sit("redteam.zeroize_w71.double_wipe_safe")
def sit_double_wipe_safe():
    """Double destroy(): must be a safe no-op, never an error, and
    the buffer stays wiped."""
    mat = KeyMaterial("epoch-p2", secrets.token_bytes(32))
    buf = mat.key
    mat.destroy()
    try:
        mat.destroy()
    except Exception as e:  # noqa: BLE001
        return {"verdict": "break",
                "note": "double destroy raised %r" % e}
    if bytes(buf) == b"\x00" * 32 and mat.key is None:
        return {"verdict": "stopped", "note": "double wipe safe"}
    return {"verdict": "break", "note": "buffer not wiped after double"}


@_sit("redteam.zeroize_w71.use_after_wipe_fails_loud")
def sit_use_after_wipe_fails_loud():
    """The forgery footgun: a destroyed key must never silently HMAC
    under an all-zero key. Any use after destroy() raises loud."""
    mat = KeyMaterial("epoch-p3", secrets.token_bytes(32))
    mat.destroy()
    try:
        hmac.new(mat.key, b"forge-me", hashlib.sha256).hexdigest()
    except TypeError:
        pass
    else:
        return {"verdict": "break",
                "note": "HMAC with destroyed key did NOT raise"}
    ring = KeyRing.generate(epoch="epoch-1")
    ring.destroy()
    try:
        ring.activate()
    except (KeyError, AttributeError, TypeError):
        return {"verdict": "stopped",
                "note": "post-wipe use raises loud; no zero-key MAC"}
    return {"verdict": "break",
            "note": "destroyed ring activated without raising"}


@_sit("redteam.zeroize_w71.exception_skips_wipe")
def sit_exception_skips_wipe():
    """An exception between key-use and wipe must not skip the wipe
    (context-manager discipline)."""
    canary = secrets.token_bytes(32)
    seen = []
    try:
        with key_buffer(canary) as buf:
            seen.append(buf)
            hmac.new(buf, b"m", hashlib.sha256).hexdigest()
            raise RuntimeError("consumer blew up")
    except RuntimeError:
        pass
    if bytes(seen[0]) == b"\x00" * len(canary):
        return {"verdict": "stopped",
                "note": "wipe survived the exception path"}
    return {"verdict": "break", "note": "exception skipped the wipe"}


@_sit("redteam.zeroize_w71.immutable_wipe_theater_refused")
def sit_immutable_wipe_theater_refused():
    """Anti-theater pin: zeroize() must REFUSE bytes/str with
    TypeError — "wiping" an immutable would be a lie."""
    refused = 0
    for imm in (b"sixteen-bytes-key!", "sixteen-bytes-key!"):
        try:
            zeroize(imm)
        except TypeError:
            refused += 1
    if refused == 2:
        return {"verdict": "stopped",
                "note": "immutable wipe refused loud (2/2)"}
    return {"verdict": "break",
            "note": "zeroize accepted an immutable input"}


@_sit("redteam.zeroize_w71.census_wipable_gone")
def sit_census_wipable_gone():
    """Refcount census: after destroy() exactly one holder of the key
    buffer remains (this probe's frame); the HMAC object kept no
    Python-level reference."""
    import sys as _sys
    canary = secrets.token_bytes(32)
    mat = KeyMaterial("epoch-p6", canary)
    buf = mat.key
    hmac.new(mat.key, b"census", hashlib.sha256).hexdigest()
    mat.destroy()
    holders = _sys.getrefcount(buf) - 1  # minus getrefcount's own arg
    del mat, buf
    if holders == 1:
        return {"verdict": "stopped",
                "note": "wipable inventory gone; 1 holder (probe frame)"}
    return {"verdict": "break",
            "note": "unexpected holders after destroy(): %d" % holders}


@_sit("redteam.zeroize_w71.env_str_residual_documented")
def sit_env_str_residual_documented():
    """Boundary pin (documented residual, NOT a finding):
    os.environ values are immutable str — zeroize refuses loud and
    the str persists. The verdict documents the boundary."""
    with _env(GOV_W71_PROBE="probe-key-material"):
        refused = False
        try:
            zeroize(os.environ["GOV_W71_PROBE"])
        except TypeError:
            refused = True
        persists = os.environ.get("GOV_W71_PROBE") == "probe-key-material"
    if refused and persists:
        return {"verdict": "stopped",
                "note": "boundary documented: immutable env str "
                        "refused loud and persists; raw-memory/ "
                        "allocator residue likewise out of reach "
                        "(see zeroization design doc E2)"}
    return {"verdict": "break",
            "note": "env-str residual behaved unexpectedly"}


# ----------------------------------------------------------------------
# EgressLedger deployment_mode follow-up
# ----------------------------------------------------------------------

def _first_epoch(path):
    with open(str(path), encoding="utf-8") as f:
        return json.loads(f.readline()).get("key_epoch")


@_sit("redteam.zeroize_w71.ledger_inherits_env_mode")
def sit_ledger_inherits_env_mode():
    """One declaration moves log+ledger together: staging env + dev
    opt-in -> ActionLog AND EgressLedger entries land under the SAME
    epoch. The same-epoch contract holds."""
    with _clean_key_env():
        with _env(GOV_DEPLOYMENT_MODE="staging", GOV_DEV_KEYS="1"):
            with _dev_keys(True):
                buf = io.StringIO()
                with redirect_stderr(buf):
                    d = tempfile.mkdtemp(prefix="w71probe-ledger-")
                    log = log_mod.ActionLog(
                        os.path.join(d, "actions.jsonl"))
                    log.append({"event": "ledger-mode-probe"})
                    led = EgressLedger(os.path.join(d, "egress.jsonl"))
                    led.append({"api": "probe.call", "args": {}})
                log_epoch = _first_epoch(log.path)
                led_epoch = _first_epoch(led.path)
    if log_epoch == led_epoch == "dev":
        return {"verdict": "stopped",
                "note": "log+ledger share epoch 'dev' under one "
                        "env declaration"}
    return {"verdict": "break",
            "note": "epochs forked: log=%r ledger=%r"
                    % (log_epoch, led_epoch)}


@_sit("redteam.zeroize_w71.ledger_no_fork_kwarg")
def sit_ledger_no_fork_kwarg():
    """Per-ledger mode forking is not expressible: the kwarg does not
    exist, so attempting it fails fast with TypeError."""
    d = tempfile.mkdtemp(prefix="w71probe-ledger-")
    try:
        EgressLedger(os.path.join(d, "egress.jsonl"),
                     deployment_mode="staging")
    except TypeError:
        return {"verdict": "stopped",
                "note": "no per-ledger mode kwarg; fork not expressible"}
    return {"verdict": "break",
            "note": "EgressLedger accepted a deployment_mode kwarg"}


@_sit("redteam.zeroize_w71.ledger_kwarg_mismatch_fails_loud")
def sit_ledger_kwarg_mismatch_fails_loud():
    """ActionLog(deployment_mode='staging') with unset env mode: the
    log resolves staging/dev while the ledger resolves production ->
    the ledger must REFUSE LOUD (production+dev contradiction), never
    silently fork epochs."""
    with _clean_key_env():
        with _env(GOV_DEV_KEYS="1"):  # GOV_DEPLOYMENT_MODE unset
            with _dev_keys(True):
                buf = io.StringIO()
                with redirect_stderr(buf):
                    d = tempfile.mkdtemp(prefix="w71probe-ledger-")
                    log = log_mod.ActionLog(
                        os.path.join(d, "actions.jsonl"),
                        deployment_mode="staging")
                    log.append({"event": "mismatch-probe"})
                    led = EgressLedger(os.path.join(d, "egress.jsonl"))
                    try:
                        led.append({"api": "probe.call", "args": {}})
                    except NoKeyConfiguredError as e:
                        return {
                            "verdict": "stopped",
                            "note": "ledger refused loud "
                                    "(production+dev contradiction); "
                                    "no silent epoch fork: %.80s" % e}
                    except Exception as e:  # noqa: BLE001
                        return {"verdict": "break",
                                "note": "wrong exception type: %r" % e}
    return {"verdict": "break",
            "note": "ledger appended despite the mode mismatch "
                    "(silent fork?)"}


def main():
    for sid in sorted(SITUATIONS):
        SITUATIONS[sid]()
    n_hold = sum(1 for r in RESULTS if r["verdict"] == "stopped")
    n_miss = sum(1 for r in RESULTS if r["verdict"] not in ("stopped",))
    for r in RESULTS:
        print("%-55s %s  %s" % (r["id"], r["verdict"],
                                r["detail"].get("note", "")))
    print("w71 battery: %d HOLD / %d MISS|ERROR" % (n_hold, n_miss))
    return 1 if n_miss else 0


if __name__ == "__main__":
    sys.exit(main())
