"""Wave-69 break-first probes (2026-09-22): prod KMS key management —
kill the dev-key fallback.

Attack lanes (each must FAIL CLOSED — verdict "stopped"):

  FALLBACK RESURRECTION (every env/config/argument path that could
  silently re-enable the dev key in production):
    fallback_env_alone_refused      — GOV_DEV_KEYS=1 alone, production,
                                       no in-code opt-in -> refuse (F73)
    fallback_dev_bytes_refused      — dev bytes in GOV_LOG_KEY -> refuse
    fallback_dev_epoch_refused      — GOV_LOG_KEY_EPOCH=dev -> refuse
    fallback_archive_smuggle_refused— dev key in GOV_LOG_KEY_ARCHIVE -> refuse (F77)
    fallback_production_contradiction — production + double opt-in ->
                                       refuse LOUD (NEW wave-69 close)
    fallback_keyring_file_dev_seeded— GOV_KEYRING_FILE with dev-seeded
                                       keyring -> refuse
    fallback_unknown_mode           — GOV_DEPLOYMENT_MODE=bogus ->
                                       ValueError fail-fast
  KEY CONFUSION (era mismatch):
    key_confusion_dev_to_prod       — dev-signed log under prod verifier
                                       -> era/label mismatch, fail
    key_confusion_prod_to_dev       — prod-signed log under dev verifier
                                       -> fail
  MIXED-KEY CHAINS (rotation):
    mixed_chain_rotation_verifies   — rotation mid-chain verifies
                                       per-epoch (closure pin)
    mixed_chain_splice_fails        — transplanted old-epoch segment
                                       -> fail
  LOST-KEY BEHAVIOR:
    lost_key_file_deleted           — keyring file deleted -> resolve
                                       fails closed
    lost_key_env_unset_mid_run      — GOV_LOG_KEY unset mid-run -> next
                                       append raises, no unsigned write
  ERA-MARKING HONESTY:
    era_marking_export_honest       — dev-signed log with forged
                                       "production" labels -> export
                                       renders dev/FAILED, never a prod
                                       banner
  LEGITIMATE PATH (closure pin):
    legit_staging_dev_path          — staging + double opt-in -> appends
                                       work, dev era loudly marked

All runs synthetic/local, $0. Deterministic except wall-clock ts
(never asserted on). Env hygiene restores every mutated variable and
the gov.log dev flags in finally.
"""

import contextlib
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
# Import the test harness WITHOUT running tests/__init__.py (which flips
# on the dev-key opt-in process-wide); dev keys are enabled per-probe
# with _env()+_dev_keys() instead, and restored afterwards.
sys.path.insert(0, str(REPO_ROOT / "tests"))

import harness  # noqa: E402
from gov import keyprovider as kp_mod  # noqa: E402
from gov import keys as keys_mod  # noqa: E402
from gov import log as log_mod  # noqa: E402
from gov.keys import KeyRing, NoKeyConfiguredError  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "w69_make_report_probe", str(REPO_ROOT / "demo" / "make_report.py"))
make_report = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(make_report)

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
    """Per-probe dev-key opt-in. Declares staging explicitly (wave-61
    discipline) so the probe is self-sufficient under direct __main__
    runs and under run_evals (ambient staging preserved)."""
    if enabled:
        with _env(GOV_DEV_KEYS="1", GOV_DEPLOYMENT_MODE="staging"):
            prev = log_mod._dev_enabled
            log_mod.enable_dev_keys()
            try:
                yield
            finally:
                log_mod._dev_enabled = prev
    else:
        yield


@contextlib.contextmanager
def _no_dev_optin():
    """Force the dev-key opt-in OFF (both factors), restoring after."""
    with _env(GOV_DEV_KEYS=None):
        prev = log_mod._dev_enabled
        log_mod._dev_enabled = False
        try:
            yield
        finally:
            log_mod._dev_enabled = prev


@contextlib.contextmanager
def _unwarned():
    prev = log_mod._dev_warned
    log_mod._dev_warned = False
    try:
        yield
    finally:
        log_mod._dev_warned = prev


def _govrun():
    old = os.environ.get("TMPDIR")
    old_cached = tempfile.tempdir
    os.environ["TMPDIR"] = "/tmp/gov-run"
    tempfile.tempdir = None
    run_tmp = tempfile.mkdtemp(prefix="w69probe-")
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


_govrun = contextlib.contextmanager(_govrun)


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


def _fresh_log(name="actions.jsonl"):
    d = tempfile.mkdtemp(prefix="w69probe-")
    return log_mod.ActionLog(os.path.join(d, name))


# ----------------------------------------------------------------------
# Fallback resurrection
# ----------------------------------------------------------------------

@_sit("redteam.keymgmt_w69.fallback_env_alone_refused")
def sit_fallback_env_alone_refused():
    """GOV_DEV_KEYS=1 alone (no in-code opt-in) in production must refuse
    (F73) — env alone never enables dev keys."""
    with _env(GOV_DEPLOYMENT_MODE="production"):
        with _no_dev_optin():
            with _env(GOV_DEV_KEYS="1"):
                log = _fresh_log()
                try:
                    log.append({"event": "x"})
                except NoKeyConfiguredError:
                    return {"verdict": "stopped",
                            "note": "env-alone refused (F73)"}
                return {"verdict": "break",
                        "note": "GOV_DEV_KEYS=1 alone started a chain"}


@_sit("redteam.keymgmt_w69.fallback_dev_bytes_refused")
def sit_fallback_dev_bytes_refused():
    """Pasting the public dev bytes into GOV_LOG_KEY must be rejected
    outright, even in production."""
    with _env(GOV_DEPLOYMENT_MODE="production",
              GOV_LOG_KEY=log_mod._DEV_KEY.decode("utf-8")):
        log = _fresh_log()
        try:
            log.append({"event": "x"})
        except NoKeyConfiguredError:
            return {"verdict": "stopped",
                    "note": "dev bytes in GOV_LOG_KEY refused"}
        return {"verdict": "break",
                "note": "dev bytes accepted as a production key"}


@_sit("redteam.keymgmt_w69.fallback_dev_epoch_refused")
def sit_fallback_dev_epoch_refused():
    """A real key with GOV_LOG_KEY_EPOCH=dev must be rejected."""
    with _env(GOV_DEPLOYMENT_MODE="production",
              GOV_LOG_KEY="real-operator-key",
              GOV_LOG_KEY_EPOCH="dev"):
        log = _fresh_log()
        try:
            log.append({"event": "x"})
        except NoKeyConfiguredError:
            return {"verdict": "stopped",
                    "note": "dev epoch with real key refused"}
        return {"verdict": "break",
                "note": "dev epoch accepted on a real key"}


@_sit("redteam.keymgmt_w69.fallback_archive_smuggle_refused")
def sit_fallback_archive_smuggle_refused():
    """Smuggling the dev key via GOV_LOG_KEY_ARCHIVE under a retired
    epoch must be rejected (F77)."""
    archive = json.dumps(
        {"epoch-old": log_mod._DEV_KEY.decode("utf-8")})
    with _env(GOV_DEPLOYMENT_MODE="production",
              GOV_LOG_KEY="real-operator-key",
              GOV_LOG_KEY_ARCHIVE=archive):
        try:
            KeyRing.from_env()
        except NoKeyConfiguredError:
            return {"verdict": "stopped",
                    "note": "dev key in archive refused (F77)"}
        return {"verdict": "break",
                "note": "dev key smuggled via archive accepted"}


@_sit("redteam.keymgmt_w69.fallback_production_contradiction")
def sit_fallback_production_contradiction():
    """THE wave-69 close: production mode + the full double opt-in
    (in-code enable_dev_keys() AND GOV_DEV_KEYS=1) must REFUSE LOUD —
    a deployment that declared itself production but has dev-key
    enabling active (stray import + inherited env) previously got
    dev-key chains behind a stderr warning."""
    with _env(GOV_DEPLOYMENT_MODE="production", GOV_DEV_KEYS="1"):
        prev = log_mod._dev_enabled
        log_mod.enable_dev_keys()
        try:
            log = _fresh_log()
            try:
                log.append({"event": "x"})
            except NoKeyConfiguredError as e:
                loud = ("production" in str(e)
                        and "contradicts" in str(e))
                return {"verdict": "stopped" if loud else "break",
                        "note": "contradiction refused loud"
                                if loud else
                                "refused but not loud: %s" % e}
            return {"verdict": "break",
                    "note": "dev-key chain started in production mode"}
        finally:
            log_mod._dev_enabled = prev


@_sit("redteam.keymgmt_w69.fallback_keyring_file_dev_seeded")
def sit_fallback_keyring_file_dev_seeded():
    """GOV_KEYRING_FILE pointing at a keyring seeded with the public dev
    key must be rejected."""
    d = tempfile.mkdtemp(prefix="w69probe-")
    ring = KeyRing.generate("epoch-1")
    ring._keys["epoch-1"] = keys_mod.KeyMaterial(
        "epoch-1", log_mod._DEV_KEY, status="active")
    p = os.path.join(d, "keyring.json")
    ring.save(p)
    with _env(GOV_DEPLOYMENT_MODE="production", GOV_KEYRING_FILE=p):
        log = _fresh_log()
        try:
            log.append({"event": "x"})
        except NoKeyConfiguredError:
            return {"verdict": "stopped",
                    "note": "dev-seeded keyring file refused"}
        return {"verdict": "break",
                "note": "dev-seeded keyring file accepted"}


@_sit("redteam.keymgmt_w69.fallback_unknown_mode")
def sit_fallback_unknown_mode():
    """A garbage GOV_DEPLOYMENT_MODE must fail fast, never silently
    disable the guard."""
    with _env(GOV_DEPLOYMENT_MODE="bogus"):
        log = _fresh_log()
        try:
            log.append({"event": "x"})
        except ValueError as e:
            return {"verdict": "stopped",
                    "note": "unknown mode fail-fast: %s" % e}
        except NoKeyConfiguredError:
            return {"verdict": "break",
                    "note": "unknown mode fell through to key resolution"}
        return {"verdict": "break",
                "note": "unknown mode started a chain"}


# ----------------------------------------------------------------------
# Key confusion
# ----------------------------------------------------------------------

@_sit("redteam.keymgmt_w69.key_confusion_dev_to_prod")
def sit_key_confusion_dev_to_prod():
    """Dev-signed records presented to a production verifier must fail
    with an era/label mismatch — never verify."""
    with _dev_keys(True):
        log = _fresh_log()
        log.append({"event": "x"})
        path = str(log.path)
    with _env(GOV_DEPLOYMENT_MODE="production",
              GOV_LOG_KEY="production-key-material"):
        v = log_mod._verify(path)
    if not v["ok"] and "key_epoch" in (v["error"] or ""):
        return {"verdict": "stopped",
                "note": "dev log rejected by prod verifier: %s"
                        % v["error"]}
    return {"verdict": "break",
            "note": "dev-signed log verified under a prod key: %r" % v}


@_sit("redteam.keymgmt_w69.key_confusion_prod_to_dev")
def sit_key_confusion_prod_to_dev():
    """Prod-signed records presented to a dev verifier must fail."""
    with _env(GOV_DEPLOYMENT_MODE="production",
              GOV_LOG_KEY="production-key-material",
              GOV_LOG_KEY_EPOCH="epoch-1"):
        log = _fresh_log()
        log.append({"event": "x"})
        path = str(log.path)
    with _dev_keys(True):
        v = log_mod._verify(path)
    if not v["ok"] and "key_epoch" in (v["error"] or ""):
        return {"verdict": "stopped",
                "note": "prod log rejected by dev verifier: %s"
                        % v["error"]}
    return {"verdict": "break",
            "note": "prod-signed log verified under dev keys: %r" % v}


# ----------------------------------------------------------------------
# Mixed-key chains
# ----------------------------------------------------------------------

@_sit("redteam.keymgmt_w69.mixed_chain_rotation_verifies")
def sit_mixed_chain_rotation_verifies():
    """Legitimate rotation mid-chain: old segments verify with the old
    key, new with the new (closure pin — rotation keeps working)."""
    with _env(GOV_DEPLOYMENT_MODE="production"):
        ring = KeyRing.generate("epoch-1")
        ring.activate()
        try:
            log = _fresh_log()
            log.append({"event": "pre", "i": 1})
            ring.rotate("epoch-2")
            ring.activate()
            log.append({"event": "post", "i": 2})
            path = str(log.path)
            verdict = ring.verify_log(path)
            if verdict["ok"] and verdict["epochs_seen"] == [
                    "epoch-1", "epoch-2"]:
                return {"verdict": "stopped",
                        "note": "rotation verifies per-epoch"}
            return {"verdict": "break",
                    "note": "legitimate rotation failed: %r" % verdict}
        finally:
            for k in ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH",
                      "GOV_LOG_KEY_ARCHIVE"):
                os.environ.pop(k, None)


@_sit("redteam.keymgmt_w69.mixed_chain_splice_fails")
def sit_mixed_chain_splice_fails():
    """An attacker-transplanted old-epoch segment must fail
    verification — the MAC binds (epoch, prev_hash, content)."""
    with _env(GOV_DEPLOYMENT_MODE="production"):
        ring = KeyRing.generate("epoch-1")
        ring.activate()
        try:
            log = _fresh_log()
            for i in range(3):
                log.append({"event": "e", "i": i})
            ring.rotate("epoch-2")
            ring.activate()
            for i in range(3, 5):
                log.append({"event": "e", "i": i})
            path = str(log.path)
            lines = [l for l in Path(path).read_text(
                encoding="utf-8").splitlines() if l.strip()]
            victim = json.loads(lines[3])
            donor = json.loads(lines[0])
            donor["seq"] = victim["seq"]
            lines[3] = json.dumps(donor, ensure_ascii=True)
            Path(path).write_text("\n".join(lines) + "\n",
                                  encoding="utf-8")
            verdict = ring.verify_log(path)
            if not verdict["ok"]:
                return {"verdict": "stopped",
                        "note": "spliced chain rejected: %s"
                                % verdict["error"]}
            return {"verdict": "break",
                    "note": "spliced chain verified clean"}
        finally:
            for k in ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH",
                      "GOV_LOG_KEY_ARCHIVE"):
                os.environ.pop(k, None)


# ----------------------------------------------------------------------
# Lost-key behavior
# ----------------------------------------------------------------------

@_sit("redteam.keymgmt_w69.lost_key_file_deleted")
def sit_lost_key_file_deleted():
    """The keyring file is deleted: resolution fails closed, loud."""
    d = tempfile.mkdtemp(prefix="w69probe-")
    ring = KeyRing.generate("epoch-1")
    p = os.path.join(d, "keyring.json")
    ring.save(p)
    with _env(GOV_DEPLOYMENT_MODE="production", GOV_KEYRING_FILE=p):
        key, _ = kp_mod.resolve_active_key()
        assert key == ring.active().key
        os.unlink(p)
        try:
            kp_mod.resolve_active_key()
        except (FileNotFoundError, OSError, NoKeyConfiguredError) as e:
            return {"verdict": "stopped",
                    "note": "deleted key file fails closed: %s: %s"
                            % (type(e).__name__, e)}
        return {"verdict": "break",
                "note": "resolution survived key-file deletion"}


@_sit("redteam.keymgmt_w69.lost_key_env_unset_mid_run")
def sit_lost_key_env_unset_mid_run():
    """GOV_LOG_KEY vanishes mid-run: the next append fails closed —
    no silent unsigned continuation."""
    with _env(GOV_DEPLOYMENT_MODE="production",
              GOV_LOG_KEY="mid-run-key"):
        log = _fresh_log()
        log.append({"event": "before"})
        os.environ.pop("GOV_LOG_KEY", None)
        with _no_dev_optin():
            try:
                log.append({"event": "after"})
            except NoKeyConfiguredError:
                return {"verdict": "stopped",
                        "note": "mid-run key loss fails closed"}
            return {"verdict": "break",
                    "note": "append succeeded with no key configured"}


# ----------------------------------------------------------------------
# Era-marking honesty
# ----------------------------------------------------------------------

@_sit("redteam.keymgmt_w69.era_marking_export_honest")
def sit_era_marking_export_honest():
    """A dev-signed log with forged 'production' labels must render
    dev/FAILED in the evidence export — a prod banner over dev-key
    material is unreachable."""
    with _dev_keys(True):
        log = _fresh_log()
        log.append({"event": "probe"})
        path = str(log.path)
    entries = [json.loads(l) for l in Path(path).read_text(
        encoding="utf-8").splitlines() if l.strip()]
    for e in entries:
        e["key_epoch"] = "production"
        e["hash"] = log_mod._compute_mac(
            log_mod._DEV_KEY, "production", e["prev_hash"],
            log_mod._canonical(e))
    forged = os.path.join(os.path.dirname(path), "forged.jsonl")
    Path(forged).write_text("\n".join(
        json.dumps(e, ensure_ascii=True) for e in entries) + "\n",
        encoding="utf-8")
    with _dev_keys(True):
        verdict = log_mod._verify(forged)
    assert not verdict["ok"], "forged labels must not verify"
    ks = make_report.key_status(entries, verdict["key_epoch"])
    md = make_report.render_markdown(
        "w69-probe", "2026-09-22T00:00:00+00:00", False, len(entries),
        [], [], ks, None)
    prod_banner = "Operator-configured key" in ks["banner_line"]
    dev_banner = ks["status"] == "dev" and bool(ks["label_mismatch"])
    if dev_banner and not prod_banner and "PUBLIC/DEVELOPMENT" in md:
        return {"verdict": "stopped",
                "note": "forged labels render dev/FAILED with mismatch "
                        "flagged, never a prod banner"}
    return {"verdict": "break",
            "note": "export mis-graded forged labels: %r" % ks}


# ----------------------------------------------------------------------
# Legitimate path (closure pin)
# ----------------------------------------------------------------------

@_sit("redteam.keymgmt_w69.legit_staging_dev_path")
def sit_legit_staging_dev_path():
    """Staging + double opt-in still works: appends land, the dev era is
    loudly marked (stderr warning + dev epoch on every entry)."""
    import io
    from contextlib import redirect_stderr
    with _dev_keys(True):
        with _unwarned():
            buf = io.StringIO()
            with redirect_stderr(buf):
                log = _fresh_log()
                e = log.append({"event": "legit"})
            warned = "PUBLIC development key" in buf.getvalue()
        v = log_mod._verify(str(log.path))
    if v["ok"] and e["key_epoch"] == "dev" and warned:
        return {"verdict": "stopped",
                "note": "legit dev path intact, era loudly marked"}
    return {"verdict": "break",
            "note": "legit dev path broken: ok=%s epoch=%s warned=%s"
                    % (v["ok"], e.get("key_epoch"), warned)}


def _main():
    for sid in sorted(SITUATIONS):
        SITUATIONS[sid]()
    stopped = [r for r in RESULTS if r["verdict"] == "stopped"]
    broken = [r for r in RESULTS if r["verdict"] not in ("stopped",)]
    print("wave-69 probes: %d stopped / %d total"
          % (len(stopped), len(RESULTS)))
    for r in RESULTS:
        print("  %-55s %s" % (r["id"], r["verdict"]))
        if r["verdict"] != "stopped":
            print("    %r" % (r["detail"],))
    return 0 if not broken else 1


if __name__ == "__main__":
    sys.exit(_main())
