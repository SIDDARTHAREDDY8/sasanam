"""Wave-69 break-first probes (2026-09-22), wave-81 semantics (2026-09-23):
prod KMS key management — the dev-key fallback is DELETED from gov/.

Attack lanes (each must FAIL CLOSED — verdict "stopped"):

  NO-FALLBACK (every key-resolution path without explicit provisioning
  refuses, in every deployment mode; explicit material is used verbatim):
    fallback_env_alone_refused      — nothing configured, production ->
                                       refuse (no fallback left to enable)
    fallback_dev_bytes_refused      — retired public dev bytes placed in
                                       GOV_LOG_KEY are used AS CONFIGURED
                                       (no screening anymore); nothing
                                       mints them unconfigured
    fallback_dev_epoch_refused      — epoch "dev" is a label, not a gate:
                                       a real key with epoch "dev" works,
                                       and the export marks it
                                       non-production honestly
    fallback_archive_smuggle_refused— archive epochs are used as-is
                                       per-epoch (no screening); explicit
                                       archive still verifies
    fallback_production_contradiction — the wave-69 contradiction is
                                       unstatable now: production mode +
                                       explicit key appends; production +
                                       no key refuses loud
    fallback_keyring_file_dev_seeded— GOV_KEYRING_FILE material is used
                                       as configured, in every mode
    fallback_unknown_mode           — GOV_DEPLOYMENT_MODE=bogus ->
                                       ValueError fail-fast
  KEY CONFUSION (era mismatch):
    key_confusion_dev_to_prod       — key-one-signed log under a key-two
                                       verifier -> era/label mismatch, fail
    key_confusion_prod_to_dev       — key-two-signed log under a key-one
                                       verifier -> fail
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
    era_marking_export_honest       — explicit-key log with forged
                                       "production" labels -> export
                                       renders non-production/FAILED,
                                       never a prod banner
  LEGITIMATE PATH (closure pin):
    legit_staging_dev_path          — explicit provisioning works in
                                       every mode, no warnings, era
                                       marked by the configured epoch

Probe function names and situation IDs are pinned by
evals/scenarios/registry.yaml (registry gate); bodies assert the
wave-81 contract.

All runs synthetic/local, $0. Deterministic except wall-clock ts
(never asserted on). Env hygiene restores every mutated variable in
finally.
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
# Import the test harness WITHOUT running tests/__init__.py's old
# process-wide state (kept for isolation); per-probe keys are managed
# with _env()+_dev_keys() instead, and restored afterwards.
sys.path.insert(0, str(REPO_ROOT / "tests"))
sys.path.insert(0, str(REPO_ROOT / "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

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
            "GOV_DEPLOYMENT_MODE", "GOV_KEYRING_FILE")


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
    """Wave-81: per-probe explicit key provisioning (replaces the
    deleted gov.log dev-key opt-in). Declares staging explicitly
    (wave-61 discipline) so the probe is self-sufficient under direct
    __main__ runs and under run_evals (ambient staging preserved)."""
    if enabled:
        import secrets as _secrets
        with _env(GOV_DEPLOYMENT_MODE="staging",
                  GOV_LOG_KEY=_secrets.token_hex(32),
                  GOV_LOG_KEY_EPOCH="test",
                  GOV_LOG_KEY_ARCHIVE=None):
            yield
    else:
        yield


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
# No-fallback: without explicit provisioning every path refuses, in
# every mode; explicit material is used verbatim.
# ----------------------------------------------------------------------

@_sit("redteam.keymgmt_w69.fallback_env_alone_refused")
def sit_fallback_env_alone_refused():
    """Wave-81: nothing configured in production must refuse — there is
    no fallback left to enable (the dev-key machinery is deleted)."""
    with _env(GOV_DEPLOYMENT_MODE="production",
              GOV_LOG_KEY=None, GOV_LOG_KEY_EPOCH=None,
              GOV_LOG_KEY_ARCHIVE=None, GOV_KEYRING_FILE=None):
        log = _fresh_log()
        try:
            log.append({"event": "x"})
        except NoKeyConfiguredError:
            return {"verdict": "stopped",
                    "note": "unprovisioned production refused"}
        return {"verdict": "break",
                "note": "chain started with no key configured"}


@_sit("redteam.keymgmt_w69.fallback_dev_bytes_refused")
def sit_fallback_dev_bytes_refused():
    """Wave-81: the dev-key byte screening is deleted WITH the dev key.
    The retired public dev bytes placed explicitly in GOV_LOG_KEY are
    used AS CONFIGURED (operator misconfiguration, not a fallback) —
    and, critically, no gov/ path mints or derives them on its own:
    without explicit configuration resolution refuses."""
    retired = "retired-public-dev-bytes-v1"  # historical bytes deleted
    with _env(GOV_DEPLOYMENT_MODE="production",
              GOV_LOG_KEY=retired, GOV_LOG_KEY_EPOCH="epoch-9"):
        log = _fresh_log()
        try:
            e = log.append({"event": "x"})
        except NoKeyConfiguredError:
            return {"verdict": "break",
                    "note": "explicit key unexpectedly refused"}
        if e["key_epoch"] != "epoch-9":
            return {"verdict": "break",
                    "note": "explicit bytes not used verbatim"}
    with _env(GOV_DEPLOYMENT_MODE="production",
              GOV_LOG_KEY=None, GOV_LOG_KEY_EPOCH=None,
              GOV_LOG_KEY_ARCHIVE=None, GOV_KEYRING_FILE=None):
        try:
            keys_mod.require_key()
        except NoKeyConfiguredError:
            return {"verdict": "stopped",
                    "note": "explicit bytes used verbatim when "
                            "configured; nothing mints them unconfigured"}
        return {"verdict": "break",
                "note": "require_key resolved with no key configured"}


@_sit("redteam.keymgmt_w69.fallback_dev_epoch_refused")
def sit_fallback_dev_epoch_refused():
    """Wave-81: the epoch label is not a gate. A real explicitly
    configured key with GOV_LOG_KEY_EPOCH=dev works — and the evidence
    export marks the non-production label honestly (no custody claim)."""
    with _env(GOV_DEPLOYMENT_MODE="production",
              GOV_LOG_KEY="real-operator-key",
              GOV_LOG_KEY_EPOCH="dev"):
        log = _fresh_log()
        try:
            e = log.append({"event": "x"})
        except NoKeyConfiguredError as ex:
            return {"verdict": "break",
                    "note": "real key with dev label refused: %s" % ex}
        if e["key_epoch"] != "dev":
            return {"verdict": "break",
                    "note": "label not carried: %r" % e["key_epoch"]}
        ks = make_report.key_status([e], "dev")
        if ks["status"] == "dev" and "Non-production" in ks["banner_line"]:
            return {"verdict": "stopped",
                    "note": "dev label works and renders honestly"}
        return {"verdict": "break",
                "note": "dev label mis-rendered: %r" % ks}


@_sit("redteam.keymgmt_w69.fallback_archive_smuggle_refused")
def sit_fallback_archive_smuggle_refused():
    """Wave-81: the archive screening is deleted with the dev key.
    Archive epochs are used as-is per-epoch: an explicit archive still
    verifies old segments, and no screening gate stands in the way."""
    archive = json.dumps({"epoch-old": "archived-operator-key"})
    with _env(GOV_DEPLOYMENT_MODE="production",
              GOV_LOG_KEY="real-operator-key",
              GOV_LOG_KEY_EPOCH="epoch-1",
              GOV_LOG_KEY_ARCHIVE=archive):
        try:
            ring = KeyRing.from_env()
        except NoKeyConfiguredError as e:
            return {"verdict": "break",
                    "note": "explicit archive refused: %s" % e}
        if ring.get("epoch-old") is None or ring.get("epoch-1") is None:
            return {"verdict": "break",
                    "note": "archive epochs not adopted: %r"
                            % ring.epochs()}
        return {"verdict": "stopped",
                "note": "explicit archive adopted verbatim, no screening"}


@_sit("redteam.keymgmt_w69.fallback_production_contradiction")
def sit_fallback_production_contradiction():
    """Wave-81: the wave-69 production/dev contradiction is unstatable —
    the dev side is deleted. Production mode + explicit key appends;
    production mode + no key refuses loud. Both directions hold."""
    with _env(GOV_DEPLOYMENT_MODE="production",
              GOV_LOG_KEY="prod-explicit-key",
              GOV_LOG_KEY_EPOCH="epoch-1"):
        log = _fresh_log()
        try:
            log.append({"event": "x"})
        except NoKeyConfiguredError as e:
            return {"verdict": "break",
                    "note": "explicit production key refused: %s" % e}
    with _env(GOV_DEPLOYMENT_MODE="production",
              GOV_LOG_KEY=None, GOV_LOG_KEY_EPOCH=None,
              GOV_LOG_KEY_ARCHIVE=None, GOV_KEYRING_FILE=None):
        log = _fresh_log()
        try:
            log.append({"event": "x"})
        except NoKeyConfiguredError as e:
            loud = "production" in str(e).lower() or "GOV_LOG_KEY" in str(e)
            return {"verdict": "stopped" if loud else "break",
                    "note": "unprovisioned production refused loud"
                            if loud else
                            "refused but not loud: %s" % e}
        return {"verdict": "break",
                "note": "chain started in production with no key"}


@_sit("redteam.keymgmt_w69.fallback_keyring_file_dev_seeded")
def sit_fallback_keyring_file_dev_seeded():
    """Wave-81: GOV_KEYRING_FILE material is used as configured — a
    file-seeded keyring works in production (explicit provisioning,
    not a fallback)."""
    d = tempfile.mkdtemp(prefix="w69probe-")
    ring = KeyRing.generate("epoch-1")
    p = os.path.join(d, "keyring.json")
    ring.save(p)
    with _env(GOV_DEPLOYMENT_MODE="production", GOV_KEYRING_FILE=p,
              GOV_LOG_KEY=None, GOV_LOG_KEY_EPOCH=None):
        log = _fresh_log()
        try:
            e = log.append({"event": "x"})
        except NoKeyConfiguredError as ex:
            return {"verdict": "break",
                    "note": "file keyring refused: %s" % ex}
        if e["key_epoch"] != "epoch-1":
            return {"verdict": "break",
                    "note": "wrong epoch: %r" % e["key_epoch"]}
        return {"verdict": "stopped",
                "note": "file keyring used as configured"}


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
    """Wave-81: key-one-signed records presented to a key-two verifier
    must fail with an era/label mismatch — never verify. (Old name kept
    for the registry; the dev/prod key pair is deleted.)"""
    with _env(GOV_DEPLOYMENT_MODE="production",
              GOV_LOG_KEY="key-one-material",
              GOV_LOG_KEY_EPOCH="epoch-1"):
        log = _fresh_log()
        log.append({"event": "x"})
        path = str(log.path)
    with _env(GOV_DEPLOYMENT_MODE="production",
              GOV_LOG_KEY="key-two-material",
              GOV_LOG_KEY_EPOCH="epoch-2"):
        v = log_mod._verify(path)
    if not v["ok"] and "key_epoch" in (v["error"] or ""):
        return {"verdict": "stopped",
                "note": "key-one log rejected by key-two verifier: %s"
                        % v["error"]}
    return {"verdict": "break",
            "note": "key-one-signed log verified under key-two: %r" % v}


@_sit("redteam.keymgmt_w69.key_confusion_prod_to_dev")
def sit_key_confusion_prod_to_dev():
    """Wave-81: key-two-signed records presented to a key-one verifier
    must fail. (Old name kept for the registry.)"""
    with _env(GOV_DEPLOYMENT_MODE="production",
              GOV_LOG_KEY="key-two-material",
              GOV_LOG_KEY_EPOCH="epoch-2"):
        log = _fresh_log()
        log.append({"event": "x"})
        path = str(log.path)
    with _env(GOV_DEPLOYMENT_MODE="production",
              GOV_LOG_KEY="key-one-material",
              GOV_LOG_KEY_EPOCH="epoch-1"):
        v = log_mod._verify(path)
    if not v["ok"] and "key_epoch" in (v["error"] or ""):
        return {"verdict": "stopped",
                "note": "key-two log rejected by key-one verifier: %s"
                        % v["error"]}
    return {"verdict": "break",
            "note": "key-two-signed log verified under key-one: %r" % v}


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
    """Wave-81: an explicit-key log with forged 'production' labels must
    render non-production/FAILED in the evidence export — a prod banner
    over forged labels is unreachable."""
    insider = "w69-insider-key"
    with _env(GOV_LOG_KEY=insider, GOV_LOG_KEY_EPOCH="epoch-1"):
        log = _fresh_log()
        log.append({"event": "probe"})
        path = str(log.path)
    entries = [json.loads(l) for l in Path(path).read_text(
        encoding="utf-8").splitlines() if l.strip()]
    for e in entries:
        e["key_epoch"] = "production"
        e["hash"] = log_mod._compute_mac(
            insider.encode("utf-8"), "production", e["prev_hash"],
            log_mod._canonical(e))
    forged = os.path.join(os.path.dirname(path), "forged.jsonl")
    Path(forged).write_text("\n".join(
        json.dumps(e, ensure_ascii=True) for e in entries) + "\n",
        encoding="utf-8")
    with _env(GOV_LOG_KEY=insider, GOV_LOG_KEY_EPOCH="epoch-1"):
        verdict = log_mod._verify(forged)
    assert not verdict["ok"], "forged labels must not verify"
    ks = make_report.key_status(entries, verdict["key_epoch"])
    md = make_report.render_markdown(
        "w69-probe", "2026-09-22T00:00:00+00:00", False, len(entries),
        [], [], ks, None)
    prod_banner = "verified epoch `production`" in ks["banner_line"]
    honest = (ks["verified_epoch"] == "epoch-1"
              and bool(ks["label_mismatch"])
              and "LABEL MISMATCH" in ks["banner_line"])
    if honest and not prod_banner and "Non-production epoch label" not in md:
        # The forged labels never render a prod banner; the mismatch is
        # flagged. (md carries the FAILED-verdict rendering, not the
        # non-production banner — that banner belongs to clean logs
        # whose configured epoch is itself a non-production label.)
        return {"verdict": "stopped",
                "note": "forged labels render FAILED with mismatch "
                        "flagged, never a prod banner"}
    return {"verdict": "break",
            "note": "export mis-graded forged labels: %r" % ks}


# ----------------------------------------------------------------------
# Legitimate path (closure pin)
# ----------------------------------------------------------------------

@_sit("redteam.keymgmt_w69.legit_staging_dev_path")
def sit_legit_staging_dev_path():
    """Wave-81: explicit provisioning works in every deployment mode —
    appends land, the configured epoch marks every entry, no warnings,
    no fallback. (Old name kept for the registry.)"""
    for mode in ("production", "staging", "dev", "test"):
        with _env(GOV_DEPLOYMENT_MODE=mode,
                  GOV_LOG_KEY="legit-explicit-key",
                  GOV_LOG_KEY_EPOCH="epoch-1",
                  GOV_LOG_KEY_ARCHIVE=None):
            log = _fresh_log("actions-%s.jsonl" % mode)
            e = log.append({"event": "legit"})
            v = log_mod._verify(str(log.path))
            if not (v["ok"] and e["key_epoch"] == "epoch-1"):
                return {"verdict": "break",
                        "note": "legit path broken in mode %s: ok=%s "
                                "epoch=%s" % (mode, v["ok"],
                                              e.get("key_epoch"))}
    return {"verdict": "stopped",
            "note": "explicit provisioning works in every mode"}


# D1 verdict mapping for the HOLD/MISS vocabulary
# (evals/SUMMARY_FORM_POLICIES.md): "stopped" (attack stopped) -> HELD,
# "break" -> BREAK, "error" -> ERROR, "residual" -> HELD with a
# "residual: " note prefix. Red-first: an unmapped verdict maps to BREAK.
_VERDICT_MAP = {"stopped": "HELD", "break": "BREAK", "error": "ERROR",
                "residual": "HELD"}


def _note_of(row):
    # D2 contract for the w72 family: the note lives under
    # detail["note"], falling back to detail["error"] for harness
    # exceptions (which record {"error": ...} with no "note").
    return row["detail"].get("note") or row["detail"].get("error", "")


def _main():
    for sid in sorted(SITUATIONS):
        SITUATIONS[sid]()
    rows = [{"id": r["id"],
             "verdict": _VERDICT_MAP.get(r["verdict"], "BREAK"),
             "detail": r["detail"]} for r in RESULTS]
    probe_lines.emit_dicts(rows, pid_key="id", note_getter=_note_of)
    brk = sum(1 for r in rows if r["verdict"] == "BREAK")
    held = sum(1 for r in rows if r["verdict"] == "HELD")
    err = sum(1 for r in rows if r["verdict"] == "ERROR")
    print("w69 battery: %d BREAK / %d HELD / %d ERROR"
          % (brk, held, err))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        [(r["id"], r["verdict"], _note_of(r)) for r in rows], brk, held, err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    # Exit-equivalent to the old `0 if not broken else 1`: broken counted
    # every non-"stopped" verdict, i.e. break + error == brk + err here
    # (no sit function records "residual" as a verdict).
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(_main())
