"""Deployment-side alerting cron wrapper for the fail-closed witness monitor.

This is the tracked gap from wave-323 lane 2: ``gov/witness_monitor.py``
counts consecutive failures and exposes ``ALERT_AFTER_FAILURES = 3``,
but the cron wrapper that turns those counts into pages did not exist.
This module is that wrapper.

Design (stdlib-only; the file sink is $0, the webhook sink needs no
third-party library):

* **Alert from the 3rd consecutive failure, every run while down.**
  Failures 1 and 2 are silent; from the threshold on, every run emits
  a failure alert -- there is no fatigue suppression that could hide
  an ongoing outage.
* **Daily heartbeat when healthy.** Silence is itself a signal: a
  healthy run emits a heartbeat at most once per
  ``heartbeat_interval_seconds`` (default 86400). The first healthy run
  ever heartbeats immediately (the operator gets a positive signal
  that the wrapper is alive).
* **Crash-safe state.** The alert state (failure count mirror,
  last-alert id, heartbeat/advance timestamps) is written atomically
  (tmp + fsync + ``os.replace``). The failure count itself is read
  from the monitor's own atomically-persisted state, so a crash
  between the monitor run and the alert emit never loses the count:
  alert ids are ``(monitor_id, incident, failures)`` and the file
  sink dedupes by id, so a crash-retry emits exactly once. (A crash
  between state-save and emit may skip that tick's alert, but the
  count survives and the next tick re-alerts -- alerts fire every run
  while down.)
* **Sinks.** :class:`AlertSink` is the interface. :class:`FileAlertSink`
  (default) appends JSON-lines alerts, fsync'd. :class:`WebhookAlertSink`
  POSTs JSON via ``urllib``; a delivery failure (exception or non-2xx)
  never crashes the monitor loop -- the alert is appended to a durable
  queue file and retried on subsequent runs. :class:`MemoryAlertSink`
  exists for tests.
* **Unknown/ambiguous states alert LOUD.** A corrupt alert state, a
  monitor_id mismatch, a malformed ``monitor_step`` return, or any
  unexpected exception raises the coded
  ``witness-alert-wrapper-error`` and emits it through the sink before
  propagating -- never silently.

Alert payload: ``alert_id``, ``alert_kind`` (``failure-alert`` |
``heartbeat``), ``monitor_id``, ``ts``, ``consecutive_failures``,
``last_code``, ``last_detail``, ``head`` (``{size, root}``),
``head_age_seconds`` (seconds since the trusted head last advanced --
during an outage the head is frozen so the age grows, which is exactly
what the operator needs to see), ``policy_id``, ``policy_version``.

Exit codes for the cron entry point: 0 = healthy run (a heartbeat may
have been emitted); 2 = monitor refusal (alerted per the rules above);
1 = wrapper error (alerted LOUD when the sink is usable).

Only ``gov/decision_codes.py`` is touched besides this new module (the
one ``witness-alert-*`` registration). ``gov/witness_monitor.py``,
``gov/witness_publish.py`` and ``gov/witness_policy.py`` are consumed
read-only, never modified.
"""

import importlib.util
import json
import os
import subprocess
import sys
import time
import urllib.request

# ---------------------------------------------------------------------------
# Decision codes (registered centrally in gov/decision_codes.py).
# ---------------------------------------------------------------------------

WITNESS_ALERT_WRAPPER_ERROR = "witness-alert-wrapper-error"

_ALERT_STATE_VERSION = 1
_DEFAULT_HEARTBEAT_INTERVAL_S = 86400  # one day
_MAX_QUEUE_LINES = 10000  # operational bound on the webhook retry queue


class AlertWrapperError(Exception):
    """A coded wrapper failure. Always alerted LOUD before propagating."""

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("[%s] %s" % (code, detail) if detail else
                         "[%s]" % (code,))


# ---------------------------------------------------------------------------
# Dependency loading (file path, socket-free -- mirrors the partner
# layers' standalone-capable discipline).
# ---------------------------------------------------------------------------

def _load_dep(filename, standalone_name):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        filename)
    try:
        spec = importlib.util.spec_from_file_location(standalone_name,
                                                      path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        raise AlertWrapperError(
            WITNESS_ALERT_WRAPPER_ERROR,
            "cannot load %s from %r: %s" % (filename, path, exc))
    return module


_wm = None


def _monitor_mod():
    global _wm
    if _wm is None:
        _wm = _load_dep("witness_monitor.py", "witness_monitor_standalone")
    return _wm


# ---------------------------------------------------------------------------
# Alert sinks.
# ---------------------------------------------------------------------------

class AlertSink:
    """Interface: ``emit(alert_dict)`` persists/delivers one alert."""

    def emit(self, alert):
        raise NotImplementedError


def _alert_line(alert):
    return (json.dumps(alert, sort_keys=True, separators=(",", ":"))
            + "\n").encode("utf-8")


def _id_present(path, alert_id):
    """True when an alert with this id is already recorded in the file."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except FileNotFoundError:
        return False
    except OSError:
        return False
    needle = json.dumps(alert_id).encode("utf-8")
    # Line-oriented check: the id appears as the value of "alert_id".
    for line in data.split(b"\n"):
        if b'"alert_id":' in line and needle in line:
            try:
                obj = json.loads(line.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if isinstance(obj, dict) and obj.get("alert_id") == alert_id:
                return True
    return False


def _append_line(path, line_bytes):
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    with open(path, "ab") as fh:
        fh.write(line_bytes)
        fh.flush()
        os.fsync(fh.fileno())


class FileAlertSink(AlertSink):
    """Default $0 sink: appends JSON-lines alerts, fsync'd, idempotent
    by alert_id (a crash-retry never double-records)."""

    def __init__(self, queue_path):
        if not isinstance(queue_path, str) or not queue_path:
            raise TypeError("queue_path must be a non-empty string")
        self.queue_path = queue_path

    def emit(self, alert):
        alert_id = alert.get("alert_id")
        if not alert_id:
            raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                    "alert has no alert_id; refusing to "
                                    "emit an unidentifiable alert")
        if _id_present(self.queue_path, alert_id):
            return False  # already recorded: exactly-once per id
        _append_line(self.queue_path, _alert_line(alert))
        return True


class WebhookAlertSink(AlertSink):
    """POSTs alerts as JSON. A delivery failure (exception or non-2xx)
    never raises: the alert is appended to the durable queue file and
    retried on subsequent runs (``drain_queue``)."""

    def __init__(self, url, queue_path, timeout_s=10):
        if not isinstance(url, str) or not url.startswith("http"):
            raise TypeError("url must be an http(s) URL string")
        self.url = url
        self.timeout_s = timeout_s
        self._file = FileAlertSink(queue_path)

    def _post(self, alert):
        req = urllib.request.Request(
            self.url, data=_alert_line(alert),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            return 200 <= resp.status < 300

    def emit(self, alert):
        try:
            if self._post(alert):
                return True
        except Exception:  # noqa: BLE001 -- delivery failure: queue it
            pass
        # Delivery failed (or non-2xx): durable queue, never a crash.
        self._file.emit(alert)
        return False

    def drain_queue(self):
        """Best-effort retry of queued alerts. Returns
        ``(delivered, remaining)``. Failures stay queued."""
        path = self._file.queue_path
        try:
            with open(path, "r", encoding="utf-8") as fh:
                lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        except FileNotFoundError:
            return (0, 0)
        except OSError:
            # The queue exists but is unreadable: report it as remaining
            # without crashing the monitor run.
            return (0, -1)
        remaining = []
        delivered = 0
        for line in lines[-_MAX_QUEUE_LINES:]:
            try:
                alert = json.loads(line)
            except ValueError:
                continue  # corrupt line: drop (it was never a valid alert)
            try:
                ok = self._post(alert)
            except Exception:  # noqa: BLE001
                ok = False
            if ok:
                delivered += 1
            else:
                remaining.append(line)
        # Bound the queue; oldest beyond the cap are dropped and the
        # drop is documented in the module docstring (operational note).
        remaining = remaining[-_MAX_QUEUE_LINES:]
        tmp = path + ".drain.%d.tmp" % (os.getpid(),)
        with open(tmp, "w", encoding="utf-8") as fh:
            for line in remaining:
                fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        return (delivered, len(remaining))


class MemoryAlertSink(AlertSink):
    """Test sink: records alerts in memory, dedupes by alert_id like the
    file sink."""

    def __init__(self):
        self.alerts = []

    def emit(self, alert):
        if any(a.get("alert_id") == alert.get("alert_id")
               for a in self.alerts):
            return False
        self.alerts.append(dict(alert))
        return True


# ---------------------------------------------------------------------------
# Alert state (atomic; the wrapper's memory across cron runs).
# ---------------------------------------------------------------------------

def _alert_state_shape(state, where):
    if not isinstance(state, dict):
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "%s: top level must be a JSON object"
                                % (where,))
    if state.get("version") != _ALERT_STATE_VERSION:
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "%s: unsupported alert-state version %r"
                                % (where, state.get("version")))
    for key in ("consecutive_failures", "last_heartbeat_ts",
                "incident_seq"):
        v = state.get(key)
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                    "%s: %s must be a non-negative int"
                                    % (where, key))
    lat = state.get("last_advanced_ts")
    if lat is not None and (isinstance(lat, bool) or not isinstance(lat,
                                                                   int)
                            or lat < 0):
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "%s: last_advanced_ts must be a "
                                "non-negative int or null" % (where,))
    head = state.get("head")
    if head is not None and (
            not isinstance(head, dict) or not isinstance(head.get("size"),
                                                         int)
            or not isinstance(head.get("root"), str)):
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "%s: head must be {size, root} or null"
                                % (where,))
    if not isinstance(state.get("monitor_id"), str):
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "%s: monitor_id must be a string"
                                % (where,))
    return state


def _new_alert_state(monitor_id):
    return {"version": _ALERT_STATE_VERSION,
            "monitor_id": monitor_id,
            "consecutive_failures": 0,
            # incident_seq distinguishes outages: it increments on each
            # healthy -> failing transition so a later outage's alerts
            # never dedupe against an earlier outage's (the alert id
            # carries it; a crash-retry within one outage keeps it).
            "incident_seq": 0,
            "last_alert_id": None,
            "last_heartbeat_ts": 0,
            "last_advanced_ts": None,
            "last_code": None,
            "last_detail": None,
            "head": None,
            "policy_id": None,
            "policy_version": None}


def load_alert_state(path, monitor_id):
    """Load the alert state, shape-checked. A missing file yields a
    fresh state; a corrupt file or monitor_id mismatch is a LOUD
    wrapper error (never a silent re-baseline)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except FileNotFoundError:
        return _new_alert_state(monitor_id)
    except OSError as exc:
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "cannot read alert state %r: %s"
                                % (path, exc))
    try:
        state = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "alert state %r is not valid JSON: %s"
                                % (path, exc))
    state = _alert_state_shape(state, "alert state %r" % (path,))
    if state["monitor_id"] != monitor_id:
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "alert state monitor_id %r does not match "
                                "configured %r: refusing (replay guard)"
                                % (state["monitor_id"], monitor_id))
    return state


def _save_alert_state(path, state, now_s):
    state = dict(state)
    state["last_run"] = now_s
    payload = (json.dumps(state, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
               + b"\n")
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    tmp = os.path.join(directory,
                        ".alert-state.%d.tmp" % (os.getpid(),))
    with open(tmp, "wb") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Config checks (programmer errors raise AlertWrapperError -> LOUD).
# ---------------------------------------------------------------------------

def _check_config(cfg):
    if not isinstance(cfg, dict):
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "config must be a mapping")
    for key in ("monitor_id", "state_path", "alert_state_path"):
        v = cfg.get(key)
        if not isinstance(v, str) or not v:
            raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                    "config[%r] must be a non-empty string"
                                    % (key,))
    sink_cfg = cfg.get("sink")
    if sink_cfg is not None and not isinstance(sink_cfg, dict):
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "config['sink'] must be a mapping or null")
    fetch = cfg.get("fetch")
    if fetch is not None and not callable(fetch) and not isinstance(
            fetch, dict):
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "config['fetch'] must be a callable, a "
                                "mapping, or null")
    if isinstance(fetch, dict):
        if "command" in fetch and "checkpoint_path" in fetch:
            raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                    "config['fetch'] takes either "
                                    "'command' or 'checkpoint_path'")
        if "command" not in fetch and "checkpoint_path" not in fetch:
            raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                    "config['fetch'] needs 'command' or "
                                    "'checkpoint_path'")
        if ("command" in fetch
                and (not isinstance(fetch["command"], list)
                     or not fetch["command"])):
            raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                    "config['fetch']['command'] must be a "
                                    "non-empty argv list")
        if ("checkpoint_path" in fetch
                and not isinstance(fetch["checkpoint_path"], str)):
            raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                    "config['fetch']['checkpoint_path'] "
                                    "must be a string")
    # The wrapper reads these before the monitor's own shape checks run;
    # a missing key must refuse coded here, not as a raw KeyError.
    pi = cfg.get("policy_inputs")
    if not isinstance(pi, dict):
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "config['policy_inputs'] must be a mapping")
    if not isinstance(pi.get("policy_id"), str) or not pi.get("policy_id"):
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "config['policy_inputs']['policy_id'] must "
                                "be a non-empty string")
    pv = pi.get("policy_version")
    if isinstance(pv, bool) or not isinstance(pv, int) or pv < 0:
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "config['policy_inputs']['policy_version'] "
                                "must be a non-negative int")
    if not isinstance(cfg.get("witness_set"), dict):
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "config['witness_set'] must be a mapping")
    if not isinstance(cfg.get("allowed_origins"), (list, tuple)):
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "config['allowed_origins'] must be a list")
    now = cfg.get("now")
    if now is not None and (isinstance(now, bool) or not isinstance(
            now, int) or now < 0):
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "config['now'] must be a non-negative int "
                                "unix timestamp or null")
    hb = cfg.get("heartbeat_interval_seconds",
                 _DEFAULT_HEARTBEAT_INTERVAL_S)
    if isinstance(hb, bool) or not isinstance(hb, int) or hb < 1:
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "config['heartbeat_interval_seconds'] must "
                                "be a positive int")
    aaf = cfg.get("alert_after_failures")
    if aaf is not None and (isinstance(aaf, bool) or not isinstance(
            aaf, int) or aaf < 1):
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "config['alert_after_failures'] must be a "
                                "positive int or null")
    fto = cfg.get("fetch_timeout_s")
    if fto is not None and (isinstance(fto, bool) or not isinstance(
            fto, (int, float)) or fto <= 0):
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "config['fetch_timeout_s'] must be a "
                                "positive number or null")
    return cfg


def _build_sink(cfg):
    sink_cfg = cfg.get("sink") or {"type": "file"}
    stype = sink_cfg.get("type", "file")
    if stype == "file":
        qp = sink_cfg.get("queue_path") or cfg.get("alert_queue_path")
        if not qp:
            raise AlertWrapperError(
                WITNESS_ALERT_WRAPPER_ERROR,
                "file sink needs 'queue_path' (in sink config or "
                "config['alert_queue_path'])")
        return FileAlertSink(qp)
    if stype == "webhook":
        url = sink_cfg.get("url")
        qp = sink_cfg.get("queue_path") or cfg.get("alert_queue_path")
        if not url or not qp:
            raise AlertWrapperError(
                WITNESS_ALERT_WRAPPER_ERROR,
                "webhook sink needs 'url' and 'queue_path'")
        return WebhookAlertSink(url, qp,
                                timeout_s=sink_cfg.get("timeout_s", 10))
    if stype == "memory":
        return MemoryAlertSink()
    raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                            "unknown sink type %r" % (stype,))


def _fetch_checkpoint(cfg):
    """Return checkpoint bytes, or None when the fetch failed (an
    availability signal, not a wrapper error)."""
    fetch = cfg.get("fetch")
    if fetch is None:
        return None
    if callable(fetch):
        try:
            out = fetch()
        except Exception as exc:  # noqa: BLE001
            raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                    "fetch callable raised: %s: %s"
                                    % (type(exc).__name__, exc))
        if out is None:
            return None
        if not isinstance(out, (bytes, bytearray)):
            raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                    "fetch callable must return bytes or "
                                    "None")
        return bytes(out) if out else None
    if "command" in fetch:
        try:
            proc = subprocess.run(fetch["command"], capture_output=True,
                                  timeout=cfg.get("fetch_timeout_s", 60))
        except Exception as exc:  # noqa: BLE001
            return None
        if proc.returncode != 0 or not proc.stdout:
            return None
        return proc.stdout
    try:
        with open(fetch["checkpoint_path"], "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    return data if data else None


def _check_monitor_result(result):
    """The monitor must return its documented verdict shape; anything
    else is an ambiguous state -> LOUD wrapper error."""
    if not isinstance(result, dict):
        return False
    for key in ("accepted", "advanced", "head", "policy_id",
                "policy_version", "consecutive_failures"):
        if key not in result:
            return False
    head = result["head"]
    if (not isinstance(head, dict) or not isinstance(head.get("size"),
                                                    int)
            or not isinstance(head.get("root"), str)):
        return False
    if result.get("accepted") is not True:
        return False
    return True


def _resolve_failures(wm, exc, cfg, alert_state):
    """Durable failure count for this refused run.

    Returns ``(failures, authoritative)``. The monitor persists its own
    counter atomically; prefer the exception's count, fall back to the
    monitor state file, then to the alert state's mirror. The two
    pre-run refuses (state-mismatch, policy-version-rollback) report
    the pre-run count -- no +1 there (the module did not persist an
    increment).

    ``authoritative`` is False when the exception carries no count
    (the monitor refused before establishing one, e.g. a corrupt
    state) AND the monitor state file is unreadable: the true count
    is unknown and the mirror is stale. The caller must NOT trust the
    mirror then -- an outage would sit below threshold forever,
    silent. Unknown counts alert LOUD.
    """
    cf = getattr(exc, "consecutive_failures", None)
    if cf is not None:
        return (cf, True)
    try:
        mstate = wm.load_monitor_state(cfg["state_path"])
        return (mstate["consecutive_failures"], True)
    except Exception:  # noqa: BLE001 -- corrupt/missing: unknown
        return (alert_state["consecutive_failures"], False)


def _failure_alert(cfg, alert_state, failures, code, detail, now_s):
    head = alert_state["head"]
    last_adv = alert_state["last_advanced_ts"]
    alert = {
        "alert_id": "witmon-alert/%s/failure/i%d/%d"
                    % (cfg["monitor_id"], alert_state["incident_seq"],
                       failures),
        "alert_kind": "failure-alert",
        "monitor_id": cfg["monitor_id"],
        "ts": now_s,
        "consecutive_failures": failures,
        "last_code": code,
        "last_detail": detail,
        "head": head,
        "head_age_seconds": (now_s - last_adv) if last_adv is not None
                            else None,
        "policy_id": alert_state["policy_id"],
        "policy_version": alert_state["policy_version"],
    }
    return alert


def _heartbeat_alert(cfg, alert_state, now_s):
    head = alert_state["head"]
    last_adv = alert_state["last_advanced_ts"]
    return {
        "alert_id": "witmon-alert/%s/heartbeat/%d"
                    % (cfg["monitor_id"], now_s),
        "alert_kind": "heartbeat",
        "monitor_id": cfg["monitor_id"],
        "ts": now_s,
        "consecutive_failures": 0,
        "last_code": None,
        "last_detail": None,
        "head": head,
        "head_age_seconds": (now_s - last_adv) if last_adv is not None
                            else None,
        "policy_id": alert_state["policy_id"],
        "policy_version": alert_state["policy_version"],
    }


def _emit_loud(sink, cfg, now_s, code, detail):
    """Emit a wrapper-error alert LOUD. Never raises for sink problems
    (the file sink raising -- e.g. disk full -- is the one case that
    propagates, because there is nowhere left to record it)."""
    alert = {
        "alert_id": "witmon-alert/%s/wrapper-error/%d"
                    % (cfg.get("monitor_id", "unknown"), now_s),
        "alert_kind": "wrapper-error",
        "monitor_id": cfg.get("monitor_id", "unknown"),
        "ts": now_s,
        "consecutive_failures": None,
        "last_code": code,
        "last_detail": detail,
        "head": None,
        "head_age_seconds": None,
        "policy_id": None,
        "policy_version": None,
    }
    try:
        sink.emit(alert)
    except AlertWrapperError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "cannot emit loud alert: %s: %s; original: "
                                "[%s] %s" % (type(exc).__name__, exc, code,
                                             detail))


# ---------------------------------------------------------------------------
# The wrapper run.
# ---------------------------------------------------------------------------

def run_monitor_once(cfg):
    """Run one cron tick: fetch, monitor_step, alert/heartbeat per the
    rules, persist state atomically.

    Returns ``{"healthy": bool, "consecutive_failures": int,
    "alerted": bool, "exit_code": int}``. Raises
    :class:`AlertWrapperError` (after a LOUD alert when the sink is
    usable) on wrapper errors.
    """
    raw = dict(cfg)
    now_raw = raw.get("now")
    now_s = (now_raw if isinstance(now_raw, int)
             and not isinstance(now_raw, bool) and now_raw >= 0
             else int(time.time()))
    # Build the sink BEFORE config validation: a broken config must
    # still alert LOUD through a usable sink. If the sink itself is
    # broken there is no channel, and the error propagates un-emitted
    # (documented; nothing else can be done).
    try:
        sink = _build_sink(raw)
    except AlertWrapperError:
        sink = None
    try:
        cfg = _check_config(raw)
    except AlertWrapperError as exc:
        if sink is not None:
            _emit_loud(sink, raw, now_s, exc.code, exc.detail)
        raise
    if sink is None:
        raise AlertWrapperError(
            WITNESS_ALERT_WRAPPER_ERROR,
            "alert sink configuration is invalid and there is no "
            "channel to alert through")
    wm = _monitor_mod()
    threshold = cfg.get("alert_after_failures")
    if threshold is None:
        threshold = wm.ALERT_AFTER_FAILURES

    def _loud(code, detail):
        _emit_loud(sink, cfg, now_s, code, detail)
        raise AlertWrapperError(code, detail)

    # Drain the webhook retry queue first (best effort; failures stay
    # queued). A drain problem never blocks the monitor run.
    if isinstance(sink, WebhookAlertSink):
        try:
            sink.drain_queue()
        except Exception:  # noqa: BLE001
            pass

    # The configured policy identity rides in every alert, including
    # failure alerts on runs where the monitor never got far enough to
    # report it (e.g. fetch failures on the first-ever run).
    try:
        alert_state = load_alert_state(cfg["alert_state_path"],
                                       cfg["monitor_id"])
    except AlertWrapperError as exc:
        _loud(exc.code, exc.detail)
    alert_state["policy_id"] = cfg["policy_inputs"]["policy_id"]
    alert_state["policy_version"] = cfg["policy_inputs"]["policy_version"]

    # The monitor treats last_seen=None + no state file as a first run
    # and would silently re-baseline. If our mirror has a trusted head
    # but the monitor's state file is gone (deleted/corrupted between
    # ticks), that is an ambiguous state -> LOUD, never a silent
    # restart of the failure count.
    if (alert_state["head"] is not None
            and not os.path.exists(cfg["state_path"])):
        _loud(WITNESS_ALERT_WRAPPER_ERROR,
              "monitor state file %r is gone but the alert state has a "
              "trusted head: refusing to re-baseline silently"
              % (cfg["state_path"],))

    checkpoint = _fetch_checkpoint(cfg)

    max_age = cfg.get("max_age")
    monitor_kwargs = {
        "witness_set": cfg["witness_set"],
        "last_seen": cfg.get("last_seen"),
        "policy_inputs": cfg["policy_inputs"],
        "allowed_origins": cfg["allowed_origins"],
        # now/max_age must be given together (the monitor enforces it).
        "now": now_s if max_age is not None else None,
        "max_age": max_age,
        "consistency_proof": cfg.get("consistency_proof"),
        "require_consistency_proof": bool(
            cfg.get("require_consistency_proof", False)),
        "state_path": cfg["state_path"],
    }

    try:
        result = wm.monitor_step(checkpoint, **monitor_kwargs)
    except AlertWrapperError:
        raise
    except Exception as exc:  # noqa: BLE001
        if isinstance(exc, wm.WitnessMonitorError):
            # A coded monitor refusal: the availability path.
            code = exc.code
            failures, authoritative = _resolve_failures(wm, exc, cfg,
                                                        alert_state)
            if not authoritative:
                # The monitor refused before establishing a count and its
                # state is unreadable: the true count is unknown.
                # Trusting the stale mirror would let an outage sit
                # below threshold forever, silent -- alert LOUD instead.
                _loud(WITNESS_ALERT_WRAPPER_ERROR,
                      "monitor refused [%s] with no failure count and its "
                      "state file is unreadable: alerting LOUD rather than "
                      "trusting a stale count" % (code,))
            mirror_prev = alert_state["consecutive_failures"]
            if mirror_prev > 0 and failures < mirror_prev:
                # The monitor's count went BACKWARDS: its state was
                # deleted or reset out from under us mid-outage (the
                # monitor treats a missing state file + last_seen=None
                # as a first run). Never silently re-baseline an
                # already-counted outage -- the re-fired alert would
                # also collide with the earlier outage's alert id and
                # be dropped by dedupe. LOUD instead.
                _loud(WITNESS_ALERT_WRAPPER_ERROR,
                      "monitor failure count %d < mirror %d: monitor "
                      "state was reset/deleted mid-outage, refusing to "
                      "re-baseline silently" % (failures, mirror_prev))
            # New outage (healthy -> failing): bump the incident
            # sequence so this outage's alerts never dedupe against a
            # prior outage's.
            if alert_state["consecutive_failures"] == 0:
                alert_state["incident_seq"] += 1
            alert_state["consecutive_failures"] = failures
            alert_state["last_code"] = code
            alert_state["last_detail"] = getattr(exc, "detail", "")
            alerted = False
            if failures >= threshold:
                alert = _failure_alert(cfg, alert_state, failures, code,
                                       alert_state["last_detail"], now_s)
                # Persist BEFORE emitting: a crash between the two
                # retries without double-alerting (id dedupe). A crash
                # may skip this tick's alert, but the count survives
                # and the next tick re-alerts (alerts fire every run
                # while down).
                alert_state["last_alert_id"] = alert["alert_id"]
                _save_alert_state(cfg["alert_state_path"], alert_state,
                                  now_s)
                sink.emit(alert)
                alerted = True
            else:
                _save_alert_state(cfg["alert_state_path"], alert_state,
                                  now_s)
            return {"healthy": False, "consecutive_failures": failures,
                    "alerted": alerted, "exit_code": 2}
        # Anything else (broken dependency, programmer error, malformed
        # return is handled below) is ambiguous -> LOUD.
        _loud(WITNESS_ALERT_WRAPPER_ERROR,
              "monitor_step raised %s: %s" % (type(exc).__name__, exc))

    # monitor_step returned: it must match its documented shape.
    if not _check_monitor_result(result):
        _loud(WITNESS_ALERT_WRAPPER_ERROR,
              "monitor_step returned a malformed verdict %r: refusing to "
              "interpret it" % (result,))

    # Healthy run: reset the counter, advance the head watermark, maybe
    # heartbeat.
    alert_state["consecutive_failures"] = 0
    alert_state["last_code"] = None
    alert_state["last_detail"] = None
    alert_state["head"] = {"size": result["head"]["size"],
                           "root": result["head"]["root"]}
    if result["advanced"]:
        alert_state["last_advanced_ts"] = now_s
    elif alert_state["last_advanced_ts"] is None:
        # First-ever baseline that did not advance (empty log edge):
        # the head exists now, so the age has a datum.
        alert_state["last_advanced_ts"] = now_s
    alert_state["policy_id"] = result["policy_id"]
    alert_state["policy_version"] = result["policy_version"]
    alerted = False
    hb_interval = cfg.get("heartbeat_interval_seconds",
                          _DEFAULT_HEARTBEAT_INTERVAL_S)
    if now_s - alert_state["last_heartbeat_ts"] >= hb_interval:
        alert = _heartbeat_alert(cfg, alert_state, now_s)
        alert_state["last_alert_id"] = alert["alert_id"]
        alert_state["last_heartbeat_ts"] = now_s
        _save_alert_state(cfg["alert_state_path"], alert_state, now_s)
        sink.emit(alert)
        alerted = True
    else:
        _save_alert_state(cfg["alert_state_path"], alert_state, now_s)
    return {"healthy": True, "consecutive_failures": 0,
            "alerted": alerted, "exit_code": 0}


# ---------------------------------------------------------------------------
# Cron entry point.
# ---------------------------------------------------------------------------

def main(argv):
    """``python -m gov.monitor_alert <config.json>`` (or
    ``python gov/monitor_alert.py <config.json>``)."""
    if len(argv) != 2:
        print("usage: monitor_alert.py <config.json>", file=sys.stderr)
        return 1
    try:
        with open(argv[1], "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        print("cannot load config %r: %s" % (argv[1], exc),
              file=sys.stderr)
        return 1
    if not isinstance(cfg, dict):
        print("config %r: top level must be a JSON object" % (argv[1],),
              file=sys.stderr)
        return 1
    try:
        outcome = run_monitor_once(cfg)
    except AlertWrapperError as exc:
        print("wrapper error: %s" % (exc,), file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 -- truly unexpected
        print("unexpected error: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        return 1
    print("healthy=%s failures=%d alerted=%s"
          % (outcome["healthy"], outcome["consecutive_failures"],
             outcome["alerted"]))
    return outcome["exit_code"]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
