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
  queue file and retried on subsequent runs. The queue is bounded at
  ``_MAX_QUEUE_LINES`` lines; when a drain finds the file longer than
  the cap, the oldest lines beyond the cap are NOT retried -- but the
  drop is never silent: a coded ``witness-alert-queue-overflow`` record
  carrying the exact drop count is appended to the durable file sink,
  so the overflow itself is LOUD and counted.
  :class:`MemoryAlertSink` exists for tests.
* **Unknown/ambiguous states alert LOUD.** A corrupt alert state, a
  monitor_id mismatch, a malformed ``monitor_step`` return, or any
  unexpected exception raises the coded
  ``witness-alert-wrapper-error`` and emits it through the sink before
  propagating -- never silently. When the sink itself is broken (no
  channel left), the failure takes the last-resort channel instead: a
  structured ``LAST-RESORT`` record to stderr AND an fsync'd append to
  the configured ``last_resort_path``; the next tick with a working
  sink re-announces it LOUD (as a ``wrapper-error`` alert) before any
  heartbeat resumes, then clears the file. A corrupt/unreadable
  status file is itself announced LOUD, never ignored.

Alert payload: ``alert_id``, ``alert_kind`` (``failure-alert`` |
``heartbeat`` | ``wrapper-error`` | ``queue-overflow``), ``monitor_id``,
``ts``, ``consecutive_failures``,
``last_code``, ``last_detail``, ``head`` (``{size, root}``),
``head_age_seconds`` (seconds since the trusted head last advanced --
during an outage the head is frozen so the age grows, which is exactly
what the operator needs to see), ``policy_id``, ``policy_version``.

Exit codes for the cron entry point: 0 = healthy run (a heartbeat may
have been emitted); 2 = monitor refusal (alerted per the rules above);
1 = wrapper error (alerted LOUD when the sink is usable; otherwise
recorded on the last-resort channel).

Only ``gov/decision_codes.py`` is touched besides this new module (the
two ``witness-alert-*`` registrations). ``gov/witness_monitor.py``,
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
WITNESS_ALERT_QUEUE_OVERFLOW = "witness-alert-queue-overflow"
_overflow_seq = 0  # process-local sequence for overflow alert ids


class AlertWrapperError(Exception):
    """A coded wrapper failure.

    Always alerted LOUD before propagating -- except when the sink
    itself cannot carry it, in which case ``emitted`` is False and the
    caller's last-resort channel (stderr + durable status file, see
    :func:`_last_resort`) applies.
    """

    def __init__(self, code, detail="", emitted=True):
        self.code = code
        self.detail = detail
        self.emitted = emitted
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
        ``(delivered, remaining)``. Failures stay queued.

        When the queue file holds more than ``_MAX_QUEUE_LINES`` lines,
        the oldest beyond the cap cannot be retried (the queue is
        bounded); the drop is never silent -- a coded
        ``witness-alert-queue-overflow`` record carrying the exact drop
        count is appended to the (durable) file sink after the atomic
        replace, so the next drain retries it like any queued alert.
        """
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
        overflow = len(lines) - _MAX_QUEUE_LINES
        if overflow < 0:
            overflow = 0
        # Bound the queue; the oldest beyond the cap are NOT retried.
        # Their count is reported LOUD via the overflow record below --
        # never dropped silently (the wave-325 residual).
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
        remaining = remaining[-_MAX_QUEUE_LINES:]
        tmp = path + ".drain.%d.tmp" % (os.getpid(),)
        with open(tmp, "w", encoding="utf-8") as fh:
            for line in remaining:
                fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        if overflow:
            # The drop itself is an alert: durable (file sink), coded,
            # counted. Best-effort -- a sink failure here must not crash
            # the drain.
            try:
                self._emit_overflow_record(overflow)
            except Exception:  # noqa: BLE001
                pass
        return (delivered, len(remaining))

    def _emit_overflow_record(self, dropped):
        """Append the coded queue-overflow record to the file sink."""
        global _overflow_seq
        _overflow_seq += 1
        now_s = int(time.time())
        record = {
            "alert_id": "witmon-alert/queue-overflow/%d/%d/%d"
                        % (now_s, os.getpid(), _overflow_seq),
            "alert_kind": "queue-overflow",
            "monitor_id": "webhook-queue",
            "ts": now_s,
            "dropped_alerts": dropped,
            "queue_cap": _MAX_QUEUE_LINES,
            "last_code": WITNESS_ALERT_QUEUE_OVERFLOW,
            "last_detail": "webhook alert queue exceeded %d lines; "
                           "%d oldest queued alert(s) dropped -- the "
                           "drop is reported here, never silent"
                           % (_MAX_QUEUE_LINES, dropped),
        }
        self._file.emit(record)


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
    lrp = cfg.get("last_resort_path")
    if lrp is not None and (not isinstance(lrp, str) or not lrp):
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "config['last_resort_path'] must be a "
                                "non-empty string or null")
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


def _wrapper_error_alert(cfg, now_s, code, detail):
    """Build (not emit) the wrapper-error alert dict.

    Factored out of :func:`_emit_loud` so the last-resort
    re-announcement (:func:`_announce_last_resort`) can construct the
    identical alert shape without the raise.
    """
    return {
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


def _emit_loud(sink, cfg, now_s, code, detail):
    """Emit a wrapper-error alert LOUD. Propagates
    :class:`AlertWrapperError` with ``emitted=False`` when the sink
    itself cannot carry the alert (e.g. disk full, unwritable queue
    path) -- the caller must then use the last-resort channel
    (:func:`_last_resort`), because there is nowhere left to record
    it through the sink."""
    alert = _wrapper_error_alert(cfg, now_s, code, detail)
    try:
        sink.emit(alert)
    except AlertWrapperError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AlertWrapperError(WITNESS_ALERT_WRAPPER_ERROR,
                                "cannot emit loud alert: %s: %s; original: "
                                "[%s] %s" % (type(exc).__name__, exc, code,
                                             detail),
                                emitted=False)


# ---------------------------------------------------------------------------
# Last-resort channel: a wrapper failure the sink could not carry.
# ---------------------------------------------------------------------------

def _last_resort(raw, code, detail):
    """Last-resort channel for wrapper failures with no usable sink.

    Writes a structured JSON record (``LAST-RESORT`` prefix) to stderr
    AND appends it (fsync'd) to the configured ``last_resort_path``.
    The next tick with a working sink re-announces it LOUD before any
    heartbeat (:func:`_announce_last_resort`). Best-effort: never
    raises. The file only grows while the sink stays broken; the first
    working tick clears it.
    """
    now_s = int(time.time())
    monitor_id = (raw.get("monitor_id") if isinstance(raw, dict)
                  else None) or "unknown"
    record = {
        "alert_id": "witmon-alert/%s/last-resort/%d/%d"
                    % (monitor_id, now_s, os.getpid()),
        "kind": "last-resort",
        "monitor_id": monitor_id,
        "ts": now_s,
        "code": code,
        "detail": detail,
    }
    line = (json.dumps(record, sort_keys=True, separators=(",", ":"))
            + "\n").encode("utf-8")
    try:
        stream = getattr(sys.stderr, "buffer", None)
        if stream is not None:
            stream.write(b"LAST-RESORT " + line)
        else:
            # Text-mode stderr (e.g. captured by a supervisor): the
            # record still goes out, decoded.
            sys.stderr.write("LAST-RESORT " + line.decode("utf-8"))
        sys.stderr.flush()
    except Exception:  # noqa: BLE001
        pass
    path = raw.get("last_resort_path") if isinstance(raw, dict) else None
    if not path:
        return
    try:
        _append_line(path, line)
    except Exception as exc:  # noqa: BLE001 -- stderr is all that is left
        try:
            sys.stderr.write("last-resort file %r unwritable: %s: %s\n"
                             % (path, type(exc).__name__, exc))
            sys.stderr.flush()
        except Exception:  # noqa: BLE001
            pass


def _emit_announcement(sink, alert):
    """Emit one re-announcement LOUD.

    Raises :class:`AlertWrapperError` with ``emitted=False`` when the
    sink cannot carry it -- the record stays pending for the following
    tick (dedupe by the stable alert_id prevents double-announce).
    """
    try:
        sink.emit(alert)
    except AlertWrapperError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AlertWrapperError(
            WITNESS_ALERT_WRAPPER_ERROR,
            "cannot re-announce last-resort record: %s: %s"
            % (type(exc).__name__, exc),
            emitted=False)


def _clear_last_resort(path):
    """Atomically clear the last-resort file (tmp + fsync + replace)."""
    tmp = path + ".clear.%d.tmp" % (os.getpid(),)
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _announce_last_resort(sink, cfg, now_s):
    """Re-announce pending last-resort records LOUD through the sink.

    Runs at tick start -- before the webhook drain and before any
    heartbeat -- so the next tick with a working sink surfaces the
    prior loud failure first. Each record is re-emitted as a
    ``wrapper-error`` alert carrying the original code/detail, keeping
    the record's stable ``alert_id`` (dedupe: a crash between announce
    and clear cannot double-announce). A corrupt or unreadable status
    file is itself announced LOUD (never silently ignored), then
    cleared. Returns the number of announcements emitted.
    """
    path = cfg.get("last_resort_path")
    if not path:
        return 0
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
    except FileNotFoundError:
        return 0
    except OSError as exc:
        alert = _wrapper_error_alert(
            cfg, now_s, WITNESS_ALERT_WRAPPER_ERROR,
            "last-resort file %r unreadable: %s: %s -- refusing to "
            "ignore it" % (path, type(exc).__name__, exc))
        _emit_announcement(sink, alert)
        _clear_last_resort(path)
        return 1
    records = []
    corrupt = 0
    for ln in lines:
        try:
            obj = json.loads(ln)
        except ValueError:
            corrupt += 1
            continue
        if isinstance(obj, dict) and obj.get("kind") == "last-resort":
            records.append(obj)
        else:
            corrupt += 1
    for rec in records:
        alert = _wrapper_error_alert(
            cfg, now_s, rec.get("code") or WITNESS_ALERT_WRAPPER_ERROR,
            "re-announced last-resort failure (first recorded at ts=%s): "
            "[%s] %s" % (rec.get("ts"), rec.get("code"), rec.get("detail")))
        if rec.get("alert_id"):
            alert["alert_id"] = rec["alert_id"]
        _emit_announcement(sink, alert)
    if corrupt:
        alert = _wrapper_error_alert(
            cfg, now_s, WITNESS_ALERT_WRAPPER_ERROR,
            "last-resort file %r held %d unparseable line(s): refused "
            "to ignore" % (path, corrupt))
        _emit_announcement(sink, alert)
    if records or corrupt:
        _clear_last_resort(path)
    return len(records) + (1 if corrupt else 0)


# ---------------------------------------------------------------------------
# The wrapper run.
# ---------------------------------------------------------------------------

def run_monitor_once(cfg):
    """Run one cron tick: fetch, monitor_step, alert/heartbeat per the
    rules, persist state atomically.

    Returns ``{"healthy": bool, "consecutive_failures": int,
    "alerted": bool, "exit_code": int}``. Raises
    :class:`AlertWrapperError` (after a LOUD alert when the sink is
    usable; with ``emitted=False`` when the sink itself could not carry
    it) on wrapper errors. A pending last-resort record from a prior
    failed tick is re-announced LOUD first, before the webhook drain
    and before any heartbeat.
    """
    raw = dict(cfg)
    now_raw = raw.get("now")
    now_s = (now_raw if isinstance(now_raw, int)
             and not isinstance(now_raw, bool) and now_raw >= 0
             else int(time.time()))
    # Build the sink BEFORE config validation: a broken config must
    # still alert LOUD through a usable sink. If the sink itself is
    # broken there is no sink channel; the error propagates un-emitted
    # (emitted=False) and the caller uses the last-resort channel
    # (stderr + last_resort_path) instead.
    try:
        sink = _build_sink(raw)
    except AlertWrapperError:
        sink = None
    try:
        cfg = _check_config(raw)
    except AlertWrapperError as exc:
        if sink is not None:
            _emit_loud(sink, raw, now_s, exc.code, exc.detail)
        else:
            # No sink channel at all: mark the failure un-emitted so the
            # caller takes the last-resort channel (stderr + status file).
            exc.emitted = False
        raise
    if sink is None:
        raise AlertWrapperError(
            WITNESS_ALERT_WRAPPER_ERROR,
            "alert sink configuration is invalid and there is no "
            "channel to alert through",
            emitted=False)
    wm = _monitor_mod()
    threshold = cfg.get("alert_after_failures")
    if threshold is None:
        threshold = wm.ALERT_AFTER_FAILURES

    def _loud(code, detail):
        _emit_loud(sink, cfg, now_s, code, detail)
        raise AlertWrapperError(code, detail)

    # Re-announce a prior tick's last-resort failure LOUD, first: a
    # recovered sink surfaces what the broken sink could not say,
    # before any heartbeat resumes.
    _announce_last_resort(sink, cfg, now_s)

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
        # A wrapper failure the sink could not carry (emitted=False)
        # takes the last-resort channel: structured record to stderr
        # and the durable status file, re-announced by the next tick.
        if not getattr(exc, "emitted", True):
            _last_resort(cfg, exc.code, exc.detail)
        print("wrapper error: %s" % (exc,), file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 -- truly unexpected
        # Never emitted through the sink: last-resort it too. The record
        # code is the registered wrapper-error code (the detail carries
        # the exception type) -- no unregistered strings in code fields.
        _last_resort(cfg, WITNESS_ALERT_WRAPPER_ERROR,
                     "unexpected %s: %s" % (type(exc).__name__, exc))
        print("unexpected error: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        return 1
    print("healthy=%s failures=%d alerted=%s"
          % (outcome["healthy"], outcome["consecutive_failures"],
             outcome["alerted"]))
    return outcome["exit_code"]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
