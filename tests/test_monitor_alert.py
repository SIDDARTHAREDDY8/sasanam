"""Unit tests for gov/monitor_alert (wave-324 lane 1).

Covers the sink implementations, alert-state durability, alert-id
stability, heartbeat timing, webhook queue/drain, and the cron entry
point's exit codes -- the battery covers the end-to-end wrapper
behaviors red-first.
"""

import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import monitor_alert as ma  # noqa: E402


def _tmpdir():
    return tempfile.mkdtemp(prefix="witalert-unit-")


class SinkTests(unittest.TestCase):
    def test_file_sink_appends_json_lines(self):
        d = _tmpdir()
        qp = os.path.join(d, "alerts.jsonl")
        sink = ma.FileAlertSink(qp)
        self.assertTrue(sink.emit({"alert_id": "a1", "k": "v"}))
        with open(qp, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["alert_id"], "a1")

    def test_file_sink_dedupe_by_id(self):
        d = _tmpdir()
        qp = os.path.join(d, "alerts.jsonl")
        sink = ma.FileAlertSink(qp)
        alert = {"alert_id": "a1", "alert_kind": "failure-alert"}
        self.assertTrue(sink.emit(alert))
        self.assertFalse(sink.emit(dict(alert)))
        self.assertFalse(sink.emit({"alert_id": "a1", "other": 1}))
        with open(qp, "r", encoding="utf-8") as fh:
            self.assertEqual(len(fh.read().splitlines()), 1)

    def test_file_sink_rejects_idless_alert(self):
        d = _tmpdir()
        sink = ma.FileAlertSink(os.path.join(d, "q.jsonl"))
        with self.assertRaises(ma.AlertWrapperError):
            sink.emit({"alert_kind": "failure-alert"})

    def test_memory_sink_dedupe(self):
        sink = ma.MemoryAlertSink()
        self.assertTrue(sink.emit({"alert_id": "a1"}))
        self.assertFalse(sink.emit({"alert_id": "a1"}))
        self.assertEqual(len(sink.alerts), 1)

    def test_webhook_queues_on_failure(self):
        d = _tmpdir()
        qp = os.path.join(d, "q.jsonl")
        sink = ma.WebhookAlertSink("http://127.0.0.1:9/nope", qp)
        orig = ma.WebhookAlertSink._post
        ma.WebhookAlertSink._post = lambda self, a: (_ for _ in ()).throw(
            ConnectionError("down"))
        try:
            self.assertFalse(sink.emit({"alert_id": "a1"}))
        finally:
            ma.WebhookAlertSink._post = orig
        with open(qp, "r", encoding="utf-8") as fh:
            self.assertEqual(len(fh.read().splitlines()), 1)

    def test_webhook_drain_delivers_and_empties(self):
        d = _tmpdir()
        qp = os.path.join(d, "q.jsonl")
        sink = ma.WebhookAlertSink("http://127.0.0.1:9/nope", qp)
        orig = ma.WebhookAlertSink._post
        ma.WebhookAlertSink._post = lambda self, a: False
        try:
            sink.emit({"alert_id": "a1"})
            sink.emit({"alert_id": "a2"})
        finally:
            ma.WebhookAlertSink._post = orig
        ma.WebhookAlertSink._post = lambda self, a: True
        try:
            delivered, remaining = sink.drain_queue()
        finally:
            ma.WebhookAlertSink._post = orig
        self.assertEqual((delivered, remaining), (2, 0))

    def test_webhook_non_2xx_queues(self):
        d = _tmpdir()
        qp = os.path.join(d, "q.jsonl")
        sink = ma.WebhookAlertSink("http://127.0.0.1:9/nope", qp)
        orig = ma.WebhookAlertSink._post
        ma.WebhookAlertSink._post = lambda self, a: False
        try:
            self.assertFalse(sink.emit({"alert_id": "a1"}))
        finally:
            ma.WebhookAlertSink._post = orig
        with open(qp, "r", encoding="utf-8") as fh:
            self.assertEqual(len(fh.read().splitlines()), 1)


class AlertStateTests(unittest.TestCase):
    def test_fresh_state_when_missing(self):
        d = _tmpdir()
        st = ma.load_alert_state(os.path.join(d, "nope.json"), "m1")
        self.assertEqual(st["monitor_id"], "m1")
        self.assertEqual(st["consecutive_failures"], 0)
        self.assertEqual(st["last_heartbeat_ts"], 0)

    def test_corrupt_state_raises_coded(self):
        d = _tmpdir()
        p = os.path.join(d, "s.json")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("{bad json")
        with self.assertRaises(ma.AlertWrapperError) as cm:
            ma.load_alert_state(p, "m1")
        self.assertEqual(cm.exception.code,
                         "witness-alert-wrapper-error")

    def test_monitor_id_mismatch_raises(self):
        d = _tmpdir()
        p = os.path.join(d, "s.json")
        st = ma._new_alert_state("m1")
        ma._save_alert_state(p, st, 100)
        with self.assertRaises(ma.AlertWrapperError):
            ma.load_alert_state(p, "m2")

    def test_state_roundtrip_atomic(self):
        d = _tmpdir()
        p = os.path.join(d, "s.json")
        st = ma._new_alert_state("m1")
        st["consecutive_failures"] = 3
        st["last_alert_id"] = "x"
        ma._save_alert_state(p, st, 200)
        back = ma.load_alert_state(p, "m1")
        self.assertEqual(back["consecutive_failures"], 3)
        self.assertEqual(back["last_alert_id"], "x")
        self.assertEqual(back["last_run"], 200)

    def test_bad_shape_refused(self):
        d = _tmpdir()
        p = os.path.join(d, "s.json")
        st = ma._new_alert_state("m1")
        st["consecutive_failures"] = -1
        ma._save_alert_state(p, st, 1)
        with self.assertRaises(ma.AlertWrapperError):
            ma.load_alert_state(p, "m1")


class AlertIdTests(unittest.TestCase):
    def test_failure_alert_id_stable(self):
        cfg = {"monitor_id": "m1"}
        st = {"head": None, "last_advanced_ts": None, "policy_id": "p",
              "policy_version": 2, "incident_seq": 7}
        a1 = ma._failure_alert(cfg, st, 3, "c", "d", 1000)
        a2 = ma._failure_alert(cfg, st, 3, "c", "d", 2000)
        # Same count -> same id (crash-retry dedupes); ts differs.
        self.assertEqual(a1["alert_id"], a2["alert_id"])
        self.assertNotEqual(a1["ts"], a2["ts"])
        a3 = ma._failure_alert(cfg, st, 4, "c", "d", 2000)
        self.assertNotEqual(a1["alert_id"], a3["alert_id"])

    def test_payload_fields(self):
        cfg = {"monitor_id": "m1"}
        st = {"head": {"size": 5, "root": "ab" * 32},
              "last_advanced_ts": 900, "policy_id": "p",
              "policy_version": 2, "incident_seq": 7}
        a = ma._failure_alert(cfg, st, 3, "witness-monitor-stale",
                              "detail", 1000)
        self.assertEqual(a["head_age_seconds"], 100)
        self.assertEqual(a["policy_id"], "p")
        self.assertEqual(a["policy_version"], 2)
        self.assertEqual(a["last_code"], "witness-monitor-stale")

    def test_head_age_none_before_first_advance(self):
        cfg = {"monitor_id": "m1"}
        st = {"head": None, "last_advanced_ts": None, "policy_id": "p",
              "policy_version": 1, "incident_seq": 7}
        a = ma._failure_alert(cfg, st, 3, "c", "d", 1000)
        self.assertIsNone(a["head_age_seconds"])


class ConfigTests(unittest.TestCase):
    def _base(self):
        d = _tmpdir()
        return {"monitor_id": "m1",
                "state_path": os.path.join(d, "ms.json"),
                "alert_state_path": os.path.join(d, "as.json"),
                "sink": {"type": "memory"},
                "witness_set": {"w1": "vkey"},
                "policy_inputs": {"operator_vkeys": ["o"], "quorum_k": 1,
                                  "policy_id": "p", "policy_version": 1},
                "allowed_origins": ["o"]}

    def test_missing_monitor_id_rejected(self):
        cfg = self._base()
        del cfg["monitor_id"]
        with self.assertRaises(ma.AlertWrapperError):
            ma._check_config(cfg)

    def test_unknown_sink_type_rejected(self):
        cfg = self._base()
        cfg["sink"] = {"type": "pigeon"}
        with self.assertRaises(ma.AlertWrapperError):
            ma._build_sink(cfg)

    def test_webhook_sink_needs_url_and_queue(self):
        cfg = self._base()
        cfg["sink"] = {"type": "webhook", "url": "http://x/"}
        with self.assertRaises(ma.AlertWrapperError):
            ma._build_sink(cfg)

    def test_fetch_command_and_path_conflict(self):
        cfg = self._base()
        cfg["fetch"] = {"command": ["true"], "checkpoint_path": "/x"}
        with self.assertRaises(ma.AlertWrapperError):
            ma._check_config(cfg)

    def test_fetch_empty_dict_rejected(self):
        cfg = self._base()
        cfg["fetch"] = {}
        with self.assertRaises(ma.AlertWrapperError):
            ma._check_config(cfg)

    def test_missing_policy_inputs_rejected(self):
        cfg = self._base()
        del cfg["policy_inputs"]
        with self.assertRaises(ma.AlertWrapperError):
            ma._check_config(cfg)

    def test_policy_inputs_missing_policy_id_rejected(self):
        cfg = self._base()
        del cfg["policy_inputs"]["policy_id"]
        with self.assertRaises(ma.AlertWrapperError):
            ma._check_config(cfg)

    def test_missing_witness_set_rejected(self):
        cfg = self._base()
        del cfg["witness_set"]
        with self.assertRaises(ma.AlertWrapperError):
            ma._check_config(cfg)

    def test_missing_allowed_origins_rejected(self):
        cfg = self._base()
        del cfg["allowed_origins"]
        with self.assertRaises(ma.AlertWrapperError):
            ma._check_config(cfg)

    def test_fetch_command_nonzero_is_none(self):
        cfg = self._base()
        cfg["fetch"] = {"command": ["false"]}
        self.assertIsNone(ma._fetch_checkpoint(cfg))

    def test_fetch_missing_file_is_none(self):
        cfg = self._base()
        cfg["fetch"] = {"checkpoint_path": "/nonexistent-xyz"}
        self.assertIsNone(ma._fetch_checkpoint(cfg))

    def test_fetch_callable_bytes(self):
        cfg = self._base()
        cfg["fetch"] = lambda: b"bytes-note"
        self.assertEqual(ma._fetch_checkpoint(cfg), b"bytes-note")

    def test_fetch_callable_wrong_type_loud(self):
        cfg = self._base()
        cfg["fetch"] = lambda: "not-bytes"
        with self.assertRaises(ma.AlertWrapperError):
            ma._fetch_checkpoint(cfg)


class MainTests(unittest.TestCase):
    def _write_cfg(self, d, cfg):
        p = os.path.join(d, "cfg.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh)
        return p

    def test_main_usage_error(self):
        self.assertEqual(ma.main(["monitor_alert.py"]), 1)

    def test_main_missing_config(self):
        self.assertEqual(ma.main(["monitor_alert.py", "/nonexistent"]), 1)

    def test_main_bad_config_shape(self):
        d = _tmpdir()
        p = self._write_cfg(d, {"monitor_id": "m1"})  # incomplete
        # run_monitor_once raises AlertWrapperError -> exit 1
        self.assertEqual(ma.main(["monitor_alert.py", p]), 1)

    def test_main_broken_monitor_config_exit_1(self):
        # Valid sink, broken monitor inputs: LOUD is attempted, exit 1.
        d = _tmpdir()
        qp = os.path.join(d, "alerts.jsonl")
        cfg = {"monitor_id": "m1",
               "state_path": os.path.join(d, "ms.json"),
               "alert_state_path": os.path.join(d, "as.json"),
               "sink": {"type": "file", "queue_path": qp},
               "witness_set": {"w1": "v"},
               "allowed_origins": ["o"]}  # policy_inputs missing
        p = self._write_cfg(d, cfg)
        self.assertEqual(ma.main(["monitor_alert.py", p]), 1)
        with open(qp, "r", encoding="utf-8") as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1)
        alert = json.loads(lines[0])
        self.assertEqual(alert["alert_kind"], "wrapper-error")
        self.assertEqual(alert["last_code"], "witness-alert-wrapper-error")


if __name__ == "__main__":
    unittest.main()
