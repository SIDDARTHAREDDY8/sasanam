"""Wave-35 F110 residual probes (2026-09-22).

F110 (P15, Z.ai ZCode class, MEDIUM, CLOSED wave-35): the wave-34
closure control (gov/platform_egress.py) stopped the original
silent-collection shape, but the closure control itself had four
confirmed residuals. Each had a 1:1 registered probe here that
returned break pre-fix (closure: open); all four were rewritten
break -> stopped as the defects were fixed (closure: green) -- the
wave-34 P16 pattern.

  1. f110_residual_consent_token_forgery -- was: check_consent
     validated only shape/scope/expiry; a hand-forged token dict was
     accepted. Now: tokens are HMAC-bound to issuance (platform-held
     key, stdlib hmac); hand-minted/tampered/wrong-key/missing-MAC
     forgeries are refused.
  2. f110_residual_audit_after_side_effect -- was: the upload side
     effect (sink.put) preceded any audit record; a failed upload left
     no trace of the attempt. Now: platform_egress_authorized lands
     before sink.put; failed uploads get platform_egress_upload_failed.
  3. f110_residual_plaintext_archive_default -- was: archives were
     plaintext by default when no archive_key was passed; no explicit
     opt-in. Now: no-key collection is refused unless explicit
     allow_plaintext=True (audited as plaintext_explicit).
  4. f110_residual_demo_cipher_default -- was: archive_key without an
     explicit cipher silently used the demo-grade XOR stream cipher
     (malleable, unauthenticated). Now: fail-closed without an
     explicit cipher; the demo cipher is test-only and must be passed
     explicitly.

All runs synthetic/local, $0. Deterministic: verdicts do not depend
on random values or wall-clock time (token ttls are issued and
checked within the same probe run).
"""

import contextlib
import os
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
# Import the test harness WITHOUT running tests/__init__.py (which flips
# on the dev-key opt-in process-wide); dev keys are enabled per-probe
# with _govrun() instead, and restored afterwards.
sys.path.insert(0, str(REPO_ROOT / "tests"))

import harness  # noqa: E402
from gov import log as log_mod  # noqa: E402
from gov.platform_egress import (  # noqa: E402
    ConsentToken,
    PlatformEgressError,
    WorkspaceCollector,
    check_consent,
    demonstration_cipher,
    issue_consent,
)

RESULTS = []
SITUATIONS = {}


# --------------------------------------------------------------------------
# Helpers (mirroring evals/w33_probes.py conventions)
# --------------------------------------------------------------------------

@contextlib.contextmanager
def _tmp(name):
    base = Path(os.environ.get("TMPDIR", "/tmp")) / "w35"
    base.mkdir(parents=True, exist_ok=True)
    d = Path(tempfile.mkdtemp(prefix="w35-", dir=str(base)))
    try:
        yield d
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


@contextlib.contextmanager
def _env(**kw):
    saved = {k: os.environ.get(k) for k in kw}
    try:
        for k, v in kw.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@contextlib.contextmanager
def _dev_keys(enabled=True):
    """Wave-81: explicit test-key provisioning.

    Replaces the deleted gov.log dev-key opt-in. With enabled=True,
    yields with an explicit random GOV_LOG_KEY/GOV_LOG_KEY_EPOCH set
    and GOV_LOG_KEY_ARCHIVE cleared, restoring everything afterwards.
    enabled=False is a plain passthrough (no key provisioned).
    """
    if not enabled:
        yield
        return
    import secrets as _secrets
    _saved = {n: os.environ.get(n) for n in (
        "GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")}
    _had = {n: n in os.environ for n in _saved}
    os.environ["GOV_LOG_KEY"] = _secrets.token_hex(32)
    os.environ["GOV_LOG_KEY_EPOCH"] = "test"
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)
    try:
        yield
    finally:
        for _n in _saved:
            if _had[_n]:
                os.environ[_n] = _saved[_n]
            else:
                os.environ.pop(_n, None)
@contextlib.contextmanager
def _govrun():
    with _dev_keys(True):
        yield


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
                                           % (type(e).__name__, e)}})
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        SITUATIONS[sid] = wrapper
        return wrapper
    return deco


class _RecordingSink:
    """In-memory upload target that records call order (and can fail)."""

    def __init__(self, host, events, fail=False):
        self.host = host
        self.uploads = []
        self._events = events
        self._fail = fail

    def put(self, name, payload):
        self._events.append(("put", name))
        if self._fail:
            raise IOError("synthetic network failure")
        self.uploads.append({"name": name, "payload": payload,
                             "host": self.host})


class _OrderLog:
    """Log wrapper recording append order alongside sink events."""

    def __init__(self, log, events):
        self._log = log
        self._events = events

    def append(self, entry):
        self._events.append(("log", entry.get("event")))
        return self._log.append(entry)


def _workspace(tmp):
    ws = Path(tmp) / "ws"
    (ws / "src").mkdir(parents=True)
    (ws / "src" / "app.py").write_text("print('hello')\n")
    (ws / ".git" / "objects").mkdir(parents=True)
    (ws / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (ws / "notes.md").write_text("synthetic workspace\n")
    return ws


# --------------------------------------------------------------------------
# F110 residual 1/4 -- consent tokens are HMAC-bound (FIXED wave-35)
# --------------------------------------------------------------------------

# Synthetic platform-held consent-signing key for probes (test-only).
_PROBE_CONSENT_KEY = b"probe-consent-key-32-bytes-synth"


@_sit("redteam.incident.p15.f110_residual_consent_token_forgery")
def sit_p15_f110_residual_consent_token_forgery():
    """STOPPED (F110 residual 1/4, FIXED wave-35): consent tokens are
    HMAC-bound to issuance under a platform-held key (stdlib hmac).

    The wave-35 fix: issue_consent MACs the token fields
    (HMAC-SHA256, key held by the platform, never in the token); the
    collector verifies with hmac.compare_digest. Three forgeries,
    end to end through WorkspaceCollector.collect():
      (a) a hand-minted token dict (no issuance ever happened);
      (b) a genuinely issued token with tampered (extended) expires_at;
      (c) a genuinely issued token with a swapped token_id.
    Stopped = every forgery is refused (bad_mac, audited) while the
    honest path (real token -> governed upload) still works.
    """
    now = int(time.time())
    with _tmp("f110r1") as tmp:
        ws = _workspace(tmp)
        with _govrun():
            ctx = harness.make_run()
            collector = WorkspaceCollector(
                ctx["log"], ctx["policy"],
                egress_allowlist={"idx.example.com"},
                consent_key=_PROBE_CONSENT_KEY)
            honest = issue_consent(ctx["log"], _PROBE_CONSENT_KEY,
                                   granted_by="operator-1")

            forgeries = {
                # (a) hand-minted: no issuance, no audit entry, no key.
                "a_hand_minted": {
                    "token_id": "pec-" + "ab" * 16,
                    "scope": "workspace_collect",
                    "granted_by": "attacker",
                    "granted_at": now,
                    "expires_at": now + 3600,
                },
                # (b) tampered expiry on a real token.
                "b_tampered_expiry": dict(
                    honest.as_dict(), expires_at=now + 86400 * 365),
                # (c) swapped token id on a real token.
                "c_swapped_id": dict(
                    honest.as_dict(), token_id="pec-" + "cd" * 16),
            }
            refused = {}
            for name, forged in forgeries.items():
                sink = _RecordingSink("idx.example.com", [])
                try:
                    collector.collect(
                        ws, consent=ConsentToken(forged),
                        destination="idx.example.com", sink=sink,
                        allow_plaintext=True)
                    refused[name] = not sink.uploads
                except PlatformEgressError as exc:
                    refused[name] = "bad_mac" in str(exc)

            # Honest path must work (probe vacuity check).
            sink_ok = _RecordingSink("idx.example.com", [])
            honest_ok = False
            try:
                collector.collect(ws, consent=honest,
                                  destination="idx.example.com",
                                  sink=sink_ok, allow_plaintext=True)
                honest_ok = bool(sink_ok.uploads)
            except PlatformEgressError:
                honest_ok = False

    stopped = all(refused.values()) and honest_ok
    return {
        "verdict": "stopped" if stopped else "break",
        "forgeries_refused_with_bad_mac": [k for k, v in refused.items()
                                           if v],
        "forgeries_accepted": [k for k, v in refused.items() if not v],
        "honest_path_works": honest_ok,
        "note": "forged tokens refused=%s accepted=%s; honest path works=%s"
                % ([k for k, v in refused.items() if v],
                   [k for k, v in refused.items() if not v], honest_ok),
    }


# --------------------------------------------------------------------------
# F110 residual 2/4 -- write-ahead audit ordering (FIXED wave-35)
# --------------------------------------------------------------------------

@_sit("redteam.incident.p15.f110_residual_audit_after_side_effect")
def sit_p15_f110_residual_audit_after_side_effect():
    """STOPPED (F110 residual 2/4, FIXED wave-35): write-ahead audit
    ordering.

    The wave-35 fix: the platform_egress_authorized entry lands BEFORE
    sink.put (fail-closed: if the append raises, no upload is
    attempted); a failed put produces an explicit
    platform_egress_upload_failed entry; the completion entry follows
    the put. Stopped = (a) a failing put leaves the authorized entry
    (landed pre-side-effect), a failed entry, and NO completion entry;
    (b) on the success path the authorized entry precedes the put.
    """
    with _tmp("f110r2") as tmp:
        ws = _workspace(tmp)
        with _govrun():
            ctx = harness.make_run()
            token = issue_consent(ctx["log"], _PROBE_CONSENT_KEY,
                                  granted_by="operator-1")

            # (a) failing sink: the attempt is fully audited.
            events_fail = []
            fail_collector = WorkspaceCollector(
                _OrderLog(ctx["log"], events_fail), ctx["policy"],
                egress_allowlist={"idx.example.com"},
                consent_key=_PROBE_CONSENT_KEY)
            fail_sink = _RecordingSink("idx.example.com", events_fail,
                                       fail=True)
            before = len(ctx["read_log"]())
            raised = False
            try:
                fail_collector.collect(
                    ws, consent=token, destination="idx.example.com",
                    sink=fail_sink, allow_plaintext=True)
            except PlatformEgressError as exc:
                raised = "upload_failed" in str(exc)
            new_events = [e for e in ctx["read_log"]()[before:]
                          if (e.get("event") or "").startswith(
                              "platform_egress")]
            put_attempted = ("put", "workspace-archive.bin") in events_fail
            authorized = [e for e in new_events
                          if e.get("event") == "platform_egress_authorized"]
            failed = [e for e in new_events
                      if e.get("event") == "platform_egress_upload_failed"]
            completed = [e for e in new_events
                         if e.get("event") == "platform_egress_upload"]
            fail_ok = (raised and put_attempted and len(authorized) == 1
                       and len(failed) == 1 and len(completed) == 0)

            # (b) succeeding sink: authorized precedes the put.
            events_ok = []
            ok_collector = WorkspaceCollector(
                _OrderLog(ctx["log"], events_ok), ctx["policy"],
                egress_allowlist={"idx.example.com"},
                consent_key=_PROBE_CONSENT_KEY)
            ok_sink = _RecordingSink("idx.example.com", events_ok)
            ok_collector.collect(ws, consent=token,
                                 destination="idx.example.com",
                                 sink=ok_sink, allow_plaintext=True)
            put_idx = next(
                (i for i, e in enumerate(events_ok) if e[0] == "put"), None)
            pre_put_auth = any(
                e == ("log", "platform_egress_authorized")
                for e in events_ok[:put_idx if put_idx is not None else 0])

    stopped = fail_ok and pre_put_auth
    return {
        "verdict": "stopped" if stopped else "break",
        "failed_upload_audited": fail_ok,
        "write_ahead_authorized_before_put": pre_put_auth,
        "note": "failing put: fully audited (authorized+failed, no "
                "completion)=%s; success path: write-ahead authorized "
                "before put=%s" % (fail_ok, pre_put_auth),
    }


# --------------------------------------------------------------------------
# F110 residual 3/4 -- key-required archives (FIXED wave-35)
# --------------------------------------------------------------------------

@_sit("redteam.incident.p15.f110_residual_plaintext_archive_default")
def sit_p15_f110_residual_plaintext_archive_default():
    """STOPPED (F110 residual 3/4, FIXED wave-35): no silent plaintext.

    The wave-35 fix: collect() without archive_key is REFUSED unless
    the deployer passes an explicit allow_plaintext=True opt-in, which
    is recorded in the audit entry (plaintext_explicit: True).
    Stopped = the no-key call is refused (archive_key_required,
    audited denial, nothing uploaded) while the explicit opt-in path
    still works and is audited as explicit.
    """
    with _tmp("f110r3") as tmp:
        ws = _workspace(tmp)
        with _govrun():
            ctx = harness.make_run()
            collector = WorkspaceCollector(
                ctx["log"], ctx["policy"],
                egress_allowlist={"idx.example.com"},
                consent_key=_PROBE_CONSENT_KEY)
            token = issue_consent(ctx["log"], _PROBE_CONSENT_KEY,
                                  granted_by="operator-1")

            # No-key, no opt-in: refused.
            sink_refused = _RecordingSink("idx.example.com", [])
            refused = False
            try:
                collector.collect(
                    ws, consent=token, destination="idx.example.com",
                    sink=sink_refused)
            except PlatformEgressError as exc:
                refused = ("archive_key_required" in str(exc)
                           and not sink_refused.uploads)

            # Explicit opt-in: works, and is audited as explicit.
            sink_ok = _RecordingSink("idx.example.com", [])
            before = len(ctx["read_log"]())
            result = collector.collect(
                ws, consent=token, destination="idx.example.com",
                sink=sink_ok, allow_plaintext=True)
            uploads = [e for e in ctx["read_log"]()[before:]
                       if e.get("event") == "platform_egress_upload"]
            explicit_ok = (bool(result.get("uploaded"))
                           and result.get("plaintext_explicit") is True
                           and uploads and uploads[0].get(
                               "plaintext_explicit") is True)

    stopped = refused and explicit_ok
    return {
        "verdict": "stopped" if stopped else "break",
        "no_key_no_opt_in_refused": refused,
        "explicit_opt_in_works_and_audited": bool(explicit_ok),
        "note": "no-key collect refused=%s; explicit allow_plaintext "
                "works and is audited explicit=%s"
                % (refused, bool(explicit_ok)),
    }


# --------------------------------------------------------------------------
# F110 residual 4/4 -- fail-closed without a production cipher
# (FIXED wave-35)
# --------------------------------------------------------------------------

@_sit("redteam.incident.p15.f110_residual_demo_cipher_default")
def sit_p15_f110_residual_demo_cipher_default():
    """STOPPED (F110 residual 4/4, FIXED wave-35): no silent cipher
    selection.

    The wave-35 fix (stdlib only, no new deps): collect() with
    archive_key but no explicit cipher= is REFUSED
    (archive_cipher_required) -- the module never silently selects a
    cipher. demonstration_cipher remains TEST-ONLY and must be passed
    explicitly AND with GOV_DEMO_CIPHER_OK=1 (wave-37 hardening);
    production deployments pass a real AEAD. Stopped =
    the key-without-cipher call is refused (nothing uploaded) while
    the explicit-cipher path still works end to end.
    """
    with _tmp("f110r4") as tmp:
        ws = _workspace(tmp)
        with _govrun():
            ctx = harness.make_run()
            collector = WorkspaceCollector(
                ctx["log"], ctx["policy"],
                egress_allowlist={"idx.example.com"},
                consent_key=_PROBE_CONSENT_KEY)
            token = issue_consent(ctx["log"], _PROBE_CONSENT_KEY,
                                  granted_by="operator-1")
            key = os.urandom(32)

            # Key without cipher: refused.
            sink_refused = _RecordingSink("idx.example.com", [])
            refused = False
            try:
                collector.collect(
                    ws, consent=token, destination="idx.example.com",
                    sink=sink_refused, archive_key=key)
            except PlatformEgressError as exc:
                refused = ("archive_cipher_required" in str(exc)
                           and not sink_refused.uploads)

            # Explicit cipher: works end to end. Wave-37: the TEST-ONLY
            # demonstration_cipher also requires GOV_DEMO_CIPHER_OK=1;
            # this probe is a synthetic context, so set/restore it here
            # (production copy-paste without the env var is refused --
            # that is the wave-37 hardening under test in the unit
            # suite).
            sink_ok = _RecordingSink("idx.example.com", [])
            with _env(GOV_DEMO_CIPHER_OK="1"):
                result = collector.collect(
                    ws, consent=token, destination="idx.example.com",
                    sink=sink_ok, archive_key=key,
                    cipher=demonstration_cipher)
            blob = sink_ok.uploads[0]["payload"]
            nonce, ct = blob[:16], blob[16:]
            with _env(GOV_DEMO_CIPHER_OK="1"):
                round_trips = demonstration_cipher(
                    key, nonce, ct).startswith(b"--- .git/HEAD ---\n")
            explicit_ok = (bool(result.get("encrypted")) and round_trips)

    stopped = refused and explicit_ok
    return {
        "verdict": "stopped" if stopped else "break",
        "key_without_cipher_refused": refused,
        "explicit_cipher_path_works": explicit_ok,
        "note": "key-without-cipher refused=%s; explicit cipher path "
                "works=%s" % (refused, explicit_ok),
    }
