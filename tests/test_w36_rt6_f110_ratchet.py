"""RT6: red-team round 6 on the F110 closure (wave-36).

Same-day ratchet of the wave-35 F110 closure (HMAC-bound consent
tokens, write-ahead audit ordering, key-required archives,
fail-closed without a production cipher). Targets:

  A. consent-token forgery: replay, scope-swap, expiry/ttl games,
     granted_by tamper, cross-key / cross-collector reuse.
  B. audit-ordering races: side effect before completion audit;
     consent-before-read ordering.
  C. allow_plaintext abuse: agent-shaped caller without consent.
  D. deployer-injected AEAD seam: what if the deployer never injects
     one (fail-closed shape pinned, not silent weak crypto).
  E. sink/destination binding (NEW): policy is evaluated on the
     ``destination`` STRING while the bytes go to ``sink.put``.
     Pre-hardening, a sink whose ``.host`` differs from the
     allowlisted destination sailed through -- the policy check was
     bound to a string the bytes never followed.

Discipline: probes are written FAIL-FIRST (expecting refusal). A
probe that fails pre-fix DEMONSTRATES the miss; the fix lands; the
probe must then pass. Variants that hold pre-fix are documented as
held or as by-design boundaries with the rationale in the test.

Finding policy (RT5 precedent): a variant becomes a finding only if
it demonstrates end-to-end evasion of the F110 threat class
(unconsented platform code uploading workspaces). Hardening without
demonstrated evasion is recorded as hardening, not a finding.
"""

import os
import sys
import time
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # noqa: E402
from gov.platform_egress import (  # noqa: E402
    ConsentToken,
    PlatformEgressError,
    WorkspaceCollector,
    check_consent,
    issue_consent,
)

_KEY = b"rt6-consent-key-32-bytes-synth!"
_OTHER_KEY = b"rt6-other-key-32-bytes-synth!!"


class _Sink:
    def __init__(self, host):
        self.host = host
        self.uploads = []

    def put(self, name, payload):
        self.uploads.append({"name": name, "payload": payload,
                             "host": self.host})


def _ctx():
    return make_run()


def _collector(ctx, **kw):
    kw.setdefault("egress_allowlist", {"idx.example.com"})
    kw.setdefault("consent_key", _KEY)
    return WorkspaceCollector(ctx["log"], ctx["policy"], **kw)


def _token(ctx, **kw):
    kw.setdefault("granted_by", "operator-1")
    return issue_consent(ctx["log"], _KEY, **kw)


def _workspace(tmp):
    ws = Path(tmp) / "ws"
    (ws / "src").mkdir(parents=True)
    (ws / "src" / "app.py").write_text("print('hello')\n")
    return ws


class TestRT6ConsentForgery(unittest.TestCase):
    """A. Consent-token forgery variants."""

    def test_replay_is_visible_not_silent(self):
        # Replay of a live token: by design the token is a bearer
        # credential for its ttl window -- the control is audit
        # visibility, not single-use. Both uploads must carry
        # authorized entries keyed to the same token_id.
        ctx = _ctx()
        collector = _collector(ctx)
        token = _token(ctx)
        ws = _workspace(ctx["run_dir"])
        sink = _Sink("idx.example.com")
        before = len(ctx["read_log"]())
        for _ in range(2):
            r = collector.collect(ws, consent=token,
                                  destination="idx.example.com",
                                  sink=sink, allow_plaintext=True)
            self.assertTrue(r["uploaded"])
        new = ctx["read_log"]()[before:]
        authorized = [e for e in new
                      if e.get("event") == "platform_egress_authorized"]
        self.assertEqual(len(authorized), 2)
        self.assertTrue(all(e["token_id"] == token.token_id
                            for e in authorized))
        # NOT a finding: replay is in-window bearer use with full
        # audit; revocation is out of scope by design.

    def test_granted_by_tamper_refused(self):
        ctx = _ctx()
        token = _token(ctx)
        d = token.as_dict()
        d["granted_by"] = "attacker"
        with self.assertRaises(PlatformEgressError):
            check_consent(d, _KEY)

    def test_zero_ttl_issuance_is_dead_on_arrival(self):
        # ttl_s=0: the token is already expired at issuance. The
        # issuance is still audit-logged (honest record), but the
        # token can never authorize -- fail-closed, not a live
        # credential.
        ctx = _ctx()
        token = _token(ctx, ttl_s=0)
        with self.assertRaises(PlatformEgressError) as cm:
            check_consent(token, _KEY)
        self.assertIn("expired", str(cm.exception))

    def test_negative_ttl_issuance_is_dead_on_arrival(self):
        ctx = _ctx()
        token = _token(ctx, ttl_s=-3600)
        with self.assertRaises(PlatformEgressError):
            check_consent(token, _KEY)

    def test_cross_collector_key_reuse_refused(self):
        # Token MACed under _KEY presented to a collector holding
        # _OTHER_KEY: refused. Consent does not cross key domains.
        ctx = _ctx()
        collector = _collector(ctx, consent_key=_OTHER_KEY)
        token = _token(ctx)  # issued under _KEY
        ws = _workspace(ctx["run_dir"])
        sink = _Sink("idx.example.com")
        with self.assertRaises(PlatformEgressError):
            collector.collect(ws, consent=token,
                              destination="idx.example.com",
                              sink=sink, allow_plaintext=True)
        self.assertEqual(len(sink.uploads), 0)

    def test_wrong_scope_token_refused_at_collect(self):
        ctx = _ctx()
        collector = _collector(ctx)
        token = _token(ctx, scope="metrics_upload")
        ws = _workspace(ctx["run_dir"])
        sink = _Sink("idx.example.com")
        with self.assertRaises(PlatformEgressError):
            collector.collect(ws, consent=token,
                              destination="idx.example.com",
                              sink=sink, allow_plaintext=True)
        self.assertEqual(len(sink.uploads), 0)

    def test_token_validity_is_mac_not_log_presence(self):
        # By design: check_consent never consults the audit log. The
        # MAC is the authority; the issuance audit entry is
        # attribution. Log tampering is detectable via the
        # HMAC-chained log (P11's problem), not by re-checking
        # presence here. Pin the design so a future reader does not
        # "fix" it into a TOCTOU.
        ctx = _ctx()
        token = _token(ctx)
        verbatim_copy = dict(token.as_dict())
        # No log access at all in this call path:
        self.assertEqual(check_consent(verbatim_copy, _KEY)["token_id"],
                         token.token_id)


class TestRT6AuditOrdering(unittest.TestCase):
    """B. Audit-ordering races."""

    def test_consent_checked_before_workspace_read(self):
        # A forged token must be refused BEFORE any workspace bytes
        # are packed. Use a workspace path that does not exist: if
        # the refusal names consent (not the filesystem), the order
        # holds.
        ctx = _ctx()
        collector = _collector(ctx)
        forged = {"token_id": "pec-forged", "scope": "workspace_collect",
                  "granted_by": "x", "granted_at": 1, "expires_at": 2,
                  "mac": "00" * 32}
        sink = _Sink("idx.example.com")
        missing = Path(ctx["run_dir"]) / "does-not-exist"
        with self.assertRaises(PlatformEgressError) as cm:
            collector.collect(missing, consent=forged,
                              destination="idx.example.com",
                              sink=sink, allow_plaintext=True)
        self.assertIn("consent", str(cm.exception))
        self.assertEqual(len(sink.uploads), 0)

    def test_refusal_survives_log_failure(self):
        # _deny is best-effort on the log but the refusal itself must
        # still raise -- a logging outage must not become an upload.
        ctx = _ctx()

        class _RaisingLog:
            def append(self, entry):
                raise IOError("synthetic log outage")

        collector = WorkspaceCollector(
            _RaisingLog(), ctx["policy"],
            egress_allowlist={"idx.example.com"}, consent_key=_KEY)
        token = _token(ctx)
        ws = _workspace(ctx["run_dir"])
        sink = _Sink("evil.example.net")
        with self.assertRaises(PlatformEgressError):
            collector.collect(ws, consent=token,
                              destination="evil.example.net",
                              sink=sink, allow_plaintext=True)
        self.assertEqual(len(sink.uploads), 0)

    def test_none_destination_denied(self):
        ctx = _ctx()
        collector = _collector(ctx)
        token = _token(ctx)
        ws = _workspace(ctx["run_dir"])
        sink = _Sink("idx.example.com")
        with self.assertRaises(PlatformEgressError):
            collector.collect(ws, consent=token, destination=None,
                              sink=sink, allow_plaintext=True)
        self.assertEqual(len(sink.uploads), 0)


class TestRT6PlaintextAndCipherSeam(unittest.TestCase):
    """C/D. allow_plaintext abuse + the deployer-injected AEAD seam."""

    def test_plaintext_opt_in_without_consent_refused(self):
        # Agent-shaped caller: allow_plaintext=True but no (valid)
        # consent. The opt-in is an OPERATOR acknowledgment, and the
        # consent gate runs first.
        ctx = _ctx()
        collector = _collector(ctx)
        ws = _workspace(ctx["run_dir"])
        sink = _Sink("idx.example.com")
        forged = {"token_id": "pec-forged", "scope": "workspace_collect",
                  "granted_by": "x", "granted_at": 1, "expires_at": 2,
                  "mac": "00" * 32}
        with self.assertRaises(PlatformEgressError) as cm:
            collector.collect(ws, consent=forged,
                              destination="idx.example.com",
                              sink=sink, allow_plaintext=True)
        self.assertIn("consent", str(cm.exception))
        self.assertEqual(len(sink.uploads), 0)

    def test_no_cipher_deployer_gets_refusal_not_weak_crypto(self):
        # The AEAD seam, attacker-shaped as a deployer who never
        # injects a cipher: archive_key WITHOUT cipher= is REFUSED.
        # The failure mode is "cannot do encrypted uploads", never
        # "silently weak crypto". Pinned as the wave-35 honesty
        # review's executable form.
        ctx = _ctx()
        collector = _collector(ctx)
        token = _token(ctx)
        ws = _workspace(ctx["run_dir"])
        sink = _Sink("idx.example.com")
        with self.assertRaises(PlatformEgressError) as cm:
            collector.collect(ws, consent=token,
                              destination="idx.example.com",
                              sink=sink,
                              archive_key=b"deployer-key-16bytes")
        self.assertIn("cipher", str(cm.exception))
        self.assertEqual(len(sink.uploads), 0)

    def test_no_cipher_no_key_is_also_refused(self):
        # Neither key nor explicit plaintext opt-in: refused (no
        # silent plaintext default).
        ctx = _ctx()
        collector = _collector(ctx)
        token = _token(ctx)
        ws = _workspace(ctx["run_dir"])
        sink = _Sink("idx.example.com")
        with self.assertRaises(PlatformEgressError):
            collector.collect(ws, consent=token,
                              destination="idx.example.com",
                              sink=sink)
        self.assertEqual(len(sink.uploads), 0)


class TestRT6SinkDestinationBinding(unittest.TestCase):
    """E. The sink/destination binding seam (NEW in RT6).

    Pre-hardening this test DEMONSTRATES the miss: consent is valid,
    the destination string is allowlisted, but the sink's own
    ``.host`` points elsewhere -- and the upload went through anyway.
    The policy decision was bound to a string the bytes never
    followed.

    Threat-class note (why hardening, not a finding): the F110
    threat class is UNCONSENTED platform code uploading workspaces.
    Reaching this seam requires a valid consent token, which the
    unconsented attacker cannot mint (platform-held key). No
    end-to-end evasion of the threat class is demonstrated, so per
    the RT5 precedent this is defense-in-depth hardening: bind the
    policy-checked destination to the actual bytes path so a later
    misconfigured/configurable sink cannot silently diverge.
    """

    def test_sink_host_mismatch_refused(self):
        ctx = _ctx()
        collector = _collector(ctx)
        token = _token(ctx)
        ws = _workspace(ctx["run_dir"])
        # Destination string is allowlisted; the SINK goes elsewhere.
        sink = _Sink("evil.example.net")
        with self.assertRaises(PlatformEgressError) as cm:
            collector.collect(ws, consent=token,
                              destination="idx.example.com",
                              sink=sink, allow_plaintext=True)
        self.assertIn("sink", str(cm.exception).lower())
        self.assertEqual(len(sink.uploads), 0)

    def test_matching_sink_host_still_uploads(self):
        # The binding must not break the honest path.
        ctx = _ctx()
        collector = _collector(ctx)
        token = _token(ctx)
        ws = _workspace(ctx["run_dir"])
        sink = _Sink("idx.example.com")
        result = collector.collect(ws, consent=token,
                                   destination="idx.example.com",
                                   sink=sink, allow_plaintext=True)
        self.assertTrue(result["uploaded"])
        self.assertEqual(len(sink.uploads), 1)

    def test_sink_without_host_attr_is_deployer_responsibility(self):
        # A sink that exposes no .host cannot be bound -- documented
        # boundary: the deployer owns the sink's routing, same trust
        # class as the injected cipher. The control fails closed
        # only where it has a verifiable claim.
        ctx = _ctx()
        collector = _collector(ctx)
        token = _token(ctx)
        ws = _workspace(ctx["run_dir"])

        class _HostlessSink:
            def __init__(self):
                self.uploads = []

            def put(self, name, payload):
                self.uploads.append((name, payload))

        sink = _HostlessSink()
        result = collector.collect(ws, consent=token,
                                   destination="idx.example.com",
                                   sink=sink, allow_plaintext=True)
        self.assertTrue(result["uploaded"])


if __name__ == "__main__":
    unittest.main()
