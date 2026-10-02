"""Unit tests for gov.attested_channel (wave-243 lane E, W243-6).

Attested-channel discipline, prose re-derived from the wave-242
prospectus description of agent-receipts/obsigna (Apache-2.0,
disciplines only): the daemon signs emitter claims, not observations;
it vouches for kernel-attested peer identity, its own timestamp, the
admission chain position, and canonical-byte digests. Process
separation (keys out of the agent process) is architectural.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import attested_channel as ac
from gov import decision_codes as dc

NOW = 1700000000.0


def _peer(**over):
    base = {"uid": 1000, "gid": 1000, "pid": 4242,
            "exe": "/usr/bin/agent", "principal": "agent-7"}
    base.update(over)
    return base


def _claim(**over):
    base = {"principal": "agent-7", "ts_emit": NOW, "seq": 0,
            "payload": {"action": "read"}}
    base.update(over)
    return base


class AdmitTest(unittest.TestCase):
    def test_happy_path(self):
        adm = ac.ChannelAdmission()
        rec = adm.admit(_claim(ts_emit=NOW - 60), _peer(), "daemon", NOW)
        self.assertEqual(rec["daemon_ts"], NOW)
        self.assertEqual(rec["time_divergence_seconds"], 60)
        self.assertEqual(rec["ts_emit"], NOW - 60)
        self.assertEqual(rec["principal"], "agent-7")
        self.assertIn("peer_identity", rec["observations"])
        self.assertIn("daemon_ts", rec["observations"])
        self.assertIn("seq", rec["observations"])
        self.assertIn("canonical_digest", rec["observations"])
        self.assertEqual(rec["claims"], {"action": "read"})
        self.assertEqual(len(rec["canonical_digest"]), 64)

    def test_unattested_identity_refused_not_downgraded(self):
        adm = ac.ChannelAdmission()
        with self.assertRaises(ac.AttestedChannelError) as ctx:
            adm.admit(_claim(), None, "daemon", NOW)
        self.assertEqual(ctx.exception.code,
                         "channel-identity-unattested")

    def test_peer_mismatch_refused(self):
        adm = ac.ChannelAdmission()
        with self.assertRaises(ac.AttestedChannelError) as ctx:
            adm.admit(_claim(), _peer(principal="agent-9"), "daemon", NOW)
        self.assertEqual(ctx.exception.code, "channel-peer-mismatch")

    def test_peer_without_principal_binds_nothing(self):
        adm = ac.ChannelAdmission()
        peer = _peer()
        del peer["principal"]
        rec = adm.admit(_claim(), peer, "daemon", NOW)
        self.assertEqual(rec["principal"], "agent-7")

    def test_key_in_agent_process_refused(self):
        adm = ac.ChannelAdmission()
        with self.assertRaises(ac.AttestedChannelError) as ctx:
            adm.admit(_claim(), _peer(), "agent-process", NOW)
        self.assertEqual(ctx.exception.code, "key-in-agent-process")

    def test_unknown_key_location_refused(self):
        adm = ac.ChannelAdmission()
        with self.assertRaises(ac.AttestedChannelError) as ctx:
            adm.admit(_claim(), _peer(), "agent-sidecar", NOW)
        self.assertEqual(ctx.exception.code, "key-in-agent-process")

    def test_external_key_locations_admit(self):
        for loc in ("daemon", "external-kms", "hsm", "vault-transit"):
            adm = ac.ChannelAdmission()
            rec = adm.admit(_claim(), _peer(), loc, NOW)
            self.assertEqual(rec["principal"], "agent-7")

    def test_forged_timestamp_refused(self):
        adm = ac.ChannelAdmission()
        with self.assertRaises(ac.AttestedChannelError) as ctx:
            adm.admit(_claim(ts_emit=NOW - 90000), _peer(), "daemon", NOW)
        self.assertEqual(ctx.exception.code,
                         "channel-timestamp-divergence")

    def test_future_timestamp_beyond_bound_refused(self):
        adm = ac.ChannelAdmission()
        with self.assertRaises(ac.AttestedChannelError) as ctx:
            adm.admit(_claim(ts_emit=NOW + 90000), _peer(), "daemon", NOW)
        self.assertEqual(ctx.exception.code,
                         "channel-timestamp-divergence")

    def test_skew_within_bound_admits_with_divergence_recorded(self):
        adm = ac.ChannelAdmission()
        rec = adm.admit(_claim(ts_emit=NOW + 299), _peer(), "daemon", NOW)
        self.assertEqual(rec["daemon_ts"], NOW)
        self.assertEqual(rec["time_divergence_seconds"], -299)

    def test_sequence_break_refused(self):
        adm = ac.ChannelAdmission()
        adm.admit(_claim(seq=0), _peer(), "daemon", NOW)
        with self.assertRaises(ac.AttestedChannelError) as ctx:
            adm.admit(_claim(seq=0), _peer(), "daemon", NOW)
        self.assertEqual(ctx.exception.code, "channel-sequence-break")
        rec = adm.admit(_claim(seq=1), _peer(), "daemon", NOW)
        self.assertEqual(rec["seq"], 1)

    def test_sequences_are_per_peer(self):
        adm = ac.ChannelAdmission()
        adm.admit(_claim(seq=0), _peer(pid=1), "daemon", NOW)
        rec = adm.admit(_claim(seq=0), _peer(pid=2), "daemon", NOW)
        self.assertEqual(rec["seq"], 0)

    def test_malformed_claim_refused(self):
        adm = ac.ChannelAdmission()
        for bad in ({"principal": "agent-7"},
                    _claim(principal=""),
                    _claim(ts_emit="now"),
                    _claim(seq=-1),
                    _claim(payload=None)):
            with self.assertRaises(ac.AttestedChannelError) as ctx:
                adm.admit(bad, _peer(), "daemon", NOW)
            self.assertEqual(ctx.exception.code,
                             "channel-record-malformed")

    def test_malformed_peer_refused(self):
        adm = ac.ChannelAdmission()
        for bad in ({"uid": 1, "gid": 1, "pid": 1},
                    _peer(exe=""),
                    _peer(uid=-1),
                    "not-a-dict"):
            with self.assertRaises(ac.AttestedChannelError) as ctx:
                adm.admit(_claim(), bad, "daemon", NOW)
            self.assertIn(ctx.exception.code,
                          ("channel-record-malformed",
                           "channel-identity-unattested"))


class SinkTest(unittest.TestCase):
    def _raw(self, **over):
        import json
        return json.dumps(_claim(**over), sort_keys=True)

    def test_collect_stores_verbatim(self):
        sink = ac.ForwardCompatSink()
        raw = self._raw()
        idx = sink.collect(raw)
        self.assertEqual(idx, 0)
        self.assertEqual(sink._blobs[0], raw.encode("utf-8"))

    def test_collect_rejects_non_json(self):
        sink = ac.ForwardCompatSink()
        with self.assertRaises(ac.AttestedChannelError) as ctx:
            sink.collect(b"not json {{{")
        self.assertEqual(ctx.exception.code, "channel-record-malformed")

    def test_audit_admits_honest_blob(self):
        sink = ac.ForwardCompatSink()
        sink.collect(self._raw(ts_emit=NOW - 10))
        records = sink.audit(lambda r: _peer(), "daemon", NOW)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["daemon_ts"], NOW)

    def test_audit_refuses_tampered_blob(self):
        sink = ac.ForwardCompatSink()
        sink.collect(self._raw())
        import json
        tampered = json.loads(self._raw())
        tampered["payload"] = {"action": "delete"}
        sink._blobs[0] = json.dumps(tampered,
                                    sort_keys=True).encode("utf-8")
        with self.assertRaises(ac.AttestedChannelError) as ctx:
            sink.audit(lambda r: _peer(), "daemon", NOW)
        self.assertEqual(ctx.exception.code, "channel-record-malformed")

    def test_audit_chains_sequences(self):
        import json
        sink = ac.ForwardCompatSink()
        sink.collect(json.dumps(_claim(seq=0), sort_keys=True))
        sink.collect(json.dumps(_claim(seq=0), sort_keys=True))
        with self.assertRaises(ac.AttestedChannelError) as ctx:
            sink.audit(lambda r: _peer(), "daemon", NOW)
        self.assertEqual(ctx.exception.code, "channel-sequence-break")


class TaxonomyTest(unittest.TestCase):
    def test_new_codes_mapped(self):
        # Wave-243 lane E: 6 new attested-channel codes, additive only.
        for code in ("channel-record-malformed",
                     "channel-identity-unattested",
                     "channel-peer-mismatch", "key-in-agent-process",
                     "channel-timestamp-divergence",
                     "channel-sequence-break"):
            rec = dc.code_for(code)
            self.assertEqual(rec["code"], code)
            self.assertEqual(rec["domain"], "attested-channel")
        # Wave-243 lane E: re-pointed 788 -> 794 (6 new attested-channel
        # codes), additive only.
        # Wave-243 merge: re-pointed 788 -> 828 (40 additive codes: 2 cosign-interop
        # + 5 finality-bound + 6 transactional-tokens + 4 action-bound-permits
        # + 6 attested-channel + 2 outcome-vocabulary + 5 verifier-failclosed
        # + 10 effect-agreement/registry/mcp), additive only, composed from the
        # eight lane commits by direct byte-verification.
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 1730)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 lane 2: pin 1730 -> 1730 (+3 toolcall-*: sequence-violated, secret-in-args, rule-compile-invalid)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
