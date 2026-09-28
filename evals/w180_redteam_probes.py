#!/usr/bin/env python3
"""Wave-180 lane D: red-team probes on wave-179's four new surfaces.

Break-first battery per the diagnosing-bugs skill. Each probe attacks a
concrete seam of wave-179's work and reports BREAK (gap demonstrated),
HELD (defense held), or HELD* (held, with a documented residual or
limitation worth naming). The product code is UNMODIFIED; every probe
runs against the pristine tree at 88261a9.

Surfaces:
  A. Ed25519 audit-signer wiring (gov/log.py resolve_audit_signer /
     open_audit_log; gov/evidence_bundle.py seal/assemble binding;
     gov/evidence_verify.py V9d).
  B. TUF pin expiry + rollback (gov/skill_watch.py).
  C. Differential discovery (gov/discovery_diff.py + gov/discovery.py).
  D. F196 packet<->receipt pairing (gov/decision_packet.py).

Deterministic (every probe runs twice; a verdict change is an ERROR),
synthetic/local only, $0. Exit nonzero only on harness ERRORs -- BREAK
is the expected red-team outcome (a filed finding), not a battery
failure.
"""

import copy
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

TREE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TREE))

# Fresh keys per run: the battery must not depend on ambient key config.
os.environ["GOV_LOG_KEY"] = secrets.token_hex(32)
os.environ["GOV_LOG_KEY_EPOCH"] = "w180-battery"

from gov import log as _log
from gov import decision_packet as _dp
from gov import decision_bom as _bom
from gov import invocation_receipts as _rc
from gov import skill_watch as _sw
from gov import discovery_diff as _dd
from gov import discovery as _disc

_records = []


def _record(pid, verdict, detail):
    _records.append((pid, verdict, detail))
    print("%-4s %-7s %s" % (pid, verdict, detail), flush=True)


def _fresh_tmp():
    os.makedirs("/var/tmp", exist_ok=True)
    return tempfile.mkdtemp(prefix="w180-", dir="/var/tmp")


class _EnvGuard:
    """Save/restore environ keys (None value = ensure absent)."""

    def __init__(self, **kw):
        self.kw = kw
        self.old = {}

    def __enter__(self):
        for k, v in self.kw.items():
            self.old[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return self

    def __exit__(self, *a):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return False


_PROBES = []


def probe(pid, name):
    def deco(fn):
        _PROBES.append((pid, name, fn))
        return fn
    return deco


def _run_probe(pid, name, fn):
    try:
        v1, d1 = fn()
        v2, d2 = fn()
    except Exception as e:  # noqa: BLE001 -- harness must not die
        _record(pid, "ERROR", "%s: %s" % (type(e).__name__, e))
        return
    if v1 != v2:
        _record(pid, "ERROR",
                "non-deterministic: %r vs %r" % ((v1, d1), (v2, d2)))
        return
    _record(pid, v1, d1)


# ---------------------------------------------------------------------------
# A. Ed25519 audit-signer wiring
# ---------------------------------------------------------------------------

@probe("A1", "signer absent -> HMAC-only (None), no loud failure")
def _a1():
    with _EnvGuard(GOV_AUDIT_SIGNING_KEY=None,
                   GOV_AUDIT_SIGNING_KEY_FILE=None):
        s = _log.resolve_audit_signer()
    if s is None:
        return "HELD", "absent config resolves None (HMAC-only)"
    return "BREAK", "expected None, got %r" % (s,)


@probe("A2", "malformed hex env -> NoAuditSigningKeyError (loud)")
def _a2():
    with _EnvGuard(GOV_AUDIT_SIGNING_KEY="zzzz-not-hex",
                   GOV_AUDIT_SIGNING_KEY_FILE=None):
        try:
            _log.resolve_audit_signer()
        except _log.NoAuditSigningKeyError:
            return "HELD", "malformed env raises loud"
    return "BREAK", "malformed env did not raise"


@probe("A3", "wrong-length hex env -> NoAuditSigningKeyError (loud)")
def _a3():
    with _EnvGuard(GOV_AUDIT_SIGNING_KEY="ab" * 31,
                   GOV_AUDIT_SIGNING_KEY_FILE=None):
        try:
            _log.resolve_audit_signer()
        except _log.NoAuditSigningKeyError:
            return "HELD", "31-byte seed raises loud"
    return "BREAK", "wrong-length env did not raise"


@probe("A4", "group/world-readable key file -> refused (loud)")
def _a4():
    tmp = _fresh_tmp()
    kf = os.path.join(tmp, "audit.key")
    Path(kf).write_text(secrets.token_hex(32) + "\n")
    os.chmod(kf, 0o644)
    with _EnvGuard(GOV_AUDIT_SIGNING_KEY=None,
                   GOV_AUDIT_SIGNING_KEY_FILE=kf):
        try:
            _log.resolve_audit_signer()
        except _log.NoAuditSigningKeyError:
            return "HELD", "0644 key file refused"
    return "BREAK", "0644 key file accepted"


@probe("A5", "0600 key file -> signer; entries carry ed_sig/sig_key_id")
def _a5():
    from gov.signing import Ed25519Signer
    tmp = _fresh_tmp()
    seed = secrets.token_bytes(32)
    kf = os.path.join(tmp, "audit.key")
    Path(kf).write_text(seed.hex() + "\n")
    os.chmod(kf, 0o600)
    with _EnvGuard(GOV_AUDIT_SIGNING_KEY=None,
                   GOV_AUDIT_SIGNING_KEY_FILE=kf):
        s = _log.resolve_audit_signer()
        if not isinstance(s, Ed25519Signer):
            return "BREAK", "expected Ed25519Signer, got %r" % (s,)
        lg = _log.open_audit_log(os.path.join(tmp, "a.jsonl"),
                                 deployment_mode="staging")
        e = lg.append({"event": "tool_call", "decision": "allow"})
    if isinstance(e.get("ed_sig"), str) and isinstance(
            e.get("sig_key_id"), str):
        return "HELD", "0600 file resolves; entries signed"
    return "BREAK", "entry missing ed_sig/sig_key_id: %r" % (e,)


def _signed_bundle(tmp):
    """Build+seal+assemble a signed bundle; return (bundle_dir, signer)."""
    from gov.signing import Ed25519Signer
    from gov.evidence_bundle import (EvidenceBundle,
                                     log_evidence_bundle_receipt)
    seed = secrets.token_bytes(32)
    log_path = os.path.join(tmp, "audit.jsonl")
    with _EnvGuard(GOV_AUDIT_SIGNING_KEY=seed.hex(),
                   GOV_AUDIT_SIGNING_KEY_FILE=None):
        lg = _log.open_audit_log(log_path, deployment_mode="staging")
        for i in range(4):
            lg.append({"event": "tool_call", "decision": "allow",
                       "tool": "t%d" % i})
    signer = Ed25519Signer(seed)
    eb = EvidenceBundle(log_path,
                        exported_at="2026-09-28T00:00:00+00:00",
                        operator_id="w180")
    payload = eb.build()
    manifest = eb.seal(payload, signer=signer)
    log_evidence_bundle_receipt(
        manifest,
        _log.ActionLog(log_path, signer=signer,
                       deployment_mode="staging"),
        signer=signer)
    op = {"key_id": signer.key_id,
          "public_key_hex": signer.public_key.hex()}
    out = os.path.join(tmp, "bundle")
    eb.assemble(payload, manifest, operator_key=op,
                checkpoint_keys=[dict(op)], out_dir=out)
    return out, signer


def _tamper_slice(bundle_dir, fn):
    from gov.safeguard_bundle import compute_bundle_digest
    sp = os.path.join(bundle_dir, "log_slice.jsonl")
    entries = [json.loads(l) for l in open(sp) if l.strip()]
    fn(entries)
    with open(sp, "w") as f:
        for e in entries:
            f.write(json.dumps(e, sort_keys=True) + "\n")
    digest = compute_bundle_digest(bundle_dir)
    with open(os.path.join(bundle_dir, "BUNDLE_DIGEST.sha256"),
              "w") as f:
        f.write(digest + "\n")


def _v9d_failed(bundle_dir):
    from gov import evidence_verify as _ev
    _rc, checks, _sum = _ev.verify_bundle(bundle_dir)
    return any(c.id == "V9d" and c.status == "fail" for c in checks)


@probe("A6", "V9d: stripped ed_sig fails the offline verifier")
def _a6():
    tmp = _fresh_tmp()
    out, _signer = _signed_bundle(tmp)

    def strip(entries):
        del entries[1]["ed_sig"]
    _tamper_slice(out, strip)
    if _v9d_failed(out):
        return "HELD", "stripped ed_sig -> V9d fail"
    return "BREAK", "stripped ed_sig not caught by V9d"


@probe("A7", "V9d: wrong-key ed_sig (valid foreign sig) fails")
def _a7():
    from gov.signing import Ed25519Signer as _Evil
    from gov.log import _entry_sig_body
    tmp = _fresh_tmp()
    out, _signer = _signed_bundle(tmp)
    evil = _Evil(secrets.token_bytes(32))

    def forge(entries):
        entries[1]["ed_sig"] = evil.sign(
            _entry_sig_body(entries[1])).hex()
    _tamper_slice(out, forge)
    if _v9d_failed(out):
        return "HELD", "wrong-key ed_sig -> V9d fail"
    return "BREAK", "wrong-key ed_sig not caught by V9d"


# ---------------------------------------------------------------------------
# B. TUF pin expiry + rollback (gov/skill_watch.py)
# ---------------------------------------------------------------------------

def _b_register(tmp, skill_id="s1", not_after=None):
    src_path = os.path.join(tmp, "skill-%s.py" % skill_id)
    Path(src_path).write_text("# w180 skill %s\nx = 1\n" % skill_id)
    watch = _sw.SkillWatch()
    origin = {"registry_url": "https://example.invalid/r",
              "installer_identity": "w180",
              "installed_at": "2026-09-28T00:00:00+00:00"}
    if not_after is not None:
        origin["not_after"] = not_after
    watch.register_skill(skill_id, _sw.FileContentSource(src_path),
                         origin=origin)
    return watch


@probe("B1", "expired pin refused at use ('pin-expired'), not quarantined")
def _b1():
    tmp = _fresh_tmp()
    watch = _b_register(tmp, not_after="2001-01-01T00:00:00+00:00")
    ok, detail = watch.check_at_use("s1")
    quarantined = "s1" in watch._quarantined
    if not ok and detail == "pin-expired" and not quarantined:
        return "HELD", "expired pin refused, staleness != compromise"
    return "BREAK", "ok=%r detail=%r quarantined=%r" % (
        ok, detail, quarantined)


@probe("B2", "timezone-naive not_after refused at registration")
def _b2():
    tmp = _fresh_tmp()
    try:
        _b_register(tmp, not_after="2026-01-01 00:00:00")
    except _sw.SkillWatchError:
        return "HELD", "naive datetime refused fail-closed"
    return "BREAK", "naive not_after accepted"


@probe("B3", "live rollback (older valid-MAC file) quarantines")
def _b3():
    tmp = _fresh_tmp()
    key = secrets.token_bytes(32)
    watch = _b_register(tmp)
    pin_path = os.path.join(tmp, "pins.json")
    _sw.PinStore.save(watch, pin_path, mac_key=key)   # v1
    v1_bytes = Path(pin_path).read_bytes()
    _sw.PinStore.save(watch, pin_path, mac_key=key)   # v2
    if watch._pin_manifest_version != 2:
        return "ERROR", "expected manifest v2, got %r" % (
            watch._pin_manifest_version,)
    Path(pin_path).write_bytes(v1_bytes)  # attacker restores snapshot
    ok, detail = watch.check_at_use("s1")
    if (not ok and "rollback" in detail
            and "s1" in watch._quarantined):
        return "HELD", "rollback quarantined: %s" % detail
    return "BREAK", "ok=%r detail=%r quarantined=%r" % (
        ok, detail, "s1" in watch._quarantined)


@probe("B4", "PinStore.load(min_manifest_version) refuses older file LOUD")
def _b4():
    tmp = _fresh_tmp()
    key = secrets.token_bytes(32)
    watch = _b_register(tmp)
    pin_path = os.path.join(tmp, "pins.json")
    _sw.PinStore.save(watch, pin_path, mac_key=key)   # v1
    try:
        _sw.PinStore.load(pin_path, mac_key=key, min_manifest_version=5)
    except _sw.PinStoreError:
        return "HELD", "cross-restart rollback refused LOUD"
    return "BREAK", "older file loaded despite version floor"


@probe("B5", "sweep report shape: expired pin still 'clean' (documented)")
def _b5():
    # Lane D honest note: the sweep's report shape is frozen by an
    # exact-equality test, so expiry is enforced at use time only.
    tmp = _fresh_tmp()
    watch = _b_register(tmp, not_after="2001-01-01T00:00:00+00:00")
    report = watch.verify_all()
    if "s1" in report["clean"]:
        return ("HELD*",
                "sweep reports expired pin clean -- documented future "
                "work (enforcement is at check_at_use)")
    return "BREAK", "unexpected sweep shape: %r" % (report,)


@probe("B6", "forward file write: in-memory not_after staleness")
def _b6():
    # Deployment-side save from a newer writer (valid MAC): the live
    # watcher adopts the manifest version -- do the pin records follow?
    tmp = _fresh_tmp()
    key = secrets.token_bytes(32)
    watch = _b_register(tmp, not_after="2999-01-01T00:00:00+00:00")
    pin_path = os.path.join(tmp, "pins.json")
    _sw.PinStore.save(watch, pin_path, mac_key=key)   # v1
    data = json.loads(Path(pin_path).read_bytes().decode("utf-8"))
    data.pop("manifest_mac", None)
    data["manifest_version"] = 2
    data["pins"]["s1"]["not_after"] = "2001-01-01T00:00:00+00:00"
    data["manifest_mac"] = _sw._pin_manifest_mac(
        _sw._canonical_manifest_bytes(data), key)
    Path(pin_path).write_bytes(_sw._canonical_manifest_bytes(data))
    ok, detail = watch.check_at_use("s1")
    mem_not_after = watch._skills["s1"]["not_after"]
    if not ok and detail == "pin-expired":
        return "HELD", "watcher picked up the shortened bound"
    return ("HELD*",
            "watcher kept stale in-memory not_after=%r (file says "
            "2001): forward-write adoption is version-only -- "
            "requires the MAC key, not adversary-reachable; "
            "correctness note, not a finding" % (mem_not_after,))


@probe("B7", "non-string not_after refused at registration")
def _b7():
    tmp = _fresh_tmp()
    try:
        _b_register(tmp, not_after=1767225600)
    except _sw.SkillWatchError:
        return "HELD", "int not_after refused fail-closed"
    return "BREAK", "non-string not_after accepted"


# ---------------------------------------------------------------------------
# C. Differential discovery (gov/discovery_diff.py + gov/discovery.py)
# ---------------------------------------------------------------------------

def _c_differ(snaps, clock, inventory=()):
    it = iter(snaps)
    return _dd.HostDiffer(
        [_dd.DifferentialQuery("processes", lambda: next(it),
                               interval=0, unknown_agents=True)],
        inventory=inventory, clock=lambda: clock[0])


def _c_proc(pid, name="evil", exe="/tmp/evil"):
    return {"pid": pid, "name": name, "cmdline": "%s --daemon" % name,
            "exe": exe}


@probe("C1", "first poll is a silent baseline (documented osquery)")
def _c1():
    clock = [1000.0]
    d = _c_differ([{123: _c_proc(123)}], clock)
    r = d.poll()
    if not r.unknown_agents and not r.added["processes"]:
        return "HELD", "baseline silent by design"
    return "BREAK", "baseline emitted findings: %r" % (
        r.unknown_agents,)


@probe("C2", "added unknown process -> exactly one finding")
def _c2():
    clock = [1000.0]
    d = _c_differ([{}, {123: _c_proc(123)}], clock)
    d.poll()
    clock[0] += 61
    r = d.poll()
    if (len(r.unknown_agents) == 1
            and r.unknown_agents[0]["pid"] == 123):
        return "HELD", "one unknown_agent finding"
    return "BREAK", "findings=%r" % (r.unknown_agents,)


@probe("C3", "removed process -> lifecycle event")
def _c3():
    clock = [1000.0]
    d = _c_differ([{123: _c_proc(123)}, {}], clock)
    d.poll()
    clock[0] += 61
    r = d.poll()
    if (len(r.lifecycle_events) == 1
            and r.lifecycle_events[0]["transition"] == "removed"):
        return "HELD", "removed -> lifecycle event"
    return "BREAK", "lifecycle=%r" % (r.lifecycle_events,)


@probe("C4", "collector failure keeps state, records error, no phantoms")
def _c4():
    clock = [1000.0]
    calls = [0]

    def flaky():
        calls[0] += 1
        if calls[0] == 2:
            raise RuntimeError("boom")
        return {123: _c_proc(123)}
    d = _dd.HostDiffer(
        [_dd.DifferentialQuery("processes", flaky, interval=0,
                               unknown_agents=True)],
        clock=lambda: clock[0])
    d.poll()
    clock[0] += 61
    r = d.poll()
    clock[0] += 61
    r2 = d.poll()
    if (len(r.errors) == 1 and not r.removed["processes"]
            and not r2.removed["processes"]
            and not r2.unknown_agents):
        return "HELD", "failure -> error recorded, state kept"
    return "BREAK", "errors=%r removed=%r" % (r.errors,
                                              r.removed["processes"])


@probe("C5", "inventory name match suppresses finding (documented)")
def _c5():
    # Inventory is "exe paths and/or process names" by design; a bare
    # name is the weaker, deployment-chosen option.
    clock = [1000.0]
    d = _c_differ([{}, {123: _c_proc(123, name="python3",
                                    exe="/tmp/evil-implant")}],
                  clock, inventory={"python3"})
    d.poll()
    clock[0] += 61
    r = d.poll()
    if not r.unknown_agents:
        return ("HELD*",
                "name-spoof evades finding -- documented trade-off: "
                "deployments should inventory exe paths, not bare names")
    return "BREAK", "unexpected finding despite name match"


@probe("C6", "restarted process -> new candidate (first_seen in id)")
def _c6():
    # to_discovery_signals puts first_seen in the signal detail, and
    # candidate_id_for_sig fingerprints the whole detail: an exited+
    # restarted process is a NEW candidate, never a merge. Observed
    # behavior; arguably correct (new process instance).
    clock = [1000.0]
    d = _c_differ([{}, {123: _c_proc(123)}, {},
                   {123: _c_proc(123)}], clock)
    d.poll()
    clock[0] += 61
    r2 = d.poll()
    clock[0] += 61
    d.poll()
    clock[0] += 61
    r4 = d.poll()
    tmp = _fresh_tmp()
    ledger = _disc.DiscoveryLedger(os.path.join(tmp, "ledger.jsonl"))
    c2 = ledger.note_signals(_dd.to_discovery_signals(r2))
    c4 = ledger.note_signals(_dd.to_discovery_signals(r4))
    n = len(ledger.candidates())
    if n == 2 and c2 != c4:
        return ("HELD*",
                "restart -> distinct candidate (no merge across "
                "instances); persistent process within one instance "
                "merges normally")
    return "BREAK", "candidates=%d c2=%r c4=%r" % (n, c2, c4)


@probe("C7", "changed row = removed(old)+added(new), added re-checked")
def _c7():
    clock = [1000.0]
    d = _c_differ([{123: _c_proc(123, exe="/usr/bin/ok")},
                   {123: _c_proc(123, exe="/tmp/evil")}], clock)
    d.poll()
    clock[0] += 61
    r = d.poll()
    added_exes = [a["exe"] for a in r.added["processes"]]
    removed_exes = [x["exe"] for x in r.removed["processes"]]
    if (added_exes == ["/tmp/evil"] and removed_exes == ["/usr/bin/ok"]
            and len(r.unknown_agents) == 1):
        return "HELD", "version change visible as removed+added"
    return "BREAK", "added=%r removed=%r findings=%r" % (
        added_exes, removed_exes, r.unknown_agents)


# ---------------------------------------------------------------------------
# D. F196 packet<->receipt pairing (gov/decision_packet.py)
# ---------------------------------------------------------------------------

_PROBE_POLICY_DIGEST = hashlib.sha256(
    b"w180-probe-policy-bundle-v1").hexdigest()


def _d_bom(*, head_digest, approval_id, identity):
    """Consistent Decision BOM for probe-built packets (merge fix).

    Wave-180 lane A made ``bill_of_materials`` a mandatory,
    signature-covered packet section. The D-probes build packets
    directly, so each probe packet gets a BOM that agrees with the
    packet's own sections (policy id/version/digest, evidence head,
    approval id, principal). The BOM does not bind
    ``decision_digest``, so the F196 adversarial shapes (D1/D5) are
    preserved.

    The probe trajectory uses synthetic approval ids ("A1"/"A2") with
    no real approval records; the record digest is therefore a
    deterministic synthetic fixture (documented here, not a real
    record binding -- these probes do not test approval-record
    provenance).
    """
    record_digest = hashlib.sha256(
        b"w180-probe-approval-record-" + approval_id.encode()).hexdigest()
    return _bom.build_bom(
        policy_id="pol", policy_version="1",
        policy_digest=_PROBE_POLICY_DIGEST,
        evidence_head_digest=head_digest,
        principal=dict(identity),
        approval_id=approval_id,
        approval_record_digest=record_digest)


def _d_trajectory(run_dir, *, p1_digest_override=None,
                  r1_attribution_override=None):
    """Two-decision trajectory (mirrors evals/receiptswap_probes.py)."""
    log_path = str(Path(run_dir) / "audit.jsonl")
    alog = _log.ActionLog(log_path)
    rkey = _rc.resolve_receipt_key(explicit="cd" * 32)
    for i in (1, 2):
        aid = "A%d" % i
        pol = {"policy_id": "pol", "decision": "allow",
               "tool": "write_file", "target": "/data/out%d.txt" % i,
               "approval_id": aid, "decision_seq": i}
        e_dec = alog.append({"event": "decision",
                             "approval_id": aid, "decision_seq": i,
                             "tool": "write_file", "decision": "allow",
                             "policy_decision": pol})
        dd = hashlib.sha256(json.dumps(
            pol, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        if i == 1 and p1_digest_override is not None:
            dd = p1_digest_override
        ident = {"agent_id": "ag", "role": "coder",
                 "principal": "p", "run_id": "run1"}
        bom = _d_bom(head_digest=e_dec["hash"], approval_id=aid,
                     identity=ident)
        body = _dp.build_decision_packet(
            decision="allow", boundary_declared=False,
            policy_id="pol", policy_version="1",
            matched_rules=["r1"], policy_flag=None,
            decision_digest=dd,
            canonical_target="/data/out%d.txt" % i,
            preview_digest=hashlib.sha256(
                ("preview%d" % i).encode()).hexdigest(),
            approval_id=aid, decision_seq=i,
            evidence_head_digest=e_dec["hash"],
            identity=ident,
            bill_of_materials=bom,
            policy_bundle_digest=_PROBE_POLICY_DIGEST)
        packet = _dp.sign_packet(body, bytes.fromhex("ab" * 32))
        alog.append({"event": "decision_packet", "approval_id": aid,
                     "decision_seq": i,
                     "packet_digest": _dp.packet_digest(packet),
                     "packet": packet})
        att = {"approval_id": aid, "challenge": aid,
               "result": "output-of-decision-%d" % i}
        if i == 1 and r1_attribution_override is not None:
            att = dict(r1_attribution_override)
        rbody = _rc.build_receipt(
            holder={"agent_id": "ag", "role": "coder",
                    "principal": "p", "run_id": "run1"},
            challenge=att["challenge"], action_tool="write_file",
            action_args={"path": "/data/out%d.txt" % i},
            canonical_target="/data/out%d.txt" % i,
            policy_decision="execution_authorized",
            approval_id=att["approval_id"], policy_id="pol",
            preview_text="preview%d" % i, outcome_status="executed",
            result=att["result"], key_id=rkey["key_id"],
            pubkey_hex=rkey["pubkey_hex"])
        receipt = _rc.countersign(rbody, bytes.fromhex("cd" * 32))
        alog.append({"event": "invocation_receipt",
                     "approval_id": aid, "decision_seq": i,
                     "receipt": receipt})
    return _log.read_entries(log_path)


def _d_packets(entries):
    return [e["packet"] for e in entries
            if e.get("event") == "decision_packet"]


@probe("D1", "F196 V5 re-probe: swapped decision_digest fails verify")
def _d1():
    tmp = _fresh_tmp()
    entries = _d_trajectory(tmp, p1_digest_override="ff" * 32)
    ok, reason = _dp.verify_decision_packet(_d_packets(entries)[0],
                                            entries)
    if not ok:
        return "HELD", "swapped digest refused: %s" % reason
    return "BREAK", "swapped decision_digest verified"


@probe("D2", "seqless receipt entry skips pairing (documented residual)")
def _d2():
    # F196 closure honest residual (c): approved-sweep receipts lack
    # decision_seq, so pairing skips entries without it. Probe the
    # adversarial shape: matching approval_id, ABSENT decision_seq,
    # inner receipt attributing to ANOTHER approval.
    tmp = _fresh_tmp()
    entries = copy.deepcopy(_d_trajectory(tmp))
    for e in entries:
        if (e.get("event") == "invocation_receipt"
                and e.get("approval_id") == "A1"):
            e.pop("decision_seq", None)
            e["receipt"]["policy"]["approval_id"] = "A2"
    ok, reason = _dp.verify_decision_packet(_d_packets(entries)[0],
                                            entries)
    if ok:
        return ("HELD*",
                "seqless misattributed receipt skipped by pairing -- "
                "documented F196 residual (c); close-when 'ideally' "
                "(packet_digest binding) would close it")
    return "HELD", "refused despite missing decision_seq: %s" % reason


@probe("D3", "pre-fix chain (no policy_decision) fails closed")
def _d3():
    tmp = _fresh_tmp()
    entries = copy.deepcopy(_d_trajectory(tmp))
    for e in entries:
        e.pop("policy_decision", None)
    ok, reason = _dp.verify_decision_packet(_d_packets(entries)[0],
                                            entries)
    if not ok and "policy_decision" in reason:
        return "HELD", "pre-fix chain fails closed: %s" % reason
    return "BREAK", "ok=%r reason=%r" % (ok, reason)


@probe("D4", "head pointing at non-decision entry fails closed")
def _d4():
    tmp = _fresh_tmp()
    entries = copy.deepcopy(_d_trajectory(tmp))
    pkt = _d_packets(entries)[0]
    # Point the packet's head at the invocation_receipt entry's hash.
    rcpt = [e for e in entries
            if e.get("event") == "invocation_receipt"][0]
    pkt2 = copy.deepcopy(pkt)
    pkt2["evidence"]["value"]["head_digest"] = rcpt["hash"]
    # Rebuild the BOM so it agrees with the re-pointed head: the probe
    # must exercise the non-decision-head check, not the BOM-agreement
    # check (merge fix for lane A's mandatory BOM).
    pkt_ident = pkt2["identity"]["value"]
    pkt2["bill_of_materials"]["value"] = _d_bom(
        head_digest=rcpt["hash"],
        approval_id=pkt2["approval_id"]["value"],
        identity={k: pkt_ident.get(k) for k in
                  ("agent_id", "role", "principal", "run_id")})
    pkt2 = _dp.sign_packet(
        {k: v for k, v in pkt2.items() if k != "signature"},
        bytes.fromhex("ab" * 32))
    ok, reason = _dp.verify_decision_packet(pkt2, entries)
    if not ok:
        return "HELD", "non-decision head refused: %s" % reason
    return "BREAK", "verified with head at receipt entry"


@probe("D5", "GENESIS-head packet with bogus digest refused (F199 closed)")
def _d5():
    # F199 closure: build_decision_packet defaults
    # evidence_head_digest="GENESIS", but the F196 re-derivation no
    # longer skips GENESIS heads -- a GENESIS-head packet verifies only
    # when the chain carries no decision entries (the honest
    # first-decision case). A key-holding producer (F196's own threat
    # model) minting a GENESIS-head packet with an arbitrary
    # decision_digest on a chain that DOES contain the decision entry
    # must now fail closed.
    bogus = "ff" * 32
    ident = {"agent_id": "ag", "role": "coder",
             "principal": "p", "run_id": "r"}
    bom = _d_bom(head_digest="GENESIS", approval_id="A1", identity=ident)
    body = _dp.build_decision_packet(
        decision="allow", boundary_declared=False,
        policy_id="pol", policy_version="1",
        matched_rules=["r1"], policy_flag=None,
        decision_digest=bogus, canonical_target="/x",
        preview_digest=hashlib.sha256(b"p").hexdigest(),
        approval_id="A1", decision_seq=1,
        evidence_head_digest="GENESIS",
        identity=ident,
        bill_of_materials=bom,
        policy_bundle_digest=_PROBE_POLICY_DIGEST)
    pkt = _dp.sign_packet(body, bytes.fromhex("ab" * 32))
    digest = _dp.packet_digest(pkt)
    entries = [
        {"event": "decision", "seq": 0, "hash": "h0",
         "prev_hash": "GENESIS", "approval_id": "A1",
         "decision_seq": 1,
         "policy_decision": {"policy_id": "pol", "decision": "allow"}},
        {"event": "decision_packet", "seq": 1, "hash": "h1",
         "prev_hash": "GENESIS", "approval_id": "A1",
         "decision_seq": 1, "packet_digest": digest, "packet": pkt},
    ]
    ok, reason = _dp.verify_decision_packet(pkt, entries)
    if not ok and "F199" in reason:
        return ("HELD",
                "GENESIS-head packet with bogus decision_digest "
                "REFUSED (%s): F199 closure holds" % reason)
    if ok:
        return ("BREAK",
                "GENESIS-head packet with bogus decision_digest "
                "VERIFIES (%s): F196 re-derivation dodged" % reason)
    return "HELD*", "refused but not via F199: %s" % reason


@probe("D6", "honest trajectory verifies end to end (sanity)")
def _d6():
    tmp = _fresh_tmp()
    entries = _d_trajectory(tmp)
    results = [_dp.verify_decision_packet(p, entries)
               for p in _d_packets(entries)]
    if all(ok for ok, _r in results):
        return "HELD", "honest packets verify"
    return "BREAK", "honest packet failed: %r" % (results,)


# ---------------------------------------------------------------------------
# Green check (depth-1) + main
# ---------------------------------------------------------------------------

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green_check", "SKIP",
                "GOV_SKIP_GREEN=1; standalone run still checks itself")
        return
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmp = _fresh_tmp()
    # Adjacent battery: the F196 receipt-swap probes must keep their
    # filed verdict (0 BREAK / 7 HELD post-closure).
    proc = subprocess.run(
        [sys.executable, str(TREE / "evals" / "receiptswap_probes.py")],
        capture_output=True, text=True, env=env, cwd=tmp, timeout=600)
    tail = (proc.stdout + proc.stderr)[-300:]
    _record("green_check_receiptswap",
            "PASS" if proc.returncode == 0 else "FAIL",
            "exit=%d tail=%r" % (proc.returncode, tail))
    if proc.returncode != 0:
        raise SystemExit("green check failed")


def main():
    _green_check()
    for pid, name, fn in _PROBES:
        _run_probe(pid, name, fn)
    brk = [p for p, v, _d in _records if v == "BREAK"]
    err = [p for p, v, _d in _records if v == "ERROR"]
    held = [p for p, v, _d in _records if v == "HELD"]
    helddoc = [p for p, v, _d in _records if v == "HELD*"]
    print("breaks=%d held=%d held_documented=%d errors=%d"
          % (len(brk), len(held), len(helddoc), len(err)))
    if brk:
        print("BREAK: %s" % ", ".join(brk))
    sys.exit(1 if err else 0)


if __name__ == "__main__":
    main()
