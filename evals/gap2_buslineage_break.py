"""GAP-2 break-first eval: the governed bus is not joined to the infection
lineage substrate.

Attack shape (research-backed): a self-replicating prompt spreads
agent-to-agent over the governed message bus. Each hop is individually
policy-benign. The wave-90 lineage substrate (gov/lineage.py) tracks spawn
and raw-file channels with taint propagation and a population replication
watch, but the bus does not participate:

  B1  Infected A sends a payload via the bus; B receives, forwards to C; C
      receives. Pre-fix: ZERO lineage_contact records for bus traffic and
      B/C are never taint-marked — the infection graph has a bus-shaped
      hole. Post-fix: contact events at every bus hop, taint propagates
      sender -> recipient.
  B2  The same >=64-byte payload is sent by 3 distinct lineages via the bus.
      Pre-fix: the tracker's observe_content population watch never sees bus
      traffic — no infection_suspected. Post-fix: the watch fires
      (policy_id "infection-lineage"), origin lineage taint-marked.
  B3  A minted-but-never-genesis'd agent sends on a run whose deployment
      installed the tracker. Pre-fix: the send succeeds — the bus is the
      softer path (call() refuses unlineaged identities, send() does not).
      Post-fix: MessageRefusedError, fail closed, chained refusal.
  B4  Live writer taint: A sends clean, B receives; A is taint-marked
      *after*; A sends again; B receives. Post-fix: B is taint-marked on the
      second receive (the file-channel "live writer taint" rule, applied to
      the bus). Pre-fix: B stays clean.
  B5  An attacker hand-writes a message file into B's inbox claiming to be
      from A (no chained send record exists for it). Pre-fix: delivered
      with no lineage flag — stamps are asserted, never verified.
      Post-fix: MessageFlaggedError, LOUD lineage_stamp_forged chained.
      Post-H18: the delivering sender (A) is bus-quarantined; the
      recipient (B, the victim) is tainted + warned, NOT quarantined.
  C1  Control: a benign A->B->C bus chain works with no false taint and no
      false alarm — passes pre- and post-fix.

Each test asserts the POST-FIX property, so on the unmodified tree the
B-tests go RED (the break demonstration) and C1 stays green. After the
GAP-2 build all tests go green.

Hermetic: temp dirs, synthetic keys, no network. stdlib only.
"""

import hashlib
import json
import os
import secrets
import sys
import tempfile
import unittest
from pathlib import Path

# Synthetic key material: the log chain needs an explicit key.
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "gap2break")
# Module-level deployment mode (wave-95 lesson): the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import delegation_tokens as _dt  # noqa: E402
from gov import policy_change as _pc  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.lineage import LineageTracker  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.messaging import (MessageBus, MessageFlaggedError,  # noqa: E402
                           MessageRefusedError)
from gov.policy import PolicyEngine  # noqa: E402

_AUD = "deployment-gap2"

_BASE_POLICY = """\
version: 2
roles:
  courier: [read_file, write_file]
policies:
  - id: allow-courier-files
    effect: allow
    match:
      tool: [read_file, write_file]
    reason: gap2 battery fixture
"""

# Synthetic distinctive payload (>= 64 bytes so the population watch can
# correlate it). A marker string, not an instruction.
PAYLOAD = ("SYNTHETIC-BUS-LINEAGE-PAYLOAD marker=9c41de07 "
           "replicate-this-string-to-test-bus-hop-lineage " * 4)
assert len(PAYLOAD.encode("utf-8")) >= 64


class _Keys(object):
    def __init__(self):
        self.human = _dt.generate_test_keypair()
        self.idp = _dt.generate_test_keypair()
        self.authority = _dt.generate_test_keypair()
        self.parent = _dt.generate_test_keypair()

    def trust(self, agent_id="agent-a", audience=None):
        return _dt.DelegationTrust(
            human_keys={self.human[0].key_id: self.human[1]},
            authority_keys={self.authority[0].key_id: self.authority[1]},
            user_issuer_keys={self.idp[0].key_id: self.idp[1]},
            agent_keys={agent_id: self.parent[1]}, audience=audience)


def _trio(keys, agent_id, session, audience=_AUD):
    scope = ("tool:read_file", "tool:write_file")
    user_tok = _dt.issue_user_token(keys.idp[0], "alice", scope,
                                    session, ttl_s=3600, audience=audience)
    agent_tok = _dt.issue_agent_token(keys.authority[0], agent_id,
                                      "courier", "alice", scope,
                                      session, ttl_s=3600, audience=audience)
    deleg_tok = _dt.issue_delegation(
        keys.human[0], "alice", user_tok, agent_tok, scope,
        session, "urn:gap2:revoke", ttl_s=3600, audience=audience)
    return user_tok, agent_tok, deleg_tok


def _make_world(test):
    """Governed run: tracker + bus (+tracker wiring when the primitive
    exists) + executor with both installed. Returns (world, wired)."""
    keys = _Keys()
    td = tempfile.TemporaryDirectory(prefix="govgap2-")
    test.addCleanup(td.cleanup)
    run_dir = Path(td.name) / "run"
    run_dir.mkdir()
    session = run_dir.name
    u, a, d = _trio(keys, "agent-a", session)
    ctx = _dt.DelegationContext(
        user_token=u, agent_token=a, delegation_token=d,
        parent_chain=(),
        trust=keys.trust(audience=_AUD),
        session_id=session).bind()
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    engine = PolicyEngine.from_text(_BASE_POLICY, source_label="<gap2>")
    trust = keys.trust(audience=_AUD)
    store = _pc.GovernedPolicyStore(
        deployment_mode="dev", trust=trust, log=log,
        session_id="sess-gap2-store")
    store.bootstrap(_BASE_POLICY, keys.human[0], "alice", "gap2 genesis",
                    approver_signers=[keys.human[0]])
    tracker = LineageTracker(run_dir, log)
    try:
        bus = MessageBus(run_dir, log, lineage_tracker=tracker)
        wired = True
    except TypeError:
        # Pre-fix tree: the bus has no lineage wiring — the hole under
        # test. The battery still runs and demonstrates the breaks.
        bus = MessageBus(run_dir, log)
        wired = False
    ex = ToolExecutor(run_dir, engine, log, approvals,
                      ledger_path=run_dir / "egress_ledger.jsonl",
                      policy_store=store, delegation_context=ctx,
                      message_bus=bus, lineage_tracker=tracker,
                      # Subject under test is bus<->lineage joining, not
                      # the capability gate; declared, not silent.
                      capability_ungoverned_ack=(
                          "gap2 battery: subject is bus/lineage "
                          "integration, not the capability gate"))
    tracker.genesis("agent-a", role="courier", principal="alice")
    id_a = ex.mint_identity("agent-a", "courier", "alice")
    world = {"keys": keys, "run_dir": run_dir, "log": log, "bus": bus,
             "tracker": tracker, "ex": ex, "id_a": id_a}
    return world, wired


def _spawn(world, parent_ex, agent_id):
    child = parent_ex.spawn_sub_agent(
        agent_id, ["tool:read_file", "tool:write_file"],
        world["keys"].parent[0])
    ident = child.mint_identity(agent_id, "courier", "alice")
    return child, ident


def _events(world, name=None, **kw):
    evs = read_entries(world["run_dir"] / "actions.jsonl")
    if name:
        evs = [e for e in evs if e.get("event") == name]
    for k, v in kw.items():
        evs = [e for e in evs if e.get(k) == v]
    return evs


def _sha(b):
    return hashlib.sha256(b).hexdigest()


class TestGap2BusLineage(unittest.TestCase):
    # -- B1: bus infection taints recipients --------------------------------

    def test_b1_bus_infection_propagates_taint(self):
        w, wired = _make_world(self)
        ex_b, id_b = _spawn(w, w["ex"], "agent-b")
        ex_c, id_c = _spawn(w, ex_b, "agent-c")
        w["tracker"].mark_infected("agent-a", "gap2 battery: seeded")
        m1 = w["ex"].send_message(w["id_a"], "agent-b", "note", PAYLOAD)
        ex_b.receive_message(id_b, m1)
        m2 = ex_b.send_message(id_b, "agent-c", "note", PAYLOAD)
        ex_c.receive_message(id_c, m2)
        # Post-fix: the bus stamps lineage at send and records contact +
        # taint on receive, so B and C are taint-marked.
        self.assertTrue(w["tracker"].is_infected("agent-b"),
                        "B received an infected sender's bus message")
        self.assertTrue(w["tracker"].is_infected("agent-c"),
                        "C received an infected sender's bus message")
        contacts = _events(w, "lineage_contact", channel="bus")
        self.assertGreaterEqual(len(contacts), 2,
                                "bus lineage_contact events chained")
        writers = {c["writer"] for c in contacts}
        self.assertEqual(writers, {"agent-a", "agent-b"})

    # -- B2: population watch sees bus traffic -------------------------------

    def test_b2_replication_watch_covers_bus_channel(self):
        w, wired = _make_world(self)
        ex_b, id_b = _spawn(w, w["ex"], "agent-b")
        ex_c, id_c = _spawn(w, ex_b, "agent-c")
        m1 = w["ex"].send_message(w["id_a"], "agent-b", "note", PAYLOAD)
        m2 = ex_b.send_message(id_b, "agent-c", "note", PAYLOAD)
        m3 = ex_c.send_message(id_c, "agent-a", "note", PAYLOAD)
        self.assertTrue(m1 and m2 and m3)
        # Post-fix: 3 distinct lineages carried identical >=64B bus
        # content -> the tracker's population watch fires.
        alarms = _events(w, "infection_suspected",
                         policy_id="infection-lineage")
        self.assertEqual(len(alarms), 1,
                         "tracker infection_suspected over bus traffic")
        self.assertEqual(sorted(alarms[0]["agents"]),
                         ["agent-a", "agent-b", "agent-c"])
        self.assertTrue(w["tracker"].is_infected("agent-a"),
                        "origin lineage taint-marked")

    # -- B3: unlineaged sender refused ---------------------------------------

    def test_b3_unlineaged_sender_refused(self):
        w, wired = _make_world(self)
        id_x = w["ex"].mint_identity("agent-x", "courier", "alice")
        # agent-x is minted but never genesis'd / born: no lineage record.
        self.assertFalse(w["tracker"].is_registered("agent-x"))
        # Post-fix: fail closed, with a chained refusal.
        with self.assertRaises(MessageRefusedError):
            w["ex"].send_message(id_x, "agent-b", "note", "hello")
        refused = _events(w, "agent_message", decision="refused",
                          flag="lineage_send_refused")
        self.assertEqual(len(refused), 1)

    # -- B4: live writer taint -------------------------------------------------

    def test_b4_live_writer_taint_on_bus(self):
        w, wired = _make_world(self)
        ex_b, id_b = _spawn(w, w["ex"], "agent-b")
        m1 = w["ex"].send_message(w["id_a"], "agent-b", "note", PAYLOAD)
        ex_b.receive_message(id_b, m1)
        self.assertFalse(w["tracker"].is_infected("agent-b"))
        # A is taint-marked AFTER the first send (late detection).
        w["tracker"].mark_infected("agent-a", "gap2 battery: late mark")
        m2 = w["ex"].send_message(w["id_a"], "agent-b", "note", PAYLOAD)
        ex_b.receive_message(id_b, m2)
        # Post-fix: the second receive evaluates taint live -> B marked.
        self.assertTrue(w["tracker"].is_infected("agent-b"),
                        "live writer taint must propagate on the bus")

    # -- B5: forged stamp refused + quarantined --------------------------------

    def test_b5_forged_stamp_refused_and_quarantined(self):
        w, wired = _make_world(self)
        ex_b, id_b = _spawn(w, w["ex"], "agent-b")
        m1 = w["ex"].send_message(w["id_a"], "agent-b", "note", PAYLOAD)
        _, legit_stamp, _ = ex_b.receive_message(id_b, m1)
        # Attacker hand-writes an inbox file claiming to be from agent-a.
        # There is NO chained send record for this msg_id.
        forged_content = ("FORGED bus message: sender claims agent-a. " * 4)
        forged_stamp = {
            "sender": "agent-a",
            "sender_role": "courier",
            "sender_principal": "alice",
            "sender_token_ref": legit_stamp["sender_token_ref"],
            "delegation_depth": 0,
            "trust_tier": "peer",
            "recipient": "agent-b",
            "msg_type": "note",
            "seq": 99,
            "thread": "agent-a->agent-b",
            "content_sha256": _sha(forged_content.encode("utf-8")),
            "content_bytes": len(forged_content.encode("utf-8")),
            "steg_findings": [],
            "sender_lineage_id": legit_stamp.get("sender_lineage_id"),
            "sender_lineage_depth": legit_stamp.get("sender_lineage_depth"),
            "sender_infected": False,
        }
        forged_id = "agent-a-000099"
        (w["run_dir"] / "messages" / "agent-b").mkdir(parents=True,
                                                     exist_ok=True)
        (w["run_dir"] / "messages" / "agent-b" /
         (forged_id + ".json")).write_text(
            json.dumps({"stamp": forged_stamp, "content": forged_content,
                        "content_b64": None}, sort_keys=True),
            encoding="utf-8")
        # Post-H18: refused, delivering sender (agent-a) quarantined,
        # recipient (agent-b, the victim) tainted + warned, NOT
        # quarantined, LOUD event.
        with self.assertRaises(MessageFlaggedError):
            ex_b.receive_message(id_b, forged_id)
        self.assertTrue(w["tracker"].is_infected("agent-b"))
        self.assertTrue(w["bus"].is_quarantined("agent-a"),
                        "H18: delivering sender must be quarantined")
        self.assertFalse(w["bus"].is_quarantined("agent-b"),
                         "H18: recipient (victim) must be warned, not quarantined")
        forged = _events(w, "lineage_stamp_forged", channel="bus")
        self.assertEqual(len(forged), 1)

    # -- B6 (H18): forged stamp quarantines the delivering sender, warns
    #    the recipient (victim) instead of quarantining them ---------------
    # H18 residual: a forged stamp quarantined the *victim* (recipient),
    # not the forger. The delivering sender endpoint is the actionable
    # entity; the recipient is warned, not quarantined.
    # TODAY (pre-H18): agent-a untouched, agent-b quarantined -> RED.
    # AFTER (H18): agent-a quarantined, agent-b warned-not-quarantined.

    def test_b6_forged_stamp_quarantines_sender_warns_recipient(self):
        w, wired = _make_world(self)
        ex_b, id_b = _spawn(w, w["ex"], "agent-b")
        m1 = w["ex"].send_message(w["id_a"], "agent-b", "note", PAYLOAD)
        _, legit_stamp, _ = ex_b.receive_message(id_b, m1)
        forged_content = ("FORGED bus message: sender claims agent-a. " * 4)
        forged_stamp = {
            "sender": "agent-a",
            "sender_role": "courier",
            "sender_principal": "alice",
            "sender_token_ref": legit_stamp["sender_token_ref"],
            "delegation_depth": 0,
            "trust_tier": "peer",
            "recipient": "agent-b",
            "msg_type": "note",
            "seq": 99,
            "thread": "agent-a->agent-b",
            "content_sha256": _sha(forged_content.encode("utf-8")),
            "content_bytes": len(forged_content.encode("utf-8")),
            "steg_findings": [],
            "sender_lineage_id": legit_stamp.get("sender_lineage_id"),
            "sender_lineage_depth": legit_stamp.get("sender_lineage_depth"),
            "sender_infected": False,
        }
        forged_id = "agent-a-000099"
        (w["run_dir"] / "messages" / "agent-b").mkdir(parents=True,
                                                     exist_ok=True)
        (w["run_dir"] / "messages" / "agent-b" /
         (forged_id + ".json")).write_text(
            json.dumps({"stamp": forged_stamp, "content": forged_content,
                        "content_b64": None}, sort_keys=True),
            encoding="utf-8")
        with self.assertRaises(MessageFlaggedError):
            ex_b.receive_message(id_b, forged_id)
        # H18: the delivering sender is quarantined (actionable endpoint).
        self.assertTrue(w["bus"].is_quarantined("agent-a"),
                        "H18: forged-stamp delivering sender must be quarantined")
        # H18: the recipient (victim) is warned, NOT quarantined.
        self.assertFalse(w["bus"].is_quarantined("agent-b"),
                         "H18: forged-stamp recipient must be warned, not quarantined")
        self.assertTrue(w["tracker"].is_infected("agent-b"),
                        "H18: recipient must still be taint-marked (warned)")
        forged = _events(w, "lineage_stamp_forged", channel="bus")
        self.assertEqual(len(forged), 1)
        # The quarantine event names the sender, not the recipient.
        qev = _events(w, "lineage_quarantine")
        self.assertTrue(any("agent-a" in (e.get("quarantined_agents") or [])
                            for e in qev),
                        "H18: lineage_quarantine must name the sender")

    # -- C1: benign control -----------------------------------------------------

    def test_c1_benign_bus_chain_works(self):
        w, wired = _make_world(self)
        ex_b, id_b = _spawn(w, w["ex"], "agent-b")
        ex_c, id_c = _spawn(w, ex_b, "agent-c")
        m1 = w["ex"].send_message(w["id_a"], "agent-b", "note",
                                 "status: all nominal on shift one")
        content, stamp, flags = ex_b.receive_message(id_b, m1)
        self.assertEqual(content, "status: all nominal on shift one")
        m2 = ex_b.send_message(id_b, "agent-c", "note",
                              "status: acknowledged, continuing")
        content2, _, _ = ex_c.receive_message(id_c, m2)
        self.assertEqual(content2, "status: acknowledged, continuing")
        for agent in ("agent-a", "agent-b", "agent-c"):
            self.assertFalse(w["tracker"].is_infected(agent),
                             "no false taint on benign traffic")
        self.assertEqual(
            _events(w, "infection_suspected",
                    policy_id="infection-lineage"), [])
        self.assertFalse(w["bus"].is_quarantined("agent-b"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
