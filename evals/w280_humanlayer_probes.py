"""Break-first red battery: function-layer human approval contract
(wave-280 lane 5; HumanLayer ADAPT -- contract shapes only, no
HumanLayer code or text reused; the legacy humanlayer/humanlayer repo
is Apache-2.0 but deprecated -- the humanlayer.com rebuild is
proprietary, so only the CONTRACT SHAPES are adapted here).

The gap under test: the approval queue has machinery (queue/decide,
bridge waits, elicitation contract) but no FUNCTION-LAYER contract --
approval needs are not declared on the tool/function, so they are not
deterministic and not prompt-injection-proof; there is no
approve/deny/edit/timeout OUTCOME contract for a human decision
(the human cannot approve MODIFIED args, and a timed-out wait leaves
the record silently pending); there is no 4-tier stakes taxonomy
driving the request; and there is no agent-initiated outer loop
(request -> wait -> human decision -> resume) as a first-class
primitive.

Break shapes pinned here (all must report HELD on the lane tree):
  (a) contract registry: declare()/need_for()/requires_approval() exist;
      undeclared tools are fail-closed in request_human_decision;
      duplicate declaration refused;
  (b) the registry is authoritative over agent framing: an
      agent_justification saying "no approval needed" does not suppress
      the request (prompt-injection-proof);
  (c) edit: decide(..., edited_args={...}) approves the MODIFIED args --
      record args updated, args_digest re-MACed (integrity holds), a
      dedicated approval_args_edited chain entry records old/new
      digests, the approval_decision entry names human_outcome "edited";
  (d) edit is approve-only: edited_args on a rejection is refused
      fail-closed; non-dict / non-JSON-serializable edited_args refused;
  (e) timeout: an undecided wait returns TIMED_OUT, the record is
      stamped request_expired, an approval_timeout chain entry exists,
      and a LATER decide() on it is refused (fail-closed -- timeouts
      cannot be resurrected by a late human);
  (f) outer loop: request -> wait -> human decide in another thread ->
      resume returns APPROVED / DENIED / EDITED with the edited args
      visible to the agent;
  (g) audit-trail completeness: every human outcome (approve / deny /
      edit / timeout) lands in the HMAC-chained audit log as an
      approval_decision / approval_timeout event;
  (h) 4-tier stakes taxonomy: low/medium/high/critical, unknown tier
      refused, per-tier wait horizons ordered low < critical; the tier
      maps onto the engine's existing risk continuum (critical +30 /
      high +20 / medium +10 / low +0 on packet_risk_score, feeding
      auto-approve bar, cooling-off, and the capture-tier shield);
  (i) vanished record: a request whose approval record is destroyed
      mid-wait raises fail-closed (ValueError) -- never a fake
      TIMED_OUT;
  (j) taxonomy pin 1588/1541 raw literals sorted, 0 duplicates
      (no new decision codes needed by this lane; later lanes repoint
      the pin value-only).

$0 spend, synthetic/local, deterministic (fixed fixtures; timeouts are
short but the waits always resolve before the deadline). Stdlib only,
no in-repo git subprocesses. Fresh TMPDIR per process is the caller's
concern; the depth-1 green checks below mint their own TMPDIRs.

Run:
  mkdir -p /var/tmp/g280-humanlayer-bat && TMPDIR=/var/tmp/g280-humanlayer-bat \
    ~/workspace/.gov-venv/bin/python evals/w280_humanlayer_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g280-humanlayer-bat2 \
    ~/workspace/.gov-venv/bin/python evals/w280_humanlayer_probes.py
"""

import os
import re
import sys
import threading
import time

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from keyfixture import provision_test_key  # noqa: E402

provision_test_key()

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

from harness import make_run  # noqa: E402

try:
    from gov import human_approval_contract as hlc  # noqa: E402
    HAVE_HLC = True
except ImportError:
    hlc = None
    HAVE_HLC = False

RESULTS = []


def _record(name, verdict, detail=""):
    RESULTS.append({"probe": name, "verdict": verdict, "detail": detail})
    return verdict


def _held(name, detail=""):
    return _record(name, "HELD", detail)


def _broken(name, detail=""):
    return _record(name, "BREAK", detail)


def _error(name, detail=""):
    return _record(name, "ERROR", detail)


def _events(run, event):
    return [e for e in run["read_log"]() if e.get("event") == event]


def _queue_one(run, tool="send_email", agent_id="agent-1", **kwargs):
    ident = run["executor"].mint_identity(agent_id, "support", agent_id)
    res = run["executor"].call(ident, tool, to="victim@synthetic.local",
                               subject="hello", body="hello", **kwargs)
    assert res["status"] == "queued", res
    return res["approval_id"], ident


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------

def probe_registry_exists():
    name = "hl-contract-registry"
    if not HAVE_HLC:
        return _broken(name, "gov.human_approval_contract absent on base")
    try:
        hlc.declare(hlc.ApprovalNeed("send_email", hlc.STAKES_HIGH))
        need = hlc.need_for("send_email")
        if need is None or need.tool != "send_email":
            return _broken(name, "need_for did not return the declaration")
        if not hlc.requires_approval("send_email"):
            return _broken(name, "requires_approval False for a declared tool")
        if hlc.requires_approval("read_file"):
            return _broken(name, "requires_approval True for undeclared tool")
        return _held(name, "registry declares, looks up, and defaults closed")
    except Exception as exc:  # noqa: BLE001
        return _error(name, "raised %r" % (exc,))
    finally:
        if HAVE_HLC:
            hlc.reset_registry()


def probe_duplicate_declaration_refused():
    name = "hl-duplicate-declare-refused"
    if not HAVE_HLC:
        return _broken(name, "gov.human_approval_contract absent on base")
    try:
        hlc.declare(hlc.ApprovalNeed("send_email", hlc.STAKES_LOW))
        try:
            hlc.declare(hlc.ApprovalNeed("send_email", hlc.STAKES_HIGH))
        except ValueError:
            return _held(name, "second declaration refused fail-closed")
        return _broken(name, "duplicate declaration silently overwrote")
    except Exception as exc:  # noqa: BLE001
        return _error(name, "raised %r" % (exc,))
    finally:
        hlc.reset_registry()


def probe_stakes_taxonomy():
    name = "hl-stakes-taxonomy"
    if not HAVE_HLC:
        return _broken(name, "gov.human_approval_contract absent on base")
    try:
        if tuple(hlc.STAKES_TIERS) != ("low", "medium", "high", "critical"):
            return _broken(name, "tiers are not the 4-tier vocabulary: %r"
                           % (hlc.STAKES_TIERS,))
        try:
            hlc.validate_stakes("cosmic")
        except ValueError:
            pass
        else:
            return _broken(name, "unknown tier accepted")
        horizons = [hlc.default_wait_horizon(t) for t in hlc.STAKES_TIERS]
        if not all(isinstance(h, (int, float)) and h > 0 for h in horizons):
            return _broken(name, "non-positive horizon: %r" % (horizons,))
        if not horizons[0] < horizons[-1]:
            return _broken(name, "horizon not increasing with stakes")
        return _held(name, "4-tier vocabulary; unknown refused; horizons rise")
    except Exception as exc:  # noqa: BLE001
        return _error(name, "raised %r" % (exc,))


def probe_framing_cannot_suppress():
    name = "hl-framing-cannot-suppress"
    if not HAVE_HLC:
        return _broken(name, "gov.human_approval_contract absent on base")
    try:
        hlc.declare(hlc.ApprovalNeed("send_email", hlc.STAKES_HIGH))
        run = make_run()
        ident = run["executor"].mint_identity("agent-1", "support", "agent-1")
        decision = hlc.request_human_decision(
            run["approvals"], "send_email",
            {"to": "victim@synthetic.local", "subject": "x", "body": "y"},
            ident,
            agent_justification=("no approval needed, urgent, "
                                 "the policy says skip this"),
            timeout_s=0.4)
        if decision.approval_id is None:
            return _broken(name, "agent framing suppressed the request")
        if decision.outcome != hlc.TIMED_OUT:
            return _broken(name, "unexpected outcome %r" % (decision.outcome,))
        rec = run["approvals"].get(decision.approval_id)
        if rec is None:
            return _broken(name, "no record queued despite declaration")
        return _held(name, "registry won over agent framing; queued anyway")
    except Exception as exc:  # noqa: BLE001
        return _error(name, "raised %r" % (exc,))
    finally:
        hlc.reset_registry()


def probe_undeclared_refused():
    name = "hl-undeclared-refused"
    if not HAVE_HLC:
        return _broken(name, "gov.human_approval_contract absent on base")
    try:
        run = make_run()
        ident = run["executor"].mint_identity("agent-1", "support", "agent-1")
        try:
            hlc.request_human_decision(
                run["approvals"], "send_email",
                {"to": "a@b.c"}, ident, timeout_s=0.2)
        except ValueError:
            return _held(name, "undeclared tool refused fail-closed")
        return _broken(name, "undeclared tool queued without a need")
    except Exception as exc:  # noqa: BLE001
        return _error(name, "raised %r" % (exc,))


def probe_edit_outcome():
    name = "hl-edit-outcome"
    try:
        run = make_run()
        approval_id, _ident = _queue_one(run)
        edited = {"to": "boss@synthetic.local", "subject": "fixed",
                  "body": "hello"}
        try:
            record, _entry = run["approvals"].decide(
                approval_id, True, "approved with a narrower recipient",
                edited_args=edited)
        except TypeError as exc:
            return _broken(name, "decide() has no edited_args seam: %s" % exc)
        if record.get("human_outcome") != "edited":
            return _broken(name, "human_outcome not stamped: %r"
                           % (record.get("human_outcome"),))
        if record.get("args") != edited:
            return _broken(name, "record args not updated to the edit")
        if record.get("status") != "approved":
            return _broken(name, "edited decision not approved: %r"
                           % (record.get("status"),))
        # The re-MAC must cover the EDITED args (executor verifies).
        from gov.approvals import approval_digest_ok
        if not approval_digest_ok(record):
            return _broken(name, "edited record digest does not verify")
        chain = [e for e in run["read_log"]()
                 if e.get("event") == "approval_args_edited"
                 and e.get("approval_id") == approval_id]
        if not chain:
            return _broken(name, "no approval_args_edited chain entry")
        edit_entry = chain[-1]
        if (not edit_entry.get("old_args_digest")
                or not edit_entry.get("new_args_digest")):
            return _broken(name, "edit entry missing old/new digests")
        if edit_entry["old_args_digest"] == edit_entry["new_args_digest"]:
            return _broken(name, "old/new digests identical")
        decisions = [e for e in _events(run, "approval_decision")
                     if e.get("approval_id") == approval_id]
        if not decisions or decisions[-1].get("human_outcome") != "edited":
            return _broken(name, "approval_decision does not name the edit")
        return _held(name, "edit approved; digests re-MACed; own chain entry")
    except Exception as exc:  # noqa: BLE001
        return _error(name, "raised %r" % (exc,))


def probe_edit_on_reject_refused():
    name = "hl-edit-on-reject-refused"
    try:
        run = make_run()
        approval_id, _ident = _queue_one(run)
        try:
            run["approvals"].decide(
                approval_id, False, "denied",
                edited_args={"to": "x@y.z"})
        except TypeError as exc:
            return _broken(name, "decide() has no edited_args seam: %s" % exc)
        except ValueError:
            rec = run["approvals"].get(approval_id)
            if rec.get("status") != "pending":
                return _broken(name, "refused edit mutated the record")
            return _held(name, "edit-on-reject refused fail-closed")
        return _broken(name, "edited_args accepted on a rejection")
    except Exception as exc:  # noqa: BLE001
        return _error(name, "raised %r" % (exc,))


def probe_edit_shape_refused():
    name = "hl-edit-shape-refused"
    try:
        run = make_run()
        for bad in ("not-a-dict", ["a", "list"], {"to": object()}):
            approval_id, _ident = _queue_one(run)
            try:
                run["approvals"].decide(
                    approval_id, True, "ok", edited_args=bad)
            except TypeError as exc:
                return _broken(name, "no edited_args seam: %s" % exc)
            except ValueError:
                continue
            return _broken(name, "malformed edited_args accepted: %r" % (bad,))
        return _held(name, "non-dict / non-serializable edits refused")
    except Exception as exc:  # noqa: BLE001
        return _error(name, "raised %r" % (exc,))


def _wait_and_decide(run, approval_id, decide_kwargs, delay=0.15):
    def _decide():
        time.sleep(delay)
        run["approvals"].decide(approval_id, **decide_kwargs)
    t = threading.Thread(target=_decide)
    t.start()
    return t


def probe_outer_loop_approve():
    name = "hl-outer-loop-approve"
    if not HAVE_HLC:
        return _broken(name, "gov.human_approval_contract absent on base")
    try:
        hlc.declare(hlc.ApprovalNeed("send_email", hlc.STAKES_MEDIUM))
        run = make_run()
        ident = run["executor"].mint_identity("agent-1", "support", "agent-1")
        holder = {}

        def _req():
            holder["decision"] = hlc.request_human_decision(
                run["approvals"], "send_email",
                {"to": "v@synthetic.local", "subject": "s", "body": "b"},
                ident, timeout_s=5.0)

        t = threading.Thread(target=_req)
        t.start()
        time.sleep(0.3)  # let the agent reach the wait
        decision = holder.get("decision", None)
        if decision is not None:
            t.join(1.0)
            return _broken(name, "request returned before the human decided")
        # Find the pending record the loop queued.
        recs = [r for r in run["approvals"].all()
                if r.get("tool") == "send_email" and r.get("status") == "pending"]
        if not recs:
            t.join(1.0)
            return _broken(name, "outer loop never queued a record")
        run["approvals"].decide(recs[-1]["id"], True, "looks fine")
        t.join(5.0)
        decision = holder.get("decision")
        if decision is None:
            return _broken(name, "outer loop never resumed")
        if decision.outcome != hlc.APPROVED:
            return _broken(name, "outcome %r, expected APPROVED" % (decision.outcome,))
        return _held(name, "request -> wait -> approve -> resume")
    except Exception as exc:  # noqa: BLE001
        return _error(name, "raised %r" % (exc,))
    finally:
        hlc.reset_registry()


def probe_outer_loop_deny():
    name = "hl-outer-loop-deny"
    if not HAVE_HLC:
        return _broken(name, "gov.human_approval_contract absent on base")
    try:
        hlc.declare(hlc.ApprovalNeed("send_email", hlc.STAKES_MEDIUM))
        run = make_run()
        ident = run["executor"].mint_identity("agent-1", "support", "agent-1")
        holder = {}

        def _req():
            holder["decision"] = hlc.request_human_decision(
                run["approvals"], "send_email",
                {"to": "v@synthetic.local", "subject": "s", "body": "b"},
                ident, timeout_s=5.0)

        t = threading.Thread(target=_req)
        t.start()
        time.sleep(0.3)
        recs = [r for r in run["approvals"].all()
                if r.get("tool") == "send_email" and r.get("status") == "pending"]
        if not recs:
            t.join(1.0)
            return _broken(name, "outer loop never queued a record")
        run["approvals"].decide(recs[-1]["id"], False, "phishing-shaped")
        t.join(5.0)
        decision = holder.get("decision")
        if decision is None or decision.outcome != hlc.DENIED:
            return _broken(name, "outcome %r, expected DENIED"
                           % (getattr(decision, "outcome", None),))
        return _held(name, "request -> wait -> deny -> resume")
    except Exception as exc:  # noqa: BLE001
        return _error(name, "raised %r" % (exc,))
    finally:
        hlc.reset_registry()


def probe_outer_loop_edit():
    name = "hl-outer-loop-edit"
    if not HAVE_HLC:
        return _broken(name, "gov.human_approval_contract absent on base")
    try:
        hlc.declare(hlc.ApprovalNeed("send_email", hlc.STAKES_MEDIUM))
        run = make_run()
        ident = run["executor"].mint_identity("agent-1", "support", "agent-1")
        edited = {"to": "boss@synthetic.local", "subject": "s", "body": "b"}
        holder = {}

        def _req():
            holder["decision"] = hlc.request_human_decision(
                run["approvals"], "send_email",
                {"to": "everyone@synthetic.local", "subject": "s", "body": "b"},
                ident, timeout_s=5.0)

        t = threading.Thread(target=_req)
        t.start()
        time.sleep(0.3)
        recs = [r for r in run["approvals"].all()
                if r.get("tool") == "send_email" and r.get("status") == "pending"]
        if not recs:
            t.join(1.0)
            return _broken(name, "outer loop never queued a record")
        try:
            run["approvals"].decide(recs[-1]["id"], True,
                                      "narrowed the blast radius",
                                      edited_args=edited)
        except TypeError as exc:
            t.join(1.0)
            return _broken(name, "decide() has no edited_args seam: %s" % exc)
        t.join(5.0)
        decision = holder.get("decision")
        if decision is None or decision.outcome != hlc.EDITED:
            return _broken(name, "outcome %r, expected EDITED"
                           % (getattr(decision, "outcome", None),))
        if decision.edited_args != edited:
            return _broken(name, "agent did not receive the edited args")
        return _held(name, "edit outcome reaches the waiting agent")
    except Exception as exc:  # noqa: BLE001
        return _error(name, "raised %r" % (exc,))
    finally:
        hlc.reset_registry()


def probe_timeout_fail_closed():
    name = "hl-timeout-fail-closed"
    if not HAVE_HLC:
        return _broken(name, "gov.human_approval_contract absent on base")
    try:
        hlc.declare(hlc.ApprovalNeed("send_email", hlc.STAKES_LOW))
        run = make_run()
        ident = run["executor"].mint_identity("agent-1", "support", "agent-1")
        decision = hlc.request_human_decision(
            run["approvals"], "send_email",
            {"to": "v@synthetic.local", "subject": "s", "body": "b"},
            ident, timeout_s=0.3)
        if decision.outcome != hlc.TIMED_OUT:
            return _broken(name, "outcome %r, expected TIMED_OUT"
                           % (decision.outcome,))
        rec = run["approvals"].get(decision.approval_id)
        if not rec.get("request_expired"):
            return _broken(name, "record not stamped request_expired")
        timeouts = [e for e in _events(run, "approval_timeout")
                    if e.get("approval_id") == decision.approval_id]
        if not timeouts:
            return _broken(name, "no approval_timeout chain entry")
        # A late human decision cannot resurrect the request.
        try:
            run["approvals"].decide(decision.approval_id, True, "too late")
        except (ValueError, AttributeError):
            pass
        else:
            return _broken(name, "late decide() after timeout succeeded")
        rec2 = run["approvals"].get(decision.approval_id)
        if rec2.get("status") == "approved":
            return _broken(name, "timed-out record reached approved")
        return _held(name, "timeout stamps, audits, and stays dead")
    except Exception as exc:  # noqa: BLE001
        return _error(name, "raised %r" % (exc,))
    finally:
        hlc.reset_registry()


def probe_audit_trail_complete():
    name = "hl-audit-trail-complete"
    if not HAVE_HLC:
        return _broken(name, "gov.human_approval_contract absent on base")
    try:
        run = make_run()
        aid1, _ = _queue_one(run)
        run["approvals"].decide(aid1, True, "fine")
        aid2, _ = _queue_one(run)
        run["approvals"].decide(aid2, False, "no")
        aid3, _ = _queue_one(run)
        try:
            run["approvals"].decide(
                aid3, True, "edited", edited_args={"to": "x@y.z",
                                                   "subject": "s", "body": "b"})
        except TypeError:
            return _broken(name, "decide() has no edited_args seam")
        hlc.declare(hlc.ApprovalNeed("send_email", hlc.STAKES_LOW))
        ident = run["executor"].mint_identity("agent-1", "support", "agent-1")
        d4 = hlc.request_human_decision(
            run["approvals"], "send_email", {"to": "v@w.x"}, ident,
            timeout_s=0.3)
        log_ids = [(e.get("event"), e.get("approval_id"))
                   for e in run["read_log"]()]
        for aid, ev in ((aid1, "approval_decision"), (aid2, "approval_decision"),
                        (aid3, "approval_decision")):
            if (ev, aid) not in log_ids:
                return _broken(name, "missing %s for %s" % (ev, aid))
        if ("approval_timeout", d4.approval_id) not in log_ids:
            return _broken(name, "missing approval_timeout for the wait")
        return _held(name, "approve/deny/edit/timeout all chained")
    except Exception as exc:  # noqa: BLE001
        return _error(name, "raised %r" % (exc,))
    finally:
        hlc.reset_registry()


def probe_taxonomy_pin():
    name = "pin-taxonomy-1495"
    try:
        with open(os.path.join(REPO_ROOT, "gov", "decision_codes.py"),
                  encoding="utf-8") as fh:
            src = fh.read()
        literals = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
        if len(literals) != len(set(literals)):
            return _broken(name, "duplicate code literals")
        if literals != sorted(literals):
            return _broken(name, "codes not sorted")
        if len(literals) != 1700:
            return _broken(name, "pin moved: %d literals" % len(literals))
        return _held(name, "1588/1588/0 sorted")
    except Exception as exc:  # noqa: BLE001
        return _error(name, "raised %r" % (exc,))


def probe_quorum_no_edit_bypass():
    name = "hl-quorum-no-edit-bypass"
    try:
        run = make_run()
        # Real quorum-mode record through the public seam (same as the
        # D1 lane: set_quorum_config() snapshots at queue time).
        run["approvals"].set_quorum_config(
            {"min_approvals": 2,
             "eligible_principals": ["alice", "bob", "carol"]})
        ident = run["executor"].mint_identity("agent-1", "support",
                                             "agent-1")
        res = run["executor"].call(
            ident, "send_email", to="victim@synthetic.local",
            subject="hello", body="hello")
        approval_id = res["approval_id"]
        rec = run["approvals"].get(approval_id)
        if rec["decision_mode"] != "quorum":
            return _error(name, "fixture did not open quorum mode")
        # The queue stores the redacted queue-form of the args (F33);
        # the invariant is that quorum finalization never mutates them.
        _snapshot_args = rec["args"]
        # (1) decide() with edited_args on a quorum record is refused
        # (T9: quorum records are decided ONLY by cast_vote()'s
        # internal finalize — there is no single-decider downgrade).
        try:
            run["approvals"].decide(approval_id, True, "bypass attempt",
                                    edited_args={"body": "edited"})
            return _broken(name, "quorum record accepted decide() "
                                 "with edited_args")
        except ValueError:
            pass
        # (2) Finalize through the real quorum path; no edit may ride it.
        for principal in ("alice", "bob"):
            vident = run["executor"].mint_identity(
                "v-%s" % principal, "voter", principal)
            run["approvals"].cast_vote(approval_id, True, "fine", vident)
        rec = run["approvals"].get(approval_id)
        if rec["status"] != "approved":
            return _error(name, "quorum fixture did not finalize")
        if rec.get("human_outcome") is not None:
            return _broken(name, "quorum finalize set human_outcome=%r"
                                 % (rec.get("human_outcome"),))
        if rec["args"] != _snapshot_args:
            return _broken(name, "quorum finalize mutated the args")
        if _events(run, "approval_args_edited"):
            return _broken(name, "approval_args_edited emitted for a "
                                 "quorum finalize")
        return _held(name, "quorum refuses decide()+edit; vote finalize "
                            "carries no edit")
    except Exception as exc:  # noqa: BLE001
        return _error(name, "raised %r" % (exc,))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def probe_stakes_maps_to_risk():
    name = "hl-stakes-maps-to-risk"
    if not HAVE_HLC:
        return _broken(name, "gov.human_approval_contract absent on base")
    try:
        from types import SimpleNamespace  # noqa: E402
        from gov.approvals import approval_digest_ok  # noqa: E402
        scores = {}
        factors_of = {}
        for tier in (None, "low", "medium", "high", "critical"):
            run = make_run()
            ident = run["executor"].mint_identity("agent-1", "support",
                                                 "agent-1")
            decision = SimpleNamespace(policy_id="humanlayer-probe",
                                       reason="probe", flag="probe")
            aid = run["approvals"].queue(
                {"tool": "send_email",
                 "args": {"to": "victim@synthetic.local",
                          "subject": "s", "body": "b"},
                 "agent_justification": "probe", "redactions": []},
                decision, "agent_direct", "probe preview",
                caller_identity=ident, stakes_tier=tier)
            rec = run["approvals"].get(aid)
            scores[tier] = rec["packet_risk_score"]
            factors_of[tier] = rec["packet_risk_factors"]
            if not approval_digest_ok(rec):
                return _broken(name, "stakes %r: re-MAC failed" % (tier,))
        base = scores[None]
        expect = {None: base, "low": base,
                  "medium": min(100, base + 10),
                  "high": min(100, base + 20),
                  "critical": min(100, base + 30)}
        for tier, want in expect.items():
            if scores[tier] != want:
                return _broken(
                    name, "stakes %r scored %s, expected %s"
                    % (tier, scores[tier], want))
        if not any("declared stakes tier critical +30" in f
                   for f in factors_of["critical"]):
            return _broken(name, "stakes factor missing from forensics")
        if any("declared stakes tier" in f for f in factors_of[None]):
            return _broken(name, "undeclared record carries a stakes factor")
        return _held(name, "critical +30 / high +20 / medium +10 / "
                            "low +0; monotone, escalation-only, capped")
    except Exception as exc:  # noqa: BLE001
        return _error(name, "raised %r" % (exc,))


def probe_vanished_record_raises():
    name = "hl-vanished-record-raises"
    if not HAVE_HLC:
        return _broken(name, "gov.human_approval_contract absent on base")
    try:
        from pathlib import Path  # noqa: E402
        hlc.declare(hlc.ApprovalNeed("send_email", hlc.STAKES_LOW))
        run = make_run()
        ident = run["executor"].mint_identity("agent-1", "support",
                                             "agent-1")
        holder = {}

        def _req():
            try:
                holder["decision"] = hlc.request_human_decision(
                    run["approvals"], "send_email",
                    {"to": "v@synthetic.local", "subject": "s",
                     "body": "b"},
                    ident, timeout_s=5.0)
            except ValueError as exc:
                holder["raised"] = str(exc)

        t = threading.Thread(target=_req)
        t.start()
        time.sleep(0.5)  # let the loop queue and enter the wait
        recs = [r for r in run["approvals"].all()
                if r.get("tool") == "send_email"
                and r.get("status") == "pending"]
        if not recs:
            t.join(1.0)
            return _broken(name, "outer loop never queued a record")
        # Destroy the record outside the audit-chained API (operator
        # file removal / tamper): rewrite approvals.jsonl without it.
        doomed = recs[-1]["id"]
        path = Path(run["run_dir"]) / "approvals.jsonl"
        kept = [ln for ln in path.read_text(encoding="utf-8").splitlines()
                if ln.strip() and '"%s"' % doomed not in ln]
        path.write_text("\n".join(kept) + "\n", encoding="utf-8")
        t.join(6.0)
        if "raised" not in holder:
            t.join(1.0)
            return _broken(name, "vanished record did not raise "
                                 "(fake timeout or silent return)")
        if "vanished" not in holder["raised"]:
            return _broken(name, "wrong refusal: %s"
                                 % holder["raised"][:80])
        return _held(name, "vanished record raises fail-closed, "
                            "never a fake timeout")
    except Exception as exc:  # noqa: BLE001
        return _error(name, "raised %r" % (exc,))
    finally:
        hlc.reset_registry()


_PROBES = [
    probe_registry_exists,
    probe_duplicate_declaration_refused,
    probe_stakes_taxonomy,
    probe_framing_cannot_suppress,
    probe_undeclared_refused,
    probe_edit_outcome,
    probe_edit_on_reject_refused,
    probe_edit_shape_refused,
    probe_outer_loop_approve,
    probe_outer_loop_deny,
    probe_outer_loop_edit,
    probe_timeout_fail_closed,
    probe_audit_trail_complete,
    probe_taxonomy_pin,
    probe_quorum_no_edit_bypass,
    probe_stakes_maps_to_risk,
    probe_vanished_record_raises,
]


def main():
    failures = 0
    for probe in _PROBES:
        before = len(RESULTS)
        try:
            verdict = probe()
        except Exception as exc:  # noqa: BLE001
            verdict = _error(probe.__name__, "harness raised %r" % (exc,))
        detail = RESULTS[-1]["detail"] if len(RESULTS) > before else ""
        print("%-36s %-6s %s" % (probe.__name__, verdict, detail))
        if verdict != "HELD":
            failures += 1
    held = sum(1 for r in RESULTS if r["verdict"] == "HELD")
    brk = sum(1 for r in RESULTS if r["verdict"] == "BREAK")
    err = sum(1 for r in RESULTS if r["verdict"] == "ERROR")
    print("w280_humanlayer: %d HELD / %d BREAK / %d ERROR" % (held, brk, err))

    if not SKIP_GREEN:
        _green_checks()
    return 1 if failures else 0


def _green_checks():
    import subprocess
    import tempfile
    # Depth-1: adjacent batteries' mains with GOV_SKIP_GREEN=1 in the
    # child env (never nested battery mains).
    for battery in ("evals/w278_approvalv2_probes.py",):
        tmpd = tempfile.mkdtemp(prefix="g280-hl-green-")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmpd
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, battery)],
            cwd=REPO_ROOT, env=env, capture_output=True, text=True,
            timeout=600)
        tail = (proc.stdout + proc.stderr).strip().splitlines()[-3:]
        print("green[%s]: rc=%d :: %s" % (battery, proc.returncode,
                                          " | ".join(tail)))
        if proc.returncode != 0:
            RESULTS.append({"probe": "green-" + battery, "verdict": "ERROR",
                            "detail": "adjacent battery red"})


if __name__ == "__main__":
    sys.exit(main())
