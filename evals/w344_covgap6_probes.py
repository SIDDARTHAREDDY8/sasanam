#!/usr/bin/env python3
"""Wave-344 lane 3 battery: decision-code coverage campaign, round 6.

Round 5 (wave-343 lane 2) moved the coverage table from 2111/2131 to
2111/2131 with pin 2131, and the wave-343 merge reconciled it to
2114/2135 (20 gaps: 5 fault-injection + 15 not-yet-covered). This
battery asserts the 15 coverable residuals with real behavioral probes
(the hostile/malformed input is driven through the public seam and the
coded refusal is asserted), never tautologies. Each family carries a
discrimination control proving the probe distinguishes honest from
hostile input.

  A  release approval (2): compute_candidate, propose_release
  B  eval-task registry (2): evaltask-not-json, evaltask-bad-scoring-refs
  C  battery language (1): battery-lang-bad-metadata
  D  delegation tokens (1): hop_token_refs
  E  journal recovery (2): recover_torn_tail (no-journal, clean-journal)
  F  tool ratings (1): tool_ratings
  G  absence attestation (1): attest_absence
  H  lineage (2): clear_cross_run_lineage (no-root, no-principal)
  I  detection (1): identity_key_of
  J  provenance verifier (1): input_closure_digest
  K  quorum policy (2): canonical_link_body, make_link_record
  L  egress launcher (1): spawn_failed
  P0 pin/taxonomy honesty (2135/2135/0 sorted-unique, footer state).
  PZ green check (depth-1): adjacent suites as children with
     GOV_SKIP_GREEN=1.

Base: 1a800558 (wave-343 merge). Pin 2135, footer open F436 / next F437.

No gov/ changes in this lane. Findings: none filed (all
probes HELD on the base; a genuine BREAK would be filed as F432+).

RESIDUAL GAPS (5, documented, not probed -- each resists a clean
deterministic battery probe):
  - tool-crashed, tool-timed-out: need a full GrantDispatcher
    sandboxed child (a battery cannot deterministically crash or hang
    the sandbox child).
  - preexec_child_died: fault injection (kill the child between fork
    and the preexec ack).
  - post-rotation: needs a valid TUF root plus a live fetcher.
  - offline-verify-internal: crash-backstop; fault injection by
    design (verifies the verifier notices its own corruption).
"""

import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import types

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

PIN = 2135  #Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
FOOTER_OPEN = ("F443",)  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444)
FOOTER_NEXT = "F444"  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444)

_results = []
_EXPECTED_BREAKS = set()  # empty set, never {} (dict) -- wave-331 lesson


def _held(pid, note):
    _results.append((pid, "HELD", note))


def _break(pid, note):
    _results.append((pid, "BREAK", note))


def _error(pid, note):
    _results.append((pid, "ERROR", note))


def _code_of(exc):
    """Extract the coded refusal from the exception, or None."""
    for attr in ("code", "reason", "refusal_cause"):
        val = getattr(exc, attr, None)
        if isinstance(val, str) and val:
            return val
    msg = str(exc)
    m = re.match(r"^([\w.\-]+):", msg)
    if m:
        return m.group(1)
    m = re.search(r"\(([\w.\-]+)\)", msg)
    if m:
        return m.group(1)
    head = msg.split(":", 1)[0].strip()
    if head and all(c.islower() or c.isdigit() or c in "-_." for c in head):
        return head
    return None


def _mk_tmp():
    d = tempfile.mkdtemp(prefix="g344cov6-",
                         dir=os.environ.get("TMPDIR", "/var/tmp"))
    return d


# ---------------------------------------------------------------------------
# P0: pin / taxonomy honesty + footer state
# ---------------------------------------------------------------------------

def p0():
    from gov import decision_codes as dc
    codes = sorted(dc.TAXONOMY.keys())
    if len(codes) != PIN:
        _break("P0-pin", "registry has %d codes, want %d" % (len(codes), PIN))
        return
    raw = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r"\"code\":\s*'([\w.\-]+)'", raw)
    if len(lits) != PIN or len(set(lits)) != PIN:
        _break("P0-unique", "raw-literal uniqueness broken: %d/%d"
               % (len(set(lits)), len(lits)))
        return
    if lits != sorted(lits):
        _break("P0-sorted", "taxonomy source literals not sorted")
        return
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    want_open = "Open findings: %s." % ", ".join(FOOTER_OPEN)
    want_next = "Next free finding: **%s**." % FOOTER_NEXT
    if want_open in text and want_next in text:
        _held("P0-footer", "pin %d/%d/0 sorted-unique; footer %s / next %s"
              % (PIN, PIN, ",".join(FOOTER_OPEN), FOOTER_NEXT))
    else:
        _break("P0-footer", "footer mismatch: want %r / %r" % (want_open,
                                                               want_next))
    if 'COVERAGE_PIN = %d' % PIN not in open(
            os.path.join(REPO, "scripts",
                         "check_decision_code_coverage.py")).read():
        _break("P0-checkerpin", "coverage checker pin drifted from %d" % PIN)
    else:
        _held("P0-checkerpin", "coverage checker pins %d" % PIN)


# ---------------------------------------------------------------------------
# A: release approval -- compute_candidate, propose_release
# ---------------------------------------------------------------------------

def fa():
    from gov import release_approval as ra

    # A1: compute_candidate -- missing eval evidence / SAR refuses coded.
    tmp = _mk_tmp()
    try:
        ra.compute_candidate(tmp, os.path.join(tmp, "no-eval.json"),
                             os.path.join(tmp, "no-sar.pdf"),
                             release_id="r1")
        _break("A1", "compute_candidate with missing evidence did not raise")
    except ValueError as e:
        if _code_of(e) == "compute_candidate":
            _held("A1", "compute_candidate refuses coded on missing evidence")
        else:
            _break("A1", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("A1", "%s: %s" % (type(e).__name__, e))
    # Discrimination: with real files the candidate digests compute.
    evalp = os.path.join(tmp, "eval.json")
    sarp = os.path.join(tmp, "sar.pdf")
    open(evalp, "w").write("{}")
    open(sarp, "w").write("sar")
    open(os.path.join(tmp, "code.py"), "w").write("x=1\n")
    try:
        c1 = ra.compute_candidate(tmp, evalp, sarp, release_id="r1")
        c2 = ra.compute_candidate(tmp, evalp, sarp, release_id="r1")
        if (set(c1) == {"tree_digest", "eval_results_digest", "sar_digest",
                        "release_id", "release_digest"} and c1 == c2):
            _held("A1-disc", "honest candidate computes deterministically "
                  "(not vacuous)")
        else:
            _break("A1-disc", "candidate shape unstable: %r" % (c1,))
    except Exception as e:
        _break("A1-disc", "honest candidate failed: %s: %s"
               % (type(e).__name__, e))

    # A2: propose_release -- single-party quorum refused coded.
    try:
        ra.propose_release(None, None, code_dir=tmp,
                           eval_results_path=evalp, sar_path=sarp,
                           release_id="r1", min_approvals=1)
        _break("A2", "propose_release with min_approvals=1 did not raise")
    except ValueError as e:
        if _code_of(e) == "propose_release":
            _held("A2", "propose_release refuses coded on single-party "
                  "quorum")
        else:
            _break("A2", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("A2", "%s: %s" % (type(e).__name__, e))
    # Discrimination: min_approvals=2 passes the quorum guard and reaches
    # the candidate computation (a DIFFERENT refusal on bad paths).
    try:
        ra.propose_release(None, None, code_dir=tmp,
                           eval_results_path=os.path.join(tmp, "missing.json"),
                           sar_path=sarp, release_id="r1", min_approvals=2)
        _break("A2-disc", "expected the compute_candidate refusal, got none")
    except ValueError as e:
        if _code_of(e) == "compute_candidate":
            _held("A2-disc", "quorum guard passes; failure moves to the "
                  "candidate layer (distinct code)")
        else:
            _break("A2-disc", "wrong downstream code: %r" % _code_of(e))
    except Exception as e:
        _error("A2-disc", "%s: %s" % (type(e).__name__, e))


# ---------------------------------------------------------------------------
# B: eval-task registry -- evaltask-not-json, evaltask-bad-scoring-refs
# ---------------------------------------------------------------------------

def fb():
    from gov import eval_tasks as et

    def _reg():
        reg = et.EvalTaskRegistry()
        reg.register_dataset("ds", [{"q": "a", "want": "A"}])
        reg.register_scoring_function("exact", lambda s, o: 1.0)
        return reg

    # B1: evaltask-not-json -- non-JSON-serializable run_config refused.
    reg = _reg()
    try:
        reg.register_eval_task("t1", dataset_id="ds", scoring_ids=["exact"],
                               run_config={"bad": {1, 2}})
        _break("B1", "non-JSON run_config did not refuse")
    except et.EvalTaskError as e:
        if _code_of(e) == "evaltask-not-json":
            _held("B1", "evaltask-not-json refuses coded")
        else:
            _break("B1", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("B1", "%s: %s" % (type(e).__name__, e))
    # Discrimination: JSON-native run_config registers.
    try:
        reg.register_eval_task("t1ok", dataset_id="ds",
                               scoring_ids=["exact"],
                               run_config={"temperature": 0})
        _held("B1-disc", "JSON-native run_config registers (not vacuous)")
    except Exception as e:
        _break("B1-disc", "honest registration failed: %s" % e)

    # B2: evaltask-bad-scoring-refs -- empty scoring_ids refused.
    reg2 = _reg()
    try:
        reg2.register_eval_task("t2", dataset_id="ds", scoring_ids=[])
        _break("B2", "empty scoring_ids did not refuse")
    except et.EvalTaskError as e:
        if _code_of(e) == "evaltask-bad-scoring-refs":
            _held("B2", "evaltask-bad-scoring-refs refuses coded")
        else:
            _break("B2", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("B2", "%s: %s" % (type(e).__name__, e))
    # Discrimination: unknown scoring id gives a DIFFERENT coded refusal.
    try:
        reg2.register_eval_task("t3", dataset_id="ds",
                                scoring_ids=["no-such-scorer"])
        _break("B2-disc", "unknown scorer did not refuse")
    except et.EvalTaskError as e:
        if _code_of(e) == "evaltask-unknown-scoring-function":
            _held("B2-disc", "unknown scorer refuses under its own code "
                  "(distinct)")
        else:
            _break("B2-disc", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("B2-disc", "%s: %s" % (type(e).__name__, e))


# ---------------------------------------------------------------------------
# C: battery language -- battery-lang-bad-metadata
# ---------------------------------------------------------------------------

def fc():
    from gov import battery_lang

    # C1: malformed PROBE_METADATA entry (not a 3-tuple) refuses coded.
    mod = types.ModuleType("w344mod_badmeta")
    mod.PROBE_METADATA = {"p1": ("plugin-a", "strategy-b")}  # 2-tuple
    try:
        battery_lang.resolve_metadata(mod)
        _break("C1", "bad metadata did not refuse")
    except battery_lang.BatteryLanguageError as e:
        if _code_of(e) == "battery-lang-bad-metadata":
            _held("C1", "battery-lang-bad-metadata refuses coded")
        else:
            _break("C1", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("C1", "%s: %s" % (type(e).__name__, e))
    # Discrimination: well-formed metadata resolves.
    mod2 = types.ModuleType("w344mod_okmeta")
    mod2.PROBE_METADATA = {
        "p1": (next(iter(battery_lang.PLUGINS)),
               next(iter(battery_lang.STRATEGIES)),
               next(iter(battery_lang.GRADERS))),
    }
    try:
        resolved = battery_lang.resolve_metadata(mod2)
        if set(resolved) == {"p1"}:
            _held("C1-disc", "well-formed metadata resolves (not vacuous)")
        else:
            _break("C1-disc", "unexpected resolution: %r" % (resolved,))
    except Exception as e:
        _break("C1-disc", "honest metadata failed: %s" % e)


# ---------------------------------------------------------------------------
# D: delegation tokens -- hop_token_refs
# ---------------------------------------------------------------------------

def fd():
    from gov import delegation_tokens as dt

    keys = dt.generate_test_keypair()
    idp = dt.generate_test_keypair()
    authority = dt.generate_test_keypair()
    human = dt.generate_test_keypair()
    session = "sess-test"
    user_tok = dt.issue_user_token(idp[0], "user-7",
                                   ("tool:read_file",), session, ttl_s=3600)
    agent_tok = dt.issue_agent_token(authority[0], "agent-1", "scout",
                                     "user-7", ("tool:read_file",),
                                     session, ttl_s=3600)
    deleg_tok = dt.issue_delegation(human[0], "user-7", user_tok, agent_tok,
                                    ("tool:read_file",), session,
                                    "urn:revoke:test", ttl_s=3600)
    # D1: a token of the wrong kind in the hop refuses coded.
    bad = dict(deleg_tok)
    bad["token_kind"] = "agent"
    try:
        dt.hop_token_refs(user_tok, agent_tok, bad)
        _break("D1", "wrong-kind token did not refuse")
    except ValueError as e:
        if _code_of(e) == "hop_token_refs":
            _held("D1", "hop_token_refs refuses coded on kind mismatch")
        else:
            _break("D1", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("D1", "%s: %s" % (type(e).__name__, e))
    # Discrimination: the honest trio binds to refs, never secrets.
    try:
        refs = dt.hop_token_refs(user_tok, agent_tok, deleg_tok)
        blob = str(refs)
        leaked = any(t.get("sig") and t["sig"] in blob
                     for t in (user_tok, agent_tok, deleg_tok))
        if (refs["user_token_ref"] == dt.token_ref(user_tok)
                and refs["tokens_schema"] == dt.TOKENS_SCHEMA
                and not leaked):
            _held("D1-disc", "honest trio binds refs without leaking sigs")
        else:
            _break("D1-disc", "refs malformed: %r" % (refs,))
    except Exception as e:
        _break("D1-disc", "honest trio failed: %s" % e)


# ---------------------------------------------------------------------------
# E: journal recovery -- recover_torn_tail
# ---------------------------------------------------------------------------

def fe():
    from gov import durable_journal as dj

    tmp = _mk_tmp()
    # E1: no journal at the path refuses coded.
    try:
        dj.recover_torn_tail(os.path.join(tmp, "no-journal-here.jsonl"))
        _break("E1", "missing journal did not refuse")
    except ValueError as e:
        if _code_of(e) == "recover_torn_tail":
            _held("E1", "recover_torn_tail refuses coded on missing journal")
        else:
            _break("E1", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("E1", "%s: %s" % (type(e).__name__, e))
    # E2: a clean journal refuses with the SAME code (nothing to recover)
    # -- the operator path is loud, never a silent no-op.
    clean = os.path.join(tmp, "clean.jsonl")
    j = dj.Journal(clean)
    j.append("W", {"worker": 1})
    try:
        dj.recover_torn_tail(clean)
        _break("E2", "clean journal recovery did not refuse")
    except ValueError as e:
        if _code_of(e) == "recover_torn_tail":
            _held("E2", "clean journal refuses coded (no silent no-op)")
        else:
            _break("E2", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("E2", "%s: %s" % (type(e).__name__, e))


# ---------------------------------------------------------------------------
# F: tool ratings -- tool_ratings
# ---------------------------------------------------------------------------

def ff():
    from gov import tool_ratings as tr

    # F1: a non-mapping deployment rating refuses coded. The refusal is
    # prose-form (message starts with the code literal, no "code: detail"
    # colon), so the code is asserted by literal prefix, not _code_of.
    try:
        tr.normalize_tool_ratings("not-a-mapping")
        _break("F1", "non-mapping ratings did not refuse")
    except ValueError as e:
        if str(e).startswith("tool_ratings"):
            _held("F1", "tool_ratings refuses coded on non-mapping")
        else:
            _break("F1", "wrong message: %r" % (str(e)[:80],))
    except Exception as e:
        _error("F1", "%s: %s" % (type(e).__name__, e))
    # Discrimination: None (no deployment overrides) merges cleanly.
    try:
        merged = tr.normalize_tool_ratings(None)
        if isinstance(merged, dict) and merged:
            _held("F1-disc", "None deployment merges to defaults "
                  "(not vacuous)")
        else:
            _break("F1-disc", "unexpected merge result")
    except Exception as e:
        _break("F1-disc", "honest merge failed: %s" % e)


# ---------------------------------------------------------------------------
# G: absence attestation -- attest_absence
# ---------------------------------------------------------------------------

def fg():
    from gov import absence as ab

    seed = os.urandom(32)
    issuer = ab.AbsenceIssuer("issuer-1", seed)
    # G1: empty subject digest refuses coded.
    try:
        issuer.attest_absence("")
        _break("G1", "empty subject_digest did not refuse")
    except ValueError as e:
        if _code_of(e) == "attest_absence":
            _held("G1", "attest_absence refuses coded on empty digest")
        else:
            _break("G1", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("G1", "%s: %s" % (type(e).__name__, e))
    # Discrimination: a real digest attests a signed negative outcome.
    try:
        neg = issuer.attest_absence("ab" * 32)
        if isinstance(neg, dict) and neg.get("claim") == "never-advertised":
            _held("G1-disc", "honest attestation signs never-advertised "
                  "(not vacuous)")
        else:
            _break("G1-disc", "unexpected negative: %r" % (neg,))
    except Exception as e:
        _break("G1-disc", "honest attestation failed: %s" % e)


# ---------------------------------------------------------------------------
# H: lineage -- clear_cross_run_lineage
# ---------------------------------------------------------------------------

def fh():
    from gov import lineage as ln

    class _StubLog(object):
        def __init__(self):
            self.events = []

        def append(self, entry):
            self.events.append(entry)
            return {"seq": len(self.events) - 1}

    run_dir = os.path.join(_mk_tmp(), "run")
    os.makedirs(run_dir)
    tracker = ln.LineageTracker(run_dir, _StubLog())
    # H1: no cross-run root configured refuses coded.
    try:
        tracker.clear_cross_run_lineage("alice")
        _break("H1", "clear without cross-run root did not refuse")
    except ln.LineageError as e:
        if _code_of(e) == "clear_cross_run_lineage":
            _held("H1", "clear_cross_run_lineage refuses coded without "
                  "cross-run root")
        else:
            _break("H1", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("H1", "%s: %s" % (type(e).__name__, e))
    # H2: with a root configured, a missing principal refuses under the
    # SAME code (distinct detail) -- fail-closed on operator error.
    tracker2 = ln.LineageTracker(run_dir, _StubLog(),
                                 cross_run_root=os.path.join(run_dir,
                                                             "xrun"))
    try:
        tracker2.clear_cross_run_lineage("")
        _break("H2", "clear with empty principal did not refuse")
    except ln.LineageError as e:
        if _code_of(e) == "clear_cross_run_lineage" \
                and "principal is required" in str(e):
            _held("H2", "empty principal refuses coded (distinct detail)")
        else:
            _break("H2", "wrong code/detail: %r" % (str(e),))
    except Exception as e:
        _error("H2", "%s: %s" % (type(e).__name__, e))


# ---------------------------------------------------------------------------
# I: detection -- identity_key_of
# ---------------------------------------------------------------------------

def fi():
    from gov import detection as det

    # I1: a non-identity, non-entry object refuses coded.
    try:
        det.identity_key_of(42)
        _break("I1", "identity_key_of(42) did not refuse")
    except TypeError as e:
        if _code_of(e) == "identity_key_of":
            _held("I1", "identity_key_of refuses coded on wrong type")
        else:
            _break("I1", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("I1", "%s: %s" % (type(e).__name__, e))
    # Discrimination: an entry dict keys honestly.
    try:
        key = det.identity_key_of({"principal": "alice", "agent_id": "a1",
                                   "run_id": "r9"})
        if key == "u:alice/a:a1/d:r9":
            _held("I1-disc", "entry dict keys honestly (not vacuous)")
        else:
            _break("I1-disc", "unexpected key: %r" % (key,))
    except Exception as e:
        _break("I1-disc", "honest entry failed: %s" % e)


# ---------------------------------------------------------------------------
# J: provenance verifier -- input_closure_digest
# ---------------------------------------------------------------------------

def fj():
    from gov import provenance_verifier as pv
    from gov import build_provenance as bp

    # J1: a malformed sealed statement refuses coded (not a raw
    # ProvenanceError escape).
    try:
        pv.input_closure_digest({"statement": {}})
        _break("J1", "malformed statement did not refuse")
    except pv.ProvenanceVerifierError as e:
        if _code_of(e) == "input_closure_digest":
            _held("J1", "input_closure_digest refuses coded on malformed "
                  "statement")
        else:
            _break("J1", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("J1", "%s: %s" % (type(e).__name__, e))
    # Discrimination: a real statement digests to a stable 64-hex hash.
    stmt = bp.ProvenanceStatement(
        builder="b1", recipe="repo@sha256:" + "11" * 32,
        inputs=[bp.ProvenanceInput(name="a-src", digest_hex="1" * 64,
                                   deterministic=True)],
        artifact_hex="aa" * 32, built_at=1700000000)
    try:
        d1 = pv.input_closure_digest(stmt)
        d2 = pv.input_closure_digest(stmt)
        if re.fullmatch(r"[0-9a-f]{64}", d1) and d1 == d2:
            _held("J1-disc", "honest statement digests stably (not vacuous)")
        else:
            _break("J1-disc", "unstable digest: %r" % (d1,))
    except Exception as e:
        _break("J1-disc", "honest statement failed: %s" % e)


# ---------------------------------------------------------------------------
# K: quorum policy -- canonical_link_body, make_link_record
# ---------------------------------------------------------------------------

def fk():
    from gov import quorum_policy as qp
    from gov import signing as sg

    # K1: empty step_name refuses coded.
    try:
        qp.canonical_link_body("", "ab" * 32, "cmd", "key1")
        _break("K1", "empty step_name did not refuse")
    except qp.QuorumPolicyError as e:
        if _code_of(e) == "canonical_link_body":
            _held("K1", "canonical_link_body refuses coded on empty "
                  "step_name")
        else:
            _break("K1", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("K1", "%s: %s" % (type(e).__name__, e))
    # Discrimination: honest args bind under the link domain.
    try:
        body = qp.canonical_link_body("step-1", "ab" * 32, "run tests",
                                      "key1")
        if isinstance(body, bytes) and b"quorum-link" in body \
                and b"step-1" in body:
            _held("K1-disc", "honest link body binds under the domain "
                  "(not vacuous)")
        else:
            _break("K1-disc", "unexpected body: %r" % (body,))
    except Exception as e:
        _break("K1-disc", "honest body failed: %s" % e)

    # K2: a signer without key_id/sign refuses coded.
    try:
        qp.make_link_record("step-1", "ab" * 32, object())
        _break("K2", "signer-less record did not refuse")
    except qp.QuorumPolicyError as e:
        if _code_of(e) == "make_link_record":
            _held("K2", "make_link_record refuses coded on bad signer")
        else:
            _break("K2", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("K2", "%s: %s" % (type(e).__name__, e))
    # Discrimination: a real signer produces a verifiable record.
    try:
        signer = sg.Ed25519Signer(os.urandom(32))
        rec = qp.make_link_record("step-1", "ab" * 32, signer,
                                  expected_command="run tests")
        if (set(rec) == {"step_name", "statement_digest", "expected_command",
                         "signer_keyid", "signature"}
                and rec["signer_keyid"] == signer.key_id
                and len(bytes.fromhex(rec["signature"])) == 64):
            _held("K2-disc", "honest record signs over the link body "
                  "(not vacuous)")
        else:
            _break("K2-disc", "unexpected record: %r" % (rec,))
    except Exception as e:
        _break("K2-disc", "honest record failed: %s" % e)


# ---------------------------------------------------------------------------
# L: egress launcher -- spawn_failed
# ---------------------------------------------------------------------------

def fl():
    from gov.egress_launcher import (
        EgressLaunchRefused, FilteredEgressLauncher, SimulatedWallFixture,
        SimulatedWallProvider, install_simulated_wall,
        repin_after_fixture_fixup,
    )

    tmp = _mk_tmp()
    sim = os.path.join(tmp, "wall")
    install_simulated_wall(sim, wall_id="g344unit")
    fix = SimulatedWallFixture(sim)
    fix.__enter__()
    try:
        inv = repin_after_fixture_fixup(sim)
        fix.inventory = inv
        events = []
        launcher = FilteredEgressLauncher(
            manifest_path=os.path.join(sim, "wall_pins.json"),
            receipt_path=os.path.join(sim, "wall_receipt.json"),
            wall_provider=fix.provider(), audit=events.append,
            trust=inv.trust)
        # L1: a spawn whose executable does not exist refuses coded.
        try:
            launcher.run_child(["/definitely/not/a/real/executable",
                                "--x"], capture_output=True)
            _break("L1", "missing executable did not refuse")
        except EgressLaunchRefused as e:
            if _code_of(e) == "spawn_failed":
                refused = [ev for ev in events
                           if ev.get("event") == "egress_wall_launch_refused"
                           and ev.get("reason") == "spawn_failed"]
                if refused:
                    _held("L1", "spawn_failed refuses coded with audit "
                          "trail")
                else:
                    _break("L1", "refusal lacked the audit event")
            else:
                _break("L1", "wrong code: %r" % _code_of(e))
        except Exception as e:
            _error("L1", "%s: %s" % (type(e).__name__, e))
        # Discrimination: a real executable launches behind the wall.
        try:
            cp = launcher.run_child([sys.executable, "-c", "pass"],
                                    capture_output=True)
            if cp.returncode == 0:
                _held("L1-disc", "honest spawn launches (not vacuous)")
            else:
                _break("L1-disc", "honest spawn rc=%r" % (cp.returncode,))
        except Exception as e:
            _break("L1-disc", "honest spawn failed: %s" % e)
    finally:
        fix.__exit__(None, None, None)


# ---------------------------------------------------------------------------
# PZ: depth-1 green check (adjacent suites; GOV_SKIP_GREEN=1 honored)
# ---------------------------------------------------------------------------

def _green_check():
    suites = [
        ("tests/test_eval_tasks.py", "eval tasks"),
        ("tests/test_provenance_verifier.py", "provenance verifier"),
        ("tests/test_w74_identity.py", "w74 identity"),
        ("tests/test_s6_lineage.py", "lineage"),
        ("tests/test_release_approval.py", "release approval"),
        ("tests/test_ratings.py", "ratings"),
        ("tests/test_durable_journal.py", "journal"),
    ]
    notes = []
    for path, label in suites:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", path.replace("/", ".")[:-3]],
            cwd=REPO, env=env, capture_output=True, text=True,
            timeout=900)
        if proc.returncode != 0:
            notes.append("suite %s (%s) RED:\n%s\n%s"
                         % (path, label, proc.stdout[-2000:],
                            proc.stderr[-2000:]))
    return notes


def main():
    p0()
    fa(); fb(); fc(); fd(); fe(); ff(); fg(); fh()
    fi(); fj(); fk(); fl()
    total = len(_results)
    held = sum(1 for r in _results if r[1] == "HELD")
    broken = [r for r in _results if r[1] == "BREAK"]
    errored = [r for r in _results if r[1] == "ERROR"]
    probe_breaks = set(r[0] for r in broken)
    expected = _EXPECTED_BREAKS
    if probe_breaks ^ expected:
        print("MISMATCH: got %s, expected %s"
              % (sorted(probe_breaks), sorted(expected)))
        for pid, status, note in _results:
            if status != "HELD":
                print("  %s %s: %s" % (status, pid, note))
        sys.exit(1)
    green_notes = []
    if os.environ.get("GOV_SKIP_GREEN") != "1":
        green_notes = _green_check()
    else:
        print("green check skipped (GOV_SKIP_GREEN=1)")
    print("%d/%d/%d probes HELD (0 BREAK, 0 ERROR expected); "
          "green notes: %d" % (held, total, len(errored), len(green_notes)))
    if broken or errored or green_notes:
        for pid, status, note in _results:
            if status != "HELD":
                print("  %s %s: %s" % (status, pid, note))
        for n in green_notes:
            print("  GREEN-NOTE: %s" % n[:500])
        sys.exit(1)
    print("ALL GREEN")


if __name__ == "__main__":
    main()
