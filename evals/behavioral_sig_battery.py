#!/usr/bin/env python3
"""Behavioral-signature registry battery (wave-175 lane 3, R7 shortlist #6).

RED-first: on a tree WITHOUT ``gov.behavioral_sigs`` this battery FAILs
with ImportError (the documented failure mode) — today's discovery path
has no versioned behavioral-signature registry, and the Sysdig/Marimo
profile (12 API calls across 11 IPs in 22 s) is invisible to the
existing shadow scan (machine_cadence needs >=25 actions / >=30 min).
On the built tree it PASSes: the six v1 signatures match their
Marimo-like true positives, never the benign controls, deterministically.

Deterministic: fixed epoch + seeded RNG, no wall clock, no network.
$0 spend, synthetic/local only.

Probes (each signature: true-positive + benign FP control):
  p1  fanned_egress TP (Marimo-like: 11 dests / 22 s) -> MATCHED
  p2  fanned_egress benign (2-endpoint poller)        -> not matched
  p3  parallel_sessions TP (4 overlapping sessions)   -> MATCHED
  p4  parallel_sessions benign (single session)       -> not matched
  p5  credential_then_export TP (secrets read -> export <120 s) -> MATCHED
  p6  credential_then_export benign (read alone / export alone) -> not matched
  p7  burst_cadence TP (12 regular actions / 22 s)    -> MATCHED
  p8  burst_cadence benign (irregular paste burst)    -> not matched
  p9  memory_write_heavy TP (20w/2r)                  -> MATCHED
  p10 memory_write_heavy benign (10w/10r)             -> not matched
  p11 approval_queue_spam TP (10 requests / 300 s)    -> MATCHED
  p12 approval_queue_spam benign (2 requests)         -> not matched
  p13 registry shape: every signature id/version pinned; finding
      carries (id, version); REGISTRY_VERSION constant
  p14 determinism: scan twice -> byte-identical findings
  p15 synthetic corpus precision/recall per signature (seeded;
      self-consistency regression pin, NOT a field measurement)
  p16 every signature ships fp_control + evasion note (non-empty)
  p17 discovery-vocabulary adapter: matched findings -> discovery.py
      (signal_kind, weight, detail) dicts, advisory only

Run:
  mkdir -p /tmp/gov-bsig
  TMPDIR=/tmp/gov-bsig ~/workspace/.gov-venv/bin/python \
      evals/behavioral_sig_battery.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-bsigb \
      ~/workspace/.gov-venv/bin/python evals/behavioral_sig_battery.py
"""

import json
import os
import random
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

BASE = 1_788_000_000  # fixed epoch: deterministic, no wall clock
rng = random.Random(20260928)

try:
    from gov import behavioral_sigs as bs
    HAVE_SIGS = True
    IMPORT_ERROR = None
except ImportError as e:  # noqa: BLE001 - red path is the documented mode
    bs = None
    HAVE_SIGS = False
    IMPORT_ERROR = e

results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), str(detail)))
    print(("PASS " if cond else "FAIL ") + name +
          ("  " + str(detail) if detail else ""))


def ev(t, tool, event, principal="p", dest=None, target=None, session=None):
    e = {"seq": 0, "ts": t, "principal": principal,
         "tool": tool, "event": event}
    if dest is not None:
        e["dest"] = dest
    if target is not None:
        e["target"] = target
    if session is not None:
        e["session_id"] = session
    return e


# --- fixtures -------------------------------------------------------------

def marimo_like(t0, principal="svc-shadow-7"):
    """12 API calls across 11 IPs in 22 s + secrets read + export."""
    out = []
    for i in range(12):
        out.append(ev(t0 + i * 2.0, "api_call", "api_call",
                      principal, dest="10.0.0.%d" % (i % 11 + 1)))
    out.append(ev(t0 + 40.0, "secrets_read", "read", principal,
                  target="aws-secrets-manager/ssh-key"))
    out.append(ev(t0 + 80.0, "db_dump", "export", principal,
                  target="postgres/full"))
    return out


def benign_poller(t0, principal="cron-1"):
    """Routine automation: 2 endpoints, 30 min."""
    return [ev(t0 + i * 60.0, "api_call", "api_call", principal,
               dest="10.1.0.%d" % (i % 2 + 1))
            for i in range(30)]


def parallel_sessions_tp(t0, principal="svc-shadow-7"):
    out = []
    for s in range(4):
        sid = "sess-%d" % s
        for i in range(6):
            out.append(ev(t0 + s * 30.0 + i * 10.0, "api_call",
                          "api_call", principal, session=sid))
    return out


def single_session(t0, principal="user-1"):
    return [ev(t0 + i * 60.0, "shell", "execute", principal,
               session="sess-0") for i in range(10)]


def burst_tp(t0, principal="svc-shadow-7"):
    return [ev(t0 + i * 2.0, "api_call", "api_call", principal)
            for i in range(12)]


def paste_burst_benign(t0, principal="user-1"):
    """Human paste burst: irregular gaps (0.2 s clumps, 5 s pauses)."""
    out, t = [], t0
    for i in range(40):
        out.append(ev(t, "read", "read", principal))
        t += 0.2 if i % 5 else 5.0
    return out


def memwrite_tp(t0, principal="svc-shadow-7"):
    out = [ev(t0 + i * 3.0, "memory_write", "write", principal,
              target="mem/slot-%d" % i) for i in range(20)]
    out += [ev(t0 + 100.0 + i, "memory_read", "read", principal)
            for i in range(2)]
    return out


def memwrite_benign(t0, principal="user-1"):
    out = [ev(t0 + i * 6.0, "memory_write", "write", principal)
           for i in range(10)]
    out += [ev(t0 + 300.0 + i * 6.0, "memory_read", "read", principal)
            for i in range(10)]
    return out


def approval_spam_tp(t0, principal="svc-shadow-7"):
    return [ev(t0 + i * 25.0, "approval_request", "approval_submit",
               principal) for i in range(10)]


def approval_benign(t0, principal="user-1"):
    return [ev(t0 + i * 3600.0, "approval_request", "approval_submit",
               principal) for i in range(2)]


def divd_narrative_tp(t0, principal="svc-shadow-7"):
    """DIVD 2026-09: machine-speed burst + self-commenting narrative."""
    out = [ev(t0 + i * 0.6, "api_call", "api_call", principal,
              session="s1") for i in range(14)]
    out += [ev(t0 + 0.5 + i * 1.1, "log_write", "decision_note",
               principal, session="s1") for i in range(15)]
    return out


def quiet_logger_benign(t0, principal="user-1"):
    """Routine operator logging: terse, few narratives.

    Actions use irregular gaps on purpose: this fixture isolates the
    narrative signature (which keys on note count + ratio, never
    cadence), so it must not exercise burst_cadence's documented
    machine-regular confound.
    """
    out, t = [], t0
    for i in range(14):
        out.append(ev(t, "api_call", "api_call", principal,
                      session="s1"))
        t += 0.2 if i % 3 else 7.0
    out += [ev(t0 + 0.5 + i * 30.0, "log_write", "decision_note",
               principal, session="s1") for i in range(3)]
    return out


def self_interference_tp(t0, principal="svc-shadow-7"):
    """DIVD 2026-09: password spray breaking the agent's own AiTM."""
    return [
        ev(t0, "net_probe", "aitm_establish", principal,
           target="segment-dmz", session="s1"),
        ev(t0 + 4.0, "auth_try", "password_spray", principal,
           target="sso-portal", session="s1"),
    ]


def spray_alone_benign(t0, principal="user-1"):
    """Password spray with no prior established capability."""
    return [ev(t0 + i, "auth_try", "password_spray", principal,
               target="sso-portal", session="s1") for i in range(3)]


HINTS = [r"secret", r"credential", r"ssh-key", r"token"]


def matched_id(findings, sig_id):
    return [f for f in findings
            if f.signature_id == sig_id and f.matched]


# --- probes ---------------------------------------------------------------

def main():
    if not HAVE_SIGS:
        print("RED: gov.behavioral_sigs missing: %s" % (IMPORT_ERROR,))
        print("BATTERY: FAIL (0/17)")
        return 1

    t0 = BASE
    # p1/p2 fanned_egress
    f = bs.scan(marimo_like(t0))
    m = matched_id(f, "fanned_egress")
    check("p1_fanned_egress_tp", len(m) == 1,
          "Marimo-like 11 dests/22s -> %s" %
          (m[0].detail if m else "no match"))
    f = bs.scan(benign_poller(t0))
    check("p2_fanned_egress_benign", not matched_id(f, "fanned_egress"),
          "2-endpoint poller must not match")

    # p3/p4 parallel_sessions
    f = bs.scan(parallel_sessions_tp(t0))
    m = matched_id(f, "parallel_sessions")
    check("p3_parallel_sessions_tp", len(m) == 1,
          "4 overlapping sessions -> %s" %
          (m[0].detail if m else "no match"))
    f = bs.scan(single_session(t0))
    check("p4_parallel_sessions_benign", not matched_id(f, "parallel_sessions"),
          "single session must not match")

    # p5/p6 credential_then_export
    f = bs.scan(marimo_like(t0), credential_hints=HINTS)
    m = matched_id(f, "credential_then_export")
    check("p5_credential_then_export_tp", len(m) == 1,
          "secrets read -> export 40s later -> %s" %
          (m[0].detail if m else "no match"))
    f = bs.scan([ev(t0, "secrets_read", "read", target="x/ssh-key")],
                credential_hints=HINTS)
    b1 = not matched_id(f, "credential_then_export")
    f = bs.scan([ev(t0, "db_dump", "export", target="postgres/full")],
                credential_hints=HINTS)
    b2 = not matched_id(f, "credential_then_export")
    check("p6_credential_then_export_benign", b1 and b2,
          "read-alone and export-alone must not match")
    f = bs.scan(marimo_like(t0))  # no hints -> absent, house rule
    check("p6b_credential_then_export_no_hints_absent",
          not matched_id(f, "credential_then_export"),
          "no operator hints -> signal absent (never invented)")

    # p7/p8 burst_cadence
    f = bs.scan(burst_tp(t0))
    m = matched_id(f, "burst_cadence")
    check("p7_burst_cadence_tp", len(m) == 1,
          "12 regular actions/22s -> %s" %
          (m[0].detail if m else "no match"))
    f = bs.scan(paste_burst_benign(t0))
    check("p8_burst_cadence_benign", not matched_id(f, "burst_cadence"),
          "irregular paste burst must not match")

    # p9/p10 memory_write_heavy
    f = bs.scan(memwrite_tp(t0))
    m = matched_id(f, "memory_write_heavy")
    check("p9_memory_write_heavy_tp", len(m) == 1,
          "20w/2r -> %s" % (m[0].detail if m else "no match"))
    f = bs.scan(memwrite_benign(t0))
    check("p10_memory_write_heavy_benign",
          not matched_id(f, "memory_write_heavy"),
          "balanced 10w/10r must not match")

    # p11/p12 approval_queue_spam
    f = bs.scan(approval_spam_tp(t0))
    m = matched_id(f, "approval_queue_spam")
    check("p11_approval_queue_spam_tp", len(m) == 1,
          "10 requests/250s -> %s" % (m[0].detail if m else "no match"))
    f = bs.scan(approval_benign(t0))
    check("p12_approval_queue_spam_benign",
          not matched_id(f, "approval_queue_spam"),
          "2 requests must not match")

    # p18 self_narrated_trajectory (DIVD wave-245): self-commenting
    # narrative volume; 3 terse notes must not match.
    f = bs.scan(divd_narrative_tp(t0))
    check("p18_self_narrated_trajectory_tp",
          matched_id(f, "self_narrated_trajectory"),
          "noisy machine-speed self-commentary must match")
    f = bs.scan(quiet_logger_benign(t0))
    check("p18_self_narrated_trajectory_benign",
          not matched_id(f, "self_narrated_trajectory"),
          "3 terse notes must not match")

    # p19 self_interference (DIVD wave-245): spray after own AiTM;
    # spray alone is not self-interference.
    f = bs.scan(self_interference_tp(t0))
    check("p19_self_interference_tp",
          matched_id(f, "self_interference"),
          "spray after own AiTM establishment must match")
    f = bs.scan(spray_alone_benign(t0))
    check("p19_self_interference_benign",
          not matched_id(f, "self_interference"),
          "spray with no prior establishment must not match")

    # p13 registry shape / versioning
    sigs = bs.SIGNATURES
    pinned = all(s.signature_id and s.version and s.name and s.desc
                 for s in sigs.values())
    f = bs.scan(marimo_like(t0), credential_hints=HINTS)
    carried = all(fl.signature_id in sigs and
                  fl.signature_version ==
                  sigs[fl.signature_id].version for fl in f)
    check("p13_registry_versioned", pinned and carried and
          isinstance(bs.REGISTRY_VERSION, str) and bs.REGISTRY_VERSION,
          "REGISTRY_VERSION=%s, %d signatures pinned" %
          (bs.REGISTRY_VERSION, len(sigs)))

    # p14 determinism x2
    a = bs.scan(marimo_like(t0), credential_hints=HINTS)
    b = bs.scan(marimo_like(t0), credential_hints=HINTS)
    ja = json.dumps([fl.to_dict() for fl in a], sort_keys=True)
    jb = json.dumps([fl.to_dict() for fl in b], sort_keys=True)
    check("p14_determinism_x2", ja == jb, "byte-identical findings")

    # p15 synthetic corpus precision/recall (self-consistency regression
    # pin — synthetic, NOT a field measurement). Each signature gets a
    # dedicated TP set; the benign set is shared.
    tp_sets = {
        "fanned_egress": [marimo_like(BASE + i * 10000)
                          for i in range(8)],
        "parallel_sessions": [parallel_sessions_tp(BASE + i * 10000)
                              for i in range(8)],
        "credential_then_export": [marimo_like(BASE + i * 10000)
                                   for i in range(8)],
        "burst_cadence": [burst_tp(BASE + i * 10000) for i in range(8)],
        "memory_write_heavy": [memwrite_tp(BASE + i * 10000)
                               for i in range(8)],
        "approval_queue_spam": [approval_spam_tp(BASE + i * 10000)
                                for i in range(8)],
        "self_narrated_trajectory": [divd_narrative_tp(BASE + i * 10000)
                                    for i in range(8)],
        "self_interference": [self_interference_tp(BASE + i * 10000)
                              for i in range(8)],
    }
    bens = []
    for i in range(4):
        bens.append(benign_poller(BASE + 500000 + i * 10000))
        bens.append(single_session(BASE + 500000 + i * 10000))
        bens.append(paste_burst_benign(BASE + 500000 + i * 10000))
        bens.append(memwrite_benign(BASE + 500000 + i * 10000))
        bens.append(approval_benign(BASE + 500000 + i * 10000))
        bens.append(quiet_logger_benign(BASE + 500000 + i * 10000))
        bens.append(spray_alone_benign(BASE + 500000 + i * 10000))
    per_sig = {}
    for sig_id in sigs:
        tps = tp_sets[sig_id]
        tp_hit = sum(1 for tr in tps
                     if matched_id(bs.scan(tr, credential_hints=HINTS),
                                   sig_id))
        fp = sum(1 for tr in bens
                 if matched_id(bs.scan(tr, credential_hints=HINTS), sig_id))
        prec = tp_hit / (tp_hit + fp) if (tp_hit + fp) else 1.0
        rec = tp_hit / len(tps)
        per_sig[sig_id] = (round(prec, 3), round(rec, 3))
    # Per-signature floors: burst_cadence has a documented precision
    # confound (regular benign automation is cadence-indistinguishable
    # from a machine burst), so its precision floor is 0.6 — the
    # confound is named in the signature's fp_control, not hidden.
    floors = {s: (0.8, 0.8) for s in sigs}
    floors["burst_cadence"] = (0.6, 0.8)
    ok = all(p >= floors[s][0] and r >= floors[s][1]
             for s, (p, r) in per_sig.items())
    check("p15_corpus_precision_recall", ok,
          "per-signature (P,R) vs floors %s: %s" %
          ({k: v for k, v in floors.items()}, per_sig))

    # p16 fp_control + evasion note shipped per signature
    ok = all(s.fp_control.strip() and s.evasion_note.strip()
             for s in sigs.values())
    check("p16_fp_control_and_evasion", ok,
          "every signature documents its FP control + evasion")

    # p17 discovery-vocabulary adapter (advisory only)
    f = bs.scan(marimo_like(t0), credential_hints=HINTS)
    sigs_out = bs.to_discovery_signals(f)
    ok = all(set(s) >= {"signal_kind", "weight", "detail"} and
             isinstance(s["weight"], int) for s in sigs_out)
    kinds = sorted(s["signal_kind"] for s in sigs_out)
    check("p17_discovery_adapter", ok and len(sigs_out) > 0,
          "advisory signals: %s" % kinds)

    # green check: adjacent seam (depth-1; honors GOV_SKIP_GREEN)
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green_check: SKIPPED (GOV_SKIP_GREEN=1)")
    else:
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        tmp = tempfile.mkdtemp(prefix="bsig-green-")
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [sys.executable,
             os.path.join(REPO_ROOT, "evals", "shadow_agent_battery.py")],
            capture_output=True, text=True, env=env, timeout=600)
        check("green_adjacent_shadow_battery", r.returncode == 0,
              "rc=%d tail=%s" % (r.returncode, r.stdout[-200:]))

    # standalone env check note (run separately under env -u)
    passed = sum(1 for _, c, _ in results if c)
    total = len(results)
    print("BATTERY: %s (%d/%d)" %
          ("PASS" if passed == total else "FAIL", passed, total))
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
