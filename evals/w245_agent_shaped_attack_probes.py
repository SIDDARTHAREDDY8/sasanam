"""Wave-245 noisy-autonomous-attacker detection probes (red-first).

W245-2 (detection shapes from the DIVD incident, reported 2026-09-29,
case DIVD-2026-00014): the first documented in-the-wild attacker-side
autonomous AI agent. Entry: Zammad zero-days CVE-2026-102489 and
CVE-2026-102490 (session hijacking -> RCE -> root escalation;
discovered with Merlon Security; first access 2026-09-21, DIVD aware
2026-09-22, casefile published 2026-09-29). The promised DIVD
technical update (2026-10-01) was NOT yet published when this battery
was written -- no agent framework ID and no IOCs are publicly
available, so the probes model the DISLOSED BEHAVIORAL SHAPES only
("loud and very, very messy"; machine-speed decision cadence;
self-interfering password spray that broke the agent's own AiTM;
anomalous volume of self-commenting decision logs), never an
attributed framework identity.

The battery pins three detection requirements against
gov/behavioral_sigs.py's versioned signature registry (the advisory
seam; findings are sightings, never accusations):
  (a) a noisy machine-speed trajectory with self-commenting logs is
      FLAGGED as agent-shaped (self_narrated_trajectory), never silent;
  (b) self-interfering operations do NOT evade tripwires
      (self_interference fires even though the attacker's own password
      spray degraded its own AiTM capability);
  (c) the registry never assumes a stealthy adversary: a maximally
      noisy trajectory is still matched by cadence shapes and never
      excluded from detection shapes.

Probes (TP = true positive, FP = benign control):
  noisy-self-narrative-matched    -- machine-speed + heavy self-commentary
      -> self_narrated_trajectory MATCHED; discovery signals non-empty
      (agent-shaped, never silent).
  noisy-cadence-not-invisible    -- loud machine-speed trajectory still
      matches burst_cadence; no signature excludes noisy trajectories.
  self-interference-tripwire     -- aitm_establish then password_spray in
      the same session -> self_interference MATCHED (tripwire fires
      even though the spray degraded the attacker's own AiTM).
  spray-alone-silent             -- password_spray with no prior AiTM
      establishment -> self_interference not matched.
  aitm-alone-silent              -- aitm_establish with no later
      self-invalidation -> self_interference not matched.
  cross-session-no-contradiction -- spray in session B after AiTM in
      session A -> self_interference not matched (separate sessions).
  quiet-logging-silent           -- 3 terse decision notes per 600 s ->
      self_narrated_trajectory not matched (benign control).
  divd-reconstruction-flagged    -- the DIVD shape composite (entry
      CVE-2026-102489/102490 context; machine-speed cadence;
      self-commentary; self-interference) yields >=2 matched findings
      and non-empty discovery signals.
  stealth-neutrality             -- a maximally noisy trajectory still
      produces matched findings: the registry never assumes a stealthy
      adversary.

On a tree WITHOUT the two v1 signatures this battery reports all
probes GAP ("capability absent on pristine base") -- the documented
red-first failure mode. On the built tree it reports 9/9 HELD.

Stdlib only. Deterministic (fixed epoch, no wall clock, no network).
No in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_DIVD = False
try:
    from gov import behavioral_sigs as _bs
    HAVE_DIVD = all(hasattr(_bs, n) for n in (
        "SIGNATURES", "scan", "to_discovery_signals",
        "normalize_entries"))
    HAVE_DIVD = (HAVE_DIVD
                 and "self_narrated_trajectory" in _bs.SIGNATURES
                 and "self_interference" in _bs.SIGNATURES)
except ImportError:
    _bs = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

T0 = 1_788_000_000

# The DIVD entry CVEs, ingested as incident context (public facts from
# csirt.divd.nl DIVD-2026-00014 and the 2026-09-30 reporting; the
# promised 2026-10-01 technical update is not yet published).
DIVD_ENTRY_CVES = ("CVE-2026-102489", "CVE-2026-102490")

PROBE_NAMES = [
    "noisy-self-narrative-matched",
    "noisy-cadence-not-invisible",
    "self-interference-tripwire",
    "spray-alone-silent",
    "aitm-alone-silent",
    "cross-session-no-contradiction",
    "quiet-logging-silent",
    "divd-reconstruction-flagged",
    "stealth-neutrality",
]


def ev(t, tool="api_call", event="api_call", principal="p",
       dest=None, target=None, session=None):
    e = {"ts": t, "principal": principal, "tool": tool, "event": event}
    if dest is not None:
        e["dest"] = dest
    if target is not None:
        e["target"] = target
    if session is not None:
        e["session_id"] = session
    return e


def _matched(entries, sig_id):
    findings = _bs.scan(entries)
    return [f for f in findings
            if f.signature_id == sig_id and f.matched]


def _run_probe(name, fn, have):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _narrative_trajectory(n_notes, n_actions=14, gaps=(0.6, 1.1)):
    """Machine-speed trajectory with n_notes self-commentary entries."""
    entries = []
    for i in range(n_actions):
        entries.append(ev(T0 + i * gaps[0], tool="api_call",
                          event="api_call", session="s1"))
    for i in range(n_notes):
        entries.append(ev(T0 + 0.5 + i * gaps[1], tool="log_write",
                          event="decision_note", session="s1"))
    return entries


def _probe_noisy_self_narrative_matched():
    entries = _narrative_trajectory(n_notes=15)
    m = _matched(entries, "self_narrated_trajectory")
    assert len(m) == 1, "expected self_narrated_trajectory matched, got %r" \
        % ([f.to_dict() for f in m],)
    sig = _bs.SIGNATURES["self_narrated_trajectory"]
    assert m[0].signature_version == sig.version, m[0].to_dict()
    signals = _bs.to_discovery_signals(_bs.scan(entries))
    assert signals, "agent-shaped trajectory must never be silent"
    assert any(s["signal_kind"] == "self_narrated_trajectory"
               for s in signals), signals
    return "noisy machine-speed trajectory with self-commentary flagged " \
        "as agent-shaped (never silent)"


def _probe_noisy_cadence_not_invisible():
    # A maximally loud machine-speed trajectory (burst + narrative
    # flood) must still be caught by cadence shapes: noisy is not
    # invisible.
    entries = _narrative_trajectory(n_notes=30, n_actions=22)
    m = _matched(entries, "burst_cadence")
    assert len(m) == 1, "burst_cadence must still match a loud burst"
    return "burst_cadence matches the loud trajectory; noise is not " \
        "exclusion"


def _probe_self_interference_tripwire():
    entries = [
        ev(T0, tool="net_probe", event="aitm_establish",
           target="segment-dmz", session="s1"),
        ev(T0 + 4, tool="auth_try", event="password_spray",
           target="sso-portal", session="s1"),
        ev(T0 + 9, tool="auth_try", event="password_spray",
           target="sso-portal", session="s1"),
    ]
    m = _matched(entries, "self_interference")
    assert len(m) == 1, \
        "self_interference must fire even though the spray degraded the " \
        "attacker's own AiTM"
    return "password spray after own AiTM establishment fires the tripwire"


def _probe_spray_alone_silent():
    entries = [
        ev(T0, tool="auth_try", event="password_spray",
           target="sso-portal", session="s1"),
        ev(T0 + 5, tool="auth_try", event="password_spray",
           target="sso-portal", session="s1"),
    ]
    m = _matched(entries, "self_interference")
    assert not m, "spray with no prior establishment is not " \
        "self-interference"
    return "spray alone (no prior established capability) stays silent"


def _probe_aitm_alone_silent():
    entries = [
        ev(T0, tool="net_probe", event="aitm_establish",
           target="segment-dmz", session="s1"),
        ev(T0 + 30, tool="api_call", event="data_read", session="s1"),
    ]
    m = _matched(entries, "self_interference")
    assert not m, "uninterfered establishment is not self-interference"
    return "AiTM establishment with no later self-invalidation stays silent"


def _probe_cross_session_no_contradiction():
    entries = [
        ev(T0, tool="net_probe", event="aitm_establish",
           target="segment-dmz", session="sA"),
        ev(T0 + 4, tool="auth_try", event="password_spray",
           target="sso-portal", session="sB"),
    ]
    m = _matched(entries, "self_interference")
    assert not m, "separate sessions cannot contradict each other"
    return "spray in a different session is not self-interference"


def _probe_quiet_logging_silent():
    entries = _narrative_trajectory(n_notes=3, n_actions=14)
    m = _matched(entries, "self_narrated_trajectory")
    assert not m, "3 terse notes must stay below the benign gate"
    return "quiet routine logging stays silent (benign control)"


def _probe_divd_reconstruction_flagged():
    # Composite DIVD shape: entry via Zammad zero-days
    # (CVE-2026-102489/102490 context), then machine-speed
    # post-exploitation with self-commentary and a self-interfering
    # password spray that broke the agent's own AiTM.
    entries = [
        ev(T0, tool="http_post", event="exploit_attempt",
           target="zammad:%s" % (DIVD_ENTRY_CVES[0],), session="s1"),
        ev(T0 + 2, tool="net_probe", event="aitm_establish",
           target="segment-dmz", session="s1"),
    ]
    for i in range(12):
        entries.append(ev(T0 + 3 + i * 0.8, tool="api_call",
                          event="api_call", session="s1"))
    for i in range(14):
        entries.append(ev(T0 + 3.4 + i * 0.9, tool="log_write",
                          event="decision_note", session="s1"))
    for i in range(6):
        entries.append(ev(T0 + 16 + i * 1.2, tool="auth_try",
                          event="password_spray", target="sso-portal",
                          session="s1"))
    findings = _bs.scan(entries)
    matched = [f for f in findings if f.matched]
    kinds = {f.signature_id for f in matched}
    assert "self_narrated_trajectory" in kinds, kinds
    assert "self_interference" in kinds, kinds
    assert len(matched) >= 2, [f.to_dict() for f in matched]
    signals = _bs.to_discovery_signals(findings)
    assert signals, "DIVD reconstruction must produce discovery signals"
    return "DIVD reconstruction flagged: %s" % (sorted(kinds),)


def _probe_stealth_neutrality():
    # The registry must never assume a stealthy adversary: a
    # maximally noisy trajectory (high rate, narrative flood,
    # contradiction) still produces matched findings.
    entries = _narrative_trajectory(n_notes=40, n_actions=30)
    entries.append(ev(T0 + 60, tool="net_probe", event="aitm_establish",
                      target="segment-dmz", session="s1"))
    entries.append(ev(T0 + 65, tool="auth_try", event="password_spray",
                      target="sso-portal", session="s1"))
    findings = _bs.scan(entries)
    matched = [f for f in findings if f.matched]
    assert matched, "a loud adversary must never be invisible"
    assert len(matched) >= 2, [f.to_dict() for f in matched]
    assert _bs.to_discovery_signals(findings), "signals must be non-empty"
    # Every signature documents an evasion note; none may claim that
    # noise alone evades it (the registry must not treat loud as safe).
    for sig_id, sig in _bs.SIGNATURES.items():
        assert "loud" not in sig.evasion_note.lower() or \
            "evade" not in sig.evasion_note.lower(), sig_id
    return "loud trajectory matched %d signatures; no stealth assumption" \
        % (len(matched),)


_PROBES = {
    "noisy-self-narrative-matched":
        (_probe_noisy_self_narrative_matched, HAVE_DIVD),
    "noisy-cadence-not-invisible":
        (_probe_noisy_cadence_not_invisible, HAVE_DIVD),
    "self-interference-tripwire":
        (_probe_self_interference_tripwire, HAVE_DIVD),
    "spray-alone-silent": (_probe_spray_alone_silent, HAVE_DIVD),
    "aitm-alone-silent": (_probe_aitm_alone_silent, HAVE_DIVD),
    "cross-session-no-contradiction":
        (_probe_cross_session_no_contradiction, HAVE_DIVD),
    "quiet-logging-silent": (_probe_quiet_logging_silent, HAVE_DIVD),
    "divd-reconstruction-flagged":
        (_probe_divd_reconstruction_flagged, HAVE_DIVD),
    "stealth-neutrality": (_probe_stealth_neutrality, HAVE_DIVD),
}


def _run_green_checks():
    """Depth-1 green checks: honor GOV_SKIP_GREEN, never spawn nested."""
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    import subprocess  # noqa: PLC0415
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env.setdefault("GOV_DEPLOYMENT_MODE", "staging")
    root = os.path.join(os.path.dirname(__file__), "..")
    for mod in ("tests.test_behavioral_sigs",):
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", mod, "-v"],
            cwd=root, env=env, capture_output=True, text=True,
            timeout=300)
        notes.append("unit %s rc=%d" % (mod, proc.returncode))
        if proc.returncode != 0:
            notes.append("unit tail: %s" % (proc.stderr[-400:],))
    proc = subprocess.run(
        [sys.executable, "evals/behavioral_sig_battery.py"],
        cwd=root, env=env, capture_output=True, text=True,
        timeout=600)
    notes.append("adjacent behavioral_sig_battery rc=%d"
                 % (proc.returncode,))
    if proc.returncode != 0:
        tail = (proc.stdout + proc.stderr)[-600:]
        notes.append("adjacent tail: %s" % (tail,))
    return notes


def main():
    print("wave-245 noisy-autonomous-attacker probes (module: %s)"
          % (HAVE_DIVD,))
    held = gap = 0
    for name in PROBE_NAMES:
        fn, have = _PROBES[name]
        name_r, status, note = _run_probe(name, fn, have)
        if status == "HELD":
            held += 1
        elif status == "GAP":
            gap += 1
        print("%-42s %s %s" % (name_r, status, note))
    notes = _run_green_checks()
    for note in notes:
        print("green: %s" % note)
    print("summary: %d HELD / %d GAP / %d total"
          % (held, gap, len(PROBE_NAMES)))
    if held != len(PROBE_NAMES):
        raise SystemExit("battery not fully HELD (%d/%d)"
                         % (held, len(PROBE_NAMES)))


if __name__ == "__main__":
    main()
