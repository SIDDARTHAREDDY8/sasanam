"""Wave-148, row 13: canary fragment floor + entropy gating.

Row-13 residual: fragments of planted canaries are matched cumulatively
(wave-146), but there was no measured per-format minimum fragment length
and no entropy discipline -- a short or low-entropy fragment could, in
principle, trip alone. This battery pins both:

  floor_above_trips      the per-format floor is enforced: deriving
                         below it clamps up (token 8 / hostname 8 /
                         env_entry 10)
  floor_env_entry_ten    env_entry derivation refuses to go below 10
                         (measured: L=8 hits the "sk_live_" structural
                         prefix in benign chatter)
  below_floor_silent     a below-floor fragment stays silent (EXPECTED:
                         structural -- it cannot reach the half-span
                         threshold, so this is not a detection claim)
  one_low_entropy_silent ONE low-entropy 16-char fragment alone stays
                         silent (pre-wave-148: the half-span rule trips
                         on it -- this is the RED probe)
  two_low_entropy_trip   two DISTINCT low-entropy fragments from the same
                         canary still trip (pair rule is entropy-blind)
  whole_canary_unchanged the full-value path is unaffected by the gate
  canary_fragment_no_regression
                         the wave-146 canary_fragment_probes battery
                         stays green
  deterministic_x2       byte-identical verdicts across two runs

Measured numbers (2026-09-27, 20 run_ids x 80-text benign corpus):
  per-format floors: token 8 / hostname 8 / env_entry 10
  entropy gate 2.0 bits/char: below every genuine half-span measured
  (6080 half-spans over 40 run_ids bottom out at 2.371) and every
  genuine 16-char fragment (3660 fragments bottom out at 2.125 --
  slack-token digit runs, which can never half-span-trip alone: the
  slack value is ~50 chars, half = 25 > 16).
Known residual: dictionary-word fragments above the gate
("passwordpassword" = 2.75) still half-span-trip alone. Row 13 stays
PARTIAL.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import canary as C  # noqa: E402

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-38s %-10s %s" % (name, verdict, detail))


def _mint_and_registry(run_id):
    mint = C.CanaryMint(run_id)
    reg = C.CanaryRegistry()
    reg.register(mint)
    return mint, reg


class _SyntheticMint:
    """Duck-typed mint for a hand-built low-entropy canary.

    Stands in for short structured canaries whose fragments are
    low-entropy (repetitive/digit-heavy segments). Exercises the real
    register/match_fragments path -- only the VALUE is synthetic.
    """

    def __init__(self, value, kind="bearer_token", label="synth-lowent"):
        self.run_id = "synth-lowent-run"
        self._c = {"kind": kind, "label": label, "value": value,
                   "channel": "decoy_config"}

    def values(self):
        return [dict(self._c)]


# 32-char alternating value: half = 16, so a single 16-char window
# reaches the half-span threshold; every window has entropy 1.0.
SYNTH_VALUE = "ab" * 16


def floor_above_trips():
    """The per-format floor is enforced at derivation time.

    For every planted format: deriving at the floor yields fragments
    all >= the floor, and requesting BELOW the floor clamps up to it.
    (match_fragments itself scans 16-char windows, so the floor is a
    derivation invariant, not a trip rule -- documented here.)
    """
    name = "floor_above_trips"
    if not hasattr(C, "_fragment_floor"):
        _record(name, "BREAK", "no per-format floor exists "
                "(_fragment_floor missing)")
        return
    mint, _ = _mint_and_registry("floor-run")
    expect = {"aws_access_key": 8, "aws_secret_key": 8,
              "bearer_token": 8, "hostname": 8, "env_entry": 10}
    seen_kinds = set()
    for c in mint.values():
        kind = c["kind"]
        seen_kinds.add(kind)
        floor = C._fragment_floor(kind)
        if floor != expect[kind]:
            _record(name, "BREAK", "floor for %s is %d, measured %d"
                    % (kind, floor, expect[kind]))
            return
        at = C._derive_fragments(c["value"], kind=kind, frag_len=floor)
        below = C._derive_fragments(c["value"], kind=kind,
                                    frag_len=floor - 1)
        for f in at + below:
            if len(f) < floor:
                _record(name, "BREAK", "%s derived %d-char fragment "
                        "below floor %d" % (kind, len(f), floor))
                return
        if below and min(len(f) for f in below) != floor:
            _record(name, "BREAK", "%s frag_len=%d did not clamp to "
                    "floor %d" % (kind, floor - 1, floor))
            return
    if seen_kinds != set(expect):
        _record(name, "ERROR", "mint kinds changed: %s"
                % sorted(seen_kinds))
        return
    _record(name, "HELD", "floors enforced for 5 formats "
            "(token 8 / hostname 8 / env_entry 10); "
            "below-floor requests clamp up")


def floor_env_entry_ten():
    """env_entry derivation clamps to the measured floor of 10."""
    name = "floor_env_entry_ten"
    value = "sk_live_" + "R" * 24
    try:
        got = C._derive_fragments(value, kind="env_entry", frag_len=8)
    except TypeError:
        _record(name, "BREAK", "_derive_fragments has no kind/frag_len "
                "support (no floor enforcement)")
        return
    if not got:
        _record(name, "BREAK", "no fragments derived for env_entry at all")
        return
    if any(len(f) < 10 for f in got):
        _record(name, "BREAK", "env_entry derived below the floor of 10: "
                "%r" % (got[0],))
        return
    if any(len(f) != 10 for f in got):
        _record(name, "BREAK", "expected clamp to exactly 10, got lengths "
                "%s" % sorted(set(len(f) for f in got)))
        return
    _record(name, "HELD", "frag_len=8 clamped to floor 10 (%d fragments)"
            % len(got))


def below_floor_silent():
    """A below-floor fragment stays silent (EXPECTED: structural)."""
    name = "below_floor_silent"
    _, reg = _mint_and_registry("below-floor-run")
    # 9-char slice of the sk_live_ structural prefix: below the
    # env_entry floor of 10 and below every half-span threshold, so
    # silence is structural, not a detection claim.
    if reg.match_fragments("the key starts with sk_live_R"):
        _record(name, "BREAK", "below-floor fragment tripped")
        return
    _record(name, "EXPECTED", "9-char below-floor slice is silent by "
            "construction (cannot reach any half-span threshold)")


def _shannon_bits(s):
    """Local entropy helper so the behavioral probes do not depend on
    the product's own (post-seam) helper."""
    import math
    from collections import Counter
    n = len(s)
    return -sum((c / n) * math.log2(c / n)
                for c in Counter(s).values())


def one_low_entropy_silent():
    """ONE low-entropy 16-char fragment alone stays silent."""
    name = "one_low_entropy_silent"
    reg = C.CanaryRegistry()
    reg.register(_SyntheticMint(SYNTH_VALUE))
    frag = "abababababababab"  # entropy 1.0 < 2.0 gate
    ent = _shannon_bits(frag)
    hit = reg.match_fragments("leaked slice: " + frag + " end")
    if hit is not None:
        _record(name, "BREAK", "single low-entropy fragment tripped "
                "(entropy %.2f, trigger %s)" % (ent, hit["trigger"]))
        return
    _record(name, "HELD", "single low-entropy fragment silent "
            "(entropy %.2f < 2.0 gate)" % ent)


def two_low_entropy_trip():
    """Two DISTINCT low-entropy fragments from one canary still trip."""
    name = "two_low_entropy_trip"
    reg = C.CanaryRegistry()
    reg.register(_SyntheticMint(SYNTH_VALUE))
    # Positional call: works on the pre-seam single-arg signature too.
    frags = C._derive_fragments(SYNTH_VALUE)
    distinct = sorted(set(frags))
    if len(distinct) < 2:
        _record(name, "ERROR", "synthetic value yielded <2 distinct "
                "fragments")
        return
    first = reg.match_fragments("slice one: " + distinct[0])
    if first is not None:
        _record(name, "BREAK", "first low-entropy fragment alone tripped "
                "(gate regression)")
        return
    second = reg.match_fragments("slice two: " + distinct[1])
    if second is None:
        _record(name, "BREAK", "two distinct low-entropy fragments did "
                "not trip")
        return
    if second["trigger"] != "two_distinct_fragments":
        _record(name, "BREAK", "wrong trigger: %s" % second["trigger"])
        return
    _record(name, "HELD", "two distinct low-entropy fragments trip "
            "(trigger=%s)" % second["trigger"])


def whole_canary_unchanged():
    """The full-value path ignores the entropy gate."""
    name = "whole_canary_unchanged"
    reg = C.CanaryRegistry()
    reg.register(_SyntheticMint(SYNTH_VALUE))
    hit = reg.match_value("full dump: " + SYNTH_VALUE + " done")
    if hit is None:
        _record(name, "BREAK", "whole low-entropy canary no longer "
                "matches")
        return
    _record(name, "HELD", "whole-canary path unaffected by the entropy "
            "gate")


def canary_fragment_no_regression():
    """The wave-146 canary_fragment_probes battery stays green."""
    name = "canary_fragment_no_regression"
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location(
        "_cf_floor_reg", os.path.join(here, "canary_fragment_probes.py"))
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        mod._run_all()
        results = list(mod._RESULTS)
    except Exception as exc:  # noqa: BLE001 - battery must report
        _record(name, "BREAK", "regression battery raised %r" % (exc,))
        return
    bad = ["%s: %s (%s)" % (pn, v, d) for pn, v, d in results
           if v in ("BREAK", "ERROR")]
    if bad:
        _record(name, "BREAK", "regression: %s" % "; ".join(bad))
        return
    _record(name, "HELD", "canary_fragment_probes.py: %d probes clean"
            % len(results))


def _run_all():
    global _RESULTS
    _RESULTS = []
    for fn in (floor_above_trips, floor_env_entry_ten, below_floor_silent,
               one_low_entropy_silent, two_low_entropy_trip,
               whole_canary_unchanged, canary_fragment_no_regression):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - battery must report
            _record(fn.__name__, "ERROR", "raised %r" % (exc,))
    return list(_RESULTS)


def deterministic_x2():
    name = "deterministic_x2"
    first = [(n, v) for n, v, _ in _run_all()]
    second = [(n, v) for n, v, _ in _run_all()]
    if first != second:
        _record(name, "BREAK", "verdicts differ between runs: %r vs %r"
                % (first, second))
        return
    _record(name, "HELD", "%d probes byte-identical verdicts across 2 runs"
            % len(first))


def main():
    _run_all()
    deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("canary_fragment_floor_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
