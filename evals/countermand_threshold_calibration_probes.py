#!/usr/bin/env python3
"""Threshold-calibration resistance battery (row-7, wave-138 lane).

Row-7 residual (wave-137): the similarity countermand's 0.5
token-Tversky threshold is a FIXED, attacker-visible constant
(``gov/intent_ledger.py::similarity_countermand`` reusing
``gov/target_match.py::DEFAULT_THRESHOLD``). An attacker can probe
with crafted messages, bisect to the exact flip point, and sit just
under it (0.499...) with the negation cue intact.

Wave-138 hardens the seam: the decision threshold is derived per
message as ``HMAC-SHA256(deployment_key, domain || message)`` mapped
into [0.4, 0.6) -- mean 0.5, the nominal operating point
(``DEFAULT_THRESHOLD`` stays the nominal reference in
``gov/target_match.py``). The key comes from the EXISTING
key-provider seam (``gov.keyprovider.resolve_active_key``); no key is
hardcoded or committed. Deterministic per deployment, unpredictable
without the key. Band rationale (documented, not hidden):
  - max threshold 0.6 < 0.8: high-similarity countermands always fire;
  - min threshold 0.4 > 0.3: low-similarity messages never fire;
  - half-width 0.1: fine-step sweeping cannot localize one flip point.

Probe map (30 message families x graded-similarity steps against one
anchor, all carrying a negation cue):
  p1 no_fixed_flip_point: for each family find the accept/revoke flip
     interval over the similarity sweep. HELD iff the flip midpoints
     are NOT a single fixed value (spread > 0.05). Pre-seam RED: every
     family flips at ~0.487 (spread 0.005) -> BREAK.
  p2 near_identical_similarity_different_verdicts: message pairs from
     different families with |sim_a - sim_b| <= 0.005 but different
     verdicts. Pre-seam RED: impossible (verdict is a pure function of
     score) -> BREAK.
  p3 high_similarity_still_revokes: negation-cued messages with
     similarity >= 0.8 all fire (regression pin; HELD in both eras).
  p4 low_similarity_never_revokes: negation-cued messages with
     similarity <= 0.3 never fire (regression pin; HELD in both eras).
  p5 same_key_agrees: identical deployment key -> identical verdicts
     and thresholds over the corpus, twice (per-deployment
     determinism; HELD in both eras).
  p6 different_keys_diverge [DOCUMENTED EXPECTED DIVERGENCE, not a
     product miss]: two deployments with different keys disagree on
     edge-case verdicts -- the intended consequence of keying the
     threshold. Pre-seam RED: the threshold is key-independent, so
     verdicts agree -> BREAK (calibration possible across
     deployments). Post-seam: EXPECTED-DIVERGENCE (labeled).

Verdicts: HELD / BREAK / ERROR / EXPECTED-DIVERGENCE; deterministic
across 2 in-process runs. $0, stdlib only.

Honest ceilings (documented, not hidden): full synonym replacement
still misses (zero shared tokens); the deployment key must be managed
like other secrets -- if the attacker learns it, calibration returns;
the key-provider seam's own custody story (wave-81: explicit
provisioning, fail-closed, no dev fallback) applies unchanged.
"""

import itertools
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _provision_keys():
    import secrets
    os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
    os.environ.setdefault("GOV_LOG_KEY_EPOCH", "threshold-calibration")


_provision_keys()

from gov.intent_ledger import similarity_countermand  # noqa: E402
from gov.target_match import target_similarity  # noqa: E402

try:
    from gov.intent_ledger import derive_countermand_threshold
    _HAS_DERIVE = True
except ImportError:  # pre-hardening tree: the seam does not exist yet
    derive_countermand_threshold = None
    _HAS_DERIVE = False


ANCHOR = "Send the Q3 report to the vendor."
PRINCIPAL_PRIORS = [ANCHOR]

_POOL = ("please kindly review attached memo today regarding quarterly "
         "budget planning session notes draft final copy archive folder "
         "item ticket queue backlog summary brief deck slides appendix "
         "index glossary alpha bravo charlie delta echo foxtrot gamma "
         "hotel india juliet kilo lima mike november").split()
_LEADS = ["Do not", "Please do not", "Never"]
_WORDS = ["send", "q3", "report", "vendor"]
_SHARED_SETS = ([set(c) for c in itertools.combinations(_WORDS, 2)]
                + [set(c) for c in itertools.combinations(_WORDS, 3)])


def _build_corpus():
    """(family_id, message, similarity) for graded sweeps 0.28 -> 0.92.

    One family = (negation lead-in, shared-token set); each family
    sweeps filler-token count so similarity descends in fine steps.
    Every message carries a negation cue.
    """
    corpus = []
    for lead in _LEADS:
        for shared in _SHARED_SETS:
            fam = "%s|%s" % (lead, "+".join(sorted(shared)))
            filler = 0
            while filler <= 48:
                msg = "%s %s %s" % (lead, " ".join(sorted(shared)),
                                    " ".join(_POOL[:filler]))
                sim = target_similarity(msg, ANCHOR)
                corpus.append((fam, msg.strip(), sim))
                filler += 1
                if sim <= 0.28:
                    break
    return corpus


_CORPUS = _build_corpus()
_FAMILIES = sorted(set(f for f, _, _ in _CORPUS))


def _verdict(msg):
    fired, _, _ = similarity_countermand(msg, PRINCIPAL_PRIORS)
    return fired


def p1_no_fixed_flip_point():
    """The accept/revoke boundary is not a single fixed value."""
    mids = []
    table = []
    for fam in _FAMILIES:
        steps = sorted((s for f, _, s in _CORPUS if f == fam))
        scored = [(s, m) for f, m, s in _CORPUS if f == fam]
        fired = [(s, _verdict(m)) for s, m in scored]
        lo_steps = [s for s, v in fired if not v]
        hi_steps = [s for s, v in fired if v]
        if not lo_steps or not hi_steps:
            return ("ERROR", "family %s never flips "
                    "(lo=%d hi=%d) -- corpus premise broken"
                    % (fam, len(lo_steps), len(hi_steps)))
        lo, hi = max(lo_steps), min(hi_steps)
        mid = (lo + hi) / 2.0
        mids.append(mid)
        table.append((fam, lo, hi, mid))
    spread = max(mids) - min(mids)
    detail = ("flip-mid spread %.4f over %d families "
              "(min %.4f, max %.4f)" % (spread, len(mids),
                                        min(mids), max(mids)))
    if spread > 0.05:
        return ("HELD", detail + ": no single calibratable flip point")
    return ("BREAK", detail + ": flip point is effectively FIXED -- "
            "an attacker sweeping 0.30->0.70 can calibrate to it and "
            "sit just under it")


def p2_near_identical_similarity_different_verdicts():
    """Verdict is not a pure function of similarity score."""
    scored = [(_verdict(m), s, f) for f, m, s in _CORPUS]
    pairs = 0
    examples = []
    for i in range(len(scored)):
        v1, s1, f1 = scored[i]
        for j in range(i + 1, len(scored)):
            v2, s2, f2 = scored[j]
            if f1 == f2 or v1 == v2:
                continue
            if abs(s1 - s2) <= 0.005:
                pairs += 1
                if len(examples) < 3:
                    examples.append((s1, s2, v1, v2))
    if pairs >= 5:
        return ("HELD", "%d cross-family pairs with |dsim| <= 0.005 but "
                "different verdicts (e.g. %s): similarity alone does "
                "not determine the verdict" % (pairs, examples[0]))
    return ("BREAK", "only %d near-identical-similarity pairs with "
            "different verdicts: the verdict is (nearly) a pure "
            "function of score -- calibration possible" % pairs)


_HIGH_SIM = [
    "Do not send the Q3 report to the vendor",
    "Please do not send the Q3 report to the vendor",
    "Never send the Q3 report to the vendor",
    "Do not ever send the Q3 report to the vendor",
    "Please do not ever send that Q3 report to the vendor",
    "Never send that Q3 report to the vendor anywhere",
    "Do not send the Q3 report to the vendor please",
    "Please refrain from sending the Q3 report to the vendor",
    "Do not send that Q3 report to the vendor today",
    "Never ever send the Q3 report to the vendor",
    "Do not send that Q3 report to the vendor now",
    "Please do not send the Q3 report over to the vendor",
    "Never send the Q3 report to that vendor",
]


def p3_high_similarity_still_revokes():
    """Negation-cued messages with similarity >= 0.8 always fire."""
    for m in _HIGH_SIM:
        s = target_similarity(m, ANCHOR)
        if s < 0.8:
            return ("ERROR", "battery premise broken: %r scores %.3f "
                    "(need >= 0.8)" % (m, s))
    missed = [m for m in _HIGH_SIM if not _verdict(m)]
    if not missed:
        return ("HELD", "all %d high-similarity (>= 0.8) negated "
                "messages fire (max derived threshold 0.6 < 0.8)"
                % len(_HIGH_SIM))
    return ("BREAK", "high-similarity countermands MISSED: %r"
            % (missed,))


_LOW_SIM = [
    "Do not touch the production database tonight",
    "Never deploy on Fridays without approval",
    "Please do not restart the cluster during business hours",
    "Do not share credentials over chat",
    "Never bypass the review queue for hotfixes",
    "Please do not email the customer list externally",
    "Do not merge without a green build",
    "Never disable the alarm system remotely",
    "Please do not rotate keys during the migration",
    "Do not open the firewall to the public internet",
    "Never skip the backup before patching",
    "Please do not publish the draft roadmap",
]


def p4_low_similarity_never_revokes():
    """Negation-cued messages with similarity <= 0.3 never fire."""
    for m in _LOW_SIM:
        s = target_similarity(m, ANCHOR)
        if s > 0.3:
            return ("ERROR", "battery premise broken: %r scores %.3f "
                    "(need <= 0.3)" % (m, s))
    fired = [m for m in _LOW_SIM if _verdict(m)]
    if not fired:
        return ("HELD", "all %d low-similarity (<= 0.3) negated "
                "messages stay silent (min derived threshold "
                "0.4 > 0.3)" % len(_LOW_SIM))
    return ("BREAK", "low-similarity messages FALSELY revoked: %r"
            % (fired,))


def p5_same_key_agrees():
    """Identical deployment key -> identical verdicts (determinism)."""
    first = [_verdict(m) for _, m, _ in _CORPUS]
    second = [_verdict(m) for _, m, _ in _CORPUS]
    if first != second:
        return ("BREAK", "verdicts not deterministic within one "
                "deployment -- do not trust")
    if _HAS_DERIVE:
        t1 = [derive_countermand_threshold(m) for _, m, _ in _CORPUS]
        t2 = [derive_countermand_threshold(m) for _, m, _ in _CORPUS]
        if t1 != t2:
            return ("BREAK", "derived thresholds not deterministic "
                    "within one deployment")
        if not all(0.4 <= t < 0.6 for t in t1):
            return ("BREAK", "derived threshold outside [0.4, 0.6): "
                    "band contract violated")
        return ("HELD", "%d verdicts and %d derived thresholds "
                "identical across runs (band [0.4, 0.6) holds)"
                % (len(first), len(t1)))
    return ("HELD", "%d verdicts identical across runs "
            "(derive seam absent pre-hardening)" % len(first))


def p6_different_keys_diverge():
    """[DOCUMENTED EXPECTED DIVERGENCE] Different deployment keys
    disagree on edge-case verdicts -- the intended consequence of
    keying the threshold, labeled not a product miss."""
    import secrets
    edge = [(m, s) for _, m, s in _CORPUS if 0.42 <= s <= 0.58]
    edge = sorted(edge, key=lambda ms: ms[1])
    edge = [m for i, (m, _) in enumerate(edge) if i % 2 == 0][:48]
    if len(edge) < 16:
        return ("ERROR", "edge set too small (%d) -- corpus premise "
                "broken" % len(edge))
    saved = os.environ.get("GOV_LOG_KEY")
    saved_epoch = os.environ.get("GOV_LOG_KEY_EPOCH")
    try:
        k1, k2 = secrets.token_hex(32), secrets.token_hex(32)
        os.environ["GOV_LOG_KEY"] = k1
        os.environ["GOV_LOG_KEY_EPOCH"] = "calib-k1"
        v1 = [_verdict(m) for m in edge]
        t1 = ([derive_countermand_threshold(m) for m in edge]
              if _HAS_DERIVE else None)
        os.environ["GOV_LOG_KEY"] = k2
        os.environ["GOV_LOG_KEY_EPOCH"] = "calib-k2"
        v2 = [_verdict(m) for m in edge]
        t2 = ([derive_countermand_threshold(m) for m in edge]
              if _HAS_DERIVE else None)
    finally:
        if saved is None:
            os.environ.pop("GOV_LOG_KEY", None)
        else:
            os.environ["GOV_LOG_KEY"] = saved
        if saved_epoch is None:
            os.environ.pop("GOV_LOG_KEY_EPOCH", None)
        else:
            os.environ["GOV_LOG_KEY_EPOCH"] = saved_epoch
    n_verdict_diff = sum(1 for a, b in zip(v1, v2) if a != b)
    if not _HAS_DERIVE:
        # Pre-hardening: the threshold ignores the key entirely.
        if n_verdict_diff == 0:
            return ("BREAK", "threshold is KEY-INDEPENDENT: two "
                    "deployments agree on all %d edge verdicts -- an "
                    "attacker who calibrates one deployment calibrates "
                    "them all" % len(edge))
        return ("ERROR", "unexpected divergence without the derive "
                "seam -- investigate")
    n_thresh_diff = sum(1 for a, b in zip(t1, t2) if a != b)
    detail = ("derived thresholds differ on %d/%d edge messages; "
              "verdicts differ on %d/%d"
              % (n_thresh_diff, len(edge), n_verdict_diff, len(edge)))
    if n_thresh_diff >= 1 and n_verdict_diff >= 1:
        return ("EXPECTED-DIVERGENCE", detail + " -- documented: "
                "keying the threshold makes edge verdicts "
                "deployment-specific by design")
    return ("ERROR", detail + " -- divergence premise broken, "
            "investigate (P(no verdict divergence) ~ 1e-9)")


PROBES = [p1_no_fixed_flip_point,
          p2_near_identical_similarity_different_verdicts,
          p3_high_similarity_still_revokes,
          p4_low_similarity_never_revokes,
          p5_same_key_agrees,
          p6_different_keys_diverge]


def run_once():
    out = []
    for p in PROBES:
        try:
            out.append((p.__name__,) + p())
        except Exception as e:  # noqa: BLE001 - probe must not die
            out.append((p.__name__, "ERROR", "%s: %s"
                        % (type(e).__name__, e)))
    return out


def main():
    first = run_once()
    second = run_once()
    det = ([v for _, v, _ in first] == [v for _, v, _ in second])
    n_break = sum(1 for _, v, _ in first if v == "BREAK")
    n_held = sum(1 for _, v, _ in first if v == "HELD")
    n_err = sum(1 for _, v, _ in first if v == "ERROR")
    n_div = sum(1 for _, v, _ in first if v == "EXPECTED-DIVERGENCE")
    print("threshold-calibration battery: %d BREAK / %d HELD / "
          "%d EXPECTED-DIVERGENCE / %d ERROR (deterministic across 2 "
          "runs: %s)" % (n_break, n_held, n_div, n_err, det))
    for name, verdict, detail in first:
        print("  %-46s %-18s %s" % (name, verdict, detail))
    print("  NOTE: EXPECTED-DIVERGENCE is the documented, intended "
          "consequence of keying the threshold (p6), not a miss.")
    if not det:
        print("NON-DETERMINISTIC across runs -- do not trust")
        return 2
    if n_err or n_break:
        print("unexpected BREAK/ERROR -- battery failed")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
