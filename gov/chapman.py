"""Chapman capture-recapture estimator for attack-surface coverage measurement.

Adapted from an idea in Fifth Third Bank's LUCY repo (Apache-2.0,
https://github.com/Fifth-Third-Bank/lucy — lucy/runtime/seal.py): LUCY
applies the Chapman estimator from wildlife ecology to bound
vulnerability-discovery coverage per code unit (>= 0.95 required).

Our analog: the attack program's probe batteries claim coverage of
incident/attack classes, but we had no *measured* bound on what fraction
of an attack-shape space our probes actually exercise. This module is
the pure math; see evals/chapman_row1_coverage.py for the Row-1
application.

The estimator
-------------
Two independent "capture occasions" (e.g. two probe batteries written by
different lanes at different times). Occasion 1 "captures" n1 distinct
attack shapes; occasion 2 captures n2; m2 shapes appear in both
("recaptures"). Chapman's bias-corrected estimator of the total shape
population N::

    N_hat = ((n1 + 1) * (n2 + 1) / (m2 + 1)) - 1

with variance::

    Var = ((n1+1)(n2+1)(n1-m2)(n2-m2)) / ((m2+1)^2 (m2+2))

Honest limits (read before citing a number from this module)
------------------------------------------------------------
1. **Closed population.** The estimator assumes no shapes enter or leave
   between occasions. The adversarial shape space is NOT closed — new
   shapes are invented. The estimate is therefore a *lower bound on the
   known/explored space*, never a bound on "all possible attacks".
2. **Equal catchability.** Every shape must be equally likely to be
   "captured" by a probe author. Probe authors do NOT sample uniformly —
   they target the control boundary. Shapes near the boundary are more
   catchable, which biases N_hat *downward* (underestimates the space).
3. **No mark loss / correct identification.** Mapping a probe to a shape
   cell is a judgment call by the analyst. A wrong taxonomy silently
   moves the estimate. The taxonomy must be published alongside any
   number (see evals/chapman_row1_coverage.py SHAPE_TAXONOMY).
4. **Independence of occasions.** The two batteries must be generated
   independently. Two batteries by the same author in one sitting are
   one occasion wearing a trenchcoat.

When these fail, the number is still useful as a *diversity diagnostic*
("our two passes overlap this much, so the explored space is at least
this big") — but it is not a security guarantee. A coverage bound is a
measurement, not a control.

$0, stdlib only, deterministic.
"""

import math

__all__ = [
    "chapman_estimate",
    "chapman_variance",
    "chapman_ci",
    "coverage_report",
]


def chapman_estimate(n1, n2, m2):
    """Chapman bias-corrected population estimate.

    n1, n2: distinct shapes captured on occasions 1 and 2 (non-negative ints).
    m2: shapes captured on BOTH occasions (0 <= m2 <= min(n1, n2)).
    Returns float N_hat. Raises ValueError on bad inputs.
    """
    for name, v in (("n1", n1), ("n2", n2), ("m2", m2)):
        if not isinstance(v, int) or v < 0:
            raise ValueError("%s must be a non-negative int, got %r" % (name, v))
    if m2 > min(n1, n2):
        raise ValueError(
            "m2 (%d) cannot exceed min(n1, n2) (%d)" % (m2, min(n1, n2)))
    return ((n1 + 1) * (n2 + 1) / (m2 + 1)) - 1


def chapman_variance(n1, n2, m2):
    """Chapman variance estimator. Same input contract as chapman_estimate."""
    # Reuse validation by calling the estimator (raises on bad input).
    chapman_estimate(n1, n2, m2)
    num = (n1 + 1) * (n2 + 1) * (n1 - m2) * (n2 - m2)
    den = (m2 + 1) ** 2 * (m2 + 2)
    return num / den


def chapman_ci(n1, n2, m2, z=1.96):
    """(N_hat, lower, upper): normal-approximation confidence interval.

    Lower is floored at max(n1, n2) — the population cannot be smaller
    than what we have already seen.
    """
    n_hat = chapman_estimate(n1, n2, m2)
    se = math.sqrt(chapman_variance(n1, n2, m2))
    lower = max(n_hat - z * se, float(max(n1, n2)))
    return n_hat, lower, n_hat + z * se


def coverage_report(n1, n2, m2, label=""):
    """Human-readable report dict for two probe batteries.

    coverage = |union| / N_hat where |union| = n1 + n2 - m2.
    """
    n_hat, lo, hi = chapman_ci(n1, n2, m2)
    union = n1 + n2 - m2
    return {
        "label": label,
        "n1": n1,
        "n2": n2,
        "m2": m2,
        "union": union,
        "N_hat": round(n_hat, 2),
        "ci95": (round(lo, 2), round(hi, 2)),
        "coverage": round(union / n_hat, 3) if n_hat > 0 else 0.0,
        "caveat": ("Lower bound on the explored shape space only; assumes "
                   "closed population + equal catchability + independent "
                   "occasions. See gov/chapman.py docstring."),
    }
