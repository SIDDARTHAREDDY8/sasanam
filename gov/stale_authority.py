"""Stale-authority probe class (W242-2, emirdag lapse as first instance).

After a draft's lapse, any evidence/verifier path accepting authority
citing that draft as *normative* authority must name the lapse. This
module is the check that makes "green on lapsed authority" a named
refusal instead of a silent pass:

- ``check_authority(authority_id, minted_at)``:
    - authority unknown (a live draft or otherwise unregistered name)
      -> ``{"status": "accepted"}`` with no stale-authority flag. The
      module names lapses; it is not a registry of live drafts.
    - registered authority, ``minted_at`` at or after the lapse instant
      -> refuses ``stale-authority`` with a cause naming the lapse.
    - registered authority, ``minted_at`` before the lapse instant
      -> ``{"status": "accepted", "provenance": "downgraded",
      "annotation": "authority-expired-<date>"}``: the receipt was fine
      when minted, but anything that re-reads it as fresh authority
      sees the downgrade.
    - malformed ``minted_at`` -> refuses ``stale-authority-malformed``
      (fail closed; never a silent pass).

Pre-staged lapse postures: ``draft-veridom-omp-02`` (lapses
2026-11-14) and ``draft-sharif-attp-01`` (lapses 2026-12-05) are
registered with their known expiry instants, so the same refusal
fires the moment they lapse -- no new code, only the clock moving.

Honest residuals:
- Lapse instants are deployment-provided registry data baked from the
  datatracker expiry dates; this module does not consult datatracker
  at runtime. A draft renewed *before* its registered lapse stays
  registered until the deployment updates the registry -- the registry
  is data, not oracle truth.
- ``minted_at`` is caller-supplied. A forged pre-expiry timestamp is
  a timestamp-attestation problem, not an authority-lapse problem.
- "Live draft" here means "not a registered lapsed authority": the
  module cannot prove a draft is alive. The control case is no-flag,
  not proof-of-liveness.

Stdlib only. Deterministic. Fail-closed on malformed input.
"""

from datetime import datetime, timezone

STALE_AUTHORITY = "stale-authority"
STALE_AUTHORITY_MALFORMED = "stale-authority-malformed"

# The emirdag draft lapsed 2026-10-13T20:40:30Z (datatracker expiry;
# verified by the wave-241 prospecting lane).
EMIRDAG_LAPSE_UTC = datetime(2026, 10, 13, 20, 40, 30, tzinfo=timezone.utc)


def _utc(year, month, day):
    return datetime(year, month, day, tzinfo=timezone.utc)


# Registered lapse registry: authority_id -> (lapse instant, annotation).
# Pre-staged entries use the known datatracker expiry dates.
LAPSED_AUTHORITIES = {
    "draft-emirdag-scitt-ai-agent-execution-00": (
        EMIRDAG_LAPSE_UTC, "authority-expired-2026-10-13"),
    "draft-veridom-omp-02": (
        _utc(2026, 11, 14), "authority-expired-2026-11-14"),
    "draft-sharif-attp-01": (
        _utc(2026, 12, 5), "authority-expired-2026-12-05"),
}


class StaleAuthorityError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code."""

    def __init__(self, code, detail):
        super(StaleAuthorityError, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise StaleAuthorityError(code, detail)


def _coerce_utc(value):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    _refuse(STALE_AUTHORITY_MALFORMED,
            "minted_at is not a datetime: %r" % (type(value).__name__,))


def check_authority(authority_id, minted_at):
    """Check whether citing ``authority_id`` as normative authority is
    admissible given the receipt was minted at ``minted_at``."""
    if not isinstance(authority_id, str) or not authority_id:
        _refuse(STALE_AUTHORITY_MALFORMED,
                "authority_id must be a non-empty string")
    entry = LAPSED_AUTHORITIES.get(authority_id)
    if entry is None:
        # Not a registered lapsed authority: no stale-authority flag.
        return {"status": "accepted"}
    lapse, annotation = entry
    minted = _coerce_utc(minted_at)
    if minted >= lapse:
        _refuse(
            STALE_AUTHORITY,
            "cause: authority %s lapsed %s; receipt minted %s cites it "
            "as normative authority after the lapse; a verifier that "
            "passes this receipt has the green-on-lapsed-authority "
            "defect" % (authority_id, lapse.strftime("%Y-%m-%d"),
                        minted.strftime("%Y-%m-%d")))
    return {"status": "accepted", "provenance": "downgraded",
            "annotation": annotation}
