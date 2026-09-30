"""Unit tests for the wave-244 emirdag -00 lapse pin (W244-10, maintenance).

The staged lapse in ``gov/stale_authority.py`` is baked registry data,
not oracle truth. These pins keep it honest against an independent
source of truth: the IETF datatracker's published expiry for
``draft-emirdag-scitt-ai-agent-execution`` (-00), verified 2026-09-30
via the datatracker API:

    "name": "draft-emirdag-scitt-ai-agent-execution",
    "rev": "00",
    "expires": "2026-10-13T20:40:30Z"

plus the maintenance readiness fixture at
``evals/fixtures/emirdag_aauth_olpc_00.pin.md``.

Stdlib unittest only. Deterministic: no network, no clock reads.
"""

import os
import re
import unittest
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import stale_authority as sa

# Independent source of truth: datatracker API record for
# draft-emirdag-scitt-ai-agent-execution, rev 00, fetched 2026-09-30.
DATATRACKER_EXPIRY = datetime(2026, 10, 13, 20, 40, 30, tzinfo=timezone.utc)

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
FIXTURE = os.path.join(REPO_ROOT, "evals", "fixtures",
                       "emirdag_aauth_olpc_00.pin.md")


def _fixture_field(text, name):
    match = re.search(r"^%s:\s*(.+)$" % re.escape(name), text,
                      re.MULTILINE)
    if match is None:
        raise AssertionError("fixture field %r not found" % name)
    return match.group(1).strip()


class EmirdagLapsePinTest(unittest.TestCase):
    def test_staged_lapse_matches_datatracker_expiry(self):
        # The expected value comes from the datatracker record, not from
        # the module under test.
        self.assertEqual(sa.EMIRDAG_LAPSE_UTC, DATATRACKER_EXPIRY)

    def test_fixture_exists_and_names_revision_00(self):
        with open(FIXTURE, "r", encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("draft-emirdag-scitt-ai-agent-execution", text)
        self.assertIn("00", text)

    def test_fixture_lapse_matches_staged_lapse(self):
        with open(FIXTURE, "r", encoding="utf-8") as fh:
            text = fh.read()
        lapse = _fixture_field(text, "Lapse")
        self.assertEqual(
            datetime.strptime(lapse, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc),
            sa.EMIRDAG_LAPSE_UTC)

    def test_fixture_observation_predates_lapse(self):
        # The maintenance check must be proactive: the no-renewal
        # observation was recorded while the draft was still live, so
        # the pin plan is a standing guard, not a post-hoc scramble.
        with open(FIXTURE, "r", encoding="utf-8") as fh:
            text = fh.read()
        observed = _fixture_field(text, "Observed")
        observed_utc = datetime.strptime(
            observed, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        self.assertLess(observed_utc, sa.EMIRDAG_LAPSE_UTC)

    def test_fixture_pin_deadline_predates_lapse(self):
        with open(FIXTURE, "r", encoding="utf-8") as fh:
            text = fh.read()
        deadline = _fixture_field(text, "Pin-deadline")
        deadline_utc = datetime.strptime(
            deadline, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        self.assertLess(deadline_utc, sa.EMIRDAG_LAPSE_UTC)
        self.assertGreater(deadline_utc,
                           datetime(2026, 9, 30, tzinfo=timezone.utc))

    def test_post_lapse_check_still_refuses(self):
        # The wave-242 machinery fires on the pinned instant.
        with self.assertRaises(sa.StaleAuthorityError) as ctx:
            sa.check_authority("draft-emirdag-scitt-ai-agent-execution-00",
                               DATATRACKER_EXPIRY)
        self.assertEqual(ctx.exception.code, "stale-authority")


if __name__ == "__main__":
    unittest.main()
