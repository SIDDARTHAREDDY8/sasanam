"""S3 (K-041): tool reversibility/impact rating tests.

Verifies the S3 control surface:

* An unrated MUTATING tool must be forced to ``require_approval``
  with flag ``unrated_mutating_tool`` (policy_id
  ``tool-rating-default``) — never allowed silently.
* The six core tools keep their existing allow paths (no S3
  interference).
* ``api_call`` stays read-classified (not mutating).
* The deployment ``tool_ratings`` graduation path: a deployment can
  rate a new tool; malformed ratings fail closed at construction.
* ``policy_lint`` is advisory: warnings never flip a deny to allow
  (or an allow to deny).

S3-GAP-1 (executor computed ``_forced_require_approval`` but never
applied it — dead code, so an unrated mutating tool matching an allow
rule executed silently) was CLOSED wave-39: the guard is wired in
``gov/executor.py`` (allow -> require_approval downgrade; deny stays
deny) and ``install_package`` carries a default rating so the P7
governed-install close-out still executes. The forcing test below is
a live assertion, not expectedFailure.

Deterministic, stdlib only (unittest), no network, no real systems.
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from gov import policy_lint  # noqa: E402
from gov.executor import _MUTATING_TOOLS  # noqa: E402
from gov.tool_ratings import (  # noqa: E402
    DEFAULT_TOOL_RATINGS,
    is_destructive,
    normalize_tool_ratings,
)
from tests.harness import make_run  # noqa: E402

_SIX_CORE = ["read_file", "write_file", "delete_file", "send_email",
             "http_post", "api_call"]

_CORE_POLICY = """\
version: 2
roles:
  all: [read_file, write_file, delete_file, send_email, http_post, api_call]
rate_limit:
  max_sends_per_run: 100
  max_egress_bytes_per_run: 262144
egress:
  domain_allowlist: [synthetic.local, localhost]
policies:
  - id: test-allow-core
    effect: allow
    match:
      tool: [read_file, write_file, delete_file, http_post, api_call]
    reason: Test policy allows the non-send core tools.
  - id: test-allow-sends
    effect: allow
    match:
      tool: [send_email]
      domain_allowlisted: true
    reason: Test policy allows allowlisted sends.
"""


def _tmpdir(prefix):
    base = Path("/tmp/gov-run")
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(base)))


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return str(path)


class TestRatings(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmpdir("govs3-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    # -- the unrated-mutating-tool forcing (S3-GAP-1 closed wave-39) ----

    def test_unrated_mutating_tool_forced_require_approval(self):
        """S3-GAP-1: an unrated mutating tool must queue for approval
        with flag unrated_mutating_tool — never execute silently.

        The role allows the new tool and an allow rule matches it
        (empty match); without the S3 forcing decision the call
        executes, which is the gap."""
        policy_path = _write(
            self.tmp / "unrated.yaml", """\
version: 2
roles:
  ops: [db_wipe, read_file]
rate_limit:
  max_sends_per_run: 100
  max_egress_bytes_per_run: 262144
egress:
  domain_allowlist: [synthetic.local, localhost]
policies:
  - id: test-blanket-allow
    effect: allow
    reason: Test empty-match allow (the linter flags this; the engine honors it).
""")
        run = make_run(policy_path=policy_path)
        ident = run["mint_identity"]("o1", "ops", "acme")
        r = run["executor"].call(ident, "db_wipe", target="prod")
        self.assertEqual(r["status"], "queued", r)
        self.assertEqual(r["policy_id"], "tool-rating-default", r)
        queued = [e for e in run["read_log"]()
                  if e.get("decision") == "queued_pending"]
        self.assertTrue(queued, "expected a queued_pending audit entry")
        self.assertEqual(queued[-1]["flag"], "unrated_mutating_tool")
        self.assertEqual(queued[-1]["policy_id"], "tool-rating-default")

    # -- core tools keep their allow paths --------------------------------

    def test_six_core_tools_keep_allow_paths(self):
        """None of the six core tools may be diverted into the
        unrated-mutating-tool path: their allow behavior is unchanged."""
        policy_path = _write(self.tmp / "core.yaml", _CORE_POLICY)
        run = make_run(policy_path=policy_path)
        ex = run["executor"]
        ident = run["mint_identity"]("c1", "all", "acme")

        results = {}
        results["read_file"] = ex.call(ident, "read_file",
                                       path="notes.txt")["status"]
        results["api_call"] = ex.call(
            ident, "api_call",
            endpoint="https://synthetic.local/core")["status"]
        results["write_file"] = ex.call(
            ident, "write_file", path="out.txt",
            content="core")["status"]
        results["delete_file"] = ex.call(
            ident, "delete_file", path="out.txt")["status"]
        results["http_post"] = ex.call(
            ident, "http_post", url="https://synthetic.local/hook",
            body="core")["status"]
        results["send_email"] = ex.call(
            ident, "send_email", to="ops@synthetic.local",
            subject="core", body="core")["status"]

        for tool in _SIX_CORE:
            self.assertEqual(results[tool], "executed",
                             "core tool %r lost its allow path: %r"
                             % (tool, results[tool]))
        flags = {e.get("flag") for e in run["read_log"]()}
        self.assertNotIn("unrated_mutating_tool", flags)
        policy_ids = {e.get("policy_id") for e in run["read_log"]()}
        self.assertNotIn("tool-rating-default", policy_ids)

    def test_api_call_stays_read_classified(self):
        """api_call is read-classified (F1): reversible, no write
        access, no financial impact — and NOT in the mutating set."""
        rating = DEFAULT_TOOL_RATINGS["api_call"]
        self.assertEqual(rating["reversibility"], "reversible")
        self.assertEqual(rating["write_access"], "none")
        self.assertEqual(rating["financial_impact"], "none")
        self.assertNotIn("api_call", _MUTATING_TOOLS)
        self.assertFalse(is_destructive(rating))

    def test_mutating_tool_set(self):
        """The executor's mutating set is exactly the four documented
        mutating core tools."""
        self.assertEqual(set(_MUTATING_TOOLS),
                         {"write_file", "delete_file", "send_email",
                          "http_post"})

    # -- deployment graduation path ----------------------------------------

    def test_deployment_rating_graduates_new_tool(self):
        """A deployment can rate a NEW tool; the merged table carries
        it while the defaults are untouched."""
        merged = normalize_tool_ratings({
            "db_wipe": {"reversibility": "reversible",
                        "write_access": "own-sandbox",
                        "financial_impact": "none"},
        })
        self.assertEqual(merged["db_wipe"]["reversibility"], "reversible")
        self.assertNotIn("db_wipe", DEFAULT_TOOL_RATINGS)
        for tool in _SIX_CORE:
            self.assertEqual(merged[tool], DEFAULT_TOOL_RATINGS[tool])

    def test_deployment_rating_overrides_core_field(self):
        merged = normalize_tool_ratings({
            "send_email": {"financial_impact": "high"},
        })
        self.assertEqual(merged["send_email"]["financial_impact"], "high")
        self.assertEqual(merged["send_email"]["reversibility"],
                         "irreversible")  # other fields preserved
        # The module default is never mutated.
        self.assertEqual(
            DEFAULT_TOOL_RATINGS["send_email"]["financial_impact"], "low")

    def test_malformed_rating_fails_closed_at_construction(self):
        """A misrated tool must never silently govern: unknown fields
        and out-of-set values raise at executor-construction time."""
        with self.assertRaises(ValueError):
            normalize_tool_ratings({
                "db_wipe": {"reversibility": "sort_of"},
            })
        with self.assertRaises(ValueError):
            normalize_tool_ratings({
                "db_wipe": {"no_such_field": "reversible"},
            })
        with self.assertRaises(ValueError):
            normalize_tool_ratings({"db_wipe": "reversible"})

    # -- lint is advisory ---------------------------------------------------

    def test_policy_lint_warning_never_flips_deny_to_allow(self):
        """Lint findings are advisory: running the linter over a
        policy must not change what the engine enforces — a deny stays
        a deny and an allow stays an allow."""
        policy_path = _write(
            self.tmp / "lintadv.yaml", """\
version: 2
roles:
  sender: [send_email, http_post]
rate_limit:
  max_sends_per_run: 100
  max_egress_bytes_per_run: 262144
egress:
  domain_allowlist: [synthetic.local, localhost]
policies:
  - id: test-broad-allow-send
    effect: allow
    match:
      tool: [send_email]
    reason: Test broad allow (linter should warn: dangerous tool, no constraints).
  - id: test-deny-post
    effect: deny
    match:
      tool: [http_post]
    reason: Test deny must survive lint.
""")
        from gov.policy import PolicyEngine
        engine = PolicyEngine(policy_path)

        def decide(tool):
            action = {"tool": tool, "args": {}, "role": "sender",
                      "agent_id": "a1"}
            return engine.evaluate(action, {"domain_allowlisted": True})

        before = (decide("send_email").effect, decide("http_post").effect)
        findings = policy_lint.lint_file(policy_path)
        warns = [f for f in findings if f.get("severity") == "warning"]
        self.assertTrue(warns,
                        "expected at least one lint warning, got %r"
                        % (findings,))
        after = (decide("send_email").effect, decide("http_post").effect)
        self.assertEqual(before, after,
                         "lint run changed enforcement: %r -> %r"
                         % (before, after))
        self.assertEqual(after, ("allow", "deny"))


if __name__ == "__main__":
    unittest.main()
