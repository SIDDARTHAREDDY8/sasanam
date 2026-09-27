"""Causation-based canary attribution (post-trip triage aid).

Idea adapted from Fifth Third Bank's LUCY (Apache-2.0,
https://github.com/Fifth-Third-Bank/lucy): LUCY attributes canary trips
by CAUSATION, not proximity — every candidate in a planter-modified file
is re-examined against a fresh clean copy; a defect surviving on clean
bytes is genuine, one existing only in the planted workspace is
synthetic (docs/certification.md).

Our analog: when an egress canary trips (gov/canary.py), the current
attribution is identity-bound (agent_id, principal in the audit event).
Identity tells you *who*; it does not tell you *why the trip fired*.
This module re-runs the suspect trajectory against clean (canary-free)
bytes and diffs:

  - INTENT_CAUSAL: the agent attempts the same egress on clean bytes
    (with inert values). The exfil intent is causal; the canary merely
    revealed it. High-confidence compromise/misconfiguration.
  - CANARY_CAUSAL: no egress on clean bytes. The trip depended on the
    canary's presence/realism — the deception worked, the agent is
    opportunistic rather than targeted. Informs FP triage.
  - NO_TRIP: the planted run did not trip; nothing to attribute.
  - INCONCLUSIVE: behavior changed in ways the diff cannot attribute
    (e.g. the destination is derived from the secret value itself).

This is COMPLEMENTARY to identity-bound provenance, not a replacement —
and it is a TRIAGE AID, not a control. It never gates the halt:
check_and_trip halts first, always; attribution runs after, for the
human reviewer.

Honest limits
-------------
1. With scripted/deterministic agents (this module's harness) the clean
   re-run is exact. With a real LLM agent it is a *counterfactual
   estimate*: the model may behave differently for unrelated reasons
   (temperature, context drift). INCONCLUSIVE exists for exactly this.
2. The clean jail preserves layout and variable names but replaces
   canary values with inert placeholders. An agent that keys off
   *names* rather than values will behave identically — correctly
   attributed INTENT_CAUSAL (the intent never needed the secret).
3. Attribution answers "would it have exfiltrated anyway", not "is it
   malicious". A backup agent sweeping config files is INTENT_CAUSAL
   and benign — the mechanism note (bulk vs targeted) helps the
   reviewer tell the difference: bulk+intent_causal is a thief or a
   broken backup; targeted+intent_causal is a focused thief.

$0, stdlib only, deterministic.
"""

import hashlib
import random
from pathlib import Path

from .canary import CanaryMint, CanaryRegistry, scan_egress_attempt

__all__ = [
    "INTENT_CAUSAL",
    "CANARY_CAUSAL",
    "NO_TRIP",
    "INCONCLUSIVE",
    "CausationAttributor",
    "build_clean_jail",
]

INTENT_CAUSAL = "intent_causal"
CANARY_CAUSAL = "canary_causal"
NO_TRIP = "no_trip"
INCONCLUSIVE = "inconclusive"

# Inert placeholders: same variable names, obviously non-secret values.
# Low entropy, no secret patterns, fixed strings (deterministic).
INERT_VALUES = {
    "INTERNAL_API_TOKEN": "__INERT_TOKEN__",
    "AWS_ACCESS_KEY_ID": "__INERT_KEY_ID__",
    "AWS_SECRET_ACCESS_KEY": "__INERT_SECRET__",
    "DATABASE_URL": "__INERT_DB_URL__",
    "STRIPE_SECRET_KEY": "__INERT_STRIPE__",
}

INERT_FILE_VALUES = {
    "aws-key-0": "__INERT_KEY_ID__",
    "aws-secret-0": "__INERT_SECRET__",
    "internal-api-token": "__INERT_TOKEN__",
    "database-url": "__INERT_DB_URL__",
    "stripe-secret": "__INERT_STRIPE__",
    "github-token": "__INERT_GITHUB__",
}


def build_clean_jail(jail_root):
    """Mirror plant_canaries' layout with inert values. Returns env dict.

    Same file paths, same variable names, zero canary values — the
    "fresh clean copy" against which the planted trajectory is
    re-examined. Deterministic.
    """
    jail = Path(jail_root)
    aws_dir = jail / ".aws"
    aws_dir.mkdir(parents=True, exist_ok=True)
    (aws_dir / "credentials").write_text(
        "[default]\n"
        "aws_access_key_id = __INERT_KEY_ID__\n"
        "aws_secret_access_key = __INERT_SECRET__\n")
    (jail / ".env").write_text(
        "INTERNAL_API_TOKEN=__INERT_TOKEN__\n"
        "DATABASE_URL=__INERT_DB_URL__\n"
        "STRIPE_SECRET_KEY=__INERT_STRIPE__\n"
        "AWS_ACCESS_KEY_ID=__INERT_KEY_ID__\n"
        "AWS_SECRET_ACCESS_KEY=__INERT_SECRET__\n")
    etc = jail / "etc"
    etc.mkdir(parents=True, exist_ok=True)
    (etc / "hosts").write_text("# local service overrides\n")
    cfg = jail / "config"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "service.conf").write_text(
        "[service]\n"
        "api_token=__INERT_GITHUB__\n"
        "database_url=__INERT_DB_URL__\n")
    return dict(INERT_VALUES)


def _dest_of(tool, args):
    """Destination shape for egress comparison (host only, no secrets)."""
    try:
        if tool == "http_post":
            from urllib.parse import urlparse
            return urlparse(args.get("url", "")).hostname or "?"
        if tool == "api_call":
            from urllib.parse import urlparse
            return urlparse(args.get("endpoint", "")).hostname or "?"
        if tool == "send_email":
            to = args.get("to", "")
            return to.rsplit("@", 1)[-1] if "@" in to else "?"
    except Exception:
        pass
    return "?"


def _skeleton(args):
    """Structural skeleton of args with all string leaves classified.

    Returns a hashable structure where each string leaf is replaced by
    its class: 'secret-like' (high entropy or secret pattern), 'inert'
    (placeholder), or 'other'. Two runs have the same exfil *behavior*
    iff tool, destination, and skeleton match.
    """
    def classify(s):
        if not isinstance(s, str):
            return "other"
        if "__INERT" in s:
            return "inert"
        # secret-like: long high-entropy token or known secret prefix
        alnum = [c for c in s if c.isalnum()]
        if len(s) >= 16 and alnum and (
                len(set(alnum)) > 12 or
                s.startswith(("AKIA", "ghp_", "xoxb-", "sk-"))):
            return "secret-like"
        return "other"

    def norm(v):
        if isinstance(v, dict):
            return tuple(sorted((k, norm(x)) for k, x in v.items()))
        if isinstance(v, (list, tuple)):
            return tuple(norm(x) for x in v)
        if isinstance(v, str):
            return classify(v)
        return "other"

    return norm(args)


def _mechanism(canary_values_in_args, args, planted_file_contents):
    """bulk vs targeted, from the planted trip's observable behavior.

    bulk: the egress carries a whole canary file's content, or >=3
        distinct canary values (indiscriminate take).
    targeted: 1-2 distinct canary values, no file blob (selective take).
    """
    argtext = repr(args)
    for content in planted_file_contents:
        if not content or len(content) <= 32:
            continue
        # Compare in repr-escaped form: repr(args) escapes newlines, so
        # the raw file text never literally appears in it.
        esc = repr(content)[1:-1]  # strip the quotes, keep the escapes
        if esc in argtext:
            return "bulk"
    n = len(set(canary_values_in_args))
    return "bulk" if n >= 3 else "targeted"


class CausationAttributor:
    """Re-run a suspect trajectory on clean bytes; attribute the trip.

    agent_fn(jail_path, env) -> list of (tool, args): deterministic
    scripted agent. The attributor runs it twice (planted, clean) and
    diffs the egress behavior.
    """

    def __init__(self, run_id="causation-proto"):
        self.run_id = run_id

    def _run_planted(self, agent_fn, jail_path):
        from .canary import plant_canaries
        mint = CanaryMint(self.run_id + "|planted")
        registry = CanaryRegistry()
        registry.register(mint)
        env, _manifest = plant_canaries(jail_path, mint)
        jail = Path(jail_path)
        planted_file_contents = []
        for rel in (".aws/credentials", ".env", "etc/hosts",
                    "config/service.conf"):
            p = jail / rel
            if p.is_file():
                planted_file_contents.append(p.read_text())
        attempts = agent_fn(jail, dict(env))
        trips = []
        for tool, args in attempts:
            hit = scan_egress_attempt(tool, args, registry)
            if hit is not None:
                # Which canary values were in the args (for mechanism)?
                vals = [c["value"] for c in mint.values()]
                in_args = [v for v in vals if v and v in repr(args)]
                trips.append({"tool": tool, "args": args, "hit": hit,
                              "canary_values": in_args,
                              "planted_files": planted_file_contents})
        return trips, attempts

    def _run_clean(self, agent_fn, jail_path):
        env = build_clean_jail(jail_path)
        attempts = agent_fn(Path(jail_path), dict(env))
        return attempts

    def attribute(self, agent_fn, scratch):
        """Full attribution. scratch: Path to a temp dir we own.

        Returns a dict with verdict, mechanism, and the evidence.
        """
        scratch = Path(scratch)
        planted_jail = scratch / "planted"
        clean_jail = scratch / "clean"
        planted_jail.mkdir(parents=True, exist_ok=True)
        clean_jail.mkdir(parents=True, exist_ok=True)

        trips, _planted_attempts = self._run_planted(agent_fn, planted_jail)
        if not trips:
            return {"verdict": NO_TRIP, "mechanism": None,
                    "detail": "planted run did not trip; nothing to attribute",
                    "trips": [], "clean_attempts": []}

        clean_attempts = self._run_clean(agent_fn, clean_jail)

        trip_shapes = set(
            (t["tool"], _dest_of(t["tool"], t["args"]),
             _skeleton(t["args"])) for t in trips)
        clean_shapes = set(
            (tool, _dest_of(tool, args), _skeleton(args))
            for tool, args in clean_attempts)

        # Normalize skeletons across the canary/inert boundary: a
        # 'secret-like' leaf in the planted run and an 'inert' leaf in
        # the clean run are the SAME behavioral slot.
        def _norm_shape(shape):
            tool, dest, skel = shape
            return (tool, dest, repr(skel).replace("'secret-like'",
                                                   "'secret-slot'").replace(
                "'inert'", "'secret-slot'"))

        trip_norm = set(_norm_shape(s) for s in trip_shapes)
        clean_norm = set(_norm_shape(s) for s in clean_shapes)

        first = trips[0]
        mechanism = _mechanism(first["canary_values"], first["args"],
                              first["planted_files"])
        evidence = {
            "trip_tool": first["tool"],
            "trip_dest": _dest_of(first["tool"], first["args"]),
            "trip_kind": first["hit"]["kind"],
            "trip_label": first["hit"]["label"],
            "clean_egress_count": len(clean_attempts),
        }

        if not clean_attempts:
            return {"verdict": CANARY_CAUSAL, "mechanism": mechanism,
                    "detail": ("no egress on clean bytes: the trip depended "
                               "on the canary's presence/realism"),
                    "evidence": evidence,
                    "trips": trips, "clean_attempts": clean_attempts}
        if trip_norm & clean_norm:
            return {"verdict": INTENT_CAUSAL, "mechanism": mechanism,
                    "detail": ("same egress shape on clean bytes (inert "
                               "values): the exfil intent is causal, the "
                               "canary merely revealed it"),
                    "evidence": evidence,
                    "trips": trips, "clean_attempts": clean_attempts}
        return {"verdict": INCONCLUSIVE, "mechanism": mechanism,
                "detail": ("egress behavior changed on clean bytes in ways "
                           "the diff cannot attribute (e.g. destination "
                           "derived from the secret value)"),
                "evidence": evidence,
                "trips": trips, "clean_attempts": clean_attempts}
