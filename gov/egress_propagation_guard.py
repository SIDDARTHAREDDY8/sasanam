"""Public-output-channel injection-propagation enforcement (wave-245 lane 8).

The wave-151/152 ``gov.injection_propagation`` seam is TRIAGE TIER ONLY
by design: it flags, never blocks. This module closes the hop-1
enforcement gap for PUBLIC channels: when an injected instruction --
observed from UNTRUSTED input provenance -- is reproduced into an
outbound public channel (email reply, shared doc, public comment), the
egress review REFUSES with ``egress-injection-propagation``. The chain
is broken LOUDLY at hop 1, not discovered at hop 3.

Downstream (the second agent), consumption of a public channel is
recorded with provenance ``public-channel`` via
``consume_public_channel``; ``authorize_instruction`` then refuses to
grant that provenance instruction authority
(``instruction-provenance-public-channel``): public channels are
untrusted input, never instruction authority.

Provenance rule (fail-closed): only provenance in TRUSTED_PROVENANCES
(user / operator / deployment-policy / deployer) is instruction
authority; any other provenance -- and any source whose provenance the
guard never recorded -- is untrusted input. Malformed guard inputs
refuse ``egress-propagation-malformed``.

Deterministic, $0, stdlib-only. Span extraction and matching (exact +
word-boundary-delimited substring) are reused from
gov.injection_propagation -- this module adds the enforcement verdict
and the provenance gate, never a new matcher.

Honest ceilings (documented):
- The guard only sees what the deployment observes into it
  (``observe_input`` / ``consume_public_channel``) or into the shared
  tracker it composes; out-of-band input is invisible by design (the
  same coverage ceiling as wave-151 p11).
- Paraphrased reproductions are invisible (the wave-151 p5 ceiling,
  pinned EXPECTED here as p7).
- A deployment that never calls ``authorize_instruction`` before
  executing source instructions gets no enforcement -- the gate is a
  called seam, not a hook; the refusal is the deployment's to act on.
- Only the deployment's channel-kind declaration decides what is
  "public"; kinds outside PUBLIC_CHANNELS are out of scope (allow,
  scope="not-public-channel").
"""

from . import injection_propagation

__all__ = [
    "PUBLIC_CHANNELS",
    "TRUSTED_PROVENANCES",
    "PUBLIC_PROVENANCE_MARKER",
    "CODE_REFUSAL",
    "CODE_PROVENANCE_PUBLIC",
    "CODE_PROVENANCE_UNTRUSTED",
    "CODE_MALFORMED",
    "PublicChannelGuard",
]

# Outbound channel kinds that cross into public consumption. The
# deployment declares the kind; kinds outside this set are not public
# (the hop-1 refusal is out of scope for them by design).
PUBLIC_CHANNELS = frozenset({
    "email", "email-reply", "shared-doc", "public-comment",
    "social-post", "wiki-page", "blog-post", "forum-post",
})

# Provenance that grants instruction authority. Anything else --
# tool results, retrieved docs, public channels, agent outputs -- is
# untrusted input and can never become instruction authority.
TRUSTED_PROVENANCES = frozenset({
    "user", "operator", "deployment-policy", "deployer",
})

# Provenance marker for content consumed from a public channel.
PUBLIC_PROVENANCE_MARKER = "public-channel"

CODE_REFUSAL = "egress-injection-propagation"
CODE_PROVENANCE_PUBLIC = "instruction-provenance-public-channel"
CODE_PROVENANCE_UNTRUSTED = "instruction-provenance-untrusted"
CODE_MALFORMED = "egress-propagation-malformed"


def _normalize_channel(channel):
    if not isinstance(channel, str):
        return ""
    return channel.strip().lower().replace("_", "-").replace(" ", "-")


def _normalize_provenance(provenance):
    if not isinstance(provenance, str):
        return ""
    return provenance.strip().lower()


class PublicChannelGuard(object):
    """Hop-1 refusal seam for public-channel injection propagation.

    Composes a ``gov.injection_propagation.PropagationTracker`` (a
    fresh one by default; a shared tracker may be injected so the
    wave-151/152 auto-feed observations also feed this seam). The
    guard additionally records per-source provenance -- the tracker's
    verdicts only become hop-1 refusals when the reproduced span was
    observed with UNTRUSTED provenance.
    """

    def __init__(self, tracker=None):
        self.tracker = (tracker if tracker is not None
                        else injection_propagation.PropagationTracker())
        # agent_id -> source_id -> provenance (normalized string).
        self._provenance = {}

    # -- input observation ------------------------------------------------
    def observe_input(self, agent_id, source_id, text, provenance):
        """Record one input-context segment WITH its provenance.

        Returns the tracker's observation record plus the recorded
        provenance. Malformed inputs return (never raise) a
        ``egress-propagation-malformed`` record -- the observation is
        not trusted.
        """
        if (not isinstance(agent_id, str) or not agent_id
                or not isinstance(source_id, str) or not source_id
                or not isinstance(text, str)
                or not isinstance(provenance, str) or not provenance):
            return {"observed": False, "code": CODE_MALFORMED,
                    "reason": "observe_input needs non-empty agent_id, "
                              "source_id, text (str) and provenance"}
        agent = agent_id
        prov = _normalize_provenance(provenance)
        try:
            rec = self.tracker.observe_input(agent, source_id, text)
        except Exception:  # noqa: BLE001 -- observation never breaks input
            return {"observed": False, "code": CODE_MALFORMED,
                    "reason": "tracker observation failed"}
        self._provenance.setdefault(agent, {})[source_id] = prov
        rec["provenance"] = prov
        return rec

    def consume_public_channel(self, agent_id, source_id, text):
        """Record content consumed from a public channel (downstream).

        Provenance is forced to ``public-channel`` -- the caller does
        not get to declare a friendlier origin for public content.
        """
        return self.observe_input(agent_id, source_id, text,
                                  PUBLIC_PROVENANCE_MARKER)

    def _provenance_of(self, agent_id, source_id):
        """Recorded provenance, or "" when the guard never recorded it.

        Unknown provenance is treated as UNTRUSTED (fail-closed): only
        explicitly trusted provenance grants authority or exempts a
        span from the hop-1 refusal.
        """
        return self._provenance.get(agent_id, {}).get(source_id, "")

    @staticmethod
    def _is_trusted(provenance):
        return provenance in TRUSTED_PROVENANCES

    # -- outbound (hop-1) review -------------------------------------------
    def review_outbound(self, agent_id, channel, content,
                        user_request=None):
        """Review one boundary-crossing output to a public channel.

        Verdicts:
        - "refuse" + CODE_REFUSAL: the content reproduces an observed
          instruction span from UNTRUSTED provenance into a public
          channel -- the send must not proceed. Carries the spans and
          their source ids (the evidence), the channel, and the
          decision code.
        - "allow": no propagation; non-public channel
          (scope="not-public-channel"); or the reproduced spans were
          observed only with trusted provenance.
        Malformed inputs fail closed ("refuse" + CODE_MALFORMED).
        """
        if (not isinstance(agent_id, str) or not agent_id
                or not isinstance(channel, str)
                or not isinstance(content, str)):
            return {"verdict": "refuse", "code": CODE_MALFORMED,
                    "reason": "review_outbound needs non-empty agent_id "
                              "(str), channel (str), content (str)"}
        channel = _normalize_channel(channel)
        if channel not in PUBLIC_CHANNELS:
            return {"verdict": "allow", "scope": "not-public-channel",
                    "channel": channel, "agent_id": agent_id}
        if self.tracker is None:
            return {"verdict": "allow", "reason": "no_tracker",
                    "channel": channel, "agent_id": agent_id}
        res = self.tracker.check_output(agent_id, channel, content,
                                        user_request=user_request)
        if res.get("verdict") != "propagation_suspect":
            allow = {"verdict": "allow", "channel": channel,
                     "agent_id": agent_id,
                     "input_span_count": res.get("input_span_count", 0),
                     "output_span_count": res.get("output_span_count", 0)}
            return allow
        agent = str(agent_id)
        suspects = []
        for detail in res.get("span_detail", []):
            sources = detail.get("sources", [])
            untrusted = [s for s in sources
                         if not self._is_trusted(
                             self._provenance_of(agent, s))]
            if untrusted:
                suspects.append({"span": detail.get("span", ""),
                                 "normalized": detail.get("normalized", ""),
                                 "sources": sources,
                                 "untrusted_sources": untrusted,
                                 "match": detail.get("match")})
        if not suspects:
            return {"verdict": "allow",
                    "reason": "suspects_trusted_provenance_only",
                    "channel": channel, "agent_id": agent_id}
        return {"verdict": "refuse", "code": CODE_REFUSAL,
                "channel": channel, "agent_id": agent_id,
                "spans": [s["span"] for s in suspects],
                "span_detail": suspects,
                "sources": sorted({sid for s in suspects
                                   for sid in s["untrusted_sources"]})}

    # -- downstream instruction-authority gate ------------------------------
    def authorize_instruction(self, provenance):
        """Gate instruction authority on provenance (the second agent).

        Allow only when provenance is in TRUSTED_PROVENANCES. Public-
        channel provenance (the marker or anything derived from it,
        e.g. "public-channel:email:thread-1") refuses with
        CODE_PROVENANCE_PUBLIC; any other untrusted provenance refuses
        with CODE_PROVENANCE_UNTRUSTED; malformed input fails closed
        with CODE_MALFORMED.
        """
        prov = _normalize_provenance(provenance)
        if not prov:
            return {"verdict": "refuse", "code": CODE_MALFORMED,
                    "reason": "authorize_instruction needs provenance "
                              "(non-empty str)"}
        if prov in TRUSTED_PROVENANCES:
            return {"verdict": "allow", "provenance": prov}
        if prov == PUBLIC_PROVENANCE_MARKER or prov.startswith(
                PUBLIC_PROVENANCE_MARKER + ":"):
            return {"verdict": "refuse",
                    "code": CODE_PROVENANCE_PUBLIC,
                    "provenance": prov,
                    "reason": "public-channel provenance is untrusted "
                              "input; it can never become instruction "
                              "authority"}
        return {"verdict": "refuse",
                "code": CODE_PROVENANCE_UNTRUSTED,
                "provenance": prov,
                "reason": "provenance is not in the trusted set; "
                          "untrusted input can never become instruction "
                          "authority"}
