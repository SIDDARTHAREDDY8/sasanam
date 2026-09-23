"""StruQ-style channel separation at the adapter boundary.

Implements the adapter-schema half of StruQ (Chen et al., USENIX
Security 2025): the trusted-prompt / untrusted-data split. The
specialized fine-tuning half is OUT-OF-SCOPE for this layer; what the
adapter *can* enforce structurally is:

1. **Tag** -- every content item crossing the adapter boundary carries
   an explicit channel tag (``"data"`` vs ``"instruction"``), so the
   split is never implicit.
2. **Build** -- tool results are rendered into the data channel only,
   via the single sanctioned constructor :func:`build_tool_message`
   (``role="tool"`` + ``channel="data"``). No adapter builder
   interpolates data into instruction-position text.
3. **Validate** -- :func:`assert_channel_separation` fails closed when
   data-channel content appears in an instruction-position message, or
   when a data-role message fraudulently claims the instruction
   channel. Deployers wire this into their prompt pipeline before the
   transcript reaches a model.

Instruction-position roles are ``system`` / ``developer`` / ``user``;
``tool`` is the data role; ``assistant`` is the model's own output and
is not validated.
"""

import json

from .core import AdapterError, normalize_result

__all__ = [
    "DATA",
    "INSTRUCTION",
    "INSTRUCTION_ROLES",
    "ChannelViolationError",
    "tag_data",
    "tag_instruction",
    "build_tool_message",
    "assert_channel_separation",
    "TranscriptGuard",
]

DATA = "data"
INSTRUCTION = "instruction"

#: Roles whose messages are read by the model as instructions.
INSTRUCTION_ROLES = ("system", "developer", "user")


class ChannelViolationError(AdapterError):
    """Data-channel content reached instruction position (fail closed)."""


def tag_data(content, source):
    """Tag untrusted content (tool output, retrieved doc) as data."""
    if not isinstance(source, str) or not source:
        raise TypeError("source must be a non-empty string")
    return {"channel": DATA, "source": source, "content": content}


def tag_instruction(content, privilege):
    """Tag trusted content with its instruction privilege.

    ``privilege`` is ``"system"``, ``"developer"``, or ``"user"``
    (Instruction Hierarchy order; see :mod:`gov.adapters.trust`).
    """
    if privilege not in ("system", "developer", "user"):
        raise ValueError(
            "privilege must be 'system', 'developer', or 'user', got %r"
            % (privilege,))
    return {"channel": INSTRUCTION, "privilege": privilege,
            "content": content}


def build_tool_message(name, tool_call_id, result):
    """Sanctioned tool-result message: data channel, always.

    ``content`` keeps the exact ``normalize_result`` wire format
    (JSON string) so existing consumers are unaffected; the channel
    separation is carried by the ``channel``/``source`` tags, never by
    string delimiters that a payload could forge.
    """
    if not isinstance(name, str) or not name:
        raise TypeError("name must be a non-empty string")
    return {
        "role": "tool",
        "tool_call_id": tool_call_id,
        "name": name,
        "content": (result if isinstance(result, str)
                    else normalize_result(result)),
        "channel": DATA,
        "source": "tool:" + name,
    }


def _as_text(content):
    if isinstance(content, str):
        return content
    try:
        return json.dumps(content, sort_keys=True, default=str)
    except Exception:
        return str(content)


def assert_channel_separation(messages, data_contents=()):
    """Fail closed on instruction/data channel confusion.

    Raises :class:`ChannelViolationError` when:

    * a ``role="tool"`` message claims ``channel="instruction"``
      (forged channel tag), or
    * any of ``data_contents`` (exact rendered data strings the
      adapter emitted, e.g. tool message ``content`` values) appears
      verbatim inside an instruction-position message that is not
      itself tagged as data.

    ``data_contents`` matching is verbatim: pass the full rendered
    strings, not fragments, to avoid substring false positives.
    Returns ``None`` when the transcript is clean.
    """
    if not isinstance(messages, (list, tuple)):
        raise TypeError("messages must be a list of dicts")
    markers = [m for m in data_contents
               if isinstance(m, str) and m]
    for idx, message in enumerate(messages):
        if not isinstance(message, dict):
            raise ChannelViolationError(
                "message %d is not a dict" % idx)
        role = message.get("role")
        channel = message.get("channel")
        if role == "tool" and channel == INSTRUCTION:
            raise ChannelViolationError(
                "tool message %d claims the instruction channel "
                "(forged tag)" % idx)
        if role in INSTRUCTION_ROLES and channel != DATA:
            text = _as_text(message.get("content", ""))
            for marker in markers:
                if marker in text:
                    raise ChannelViolationError(
                        "data-channel content appears in instruction "
                        "position (message %d, role=%r)" % (idx, role))
    return None


class TranscriptGuard:
    """Stateful multiturn guard around :func:`assert_channel_separation`.

    RT18: ``assert_channel_separation`` is per-call and relies on the
    caller to supply ``data_contents`` — the rendered data strings to
    watch for. In a multiturn loop nothing persists those markers, so a
    payload planted in an early turn passes a later check when the later
    turn's caller drops them (break-first probe S1: verbatim data reused
    in instruction position, check passed with no markers fed). The
    wave-21 ``multiturn_delayed_reuse_residual`` probe only pinned the
    verbatim-with-markers shape as stopped; the marker-dropout shape was
    the live gap.

    ``TranscriptGuard`` accumulates the rendered content of every
    data-channel tool message fed to it and checks the whole transcript
    against the accumulated markers, so delayed reuse is caught even
    when the later turn supplies no markers of its own::

        guard = TranscriptGuard()
        msg = guard.feed_tool_result("read_file", "c1", result)
        transcript.append(msg)
        ...
        guard.check(transcript)  # raises ChannelViolationError on reuse

    Purely additive: :func:`assert_channel_separation`'s contract is
    unchanged. Matching stays verbatim — paraphrase and split-assembly
    reuse remain the documented heuristic residual (RT18 S3/S4).
    """

    def __init__(self):
        self._markers = []

    def _add_marker(self, marker):
        if isinstance(marker, str) and marker and \
                marker not in self._markers:
            self._markers.append(marker)

    @staticmethod
    def _string_leaves(node, _depth=0):
        """Yield string leaves of ``node`` (dict values, sequence items).

        The rendered tool message escapes inner quotes (JSON envelope),
        but a later turn re-types the RAW data — so the envelope alone
        is the wrong marker. The leaves are what an attacker reuses
        verbatim (the wave-21 probes fed the raw data strings, not the
        envelope, for exactly this reason). Dict keys are schema labels,
        not data, and are skipped.
        """
        if _depth > 8:
            return
        if isinstance(node, str):
            if node:
                yield node
        elif isinstance(node, dict):
            for value in node.values():
                yield from TranscriptGuard._string_leaves(value, _depth + 1)
        elif isinstance(node, (list, tuple)):
            for item in node:
                yield from TranscriptGuard._string_leaves(item, _depth + 1)

    def feed(self, message):
        """Accumulate markers from a data-channel message.

        Only messages tagged ``channel="data"`` (or ``role="tool"``)
        contribute markers; anything else is ignored so instruction
        messages can never poison the marker set. Markers are the
        message's rendered content plus, when the original result is
        recoverable, its string leaves (see :meth:`_string_leaves`).
        Empty renders and duplicates are skipped.
        """
        if not isinstance(message, dict):
            raise TypeError("message must be a dict, got %r"
                            % type(message).__name__)
        if message.get("channel") != DATA and \
                message.get("role") != "tool":
            return
        self._add_marker(_as_text(message.get("content", "")))

    def feed_tool_result(self, name, tool_call_id, result):
        """Build a tool message AND feed its markers in one step.

        The single sanctioned constructor
        (:func:`build_tool_message`) plus marker capture, so a loop
        cannot build the message and forget the markers. Markers cover
        the rendered message content and the result's string leaves —
        the raw data a later turn would re-type verbatim.
        """
        message = build_tool_message(name, tool_call_id, result)
        self.feed(message)
        for leaf in self._string_leaves(result):
            self._add_marker(leaf)
        self._add_marker(_as_text(result))
        return message

    def check(self, messages):
        """Validate ``messages`` against all accumulated markers.

        Raises :class:`ChannelViolationError` when any marker appears
        verbatim in an instruction-position message; returns None when
        clean.
        """
        return assert_channel_separation(messages, self._markers)

    @property
    def markers(self):
        """The accumulated marker strings (read-only copy)."""
        return list(self._markers)

    def __len__(self):
        return len(self._markers)
