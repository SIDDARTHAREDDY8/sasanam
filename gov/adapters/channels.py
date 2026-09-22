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
