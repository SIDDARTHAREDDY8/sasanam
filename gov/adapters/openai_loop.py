"""OpenAI-style function-call message loop (no API calls).

This module orchestrates the *mechanics* of an OpenAI function-calling
loop -- parsing ``assistant`` messages' ``tool_calls``, dispatching each
through a :class:`~gov.adapters.core.GovernedBinding`, and appending
``tool``-role result messages -- without ever calling a model API. The
caller supplies ``respond``: any callable ``(messages) -> assistant
message dict`` (a scripted stub in tests, a real client elsewhere).

Fail-closed parsing (:func:`parse_tool_calls`):

* ``tool_calls`` must be a list; each entry a dict with a non-empty
  string ``id`` (unique within the message), ``type == "function"``,
  and a ``function`` dict carrying a non-empty string ``name``.
* ``function.arguments`` must be a JSON **object** encoded as a string
  (a plain dict is also accepted); anything else -- malformed JSON, a
  JSON array/scalar, a missing name, a duplicate id -- raises
  :class:`MalformedToolCallError` and nothing is dispatched.
* Unknown tool names raise :class:`UnregisteredToolError` at dispatch.

``run_tool_loop`` stops (raising) on the first denied/queued tool call
by default; pass ``on_denied="return"`` / ``on_queued="return"`` to let
the model see the denial/queue notice as a ``tool`` message and carry
on.
"""

from .core import (
    AdapterError,
    GovernedBinding,
    MalformedToolCallError,
    normalize_result,
)


class ParsedToolCall:
    """A strictly validated function call: ``id``, ``name``,
    ``arguments`` (dict)."""

    __slots__ = ("id", "name", "arguments")

    def __init__(self, call_id, name, arguments):
        self.id = call_id
        self.name = name
        self.arguments = arguments

    def __repr__(self):
        return "ParsedToolCall(id=%r, name=%r, arguments=%r)" % (
            self.id, self.name, self.arguments)

    def __eq__(self, other):
        return (isinstance(other, ParsedToolCall)
                and (self.id, self.name, self.arguments)
                == (other.id, other.name, other.arguments))


def parse_tool_calls(assistant_message):
    """Strictly parse ``assistant_message["tool_calls"]``.

    Returns a list of :class:`ParsedToolCall` (possibly empty). Raises
    :class:`MalformedToolCallError` on any shape violation -- fail
    closed, before any dispatch.
    """
    if not isinstance(assistant_message, dict):
        raise MalformedToolCallError(
            "assistant message must be a dict, got %r"
            % type(assistant_message).__name__)
    raw_calls = assistant_message.get("tool_calls") or []
    if not isinstance(raw_calls, list):
        raise MalformedToolCallError(
            "'tool_calls' must be a list, got %r" % type(raw_calls).__name__)
    parsed = []
    seen_ids = set()
    for index, raw in enumerate(raw_calls):
        where = "tool_calls[%d]" % index
        if not isinstance(raw, dict):
            raise MalformedToolCallError("%s must be a dict" % where)
        call_id = raw.get("id")
        if not isinstance(call_id, str) or not call_id:
            raise MalformedToolCallError(
                "%s: 'id' must be a non-empty string" % where)
        if call_id in seen_ids:
            raise MalformedToolCallError(
                "%s: duplicate tool_call id %r" % (where, call_id))
        seen_ids.add(call_id)
        call_type = raw.get("type", "function")
        if call_type != "function":
            raise MalformedToolCallError(
                "%s: unsupported type %r (only 'function' is mediated)"
                % (where, call_type))
        function = raw.get("function")
        if not isinstance(function, dict):
            raise MalformedToolCallError(
                "%s: 'function' must be a dict" % where)
        name = function.get("name")
        if not isinstance(name, str) or not name:
            raise MalformedToolCallError(
                "%s: 'function.name' must be a non-empty string" % where)
        arguments = function.get("arguments", "{}")
        parsed_args = _parse_arguments(arguments, where)
        parsed.append(ParsedToolCall(call_id, name, parsed_args))
    return parsed


def _parse_arguments(arguments, where):
    import json
    if isinstance(arguments, dict):
        parsed = arguments
    elif isinstance(arguments, str):
        try:
            parsed = json.loads(arguments)
        except ValueError as exc:
            raise MalformedToolCallError(
                "%s: 'function.arguments' is not valid JSON: %s"
                % (where, exc))
    else:
        raise MalformedToolCallError(
            "%s: 'function.arguments' must be a JSON object string or a "
            "dict, got %r" % (where, type(arguments).__name__))
    if not isinstance(parsed, dict):
        raise MalformedToolCallError(
            "%s: 'function.arguments' must decode to a JSON object, got %r"
            % (where, type(parsed).__name__))
    for key in parsed:
        if not isinstance(key, str):
            raise MalformedToolCallError(
                "%s: argument names must be strings, got %r" % (where, key))
    return parsed


def run_tool_loop(binding, messages, respond, max_iterations=8,
                  on_denied="raise", on_queued="raise"):
    """Run a mediated function-call loop. No model API is called.

    Parameters
    ----------
    binding : GovernedBinding
        Mediation endpoint for every dispatched tool call.
    messages : list[dict]
        Starting conversation (not mutated; a new transcript list is
        returned).
    respond : callable
        ``respond(transcript) -> dict`` producing the next ``assistant``
        message. Deterministic stubs make tests reproducible.
    max_iterations : int
        Upper bound on model turns; exceeding it raises
        :class:`AdapterError` (a runaway loop must not spin forever).
    on_denied, on_queued : {"raise", "return"}
        ``"raise"`` (default): the first denied/queued call raises and
        the loop stops -- fail closed. ``"return"``: the denial/queue
        notice is delivered as a ``tool`` message so the model can react.

    Returns the full transcript: the input messages plus each assistant
    message and its ``tool``-role results (``{"role": "tool",
    "tool_call_id": ..., "name": ..., "content": <JSON>}``).
    """
    if not isinstance(binding, GovernedBinding):
        raise TypeError("binding must be a GovernedBinding, got %r"
                        % type(binding).__name__)
    if not isinstance(messages, list) or any(
            not isinstance(m, dict) for m in messages):
        raise TypeError("messages must be a list of dicts")
    if not callable(respond):
        raise TypeError("respond must be callable")
    if not isinstance(max_iterations, int) or max_iterations < 1:
        raise ValueError("max_iterations must be a positive int")

    transcript = [dict(m) for m in messages]
    for _ in range(max_iterations):
        assistant = respond(transcript)
        if not isinstance(assistant, dict):
            raise MalformedToolCallError(
                "respond() must return an assistant message dict, got %r"
                % type(assistant).__name__)
        assistant = dict(assistant)
        assistant.setdefault("role", "assistant")
        transcript.append(assistant)

        tool_calls = parse_tool_calls(assistant)
        if not tool_calls:
            break
        for call in tool_calls:
            # binding.call raises on denied/queued by default (fail
            # closed); with "return" modes the notice becomes the tool
            # message content instead.
            result = binding.call(
                call.name, on_denied=on_denied, on_queued=on_queued,
                **call.arguments)
            transcript.append({
                "role": "tool",
                "tool_call_id": call.id,
                "name": call.name,
                "content": normalize_result(result),
            })
    else:
        raise AdapterError(
            "tool loop exceeded max_iterations=%d; refusing to continue "
            "an unbounded agent loop." % max_iterations)
    return transcript
