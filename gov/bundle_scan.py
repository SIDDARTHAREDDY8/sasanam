"""Skill-bundle content scanning at the ingest seam (wave-270).

Scan-without-load for pickle-serialized skill artifacts: the scanner
walks the opcode stream with :func:`pickletools.genops` and NEVER
unpickles -- no payload bytes are ever executed, deserialized, or
interpreted beyond disassembly. This is the content-safety half of
OWASP gap #2 (the wave-267 prospectus); provenance (signatures, digest
chains, transparency) is the other half and is explicitly NOT covered
here -- see the honest limits below.

Pattern adaptation ONLY from protectai/modelscan (Apache-2.0): the
stolen mechanism is scan-without-load plus the taxonomy discipline
(severity must mean something operational). No modelscan code is
vendored and no modelscan text is copied.

Severity semantics (operational, stolen from the modelscan pattern):

- CRITICAL: a code-execution sink global (``os.system``,
  ``subprocess.Popen``, ``builtins.eval``, ...) resolved in the stream
  AND a call-capable opcode present (``REDUCE``, ``INST``, ``OBJ``, or
  ``NEWOBJ`` -- all four invoke an attacker-named callable at unpickle
  time). Unpickling such a stream executes attacker-controlled code at
  load. -> ingestion REFUSED.
- HIGH: exploitable-but-not-executing at load -- gadget primitives
  (``builtins.getattr``/``setattr``/``delattr``, ``builtins.compile``,
  ``operator.attrgetter``) or a sink global with no call opcode in the
  stream (a loaded gun, not a fired one). -> loud ADVISORY evidence,
  ingestion still admitted.
- MEDIUM: unknown/ambiguous globals -- any ``GLOBAL``/``STACK_GLOBAL``
  not on the sink, gadget, or benign-allowlist sets (e.g. a custom
  application class). The scanner cannot vouch for what it cannot
  name. -> loud ADVISORY evidence.
- LOW: odd but non-threatening packaging notes (trailing bytes after
  ``STOP``, multiple ``STOP``s). -> ADVISORY evidence.

Structural refusals (fail-closed, no severity): ``bundlescan-malformed``
(truncated/corrupt/empty/non-bytes input -- ``genops`` raises) and
``bundlescan-oversized`` (input over ``max_bytes``, refused BEFORE
parsing so a hostile payload cannot buy parse-time memory).

``STACK_GLOBAL`` (protocols 4+) carries no inline argument; the scanner
resolves it from the two most recent string pushes on a small symbolic
stack. An unresolvable ``STACK_GLOBAL`` is a MEDIUM finding (the
scanner cannot name what the stream will load).

The sink+call-opcode rule is deliberately conservative: a sink
global anywhere in the stream combined with ``REDUCE``, ``INST``,
``OBJ``, or ``NEWOBJ`` anywhere in the stream is CRITICAL, even if
the call's callable is a different global. Carrying a code-execution
sink inside a skill bundle is refusal-worthy on its own; the scanner
does not attempt dataflow. (Wave-272, F255: the rule previously fired
only on ``REDUCE``; protocol-0/1 ``INST`` carries its callable in the
opcode argument with no ``GLOBAL`` at all, and ``OBJ``/``NEWOBJ`` take
theirs from the stack -- both were invisible to the sink rule.)

Composition: :func:`gov.skill_admission.admit` accepts an additive
``artifact_bytes`` kwarg (name -> payload bytes, for artifacts the
registry believes are pickle-serialized). A ``refuse`` verdict refuses
ingestion with the scanner's machine code and the artifact identity
attached; an ``advisory`` verdict is recorded in
``evidence["content_scan"]`` with per-artifact identities -- auditable
by construction, never a silent pass.

Honest limits (stated, not absorbed):

- Signature-based scanning is bypassable BY CONSTRUCTION.
  Name-mangled payloads (sink reached through ``getattr`` chains with
  concatenated names and no literal sink in the stream), custom
  unpickler subclasses, and weight steganography all escape. The
  scanner promises "this stream contains no KNOWN sink/global
  pattern", never "this stream is safe".
- The benign-allowlist is curated, not complete. A benign stdlib
  global not on the list is MEDIUM (advisory), never a refusal --
  false denials are not the failure mode, missed detections are.
- This module answers CONTENT safety, not PROVENANCE. It does no
  signing, no digest chaining, no transparency. A signed malicious
  bundle is a key-compromise problem, not a scanning problem.
- Only pickle streams are in scope. Other serialization formats
  (torch.save IS pickle and is covered; safetensors/npz/hdf5 are
  out of scope) and polyglot containers are not analyzed.

Stdlib only (``pickletools``, ``hashlib``). Deterministic: the same
bytes always produce the same verdict (no clock, no randomness, no
I/O, no env reads). The public seam never raises on hostile input --
structural problems are coded verdicts, not exceptions.
"""

import hashlib
import pickletools

__all__ = [
    "DEFAULT_MAX_BYTES",
    "CODE_RCE_GLOBAL",
    "CODE_SUSPICIOUS_GLOBAL",
    "CODE_UNKNOWN_GLOBAL",
    "CODE_ODD_PACKAGING",
    "CODE_MALFORMED",
    "CODE_OVERSIZED",
    "scan_pickle_stream",
]

DEFAULT_MAX_BYTES = 8 * 1024 * 1024

CODE_RCE_GLOBAL = "bundlescan-rce-global"
CODE_SUSPICIOUS_GLOBAL = "bundlescan-suspicious-global"
CODE_UNKNOWN_GLOBAL = "bundlescan-unknown-global"
CODE_ODD_PACKAGING = "bundlescan-odd-packaging"
CODE_MALFORMED = "bundlescan-malformed"
CODE_OVERSIZED = "bundlescan-oversized"

# (module, name) pairs whose invocation at unpickle time executes
# attacker-controlled code. Both 'os' and 'posix' spellings: os.system
# pickles as ('posix', 'system') on POSIX.
_CODE_EXEC_SINKS = frozenset([
    ("posix", "system"),
    ("os", "system"),
    ("os", "popen"),
    ("os", "spawnl"), ("os", "spawnle"), ("os", "spawnlp"),
    ("os", "spawnlpe"), ("os", "spawnv"), ("os", "spawnve"),
    ("os", "spawnvp"), ("os", "spawnvpe"),
    ("os", "execv"), ("os", "execve"), ("os", "execl"),
    ("os", "execle"), ("os", "execlp"), ("os", "execvp"),
    ("os", "execlpe"), ("os", "execvpe"),
    ("subprocess", "Popen"), ("subprocess", "call"),
    ("subprocess", "run"), ("subprocess", "check_output"),
    ("subprocess", "check_call"),
    ("builtins", "eval"), ("builtins", "exec"),
    ("pty", "spawn"),
])

# Exploitable-but-not-executing at load: gadget primitives used in
# real pickle exploit chains (attribute confusion, code-object
# building). Advisory, never a refusal.
_GADGET_PRIMITIVES = frozenset([
    ("builtins", "getattr"), ("builtins", "setattr"),
    ("builtins", "delattr"), ("builtins", "compile"),
    ("operator", "attrgetter"),
])

# Curated benign globals: resolving to one of these is not a finding.
# Curated, not complete -- anything unlisted is MEDIUM (advisory).
_BENIGN_GLOBALS = frozenset([
    ("datetime", "datetime"), ("datetime", "date"),
    ("datetime", "time"), ("datetime", "timedelta"),
    ("datetime", "tzinfo"),
    ("_codecs", "encode"), ("_codecs", "decode"),
    ("copyreg", "_reconstructor"), ("copyreg", "__newobj__"),
    ("collections", "OrderedDict"), ("collections", "defaultdict"),
    ("collections", "Counter"), ("collections", "deque"),
    ("decimal", "Decimal"), ("uuid", "UUID"),
])

# Opcodes that push a string/bytes value (for STACK_GLOBAL resolution).
_STRING_PUSH_OPS = frozenset([
    "UNICODE", "BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8",
    "BINSTRING", "SHORT_BINSTRING", "BINBYTES", "BINBYTES8",
    "BYTEARRAY8",
])

_OUT_OF_SCOPE = [
    "signature-based scanning is bypassable by construction: "
    "name-mangled payloads, custom unpickler subclasses, and weight "
    "steganography escape detection",
    "content safety only: no signing, digest chaining, or transparency "
    "(the provenance half of OWASP gap #2 is out of scope)",
    "the benign-allowlist is curated, not complete; unlisted benign "
    "globals are MEDIUM advisories, never refusals",
    "only pickle streams are analyzed; other formats are out of scope",
]


# Python-2-compat module spellings that pickle protocols 0-2 emit for
# builtins (e.g. GLOBAL '__builtin__ eval'). Normalized to the
# canonical spelling before classification.
_MODULE_ALIASES = {
    "__builtin__": "builtins",
    "copy_reg": "copyreg",
}


def _finding(severity, code, detail):
    return {"severity": severity, "code": code, "detail": detail}


def _verdict_dict(verdict, code, severity, findings, digest, nbytes):
    return {
        "verdict": verdict,
        "code": code,
        "severity": severity,
        "findings": findings,
        "evidence_digest": digest,
        "payload_bytes": nbytes,
        "out_of_scope": list(_OUT_OF_SCOPE),
    }


def _structural_refusal(code, detail, digest, nbytes):
    return _verdict_dict(
        "refuse", code, "none",
        [_finding("none", code, detail)], digest, nbytes)


def _scan_stream(data):
    """Walk the opcode stream; return (globals, saw_call_opcode, notes).

    ``globals``: list of ``(module, name, pos, resolvable)`` in stream
    order. ``saw_call_opcode``: True when any call-capable opcode --
    ``REDUCE``, ``INST``, ``OBJ``, or ``NEWOBJ`` -- is present (all
    four invoke an attacker-named callable at unpickle time). Raises
    on truncated/corrupt input (caller maps to
    ``bundlescan-malformed``). Never unpickles.

    ``INST`` (protocol 0/1) carries the callable as the opcode
    argument (``'module name'``, same shape as ``GLOBAL``) -- it is
    resolved into ``globals`` exactly like a ``GLOBAL``. ``OBJ`` and
    ``NEWOBJ`` take their callable from the stack (a prior
    ``GLOBAL``/``STACK_GLOBAL``); they only set ``saw_call_opcode``.
    """
    resolved = []
    recent_strings = []
    saw_call_opcode = False
    stop_count = 0
    first_stop_end = None
    notes = []
    for opcode, arg, pos in pickletools.genops(data):
        name = opcode.name
        if name in _STRING_PUSH_OPS:
            if isinstance(arg, str):
                recent_strings.append(arg)
            elif isinstance(arg, (bytes, bytearray)):
                try:
                    recent_strings.append(bytes(arg).decode("utf-8"))
                except Exception:  # noqa: BLE001 -- best effort
                    recent_strings.append(repr(bytes(arg)))
            else:
                recent_strings.append(repr(arg))
            del recent_strings[:max(0, len(recent_strings) - 8)]
        elif name == "GLOBAL" or name == "INST":
            # GLOBAL arg is the single string 'module name' on
            # protocols 0-3. INST (protocol 0/1) carries its callable
            # in the opcode argument in the same shape -- the sink
            # hides here, invisible to GLOBAL-only scanning. Both are
            # call-target resolutions; INST additionally marks the
            # stream as call-capable.
            if name == "INST":
                saw_call_opcode = True
            if isinstance(arg, str) and " " in arg:
                module, gname = arg.split(" ", 1)
                resolved.append((module, gname, pos, True))
            else:
                resolved.append(("<unresolved>", repr(arg), pos, False))
        elif name == "STACK_GLOBAL":
            if len(recent_strings) >= 2:
                resolved.append((recent_strings[-2], recent_strings[-1],
                                 pos, True))
            else:
                resolved.append(("<unresolved>", "STACK_GLOBAL", pos,
                                 False))
        elif name in ("REDUCE", "OBJ", "NEWOBJ"):
            # All three invoke an attacker-named callable taken from
            # the stack (REDUCE) or bound at the call site; together
            # with INST they are the call-capable opcodes.
            saw_call_opcode = True
        elif name == "STOP":
            stop_count += 1
            if first_stop_end is None:
                first_stop_end = pos + 1
    if stop_count > 1:
        notes.append(_finding(
            "low", CODE_ODD_PACKAGING,
            "stream contains %d STOP opcodes (expected 1)" % stop_count))
    if first_stop_end is not None and first_stop_end < len(data):
        notes.append(_finding(
            "low", CODE_ODD_PACKAGING,
            "%d trailing byte(s) after STOP" % (len(data) - first_stop_end)))
    return resolved, saw_call_opcode, notes


def _classify(resolved, saw_call_opcode):
    """Classify resolved globals into findings (stream order).

    The sink rule fires when a code-execution sink global is resolved
    ANYWHERE in the stream AND a call-capable opcode (REDUCE, INST,
    OBJ, or NEWOBJ) is present ANYWHERE in the stream. This is
    deliberately conservative: the scanner does not attempt dataflow,
    and carrying a code-execution sink inside a skill bundle is
    refusal-worthy on its own.
    """
    findings = []
    seen = set()
    for module, gname, pos, resolvable in resolved:
        if not resolvable:
            findings.append(_finding(
                "medium", CODE_UNKNOWN_GLOBAL,
                "unresolvable global reference at stream offset %d: "
                "the scanner cannot name what the stream will load"
                % (pos,)))
            continue
        key = (module, gname)
        if key in seen:
            continue
        seen.add(key)
        # Normalize py2-compat spellings ('__builtin__ eval' on
        # protocols 0-2) so the tables cannot be dodged by spelling.
        key = (_MODULE_ALIASES.get(module, module), gname)
        module = key[0]
        where = "stream offset %d" % (pos,)
        if key in _CODE_EXEC_SINKS:
            if saw_call_opcode:
                findings.append(_finding(
                    "critical", CODE_RCE_GLOBAL,
                    "code-execution sink %s.%s with a call opcode "
                    "(REDUCE/INST/OBJ/NEWOBJ) present at %s: "
                    "unpickling executes attacker-controlled code"
                    % (module, gname, where)))
            else:
                findings.append(_finding(
                    "high", CODE_SUSPICIOUS_GLOBAL,
                    "code-execution sink %s.%s with no call opcode at "
                    "%s: a loaded gun, not a fired one"
                    % (module, gname, where)))
        elif key in _GADGET_PRIMITIVES:
            findings.append(_finding(
                "high", CODE_SUSPICIOUS_GLOBAL,
                "gadget primitive %s.%s at %s: exploitable in "
                "pickle chains, does not execute at load"
                % (module, gname, where)))
        elif key in _BENIGN_GLOBALS:
            continue
        else:
            findings.append(_finding(
                "medium", CODE_UNKNOWN_GLOBAL,
                "unknown global %s.%s at %s: the scanner cannot vouch "
                "for what it cannot name" % (module, gname, where)))
    return findings


def scan_pickle_stream(data, max_bytes=DEFAULT_MAX_BYTES, context=None):
    """Scan a pickle payload without unpickling it.

    ``data``: bytes-like pickle stream. ``max_bytes``: size bound;
    larger inputs are refused before parsing. ``context``: optional
    caller label echoed in finding details.

    Returns a verdict dict ``{"verdict", "code", "severity",
    "findings", "evidence_digest", "payload_bytes", "out_of_scope"}``.
    ``verdict`` is "clean", "advisory", or "refuse". Never raises on
    hostile input -- structural problems are coded verdicts.
    """
    nbytes = len(data) if isinstance(data, (bytes, bytearray)) else -1
    digest = (hashlib.sha256(bytes(data)).hexdigest()
              if isinstance(data, (bytes, bytearray)) else
              hashlib.sha256(b"").hexdigest())
    ctx = " (%s)" % (context,) if context else ""
    try:
        if not isinstance(data, (bytes, bytearray)):
            return _structural_refusal(
                CODE_MALFORMED,
                "payload must be bytes-like, got %s%s"
                % (type(data).__name__, ctx), digest, nbytes)
        if len(data) == 0:
            return _structural_refusal(
                CODE_MALFORMED, "empty payload%s" % (ctx,), digest, 0)
        if not isinstance(max_bytes, int) or max_bytes <= 0:
            return _structural_refusal(
                CODE_MALFORMED,
                "max_bytes must be a positive int%s" % (ctx,),
                digest, len(data))
        if len(data) > max_bytes:
            return _structural_refusal(
                CODE_OVERSIZED,
                "payload %d bytes exceeds max_bytes %d%s"
                % (len(data), max_bytes, ctx), digest, len(data))
        resolved, saw_call_opcode, notes = _scan_stream(bytes(data))
        findings = _classify(resolved, saw_call_opcode) + notes
    except Exception as exc:  # noqa: BLE001 -- fail closed, never raise
        return _structural_refusal(
            CODE_MALFORMED,
            "stream failed structural validation (%s: %s)%s"
            % (type(exc).__name__, exc, ctx), digest,
            len(data) if isinstance(data, (bytes, bytearray)) else -1)

    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    top = max([order[f["severity"]] for f in findings
               if f["severity"] in order] or [0])
    if top >= 4:
        code = CODE_RCE_GLOBAL
        return _verdict_dict("refuse", code, "critical", findings,
                             digest, len(data))
    if top == 3:
        return _verdict_dict("advisory", CODE_SUSPICIOUS_GLOBAL, "high",
                             findings, digest, len(data))
    if top == 2:
        return _verdict_dict("advisory", CODE_UNKNOWN_GLOBAL, "medium",
                             findings, digest, len(data))
    if top == 1:
        return _verdict_dict("advisory", CODE_ODD_PACKAGING, "low",
                             findings, digest, len(data))
    return _verdict_dict("clean", None, "none", [], digest, len(data))
