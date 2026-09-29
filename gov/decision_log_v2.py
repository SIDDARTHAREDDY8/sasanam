"""Decision-log event shape v2 (wave-202 lane D).

Wave-201 prospecting section 5 -- OPA decision-logs verdict (ADAPT the
event-shape discipline, SKIP Rego; Apache-2.0, bytes verified 2026-09-29;
re-implemented stdlib-only, no Rego, nothing vendored): every decision
event carries a content-derived ``decision_id``, self-recorded redaction
(``erased``/``masked`` JSON-pointer lists per RFC 6901, proving what was
NOT logged), and replay-capture (enough deterministic input to re-run the
decision function and reproduce the verdict).

The v2 event is an ENVELOPE around the decision, not a second verdict
path. Its replay-capture names a function in the module's replay
registry; the registry ships the small built-in ``deny_first_rules``
replay function for self-contained verification, and an operator can
register an adapter whose inputs embed a ``gov/decision_replay.py``
trace (composing with the full engine-trace replayer) -- the v2
contract is only "re-run fn(inputs) and compare with verdict".

Schema (``event_version: 2``)::

    {
      "event_version": 2,
      "decision_id": "<sha256 hex over the canonical event, minus "
                     "decision_id itself and minus audit bookkeeping>",
      "decision": {"kind": str, "effect": str, "policy_id": str,
                   "reason": str},
      "body": { ...redacted decision context... },
      "erased": ["<json-pointer>", ...],   # leaves REMOVED from body
      "masked": ["<json-pointer>", ...],   # leaves replaced by {"$masked": true}
      "sensitive_digests": ["<sha256 hex>", ...],
          # one per erased/masked leaf: sha256(pointer + "\\x00" +
          # canonical(leaf value)) -- the event commits to WHAT was
          # withheld, without revealing it
      "replay": {"fn": "<registered replay fn name>",
                 "inputs": {...canonical...},
                 "verdict": {...},
                 "complete": true},
      "audit": {"seq": int, "entry_hash": "<hex>"}  # filled by
          # append_event; chain bookkeeping, EXCLUDED from decision_id
    }

Verification layers (fail LOUD, never silent):

1. ``verify_event`` -- structural shape, ``decision_id`` recomputation,
   pointer validity + disjointness, redaction self-consistency (an
   erased pointer must be ABSENT from the body; a masked pointer must
   hold exactly the placeholder; a body leaf whose (pointer, value)
   digest is committed in ``sensitive_digests`` but has NO covering
   pointer is a REDACTION LIE, named loudly), optional caller-supplied
   value predicates (a body leaf matching a predicate without a
   covering pointer is a lie -- the auditor's PII-pattern hook, not a
   baked-in heuristic), and replay verification.
2. ``verify_redaction(event, raw_body)`` -- for the auditor holding the
   RAW inputs: re-applies the redactions and demands byte-equality with
   the recorded body, and re-derives ``sensitive_digests``. Catches a
   capture-time lie (producer recorded PII while claiming redaction)
   that offline verification cannot see.
3. ``verify_replay(event)`` -- re-runs the registered replay function
   over the recorded inputs and demands the recomputed verdict equal
   the recorded one. A claimed-complete replay whose inputs omit a
   material decision input DIVERGES and is caught loudly. An unknown
   replay function name, or a missing required input, fails closed.

HONEST CEILINGS (documented, not papered):

* ``decision_id`` is a binding, not a signature: anyone can recompute
  it after forging a whole event. Post-hoc edit detection comes from
  the hash-chained audit log (``append_event``); the id makes the event
  self-describing and catches partial/corrupt tampering.
* Capture-time lies (a compromised producer recording a
  false-but-self-consistent event) are NOT detectable offline -- the
  same ceiling ``gov/decision_replay.py`` documents. ``verify_redaction``
  with the raw inputs is the auditor's answer when they hold them.
* Digest-commitment false positives: two body leaves with the same
  POINTER and the same VALUE are indistinguishable -- that is the
  design (the commitment is per (pointer, value)). A body leaf that
  coincidentally equals a committed sensitive value at a DIFFERENT
  pointer is NOT flagged (pointer is part of the digest preimage).
* ``value_predicates`` are caller-supplied; the module ships none, so
  no PII heuristic lives in the product.
* List-index redaction pointers are positionally unstable: after an
  erasure the surviving elements shift, so the offline "erased pointer
  must be absent" check is value-aware for list indices (only the exact
  committed value restored at the exact pointer is a lie). A
  same-valued duplicate shifting into an erased index is not flagged
  offline -- ``verify_redaction`` with the raw body re-derives the
  deletion order exactly and is the strong check for lists.

Stdlib only. Deterministic: no clock, no randomness, no I/O, no env
reads in the build/verify path. No ``gov`` imports: the auditor can run
this without the repo (same standalone story as decision_bom.py /
decision_replay.py).

$0 spend. No network.
"""

import copy
import hashlib
import json

EVENT_VERSION = 2

MASKED_PLACEHOLDER = {"$masked": True}


class DecisionEventError(Exception):
    """Base for all decision-log-v2 errors (loud, fail-closed)."""


class EventBuildError(DecisionEventError):
    """The event could not be built (caller supplied bad inputs)."""


class EventVerifyError(DecisionEventError):
    """Event verification failed (structural / id / redaction / replay)."""


class RedactionLieError(EventVerifyError):
    """The event's redaction claims are false (named loudly)."""


class ReplayDivergenceError(EventVerifyError):
    """Replayed verdict != recorded verdict (named loudly)."""


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _canonical_build(obj, what):
    """Canonical bytes for builder inputs; non-canonicalizable caller
    data is an EventBuildError (fail-closed, in-taxonomy)."""
    try:
        return _canonical(obj)
    except (TypeError, ValueError) as e:
        raise EventBuildError("%s is not JSON-canonicalizable: %s"
                              % (what, e))


def _canonical_verify(obj, what):
    """Canonical bytes for verifier inputs; non-canonicalizable event
    data is an EventVerifyError (fail-closed, in-taxonomy)."""
    try:
        return _canonical(obj)
    except (TypeError, ValueError) as e:
        raise EventVerifyError("%s is not JSON-canonicalizable: %s"
                               % (what, e))


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


# ---------------------------------------------------------------------------
# JSON Pointer (RFC 6901), stdlib-only, dict/list documents only.
# ---------------------------------------------------------------------------

def _split_pointer(pointer):
    if not isinstance(pointer, str):
        raise EventBuildError("pointer must be a string, got %r" % (pointer,))
    if pointer == "":
        raise EventBuildError("empty pointer (whole-document) not allowed "
                              "for redaction")
    if not pointer.startswith("/"):
        raise EventBuildError("pointer must start with '/': %r" % (pointer,))
    return [tok.replace("~1", "/").replace("~0", "~")
            for tok in pointer.split("/")[1:]]


def _escape(token):
    return token.replace("~", "~0").replace("/", "~1")


def _resolve(doc, pointer):
    """Return the value at pointer; raise EventBuildError if absent."""
    node = doc
    for tok in _split_pointer(pointer):
        if isinstance(node, dict):
            if tok not in node:
                raise EventBuildError(
                    "pointer %r does not resolve (missing key %r)"
                    % (pointer, tok))
            node = node[tok]
        elif isinstance(node, list):
            if tok == "-":
                raise EventBuildError(
                    "pointer %r uses '-' (append) -- not resolvable"
                    % (pointer,))
            try:
                idx = int(tok)
            except ValueError:
                raise EventBuildError(
                    "pointer %r has non-integer list index %r"
                    % (pointer, tok))
            if idx < 0 or idx >= len(node):
                raise EventBuildError(
                    "pointer %r list index %d out of range" % (pointer, idx))
            node = node[idx]
        else:
            raise EventBuildError(
                "pointer %r descends into scalar at %r" % (pointer, tok))
    return node


def _delete(doc, pointer):
    toks = _split_pointer(pointer)
    node = doc
    for tok in toks[:-1]:
        node = node[tok] if isinstance(node, dict) else node[int(tok)]
    last = toks[-1]
    if isinstance(node, dict):
        del node[last]
    else:
        del node[int(last)]


def _set(doc, pointer, value):
    toks = _split_pointer(pointer)
    node = doc
    for tok in toks[:-1]:
        node = node[tok] if isinstance(node, dict) else node[int(tok)]
    last = toks[-1]
    if isinstance(node, dict):
        node[last] = value
    else:
        node[int(last)] = value


def _walk_leaves(doc, prefix=""):
    """Yield (pointer, value) for every scalar leaf."""
    if isinstance(doc, dict):
        for key in doc:
            yield from _walk_leaves(doc[key], prefix + "/" + _escape(key))
    elif isinstance(doc, list):
        for i, item in enumerate(doc):
            yield from _walk_leaves(item, prefix + "/" + str(i))
    else:
        yield prefix, doc


def _pointer_covers(pointer, leaf_pointer):
    """True if redaction at ``pointer`` covers the leaf at ``leaf_pointer``."""
    return leaf_pointer == pointer or leaf_pointer.startswith(pointer + "/")


def _deletion_order(pointers):
    """Order erased pointers so deletions are correct: deeper paths
    first (a parent deleted before its child would orphan the child),
    and within the same parent list, higher indices first (deleting
    index 0 shifts every later index). Dict keys are order-free."""

    def key(pointer):
        toks = _split_pointer(pointer)
        nums = []
        for tok in toks:
            try:
                nums.append(-int(tok))
            except ValueError:
                nums.append(0)
        return (-len(toks), nums)

    return sorted(pointers, key=key)


def _sensitive_digest(pointer, value):
    return _sha256_hex((pointer + "\x00").encode("utf-8") + _canonical(value))


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def _check_pointer_lists(erased, masked):
    for name, lst in (("erased", erased), ("masked", masked)):
        if not isinstance(lst, (list, tuple)):
            raise EventBuildError("%s must be a list of pointers" % name)
        if len(set(lst)) != len(lst):
            raise EventBuildError("%s has duplicate pointers" % name)
        for p in lst:
            _split_pointer(p)  # validates syntax
    overlap = set(erased) & set(masked)
    if overlap:
        raise EventBuildError(
            "pointers in both erased and masked: %s" % sorted(overlap))
    for a in list(erased) + list(masked):
        for b in list(erased) + list(masked):
            if a != b and (b.startswith(a + "/") or a.startswith(b + "/")):
                raise EventBuildError(
                    "overlapping redaction pointers %r and %r" % (a, b))


def build_event(*, decision, raw_body, erased=(), masked=(),
                replay_fn, replay_inputs, replay_verdict,
                replay_complete=True):
    """Build a v2 decision event (fail-closed on bad inputs).

    ``decision``: dict with kind/effect/policy_id/reason (strings).
    ``raw_body``: the unredacted decision context (JSON-able dict).
    ``erased``/``masked``: JSON-pointer lists into ``raw_body``.
    ``replay_fn``: registered replay function name; ``replay_inputs``
    the canonical inputs; ``replay_verdict`` the recorded verdict;
    ``replay_complete``: True iff the capture is claimed complete
    (an honest False says "partial capture" instead of lying).
    """
    if not isinstance(decision, dict):
        raise EventBuildError("decision must be a dict")
    unknown = set(decision) - {"kind", "effect", "policy_id", "reason"}
    if unknown:
        raise EventBuildError("decision carries unknown keys: %s"
                              % sorted(unknown))
    for key in ("kind", "effect", "policy_id", "reason"):
        if not isinstance(decision.get(key), str) or not decision[key]:
            raise EventBuildError("decision.%s must be a non-empty string"
                                  % key)
    if not isinstance(raw_body, dict):
        raise EventBuildError("raw_body must be a dict")
    _check_pointer_lists(erased, masked)
    if not isinstance(replay_fn, str) or not replay_fn:
        raise EventBuildError("replay_fn must be a non-empty string")
    if replay_fn not in _REPLAY_FNS:
        raise EventBuildError("unknown replay_fn %r (not registered)"
                              % (replay_fn,))
    for name, val in (("replay_inputs", replay_inputs),
                      ("replay_verdict", replay_verdict)):
        try:
            _canonical(val)
        except Exception as e:
            raise EventBuildError("%s is not JSON-canonicalizable: %s"
                                  % (name, e))
    if not isinstance(replay_complete, bool):
        raise EventBuildError("replay_complete must be a bool")
    # Canonicalizability gate: everything below (digests, decision_id)
    # canonicalizes sub-objects of these, so one upfront check keeps
    # every later _canonical call in-taxonomy (no bare TypeError).
    _canonical_build(raw_body, "raw_body")
    _canonical_build(decision, "decision")

    body = copy.deepcopy(raw_body)
    sensitive_digests = []
    # Resolve every leaf against the PRISTINE raw body first (list
    # indices shift under deletion -- resolving up front keeps the
    # digests bound to the claimed pointers).
    resolved = [(p, _resolve(raw_body, p)) for p in erased] + \
               [(p, _resolve(raw_body, p)) for p in masked]
    for pointer, value in resolved:
        sensitive_digests.append(_sensitive_digest(pointer, value))
    for pointer in _deletion_order(erased):
        _delete(body, pointer)
    for pointer in masked:
        _set(body, pointer, copy.deepcopy(MASKED_PLACEHOLDER))

    event = {
        "event_version": EVENT_VERSION,
        "decision": {k: decision[k]
                     for k in ("kind", "effect", "policy_id", "reason")},
        "body": body,
        "erased": sorted(erased),
        "masked": sorted(masked),
        "sensitive_digests": sorted(sensitive_digests),
        "replay": {
            "fn": replay_fn,
            "inputs": copy.deepcopy(replay_inputs),
            "verdict": copy.deepcopy(replay_verdict),
            "complete": replay_complete,
        },
    }
    event["decision_id"] = _decision_id_for(event)
    return event


def _decision_id_for(event):
    """Content-derived id: sha256 over the canonical event minus
    ``decision_id`` itself and minus ``audit`` chain bookkeeping (the
    audit log's HMAC chain binds seq/hash independently, same as the
    log's reserved-metadata rule)."""
    preimage = {k: v for k, v in event.items()
                if k not in ("decision_id", "audit")}
    return _sha256_hex(_canonical(preimage))


def event_digest(event):
    """sha256 over the canonical event MINUS the ``audit`` chain
    bookkeeping (same exclusion as ``decision_id``). ``append_event``
    stamps ``audit`` in-memory AFTER the entry is serialized, so the
    persisted log entry carries no ``audit`` key: excluding it keeps the
    digest reproducible by an auditor holding only the chained entry.
    A BOM built from a post-append event therefore binds a digest the
    auditor can re-derive."""
    if not is_v2_event(event):
        raise EventVerifyError("not a v2 decision event")
    _canonical_verify(event, "event")  # in-taxonomy gate for _canonical
    preimage = {k: v for k, v in event.items() if k != "audit"}
    return _sha256_hex(_canonical(preimage))


def is_v2_event(obj):
    return isinstance(obj, dict) and obj.get("event_version") == EVENT_VERSION


# ---------------------------------------------------------------------------
# Replay function registry
# ---------------------------------------------------------------------------

_REPLAY_FNS = {}


def register_replay_fn(name, fn):
    """Register a deterministic replay function.

    ``fn(inputs) -> verdict`` must be deterministic and JSON-canonical;
    it must raise (not return a default) on missing required inputs.
    Duplicate names are refused (fail-closed).
    """
    if not isinstance(name, str) or not name:
        raise EventBuildError("replay fn name must be a non-empty string")
    if not callable(fn):
        raise EventBuildError("replay fn must be callable")
    if name in _REPLAY_FNS:
        raise EventBuildError("replay_fn %r already registered" % (name,))
    _REPLAY_FNS[name] = fn


def _deny_first_rules(inputs):
    """Built-in replay fn: deterministic deny-first rule evaluation.

    inputs: {"rules": [{"id", "effect": "allow"|"deny",
             "match": {field: value}}], "request": {field: value}}.
    A rule matches when every match condition equals the request field.
    Deny-first: any matching deny wins (first in order); else the first
    matching rule decides; else default-deny. Missing required inputs
    raise (fail-closed -- a capture that omits inputs cannot replay).
    """
    if not isinstance(inputs, dict):
        raise EventBuildError("deny_first_rules: inputs must be a dict")
    try:
        rules = inputs["rules"]
        request = inputs["request"]
    except KeyError as e:
        raise EventBuildError("deny_first_rules: missing input %s" % (e,))
    if not isinstance(rules, list) or not isinstance(request, dict):
        raise EventBuildError("deny_first_rules: bad rules/request shape")
    matched = []
    for rule in rules:
        if not isinstance(rule, dict):
            raise EventBuildError("deny_first_rules: rule not a dict")
        rid = rule.get("id")
        effect = rule.get("effect")
        conds = rule.get("match", {})
        if effect not in ("allow", "deny") or not isinstance(conds, dict):
            raise EventBuildError(
                "deny_first_rules: bad rule %r" % (rid,))
        if all(request.get(f) == v for f, v in conds.items()):
            matched.append((rid, effect))
    deny_hits = [rid for rid, eff in matched if eff == "deny"]
    if deny_hits:
        return {"effect": "deny", "matched_rule": deny_hits[0],
                "reason": "deny-first: rule %s matched" % deny_hits[0]}
    if matched:
        rid, _ = matched[0]
        return {"effect": "allow", "matched_rule": rid,
                "reason": "rule %s matched" % rid}
    return {"effect": "deny", "matched_rule": None,
            "reason": "default-deny: no rule matched"}


register_replay_fn("deny_first_rules", _deny_first_rules)


def verify_replay(event):
    """Re-run the recorded replay fn; the recomputed verdict must equal
    the recorded verdict byte-for-byte (canonical form). Raises
    ReplayDivergenceError / EventVerifyError -- never silent."""
    replay = event.get("replay")
    if not isinstance(replay, dict):
        raise EventVerifyError("event.replay is not a dict")
    fn_name = replay.get("fn")
    fn = _REPLAY_FNS.get(fn_name)
    if fn is None:
        raise EventVerifyError("unknown replay fn %r" % (fn_name,))
    if replay.get("complete") is not True:
        raise EventVerifyError(
            "replay.complete is not true -- partial capture cannot "
            "verify as a complete replay (honest False, not a lie)")
    try:
        recomputed = fn(copy.deepcopy(replay.get("inputs")))
    except EventVerifyError:
        raise
    except DecisionEventError as e:
        raise EventVerifyError(
            "replay fn %r refused the recorded inputs (%s: %s) -- the "
            "recorded inputs do not replay (omitted or malformed inputs "
            "fail closed, never default)" % (fn_name, type(e).__name__, e))
    except Exception as e:
        raise EventVerifyError(
            "replay fn %r raised %s: %s -- the recorded inputs do not "
            "replay (omitted or malformed inputs fail closed, never "
            "default)" % (fn_name, type(e).__name__, e))
    recorded = replay.get("verdict")
    if _canonical(recomputed) != _canonical(recorded):
        raise ReplayDivergenceError(
            "replay DIVERGED for fn %r: recorded=%s recomputed=%s"
            % (fn_name, _canonical(recorded).decode(),
               _canonical(recomputed).decode()))
    return True


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

def verify_event(event, *, value_predicates=()):
    """Full offline verification of a v2 event. Returns True; raises
    EventVerifyError / RedactionLieError / ReplayDivergenceError.

    ``value_predicates``: optional callables ``pred(pointer, value) ->
    bool``; a body leaf matching one without a covering erased/masked
    pointer is a redaction lie (the auditor's hook -- the module ships
    no PII heuristics of its own).
    """
    if not is_v2_event(event):
        raise EventVerifyError(
            "not a v2 decision event (event_version=%r)" % (
                event.get("event_version") if isinstance(event, dict)
                else None,))
    # Canonicalizability gate (see build_event): every later
    # _canonical call operates on sub-objects of the event.
    _canonical_verify(event, "event")
    decision = event.get("decision")
    if not isinstance(decision, dict):
        raise EventVerifyError("event.decision is not a dict")
    for key in ("kind", "effect", "policy_id", "reason"):
        if not isinstance(decision.get(key), str):
            raise EventVerifyError("event.decision.%s missing/not a string"
                                   % key)
    body = event.get("body")
    if not isinstance(body, dict):
        raise EventVerifyError("event.body is not a dict")
    erased = event.get("erased")
    masked = event.get("masked")
    if not isinstance(erased, (list, tuple)) or not isinstance(
            masked, (list, tuple)):
        raise EventVerifyError(
            "event.erased/event.masked must be pointer lists")
    try:
        _check_pointer_lists(erased, masked)
    except EventBuildError as e:
        raise EventVerifyError("bad redaction pointer lists: %s" % (e,))
    erased = list(erased)
    masked = list(masked)

    # 1. decision_id binding.
    recorded_id = event.get("decision_id")
    if not _is_hex64(recorded_id):
        raise EventVerifyError("event.decision_id is not 64-char hex")
    recomputed_id = _decision_id_for(event)
    if recorded_id != recomputed_id:
        raise EventVerifyError(
            "decision_id MISMATCH: recorded=%s recomputed=%s -- the event "
            "was edited after id computation (post-hoc tampering fails "
            "closed)" % (recorded_id, recomputed_id))

    # 2. redaction self-consistency.
    digests = event.get("sensitive_digests")
    if not isinstance(digests, list) or not all(
            _is_hex64(d) for d in digests):
        raise EventVerifyError("event.sensitive_digests malformed")
    digest_set = set(digests)
    for pointer in erased:
        try:
            actual = _resolve(body, pointer)
        except EventBuildError:
            continue  # correctly absent
        # List indices shift under deletion, so "pointer resolves" is
        # meaningless for them: only the exact committed value restored
        # at the exact pointer is a lie (the digest walk below plus
        # verify_redaction with the raw body are the strong checks for
        # lists). Dict paths are stable: any resolution is a lie.
        try:
            int(_split_pointer(pointer)[-1])
            list_index = True
        except ValueError:
            list_index = False
        if not list_index or \
                _sensitive_digest(pointer, actual) in digest_set:
            raise RedactionLieError(
                "REDACTION LIE: erased pointer %r is PRESENT in the "
                "recorded body -- the erasure claim is false" % (pointer,))
    for pointer in masked:
        try:
            actual = _resolve(body, pointer)
        except EventBuildError:
            raise RedactionLieError(
                "REDACTION LIE: masked pointer %r is ABSENT from the "
                "recorded body" % (pointer,))
        if actual != MASKED_PLACEHOLDER:
            raise RedactionLieError(
                "REDACTION LIE: masked pointer %r holds %r, not the "
                "mask placeholder -- raw value retained under a mask "
                "claim" % (pointer, actual))
    for leaf_pointer, value in _walk_leaves(body):
        if _sensitive_digest(leaf_pointer, value) in digest_set:
            if not any(_pointer_covers(p, leaf_pointer)
                       for p in erased + masked):
                raise RedactionLieError(
                    "REDACTION LIE: body leaf %r matches a committed "
                    "sensitive digest but NO erased/masked pointer covers "
                    "it -- the pointer list is incomplete" % (leaf_pointer,))
        for pred in value_predicates:
            try:
                hit = bool(pred(leaf_pointer, value))
            except Exception:
                hit = False
            if hit and not any(_pointer_covers(p, leaf_pointer)
                               for p in erased + masked):
                raise RedactionLieError(
                    "REDACTION LIE: body leaf %r matched an auditor "
                    "predicate but no erased/masked pointer covers it"
                    % (leaf_pointer,))

    # 3. replay.
    verify_replay(event)
    return True


def verify_redaction(event, raw_body):
    """Auditor-with-raw verification: re-apply the event's redactions to
    ``raw_body`` and demand byte-equality with the recorded body, and
    re-derive ``sensitive_digests``. Catches capture-time lies that
    offline verification cannot see. The ``decision_id`` binding is
    checked first: an auditor calling only this must not pass a
    tampered event. Returns True; raises loudly."""
    if not is_v2_event(event):
        raise EventVerifyError("not a v2 decision event")
    _canonical_verify(event, "event")
    if not isinstance(raw_body, dict):
        raise EventVerifyError("raw_body must be a dict")
    _canonical_verify(raw_body, "raw_body")
    recorded_id = event.get("decision_id")
    if not _is_hex64(recorded_id) or \
            recorded_id != _decision_id_for(event):
        raise EventVerifyError(
            "decision_id MISMATCH -- the event was edited after id "
            "computation (post-hoc tampering fails closed)")
    expected = copy.deepcopy(raw_body)
    recomputed_digests = []
    for pointer in event.get("erased", []):
        try:
            value = _resolve(raw_body, pointer)
        except EventBuildError as e:
            raise RedactionLieError(
                "REDACTION LIE: erased pointer %r does not resolve in the "
                "auditor-supplied raw body: %s" % (pointer, e))
        recomputed_digests.append(_sensitive_digest(pointer, value))
    for pointer in _deletion_order(event.get("erased", [])):
        _delete(expected, pointer)
    for pointer in event.get("masked", []):
        try:
            value = _resolve(expected, pointer)
        except EventBuildError as e:
            raise RedactionLieError(
                "REDACTION LIE: masked pointer %r does not resolve in the "
                "auditor-supplied raw body: %s" % (pointer, e))
        recomputed_digests.append(_sensitive_digest(pointer, value))
        _set(expected, pointer, copy.deepcopy(MASKED_PLACEHOLDER))
    if _canonical(expected) != _canonical(event.get("body")):
        raise RedactionLieError(
            "REDACTION LIE: re-applying the recorded redactions to the "
            "raw body does NOT reproduce the recorded body -- the "
            "producer's redaction claim is false")
    if sorted(recomputed_digests) != sorted(event.get("sensitive_digests",
                                                      [])):
        raise RedactionLieError(
            "REDACTION LIE: re-derived sensitive digests do not match "
            "the committed set")
    return True


# ---------------------------------------------------------------------------
# Audit-log chaining (duck-typed: any object with .append(event) -> entry)
# ---------------------------------------------------------------------------

def append_event(action_log, event, *, extra=None):
    """Chain a v2 event into the hash-chained audit log.

    Appends ``{"decision_event_v2": event}`` (+ optional ``extra`` keys)
    and stamps ``event["audit"] = {"seq", "entry_hash"}`` from the stored
    entry. ``audit`` is chain bookkeeping and is EXCLUDED from the
    ``decision_id`` preimage (the log's HMAC chain binds seq/hash
    independently). Returns the stored entry. v1 entries are untouched.

    ``extra`` keys must not collide with the reserved
    ``decision_event_v2`` envelope key (fail-closed).
    """
    extra = extra or {}
    if "decision_event_v2" in extra:
        raise EventBuildError(
            "extra must not override the reserved 'decision_event_v2' key")
    entry = action_log.append(dict({"decision_event_v2": event}, **extra))
    event["audit"] = {"seq": entry["seq"], "entry_hash": entry["hash"]}
    return entry
