"""Approval-ceremony v2: the human-approval gate.

STEAL (ceremony/pattern, nothing copied) from langgraph's interrupt
model (``langchain-ai/langgraph`` @ ``b36b1d58``, MIT):

- four-verdict wire format ``accept | ignore | respond | edit`` with
  typed payloads (``edit`` = repair, not reject);
- id-addressed resume; multiple pending approvals + a resume that does
  not address an approval by id fails closed;
- ``versions_seen`` one-shot gating: a consumed approval never re-fires;
- hanging-approval computation over a durable pending set;
- anti-stale semantics: resuming from a forked/older lineage re-fires
  the approval, never applies a cached one;
- deterministic ids as routing keys only.

ADAPT: ``allow_*`` verdict gating moved engine-side (langgraph's is
client-side only); xxh3 ids replaced by a stdlib sha256 routing key;
``response_schema`` accepted only as a real validated type, never a
bare dict.

DROP: unauthenticated thread-id-only resume (Sasanam requires a signed
corroboration receipt on the resume path, bound to the approver's
registered DID); whole-node re-execution (the gate is not a
re-executing node — pre-gate side effects are protected by durable
once-tokens instead); order-matched multi-approval resume.

Composition: resume receipts are ``gov.corroboration_receipt``
DSSE envelopes. The receipt's ``decision_digest`` must equal the
surfaced approval's payload digest, and the reviewer DID must be in
the gate's deployment-pinned approver registry. Signature alone is
never enough.

Honest limits (carried in every outcome's ``out_of_scope``):

- the gate binds *participation*, not *comprehension*: nothing proves
  the human read the surfaced payload;
- receipts are only as trustworthy as the approver-key registry and
  the receipt module's own guarantees;
- the gate cannot prevent a caller from performing the gated action
  without asking — it is a ceremony, not a capability;
- approvals have no expiry in this lane (a stale pending approval is
  a deployment-policy question, not yet modeled);
- interrupt values are not confidential: whoever holds the store sees
  the surfaced payloads.
"""

import base64
import copy
import hashlib
import json
import os

# ------------------------------------------------------------------
# Errors.
# ------------------------------------------------------------------


class ApprovalCeremonyError(Exception):
    """Machine-coded ceremony refusal. ``code`` is a decision code."""

    def __init__(self, code, detail):
        super(ApprovalCeremonyError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


class _SchemaViolation(Exception):
    pass


# ------------------------------------------------------------------
# Deterministic helpers.
# ------------------------------------------------------------------

_ID_DOMAIN = b"sasanam-approval-ceremony/v1|"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _payload_digest(payload):
    return _sha256_hex(_canonical(payload))


def _approval_id(thread_id, lineage, name, payload_digest):
    raw = (_ID_DOMAIN + b"|".join(
        x.encode("utf-8") for x in
        (thread_id, lineage, name, payload_digest)))
    # 32 hex chars, xxh3-128-shaped routing key. Deterministic, visible,
    # computable by anyone who knows the inputs: a routing key, NEVER
    # a capability and never a secret.
    return _sha256_hex(raw)[:32]


_VERDICTS = ("accept", "ignore", "respond", "edit")

_OUT_OF_SCOPE = (
    "binds participation, not comprehension: nothing proves the human "
    "read the surfaced payload; receipts are only as trustworthy as the "
    "approver-key registry; the gate is a ceremony, not a capability — "
    "it cannot stop a caller from acting without asking; approvals do "
    "not expire in this lane; surfaced payloads are not confidential."
)


# ------------------------------------------------------------------
# Response schemas: real validated types only.
# ------------------------------------------------------------------

class ResponseSchema(object):
    """A response schema the ENGINE validates.

    A bare ``dict`` (JSON Schema on the wire) is refused at request
    time: surfaced-but-unvalidated is a false assurance (langgraph
    trap T4). Only ``ResponseSchema`` instances travel with a request.
    """

    _KINDS = ("none", "text", "enum", "record", "action")

    def __init__(self, kind, spec=None):
        if kind not in self._KINDS:
            raise _SchemaViolation("unknown schema kind %r" % (kind,))
        self.kind = kind
        self.spec = spec

    @classmethod
    def none(cls):
        return cls("none")

    @classmethod
    def text(cls):
        return cls("text")

    @classmethod
    def enum(cls, values):
        values = tuple(values)
        if not values or not all(isinstance(v, str) for v in values):
            raise _SchemaViolation("enum needs a non-empty str tuple")
        return cls("enum", values)

    @classmethod
    def record(cls, fields):
        if not isinstance(fields, dict) or not fields:
            raise _SchemaViolation("record needs a non-empty field dict")
        for name, sub in fields.items():
            if not isinstance(name, str) or \
                    not isinstance(sub, ResponseSchema):
                raise _SchemaViolation("record fields must be str->schema")
        return cls("record", dict(fields))

    @classmethod
    def action(cls):
        return cls("action")

    # -- validation: returns the validated object, never the raw input.

    def validate(self, value):
        if self.kind == "none":
            if value is not None:
                raise _SchemaViolation("expected None")
            return None
        if self.kind == "text":
            if not isinstance(value, str):
                raise _SchemaViolation("expected str")
            return value
        if self.kind == "enum":
            if value not in self.spec:
                raise _SchemaViolation("not in enum %r" % (self.spec,))
            return value
        if self.kind == "record":
            if not isinstance(value, dict):
                raise _SchemaViolation("expected a mapping")
            if set(value.keys()) != set(self.spec.keys()):
                raise _SchemaViolation(
                    "fields %r != schema %r"
                    % (sorted(value.keys()), sorted(self.spec.keys())))
            return {k: self.spec[k].validate(value[k])
                    for k in self.spec}
        if self.kind == "action":
            if not isinstance(value, dict):
                raise _SchemaViolation("expected an action mapping")
            if set(value.keys()) != {"action", "args"}:
                raise _SchemaViolation(
                    "action must be exactly {action, args}")
            action = value["action"]
            args = value["args"]
            if not isinstance(action, str) or not action:
                raise _SchemaViolation("action.action must be non-empty str")
            if not isinstance(args, dict):
                raise _SchemaViolation("action.args must be a mapping")
            for k, v in args.items():
                if not isinstance(k, str) or not isinstance(
                        v, (str, int, float, bool)) and v is not None:
                    raise _SchemaViolation("action.args must be str->scalar")
            return {"action": action,
                    "args": {k: args[k] for k in sorted(args)}}
        raise _SchemaViolation("unreachable")

    # -- journal (de)serialization.

    def to_json(self):
        if self.kind == "enum":
            return {"kind": "enum", "values": list(self.spec)}
        if self.kind == "record":
            return {"kind": "record",
                    "fields": {k: v.to_json()
                               for k, v in self.spec.items()}}
        return {"kind": self.kind}

    @classmethod
    def from_json(cls, obj):
        if not isinstance(obj, dict):
            raise _SchemaViolation("schema journal record malformed")
        kind = obj.get("kind")
        if kind == "enum":
            return cls.enum(obj.get("values", []))
        if kind == "record":
            return cls.record({k: cls.from_json(v)
                               for k, v in obj.get("fields", {}).items()})
        if kind in ("none", "text", "action"):
            return cls(kind)
        raise _SchemaViolation("unknown schema kind %r" % (kind,))


# ------------------------------------------------------------------
# Stores: durable pending-approval set + once-tokens + lineage.
# ------------------------------------------------------------------

class MemoryApprovalStore(object):
    """In-memory approval store. Subclassed by FileApprovalStore."""

    def __init__(self):
        self._records = {}      # approval_id -> record
        self._consumed = set()  # approval_ids
        self._lineage = {}      # thread_id -> current lineage
        self._once = {}         # (thread_id, token) -> result

    # -- lineage ----------------------------------------------------

    def current_lineage(self, thread_id):
        return self._lineage.get(thread_id, "l0")

    # -- approvals --------------------------------------------------

    def put_record(self, record):
        self._records[record["approval_id"]] = record

    def get_record(self, approval_id):
        return self._records.get(approval_id)

    def mark_consumed(self, approval_id):
        self._consumed.add(approval_id)

    def is_consumed(self, approval_id):
        return approval_id in self._consumed

    def set_lineage(self, thread_id, lineage):
        self._lineage[thread_id] = lineage

    def pending(self, thread_id):
        lineage = self.current_lineage(thread_id)
        return [r for r in self._records.values()
                if r["thread_id"] == thread_id
                and r["lineage"] == lineage
                and r["approval_id"] not in self._consumed]

    # -- once-tokens -------------------------------------------------

    def once_get(self, thread_id, token):
        return self._once.get((thread_id, token), _MISSING)

    def once_put(self, thread_id, token, result):
        self._once[(thread_id, token)] = result

    # -- journal hooks (no-ops in memory; overridden for files) ------

    def _journal(self, event):
        pass


_MISSING = object()


class FileApprovalStore(MemoryApprovalStore):
    """JSONL-journaled store: replays on open (F251 lesson).

    Every mutation appends one event; the constructor replays the
    journal in order, so pending approvals survive restarts. A
    shape-invalid journal record raises loudly — silently skipping
    would reintroduce the F251 defect class.
    """

    def __init__(self, path):
        super(FileApprovalStore, self).__init__()
        self._path = path
        parent = os.path.dirname(os.path.abspath(path))
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        if os.path.exists(path):
            self._replay(path)

    # -- journal ----------------------------------------------------

    def _journal(self, event):
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, sort_keys=True) + "\n")

    def _replay(self, path):
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    raise ApprovalCeremonyError(
                        "ceremony-v2-malformed",
                        "journal line %d is not JSON" % lineno)
                self._apply(event, lineno)

    def _apply(self, event, lineno):
        kind = event.get("event") if isinstance(event, dict) else None
        if kind == "approval-requested":
            record = event.get("record")
            self._check_record(record, lineno)
            super(FileApprovalStore, self).put_record(record)
        elif kind == "approval-resumed":
            aid = event.get("approval_id")
            if not isinstance(aid, str):
                raise ApprovalCeremonyError(
                    "ceremony-v2-malformed",
                    "journal line %d: bad approval-resumed" % lineno)
            super(FileApprovalStore, self).mark_consumed(aid)
        elif kind == "lineage-forked":
            tid = event.get("thread_id")
            new = event.get("to_lineage")
            if not isinstance(tid, str) or not isinstance(new, str):
                raise ApprovalCeremonyError(
                    "ceremony-v2-malformed",
                    "journal line %d: bad lineage-forked" % lineno)
            super(FileApprovalStore, self).set_lineage(tid, new)
        elif kind == "once-token-fired":
            tid = event.get("thread_id")
            token = event.get("token")
            if not isinstance(tid, str) or not isinstance(token, str):
                raise ApprovalCeremonyError(
                    "ceremony-v2-malformed",
                    "journal line %d: bad once-token-fired" % lineno)
            super(FileApprovalStore, self).once_put(
                tid, token, event.get("result"))
        else:
            raise ApprovalCeremonyError(
                "ceremony-v2-malformed",
                "journal line %d: unknown event %r" % (lineno, kind))

    @staticmethod
    def _check_record(record, lineno):
        need = ("approval_id", "thread_id", "lineage", "name",
                "payload", "payload_digest", "allowed_verdicts",
                "issued_at")
        if not isinstance(record, dict) or \
                any(k not in record for k in need):
            raise ApprovalCeremonyError(
                "ceremony-v2-malformed",
                "journal line %d: bad approval-requested" % lineno)

    # -- mutating overrides (journal every mutation) -----------------

    def put_record(self, record):
        super(FileApprovalStore, self).put_record(record)
        self._journal({"event": "approval-requested", "record": record})

    def mark_consumed(self, approval_id):
        super(FileApprovalStore, self).mark_consumed(approval_id)
        self._journal({"event": "approval-resumed",
                       "approval_id": approval_id})

    def set_lineage(self, thread_id, lineage):
        old = self.current_lineage(thread_id)
        super(FileApprovalStore, self).set_lineage(thread_id, lineage)
        self._journal({"event": "lineage-forked", "thread_id": thread_id,
                       "from_lineage": old, "to_lineage": lineage})

    def once_put(self, thread_id, token, result):
        super(FileApprovalStore, self).once_put(thread_id, token, result)
        self._journal({"event": "once-token-fired", "thread_id": thread_id,
                       "token": token, "result": result})


# ------------------------------------------------------------------
# The gate.
# ------------------------------------------------------------------

class ApprovalGate(object):
    """The approval-ceremony v2 gate.

    ``verifiers`` maps reviewer DID -> ``gov.signing.Verifier``: the
    deployment-pinned approver registry. A resume receipt must verify
    under the key its statement names as reviewer, and that reviewer
    must be registered. Thread-id-alone resume is dropped: without a
    signed receipt from a registered approver, nothing advances.
    """

    def __init__(self, store, verifiers):
        if not isinstance(verifiers, dict) or not verifiers:
            raise ApprovalCeremonyError(
                "ceremony-v2-malformed",
                "verifiers must be a non-empty {reviewer DID: Verifier}")
        for did, verifier in verifiers.items():
            if not isinstance(did, str) or not did or \
                    not hasattr(verifier, "verify"):
                raise ApprovalCeremonyError(
                    "ceremony-v2-malformed",
                    "verifier registry entry malformed")
        self._store = store
        self._verifiers = dict(verifiers)

    # -- request ----------------------------------------------------

    def request_approval(self, thread_id, name, payload,
                         allowed_verdicts=("accept", "ignore", "respond",
                                           "edit"),
                         response_schema=None, now=None, lineage=None):
        """Surface an approval request. Idempotent: the same
        (thread, lineage, name, payload) returns the same approval —
        re-executing the requesting node never double-pends."""
        self._check_shape(thread_id, name, payload, allowed_verdicts,
                          response_schema, now)
        lineage = lineage or self._store.current_lineage(thread_id)
        if not isinstance(lineage, str) or not lineage:
            raise ApprovalCeremonyError("ceremony-v2-malformed",
                                        "lineage must be a non-empty str")
        digest = _payload_digest(payload)
        aid = _approval_id(thread_id, lineage, name, digest)
        existing = self._store.get_record(aid)
        if existing is not None:
            return self._surfaced(existing)
        record = {
            "approval_id": aid,
            "thread_id": thread_id,
            "lineage": lineage,
            "name": name,
            "payload": copy.deepcopy(payload),
            "payload_digest": digest,
            "allowed_verdicts": list(allowed_verdicts),
            "response_schema": (None if response_schema is None
                                else response_schema.to_json()),
            "issued_at": now,
        }
        self._store.put_record(record)
        return self._surfaced(record)

    @staticmethod
    def _surfaced(record):
        return {
            "approval_id": record["approval_id"],
            "thread_id": record["thread_id"],
            "lineage": record["lineage"],
            "payload_digest": record["payload_digest"],
            "allowed_verdicts": list(record["allowed_verdicts"]),
            "issued_at": record["issued_at"],
            # The routing-key note travels with every surfaced request:
            "id_note": "approval_id is a deterministic routing key, "
                       "not a capability and not a secret.",
        }

    def _check_shape(self, thread_id, name, payload, allowed_verdicts,
                     response_schema, now):
        if not isinstance(thread_id, str) or not thread_id:
            raise ApprovalCeremonyError("ceremony-v2-malformed",
                                        "thread_id must be non-empty str")
        if not isinstance(name, str) or not name:
            raise ApprovalCeremonyError("ceremony-v2-malformed",
                                        "name must be non-empty str")
        if not isinstance(payload, dict):
            raise ApprovalCeremonyError("ceremony-v2-malformed",
                                        "payload must be a mapping")
        try:
            _canonical(payload)
        except (TypeError, ValueError):
            raise ApprovalCeremonyError("ceremony-v2-malformed",
                                        "payload must be JSON-serializable")
        if not isinstance(allowed_verdicts, (list, tuple)) or \
                not allowed_verdicts or \
                any(v not in _VERDICTS for v in allowed_verdicts):
            raise ApprovalCeremonyError(
                "ceremony-v2-malformed",
                "allowed_verdicts must be a non-empty subset of %r"
                % (_VERDICTS,))
        if response_schema is not None and \
                not isinstance(response_schema, ResponseSchema):
            # Bare dicts (JSON Schema on the wire) are refused here, at
            # request time — never surfaced-but-unvalidated (T4).
            raise ApprovalCeremonyError(
                "ceremony-v2-schema-invalid",
                "response_schema must be a ResponseSchema, not %r"
                % type(response_schema).__name__)
        if not isinstance(now, int) or isinstance(now, bool):
            raise ApprovalCeremonyError("ceremony-v2-malformed",
                                        "now must be an int (no clock)")

    # -- resume -----------------------------------------------------

    def resume_approval(self, approval_id, verdict, arg,
                        receipt_envelope, now=None):
        """Resume one approval by id. Refusals raise
        ``ApprovalCeremonyError`` with a machine code; a successful
        resume returns the outcome dict (never raises on success)."""
        checked = []
        if not isinstance(now, int) or isinstance(now, bool):
            raise ApprovalCeremonyError("ceremony-v2-malformed",
                                        "now must be an int (no clock)")
        # (1) shape.
        if not isinstance(approval_id, str) or not approval_id:
            raise ApprovalCeremonyError("ceremony-v2-malformed",
                                        "approval_id must be non-empty str")
        if verdict not in _VERDICTS:
            raise ApprovalCeremonyError("ceremony-v2-malformed",
                                        "verdict must be one of %r"
                                        % (_VERDICTS,))
        checked.append("shape")
        # (2) known approval.
        record = self._store.get_record(approval_id)
        if record is None:
            raise ApprovalCeremonyError("ceremony-v2-unknown-approval",
                                        "no such pending approval")
        checked.append("known")
        # (3) lineage: an approval from an abandoned lineage never
        # resumes — the fork re-fires it under a new id instead.
        if record["lineage"] != \
                self._store.current_lineage(record["thread_id"]):
            raise ApprovalCeremonyError(
                "ceremony-v2-stale-lineage",
                "approval belongs to abandoned lineage %r"
                % (record["lineage"],))
        checked.append("lineage")
        # (4) one-shot consumption.
        if self._store.is_consumed(approval_id):
            raise ApprovalCeremonyError("ceremony-v2-already-consumed",
                                        "approval already consumed")
        checked.append("not-consumed")
        # (5) verdict allowlist, ENGINE-enforced (T5).
        if verdict not in record["allowed_verdicts"]:
            raise ApprovalCeremonyError(
                "ceremony-v2-verdict-not-allowed",
                "verdict %r not in allowed %r"
                % (verdict, record["allowed_verdicts"]))
        checked.append("verdict-allowed")
        # (6) typed verdict payloads.
        self._check_arg_shape(verdict, arg)
        checked.append("arg-shape")
        # (7) signed approver receipt (T2/T6): the statement's reviewer
        # must be a registered approver, the signature must verify
        # under that reviewer's key, and the receipt must bind the
        # exact surfaced payload digest (test 8).
        receipt_digest = self._check_receipt(record, receipt_envelope)
        checked.append("receipt")
        # (8) response-schema validation: the node receives the
        # VALIDATED object, never the raw resume value.
        payload_out = self._validated_payload(record, verdict, arg)
        checked.append("schema")
        # Consume (one-shot) and return.
        self._store.mark_consumed(approval_id)
        outcome = {
            "approved": verdict in ("accept", "edit"),
            "approval_id": approval_id,
            "verdict": verdict,
            "payload": payload_out,
            "receipt_digest": receipt_digest,
            "checked": checked,
            "out_of_scope": _OUT_OF_SCOPE,
        }
        outcome["outcome"] = {
            "accept": "accepted", "ignore": "declined",
            "respond": "responded", "edit": "edited",
        }[verdict]
        return outcome

    @staticmethod
    def _check_arg_shape(verdict, arg):
        if verdict in ("accept", "ignore"):
            if arg is not None:
                raise ApprovalCeremonyError(
                    "ceremony-v2-verdict-arg-mismatch",
                    "%r carries no payload (got %r)"
                    % (verdict, type(arg).__name__))
        elif verdict == "respond":
            if not isinstance(arg, str):
                raise ApprovalCeremonyError(
                    "ceremony-v2-verdict-arg-mismatch",
                    "respond carries a str feedback (got %r)"
                    % type(arg).__name__)
        elif verdict == "edit":
            if not isinstance(arg, dict):
                raise ApprovalCeremonyError(
                    "ceremony-v2-verdict-arg-mismatch",
                    "edit carries an action mapping (got %r)"
                    % type(arg).__name__)

    def _check_receipt(self, record, receipt_envelope):
        from gov import corroboration_receipt as cr
        if not isinstance(receipt_envelope, dict):
            raise ApprovalCeremonyError("ceremony-v2-receipt-invalid",
                                        "receipt must be a DSSE envelope")
        # Read the statement's reviewer WITHOUT trusting it, then
        # verify under the registered key for that reviewer.
        try:
            raw = base64.b64decode(receipt_envelope.get("payload", ""),
                                   validate=True)
            statement = json.loads(raw.decode("utf-8"))
            reviewer = statement["predicate"]["reviewer"]
        except (ValueError, KeyError, TypeError):
            raise ApprovalCeremonyError("ceremony-v2-receipt-invalid",
                                        "receipt payload unreadable")
        verifier = self._verifiers.get(reviewer)
        if verifier is None:
            raise ApprovalCeremonyError(
                "ceremony-v2-receipt-invalid",
                "reviewer %r is not a registered approver" % (reviewer,))
        try:
            _ok, verified_statement = cr.verify_envelope(
                receipt_envelope, verifier)
        except Exception as exc:  # noqa: BLE001 -- mapped below
            raise ApprovalCeremonyError(
                "ceremony-v2-receipt-invalid",
                "receipt verification failed: %s: %s"
                % (type(exc).__name__, getattr(exc, "code", exc)))
        try:
            cr.verify_statement_binding(verified_statement,
                                        record["payload_digest"])
        except Exception as exc:  # noqa: BLE001 -- mapped below
            raise ApprovalCeremonyError(
                "ceremony-v2-payload-tampered",
                "receipt does not bind the surfaced payload: %s"
                % getattr(exc, "code", exc))
        return _sha256_hex(_canonical(receipt_envelope))

    def _validated_payload(self, record, verdict, arg):
        schema_json = record.get("response_schema")
        schema = None
        if schema_json is not None:
            try:
                schema = ResponseSchema.from_json(schema_json)
            except _SchemaViolation as exc:
                raise ApprovalCeremonyError("ceremony-v2-schema-invalid",
                                            "stored schema corrupt: %s"
                                            % (exc,))
        if verdict == "accept":
            return copy.deepcopy(record["payload"])
        if verdict == "ignore":
            return None
        # respond / edit: the node receives the VALIDATED object.
        if schema is None:
            return copy.deepcopy(arg)
        try:
            return schema.validate(copy.deepcopy(arg))
        except _SchemaViolation as exc:
            raise ApprovalCeremonyError("ceremony-v2-schema-violation",
                                        "resume value fails schema: %s"
                                        % (exc,))

    # -- resume_next: single-value mode, ambiguity fails closed --------

    def resume_next(self, thread_id, verdict, arg, receipt_envelope,
                    now=None):
        """Positional resume: binds to THE pending approval. With zero
        pending -> unknown; with more than one -> hard error
        (ambiguity fails closed, langgraph's RuntimeError behavior)."""
        hanging = self.pending(thread_id)
        if not hanging:
            raise ApprovalCeremonyError("ceremony-v2-unknown-approval",
                                        "no pending approval on thread")
        if len(hanging) > 1:
            raise ApprovalCeremonyError(
                "ceremony-v2-ambiguous-resume",
                "%d approvals pending; address one by id"
                % len(hanging))
        return self.resume_approval(hanging[0]["approval_id"], verdict,
                                    arg, receipt_envelope, now=now)

    # -- hanging approvals --------------------------------------------

    def pending(self, thread_id):
        """Hanging approvals: pending minus consumed, current lineage."""
        return [self._surfaced(r)
                for r in self._store.pending(thread_id)]

    # -- fork: stale lineages re-fire ----------------------------------

    def fork_thread(self, thread_id, new_lineage, now=None):
        """Move a thread to a new lineage. Every pending approval is
        RE-FIRED under a new id in the new lineage; approvals from the
        abandoned lineage can never resume again (test 7)."""
        if not isinstance(new_lineage, str) or not new_lineage:
            raise ApprovalCeremonyError("ceremony-v2-malformed",
                                        "new_lineage must be non-empty str")
        if not isinstance(now, int) or isinstance(now, bool):
            raise ApprovalCeremonyError("ceremony-v2-malformed",
                                        "now must be an int (no clock)")
        hanging = self._store.pending(thread_id)
        refired = []
        for record in hanging:
            schema = None
            if record.get("response_schema") is not None:
                schema = ResponseSchema.from_json(
                    record["response_schema"])
            new_rec = self.request_approval(
                thread_id, record["name"], record["payload"],
                allowed_verdicts=tuple(record["allowed_verdicts"]),
                response_schema=schema, now=now, lineage=new_lineage)
            refired.append(new_rec["approval_id"])
        self._store.set_lineage(thread_id, new_lineage)
        return refired

    # -- once-tokens: no pre-gate side-effect replay --------------------

    def run_once(self, thread_id, once_token, fn):
        """Execute ``fn`` at most once per (thread, token), durably.

        A re-executed node calls its pre-gate side effects through
        here: the first call runs ``fn`` and journals the result; later
        calls (same thread+token, even after restart) return the
        cached result without re-running. This is the discipline the
        re-execution trap forces, without copying the trap.
        """
        if not isinstance(thread_id, str) or not thread_id:
            raise ApprovalCeremonyError("ceremony-v2-malformed",
                                        "thread_id must be non-empty str")
        if not isinstance(once_token, str) or not once_token:
            raise ApprovalCeremonyError("ceremony-v2-malformed",
                                        "once_token must be non-empty str")
        cached = self._store.once_get(thread_id, once_token)
        if cached is not _MISSING:
            return copy.deepcopy(cached)
        result = fn()
        try:
            json.dumps(result)
        except (TypeError, ValueError):
            raise ApprovalCeremonyError(
                "ceremony-v2-malformed",
                "run_once result must be JSON-serializable")
        self._store.once_put(thread_id, once_token,
                             copy.deepcopy(result))
        return result


__all__ = [
    "ApprovalCeremonyError",
    "ApprovalGate",
    "ResponseSchema",
    "MemoryApprovalStore",
    "FileApprovalStore",
]
