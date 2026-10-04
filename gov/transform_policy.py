"""Deterministic transform-declassification policy.

A trusted transform (sanitizer, classifier, formatter) is a
*declassification point*: its output may be labeled above its inputs'
trust only through this module's rules. The policy **governs**; it never
executes the transform. The caller runs the transform (in whatever sandbox
the deployment uses) and presents the output for certification.

Rules (see SPEC.md for the full design lineage):
1. Unregistered transforms run on the data plane: output keeps
   min(input labels), never lowers. ``transform-unregistered``.
2. The presented function must match the registered (where) identity:
   module + qualname + code digest. ``transform-identity-mismatch``.
3. Model-mediated transforms are NEVER label-lowering, even with a token:
   structural, not a policy knob. ``transform-model-lowering-refused``.
4. Deterministic outputs are re-verified against the declared output
   contract (capacity, max_bytes, allowlist shape / enum membership)
   BEFORE any label decision. Failure refuses coded; laundered bytes are
   never silently passed. ``transform-contract-violated`` /
   ``transform-capacity-exceeded``.
5. Lowering (label above min input trust):
   - bounded capacities (bool/enum/number): free within the bit budget;
     the registration is the audited act. No token.
   - string capacity: requires a valid single-use ``transform-declassify``
     token (exact mode) minted through the approval path. Without a token
     the output stays at data-plane trust (usable, not lowered). Invalid
     token -> ``transform-token-invalid``; replayed nonce ->
     ``transform-token-replayed``.
6. Certified outputs are HMAC-sealed (F34 key ceremony, no new crypto)
   and convertible to ``provenance_labels.Segment`` via ``to_segment()``:
   the additive sink wiring. The sink verifies the seal (existing
   behavior); forgery requires the F34 key.

Stdlib only. Deterministic except for explicit ``now`` on the token path
(the caller supplies it; never read on the hot path otherwise).
"""

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import threading
import time

try:
    import fcntl
except ImportError:  # pragma: no cover -- Linux-only deployment
    fcntl = None

try:
    from . import approval_tokens as _at
except ImportError:  # standalone
    import approval_tokens as _at
try:
    from . import provenance_labels as _pl
except ImportError:  # standalone
    import provenance_labels as _pl
try:
    from .log import _active_key
except ImportError:  # standalone
    from log import _active_key
try:
    from . import transform_registry as _tr
except ImportError:  # standalone
    import transform_registry as _tr

__all__ = [
    "TransformError",
    "TransformResult",
    "TransformOutput",
    "TransformPolicy",
    "FileConsumeStore",
    "TRANSFORM_DECLASSIFY_CAPABILITY",
    "verify_output",
    "output_digest_of",
    "to_segment",
    "POLICY_VERSION",
]

POLICY_VERSION = 1

#: The step-3 capability a transform-declassify token must carry. The
#: *decision to declassify* is a privileged, audited act minted through
#: the existing approval path -- not a property of the transform.
TRANSFORM_DECLASSIFY_CAPABILITY = "transform-declassify"

_CONSUME_DOMAIN = b"transform-consume-v1:"
_OUTPUT_DOMAIN = b"transform-output-v1:"

#: Refusal codes decided by this module (also in gov/decision_codes.py,
#: the transform-* family).
POLICY_CODES = (
    "transform-unregistered",
    "transform-identity-mismatch",
    "transform-model-lowering-refused",
    "transform-contract-violated",
    "transform-token-invalid",
    "transform-token-replayed",
    "transform-ledger-corrupt",
    "transform-capacity-exceeded",
)

#: FIDES capacity classes. Narrowing is allowed only under a declared
#: string (a bool/number/enum value inside a string channel is still
#: just a string to the consumer); every other declared class requires
#: the actual capacity to match exactly. Deliberately stricter than the
#: full FIDES lattice: a declared enum is a closed set, and anything
#: outside it is a laundering-budget violation.
_CAPACITY_RANK = {"bool": 0, "number": 1, "enum": 2, "string": 3,
                  "opaque-ref": 4}

#: bool/enum/number channels carry a bounded number of bits, so lowering
#: through them needs no per-use token; the registration is the audit.
_BOUNDED = frozenset({"bool", "enum", "number"})

#: Allowed bits per capacity class for the robustness check.
_CAPACITY_BITS = {"bool": 1.0, "number": 64.0, "opaque-ref": 0.0}

_LEDGER_FILENAME = "transform_consume_ledger.jsonl"
_REF_PATTERN = re.compile(r"^\$[A-Za-z0-9_\-]{1,64}$")


class TransformError(Exception):
    """Coded-by-construction refusal from the transform policy.

    The message always starts with the machine-checkable code.
    """


def _fail(code, detail):
    raise TransformError("%s: %s" % (code, detail))


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _hex32(value, what):
    if not isinstance(value, str) or len(value) != 32:
        _fail("transform-token-invalid",
              "%s must be 32 hex chars" % what)
    try:
        int(value, 16)
    except ValueError:
        _fail("transform-token-invalid",
              "%s must be 32 hex chars" % what)
    return value


class TransformResult(object):
    """The outcome of ``TransformPolicy.certify``.

    ``verdict`` is one of "LOWERED" (label raised above min input trust),
    "DATA_PLANE" (output usable at min input trust; no lowering), or
    "REFUSE" (coded refusal; ``sealed`` is None). ``code`` is the
    machine-checkable refusal code, or None when nothing was refused.
    """

    __slots__ = ("verdict", "label", "sealed", "code", "detail")

    def __init__(self, verdict, label, sealed, code, detail=""):
        self.verdict = verdict
        self.label = label
        self.sealed = sealed
        self.code = code
        self.detail = detail

    def __repr__(self):
        return ("TransformResult(verdict=%r, label=%r, code=%r)"
                % (self.verdict, self.label, self.code))


class TransformOutput(object):
    """A policy-sealed transform output (the Trusted Types typed object).

    Binds (transform name, output bytes digest, certified label, capacity,
    verdict, basis) under an HMAC seal. ``basis`` is the consuming token
    nonce for token-gated lowering, "bounded" for bit-budget lowering, or
    "data-plane" when no lowering occurred.
    """

    __slots__ = ("name", "output", "output_digest", "label", "capacity",
                 "verdict", "basis", "nonce", "signature")

    def __init__(self, name, output, output_digest, label, capacity,
                 verdict, basis, nonce, signature):
        self.name = name
        self.output = output
        self.output_digest = output_digest
        self.label = label
        self.capacity = capacity
        self.verdict = verdict
        self.basis = basis
        self.nonce = nonce
        self.signature = signature

    def _body(self):
        return {
            "v": POLICY_VERSION,
            "name": self.name,
            "output_digest": self.output_digest,
            "label": self.label,
            "capacity": self.capacity,
            "verdict": self.verdict,
            "basis": self.basis,
            "nonce": self.nonce,
        }

    def __repr__(self):
        return ("TransformOutput(name=%r, label=%r, verdict=%r)"
                % (self.name, self.label, self.verdict))


def _seal_output_body(body):
    key, key_epoch = _active_key()
    msg = (_OUTPUT_DOMAIN + key_epoch.encode("utf-8") + b"|"
           + _canonical(body).encode("utf-8"))
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_output(out):
    """Constant-time verification of a sealed TransformOutput.

    Returns False for ANY mismatch: wrong bytes, tampered fields, wrong
    key, or a missing signature. Never raises on adversarial input.
    """
    try:
        if not isinstance(out, TransformOutput):
            return False
        if not out.signature:
            return False
        if hashlib.sha256(out.output).hexdigest() != out.output_digest:
            return False
        expected = _seal_output_body(out._body())
        return hmac.compare_digest(expected, out.signature)
    except Exception:
        return False


def output_digest_of(out):
    """The SHA-256 digest the sealed output commits to."""
    return out.output_digest


def _replace_output(out, new_output):
    """Test helper: copy a sealed output with different bytes (the seal
    then fails -- used to prove tamper-evidence)."""
    return TransformOutput(
        name=out.name, output=new_output, output_digest=out.output_digest,
        label=out.label, capacity=out.capacity, verdict=out.verdict,
        basis=out.basis, nonce=out.nonce, signature=out.signature)


def to_segment(sealed):
    """Convert a verified sealed output to a provenance Segment.

    The additive sink wiring: the segment carries origin "transform",
    principal = transform name, and the certified trust level, sealed via
    ``sign_label``. ``provenance_gate`` verifies the seal (existing sink
    behavior); unverifiable segments degrade to UNTRUSTED there.
    Raises TransformError (transform-contract-violated) on an unverified
    sealed output -- never emit an uncertified segment.
    """
    if not verify_output(sealed):
        _fail("transform-contract-violated",
              "cannot convert an unverified transform output to a segment")
    try:
        text = sealed.output.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    label = _pl.ProvenanceLabel(
        origin="transform", principal=sealed.name,
        trust_level=int(sealed.label), nonce=sealed.nonce, signature="")
    # The seal binds the exact segment content the sink will grade
    # (provenance_labels requires str for sealing).
    sealed_label = _pl.sign_label(label, text)
    return _pl.Segment(segment_id="transform-" + sealed.nonce[:12],
                       label=sealed_label, content=text)


class FileConsumeStore(object):
    """Durable, TokenConsumeStore-compatible nonce ledger.

    Append-only JSONL, hash-chained, each line HMAC-sealed under the F34
    key (domain ``transform-consume-v1:``). Replays the file on init; a
    broken chain fails closed (``transform-ledger-corrupt``): the policy
    then refuses every token-gated lowering rather than risk a replay.

    Concurrency (B1): ``consume`` holds a process-wide ``threading.Lock``
    and an exclusive ``fcntl`` lock on the ledger file while it re-scans
    the file for the nonce and appends. The check-and-append is therefore
    atomic across threads AND across processes sharing the directory --
    two concurrent consumers cannot both spend one token. (The
    ``is_consumed`` probe inside ``verify_token`` is advisory; ``consume``
    is the authoritative enforcement point.)

    This addresses the wave-314 "process-local nonce store" residual for
    the transform-declassify token family: two policy instances sharing
    ``directory`` refuse cross-instance replays. Honest bounds: the
    directory must be shared by all instances that honor the tokens; an
    operator-wiped ledger is an auditable genesis event, not a silent
    reset; *truncation* (suffix deletion) is undetectable by a hash chain
    and resurrects consumed nonces -- deployments that need truncation
    detection must snapshot the tip digest out-of-band. Without a
    directory the policy falls back to the process-local
    ``TokenConsumeStore`` (same residual, explicit).
    """

    def __init__(self, directory):
        self._dir = os.path.abspath(directory)
        try:
            os.makedirs(self._dir, exist_ok=True)
        except OSError as e:
            _fail("transform-ledger-corrupt",
                  "cannot create consume-ledger directory: %r" % (e,))
        self._path = os.path.join(self._dir, _LEDGER_FILENAME)
        self._lock = threading.Lock()
        self._consumed = set()
        self._last = "GENESIS"
        self._load()

    def _line_digest(self, nonce, consumed_at, prev):
        key, key_epoch = _active_key()
        msg = (_CONSUME_DOMAIN + key_epoch.encode("utf-8") + b"|"
               + _canonical({"nonce": nonce, "consumed_at": consumed_at,
                             "prev": prev}).encode("utf-8"))
        return hmac.new(key, msg, hashlib.sha256).hexdigest()

    def _verify_lines(self, lines):
        """Verify a chain of ledger lines. Returns (consumed, tip).
        Raises transform-ledger-corrupt on ANY defect -- never partially."""
        consumed = set()
        prev = "GENESIS"
        for i, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                _fail("transform-ledger-corrupt",
                      "ledger line %d is not JSON" % (i,))
            try:
                if not isinstance(rec, dict) or rec.get("prev") != prev:
                    _fail("transform-ledger-corrupt",
                          "ledger chain broken at line %d" % (i,))
                nonce = rec.get("nonce")
                at = rec.get("consumed_at")
                if not isinstance(nonce, str) or not isinstance(at, int) \
                        or isinstance(at, bool):
                    _fail("transform-ledger-corrupt",
                          "ledger line %d malformed" % (i,))
                expected = self._line_digest(nonce, at, prev)
                if not hmac.compare_digest(expected,
                                           rec.get("digest") or ""):
                    _fail("transform-ledger-corrupt",
                          "ledger seal mismatch at line %d" % (i,))
            except TransformError:
                raise
            except Exception as e:  # noqa: BLE001 -- tampered line shapes
                _fail("transform-ledger-corrupt",
                      "ledger line %d unreadable: %r" % (i, e))
            consumed.add(nonce)
            prev = expected
        return consumed, prev

    def _load(self):
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except FileNotFoundError:
            return
        except OSError as e:
            _fail("transform-ledger-corrupt",
                  "cannot read consume ledger: %r" % (e,))
        self._consumed, self._last = self._verify_lines(lines)

    def is_consumed(self, nonce):
        # Advisory only (used by verify_token's replay probe); the
        # authoritative check-and-set lives in consume().
        return nonce in self._consumed

    def snapshot(self):
        return {"consumed": sorted(self._consumed), "tip": self._last}

    def consume(self, nonce, now=None):
        """Consume a nonce durably and atomically.

        Holds the process lock and an exclusive file lock while
        re-scanning the ledger and appending, so concurrent consumers
        (threads or processes) cannot double-spend. Raises
        transform-token-replayed on a double consumption and
        transform-ledger-corrupt on I/O or chain failure.
        """
        _hex32(nonce, "nonce")
        try:
            at = int(now) if now is not None else int(time.time())
        except (TypeError, ValueError):
            _fail("transform-token-invalid", "now must be an int epoch")
        with self._lock:
            try:
                fh = open(self._path, "a+", encoding="utf-8")
            except OSError as e:
                _fail("transform-ledger-corrupt",
                      "cannot open consume ledger: %r" % (e,))
            try:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                try:
                    fh.seek(0)
                    consumed, tip = self._verify_lines(
                        fh.read().splitlines())
                except TransformError:
                    raise
                if nonce in consumed:
                    _fail("transform-token-replayed",
                          "nonce %s... already consumed; a token "
                          "authorizes at most one lowering"
                          % (nonce[:12],))
                digest = self._line_digest(nonce, at, tip)
                rec = {"nonce": nonce, "consumed_at": at, "prev": tip,
                       "digest": digest}
                fh.write(_canonical(rec) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                try:
                    if fcntl is not None:
                        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
                fh.close()
            self._consumed = consumed | {nonce}
            self._last = digest
            return True


def _capacity_of_bytes(data, enum_values=None):
    """Compute the actual capacity class of output bytes."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "string"
    if text in ("true", "false"):
        return "bool"
    try:
        int(text)
        return "number"
    except ValueError:
        pass
    try:
        float(text)
        return "number"
    except ValueError:
        pass
    if enum_values and text in enum_values:
        return "enum"
    if _REF_PATTERN.match(text):
        return "opaque-ref"
    return "string"


def _narrower_or_equal(actual, declared):
    """True when the actual capacity fits inside the declared class."""
    if actual == declared:
        return True
    if declared == "string" and actual in ("bool", "number", "enum"):
        return True  # a narrower value in a string channel is fine
    return False


class TransformPolicy(object):
    """Certify transform outputs against the registry's (where, what)."""

    def __init__(self, registry, consume_dir=None):
        if not isinstance(registry, _tr.TransformRegistry):
            _fail("transform-registration-denylist-refused",
                  "TransformPolicy takes a TransformRegistry")
        self._registry = registry
        self._ledger_error = None
        if consume_dir is None:
            self._store = _at.TokenConsumeStore()
            self._durable = False
        else:
            try:
                self._store = FileConsumeStore(consume_dir)
                self._durable = True
            except TransformError as e:
                # A corrupt ledger poisons the policy at construction;
                # certify() then fails closed on every token-gated path
                # (transform-ledger-corrupt) instead of crashing the
                # deployment or silently degrading to process-local.
                self._store = None
                self._durable = False
                self._ledger_error = str(e)

    @property
    def durable_consumption(self):
        """True when token replay is refused across processes/instances."""
        return self._durable

    # -- token minting -------------------------------------------------
    def mint_declassify_token(self, *, transform, output_digest, capacity,
                              input_min_trust, issuer, ttl_seconds,
                              issued_at=None, nonce=None):
        """Mint a single-use transform-declassify token through the
        approval-token path. The *decision to declassify* is privileged,
        TTL-bound, and audited -- not a property of the transform.

        ``capacity`` must be the transform's DECLARED capacity from its
        registered output contract (``certify`` verifies the token
        against the declared class); minting with any other value yields
        a token that can never verify.
        """
        binding = {"mode": "exact",
                   "args": {"transform": transform,
                            "output_digest": output_digest,
                            "capacity": capacity,
                            "input_min_trust": int(input_min_trust)}}
        return _at.issue_token(TRANSFORM_DECLASSIFY_CAPABILITY, binding,
                               issuer=issuer, ttl_seconds=ttl_seconds,
                               issued_at=issued_at, nonce=nonce)

    # -- certification ---------------------------------------------------
    def certify(self, name, transform_fn, output, input_trusts, *,
                declassify_token=None, now=None):
        """Certify a transform output. Never raises on adversarial input;
        every refusal is a TransformResult with a code."""
        try:
            at = int(now) if now is not None else int(time.time())
        except (TypeError, ValueError):
            return TransformResult("REFUSE", 0, None,
                                   "transform-contract-violated",
                                   "now must be an int epoch")
        if isinstance(output, str):
            output = output.encode("utf-8")
        if not isinstance(output, (bytes, bytearray)):
            return TransformResult("REFUSE", 0, None,
                                   "transform-contract-violated",
                                   "output must be bytes")
        output = bytes(output)
        try:
            trusts = [int(t) for t in (input_trusts or [0])]
        except (TypeError, ValueError):
            return TransformResult("REFUSE", 0, None,
                                   "transform-contract-violated",
                                   "input_trusts must be int trust levels")
        target = min(trusts)

        reg = self._registry.get(name)
        if reg is None:
            return TransformResult("DATA_PLANE", target, None,
                                   "transform-unregistered",
                                   "transform %r is not registered; output "
                                   "keeps min input trust and can never "
                                   "lower" % (name,))
        # (where): the presented function must be the registered one.
        try:
            ident = _tr.fn_identity(transform_fn)
        except TransformError:
            ident = None
        if ident != (reg.module, reg.qualname, reg.code_digest):
            return TransformResult("REFUSE", target, None,
                                   "transform-identity-mismatch",
                                   "presented function is not the registered "
                                   "transform %r" % (name,))
        # Model transforms: structural data-plane, token or not. The
        # output still respects the declared max_bytes (an unbounded
        # model output is not sealable).
        if reg.kind == "model":
            if declassify_token is not None:
                return TransformResult("REFUSE", target, None,
                                       "transform-model-lowering-refused",
                                       "a model-mediated transform can never "
                                       "lower a label, even with a token")
            if len(output) > reg.output_contract["max_bytes"]:
                return TransformResult("REFUSE", target, None,
                                       "transform-contract-violated",
                                       "model output exceeds declared "
                                       "max_bytes")
            return TransformResult("DATA_PLANE", target,
                                   self._seal(name, output, target,
                                              reg.output_contract["capacity"],
                                              "DATA_PLANE", "data-plane"),
                                   None, "")
        # Deterministic: re-verify the output against the contract first.
        ok, fail_code, actual_capacity = self._check_contract(reg, output)
        if not ok:
            return TransformResult("REFUSE", target, None, fail_code,
                                   "output of %r failed its declared "
                                   "contract" % (name,))
        declared = reg.output_contract["capacity"]
        lowers_to = reg.lowers_to
        if lowers_to is None or lowers_to <= target:
            return TransformResult("DATA_PLANE", target,
                                   self._seal(name, output, target,
                                              actual_capacity,
                                              "DATA_PLANE", "data-plane"),
                                   None, "")
        # A lowering is requested. The token decision branches on the
        # DECLARED capacity, not the actual output capacity: a declared
        # string registration was audited as token-gated, and a narrow
        # output (b"true") must not silently escape the gate.
        if declared in _BOUNDED:
            # Bit-budget channel: the registration is the audited act.
            return TransformResult("LOWERED", int(lowers_to),
                                   self._seal(name, output, int(lowers_to),
                                              actual_capacity,
                                              "LOWERED", "bounded"),
                                   None, "")
        # String / opaque-ref capacity: a minted single-use capability is
        # required.
        if declassify_token is None:
            return TransformResult("DATA_PLANE", target,
                                   self._seal(name, output, target,
                                              actual_capacity,
                                              "DATA_PLANE", "data-plane"),
                                   None,
                                   "string-capacity lowering of %r requires "
                                   "a transform-declassify token; output "
                                   "keeps data-plane trust" % (name,))
        if self._ledger_error is not None:
            # The consume ledger is corrupt: at-most-once cannot be
            # enforced, so no token-gated lowering is certified.
            return TransformResult("REFUSE", target, None,
                                   "transform-ledger-corrupt",
                                   self._ledger_error)
        presented = {"transform": name,
                     "output_digest": hashlib.sha256(output).hexdigest(),
                     "capacity": declared,
                     "input_min_trust": target}
        try:
            _at.verify_token(declassify_token,
                             capability=TRANSFORM_DECLASSIFY_CAPABILITY,
                             args=presented, now=at,
                             consume_store=self._store)
        except _at.ApprovalTokenError as e:
            code = ("transform-token-replayed"
                    if getattr(e, "code", "") == "approval-token-replayed"
                    else "transform-token-invalid")
            return TransformResult("REFUSE", target, None, code, str(e))
        except Exception as e:
            return TransformResult("REFUSE", target, None,
                                   "transform-token-invalid", repr(e))
        nonce = declassify_token.get("nonce")
        try:
            self._store.consume(nonce, now=at)
        except TransformError as e:
            msg = str(e)
            if msg.startswith("transform-ledger-corrupt"):
                code = "transform-ledger-corrupt"
            elif msg.startswith("transform-token-invalid"):
                code = "transform-token-invalid"
            else:
                code = "transform-token-replayed"
            return TransformResult("REFUSE", target, None, code, msg)
        return TransformResult("LOWERED", int(lowers_to),
                               self._seal(name, output, int(lowers_to),
                                          actual_capacity,
                                          "LOWERED", nonce),
                               None, "")

    def _seal(self, name, output, label, capacity, verdict, basis):
        out = TransformOutput(
            name=name, output=output,
            output_digest=hashlib.sha256(output).hexdigest(),
            label=int(label), capacity=capacity, verdict=verdict,
            basis=basis, nonce=secrets.token_hex(16), signature="")
        out.signature = _seal_output_body(out._body())
        return out

    def _check_contract(self, reg, output):
        """Re-verify output bytes against the declared output contract.

        Returns (ok, fail_code, actual_capacity). DOMPurify discipline:
        the checker uses the same consumer semantics the sink will use
        (here: the declared allowlist shape, fullmatch).
        """
        oc = reg.output_contract
        if len(output) > oc["max_bytes"]:
            return (False, "transform-contract-violated", "string")
        declared = oc["capacity"]
        if declared == "enum":
            # Enum membership is checked FIRST, before the capacity
            # classifier: an enum whose members spell a bool/int/float
            # (e.g. ["true","false"] or ["200","404"]) must still certify
            # its conformant outputs.
            try:
                text = output.decode("utf-8")
            except UnicodeDecodeError:
                return (False, "transform-contract-violated", "string")
            if text in oc["enum_values"]:
                return (True, None, "enum")
            actual = _capacity_of_bytes(output, oc.get("enum_values"))
            return (False, "transform-capacity-exceeded", actual)
        actual = _capacity_of_bytes(output, oc.get("enum_values"))
        if not _narrower_or_equal(actual, declared):
            # The transform emitted on a wider channel than declared:
            # the FIDES laundering budget is blown.
            return (False, "transform-capacity-exceeded", actual)
        if declared == "string":
            try:
                text = output.decode("utf-8")
            except UnicodeDecodeError:
                # String capacity is text: non-UTF-8 bytes cannot be
                # re-verified against the shape and never certify.
                return (False, "transform-contract-violated", actual)
            if "shape" in oc:
                try:
                    if re.fullmatch(oc["shape"], text) is None:
                        return (False, "transform-contract-violated", actual)
                except re.error:
                    return (False, "transform-contract-violated", actual)
        if declared == "opaque-ref":
            try:
                text = output.decode("utf-8")
            except UnicodeDecodeError:
                return (False, "transform-contract-violated", actual)
            if _REF_PATTERN.match(text) is None:
                return (False, "transform-contract-violated", actual)
        return (True, None, actual)

    # -- robustness acceptance (Zdancewic & Myers) -----------------------
    def robustness_check(self, name, transform_fn, benign_inputs,
                         attacker_inputs, *, forbidden_markers=()):
        """Executable robustness acceptance test.

        Runs the transform on benign and attacker-chosen inputs of the
        same shape. For bounded capacities, the attacker's released bits
        must not exceed EITHER the declared channel budget OR the benign
        set's release (Zdancewic & Myers: an active attacker learns no
        more than a passive one). The benign set MUST cover the declared
        output space -- e.g. for an enum classifier it must contain an
        input for every enum value -- otherwise the comparison is
        vacuous. For string capacity, no forbidden marker may survive in
        any attacker output, and every output must verify against the
        contract; string robustness REQUIRES forbidden_markers (without
        them the test is vacuous and fails closed). Raises
        TransformError on violation; returns a report dict otherwise.
        """
        reg = self._registry.get(name)
        if reg is None:
            _fail("transform-unregistered",
                  "robustness_check on unregistered transform %r" % (name,))
        try:
            ident = _tr.fn_identity(transform_fn)
        except TransformError:
            ident = None
        if ident != (reg.module, reg.qualname, reg.code_digest):
            _fail("transform-identity-mismatch",
                  "robustness_check: presented function is not the "
                  "registered transform %r" % (name,))
        capacity = reg.output_contract["capacity"]

        def run(inputs):
            outs = []
            for inp in inputs:
                raw = transform_fn(inp)
                data = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
                ok, code, _ = self._check_contract(reg, data)
                if not ok:
                    _fail(code, "robustness_check: transform output failed "
                               "its contract on input %r" % (inp,))
                outs.append(data)
            return outs

        benign_outs = run(benign_inputs)
        attacker_outs = run(attacker_inputs)
        report = {"transform": name, "capacity": capacity,
                  "n_benign": len(benign_outs),
                  "n_attacker": len(attacker_outs)}
        if capacity in _CAPACITY_BITS or capacity == "enum":
            if capacity == "enum":
                budget = math.log2(len(reg.output_contract["enum_values"]))
            else:
                budget = _CAPACITY_BITS[capacity]
            a_bits = math.log2(len(set(attacker_outs)) or 1)
            b_bits = math.log2(len(set(benign_outs)) or 1)
            report.update({"attacker_bits": a_bits, "benign_bits": b_bits,
                           "budget_bits": budget})
            if a_bits > budget + 1e-9:
                _fail("transform-capacity-exceeded",
                      "robustness_check: attacker inputs release %.2f bits "
                      "over a %.2f-bit channel" % (a_bits, budget))
            if a_bits > b_bits + 1e-9:
                _fail("transform-capacity-exceeded",
                      "robustness_check: attacker inputs release %.2f bits, "
                      "benign inputs release %.2f bits -- the active "
                      "attacker learns more than the passive one "
                      "(Zdancewic & Myers)" % (a_bits, b_bits))
            report["passed"] = True
            return report
        # string capacity: marker survival + contract already checked.
        # Without markers the test is vacuous: fail closed.
        if not forbidden_markers:
            _fail("transform-contract-violated",
                  "robustness_check: string capacity requires "
                  "forbidden_markers; without them the acceptance test is "
                  "vacuous")
        survived = []
        for out in attacker_outs:
            for marker in forbidden_markers:
                mb = marker.encode("utf-8") if isinstance(marker, str) else marker
                if mb and mb in out:
                    survived.append(marker)
        report.update({"markers_survived": sorted(set(str(m) for m in survived))})
        if survived:
            _fail("transform-contract-violated",
                  "robustness_check: attacker payload survived the "
                  "transform: %r" % (sorted(set(str(m) for m in survived)),))
        report["passed"] = True
        return report
