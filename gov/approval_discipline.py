"""Alertmanager-style approval discipline: inhibition, silences,
and repeat-interval coalescing in front of the approval queue.

ADAPT (pattern only) of the notification-discipline mechanism from
``prometheus/alertmanager`` (Apache-2.0; license verified from the
upstream LICENSE file on 2026-10-01; no alertmanager code or config
text vendored). The recombination target is **approval fatigue**: an
attacker (or noisy tooling) spamming the approval queue with
repeated approval requests until a human rubber-stamps one.

The three mechanisms, recombined for approvals:

- **Repeat interval.** An identical pending approval (same action,
  scope, subject, args digest, context digest) inside the repeat
  window is NOT re-prompted: the decision returns ``coalesced`` with
  the original ``pending_id`` so the caller can attach to it. A
  different decision (any identity field differs) always re-prompts.
  A pending older than the window re-prompts (re-notification).
- **Silences.** An operator-signed, time-bounded silence suppresses
  re-prompting for a stated matcher class. Creation requires a valid
  operator HMAC, a mandatory expiry inside the maximum window, and a
  journal entry. A silence covering a high/critical severity class is
  refused at creation, and a high/critical *request* is never
  silenced even when a silence matches it (defense in depth). A
  silence can only ever suppress *prompts* -- ``silence_covers`` is
  structurally False for ``"enforcement"``: the module has no
  deny-suppression API at all.
- **Inhibition.** A digest-bound refusal fact (``note_refusal``)
  inhibits the redundant prompt for the same identity while
  active. The fact must carry a ``journal_digest`` binding it to
  a journaled event; caller claims without that binding are
  refused. Full journal verification stays deployment-owned
  (see residuals).

Composition: this layer sits IN FRONT of the approval queue. The
caller passes ``queue_fn``; the module either calls it (prompt
issued) or returns a suppression decision. It never renders an
approval verdict and never replaces the queue's decision.

Caller contract -- the safe interpretation of each decision kind:

- ``"prompt"``: ``queue_fn`` was called; await its verdict.
- ``"coalesced"``: attach to ``pending_id`` -- the pending
  request's verdict covers this resubmission.
- ``"silenced"`` / ``"inhibited"``: do NOT re-prompt, and do NOT
  treat the request as approved. A silenced/inhibited request
  has no approval; the action must not proceed on this basis.
  Silence is fatigue control (stop nagging), never authorization.

Inhibition applies at every severity on purpose: it is grounded
in a per-decision refusal fact (the action was already refused,
so re-prompting is pure noise). Silences get the extra
high/critical guard because they are operator-configured
classes -- a misconfigured silence must not hide a
high-severity prompt.

Fail-closed: malformed silences/inhibitors/requests are refused with
machine codes, and a prompt is never suppressed on error -- any
suppression path that cannot be validated falls through to a fresh
prompt.

Honest residuals (deployment-owned):

- Repeat/pending/silence/inhibition state is in-memory per
  ``ApprovalDiscipline`` instance; a restart loses it.
- The operator HMAC key is deployment-owned; there is no key
  ceremony here (``_check_key`` requires >= 16 bytes, no fallback).
- ``note_refusal`` consumes a caller-presented refusal fact; the
  module checks the ``journal_digest`` binding is present and
  well-formed but does not re-verify the journal itself.
- Request ``severity`` is caller-supplied. A caller that marks a
  high-severity action ``"low"`` defeats the high-severity silence
  guard; deployments must set severity from a trusted classifier.
- Silences suppress prompts only. If a deployment wires silence
  state into an enforcement path, that wiring -- not this module --
  is the vulnerability.

Stdlib only. Deterministic. Every refusal at the public seams is
machine-coded (bare ValueError is reserved for caller misuse such
as a non-positive window or an unknown resolve verdict, per the
sibling-module convention).
"""

import hashlib
import hmac
import json
import time

SILENCE_DOMAIN = b"discipline-silence.v1"

_REQUEST_FIELDS = ("action", "scope", "subject", "args_digest",
                   "context_digest", "severity")
_SEVERITIES = ("low", "medium", "high", "critical")
_HIGH_SEVERITIES = ("high", "critical")
_MATCH_FIELDS = ("action", "scope", "subject", "severity")
_VERDICTS = ("approved", "denied", "expired")


def _decision(kind, code, pending_id, detail):
    return {"kind": kind, "code": code, "pending_id": pending_id,
            "detail": detail}


class DisciplineError(Exception):
    """Base error for approval-discipline refusals.

    Concrete subclasses carry the machine code as a class
    attribute; the base itself is never raised and therefore
    carries no taxonomy code.
    """


class InhibitorMalformed(DisciplineError):
    code = "discipline-inhibitor-malformed"


class InhibitorUnverifiable(DisciplineError):
    code = "discipline-inhibitor-unverifiable"


class RequestMalformed(DisciplineError):
    code = "discipline-request-malformed"


class SilenceForbiddenClass(DisciplineError):
    code = "discipline-silence-forbidden-class"


class SilenceMalformed(DisciplineError):
    code = "discipline-silence-malformed"


class SilenceUnjournaled(DisciplineError):
    code = "discipline-silence-unjournaled"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _check_key(key):
    if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
        raise SilenceMalformed(
            "discipline-silence-malformed: operator key must be "
            ">= 16 bytes")


def _as_list(cond):
    return cond if isinstance(cond, list) else [cond]


def _validate_matchers(matchers, forbid_high=True):
    if not isinstance(matchers, dict) or not matchers:
        raise SilenceMalformed(
            "discipline-silence-malformed: matchers must be a "
            "non-empty dict")
    for field, cond in matchers.items():
        if field not in _MATCH_FIELDS:
            raise SilenceMalformed(
                "discipline-silence-malformed: unknown matcher "
                "field %r" % (field,))
        vals = _as_list(cond)
        if not vals or not all(isinstance(v, str) and v
                               for v in vals):
            raise SilenceMalformed(
                "discipline-silence-malformed: matcher %r needs "
                "non-empty string value(s)" % (field,))
        if field == "severity":
            for v in vals:
                if v in _HIGH_SEVERITIES and forbid_high:
                    raise SilenceForbiddenClass(
                        "discipline-silence-forbidden-class: "
                        "silences cannot cover high/critical "
                        "severity")
                if v not in _SEVERITIES:
                    raise SilenceMalformed(
                        "discipline-silence-malformed: unknown "
                        "severity %r" % (v,))


def _silence_mac(key, matchers, not_after, created_by, created_at):
    body = _canonical({"matchers": matchers,
                       "not_after": not_after,
                       "created_by": created_by,
                       "created_at": created_at})
    return hmac.new(key, SILENCE_DOMAIN + body,
                    hashlib.sha256).hexdigest()


def _validate_request(request):
    if not isinstance(request, dict):
        raise RequestMalformed(
            "discipline-request-malformed: request must be a dict")
    for field in _REQUEST_FIELDS:
        val = request.get(field)
        if not isinstance(val, str) or not val:
            raise RequestMalformed(
                "discipline-request-malformed: field %r must be a "
                "non-empty string" % (field,))
    if request["severity"] not in _SEVERITIES:
        raise RequestMalformed(
            "discipline-request-malformed: unknown severity %r"
            % (request["severity"],))


def _identity(request):
    return (request["action"], request["scope"],
            request["subject"], request["args_digest"],
            request["context_digest"])


def _matchers_hit(matchers, request):
    for field, cond in matchers.items():
        if request[field] not in _as_list(cond):
            return False
    return True


class ApprovalDiscipline:
    """Inhibition / silence / repeat-interval gate for prompts."""

    def __init__(self, repeat_window=300.0,
                 max_silence_duration=3600.0, inhibit_window=600.0,
                 operator_key=None, journal=None):
        for name, val in (("repeat_window", repeat_window),
                          ("max_silence_duration",
                           max_silence_duration),
                          ("inhibit_window", inhibit_window)):
            if not isinstance(val, (int, float)) or val <= 0:
                raise ValueError("%s must be a positive number"
                                 % name)
        if operator_key is not None:
            _check_key(operator_key)
        self.repeat_window = float(repeat_window)
        self.max_silence_duration = float(max_silence_duration)
        self.inhibit_window = float(inhibit_window)
        self.operator_key = operator_key
        self.journal = journal
        self._pending = {}      # identity -> (pending_id, at)
        self._silences = {}     # silence_id -> canonical silence
        self._inhibitors = {}   # identity -> not_after
        self._seq = 0

    # -- operator side ------------------------------------------------

    def sign_silence(self, matchers, not_after, created_by="op-1",
                     now=None, key=None):
        """Mint an operator-signed silence dict (operator side).

        Shape-validated but NOT class-restricted: the verifier
        (add_silence) is the enforcement point for the
        high/critical class ban.
        """
        _validate_matchers(matchers, forbid_high=False)
        key = key if key is not None else self.operator_key
        _check_key(key)
        now = time.time() if now is None else now
        if not isinstance(not_after, (int, float)):
            raise SilenceMalformed(
                "discipline-silence-malformed: not_after must be "
                "numeric")
        created_at = float(now)
        mac = _silence_mac(key, matchers, float(not_after),
                           created_by, created_at)
        return {"matchers": matchers, "not_after": float(not_after),
                "created_by": created_by, "created_at": created_at,
                "mac": mac}

    # -- verifier side -------------------------------------------------

    def add_silence(self, silence, key=None, journal=None,
                    now=None):
        """Verify and install a silence; returns its silence_id."""
        now = time.time() if now is None else now
        if not isinstance(silence, dict):
            raise SilenceMalformed(
                "discipline-silence-malformed: silence must be a "
                "dict")
        for field in ("matchers", "not_after", "created_by",
                      "created_at", "mac"):
            if field not in silence:
                raise SilenceMalformed(
                    "discipline-silence-malformed: missing field "
                    "%r" % (field,))
        matchers = silence["matchers"]
        _validate_matchers(matchers)  # raises forbidden-class too
        not_after = silence["not_after"]
        created_at = silence["created_at"]
        if not isinstance(not_after, (int, float)) or \
                not isinstance(created_at, (int, float)):
            raise SilenceMalformed(
                "discipline-silence-malformed: not_after and "
                "created_at must be numeric")
        if not (now < not_after):
            raise SilenceMalformed(
                "discipline-silence-malformed: silence already "
                "expired")
        window = float(not_after) - float(created_at)
        if not (0 < window <= self.max_silence_duration):
            raise SilenceMalformed(
                "discipline-silence-malformed: silence window "
                "must be within (0, max_silence_duration]")
        key = key if key is not None else self.operator_key
        _check_key(key)
        want = _silence_mac(key, matchers, float(not_after),
                            silence["created_by"],
                            float(created_at))
        if not hmac.compare_digest(str(silence["mac"]), want):
            raise SilenceMalformed(
                "discipline-silence-malformed: operator signature "
                "invalid")
        journal = journal if journal is not None else self.journal
        if journal is None:
            raise SilenceUnjournaled(
                "discipline-silence-unjournaled: a silence with "
                "no journal entry is refused")
        canonical = {"matchers": matchers,
                     "not_after": float(not_after),
                     "created_by": silence["created_by"],
                     "created_at": float(created_at)}
        sid = "sil-" + hashlib.sha256(
            _canonical(dict(canonical, mac=want))).hexdigest()[:16]
        event = {"kind": "silence-created", "silence_id": sid,
                 "scope": "prompts-only"}
        event.update(canonical)
        # Journal FIRST: if the journal write raises, the silence
        # is never installed -- a silence nobody records is
        # refused, never half-installed.
        if isinstance(journal, list):
            journal.append(event)
        else:
            journal(event)
        self._silences[sid] = canonical
        return sid

    def silence_covers(self, silence_id, kind, now=None):
        """True iff the silence suppresses *prompts* of its class.

        Structurally False for kind="enforcement" (and for any
        unknown kind): silences can never suppress an enforcement
        denial -- there is no API for it.
        """
        if kind != "prompt":
            return False
        now = time.time() if now is None else now
        sil = self._silences.get(silence_id)
        return bool(sil is not None and sil["not_after"] > now)

    def note_refusal(self, fact, now=None):
        """Install an inhibition from a journaled refusal fact."""
        now = time.time() if now is None else now
        if not isinstance(fact, dict):
            raise InhibitorMalformed(
                "discipline-inhibitor-malformed: fact must be a "
                "dict")
        for field in ("action", "scope", "subject", "args_digest",
                      "context_digest"):
            if not isinstance(fact.get(field), str) or \
                    not fact.get(field):
                raise InhibitorMalformed(
                    "discipline-inhibitor-malformed: fact field "
                    "%r must be a non-empty string" % (field,))
        if fact.get("kind") != "refusal":
            raise InhibitorMalformed(
                "discipline-inhibitor-malformed: fact kind must "
                "be 'refusal'")
        digest = fact.get("journal_digest")
        if not isinstance(digest, str) or not digest:
            raise InhibitorUnverifiable(
                "discipline-inhibitor-unverifiable: refusal fact "
                "carries no journal_digest binding")
        ident = _identity(fact)
        self._inhibitors[ident] = float(now) + self.inhibit_window
        return True

    # -- the prompt seam ----------------------------------------------

    def prompt(self, request, queue_fn, now=None):
        """Decide whether an approval prompt is issued.

        Returns a decision dict: kind in {"prompt", "coalesced",
        "silenced", "inhibited"} with the matching machine code
        (None for a fresh prompt). ``queue_fn`` is called exactly
        once per issued prompt and never for a suppressed one.
        """
        now = time.time() if now is None else now
        _validate_request(request)
        ident = _identity(request)
        # Opportunistic pruning: expired silences/inhibitors are
        # dead state; drop them so the in-memory tables cannot
        # grow unboundedly.
        self._silences = {sid: sil
                          for sid, sil in self._silences.items()
                          if sil["not_after"] > now}
        self._inhibitors = {iid: until
                            for iid, until in
                            self._inhibitors.items()
                            if until > now}
        inhibited_until = self._inhibitors.get(ident)
        if inhibited_until is not None:
            return _decision("inhibited",
                             "discipline-prompt-inhibited", None,
                             {"inhibited_until": inhibited_until})
        if request["severity"] not in _HIGH_SEVERITIES:
            for sid, sil in self._silences.items():
                if _matchers_hit(sil["matchers"], request):
                    return _decision(
                        "silenced", "discipline-prompt-silenced",
                        None, {"silence_id": sid})
        pending = self._pending.get(ident)
        if pending is not None and \
                pending[1] + self.repeat_window > now:
            return _decision("coalesced",
                             "discipline-prompt-coalesced",
                             pending[0],
                             {"pending_ref": pending[0]})
        ticket = queue_fn(request)
        self._seq += 1
        pending_id = "pend-%d-%s" % (
            self._seq,
            hashlib.sha256(_canonical(ident)).hexdigest()[:8])
        self._pending[ident] = (pending_id, float(now))
        return _decision("prompt", None, pending_id,
                         {"ticket": ticket})

    def resolve(self, pending_id, verdict, now=None):
        """Mark a pending request resolved; forget its identity."""
        if verdict not in _VERDICTS:
            raise ValueError(
                "verdict must be one of %r" % (_VERDICTS,))
        for ident, (pid, _at) in list(self._pending.items()):
            if pid == pending_id:
                del self._pending[ident]
                return True
        return False
