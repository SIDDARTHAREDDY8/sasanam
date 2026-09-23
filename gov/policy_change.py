"""Governing the governors: policy-change control (wave-75, Part 7).

The seam through which all other parts can be silently defeated is a
policy rewrite: change the rules and the enforcement, proof, identity,
detection, and response machinery all evaluate against attacker-chosen
rules. This module closes that seam.

Three pieces (``workstreams/architect/GOVERNORS_DESIGN.md``):

1. **Chained policy changes as first-class governed events.** Every
   policy mutation carries: author identity (a Wave-74 human key —
   Ed25519, verified against the same ``DelegationTrust`` roster),
   the structured diff (author/diff/approver/timestamp), and the
   tier's approvals. Changes are chained (``parent_token_hash`` → the
   prior change's authorship token) and appended as ``policy_change``
   provenance records, so they anchor like everything else (wave-72).
2. **The nuclear rule.** ``production`` policy changes require
   two-person approval: two *distinct* roster human keys. Non-
   production modes (``staging``/``dev``/``test``) take single-human.
   Enforced in code on the only mutation path, never in policy text.
3. **Break-glass with full ceremony** (the PAL model): time-boxed,
   purpose-declared, dual-recorded (request + use), auto-expiring,
   post-use review as a *required* chained event — ``breakglass``
   provenance records, each transition chained.

Construction, not text (the Wave-74 lesson): ``GovernedPolicyStore``
is the only path that changes the executor's live engine. There is
no reload-from-disk code path — editing the policy YAML on disk
mid-run does not affect the live engine. The ``apply`` path builds
the new engine from the *stored change artifact* (verify the
artifact, never the reference — the Plugin4Shell lesson).

$0 spend, synthetic/local deterministic only. No credentials, no
network. Tests use ``Ed25519Signer(secrets.token_bytes(32))`` as the
human stand-in, labeled as such.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone

from . import signing as _signing
from .policy import PolicyEngine
from .yamlmini import parse as _parse_yaml

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PolicyChangeError(Exception):
    """A policy change was refused. Fail-closed; the caller logs the
    refusal as a decision/denied record so refusals are auditable,
    never silent."""


class AuthorshipError(PolicyChangeError):
    """The authorship token failed verification."""


class TierError(PolicyChangeError):
    """The approval tier (single-human / two-person) is unsatisfied."""


class BreakGlassError(PolicyChangeError):
    """The break-glass ceremony refused an operation."""


# ---------------------------------------------------------------------------
# Canonical policy bytes + structured diff
# ---------------------------------------------------------------------------

_AUTH_DOMAIN = b"gov-policy-change/v1\x00"
_GENESIS = "GENESIS"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def canonical_policy_bytes(text):
    """Canonical bytes of a policy YAML: parse with the SAME parser the
    engine uses, re-emit as canonical JSON.

    Two files that parse identically have identical digests —
    formatting and comment changes are no-ops. The digest commits to
    *enforced meaning*, not to bytes on disk. (Enforced meaning is
    what an approval must bind to.)
    """
    if not isinstance(text, str):
        raise PolicyChangeError("policy text must be str, got %r"
                                % type(text).__name__)
    try:
        parsed = _parse_yaml(text) or {}
    except Exception as e:
        raise PolicyChangeError("policy text does not parse: %s" % e)
    return _canonical(parsed)


def policy_digest(text):
    """SHA-256 over the canonical policy bytes."""
    return hashlib.sha256(canonical_policy_bytes(text)).hexdigest()


def _rule_ids(policies):
    ids = []
    for i, rule in enumerate(policies or []):
        if not isinstance(rule, dict):
            raise PolicyChangeError("policy rule %d is not a mapping" % i)
        rid = rule.get("id", "rule-%d" % i)
        if rid in ids:
            raise PolicyChangeError("duplicate rule id %r" % rid)
        ids.append(rid)
    return ids


def diff_policies(old_text, new_text):
    """Structured diff between two policy texts (purpose vocabulary
    only — rule ids, effects, match keys; policy YAML carries rules,
    never secrets).

    Returns ``(diff_dict, diff_digest)`` where ``diff_dict`` is::

        {"rules_added": [...], "rules_removed": [...],
         "rules_changed": {rule_id: [changed fields]},
         "sections_changed": [top-level sections whose canonical
                              form moved]}

    and ``diff_digest`` commits the author to exactly this diff.
    """
    old = json.loads(canonical_policy_bytes(old_text).decode("utf-8"))
    new = json.loads(canonical_policy_bytes(new_text).decode("utf-8"))
    old_rules = {r.get("id", "rule-%d" % i): r
                 for i, r in enumerate(old.get("policies") or [])}
    new_rules = {r.get("id", "rule-%d" % i): r
                 for i, r in enumerate(new.get("policies") or [])}
    added = sorted(set(new_rules) - set(old_rules))
    removed = sorted(set(old_rules) - set(new_rules))
    changed = {}
    for rid in sorted(set(old_rules) & set(new_rules)):
        o, n = old_rules[rid], new_rules[rid]
        fields = sorted(k for k in set(o) | set(n) if o.get(k) != n.get(k))
        if fields:
            changed[rid] = fields
    sections = sorted(
        k for k in set(old) | set(new)
        if k != "policies" and
        _canonical(old.get(k)) != _canonical(new.get(k)))
    diff = {"rules_added": added, "rules_removed": removed,
            "rules_changed": changed, "sections_changed": sections}
    return diff, hashlib.sha256(_canonical(diff)).hexdigest()


# ---------------------------------------------------------------------------
# Authorship tokens (the Wave-74 human key, reused)
# ---------------------------------------------------------------------------

TOKEN_VERSION = 1
TOKEN_KIND = "policy_change_authorship"

# The approval tier bound to each deployment mode. The wave-69/70
# deployment-mode vocabulary is load-bearing here: production policy
# is the nuclear tier (two-person); everything else moves at one
# human's speed. Staging deliberately takes the single-human tier —
# it groups with dev/test in gov/keyprovider.py's non-production
# handling. A deployment that wants staging two-person tightens this
# table explicitly.
TIER_FOR_MODE = {
    "production": "two-person",
    "staging": "single-human",
    "dev": "single-human",
    "test": "single-human",
}


def required_tier(deployment_mode):
    """The approval tier for a policy change in ``deployment_mode``."""
    try:
        return TIER_FOR_MODE[deployment_mode]
    except KeyError:
        raise PolicyChangeError("unknown deployment_mode %r" % deployment_mode)


def _iso_now(now):
    dt = now or datetime.now(timezone.utc)
    if dt.tzinfo is None:
        raise PolicyChangeError("times must be tz-aware")
    return dt.astimezone(timezone.utc)


def issue_authorship_token(signer, *, policy_ref, prior_ref,
                           parent_token_hash, author, diff_digest, tier,
                           deployment_mode, session_id, purpose, now=None):
    """Issue the human-signed authorship token for a policy change.

    ``signer`` is a ``gov.signing.Signer`` — the human author's private
    key, held by the human/deployment, never by the agent (the Wave-74
    human-signature seam, unchanged). The verifier needs only the
    roster's public keys.
    """
    if not isinstance(signer, _signing.Signer):
        raise TypeError("signer must be a gov.signing.Signer")
    if parent_token_hash not in (None, _GENESIS) and \
            not _is_hex64(parent_token_hash):
        raise PolicyChangeError("parent_token_hash must be a 64-hex ref "
                                "or GENESIS")
    body = {
        "token_version": TOKEN_VERSION,
        "token_kind": TOKEN_KIND,
        "issuer": signer.key_id,
        "subject": policy_ref,
        "issued_at": _iso_now(now).isoformat(),
        "policy_ref": policy_ref,
        "prior_ref": prior_ref,
        "parent_token_hash": parent_token_hash or _GENESIS,
        "claims": {
            "author": author,
            "diff_digest": diff_digest,
            "tier": tier,
            "deployment_mode": deployment_mode,
            "session_id": session_id,
            "purpose": purpose,
        },
    }
    sig = signer.sign(_AUTH_DOMAIN + _canonical(body)).hex()
    token = dict(body)
    token["sig"] = sig
    return token


def _is_hex64(value):
    return isinstance(value, str) and len(value) == 64 and \
        all(c in "0123456789abcdef" for c in value)


def authorship_token_ref(token):
    """The log-safe ref of an authorship token: SHA-256 over the
    canonical FULL token (including the signature — a re-signed token
    is a different token). Mirrors gov/delegation_tokens.token_ref."""
    if not isinstance(token, dict):
        raise TypeError("token must be a dict")
    return hashlib.sha256(_canonical(token)).hexdigest()


def verify_authorship_token(token, trust, expected_parent=None):
    """Verify an authorship token against the roster's human keys.

    Checks: shape, ``token_kind``/version, issuer in
    ``trust.human_keys``, Ed25519 signature, and (optionally) that
    ``parent_token_hash`` equals ``expected_parent`` (the chain link —
    the previous change's authorship ref, or GENESIS).

    Returns the token's canonical info dict. Raises AuthorshipError.
    """
    if not isinstance(token, dict):
        raise AuthorshipError("authorship token must be a dict")
    if token.get("token_version") != TOKEN_VERSION:
        raise AuthorshipError("authorship token version %r unknown"
                              % token.get("token_version"))
    if token.get("token_kind") != TOKEN_KIND:
        raise AuthorshipError("token_kind %r is not a policy-change "
                              "authorship token" % token.get("token_kind"))
    key_id = token.get("issuer")
    pub = (trust.human_keys or {}).get(key_id)
    if pub is None:
        # Forged authorship: signed by a non-roster key (or a key id
        # that is not a human's). The verifier holds only roster pubs;
        # an attacker key never verifies here. This is the refusal
        # the break-first probe must show.
        raise AuthorshipError(
            "authorship issuer %r is not a rostered human key" % key_id)
    body = {k: v for k, v in token.items() if k != "sig"}
    try:
        sig = bytes.fromhex(token.get("sig") or "")
    except (TypeError, ValueError):
        raise AuthorshipError("authorship token sig is not hex")
    if not _signing.Ed25519Verifier(pub, key_id=key_id).verify(
            _AUTH_DOMAIN + _canonical(body), sig):
        raise AuthorshipError("authorship token signature invalid for "
                              "roster human key %r" % key_id)
    if expected_parent is not None and \
            token.get("parent_token_hash") != expected_parent:
        raise AuthorshipError(
            "authorship parent_token_hash %r does not match the expected "
            "chain head %r" % (token.get("parent_token_hash"),
                               expected_parent))
    return {
        "key_id": key_id,
        "author": token["claims"]["author"],
        "policy_ref": token["policy_ref"],
        "parent_token_hash": token["parent_token_hash"],
        "ref": authorship_token_ref(token),
    }


# ---------------------------------------------------------------------------
# Tiered approvals
# ---------------------------------------------------------------------------

def approval_body(*, change_id, policy_ref, approver_key_id, decision,
                  decided_at):
    """The canonical bytes an approver signs. The approval binds to the
    change id + policy digest — never to a narrative about the change."""
    return _canonical({
        "change_id": change_id,
        "policy_ref": policy_ref,
        "approver_key_id": approver_key_id,
        "decision": decision,
        "decided_at": decided_at,
    })


def sign_approval(signer, *, change_id, policy_ref, decision="approve",
                  now=None):
    """A roster human approves a change: sign the canonical approval
    body. Returns the approval dict (no secrets — signatures only)."""
    if not isinstance(signer, _signing.Signer):
        raise TypeError("signer must be a gov.signing.Signer")
    decided_at = _iso_now(now).isoformat()
    body = approval_body(change_id=change_id, policy_ref=policy_ref,
                         approver_key_id=signer.key_id,
                         decision=decision, decided_at=decided_at)
    return {
        "approval_id": hashlib.sha256(body).hexdigest()[:32],
        "change_id": change_id,
        "policy_ref": policy_ref,
        "approver_key_id": signer.key_id,
        "decision": decision,
        "decided_at": decided_at,
        "sig": signer.sign(_AUTH_DOMAIN + body).hex(),
    }


def approvals_satisfy(approvals, *, change_id, policy_ref, tier, trust,
                      author_key_id):
    """Check the tier against the recorded approvals. Fail-closed.

    Every approval must: reference this change id + policy digest,
    carry decision "approve", be signed by a roster human key, and be
    pairwise distinct. ``single-human``: >= 1 approval.
    ``two-person``: >= 2 distinct approvals, one of which is the
    author. The same human key twice is structurally refused — the
    nuclear rule counts *keys*, not signatures.
    """
    if tier not in ("single-human", "two-person"):
        raise TierError("unknown tier %r" % tier)
    seen = []
    for ap in approvals or []:
        if not isinstance(ap, dict):
            raise TierError("approval must be a dict")
        if ap.get("change_id") != change_id or \
                ap.get("policy_ref") != policy_ref:
            raise TierError("approval %r does not bind to this change "
                            "(id/digest mismatch)" % ap.get("approval_id"))
        if ap.get("decision") != "approve":
            raise TierError("approval %r has decision %r, not 'approve'"
                            % (ap.get("approval_id"), ap.get("decision")))
        key_id = ap.get("approver_key_id")
        pub = (trust.human_keys or {}).get(key_id)
        if pub is None:
            raise TierError("approver %r is not a rostered human key"
                            % key_id)
        if key_id in seen:
            raise TierError("approver key %r counted twice — two-person "
                            "requires DISTINCT human keys" % key_id)
        body = approval_body(change_id=change_id, policy_ref=policy_ref,
                             approver_key_id=key_id,
                             decision=ap["decision"],
                             decided_at=ap.get("decided_at"))
        try:
            sig = bytes.fromhex(ap.get("sig") or "")
        except (TypeError, ValueError):
            raise TierError("approval %r sig is not hex"
                            % ap.get("approval_id"))
        if not _signing.Ed25519Verifier(pub, key_id=key_id).verify(
                _AUTH_DOMAIN + body, sig):
            raise TierError("approval %r signature invalid for roster "
                            "human key %r" % (ap.get("approval_id"), key_id))
        seen.append(key_id)
    if tier == "single-human":
        if not seen:
            raise TierError("single-human tier requires >= 1 roster "
                            "human approval")
    else:
        if len(seen) < 2:
            raise TierError("two-person tier requires >= 2 DISTINCT "
                            "roster human approvals, got %d" % len(seen))
        if author_key_id not in seen:
            raise TierError("two-person tier requires the author (%r) "
                            "among the approvers" % author_key_id)
    return {"approver_key_ids": seen, "tier": tier}


# ---------------------------------------------------------------------------
# Provenance record builders (policy_change / breakglass)
# ---------------------------------------------------------------------------

_CLOCK_SOURCE = "deployment-clock"
_RETENTION_POLICY = "gov-policy-change-default"


def _prov_base(session_id, session_open, policy_version):
    return {
        "schema_version": 1,
        "session_id": session_id,
        "session_open": session_open,
        "clock_source": _CLOCK_SOURCE,
        "principal": {"kind": "service", "ref": "governor-policy-store"},
        "delegation": {
            "delegation_schema_version": 1,
            "hops": [],
            "no_delegation_reason": "governor-internal act: the policy "
                                    "store speaks for the deployment, not "
                                    "for a delegated agent",
        },
        "policy_version": policy_version,
        "matched_rules": [],
        "payload_tier": "decision",
        "retention": {
            "class": "decision",
            "until": (_iso_now(None) + timedelta(days=365)).isoformat(),
            "policy": _RETENTION_POLICY,
        },
    }


def build_policy_change_record(*, session_id, session_open,
                               policy_version, change_id, new_version,
                               prior_version, status, tier, author_key_id,
                               approver_key_ids, policy_digest, prior_digest,
                               diff_digest, diff_summary, purpose,
                               authorship_ref, approvals):
    """A ``policy_change`` provenance record dict (validated by
    ``append_provenance`` — never written raw)."""
    prov = _prov_base(session_id, session_open, policy_version)
    prov["record_type"] = "policy_change"
    prov["policy"] = {
        "change_id": change_id,
        "policy_version": new_version,
        "prior_version": prior_version,
        "status": status,
        "tier": tier,
        "author_key_id": author_key_id,
        "approver_key_ids": list(approver_key_ids),
        "policy_digest": policy_digest,
        "prior_digest": prior_digest,
        "diff_digest": diff_digest,
        "diff_summary": diff_summary,
        "purpose": purpose,
    }
    prov["approvals"] = [
        {"approval_id": a["approval_id"], "decision": a["decision"],
         "decided_by": a["approver_key_id"],
         "decided_at": a["decided_at"]}
        for a in approvals
    ]
    prov["authorship_ref"] = authorship_ref
    return {"prov": prov}


def build_breakglass_record(*, session_id, session_open, policy_version,
                            declaration_id, phase, purpose, ttl_s,
                            requested_by, reviewed_by=None,
                            review_status="pending"):
    """A ``breakglass`` provenance record dict (validated by
    ``append_provenance`` — never written raw)."""
    prov = _prov_base(session_id, session_open, policy_version)
    prov["record_type"] = "breakglass"
    prov["breakglass"] = {
        "declaration_id": declaration_id,
        "phase": phase,
        "purpose": purpose,
        "ttl_s": ttl_s,
        "requested_by": requested_by,
        "reviewed_by": reviewed_by or "",
        "review_status": review_status,
    }
    prov["approvals"] = []
    return {"prov": prov}


def _append(log, record):
    """Append a provenance record; fail-closed with a loud refusal.

    The wave-73 contract: ``append_provenance`` raises
    ``ProvenanceError`` BEFORE writing; this helper converts that into
    a ``PolicyChangeError`` so governors-path callers see one error
    family.
    """
    from .provenance import append_provenance, ProvenanceError
    try:
        return append_provenance(log, record)
    except ProvenanceError as e:
        raise PolicyChangeError("governed event refused by provenance "
                                "validation: %s" % e)


# ---------------------------------------------------------------------------
# GovernedPolicyStore — the only mutation path for the live engine
# ---------------------------------------------------------------------------

class PolicyChange:
    """A proposed policy change artifact (in deployment memory only).

    The artifact binds the exact text the author signed to the exact
    text the approvers saw to the exact text ``apply`` enforces — one
    digest end to end.
    """

    def __init__(self, *, change_id, text, prior_text, prior_version,
                 authorship_token, tier, deployment_mode, session_id,
                 purpose, diff, diff_digest, author_key_id):
        self.change_id = change_id
        self.text = text
        self.prior_text = prior_text
        self.prior_version = prior_version
        self.authorship_token = authorship_token
        self.authorship_ref = authorship_token_ref(authorship_token)
        self.tier = tier
        self.deployment_mode = deployment_mode
        self.session_id = session_id
        self.purpose = purpose
        self.diff = diff
        self.diff_digest = diff_digest
        self.author_key_id = author_key_id
        self.approvals = []
        self.status = "proposed"
        self.new_version = None


class GovernedPolicyStore:
    """The governed path for policy: propose → approve → apply.

    Construction, not text: the executor's live engine changes ONLY
    through :meth:`apply`. There is deliberately no reload-from-disk
    path — a YAML edit on disk without a governed change event does
    not move the live engine. The first engine also enters through
    here (:meth:`bootstrap`, with ``prior_version="GENESIS"``): there
    is no unauthored policy on the governed path.

    In-flight executions: :meth:`current_engine` is a plain attribute
    read (atomic under the GIL — every read sees exactly one
    version). The executor snapshots the engine at the start of each
    ``call()``; decision records carry that engine's digest
    (``policy_version``/``policy_hash``), so "which rule decided this"
    is answerable per record across a swap.
    """

    def __init__(self, *, deployment_mode, trust, log=None, session_id,
                 session_open=None):
        self.deployment_mode = deployment_mode
        self.tier_default = required_tier(deployment_mode)
        self.trust = trust
        self.log = log
        self.session_id = session_id
        self.session_open = (session_open or
                             _iso_now(None).isoformat())
        self._engine = None
        self._version = None
        self._authorship_head = _GENESIS  # prior authorship token ref
        self._changes = {}
        self._seq = 0

    # -- introspection ------------------------------------------------
    def current_engine(self):
        if self._engine is None:
            raise PolicyChangeError("no policy bootstrapped: the store "
                                    "refuses to serve an unauthored engine")
        return self._engine

    def current_version(self):
        if self._version is None:
            raise PolicyChangeError("no policy bootstrapped")
        return self._version

    def authorship_head(self):
        return self._authorship_head

    def get_change(self, change_id):
        try:
            return self._changes[change_id]
        except KeyError:
            raise PolicyChangeError("unknown change %r" % change_id)

    # -- lifecycle ----------------------------------------------------
    def bootstrap(self, text, author_signer, author, purpose,
                  approver_signers=(), now=None):
        """Install the first policy. Same rules as a change, with
        ``prior_version="GENESIS"`` — the bootstrap is authored and
        approved, not anointed."""
        return self._new_change(
            text=text, prior_text=None, prior_version=_GENESIS,
            author_signer=author_signer, author=author, purpose=purpose,
            approver_signers=approver_signers, now=now, auto_apply=True)

    def propose(self, new_text, author_signer, author, purpose, now=None):
        """Stage a change: validate, diff, sign authorship, chain the
        ``proposed`` event. The text is stored in the artifact — apply
        enforces THIS text, never a later file read."""
        if self._engine is None:
            raise PolicyChangeError("bootstrap first: no prior policy "
                                    "to diff against")
        return self._new_change(
            text=new_text, prior_text=self._current_text(),
            prior_version=self._version, author_signer=author_signer,
            author=author, purpose=purpose, approver_signers=(),
            now=now, auto_apply=False)

    def _new_change(self, *, text, prior_text, prior_version,
                    author_signer, author, purpose, approver_signers,
                    now, auto_apply):
        # The candidate must load: a malformed policy cannot even
        # become a change artifact (fail-closed at the gate — any load
        # failure, ValueError or otherwise, is a refusal).
        try:
            PolicyEngine.from_text(text, source_label="<proposed change>")
        except Exception as e:
            raise PolicyChangeError("proposed policy refused at load: "
                                    "%s: %s" % (type(e).__name__, e))
        new_digest = policy_digest(text)
        prior_digest = (policy_digest(prior_text)
                        if prior_text is not None else _GENESIS)
        if prior_text is not None:
            diff, diff_digest = diff_policies(prior_text, text)
            if not (diff["rules_added"] or diff["rules_removed"] or
                    diff["rules_changed"] or diff["sections_changed"]):
                raise PolicyChangeError("no-op change refused: the "
                                        "diff is empty")
        else:
            diff = {"rules_added": [], "rules_removed": [],
                    "rules_changed": {},
                    "sections_changed": ["<genesis>"]}
            diff_digest = hashlib.sha256(_canonical(diff)).hexdigest()
        tier = required_tier(self.deployment_mode)
        token = issue_authorship_token(
            author_signer, policy_ref=new_digest, prior_ref=prior_digest,
            parent_token_hash=self._authorship_head, author=author,
            diff_digest=diff_digest, tier=tier,
            deployment_mode=self.deployment_mode,
            session_id=self.session_id, purpose=purpose, now=now)
        # Verify our own issuance immediately against the roster: a
        # signer whose key is not rostered fails HERE, at propose
        # time — loud, never a half-registered change.
        verify_authorship_token(token, self.trust,
                                expected_parent=self._authorship_head)
        change_id = hashlib.sha256(
            _canonical({"ref": authorship_token_ref(token),
                        "seq": self._seq})).hexdigest()[:32]
        self._seq += 1
        change = PolicyChange(
            change_id=change_id, text=text, prior_text=prior_text,
            prior_version=prior_version, authorship_token=token,
            tier=tier, deployment_mode=self.deployment_mode,
            session_id=self.session_id, purpose=purpose, diff=diff,
            diff_digest=diff_digest, author_key_id=author_signer.key_id)
        self._changes[change_id] = change
        self._emit(change, status="proposed", approvals=[])
        for signer in approver_signers:
            self.approve(change_id, signer, now=now)
        if auto_apply:
            self.apply(change_id, now=now)
        return change

    def approve(self, change_id, approver_signer, now=None):
        """Record a roster human's approval on a proposed change.
        Each approval is a chained ``approved`` event."""
        change = self.get_change(change_id)
        if change.status != "proposed":
            raise PolicyChangeError("change %r is %r, not proposable"
                                    % (change_id, change.status))
        ap = sign_approval(approver_signer, change_id=change_id,
                           policy_ref=policy_digest(change.text),
                           now=now)
        change.approvals.append(ap)
        self._emit(change, status="approved", approvals=change.approvals)
        return ap

    def apply(self, change_id, now=None):
        """The ONLY path that changes the live engine. Re-verifies
        everything (authorship vs roster, tier, digest binding), builds
        the engine from the stored artifact text, swaps atomically,
        chains the ``applied`` event."""
        change = self.get_change(change_id)
        if change.status == "applied":
            raise PolicyChangeError("change %r already applied" % change_id)
        if change.status != "proposed":
            raise PolicyChangeError("change %r is %r, not appliable"
                                    % (change_id, change.status))
        if policy_digest(change.text) != \
                change.authorship_token["policy_ref"]:
            raise PolicyChangeError("change artifact text no longer "
                                    "digests to the authored policy_ref "
                                    "— the artifact was tampered with")
        info = verify_authorship_token(
            change.authorship_token, self.trust,
            expected_parent=self._authorship_head)
        verdict = approvals_satisfy(
            change.approvals, change_id=change_id,
            policy_ref=policy_digest(change.text), tier=change.tier,
            trust=self.trust, author_key_id=change.author_key_id)
        # Build from the STORED text — the pinned artifact, never a
        # re-read of the file (Plugin4Shell: verify the artifact, not
        # the reference).
        engine = PolicyEngine.from_text(
            change.text, source_label="<governed change %s>" % change_id)
        new_version = "v%d.%s" % (self._seq,
                                  policy_digest(change.text)[:8])
        change.new_version = new_version
        change.status = "applied"
        self._engine = engine  # atomic swap: the single mutation point
        self._version = new_version
        self._current_text_cache = change.text
        self._authorship_head = info["ref"]
        self._emit(change, status="applied",
                   approvals=change.approvals)
        return engine

    def reject(self, change_id, reason, now=None):
        change = self.get_change(change_id)
        if change.status != "proposed":
            raise PolicyChangeError("change %r is %r, not rejectable"
                                    % (change_id, change.status))
        change.status = "rejected"
        self._emit(change, status="rejected",
                   approvals=change.approvals)

    # -- internals ----------------------------------------------------
    def _current_text(self):
        return getattr(self, "_current_text_cache", None)

    def _emit(self, change, status, approvals):
        if self.log is None:
            return
        approver_key_ids = [a["approver_key_id"] for a in approvals]
        record = build_policy_change_record(
            session_id=self.session_id,
            session_open=self.session_open,
            policy_version=self._version or "GENESIS",
            change_id=change.change_id,
            new_version=change.new_version or
            ("pending-%s" % change.change_id[:8]),
            prior_version=change.prior_version,
            status=status, tier=change.tier,
            author_key_id=change.author_key_id,
            approver_key_ids=approver_key_ids,
            policy_digest=policy_digest(change.text),
            prior_digest=change.authorship_token["prior_ref"],
            diff_digest=change.diff_digest,
            diff_summary={
                "rules_added": len(change.diff["rules_added"]),
                "rules_removed": len(change.diff["rules_removed"]),
                "rules_changed": len(change.diff["rules_changed"]),
                "sections_changed": change.diff["sections_changed"],
            },
            purpose=change.purpose,
            authorship_ref=change.authorship_ref,
            approvals=approvals)
        _append(self.log, record)


# ---------------------------------------------------------------------------
# Break-glass ceremony (the PAL model)
# ---------------------------------------------------------------------------

# The capability to override exists — using it leaves an un-erasable,
# anchored trail. States: declared → activated → (used)* → expired →
# reviewed. Every transition is a chained ``breakglass`` provenance
# record (dual recording: the declaration is the request record, each
# use its own record).


class _Declaration:
    def __init__(self, declaration_id, purpose, ttl_s, requested_by,
                 declared_at):
        self.declaration_id = declaration_id
        self.purpose = purpose
        self.ttl_s = ttl_s
        self.requested_by = requested_by
        self.declared_at = declared_at
        self.state = "declared"
        self.uses = 0
        self.reviewed = False
        self.expired = False

    def expires_at(self):
        return self.declared_at + timedelta(seconds=self.ttl_s)

    def is_expired(self, now):
        return _iso_now(now) >= self.expires_at()


class BreakGlass:
    """Break-glass with full ceremony.

    * **Time-boxed**: a TTL on every declaration; use after expiry is
      refused AND appends an ``expired`` record (loud).
    * **Purpose-declared**: every declaration carries the human-stated
      purpose; every ``used`` record repeats it.
    * **Dual-recorded**: the declaration (request) and each use are
      separate chained events.
    * **Auto-expiring**: expiry is enforced on every operation and by
      :meth:`expire_due`.
    * **Post-use review required**: a *distinct* roster human must
      append ``reviewed``. A new declaration cannot activate while a
      prior one has a used-but-unreviewed use (the ceremony gate).

    ``trust`` is the ``DelegationTrust`` human roster; ``log`` the
    ``ActionLog`` (records chain + anchor like everything else).
    """

    def __init__(self, *, trust, log=None, session_id, session_open=None):
        self.trust = trust
        self.log = log
        self.session_id = session_id
        self.session_open = session_open or _iso_now(None).isoformat()
        self._declarations = {}
        self._seq = 0

    # -- introspection ------------------------------------------------
    def get(self, declaration_id):
        try:
            return self._declarations[declaration_id]
        except KeyError:
            raise BreakGlassError("unknown declaration %r"
                                  % declaration_id)

    def outstanding_reviews(self):
        """Declarations with used-but-unreviewed uses. Surfaced, not
        hidden — the ceremony gate reads this."""
        return [d.declaration_id for d in self._declarations.values()
                if d.uses > 0 and not d.reviewed]

    # -- ceremony -----------------------------------------------------
    def declare(self, purpose, ttl_s, requester_signer, now=None):
        """Request break-glass: a roster human states a purpose and a
        TTL. Appends the ``declared`` (request) record."""
        if not isinstance(requester_signer, _signing.Signer):
            raise TypeError("requester_signer must be a gov.signing.Signer")
        self._require_human(requester_signer.key_id)
        if not purpose or not isinstance(purpose, str):
            raise BreakGlassError("a stated purpose is required")
        if not isinstance(ttl_s, int) or ttl_s <= 0:
            raise BreakGlassError("ttl_s must be a positive int")
        if ttl_s > 86400:
            raise BreakGlassError("ttl_s > 86400 (24h): break-glass is "
                                  "an hours-scale PAL, not a standing "
                                  "privilege — re-declare instead")
        self._seq += 1
        declaration_id = "bg-%06d" % self._seq
        decl = _Declaration(declaration_id, purpose, ttl_s,
                            requester_signer.key_id, _iso_now(now))
        self._declarations[declaration_id] = decl
        self._emit(decl, "declared", review_status="n/a")
        return decl

    def activate(self, declaration_id, now=None):
        """Enter the window. Refused while another declaration has a
        used-but-unreviewed use (ceremony gate), or when expired."""
        decl = self.get(declaration_id)
        if decl.state != "declared":
            raise BreakGlassError("declaration %r is %r, not activatable"
                                  % (declaration_id, decl.state))
        outstanding = self.outstanding_reviews()
        if outstanding:
            raise BreakGlassError(
                "ceremony gate: declarations %s have used-but-unreviewed "
                "uses — review them before activating a new one"
                % outstanding)
        if decl.is_expired(now):
            decl.expired = True
            decl.state = "expired"
            self._emit(decl, "expired", review_status="n/a")
            raise BreakGlassError("declaration %r expired before "
                                  "activation" % declaration_id)
        decl.state = "active"
        self._emit(decl, "activated", review_status="n/a")
        return decl

    def use(self, declaration_id, action_summary, now=None):
        """Record one break-glass use. Requires an active,
        unexpired declaration. Use without declaration → refused (no
        record — there is nothing to dual-record). Use after expiry →
        refused AND an ``expired`` record appended (loud)."""
        decl = self.get(declaration_id)
        if decl.state != "active":
            raise BreakGlassError(
                "break-glass use refused: declaration %r is %r, not "
                "active (use without declaration is not recorded — it "
                "is refused)" % (declaration_id, decl.state))
        if decl.is_expired(now):
            decl.expired = True
            decl.state = "expired"
            self._emit(decl, "expired", review_status="pending")
            raise BreakGlassError(
                "break-glass use refused: declaration %r expired at "
                "%s — the expiry is now a chained record"
                % (declaration_id, decl.expires_at().isoformat()))
        decl.uses += 1
        self._emit(decl, "used", review_status="pending",
                   purpose="%s — use: %s" % (decl.purpose, action_summary))
        return decl

    def expire_due(self, now=None):
        """Deterministic sweeper: close every active/declared window
        past its TTL. Each expiry is a chained record."""
        closed = []
        for decl in self._declarations.values():
            if decl.state in ("declared", "active") and \
                    decl.is_expired(now):
                decl.expired = True
                decl.state = "expired"
                self._emit(
                    decl, "expired",
                    review_status=("pending" if decl.uses > 0
                                   else "n/a"))
                closed.append(decl.declaration_id)
        return closed

    def review(self, declaration_id, reviewer_signer, finding, now=None):
        """Post-use review: REQUIRED chained event. The reviewer must
        be a roster human DISTINCT from the user — two eyes on every
        PAL use. Until this lands, the declaration blocks new
        activations (see ``activate``)."""
        decl = self.get(declaration_id)
        if decl.uses == 0:
            raise BreakGlassError("nothing to review: declaration %r "
                                  "was never used" % declaration_id)
        if decl.reviewed:
            raise BreakGlassError("declaration %r already reviewed"
                                  % declaration_id)
        if not isinstance(reviewer_signer, _signing.Signer):
            raise TypeError("reviewer_signer must be a gov.signing.Signer")
        self._require_human(reviewer_signer.key_id)
        if reviewer_signer.key_id == decl.requested_by:
            raise BreakGlassError("the user cannot review their own "
                                  "break-glass use — two-person review "
                                  "required")
        if not finding or not isinstance(finding, str):
            raise BreakGlassError("a stated review finding is required")
        decl.reviewed = True
        decl.state = "reviewed"
        self._emit(decl, "reviewed", review_status="complete",
                   reviewed_by=reviewer_signer.key_id,
                   purpose="%s — review: %s" % (decl.purpose, finding))
        return decl

    # -- internals ----------------------------------------------------
    def _require_human(self, key_id):
        if key_id not in (self.trust.human_keys or {}):
            raise BreakGlassError("key %r is not a rostered human — "
                                  "break-glass is human-only" % key_id)

    def _emit(self, decl, phase, review_status, reviewed_by=None,
              purpose=None):
        if self.log is None:
            return
        from .provenance import append_provenance
        record = build_breakglass_record(
            session_id=self.session_id,
            session_open=self.session_open,
            policy_version=getattr(self, "_policy_version", "governor"),
            declaration_id=decl.declaration_id,
            phase=phase,
            purpose=purpose or decl.purpose,
            ttl_s=decl.ttl_s,
            requested_by=decl.requested_by,
            reviewed_by=reviewed_by,
            review_status=review_status)
        try:
            append_provenance(self.log, record)
        except Exception as e:
            from .provenance import ProvenanceError
            if isinstance(e, ProvenanceError):
                raise BreakGlassError("break-glass event refused by "
                                      "provenance validation: %s" % e)
            raise
