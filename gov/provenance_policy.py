"""Admission-time provenance policy (wave-263 feature lane 3).

Adapts the slsa-framework/slsa-verifier CONSUMER shape as PATTERN ONLY
(no code copied; Apache-2.0): provenance + (source, builder, tag)
policy evaluated at ADMISSION time, verified statements piped into
policy engines (the ``--print-provenance`` idea), and Verification
Summary Attestations (VSA) as delegated verification ("I verified
artifact X against policy P at time T").

What this is: a provenance-policy consumer for evidence bundles and
gate artifacts. Before an artifact is trusted (evidence-bundle
import, gate re-run artifact, policy-bundle apply), the admission seam
checks the artifact's provenance statement against policy-as-data::

    {source:  <allowed source uris/digests>,
     builder: <allowed builder ids>,
     tag:     <version constraints>}

verified statements can be emitted (``verify_and_emit``) and piped
into the policy engine downstream, exactly the ``--print-provenance``
shape. A VSA from a trusted verifier is itself an admission
credential: the delegating verifier's key is PINNED in the policy and
the summary's scope is bounded (a VSA for policy P never admits under
policy Q; expired VSAs refused).

Fail-closed rules (all machine-coded):
- Provenance missing a field the policy requires -> refused
  (``provenance-source-refused`` / ``-builder-refused`` /
  ``-tag-refused`` / ``-subject-refused``).
- VSA from an unpinned verifier, with a bad signature, with a scope
  (policy id) mismatch, expired, or below the policy's required level
  -> ``provenance-vsa-refused``.
- A policy with no allowed sources or no allowed builders is
  VACUOUS: it admits nothing, so it cannot be constructed at all
  (``provenance-policy-vacuous``) — never a vacuous allow.
- A statement whose signature does not verify -> the emitter refuses
  to emit it (``provenance-statement-unverified``); tampered bytes
  never reach downstream policy.

Honest residuals (documented, not hidden):
- This checks provenance CLAIMS against policy; it does not make the
  claims true. A builder attestation is only as honest as the builder.
  The swapped-builder probe pins this: a validly-signed statement
  from a foreign builder still refuses.
- A VSA DELEGATES trust, it does not create it: the policy pins which
  verifier ids may speak, and the verifier's own diligence is outside
  this module's visibility. VSA is a trust edge, not a trust root.
- ``statement_from_offline_bundle`` consumes an ALREADY-VERIFIED
  bundle (verify first with the standalone verifier at
  ``tools/offline-verify``); it does not re-verify the export chain
  and does not duplicate that verifier. The offline bundle records no
  build source, so the adapter marks source ``"unrecorded"`` — a
  policy admits it only by explicitly allowing that value.

Composition: the subject digest this module binds is the same digest
``gov.safeguard_bundle.compute_bundle_digest`` produces for evidence
bundles; the adapter below bridges an exported offline bundle into a
signed provenance statement for admission.

Stdlib only. Deterministic: injectable clock (``now`` args), no I/O
except the offline-bundle adapter's file reads, no network, no
in-repo git subprocesses.
"""

import hashlib
import json
import os
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import ed25519 as _ed25519  # noqa: E402

# New decision codes introduced by this module (see gov/decision_codes.py).
CODES = (
    "provenance-builder-refused",
    "provenance-policy-vacuous",
    "provenance-source-refused",
    "provenance-statement-unverified",
    "provenance-subject-refused",
    "provenance-tag-refused",
    "provenance-vsa-refused",
)

STATEMENT_FORMAT = "sasanam-provenance-statement/1"
VSA_FORMAT = "sasanam-vsa/1"

#: Domain separation for statement signatures (Ed25519 over the
#: canonical unsigned bytes).
_STATEMENT_DOMAIN = b"sasanam-provenance-statement/v1\x00"
_VSA_DOMAIN = b"sasanam-vsa/v1\x00"

#: Source value the offline-bundle adapter writes when the bundle
#: records no build source. Policies admit it only by explicitly
#: allowing this value (an operator choice, never a default).
UNRECORDED_SOURCE = "unrecorded"

_VSA_LEVEL_RANK = {
    "SLSA_BUILD_LEVEL_1": 1,
    "SLSA_BUILD_LEVEL_2": 2,
    "SLSA_BUILD_LEVEL_3": 3,
}

_POLICY_VERSION = 1
_HEX64 = set("0123456789abcdef")


class ProvenancePolicyError(Exception):
    """Fail-closed refusal. ``code`` is a closed vocabulary member."""

    def __init__(self, code, detail=""):
        super(ProvenancePolicyError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise ProvenancePolicyError(code, detail)


def canonical_bytes(obj):
    """JCS-shaped canonical bytes (the form ``gov.offline_bundle``
    relies on; credited here rather than vendored twice)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def key_id_hex(pubkey):
    """Stable key id for a 32-byte Ed25519 public key (full hex)."""
    return bytes(pubkey).hex()


def ed25519_publickey(seed):
    """Thin re-export so callers need only this module."""
    return _ed25519.publickey(seed)


def _as_hex64(value, what=None):
    if not isinstance(value, str) or len(value) != 64:
        return None
    low = value.lower()
    if any(c not in _HEX64 for c in low):
        return None
    return low


# ---------------------------------------------------------------------------
# Statements: sign / verify / emit.
# ---------------------------------------------------------------------------

def unsigned_bytes(statement):
    """Canonical bytes of a statement WITHOUT its signatures."""
    body = {k: v for k, v in statement.items() if k != "signatures"}
    return canonical_bytes(body)


def sign_statement(statement, seed):
    """Sign a provenance statement in place (Ed25519, deterministic).

    Signs the canonical UNSIGNED bytes under ``_STATEMENT_DOMAIN`` and
    appends ``{"key_id", "sig"}`` to ``statement["signatures"]``.
    """
    if not isinstance(statement, dict):
        _refuse("provenance-statement-unverified",
                "statement must be a dict")
    pub = _ed25519.publickey(seed)
    sig = _ed25519.sign(seed, _STATEMENT_DOMAIN + unsigned_bytes(statement))
    sigs = statement.get("signatures")
    if not isinstance(sigs, list):
        sigs = []
        statement["signatures"] = sigs
    sigs.append({"key_id": key_id_hex(pub), "sig": sig.hex()})
    return statement


def verify_statement(statement, signers):
    """Verify a statement against pinned signer keys.

    ``signers`` maps key_id_hex -> pubkey_hex (the policy's
    ``statement_signers``). Returns the statement on success; raises
    ``provenance-statement-unverified`` on ANY failure (malformed
    statement, unknown key id, bad signature). The Ed25519 verify
    contract returns True/False and never raises — the False return is
    checked here (wave-243 lesson).
    """
    if not isinstance(statement, dict):
        _refuse("provenance-statement-unverified",
                "statement must be a dict")
    if statement.get("format") != STATEMENT_FORMAT:
        _refuse("provenance-statement-unverified",
                "not a sasanam provenance statement")
    if not isinstance(signers, dict) or not signers:
        _refuse("provenance-statement-unverified",
                "no pinned statement signers configured")
    sigs = statement.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        _refuse("provenance-statement-unverified",
                "statement carries no signatures")
    msg = _STATEMENT_DOMAIN + unsigned_bytes(statement)
    for entry in sigs:
        if not isinstance(entry, dict):
            continue
        key_id = entry.get("key_id")
        pub_hex = signers.get(key_id)
        if not pub_hex:
            continue  # unknown signer key: not a match, keep looking
        try:
            pub = bytes.fromhex(pub_hex)
            sig = bytes.fromhex(entry.get("sig", ""))
        except (ValueError, TypeError):
            continue
        if _ed25519.verify(pub, msg, sig) is True:
            return statement
    _refuse("provenance-statement-unverified",
            "no pinned signer signature verifies")


def verify_and_emit(statement, signers):
    """Verify a statement, then return its canonical bytes for piping.

    The ``--print-provenance`` shape: the VERIFIED statement (not a
    bare pass/fail) is the output, for downstream policy engines.
    ``policy.admit(json.loads(blob))`` consumes these bytes
    identically. A tampered statement refuses here and emits nothing.
    """
    verified = verify_statement(statement, signers)
    return canonical_bytes(verified) + b"\n"


def verify_and_print(statement, signers):
    """``verify_and_emit`` with the bytes written to stdout."""
    blob = verify_and_emit(statement, signers)
    sys.stdout.buffer.write(blob)
    sys.stdout.buffer.flush()
    return blob


# ---------------------------------------------------------------------------
# Semver tag constraints.
# ---------------------------------------------------------------------------

def _parse_semver(tag):
    """Parse ``v1.2.3``-style tags -> (nums, release_flag, pre_id) or None.

    Leading ``v``/``=`` stripped; up to three numeric core components
    (short forms zero-padded); build metadata (``+...``) ignored. A
    ``-prerelease`` suffix sorts BELOW the release (flag 0 vs 1) and
    prerelease identifiers order lexicographically (rc1 < rc2).
    Anything else -> None.
    """
    if not isinstance(tag, str) or not tag:
        return None
    t = tag.strip()
    if t[:1] in ("v", "V", "="):
        t = t[1:]
    t = t.split("+", 1)[0]
    pre, pre_id = 1, ""
    if "-" in t:
        t, pre_id = t.split("-", 1)
        pre, pre_id = 0, pre_id
    parts = t.split(".")
    if not 1 <= len(parts) <= 3:
        return None
    nums = []
    for p in parts:
        if not p.isdigit():
            return None
        nums.append(int(p))
    while len(nums) < 3:
        nums.append(0)
    return (tuple(nums), pre, pre_id)


def _semver_satisfies(tag, range_expr):
    """Comma-separated ``>=1.2.0,<2.0.0`` range check over semver tags."""
    ver = _parse_semver(tag)
    if ver is None:
        return False
    ops = {"==": lambda a, b: a == b, "!=": lambda a, b: a != b,
           ">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b,
           ">": lambda a, b: a > b, "<": lambda a, b: a < b}
    bounds = []
    for clause in str(range_expr).split(","):
        clause = clause.strip()
        if not clause:
            return False
        op = None
        for cand in ("==", "!=", ">=", "<=", ">", "<"):
            if clause.startswith(cand):
                op, operand = cand, clause[len(cand):]
                break
        if op is None:
            return False
        bound = _parse_semver(operand)
        if bound is None:
            return False
        bounds.append(bound)
        if not ops[op](ver, bound):
            return False
    # Conservative prerelease rule (npm-shaped): a prerelease tag only
    # satisfies a range that itself names a prerelease. This keeps
    # v1.0.0-rc1 out of a "<1.0.0" policy — tuple ordering alone would
    # let it slip under the ceiling.
    if ver[1] == 0 and not any(b[1] == 0 for b in bounds):
        return False
    return True


# ---------------------------------------------------------------------------
# Policy.
# ---------------------------------------------------------------------------

class ProvenancePolicy(object):
    """Policy-as-data evaluated against provenance at admission time.

    Construct via :meth:`from_dict` (validates; vacuous policies
    refuse to construct). ``admit`` returns True or raises
    ``ProvenancePolicyError`` with a closed-vocabulary code;
    ``evaluate`` is the non-raising twin.
    """

    def __init__(self, name, allowed_sources, allowed_builders,
                 tag_policy, expected_inputs, require_signed_statement,
                 statement_signers, trusted_verifiers,
                 vsa_max_age_seconds, vsa_required_level):
        self.name = name
        self.allowed_sources = tuple(allowed_sources)
        self.allowed_builders = tuple(allowed_builders)
        self.tag_policy = dict(tag_policy)
        self.expected_inputs = dict(expected_inputs)
        self.require_signed_statement = require_signed_statement
        self.statement_signers = dict(statement_signers)
        self.trusted_verifiers = dict(trusted_verifiers)
        self.vsa_max_age_seconds = vsa_max_age_seconds
        self.vsa_required_level = vsa_required_level

    @classmethod
    def from_dict(cls, d):
        """Build and validate a policy. Vacuous/malformed policies
        raise ``provenance-policy-vacuous`` — they can never admit, so
        they must not exist."""
        if not isinstance(d, dict):
            _refuse("provenance-policy-vacuous",
                    "policy must be a dict")
        name = d.get("name")
        if not isinstance(name, str) or not name:
            _refuse("provenance-policy-vacuous",
                    "policy has no name")
        if d.get("version") != _POLICY_VERSION:
            _refuse("provenance-policy-vacuous",
                    "unsupported policy version (want %d)"
                    % _POLICY_VERSION)

        def _allowed(section):
            sec = d.get(section, {})
            if not isinstance(sec, dict):
                _refuse("provenance-policy-vacuous",
                        "policy %r section malformed" % section)
            vals = sec.get("allowed", [])
            if (not isinstance(vals, list) or not vals
                    or any(not isinstance(v, str) or not v
                           for v in vals)):
                _refuse("provenance-policy-vacuous",
                        "policy has no allowed %s: admits nothing"
                        % section)
            return vals

        allowed_sources = _allowed("sources")
        allowed_builders = _allowed("builders")

        tag_policy = d.get("tags", {})
        if not isinstance(tag_policy, dict):
            _refuse("provenance-policy-vacuous", "tags section malformed")
        mode = tag_policy.get("mode", "any")
        if mode not in ("any", "versioned-tag", "branch"):
            _refuse("provenance-policy-vacuous",
                    "unknown tag mode %r" % (mode,))
        tag_allowed = tag_policy.get("allowed", [])
        if not isinstance(tag_allowed, list):
            _refuse("provenance-policy-vacuous", "tags.allowed malformed")
        if mode == "branch" and not tag_allowed:
            _refuse("provenance-policy-vacuous",
                    "branch tag mode with no allowed tags admits nothing")
        semver = tag_policy.get("semver")
        if semver is not None and mode != "versioned-tag":
            _refuse("provenance-policy-vacuous",
                    "semver constraint is only meaningful in "
                    "versioned-tag mode (got %r)" % (mode,))
        if semver is not None and mode == "versioned-tag":
            # validate the range parses against a probe version
            if not _semver_satisfies("0.0.0", semver) and \
                    not _semver_satisfies("999.999.999", semver):
                # range may exclude both probes legitimately (e.g.
                # "==1.2.3"); validate syntax clause-by-clause instead
                for clause in str(semver).split(","):
                    c = clause.strip()
                    if not any(c.startswith(op) for op in
                               ("==", "!=", ">=", "<=", ">", "<")):
                        _refuse("provenance-policy-vacuous",
                                "unparseable semver clause %r" % (c,))
                    operand = c.lstrip("=!<>)").strip()
                    if _parse_semver(operand) is None:
                        _refuse("provenance-policy-vacuous",
                                "unparseable semver bound %r" % (operand,))
        expected_inputs = d.get("expected_inputs", {})
        if not isinstance(expected_inputs, dict):
            _refuse("provenance-policy-vacuous", "expected_inputs malformed")

        require_signed = d.get("require_signed_statement", True)
        statement_signers = d.get("statement_signers", {})
        if require_signed:
            if (not isinstance(statement_signers, dict)
                    or not statement_signers):
                _refuse("provenance-policy-vacuous",
                        "signed statements required but no pinned "
                        "statement signers configured")
            for kid, pub in statement_signers.items():
                if _as_hex64(pub) is None:
                    _refuse("provenance-policy-vacuous",
                            "statement signer %r has malformed pubkey"
                            % (kid,))

        trusted = d.get("trusted_verifiers", {})
        if not isinstance(trusted, dict):
            _refuse("provenance-policy-vacuous",
                    "trusted_verifiers malformed")
        for vid, pub in trusted.items():
            if _as_hex64(pub) is None:
                _refuse("provenance-policy-vacuous",
                        "trusted verifier %r has malformed pubkey"
                        % (vid,))
        max_age = d.get("vsa_max_age_seconds", 86400)
        if not isinstance(max_age, int) or max_age <= 0:
            _refuse("provenance-policy-vacuous",
                    "vsa_max_age_seconds must be a positive int")
        level = d.get("vsa_required_level", "SLSA_BUILD_LEVEL_3")
        if level not in _VSA_LEVEL_RANK:
            _refuse("provenance-policy-vacuous",
                    "unknown vsa_required_level %r" % (level,))
        return cls(name, allowed_sources, allowed_builders,
                   {"mode": mode, "allowed": list(tag_allowed),
                    "semver": semver,
                    "required": bool(tag_policy.get("required", False))},
                   expected_inputs, bool(require_signed),
                   statement_signers, trusted, max_age, level)

    # -- statement admission -------------------------------------------

    def evaluate(self, statement, expected_subject_digest=None, now=None):
        """Non-raising twin of :meth:`admit`.

        Returns ``(True, None, "")`` on admission, else
        ``(False, code, detail)``.
        """
        try:
            self.admit(statement,
                       expected_subject_digest=expected_subject_digest,
                       now=now)
        except ProvenancePolicyError as e:
            return False, e.code, e.detail
        return True, None, ""

    def admit(self, statement, expected_subject_digest=None, now=None):
        """Admit a provenance statement under this policy.

        Returns True. Raises ``ProvenancePolicyError`` with a closed
        code on ANY refusal. Checks provenance CLAIMS against policy;
        it does not make the claims true.
        """
        # 1. signature (the emitter refuses tampered bytes first)
        if self.require_signed_statement:
            verify_statement(statement, self.statement_signers)
        elif not isinstance(statement, dict) or \
                statement.get("format") != STATEMENT_FORMAT:
            _refuse("provenance-statement-unverified",
                    "not a sasanam provenance statement")

        # 2. subject: WHAT was built (digest binding)
        subject = statement.get("subject")
        if not isinstance(subject, dict):
            _refuse("provenance-subject-refused",
                    "statement has no subject")
        digest = (subject.get("digest") or {}).get("sha256")
        digest = _as_hex64(digest, "subject digest")
        if digest is None:
            _refuse("provenance-subject-refused",
                    "subject carries no well-formed sha256 digest")
        if expected_subject_digest is not None:
            want = _as_hex64(expected_subject_digest,
                             "expected subject digest")
            if want is None:
                _refuse("provenance-subject-refused",
                        "caller supplied a malformed expected digest")
            if digest != want:
                _refuse("provenance-subject-refused",
                        "statement is for a different artifact digest")

        # 3. source: FROM WHERE (uri or digest allowlist)
        predicate = statement.get("predicate")
        if not isinstance(predicate, dict):
            _refuse("provenance-source-refused",
                    "statement has no predicate")
        src = predicate.get("source")
        if not isinstance(src, dict):
            _refuse("provenance-source-refused",
                    "predicate has no source")
        src_uri = src.get("uri")
        src_digest = (src.get("digest") or {}).get("sha256")
        src_digest = _as_hex64(src_digest, "source digest")
        matched = None
        if isinstance(src_uri, str) and src_uri in self.allowed_sources:
            matched = "uri"
        elif (src_digest is not None
                and "sha256:" + src_digest in self.allowed_sources):
            matched = "digest"
        if matched is None:
            _refuse("provenance-source-refused",
                    "source not in policy allowlist "
                    "(uri=%r)" % (src_uri,))

        # 4. builder: BY WHOM (exact builder id)
        builder = predicate.get("builder")
        builder_id = builder.get("id") if isinstance(builder, dict) else None
        if not isinstance(builder_id, str) or not builder_id:
            _refuse("provenance-builder-refused",
                    "predicate carries no builder id")
        if builder_id not in self.allowed_builders:
            _refuse("provenance-builder-refused",
                    "builder %r not in policy allowlist" % (builder_id,))

        # 5. tag: WHICH VERSION (constraint by mode)
        self._check_tag(predicate.get("tag"))

        # 6. expected inputs (the --build-workflow-input shape): every
        # expected input must be present and exactly equal.
        inputs = predicate.get("inputs")
        if self.expected_inputs:
            if not isinstance(inputs, dict):
                _refuse("provenance-source-refused",
                        "policy expects build inputs; statement has none")
            for key, want in self.expected_inputs.items():
                got = inputs.get(key)
                if got != want:
                    _refuse("provenance-source-refused",
                            "expected input %r mismatch (or missing)"
                            % (key,))
        return True

    def _check_tag(self, tag):
        mode = self.tag_policy["mode"]
        required = self.tag_policy["required"]
        if tag is None:
            if required:
                _refuse("provenance-tag-refused",
                        "policy requires a tag; statement has none")
            return
        if not isinstance(tag, str) or not tag:
            _refuse("provenance-tag-refused",
                    "tag is not a non-empty string")
        if mode == "any":
            return
        if mode == "branch":
            if tag not in self.tag_policy["allowed"]:
                _refuse("provenance-tag-refused",
                        "tag %r not in allowed branches" % (tag,))
            return
        # versioned-tag
        if _parse_semver(tag) is None:
            _refuse("provenance-tag-refused",
                    "tag %r is not a parseable version" % (tag,))
        semver = self.tag_policy.get("semver")
        if semver and not _semver_satisfies(tag, semver):
            _refuse("provenance-tag-refused",
                    "tag %r outside policy range %r" % (tag, semver))
        allowed = self.tag_policy["allowed"]
        if allowed and tag not in allowed:
            _refuse("provenance-tag-refused",
                    "tag %r not in policy allowlist" % (tag,))

    # -- VSA (delegated verification) ----------------------------------

    def admit_vsa(self, vsa, policy_id, expected_subject_digest, now=None):
        """Admit a Verification Summary Attestation as the credential.

        A VSA delegates verification: the pinned verifier asserts it
        verified ``expected_subject_digest`` under ``policy_id``. The
        VSA's scope is bounded — ``vsa.policy_id`` must equal BOTH the
        requested ``policy_id`` and this policy's name, so a VSA for P
        never admits under Q. Returns True; raises
        ``provenance-vsa-refused`` (or ``provenance-subject-refused``
        for digest mismatch) on any failure.
        """
        if now is None:
            now = time.time()
        if not isinstance(vsa, dict) or vsa.get("format") != VSA_FORMAT:
            _refuse("provenance-vsa-refused",
                    "not a sasanam VSA")
        if policy_id != self.name:
            _refuse("provenance-vsa-refused",
                    "admission requested under %r, not this policy %r"
                    % (policy_id, self.name))
        if vsa.get("policy_id") != policy_id:
            _refuse("provenance-vsa-refused",
                    "VSA scope mismatch: issued for %r, admitting under %r"
                    % (vsa.get("policy_id"), policy_id))
        verifier = vsa.get("verifier") or {}
        vid = verifier.get("id")
        pub_hex = self.trusted_verifiers.get(vid)
        if not pub_hex:
            _refuse("provenance-vsa-refused",
                    "verifier %r is not pinned in this policy" % (vid,))
        # the delegating verifier's key is pinned; its signature is the
        # whole credential. verify() returns True/False — check it.
        body = {k: v for k, v in vsa.items() if k != "signature"}
        msg = _VSA_DOMAIN + canonical_bytes(body)
        sig_entry = vsa.get("signature") or {}
        try:
            pub = bytes.fromhex(pub_hex)
            sig = bytes.fromhex(sig_entry.get("sig", ""))
        except (ValueError, TypeError, AttributeError):
            _refuse("provenance-vsa-refused",
                    "VSA signature malformed")
        if _ed25519.verify(pub, msg, sig) is not True:
            _refuse("provenance-vsa-refused",
                    "VSA signature does not verify under pinned key")
        issued_at = vsa.get("issued_at")
        expires_at = vsa.get("expires_at")
        if not isinstance(issued_at, (int, float)) or \
                not isinstance(expires_at, (int, float)):
            _refuse("provenance-vsa-refused",
                    "VSA carries no well-formed validity window")
        if not (issued_at <= now < expires_at):
            _refuse("provenance-vsa-refused",
                    "VSA outside its validity window (expired or "
                    "not yet valid)")
        age = now - issued_at
        if age > self.vsa_max_age_seconds:
            _refuse("provenance-vsa-refused",
                    "VSA older than policy max age")
        digest = ((vsa.get("subject") or {}).get("digest") or {}
                  ).get("sha256")
        digest = _as_hex64(digest, "VSA subject digest")
        want = _as_hex64(expected_subject_digest,
                         "expected subject digest")
        if digest is None or want is None or digest != want:
            _refuse("provenance-subject-refused",
                    "VSA subject digest does not match the artifact")
        rank = _VSA_LEVEL_RANK.get(vsa.get("verified_level"))
        need = _VSA_LEVEL_RANK[self.vsa_required_level]
        if rank is None or rank < need:
            _refuse("provenance-vsa-refused",
                    "VSA level %r below policy requirement %r"
                    % (vsa.get("verified_level"),
                       self.vsa_required_level))
        return True


class VSAIssuer(object):
    """The verifier side: issues signed VSAs ("I verified artifact X
    against policy P at level L, at time T"). The issuer holds the
    verifier's seed; the POLICY pins the verifier's public key. VSA
    delegates trust — it does not create it."""

    def __init__(self, verifier_id, seed):
        if not isinstance(verifier_id, str) or not verifier_id:
            raise ValueError("verifier_id must be a non-empty string")
        self.verifier_id = verifier_id
        self._seed = bytes(seed)
        self._pub = _ed25519.publickey(self._seed)

    @property
    def public_key_hex(self):
        return self._pub.hex()

    def issue(self, subject_digest, policy_id, verified_level,
              issued_at, ttl_seconds):
        """Issue a VSA dict, signed. ``ttl_seconds`` bounds the
        credential's life; the policy additionally caps age."""
        digest = _as_hex64(subject_digest, "subject digest")
        if digest is None:
            raise ValueError("subject_digest must be 64 hex chars")
        if verified_level not in _VSA_LEVEL_RANK:
            raise ValueError("unknown verified_level %r"
                             % (verified_level,))
        if not isinstance(policy_id, str) or not policy_id:
            raise ValueError("policy_id must be a non-empty string")
        if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a positive int")
        body = {
            "format": VSA_FORMAT,
            "subject": {"digest": {"sha256": digest}},
            "policy_id": policy_id,
            "verified_level": verified_level,
            "verifier": {"id": self.verifier_id},
            "issued_at": float(issued_at),
            "expires_at": float(issued_at) + ttl_seconds,
        }
        sig = _ed25519.sign(self._seed,
                            _VSA_DOMAIN + canonical_bytes(body))
        body["signature"] = {"key_id": self._pub.hex(),
                             "sig": sig.hex()}
        return body


# ---------------------------------------------------------------------------
# Offline-bundle adapter (composition, not duplication).
# ---------------------------------------------------------------------------

def statement_from_offline_bundle(bundle_dir, seed):
    """Build and sign a provenance statement for an exported offline
    bundle (``gov.offline_bundle``).

    Reads ``manifest.json`` + ``BUNDLE_DIGEST.sha256`` from
    ``bundle_dir``. The bundle must ALREADY be verified with the
    standalone verifier (``tools/offline-verify``) — this adapter does
    NOT re-verify the export chain and does not duplicate it.

    The offline bundle records no build source, so
    ``predicate.source.uri`` is ``"unrecorded"`` (see
    ``UNRECORDED_SOURCE``): a policy admits it only by explicitly
    allowing that value. The builder id is the exporter identity from
    the manifest; the ledger digest + window ride as bound inputs
    (the ``--build-workflow-input`` shape).
    """
    try:
        with open(os.path.join(bundle_dir, "manifest.json"),
                  "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, ValueError) as e:
        _refuse("provenance-statement-unverified",
                "cannot read bundle manifest: %s" % (e,))
    if not isinstance(manifest, dict):
        _refuse("provenance-statement-unverified",
                "bundle manifest is not a JSON object")
    try:
        with open(os.path.join(bundle_dir, "BUNDLE_DIGEST.sha256"),
                  "r", encoding="utf-8") as f:
            bundle_digest = f.read().strip().split()[0]
    except (OSError, IndexError) as e:
        _refuse("provenance-subject-refused",
                "cannot read bundle digest: %s" % (e,))
    if _as_hex64(bundle_digest, "bundle digest") is None:
        _refuse("provenance-subject-refused",
                "BUNDLE_DIGEST.sha256 is not a well-formed sha256 hex")
    window = manifest.get("window", {})
    statement = {
        "format": STATEMENT_FORMAT,
        "subject": {
            "name": manifest.get("bundle_id",
                                 os.path.basename(bundle_dir.rstrip("/"))),
            "digest": {"sha256": bundle_digest},
        },
        "predicate": {
            "source": {"uri": manifest.get("source_uri",
                                           UNRECORDED_SOURCE)},
            "builder": {"id": "sasanam-offline-exporter/"
                              + str(manifest.get("exporter", "unknown"))},
            "tag": None,
            "inputs": {
                "ledger_digest": str(manifest.get("ledger_digest", "")),
                "window": "%s..%s" % (window.get("from_seq"),
                                     window.get("to_seq")),
            },
        },
    }
    return sign_statement(statement, seed)
