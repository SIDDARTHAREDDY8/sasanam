"""Verification policy as DATA for decision packets (wave-267).

Pattern-only adaptation of the Sigstore policy-controller
``ClusterImagePolicy`` rule shape (Apache-2.0; no code vendored). A
``VerificationPolicy`` is a plain data document (dict/JSON)::

    {
      "version": 1,
      "name": "release-packets",          # optional, for audit
      "match": {"decision": "allow",       # selectors; all optional
                "authorityKid": "<16hex>",
                "digest": "<64hex>"},
      "authorities": [                    # OR: >=1 must verify
        {"name": "release-signers",
         "keys": [{"kid": "<16hex>", "pubkey": "<64hex>"}],
         "threshold": 1,
         "transparencyLog": {"required": True},  # default REQUIRED
         "attestations": [
           {"name": "eval",
            "predicateType": "https://example/eval/v1",
            "policy": {"op": "gte", "path": "score", "value": 10}}]},
      ],
      "policy": {"op": "eq", "path": "packetOk", "value": True},
      "mode": "enforce",                  # enforce | warn
    }

Composition (CIP, verbatim):
- candidate policies = those whose ``match`` fits the packet;
- ALL matching policies must pass (AND);
- within a policy, ANY one authority passing admits the evidence (OR);
- the outer ``policy`` sees ONLY the normalized ``VerificationResult``
  (authority names, matched key ids, attestation outcomes) -- never raw
  packet bytes;
- no matching policy refuses fail-closed (``verpol-no-match``);
- a policy with empty ``authorities`` fails closed at LOAD time;
- packet identity is digest-pinned: the verdict always carries the
  computed packet digest; a ``match.digest`` pin binds a policy to one
  exact packet.

DELIBERATE inversions of the source defaults (see the wave-266
prospectus):
- CIP quietly skips transparency-log verification when an authority
  declares no ``ctlog`` block (``IgnoreTlog=true``). Here
  ``transparencyLog.required`` defaults to True; omitting the block
  still requires anchoring. A transparency log proves inclusion only,
  never authorization or freshness -- anchoring is one check among
  several, not a trust root.
- CIP ``mode: warn`` admits with a warning. Here ``warn`` NEVER
  admits: the verdict is ``"warn"`` with ``admitted: False`` and a
  loud record, for rollout/audit only.

The outer policy language is ``pred-v1``: a minimal, deterministic,
side-effect-free predicate DSL over the normalized result (ops: eq,
ne, in, all, any, not, present, gte, lte, startswith). It is NOT
Rego/CUE -- the honest limit is documented in every verdict's
``out_of_scope``. Malformed policy documents (including unknown ops)
fail closed at load with machine-coded ``verpol-malformed-policy``.

``evaluate`` never raises: every failure path returns a refuse/warn
verdict (fail-closed for evaluators). ``load_policy`` raises
``VerificationPolicyError`` (carrying the machine ``code``) so a
malformed policy cannot be evaluated at all.

Key custody is deployment-owned: authority keys are pinned in the
policy document; this module verifies binding against those pins but
manages no key lifecycle, rotation, or revocation. Freshness is NOT
provided: there is no policy expiry here; a signed packet verifies
forever unless the policy's own checks say otherwise.
"""

import hashlib
import json

_CODES = {
    "malformed": "verpol-malformed-policy",
    "no_match": "verpol-no-match",
    "no_authority": "verpol-no-authority-matched",
    "log_unanchored": "verpol-log-not-anchored",
    "att_missing": "verpol-attestation-missing",
    "att_failed": "verpol-attestation-policy-failed",
    "policy_failed": "verpol-policy-failed",
    "packet_invalid": "verpol-packet-invalid",
    "uncheckable": "verpol-uncheckable",
}

_PRED_OPS = ("eq", "ne", "in", "all", "any", "not", "present",
             "gte", "lte", "startswith")

_MISSING = object()

_OUT_OF_SCOPE = [
    "key-custody-lifecycle",       # rotation/revocation is deployment-owned
    "revocation",                  # no CRL/OCSP equivalent for packet keys
    "freshness",  # no policy expiry; log proves inclusion only
    "rego-cue-semantics",          # pred-v1 is a documented subset, not Rego
    "attestation-payload-correctness",  # inline policy checks the payload
                                       # against data, not its truthfulness
]


class VerificationPolicyError(Exception):
    """A policy document (or predicate) that cannot be loaded.

    Carries the machine ``code`` so callers can refuse with a coded
    verdict instead of a bare exception string.
    """

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code or _CODES["malformed"]


# ---------------------------------------------------------------- helpers

def _is_hex(text, length):
    return (isinstance(text, str) and len(text) == length
            and all(c in "0123456789abcdef" for c in text))


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _kid_of_pubkey(pubkey_hex):
    return hashlib.sha256(
        bytes.fromhex(pubkey_hex)).digest()[:16].hex()


# ------------------------------------------------------- predicate DSL

def _resolve(ctx, path):
    cur = ctx
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return _MISSING
        cur = cur[part]
    return cur


def _check_pred_shape(expr):
    if not isinstance(expr, dict) or "op" not in expr:
        raise VerificationPolicyError(
            "predicate must be a dict with an 'op': %r" % (expr,))
    op = expr["op"]
    if op not in _PRED_OPS:
        raise VerificationPolicyError(
            "unknown predicate op %r" % (op,))
    if op in ("eq", "ne", "in", "gte", "lte", "startswith", "present"):
        if "path" not in expr or not isinstance(expr["path"], str):
            raise VerificationPolicyError(
                "predicate op %r needs a string 'path'" % (op,))
    if op in ("eq", "ne", "in", "gte", "lte", "startswith"):
        if "value" not in expr:
            raise VerificationPolicyError(
                "predicate op %r needs a 'value'" % (op,))
    if op in ("all", "any"):
        exprs = expr.get("exprs")
        if not isinstance(exprs, list) or not exprs:
            raise VerificationPolicyError(
                "predicate op %r needs a non-empty 'exprs' list"
                % (op,))
        for sub in exprs:
            _check_pred_shape(sub)
    if op == "not":
        if "expr" not in expr:
            raise VerificationPolicyError(
                "predicate op 'not' needs an 'expr'")
        _check_pred_shape(expr["expr"])


def _eval_pred(expr, ctx):
    op = expr["op"]
    if op == "all":
        return all(_eval_pred(s, ctx) for s in expr["exprs"])
    if op == "any":
        return any(_eval_pred(s, ctx) for s in expr["exprs"])
    if op == "not":
        return not _eval_pred(expr["expr"], ctx)
    if op == "present":
        return _resolve(ctx, expr["path"]) is not _MISSING
    val = _resolve(ctx, expr["path"])
    if val is _MISSING:
        return False
    want = expr["value"]
    if op == "eq":
        return val == want
    if op == "ne":
        return val != want
    if op == "in":
        return isinstance(want, list) and val in want
    if op == "gte":
        return isinstance(val, (int, float)) and val >= want
    if op == "lte":
        return isinstance(val, (int, float)) and val <= want
    if op == "startswith":
        return (isinstance(val, str) and isinstance(want, str)
                and val.startswith(want))
    return False  # unreachable: op validated at load


# ------------------------------------------------------------ load

def _load_key(entry):
    if not isinstance(entry, dict):
        raise VerificationPolicyError("authority key must be a dict")
    kid = entry.get("kid")
    pub = entry.get("pubkey")
    if not _is_hex(kid, 32) or not _is_hex(pub, 64):
        raise VerificationPolicyError(
            "authority key needs 16-hex kid and 64-hex pubkey")
    if _kid_of_pubkey(pub) != kid:
        raise VerificationPolicyError(
            "authority key kid is not sha256(pubkey)[:16]")
    return {"kid": kid, "pubkey": pub}


def _load_authority(entry):
    if not isinstance(entry, dict):
        raise VerificationPolicyError("authority must be a dict")
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        raise VerificationPolicyError("authority needs a name")
    keys = entry.get("keys")
    if not isinstance(keys, list) or not keys:
        raise VerificationPolicyError(
            "authority %r needs a non-empty 'keys' list" % (name,))
    keys = [_load_key(k) for k in keys]
    threshold = entry.get("threshold", 1)
    if not isinstance(threshold, int) or threshold < 1:
        raise VerificationPolicyError(
            "authority %r threshold must be a positive int" % (name,))
    tlog = entry.get("transparencyLog", {"required": True})
    if not isinstance(tlog, dict):
        raise VerificationPolicyError(
            "authority %r transparencyLog must be a dict" % (name,))
    required = tlog.get("required", True)
    if not isinstance(required, bool):
        raise VerificationPolicyError(
            "authority %r transparencyLog.required must be bool"
            % (name,))
    atts = entry.get("attestations", [])
    if not isinstance(atts, list):
        raise VerificationPolicyError(
            "authority %r attestations must be a list" % (name,))
    loaded_atts = []
    for att in atts:
        if not isinstance(att, dict):
            raise VerificationPolicyError(
                "attestation must be a dict")
        aname = att.get("name")
        ptype = att.get("predicateType")
        apol = att.get("policy")
        if not isinstance(aname, str) or not aname:
            raise VerificationPolicyError(
                "attestation needs a name")
        if not isinstance(ptype, str) or not ptype:
            raise VerificationPolicyError(
                "attestation %r needs a predicateType" % (aname,))
        if not isinstance(apol, dict):
            raise VerificationPolicyError(
                "attestation %r needs a predicate policy" % (aname,))
        _check_pred_shape(apol)
        loaded_atts.append({"name": aname, "predicateType": ptype,
                            "policy": apol})
    return {"name": name, "keys": keys, "threshold": threshold,
            "logRequired": required, "attestations": loaded_atts}


def load_policy(doc):
    """Validate a VerificationPolicy data document.

    Returns a normalized dict. Raises ``VerificationPolicyError``
    (machine-coded) on anything malformed -- a malformed policy can
    never be evaluated.
    """
    if not isinstance(doc, dict):
        raise VerificationPolicyError("policy document must be a dict")
    version = doc.get("version")
    if version != 1:
        raise VerificationPolicyError(
            "unsupported policy version %r (want 1)" % (version,))
    match = doc.get("match", {})
    if not isinstance(match, dict):
        raise VerificationPolicyError("'match' must be a dict")
    for key in match:
        if key not in ("decision", "authorityKid", "digest"):
            raise VerificationPolicyError(
                "unknown match selector %r" % (key,))
    if "decision" in match and not isinstance(match["decision"], str):
        raise VerificationPolicyError("match.decision must be a string")
    if "authorityKid" in match and not _is_hex(match["authorityKid"],
                                               32):
        raise VerificationPolicyError(
            "match.authorityKid must be 16 hex bytes")
    if "digest" in match and not _is_hex(match["digest"], 64):
        raise VerificationPolicyError(
            "match.digest must be 64 hex chars")
    authorities = doc.get("authorities")
    if not isinstance(authorities, list) or not authorities:
        raise VerificationPolicyError(
            "policy needs a non-empty 'authorities' list "
            "(empty authorities fail closed)")
    authorities = [_load_authority(a) for a in authorities]
    outer = doc.get("policy")
    if outer is not None:
        if not isinstance(outer, dict):
            raise VerificationPolicyError(
                "outer 'policy' must be a predicate dict")
        _check_pred_shape(outer)
    mode = doc.get("mode", "enforce")
    if mode not in ("enforce", "warn"):
        raise VerificationPolicyError(
            "mode must be 'enforce' or 'warn', got %r" % (mode,))
    name = doc.get("name")
    if name is not None and not isinstance(name, str):
        raise VerificationPolicyError("'name' must be a string")
    return {"version": 1, "name": name, "match": dict(match),
            "authorities": authorities, "policy": outer, "mode": mode}


# ------------------------------------------------------------ evaluate

def _packet_decision(packet):
    dec = packet.get("decision")
    if isinstance(dec, dict):
        return dec.get("value")
    return dec


def _matches(policy, packet, digest):
    match = policy["match"]
    if "decision" in match and match["decision"] != _packet_decision(
            packet):
        return False
    auth = packet.get("authority") or {}
    if "authorityKid" in match and match["authorityKid"] != auth.get(
            "kid"):
        return False
    if "digest" in match and match["digest"] != digest:
        return False
    return True


def _verify_authority(auth, packet, digest, log_lookup, attestations):
    """Return (passed, [(code, message), ...]). Never raises."""
    errors = []
    block = packet.get("authority") or {}
    kid = block.get("kid")
    pub = block.get("pubkey")
    bound = False
    if _is_hex(kid, 32) and _is_hex(pub, 64) and _kid_of_pubkey(pub) \
            == kid:
        bound = any(k["pubkey"] == pub for k in auth["keys"])
    if not bound:
        errors.append((_CODES["no_authority"],
                       "key not pinned by authority %r" % (auth["name"],)))
    elif auth["threshold"] > 1:
        # A single-signed packet binds exactly one key; a threshold
        # above 1 can never be met. Fail closed, documented.
        errors.append((_CODES["no_authority"],
                       "threshold %d unmet: packet binds one key"
                       % (auth["threshold"],)))
    if auth["logRequired"]:
        anchored = False
        if log_lookup is not None:
            try:
                anchored = bool(log_lookup(digest))
            except Exception:  # noqa: BLE001 - lookup failure = no
                anchored = False  # anchor; never an exception
        if not anchored:
            errors.append((_CODES["log_unanchored"],
                           "digest not anchored in transparency log"))
    evidence = (attestations or {}).get(auth["name"], {})
    for att in auth["attestations"]:
        rec = evidence.get(att["name"])
        if not isinstance(rec, dict):
            errors.append((_CODES["att_missing"],
                           "attestation %r missing" % (att["name"],)))
            continue
        if rec.get("predicateType") != att["predicateType"]:
            errors.append((_CODES["att_failed"],
                           "attestation %r predicateType mismatch"
                           % (att["name"],)))
            continue
        payload = rec.get("payload")
        if not isinstance(payload, dict):
            errors.append((_CODES["att_failed"],
                           "attestation %r payload not a dict"
                           % (att["name"],)))
            continue
        try:
            ok = _eval_pred(att["policy"], payload)
        except Exception:  # noqa: BLE001 - predicate failure =
            ok = False  # a failed check, never an exception
        if not ok:
            errors.append((_CODES["att_failed"],
                           "attestation %r inline policy failed"
                           % (att["name"],)))
    return (not errors), errors


def _refuse(code, reason, digest, policies, checked, detail=None):
    verdict = {
        "verdict": "refuse",
        "admitted": False,
        "code": code,
        "reason": reason,
        "packet_digest": digest,
        "policies": policies,
        "checked": checked,
        "out_of_scope": list(_OUT_OF_SCOPE),
        "evidence_digest": hashlib.sha256(
            _canonical({"code": code, "digest": digest,
                        "policies": policies})).hexdigest(),
    }
    if detail is not None:
        verdict["detail"] = detail
    return verdict


def evaluate(policies, packet, *, verifier=None, log_lookup=None,
             attestations=None):
    """Evaluate loaded policies against a decision packet.

    ``policies``: list of ``load_policy`` outputs. ``verifier``: a
    callable ``(packet) -> (bool, reason)``; the default is
    ``gov.decision_packet.verify_decision_packet`` (packet's own
    verification is non-negotiable and runs first). ``log_lookup``: a
    callable ``(digest) -> bool`` reporting transparency-log anchoring;
    ``None`` means no anchoring evidence is available (required
    anchoring then refuses). ``attestations``: ``{authority_name:
    {attestation_name: {"predicateType": ..., "payload": {...}}}}``.

    Never raises: every failure is a coded refuse/warn verdict.
    """
    try:
        return _evaluate(policies, packet, verifier=verifier,
                         log_lookup=log_lookup,
                         attestations=attestations)
    except VerificationPolicyError as exc:
        return _refuse(exc.code, str(exc), None, [], [])
    except Exception:  # noqa: BLE001 - evaluators never raise
        return _refuse(_CODES["uncheckable"],
                       "evaluation error (fail-closed)", None, [], [])


def _evaluate(policies, packet, *, verifier, log_lookup, attestations):
    if not isinstance(policies, list) or not policies:
        return _refuse(_CODES["malformed"],
                       "no policies supplied", None, [], [])
    if not isinstance(packet, dict):
        return _refuse(_CODES["packet_invalid"],
                       "packet is not a dict", None, [], [])
    try:
        from . import decision_packet as _dp
        digest = _dp.packet_digest(packet)
    except Exception:  # noqa: BLE001
        return _refuse(_CODES["packet_invalid"],
                       "packet digest not computable", None, [], [])
    candidates = [p for p in policies
                  if _matches(p, packet, digest)]
    if not candidates:
        return _refuse(_CODES["no_match"],
                       "no verification policy matches this packet",
                       digest, [], ["match"])
    # Non-negotiable: the packet's own verification runs first.
    check = verifier
    if check is None:
        from . import decision_packet as _dp
        check = _dp.verify_decision_packet
    try:
        ok, reason = check(packet)
    except Exception:  # noqa: BLE001
        ok, reason = False, "verifier raised (fail-closed)"
    if not ok:
        return _refuse(_CODES["packet_invalid"],
                       "packet verification failed: %s" % (reason,),
                       digest, [], ["packet-verification"])
    checked = ["packet-verification"]
    policy_reports = []
    saw_warn = False
    for index, policy in enumerate(candidates):
        pname = policy.get("name") or "policy#%d" % (index,)
        matched = []
        authority_errors = {}
        authority_pairs = {}
        att_summary = {}
        for auth in policy["authorities"]:
            passed, errors = _verify_authority(
                auth, packet, digest, log_lookup, attestations)
            if passed:
                matched.append(auth["name"])
            else:
                authority_pairs[auth["name"]] = errors
                authority_errors[auth["name"]] = [m for _, m in errors]
            att_summary[auth["name"]] = {
                a["name"]: (a["name"] in
                            (attestations or {}).get(auth["name"], {}))
                for a in auth["attestations"]
            }
        if not matched:
            # Zero authorities verified: refuse with the most specific
            # first-failure code (deterministic: first authority, first
            # error), with every authority's errors in the detail --
            # CIP's "errors surfaced when zero authorities pass",
            # machine-coded.
            first_name = policy["authorities"][0]["name"]
            first_code, first_msg = authority_pairs[first_name][0]
            return _refuse(
                first_code,
                "no authority verified for policy %r: %s"
                % (pname, first_msg),
                digest, policy_reports,
                checked + ["authority-binding", "log-anchoring",
                           "attestations"],
                detail={"policy": pname,
                        "authorityErrors": authority_errors})
        # Normalized VerificationResult: the ONLY input to the outer
        # policy. Raw packet bytes never reach policy-as-data.
        result = {
            "packetDigest": digest,
            "packetOk": True,
            "decision": _packet_decision(packet),
            "authorityKid": (packet.get("authority") or {}).get("kid"),
            "authorityMatches": {name: {"thresholdMet": True}
                                 for name in matched},
            "logAnchored": True,
            "attestations": att_summary,
        }
        outer_ok = True
        if policy["policy"] is not None:
            try:
                outer_ok = bool(_eval_pred(policy["policy"], result))
            except Exception:  # noqa: BLE001
                outer_ok = False
        if not outer_ok:
            return _refuse(
                _CODES["policy_failed"],
                "outer policy failed for policy %r" % (pname,),
                digest, policy_reports,
                checked + ["authority-binding", "log-anchoring",
                           "attestations", "outer-policy"])
        if policy["mode"] == "warn":
            saw_warn = True
        policy_reports.append({
            "policy": pname,
            "matchedAuthorities": matched,
            "authorityErrors": authority_errors,
            "outerPolicyOk": True,
            "mode": policy["mode"],
        })
    checked = checked + ["authority-binding", "log-anchoring",
                         "attestations", "outer-policy"]
    verdict = {
        "verdict": "warn" if saw_warn else "accept",
        "admitted": not saw_warn,  # warn NEVER admits
        "code": None,
        "reason": "all matching verification policies passed"
                  + (" (warn mode: not admitted)" if saw_warn else ""),
        "packet_digest": digest,
        "policies": policy_reports,
        "checked": checked,
        "out_of_scope": list(_OUT_OF_SCOPE),
        "evidence_digest": hashlib.sha256(
            _canonical({"verdict": "warn" if saw_warn else "accept",
                        "digest": digest,
                        "policies": policy_reports})).hexdigest(),
    }
    return verdict
