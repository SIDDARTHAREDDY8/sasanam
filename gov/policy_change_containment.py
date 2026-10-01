"""Policy-change containment check (wave-266 feature lane).

ADAPT of the *pattern* of NVIDIA OpenShell's policy prover
(Apache-2.0, verified in-repo by the wave-265 prospecting lane;
pattern only, no OpenShell code or text vendored): before a
policy/ruleset change is applied, verify the candidate is contained
in the declared damage boundary, and run the four proposal-risk
findings as machine-coded delta checks against the current policy.

Our package is stdlib-only with $0 spend, so this is a
DETERMINISTIC OVER-APPROXIMATION, not an SMT solver. Every verdict
carries honest coverage -- what was checked and what is out of
scope -- because the prover's actual steal is the coverage line:
an uncheckable delta refuses fail-closed
(``policy-change-uncheckable``) instead of earning a vacuous
``within_boundary``.

What this module provides, stdlib-only:

* :func:`check_policy_change`: compare candidate vs current vs the
  declared damage boundary. Returns a verdict report; raises
  :class:`PolicyChangeError` only on malformed (authoring-error)
  input, never on a checkable-but-failing change.
* :func:`gate_policy_change`: the apply seam. Returns the report
  when the change may be applied; raises with the first failed
  check's code otherwise. The exception detail names EVERY failed
  check, in fixed order.
* :func:`to_evidence`: the verdict as a canonical digest-linked
  record for attachment to evidence bundles / decision packets.

Policy model (the modeled rule language -- everything else is out
of scope and therefore uncheckable)::

    {"version": 1, "rules": [
        {"id": "allow-llm", "subject": "agent-worker",
         "effect": "allow", "action": "egress",
         "hosts": ["api.example.com"], "ports": [443],
         "methods": ["GET"], "paths": ["/v1/*"],
         "credential": None},
        {"id": "db", "subject": "agent-worker",
         "effect": "allow", "action": "credential-use",
         "credential": "prod-db"}]}

Host shapes: exact hostname, ``*.suffix``, IPv4/IPv6 address or
CIDR, ``*``. Port shapes: int or ``[lo, hi]``. Methods: uppercase
tokens or ``*``. Paths: exact, ``prefix/*``, ``*``. ``effect`` is
``allow`` only -- deny-rule semantics are unmodeled and therefore
uncheckable (fail closed).

Verdicts (the AuthorityProof four-verdict shape, independently
convergent): ``within_boundary`` (apply), ``exceeds_boundary``
(one or more failed checks), ``uncheckable`` (a shape the static
check cannot model -- fail closed, never vacuous).

The four proposal-risk findings (OpenShell's names, machine-coded
under domain ``policy``) refuse when the candidate EXPANDS vs the
current policy. Purely restrictive changes always pass them:

* ``policy-change-link-local-reach`` -- the expansion newly reaches
  link-local / loopback / cloud-metadata endpoints. ``*`` hosts
  count: the grant could cover 169.254.169.254.
* ``policy-change-l7-bypass-credentialed`` -- the expansion adds an
  L7 (method, path) reach on a deployment-declared credentialed
  host. Over-approximation: ANY new L7 reach on a credentialed
  host refuses, because the check cannot verify an auth layer
  actually enforces anything (that plumbing is deployment-owned).
  Legitimate new paths on credentialed endpoints go through human
  review -- that is the advisor/HITL loop's job, not this gate's.
* ``policy-change-credential-reach-expansion`` -- a subject newly
  gains reach to a credential (``credential-use`` or a rule that
  consumes one) it had no reach to.
* ``policy-change-capability-expansion`` -- the expansion adds a
  new (method, path) capability on a host:port the subject already
  reaches. A brand-new host:port is governed by the boundary
  check, not this finding.

``policy-boundary-exceeded`` refuses when any candidate grant is
not covered by the declared damage boundary.

Composition (never duplication):

* Runs BEFORE the admission-policy machinery accepts a policy
  change: gate the candidate with :func:`gate_policy_change`
  first, then run ``gov/admission_policy.py`` ``quality_gate`` on
  the new policy bundle as usual. Containment answers "does this
  change widen authority?"; the tester answers "does the new
  policy behave on the corpus?". Different questions, one
  pipeline.
* Converges with ``gov/authority_proof.py``'s boundary vocabulary
  (within/exceeds/unsupported/inconclusive), independently arrived
  at -- the shape is natural for boundary checking.

Fail-closed: malformed input raises loudly at the seam; every
refusal is machine-coded; nothing is applied on a partial check.
The boundary, current policy, and the credentialed-host set are
deployment-declared -- a lying boundary defeats containment
exactly as a lying resolver defeats resolve-before-admit.

Honest boundaries (stated, not absorbed):

* Deterministic over-approximation, not a proof: where the model
  is coarse (``*`` hosts, prefix paths), the check errs toward
  refusal. False positives are possible; they land on a human,
  never on a silent allow.
* Hostnames are matched syntactically -- DNS rebinding, CNAME
  games, and split-horizon answers are invisible to this check.
* Path patterns compare by exact/prefix shape only; semantic
  equivalence (``/a/./b`` vs ``/a/b``, case folding) is out of
  scope.
* Time-windowed, conditional, and deny rules are unmodeled.
* Filesystem, process, and other non-network policy domains are
  out of scope.
* ``auth_layer`` labels on rules are informational: the check
  cannot verify an auth layer enforces anything.
* This checks credential REACH, not credential secrecy or
  exfiltration -- pair with the credential machinery.

Stdlib only. Deterministic: no clock, no I/O, no network, no
in-repo git subprocesses.
"""

import hashlib
import ipaddress
import json
import os
import re

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

__all__ = [
    "CODES",
    "POLICY_VERSION",
    "PolicyChangeError",
    "check_policy_change",
    "gate_policy_change",
    "to_evidence",
]

# New decision codes introduced by this module (see
# gov/decision_codes.py). Sorted; the taxonomy merge asserts raw
# literal uniqueness.
CODES = (
    "policy-boundary-exceeded",
    "policy-change-capability-expansion",
    "policy-change-credential-reach-expansion",
    "policy-change-l7-bypass-credentialed",
    "policy-change-link-local-reach",
    "policy-change-malformed",
    "policy-change-uncheckable",
)

BOUNDARY_EXCEEDED = "policy-boundary-exceeded"
CAPABILITY_EXPANSION = "policy-change-capability-expansion"
CREDENTIAL_REACH_EXPANSION = "policy-change-credential-reach-expansion"
L7_BYPASS = "policy-change-l7-bypass-credentialed"
LINK_LOCAL_REACH = "policy-change-link-local-reach"
MALFORMED = "policy-change-malformed"
UNCHECKABLE = "policy-change-uncheckable"

POLICY_VERSION = 1

#: Fixed refusal order: boundary first, then the four risk
#: findings in the OpenShell checklist order. Deterministic; the
#: first failure is the exception code and every failure is named
#: in the report and the exception detail.
_CHECK_ORDER = (BOUNDARY_EXCEEDED, LINK_LOCAL_REACH, L7_BYPASS,
                CREDENTIAL_REACH_EXPANSION, CAPABILITY_EXPANSION)

_CHECKED = (
    "rule-shape",
    "subject-binding",
    "host-containment",
    "port-containment",
    "method-containment",
    "path-containment",
    "credential-binding",
    "boundary-containment",
    "link-local-reach",
    "l7-bypass-credentialed",
    "credential-reach-expansion",
    "capability-expansion",
)

_OUT_OF_SCOPE = (
    "deny-rule semantics (unmodeled; any deny rule makes the "
    "delta uncheckable)",
    "DNS resolution and rebinding of hostnames (syntactic match "
    "only)",
    "path-pattern semantic equivalence beyond exact/prefix shape",
    "time-windowed or conditional rules",
    "non-network policy domains (filesystem, process, ...)",
    "whether a declared auth_layer actually enforces anything "
    "(deployment plumbing)",
    "credential secrecy and exfiltration (this checks reach, "
    "not leakage)",
    "suffix and CIDR host shapes against link-local ranges "
    "(only exact/IP/any shapes are link-local screened)",
)

#: Link-local / loopback ranges screened by the risk check.
_LINK_LOCAL_NETS = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
)

#: Cloud metadata endpoints that are names, not IPs.
_METADATA_HOSTS = frozenset([
    "metadata.google.internal",
    "metadata.google.com",
])

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}"
                          r"[A-Za-z0-9])?$")
_METHOD_RE = re.compile(r"^[A-Z][A-Z0-9_-]*$")

_NONE = ("none",)
_ANY = ("any",)


class PolicyChangeError(Exception):
    """Loud policy-change failure. ``code`` is a closed vocabulary
    member of :data:`CODES`."""

    def __init__(self, code, detail=""):
        super(PolicyChangeError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


class _Uncheckable(Exception):
    """Internal: a well-formed shape the static check cannot model.
    Never escapes; becomes a ``policy-change-uncheckable`` report."""


def _refuse(code, detail=""):
    raise PolicyChangeError(code, detail)


def _malformed(what, detail):
    _refuse(MALFORMED, "%s: %s" % (what, detail))


def _parse_host(value, what):
    """Parse a host shape to a normalized tuple. Unknown but
    well-formed shapes raise _Uncheckable; structurally invalid
    shapes are malformed."""
    if not isinstance(value, str) or not value:
        _malformed(what, "host must be a non-empty string, got %r"
                   % (value,))
    if value == "*":
        return _ANY
    if value.startswith("*."):
        suffix = value[2:].lower()
        if not _HOSTNAME_RE.match(suffix):
            _malformed(what, "bad wildcard suffix %r" % (value,))
        return ("suffix", suffix)
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        addr = None
    if addr is not None:
        return ("ip", str(addr))
    if "/" in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise _Uncheckable("host network %r" % (value,))
        return ("cidr", str(net))
    if _HOSTNAME_RE.match(value):
        return ("exact", value.lower())
    raise _Uncheckable("host shape %r" % (value,))


def _parse_port(value, what):
    if isinstance(value, bool):
        _malformed(what, "port must be an int or [lo, hi]")
    if isinstance(value, int):
        if 1 <= value <= 65535:
            return ("port", value)
        _malformed(what, "port out of range: %r" % (value,))
    if isinstance(value, (list, tuple)) and len(value) == 2 \
            and all(isinstance(v, int) and not isinstance(v, bool)
                    for v in value):
        lo, hi = value
        if 1 <= lo <= hi <= 65535:
            return ("range", lo, hi)
        _malformed(what, "port range out of range: %r" % (value,))
    _malformed(what, "port must be an int or [lo, hi], got %r"
               % (value,))


def _parse_method(value, what):
    if not isinstance(value, str) or not value:
        _malformed(what, "method must be a non-empty string")
    if value == "*":
        return _ANY
    if _METHOD_RE.match(value):
        return ("method", value)
    _malformed(what, "method must be an uppercase token or '*', "
               "got %r" % (value,))


def _parse_path(value, what):
    if not isinstance(value, str) or not value:
        _malformed(what, "path must be a non-empty string")
    if value == "*":
        return _ANY
    if not value.startswith("/"):
        _malformed(what, "path must start with '/': %r" % (value,))
    if "*" in value:
        if value.endswith("/*") and value.count("*") == 1:
            return ("prefix", value[:-1])
        _malformed(what, "only 'prefix/*' wildcards modeled: %r"
                   % (value,))
    return ("exact", value)


def _parse_rule(rule, idx):
    what = "rules[%d]" % idx
    if not isinstance(rule, dict):
        _malformed(what, "rule must be a dict")
    rid = rule.get("id")
    if not isinstance(rid, str) or not rid:
        _malformed(what, "id must be a non-empty string")
    subject = rule.get("subject")
    if not isinstance(subject, str) or not subject:
        _malformed(what, "subject must be a non-empty string")
    if rule.get("effect", "allow") != "allow":
        raise _Uncheckable("rule %r: effect %r unmodeled (only "
                           "'allow' is checked)" % (rid,
                                                    rule.get("effect")))
    action = rule.get("action")
    if action not in ("egress", "credential-use"):
        _malformed(what, "action must be 'egress' or "
                   "'credential-use', got %r" % (action,))
    credential = rule.get("credential")
    if credential is not None and \
            (not isinstance(credential, str) or not credential):
        _malformed(what, "credential must be a string or null")
    parsed = {"id": rid, "subject": subject, "action": action,
              "credential": credential}
    if action == "egress":
        for key, parser in (("hosts", _parse_host),
                            ("ports", _parse_port),
                            ("methods", _parse_method),
                            ("paths", _parse_path)):
            values = rule.get(key)
            if not isinstance(values, list) or not values:
                _malformed(what, "%s must be a non-empty list" % key)
            parsed[key] = [parser(v, "%s.%s" % (what, key))
                           for v in values]
        auth_layer = rule.get("auth_layer")
        if auth_layer is not None and \
                (not isinstance(auth_layer, str) or not auth_layer):
            _malformed(what, "auth_layer must be a string or null")
        parsed["auth_layer"] = auth_layer
    else:
        if credential is None:
            _malformed(what, "credential-use needs a credential")
        for key in ("hosts", "ports", "methods", "paths"):
            parsed[key] = [_NONE]
    return parsed


def _load_policy(doc, what):
    """Loud load: malformed raises; unmodeled shapes raise
    _Uncheckable (fail-closed, never vacuous)."""
    if not isinstance(doc, dict):
        _malformed(what, "policy must be a dict, got %s"
                   % type(doc).__name__)
    if doc.get("version") != POLICY_VERSION:
        _malformed(what, "version must be %d, got %r"
                   % (POLICY_VERSION, doc.get("version")))
    rules = doc.get("rules")
    if not isinstance(rules, list):
        _malformed(what, "rules must be a list")
    parsed = [_parse_rule(r, i) for i, r in enumerate(rules)]
    ids = [r["id"] for r in parsed]
    if len(set(ids)) != len(ids):
        _malformed(what, "duplicate rule ids")
    return parsed


def _atoms(parsed_rules):
    """Expand rules to grant atoms: (subject, action, host, port,
    method, path, credential)."""
    atoms = set()
    for rule in parsed_rules:
        if rule["action"] == "credential-use":
            atoms.add((rule["subject"], "credential-use", _NONE,
                       _NONE, _NONE, _NONE, rule["credential"]))
            continue
        for host in rule["hosts"]:
            for port in rule["ports"]:
                for method in rule["methods"]:
                    for path in rule["paths"]:
                        atoms.add((rule["subject"], "egress", host,
                                   port, method, path,
                                   rule["credential"]))
    return atoms


def _ip_in_networks(addr_str, networks):
    try:
        addr = ipaddress.ip_address(addr_str)
    except ValueError:
        return False
    return any(addr in net for net in networks
               if addr.version == net.version)


def _host_covers(bh, ch):
    if bh == _ANY or bh == ch:
        return True
    if bh[0] == "suffix" and ch[0] == "exact":
        suffix = bh[1]
        host = ch[1]
        return host == suffix or host.endswith("." + suffix)
    if bh[0] == "cidr" and ch[0] in ("ip", "cidr"):
        try:
            bnet = ipaddress.ip_network(bh[1])
            cnet = ipaddress.ip_network(ch[1])
        except ValueError:
            return False
        return cnet.subnet_of(bnet)
    return False


def _port_covers(bp, cp):
    if bp == cp:
        return True
    if bp[0] == "range":
        if cp[0] == "port":
            return bp[1] <= cp[1] <= bp[2]
        if cp[0] == "range":
            return bp[1] <= cp[1] and cp[2] <= bp[2]
    return False


def _method_covers(bm, cm):
    return bm == _ANY or bm == cm


def _path_covers(bp, cp):
    if bp == _ANY or bp == cp:
        return True
    if bp[0] == "prefix":
        prefix = bp[1]
        if cp[0] == "exact":
            return cp[1].startswith(prefix)
        if cp[0] == "prefix":
            return cp[1].startswith(prefix)
    return False


def _covers(cover, atom):
    """Does grant-atom ``cover`` subsume grant-atom ``atom``?"""
    (bsub, bact, bh, bp, bm, bpath, bcred) = cover
    (csub, cact, ch, cp, cm, cpath, ccred) = atom
    if bact != cact:
        return False
    if not (bsub == "*" or bsub == csub):
        return False
    if bcred != ccred:
        return False
    if cact == "credential-use":
        return True
    return _host_covers(bh, ch) and _port_covers(bp, cp) \
        and _method_covers(bm, cm) and _path_covers(bpath, cpath)


def _covered_by(atom, cover_set):
    return any(_covers(c, atom) for c in cover_set)


def _is_link_local(host):
    """Over-approximation: could this host shape reach a
    link-local / loopback / metadata endpoint?"""
    if host == _ANY:
        return True  # the grant could cover 169.254.169.254
    kind = host[0]
    if kind == "ip":
        return _ip_in_networks(host[1], _LINK_LOCAL_NETS)
    if kind == "cidr":
        try:
            net = ipaddress.ip_network(host[1])
        except ValueError:
            return False
        return any(net.overlaps(ll) for ll in _LINK_LOCAL_NETS
                   if net.version == ll.version)
    if kind == "exact":
        return host[1] in _METADATA_HOSTS
    return False  # suffix: documented screening limit


def _could_reach_credentialed(host, credentialed):
    """Could this host shape include a credentialed host?"""
    if not credentialed:
        return False
    if host == _ANY:
        return True
    kind = host[0]
    if kind == "exact":
        return host[1] in credentialed
    if kind == "ip":
        return host[1] in credentialed
    if kind == "suffix":
        suffix = host[1]
        return any(h == suffix or h.endswith("." + suffix)
                   for h in credentialed)
    if kind == "cidr":
        try:
            net = ipaddress.ip_network(host[1])
        except ValueError:
            return False
        for h in credentialed:
            try:
                addr = ipaddress.ip_address(h)
            except ValueError:
                continue
            if addr in net:
                return True
        return False
    return False


def _report(verdict, delta_class, failed, expansion, detail=""):
    record = {"verdict": verdict,
              "delta_class": delta_class,
              "failed_checks": list(failed),
              "checked": list(_CHECKED),
              "out_of_scope": list(_OUT_OF_SCOPE),
              "expansion_atoms": sorted(
                  [list(a) for a in expansion],
                  key=lambda a: json.dumps(a, sort_keys=True,
                                           default=str)),
              "detail": detail}
    canonical = json.dumps(record, sort_keys=True,
                           separators=(",", ":"),
                           default=str).encode("utf-8")
    record["evidence_digest"] = hashlib.sha256(canonical).hexdigest()
    return record


def _uncheckable_report(delta_class, reason):
    return _report("uncheckable", delta_class, [UNCHECKABLE], (),
                   reason)


def check_policy_change(candidate, current, boundary,
                        credentialed_hosts=()):
    """Compare candidate vs current vs the declared damage
    boundary. Returns a verdict report; raises
    :class:`PolicyChangeError` only on malformed (authoring-error)
    input. An unmodeled shape yields verdict ``uncheckable`` --
    fail-closed, never a vacuous ``within_boundary``."""
    try:
        cand_rules = _load_policy(candidate, "candidate")
        curr_rules = _load_policy(current, "current")
        bound_rules = _load_policy(boundary, "boundary")
    except _Uncheckable as u:
        return _uncheckable_report("unknown", "unmodeled shape: %s"
                                   % (u,))
    if not bound_rules:
        return _uncheckable_report(
            "unknown", "no declared damage boundary: containment "
                       "cannot be proved without one")
    try:
        if isinstance(credentialed_hosts, str):
            raise TypeError("bare string")
        cred_hosts = frozenset(
            h.lower() for h in credentialed_hosts)
    except TypeError:
        _malformed("credentialed_hosts",
                   "must be an iterable of host strings")
    cand_atoms = _atoms(cand_rules)
    curr_atoms = _atoms(curr_rules)
    bound_atoms = _atoms(bound_rules)

    removed = curr_atoms - cand_atoms
    expansion = set(a for a in cand_atoms
                    if not _covered_by(a, curr_atoms))
    if not expansion and not removed:
        delta_class = "equivalent"
    elif not expansion:
        delta_class = "restrictive"
    else:
        delta_class = "expanding"

    failed = []
    # 1. Boundary containment: every candidate grant ⊆ boundary.
    beyond = sorted(a for a in cand_atoms
                    if not _covered_by(a, bound_atoms))
    if beyond:
        failed.append(BOUNDARY_EXCEEDED)
    # 2-5. The four proposal-risk findings over the expansion.
    link_local = sorted(
        a for a in expansion
        if a[1] == "egress" and _is_link_local(a[2]))
    if link_local:
        failed.append(LINK_LOCAL_REACH)
    l7 = sorted(
        a for a in expansion
        if a[1] == "egress"
        and _could_reach_credentialed(a[2], cred_hosts))
    if l7:
        failed.append(L7_BYPASS)
    cred_reach = sorted(
        a for a in expansion
        if a[6] is not None and not any(
            m[0] == a[0] and m[6] == a[6] for m in curr_atoms))
    if cred_reach:
        failed.append(CREDENTIAL_REACH_EXPANSION)
    capability = sorted(
        a for a in expansion
        if a[1] == "egress" and a[6] is None
        and not _is_link_local(a[2])
        and not _could_reach_credentialed(a[2], cred_hosts)
        and any(m[1] == "egress" and m[0] == a[0]
                and _host_covers(m[2], a[2])
                and _port_covers(m[3], a[3])
                for m in curr_atoms))
    if capability:
        failed.append(CAPABILITY_EXPANSION)

    ordered = [c for c in _CHECK_ORDER if c in failed]
    if not ordered:
        return _report("within_boundary", delta_class, [], (),
                       "candidate contained in the declared "
                       "damage boundary; no expansion risk "
                       "findings")
    detail = "; ".join(
        "%s: %d new grant(s)" % (code, len(
            beyond if code == BOUNDARY_EXCEEDED
            else link_local if code == LINK_LOCAL_REACH
            else l7 if code == L7_BYPASS
            else cred_reach
            if code == CREDENTIAL_REACH_EXPANSION
            else capability))
        for code in ordered)
    return _report("exceeds_boundary", delta_class, ordered,
                   expansion, detail)


def gate_policy_change(candidate, current, boundary,
                       credentialed_hosts=()):
    """The apply seam. Returns the verdict report when the change
    may be applied; raises :class:`PolicyChangeError` otherwise.
    The exception code is the first failed check in fixed order;
    the detail names EVERY failed check."""
    report = check_policy_change(candidate, current, boundary,
                                 credentialed_hosts)
    if report["verdict"] == "within_boundary":
        return report
    code = report["failed_checks"][0]
    detail = "%s (delta: %s; all failed checks: %s)" % (
        report["detail"], report["delta_class"],
        ", ".join(report["failed_checks"]))
    raise PolicyChangeError(code, detail)


def to_evidence(report):
    """The verdict as a canonical digest-linked record for
    evidence bundles / decision packets."""
    if not isinstance(report, dict) or \
            report.get("verdict") not in (
                "within_boundary", "exceeds_boundary",
                "uncheckable"):
        _refuse(MALFORMED, "to_evidence needs a verdict report")
    record = {"kind": "policy-change-decision",
              "verdict": report["verdict"],
              "delta_class": report["delta_class"],
              "failed_checks": list(report["failed_checks"]),
              "checked": list(report["checked"]),
              "out_of_scope": list(report["out_of_scope"]),
              "evidence_digest": report["evidence_digest"]}
    canonical = json.dumps(record, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    record["record_digest"] = hashlib.sha256(canonical).hexdigest()
    return record
