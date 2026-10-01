"""Break-first closure battery for F252.

F252 (LOW): ``output_ifc`` privilege grants are self-mintable. The
Endorsement ceremony authenticates nothing: ``issue_grant`` validates
authorization by shape only, and ``_check_grant`` recomputes a plain
public sha256 over the body -- no secret, no signature, no issuance
registry. A self-minted grant (never passed through ``issue_grant``)
exercises ``endorsement: ["user-verified"]`` and flows to the
``execution`` sink.

Fix (close-when criterion 1, registry option): an ``IssuanceRegistry``
records every digest minted by ``issue_grant``; ``exercise_privilege``
consults it and refuses grants that were never issued with a machine
code DISTINCT from the digest-mismatch path (``ifc-grant-unissued``).

Red phase: ``GOV_IFC_F252_IMPL=stub`` loads the permissive foil (old
semantics: no issuance check -- the registry's ``contains`` always
returns True). The attack probes BREAK on the foil (genuine F252
evidence). Green phase: against ``gov.output_ifc`` all probes HELD,
in staging AND under ``env -u GOV_DEPLOYMENT_MODE``.

Stdlib only. Deterministic (fixed timestamps, no randomness).
Depth-1 green check honoring GOV_SKIP_GREEN=1. No in-repo git
subprocesses. Fresh unique /var/tmp scratch dirs.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)

TAXONOMY_PIN = int(os.environ.get("W270_TAXONOMY_PIN", "1372"))
# Wave-270 F252 lane: 1325 + ifc-grant-unissued + ifc-registry-corrupt.
# Red phase runs with W270_TAXONOMY_PIN=1325 against the pristine tree.
assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN, (
    "taxonomy pin drift: %d != %d"
    % (len(decision_codes.TAXONOMY), TAXONOMY_PIN))

_IMPL = os.environ.get("GOV_IFC_F252_IMPL", "gov.output_ifc")

# Permissive foil: the OLD (F252-vulnerable) semantics. The registry
# exists as a degenerate shim whose ``contains`` always returns True,
# and the durable path is ignored -- exactly the "no issuance check"
# world the red-team probe broke.
_STUB_SRC = '''
import hashlib, json


class OutputIFCError(Exception):
    def __init__(self, code, detail=""):
        super(OutputIFCError, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _digest(obj):
    return hashlib.sha256(_canonical(obj).encode("utf-8")).hexdigest()


class IssuanceRegistry(object):
    """Degenerate foil: no issuance check (the F252 world)."""

    def __init__(self, path=None):
        self._path = path

    def record(self, grant_digest, now=""):
        pass

    def revoke(self, grant_digest):
        pass

    def contains(self, grant_digest):
        return True


def _check_tag_set(value, what):
    if isinstance(value, str) or not isinstance(value, (list, tuple, set)):
        raise OutputIFCError("ifc-label-malformed", "bad %s" % what)
    return frozenset(value)


def assign_label(tool_name, provenance=None, registry=None):
    return {"secrecy": [], "integrity": ["tool-external"]}


def check_sink(labeled, sink):
    if sink == "execution" and "user-verified" not in \\
            labeled.get("integrity", []):
        raise OutputIFCError("ifc-integrity-flow-denied", "sink needs trust")
    return {"allowed": True, "sink": sink, "label": labeled}


def combine_outputs(*labeled):
    return labeled[0]


def issue_grant(privilege, granted_by, authorization, ttl_seconds, now,
                registry=None):
    body = {
        "v": 1,
        "privilege": {
            "declassification": sorted(
                privilege.get("declassification", [])),
            "endorsement": sorted(privilege.get("endorsement", [])),
        },
        "granted_by": granted_by,
        "authorization": authorization,
        "issued_at": now,
        "expires_at": "2026-10-01T11:00:00Z",
    }
    grant = dict(body)
    grant["grant_digest"] = _digest(body)
    return grant


def _check_grant(grant, registry=None):
    digest = grant.get("grant_digest")
    body = {k: v for k, v in grant.items() if k != "grant_digest"}
    if not isinstance(digest, str) or _digest(body) != digest:
        raise OutputIFCError("ifc-privilege-unauthorized",
                             "grant digest mismatch: tampered or forged")
    return body


def exercise_privilege(grant, label, operation, tags, audit, now,
                       registry=None):
    body = _check_grant(grant, registry)
    tag_set = _check_tag_set(tags, "tags")
    if now > body["expires_at"]:
        raise OutputIFCError("ifc-privilege-expired", "grant expired")
    if not callable(audit):
        raise OutputIFCError("ifc-audit-required", "no audit hook")
    scope = frozenset(body["privilege"][
        "endorsement" if operation == "endorse" else "declassification"])
    if not tag_set <= scope:
        raise OutputIFCError("ifc-privilege-scope-denied", "outside scope")
    new_label = {"secrecy": label.get("secrecy", []),
                 "integrity": sorted(set(label.get("integrity", []))
                                     | tag_set)}
    record = {"event": "ifc-privilege-exercised", "operation": operation,
              "tags": sorted(tag_set), "grant_digest": grant["grant_digest"]}
    audit(record)
    return {"label": new_label, "audit_record": record}
'''


def _load_impl():
    if _IMPL == "stub":
        d = tempfile.mkdtemp(prefix="w270_f252_stub_")
        p = os.path.join(d, "stub_ifc.py")
        with open(p, "w") as f:
            f.write(_STUB_SRC)
        sys.path.insert(0, d)
        import stub_ifc
        return stub_ifc
    import importlib
    return importlib.import_module(_IMPL)


ifc = _load_impl()

# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

NOW = "2026-10-01T10:00:00Z"
LATER = "2026-10-01T10:30:00Z"
EXPIRED = "2026-10-01T12:00:00Z"

PRIV = {"declassification": ["credential"],
        "endorsement": ["user-verified"]}
AUTH = {"kind": "human-approval", "ref": "appr-f252"}

PROBES = []


def probe(fn):
    PROBES.append(fn)
    return fn


def _scratch(prefix):
    base = "/var/tmp"
    os.makedirs(base, exist_ok=True)
    return tempfile.mkdtemp(prefix=prefix, dir=base)


def _grant(registry=None, **kw):
    args = {"privilege": PRIV, "granted_by": "officer",
            "authorization": AUTH, "ttl_seconds": 3600, "now": NOW}
    args.update(kw)
    return ifc.issue_grant(registry=registry, **args)


def _forge_grant(privilege, ref, granted_by="attacker"):
    """Self-mint a grant exactly like the w269 red-team probe: the
    digest is a public function of the body, never passed through
    issue_grant, never recorded in any registry."""
    body = {
        "v": 1,
        "privilege": {
            "declassification": sorted(
                privilege.get("declassification", [])),
            "endorsement": sorted(privilege.get("endorsement", [])),
        },
        "granted_by": granted_by,
        "authorization": {"kind": "human-approval", "ref": ref},
        "issued_at": NOW,
        "expires_at": "2026-10-01T11:00:00Z",
    }
    grant = dict(body)
    grant["grant_digest"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True).encode("utf-8")).hexdigest()
    return grant


def _label():
    return {"secrecy": [], "integrity": ["tool-external"]}


def _audit():
    records = []

    def hook(record):
        records.append(record)
    return records, hook


def _code_of(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - probing
        return getattr(exc, "code", None)
    return "NO-RAISE"


# ------------------------------------------------------------------
# Attack probes (BREAK on the stub foil, HELD on the fixed module)
# ------------------------------------------------------------------

@probe
def f252_forged_grant_refused_unissued():
    """Close-when (1)+(2): a self-minted grant is refused at exercise
    with a code DISTINCT from the digest-mismatch path."""
    records, hook = _audit()
    forged = _forge_grant({"endorsement": ["user-verified"]},
                          ref="forged-ref-f252-a1")
    code = _code_of(ifc.exercise_privilege, forged, _label(), "endorse",
                    ["user-verified"], hook, NOW)
    if code == "NO-RAISE":
        return "BREAK(forged grant exercised: ceremony is theater)"
    if code != "ifc-grant-unissued":
        return "BREAK(wrong code for forgery: %r)" % (code,)
    if records:
        return "BREAK(audit fired on a refused exercise)"
    return "HELD"


@probe
def f252_cross_registry_grant_refused():
    """A grant issued into registry A is refused when exercised
    against registry B (issuance is registry-scoped)."""
    reg_a = ifc.IssuanceRegistry()
    reg_b = ifc.IssuanceRegistry()
    grant = _grant(registry=reg_a)
    records, hook = _audit()
    code = _code_of(ifc.exercise_privilege, grant, _label(), "endorse",
                    ["user-verified"], hook, NOW, registry=reg_b)
    if code == "NO-RAISE":
        return "BREAK(grant from another registry exercised)"
    if code != "ifc-grant-unissued":
        return "BREAK(wrong code: %r)" % (code,)
    return "HELD"


@probe
def f252_revoked_grant_refused():
    """Revocation (the rotation story): issue, revoke, exercise --
    the grant must refuse as unissued."""
    reg = ifc.IssuanceRegistry()
    grant = _grant(registry=reg)
    reg.revoke(grant["grant_digest"])
    records, hook = _audit()
    code = _code_of(ifc.exercise_privilege, grant, _label(), "endorse",
                    ["user-verified"], hook, NOW, registry=reg)
    if code == "NO-RAISE":
        return "BREAK(revoked grant still exercises)"
    if code != "ifc-grant-unissued":
        return "BREAK(wrong code: %r)" % (code,)
    return "HELD"


@probe
def f252_corrupt_journal_refuses_loud():
    """A corrupt durable journal refuses LOUDLY at construction
    (ifc-registry-corrupt), never silently replays partial state."""
    td = _scratch("g270-f252-journal-")
    path = os.path.join(td, "grants.jsonl")
    with open(path, "w") as f:
        f.write('{"event": "issued", "grant_digest": "%s"}\n'
                % ("ab" * 32,))
        f.write("this is not json\n")
    try:
        ifc.IssuanceRegistry(path=path)
    except Exception as exc:  # noqa: BLE001 - probing
        if getattr(exc, "code", None) == "ifc-registry-corrupt":
            return "HELD"
        return "BREAK(wrong code for corrupt journal: %r)" % (
            getattr(exc, "code", None),)
    return "BREAK(corrupt journal silently accepted)"


@probe
def f252_non_registry_arg_malformed():
    """A non-registry ``registry=`` argument fails closed
    (ifc-label-malformed), never ignored."""
    grant = _grant()
    records, hook = _audit()
    code = _code_of(ifc.exercise_privilege, grant, _label(), "endorse",
                    ["user-verified"], hook, NOW, registry="not-a-registry")
    if code == "NO-RAISE":
        return "BREAK(non-registry argument silently ignored)"
    if code != "ifc-label-malformed":
        return "BREAK(wrong code: %r)" % (code,)
    return "HELD"


# ------------------------------------------------------------------
# Control probes (HELD on both foil and fixed module)
# ------------------------------------------------------------------

@probe
def f252_legit_grant_exercises():
    """Close-when: a ceremony-issued grant still exercises, endorses,
    and flows to the execution sink."""
    grant = _grant()
    records, hook = _audit()
    out = ifc.exercise_privilege(grant, _label(), "endorse",
                                 ["user-verified"], hook, NOW)
    if "user-verified" not in out["label"]["integrity"]:
        return "BREAK(endorsement tag missing after exercise)"
    if len(records) != 1:
        return "BREAK(audit hook did not fire exactly once)"
    try:
        ifc.check_sink(out["label"], "execution")
    except Exception as exc:  # noqa: BLE001 - probing
        return "BREAK(endorsed label refused at execution: %r)" % (
            getattr(exc, "code", None),)
    return "HELD"


@probe
def f252_durable_registry_replay():
    """F251 lesson: a durable registry replays its journal on
    construction -- grants survive a simulated restart."""
    td = _scratch("g270-f252-durable-")
    path = os.path.join(td, "grants.jsonl")
    reg1 = ifc.IssuanceRegistry(path=path)
    grant = _grant(registry=reg1)
    reg2 = ifc.IssuanceRegistry(path=path)  # simulated restart
    records, hook = _audit()
    out = ifc.exercise_privilege(grant, _label(), "endorse",
                                 ["user-verified"], hook, NOW,
                                 registry=reg2)
    if "user-verified" not in out["label"]["integrity"]:
        return "BREAK(grant lost across registry restart)"
    return "HELD"


@probe
def f252_revoke_then_reissue():
    """Journal ordering: revoke then re-issue re-arms the grant."""
    reg = ifc.IssuanceRegistry()
    grant = _grant(registry=reg)
    reg.revoke(grant["grant_digest"])
    reg.record(grant["grant_digest"], NOW)
    records, hook = _audit()
    out = ifc.exercise_privilege(grant, _label(), "endorse",
                                 ["user-verified"], hook, NOW,
                                 registry=reg)
    if "user-verified" not in out["label"]["integrity"]:
        return "BREAK(re-issued grant refused)"
    return "HELD"


@probe
def f252_tampered_grant_still_unauthorized():
    """Close-when (3): digest mismatch keeps its own code
    (ifc-privilege-unauthorized), distinct from unissued."""
    grant = _grant()
    tampered = dict(grant)
    tampered["granted_by"] = "attacker"
    records, hook = _audit()
    code = _code_of(ifc.exercise_privilege, tampered, _label(), "endorse",
                    ["user-verified"], hook, NOW)
    if code != "ifc-privilege-unauthorized":
        return "BREAK(tamper path changed: %r)" % (code,)
    return "HELD"


@probe
def f252_expired_grant_still_expired():
    """Close-when (3): expiry behavior unchanged."""
    grant = _grant()
    records, hook = _audit()
    code = _code_of(ifc.exercise_privilege, grant, _label(), "endorse",
                    ["user-verified"], hook, EXPIRED)
    if code != "ifc-privilege-expired":
        return "BREAK(expiry path changed: %r)" % (code,)
    return "HELD"


@probe
def f252_no_audit_hook_still_required():
    """Close-when (3): missing audit hook still refuses."""
    grant = _grant()
    code = _code_of(ifc.exercise_privilege, grant, _label(), "endorse",
                    ["user-verified"], None, NOW)
    if code != "ifc-audit-required":
        return "BREAK(audit path changed: %r)" % (code,)
    return "HELD"


@probe
def f252_scope_escape_still_denied():
    """Close-when (3): scope escape still refuses."""
    grant = _grant()
    records, hook = _audit()
    code = _code_of(ifc.exercise_privilege, grant, _label(), "endorse",
                    ["deployment-attested"], hook, NOW)
    if code != "ifc-privilege-scope-denied":
        return "BREAK(scope path changed: %r)" % (code,)
    return "HELD"


@probe
def f252_default_registry_contract():
    """Deployment contract: issue and exercise with no explicit
    registry share the module default -- the common case works."""
    grant = _grant()
    records, hook = _audit()
    out = ifc.exercise_privilege(grant, _label(), "endorse",
                                 ["user-verified"], hook, NOW)
    if "user-verified" not in out["label"]["integrity"]:
        return "BREAK(default-registry exercise failed)"
    return "HELD"


# ------------------------------------------------------------------
# Depth-1 green check
# ------------------------------------------------------------------

def _green_check():
    """Run adjacent batteries with GOV_SKIP_GREEN=1 in the child env.
    Honors GOV_SKIP_GREEN (records a skip, returns without spawning).
    """
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ok = True
    for battery in ("evals/w268_ifc_probes.py",
                    "evals/w269_redteam_probes.py"):
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = _scratch("g270-f252-green-")
        cmd = [sys.executable, battery]
        r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                           text=True, timeout=900)
        out = r.stdout + r.stderr
        brk = out.count("[BREAK]")
        err = out.count("[ERROR]")
        if r.returncode == 0 and brk == 0 and err == 0:
            print("GREEN CHECK: %s green" % battery)
        else:
            print("GREEN CHECK FAILED: %s (rc=%s BREAK=%d ERROR=%d)"
                  % (battery, r.returncode, brk, err))
            print(out[-1500:])
            ok = False
    return ok


@probe
def adjacent_batteries_green():
    """Close-when (4): w268_ifc and w269_redteam batteries stay green."""
    if _green_check():
        return "HELD"
    return "BREAK(adjacent battery red)"


def main():
    results = []
    for p in PROBES:
        try:
            results.append((p.__name__, p()))
        except Exception as exc:  # never mask a crash
            results.append((p.__name__, "BREAK(%r)" % (exc,)))
    held = sum(1 for _, v in results if v == "HELD")
    brk = sum(1 for _, v in results if v.startswith("BREAK"))
    for name, verdict in results:
        print("%-42s %s" % (name, verdict))
    print("HELD %d / BREAK %d of %d" % (held, brk, len(results)))
    return 1 if brk else 0


if __name__ == "__main__":
    sys.exit(main())
