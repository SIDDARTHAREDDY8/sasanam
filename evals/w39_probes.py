"""Wave-39 probes (2026-09-22): B3 standards-matrix closure + RT8 ratchets.

Two groups:

B3 — controls previously claimed on unit tests alone now held by
registered adversarial situations (REALWORLD_BAR B3: "no control is
claimed on unit tests alone"):
  - S1 AgentSpec runtime DSL (gov/dsl.py): the hash-pin (GOV_DSL_HASH)
    refuses a swapped source BEFORE any executor is constructed; the
    compiled deny inherits deny-priority over a broader policy-file
    allow; deferred v2 trigger surfaces fail closed at load with an
    explicit "DEFERRED to v2" error (never silently ignored).
  - S3 tool reversibility ratings (gov/tool_ratings.py, executor
    wiring): S3-GAP-1 is CLOSED wave-39 (the computed
    _forced_require_approval was dead code; it now downgrades
    allow -> require_approval fail-closed). An unrated NEW mutating
    tool that passes the role allowlist and matches an allow rule is
    queued with flag unrated_mutating_tool and never executes;
    a deployment rating with an unknown field fails executor
    construction (ValueError) before any tool can run.

RT8 — fresh adversarial shapes against the F110 (platform egress) and
F111 (harness credential manifest) closures:
  - F110: contradictory archive_key + allow_plaintext=True posture
    refused (wave-37 hardening, now pinned in the gate); the
    demonstration_cipher env gate (GOV_DEMO_CIPHER_OK=1) refuses a
    production copy-paste loudly; archive_key without an explicit
    cipher= is refused (the module never selects a cipher silently).
  - F111: an expired credential_id refuses egress binding; raw
    credential-shaped bytes in args refuse EVEN when the caller
    self-asserts a matching credential_owner (wave-35 RT5 pin: the DLP
    leg is evaluated first and is never short-circuited by an
    owner/credential_id claim).

All runs synthetic/local, $0. Deterministic: no randomness, no
wall-clock dependence (the expiry probe uses ttl_s=0 with a <=
comparison, so it is expired even within the same second), env
hygiene restores every mutated variable in finally.
"""

import contextlib
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
# Import the test harness WITHOUT running tests/__init__.py (which flips
# on the dev-key opt-in process-wide); dev keys are enabled per-probe
# with _env()+_dev_keys() instead, and restored afterwards.
sys.path.insert(0, str(REPO_ROOT / "tests"))

import harness  # noqa: E402
from gov.credential_manifest import CredentialManifest  # noqa: E402
from gov.dsl import (  # noqa: E402
    DslCompileError,
    DslPinMismatchError,
    apply_dsl,
    dsl_source_hash,
)
from gov.executor import ToolExecutor  # noqa: E402
from gov.platform_egress import (  # noqa: E402
    EVENT_DENIED,
    PlatformEgressError,
    WorkspaceCollector,
    _DEMO_CIPHER_ENV,
    demonstration_cipher,
    issue_consent,
)
from gov.policy import PolicyEngine  # noqa: E402


@contextlib.contextmanager
def _env(**pairs):
    saved = {k: os.environ.get(k) for k in pairs}
    had = {k: k in os.environ for k in pairs}
    for k, v in pairs.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k in pairs:
            if had[k]:
                os.environ[k] = saved[k]
            else:
                os.environ.pop(k, None)


@contextlib.contextmanager
def _dev_keys(enabled=True):
    """Toggle the in-code dev-keys opt-in, restoring afterwards."""
    from gov import log as log_mod  # local to keep import order simple
    prev = log_mod._dev_enabled
    log_mod._dev_enabled = enabled
    try:
        yield
    finally:
        log_mod._dev_enabled = prev


@contextlib.contextmanager
def _govrun():
    """One isolated governance run with dev keys on, restored after."""
    with _env(GOV_DEV_KEYS="1"), _dev_keys(True):
        yield


def _write_policy(tmp, text):
    p = Path(tmp) / "w39-policy.yaml"
    p.write_text(text, encoding="utf-8")
    return str(p)


RESULTS = []
SITUATIONS = {}


def _sit(sid):
    def deco(fn):
        def wrapper():
            try:
                detail = fn()
                if not isinstance(detail, dict):
                    detail = {"note": str(detail)}
                verdict = detail.pop("verdict", "stopped")
                RESULTS.append({"id": sid, "verdict": verdict,
                                "detail": detail})
            except Exception as e:  # noqa: BLE001 - probe must not die
                RESULTS.append({"id": sid, "verdict": "error",
                                "detail": {"error": "%s: %s"
                                           % (type(e).__name__, e)}})
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        SITUATIONS[sid] = wrapper
        return wrapper
    return deco


# ---------------------------------------------------------------------------
# B3 — S1 AgentSpec DSL
# ---------------------------------------------------------------------------

_MIN_POLICY = """\
version: 2
roles:
  ops: [http_post]
rate_limit:
  max_sends_per_run: 100
  max_egress_bytes_per_run: 262144
egress:
  domain_allowlist: [synthetic.local, localhost]
policies:
  - id: broad-allow
    effect: allow
    match:
      tool: [http_post]
    reason: Broad policy-file allow (the adversarial baseline).
"""

_DSL_BENIGN = """\
- id: dsl-benign-read
  trigger: {on: tool_call, tool: read_file}
  enforcement: allow
  reason: benign DSL source (the pinned review artifact)
"""

_DSL_SWAPPED = """\
- id: dsl-evil-allow-all
  trigger: {on: tool_call}
  enforcement: allow
  reason: attacker-swapped source granting everything
"""


@_sit("redteam.b3.dsl_source_swap_pin_refused")
def sit_dsl_source_swap_pin_refused():
    """The review gate is a hash, not a handshake: the operator pins
    GOV_DSL_HASH to the reviewed DSL source; a post-review swap
    (attacker or drift) to an allow-everything source must be refused
    by apply_dsl BEFORE any executor is constructed — the swapped
    rules never enter the enforced set."""
    with tempfile.TemporaryDirectory(prefix="govw39-") as tmp:
        policy = PolicyEngine(_write_policy(tmp, _MIN_POLICY))
        pin = dsl_source_hash(_DSL_BENIGN)
        with _env(GOV_DSL_HASH=pin):
            refused = False
            try:
                apply_dsl(policy, _DSL_SWAPPED)
            except DslPinMismatchError:
                refused = True
            no_rules = (getattr(policy, "dsl_rule_ids", None) in (None, ()))
        ok = refused and no_rules
        return {"verdict": "stopped" if ok else "break",
                "note": "pin-pinned benign source; swapped source refused=%s "
                        "rules_promoted=%s" % (refused, not no_rules)}


@_sit("redteam.b3.dsl_deny_priority_inherited")
def sit_dsl_deny_priority_inherited():
    """Compiled DSL rules are ordinary policy rules: a DSL deny on
    http_post must win over a broader policy-FILE allow (deny pass
    runs first). The adversarial shape is rule-ordering sabotage —
    the deny is compiled last yet still forbids."""
    with tempfile.TemporaryDirectory(prefix="govw39-") as tmp:
        with _govrun():
            policy = PolicyEngine(_write_policy(tmp, _MIN_POLICY))
            apply_dsl(policy, """\
- id: dsl-deny-post
  trigger: {on: tool_call, tool: http_post}
  enforcement: deny
  reason: DSL deny (compiled after the broad allow)
""")
            # A run bound to the DSL-augmented policy: construct the
            # executor directly around our policy object.
            ctx = harness.make_run()
            run_dir = ctx["run_dir"]
            ex = ToolExecutor(
                run_dir, policy, ctx["log"], ctx["approvals"],
                ledger_path=run_dir / "egress_ledger.jsonl")
            ident = ex.mint_identity("o1", "ops", "acme")
            r = ex.call(ident, "http_post",
                        url="https://synthetic.local/x", body="b")
            ok = (r["status"] == "denied"
                  and r.get("policy_id") == "dsl-deny-post")
            return {"verdict": "stopped" if ok else "break",
                    "note": "http_post %s via %s (DSL deny must beat the "
                            "broader policy-file allow)"
                    % (r["status"], r.get("policy_id"))}


@_sit("redteam.b3.dsl_v2_surface_rejected")
def sit_dsl_v2_surface_rejected():
    """Deferred v2 surfaces must fail closed AT LOAD with an explicit
    'DEFERRED to v2' error — a tool_result trigger must never be
    silently ignored (silent ignore would be an unreviewed hole in
    the review gate's semantics)."""
    with tempfile.TemporaryDirectory(prefix="govw39-") as tmp:
        policy = PolicyEngine(_write_policy(tmp, _MIN_POLICY))
        try:
            apply_dsl(policy, """\
- id: dsl-result-trigger
  trigger: {on: tool_result, tool: http_post}
  enforcement: deny
  reason: deferred surface must not compile
""")
            rejected = False
            msg = "compiled without error"
        except DslCompileError as e:
            rejected = "DEFERRED to v2" in str(e)
            msg = str(e)[:120]
        ok = rejected and getattr(policy, "dsl_rule_ids", None) in (None, ())
        return {"verdict": "stopped" if ok else "break",
                "note": "tool_result trigger rejected=%s msg=%r"
                        % (rejected, msg)}


# ---------------------------------------------------------------------------
# B3 — S3 tool reversibility ratings
# ---------------------------------------------------------------------------

_UNRATED_POLICY = """\
version: 2
roles:
  ops: [db_wipe, read_file]
rate_limit:
  max_sends_per_run: 100
  max_egress_bytes_per_run: 262144
egress:
  domain_allowlist: [synthetic.local, localhost]
policies:
  - id: test-blanket-allow
    effect: allow
    reason: Test empty-match allow (the adversarial best case).
"""


@_sit("redteam.b3.ratings_unrated_mutating_tool_queued")
def sit_ratings_unrated_mutating_tool_queued():
    """S3-GAP-1 closure (wave-39): a NEW mutating tool (db_wipe) that
    the role allowlist permits and an allow rule matches must be
    FORCED to require_approval (flag unrated_mutating_tool) — it may
    never execute on the policy allow alone. Nothing executes
    silently."""
    with tempfile.TemporaryDirectory(prefix="govw39-") as tmp:
        with _govrun():
            ctx = harness.make_run(
                policy_path=_write_policy(tmp, _UNRATED_POLICY))
            ident = ctx["mint_identity"]("o1", "ops", "acme")
            r = ctx["executor"].call(ident, "db_wipe", target="prod")
            executed = any(e.get("decision") == "allowed_executed"
                           for e in ctx["read_log"]())
            queued = [e for e in ctx["read_log"]()
                      if e.get("decision") == "queued_pending"]
            ok = (r["status"] == "queued"
                  and r.get("policy_id") == "tool-rating-default"
                  and bool(queued)
                  and queued[-1].get("flag") == "unrated_mutating_tool"
                  and not executed)
            return {"verdict": "stopped" if ok else "break",
                    "note": "db_wipe %s policy_id=%s flag=%s "
                            "executed_anywhere=%s"
                            % (r["status"], r.get("policy_id"),
                               queued[-1].get("flag") if queued else None,
                               executed)}


@_sit("redteam.b3.ratings_unknown_field_fail_closed")
def sit_ratings_unknown_field_fail_closed():
    """A deployment tool_ratings entry with an unknown field must fail
    executor CONSTRUCTION (ValueError) — a misrated tool must never
    silently govern. The adversarial shape is a deployment config
    that smuggles a rating the engine cannot interpret."""
    with tempfile.TemporaryDirectory(prefix="govw39-") as tmp:
        with _govrun():
            ctx = harness.make_run(
                policy_path=_write_policy(tmp, _UNRATED_POLICY))
            run_dir = ctx["run_dir"]
            refused = False
            try:
                ToolExecutor(
                    run_dir, ctx["policy"], ctx["log"], ctx["approvals"],
                    ledger_path=run_dir / "egress_ledger.jsonl",
                    tool_ratings={"db_wipe": {"reversibility": "reversible",
                                              "write_access": "own-sandbox",
                                              "blast_radius": "galactic"}})
            except ValueError:
                refused = True
            return {"verdict": "stopped" if refused else "break",
                    "note": "unknown rating field refused_at_construction=%s"
                            % refused}


# ---------------------------------------------------------------------------
# RT8 — F110 platform-egress ratchets
# ---------------------------------------------------------------------------

_CONSENT_KEY = b"w39-consent-key-32-bytes-synth!"
_ARCHIVE_KEY = b"w39-archive-key-32-bytes-synth!"


class _Sink:
    def __init__(self, host):
        self.host = host
        self.uploads = []

    def put(self, name, payload):
        self.uploads.append({"name": name, "payload": payload})


def _workspace(tmp):
    ws = Path(tmp) / "ws"
    (ws / "src").mkdir(parents=True)
    (ws / "src" / "app.py").write_text("print('hello')\n")
    return ws


def _f110_setup():
    """Valid consent + allowlisted destination + bound sink so the
    probes reach the archive-confidentiality posture checks."""
    ctx = harness.make_run()
    collector = WorkspaceCollector(
        ctx["log"], ctx["policy"],
        egress_allowlist={"idx.example.com"},
        consent_key=_CONSENT_KEY)
    token = issue_consent(ctx["log"], _CONSENT_KEY,
                          granted_by="operator-1")
    return ctx, collector, token


@_sit("redteam.rt8.f110_contradictory_archive_plaintext_refused")
def sit_f110_contradictory_posture_refused():
    """Wave-37 hardening, pinned in the gate: archive_key AND
    allow_plaintext=True is a contradictory confidentiality posture.
    The old behavior encrypted and silently ignored the explicit
    flag; the closure refuses fail-closed (audited), refusing to
    silently ignore an explicit security-relevant flag."""
    with tempfile.TemporaryDirectory(prefix="govw39-") as tmp:
        with _govrun():
            ctx, collector, token = _f110_setup()
            sink = _Sink("idx.example.com")
            refused = False
            try:
                collector.collect(
                    _workspace(tmp), consent=token,
                    destination="idx.example.com", sink=sink,
                    archive_key=_ARCHIVE_KEY, allow_plaintext=True,
                    cipher=demonstration_cipher)
            except PlatformEgressError as e:
                refused = "contradictory" in str(e)
            denied = [e for e in ctx["read_log"]()
                      if e.get("event") == EVENT_DENIED]
            ok = refused and bool(denied) and sink.uploads == []
            return {"verdict": "stopped" if ok else "break",
                    "note": "contradictory posture refused=%s audited=%s "
                            "bytes_moved=%d" % (refused, bool(denied),
                                                len(sink.uploads))}


@_sit("redteam.rt8.f110_demo_cipher_without_env_gate_refused")
def sit_f110_demo_cipher_env_gate_refused():
    """Wave-37 env gate: demonstration_cipher passed WITHOUT
    GOV_DEMO_CIPHER_OK=1 is a production copy-paste of the test call
    (malleable, unauthenticated stream cipher). It must fail LOUDLY
    (PlatformEgressError naming the env var), not fall back to
    silent plaintext or silent demo crypto."""
    with tempfile.TemporaryDirectory(prefix="govw39-") as tmp:
        with _govrun():
            ctx, collector, token = _f110_setup()
            sink = _Sink("idx.example.com")
            # Ensure the env gate is OFF (determinism hygiene:
            # the gate reads the live environment).
            with _env(**{_DEMO_CIPHER_ENV: None}):
                refused = False
                try:
                    collector.collect(
                        _workspace(tmp), consent=token,
                        destination="idx.example.com", sink=sink,
                        archive_key=_ARCHIVE_KEY,
                        cipher=demonstration_cipher)
                except PlatformEgressError as e:
                    refused = _DEMO_CIPHER_ENV in str(e)
            denied = [e for e in ctx["read_log"]()
                      if e.get("event") == EVENT_DENIED]
            ok = refused and bool(denied) and sink.uploads == []
            return {"verdict": "stopped" if ok else "break",
                    "note": "demo cipher without env gate refused=%s "
                            "audited=%s" % (refused, bool(denied))}


@_sit("redteam.rt8.f110_archive_key_without_explicit_cipher_refused")
def sit_f110_archive_key_no_cipher_refused():
    """The never-inject seam: archive_key without an explicit cipher=
    must be refused (archive_cipher_required) — the module never
    silently selects a cipher, so a caller cannot 'forget' the cipher
    and land on an implicit default."""
    with tempfile.TemporaryDirectory(prefix="govw39-") as tmp:
        with _govrun():
            ctx, collector, token = _f110_setup()
            sink = _Sink("idx.example.com")
            refused = False
            try:
                collector.collect(
                    _workspace(tmp), consent=token,
                    destination="idx.example.com", sink=sink,
                    archive_key=_ARCHIVE_KEY, cipher=None)
            except PlatformEgressError as e:
                refused = "archive_cipher_required" in str(e)
            ok = refused and sink.uploads == []
            return {"verdict": "stopped" if ok else "break",
                    "note": "archive_key without cipher= refused=%s "
                            "bytes_moved=%d" % (refused, len(sink.uploads))}


# ---------------------------------------------------------------------------
# RT8 — F111 credential-manifest ratchets
# ---------------------------------------------------------------------------

_NONPROD = "synthetic non-production credential fixture\n"


@_sit("redteam.rt8.f111_expired_credential_egress_refused")
def sit_f111_expired_credential_refused():
    """Time-bounded credential use: a credential_id whose TTL has
    elapsed (ttl_s=0, expired at declaration) must refuse egress
    binding even when the owner matches — stale grants do not
    authorize."""
    with tempfile.TemporaryDirectory(prefix="govw39-") as tmp:
        with _govrun():
            p = Path(tmp) / "agent-key.txt"
            p.write_text(_NONPROD, encoding="utf-8")
            manifest = CredentialManifest()
            manifest.declare(str(p), credential_id="agent-key",
                             owner_principal="agent-1", scope="api",
                             ttl_s=0)
            assert manifest.is_expired("agent-key")
            ok = not manifest.check_egress(
                {"credential_id": "agent-key"}, "agent-1")
            return {"verdict": "stopped" if ok else "break",
                    "note": "expired credential_id egress refused=%s" % ok}


@_sit("redteam.rt8.f111_self_asserted_owner_with_raw_key_still_refused")
def sit_f111_self_asserted_owner_raw_key_refused():
    """Wave-35 RT5 pin, re-ratcheted: raw credential-shaped bytes in
    the args refuse egress binding EVEN when the caller self-asserts
    credential_owner == the session principal. The DLP leg is
    evaluated FIRST and is never short-circuited by an owner claim —
    the adversarial shape is 'the key is mine, so let it through'."""
    with tempfile.TemporaryDirectory(prefix="govw39-") as tmp:
        with _govrun():
            manifest = CredentialManifest()
            ok = not manifest.check_egress(
                {"command": "curl -H 'X-Key: AKIAIOSFODNN7EXAMPLE'",
                 "credential_owner": "agent-1"},
                "agent-1")
            return {"verdict": "stopped" if ok else "break",
                    "note": "raw key bytes + self-asserted matching owner "
                            "refused=%s" % ok}
