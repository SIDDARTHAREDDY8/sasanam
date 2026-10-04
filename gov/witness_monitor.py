"""Fail-closed witness monitor loop (stdlib-only, offline, deterministic).

The remaining greenfield piece of the witness layer
(``research/prospecting/w321_witness_monitor.md``, direction brief item 3):
the production substitute for checkpoint gossip is witness cosigning +
independent monitors + governance. This module is the independent-monitor
half. It consumes :func:`gov.witness_publish.verify_published_checkpoint`
outputs and advances a durable trusted head.

Adapted from the MarkovianProtocol/log-monitor exemplar (Apache-2.0; see
the prospectus), with one deliberate fix:

* The exemplar's head-advancement gate -- ``authenticated and not
  tree_bad and leaf_verified`` -- is kept. In the exemplar, when the
  persisted Merkle fringe is missing while the log grew,
  ``leaf_verified`` stays False and **the head silently never advances
  again** -- no alert fires. This module does not copy that edge: when
  the caller requires consistency evidence
  (``require_consistency_proof=True``) and the head advanced without it,
  the monitor raises the coded refusal ``witness-monitor-stale`` LOUD.
  A stalled monitor is a signal, never silence.

Explicit design decisions (the prospectus requires each to be stated):

* **Staleness: block, fail-closed.** The note layer's ``max_age`` bound
  blocks advancement on stale checkpoints (``witness-checkpoint-stale``);
  when the caller passes no ``max_age``, no staleness block applies --
  that is the caller's explicit choice, recorded in the returned verdict.
* **Alert-before-leaves.** The exemplar orders auth/consistency alerts
  before touching the leaf plane. This monitor is offline (no leaf
  plane); the ordering is preserved structurally: authentication and
  tree-consistency are checked before any consistency-proof work.
* **Advisory witnesses.** Cosignatures from witnesses outside the pinned
  ``witness_set`` are ignored per MUST-ignore-unknown-signatures and
  never counted toward quorum (the note layer enforces this).
* **State: hard stop, never silent re-baseline.** A missing, corrupt, or
  mismatched state file raises ``witness-monitor-state-missing`` /
  ``witness-monitor-state-corrupt`` / ``witness-monitor-state-mismatch``
  -- the monitor never quietly starts over. The mismatch check is the
  replay guard: the state's durable head must equal the caller's
  ``last_seen`` or the run refuses.
* **Policy version watermark.** The state's ``policy_version`` is the
  auditor-side last-seen-version watermark (the witness-policy
  direction). A caller-supplied older version refuses with the existing
  ``witness-policy-version-rollback``; a newer version updates the
  watermark (rotation composes; the caller verifies the policy against
  the trust anchor before calling).
* **Fetch failures are availability signals.** The monitor is offline,
  so fetching happens outside it. ``checkpoint_bytes=None`` records a
  failed fetch: the failure counter persists atomically and the run
  raises ``witness-monitor-fetch-failed`` -- the cron wrapper alerts
  from the 3rd consecutive failure, every run while down, per the
  exemplar's discipline. The daily heartbeat (silence is itself a
  signal) belongs to the cron wrapper, not this module (no network
  here).
* **Availability cost is budgeted explicitly.** Like Rekor v2's
  fail-closed witness quorum on the publication path, a fail-closed
  monitor freezes the trusted head during any witness outage or quorum
  shortfall; every newer checkpoint refuses and the failure counter
  re-alerts. The divergence window (records appended after the frozen
  head are unverifiable-by-policy) is the price of fail-closed.

Composition seams (consumer only -- this module never modifies the
partner layers):

* ``gov.witness_publish.verify_published_checkpoint`` -- the
  authentication + freshness + monotonicity layer. All of its coded
  refusals propagate unchanged.
* ``gov.witness_policy.verifier_inputs`` -- the monitor takes its two
  halves as ``witness_set`` (the ``{name: vkey}`` witness map, the
  lane-3 seam) and ``policy_inputs`` (operator_vkeys, quorum_k,
  policy_id, policy_version).
* ``gov.witness_log.verify_consistency`` -- the optional RFC 6962
  consistency-proof check for the ``tree_bad`` conjunct.

Only ``gov/decision_codes.py`` is touched besides the new module (the
five ``witness-monitor-*`` registrations).
"""

import importlib.util
import json
import os
import time

# ---------------------------------------------------------------------------
# Decision codes (registered centrally in gov/decision_codes.py).
# ---------------------------------------------------------------------------

WITNESS_MONITOR_STATE_CORRUPT = "witness-monitor-state-corrupt"
WITNESS_MONITOR_STATE_MISSING = "witness-monitor-state-missing"
WITNESS_MONITOR_STATE_MISMATCH = "witness-monitor-state-mismatch"
WITNESS_MONITOR_STALE = "witness-monitor-stale"
WITNESS_MONITOR_FETCH_FAILED = "witness-monitor-fetch-failed"
# Reused from the witness-policy layer (policy-version N+1 watermark):
WITNESS_POLICY_VERSION_ROLLBACK = "witness-policy-version-rollback"

_STATE_VERSION = 1
# Consecutive-failure count at which the cron wrapper should page
# (the exemplar's "alert from the 3rd consecutive failure" rule).
ALERT_AFTER_FAILURES = 3


class WitnessMonitorError(Exception):
    """A coded monitor-loop failure. ``code`` is the machine code.

    ``consecutive_failures`` is the durable failure count including
    this run's increment (so the cron wrapper can alert on thresholds
    without re-reading the state file). It is ``None`` on the two
    pre-run state refuses (state-mismatch, policy-version-rollback),
    which report the pre-run count.
    """

    def __init__(self, code, detail="", consecutive_failures=None):
        self.code = code
        self.detail = detail
        self.consecutive_failures = consecutive_failures
        super().__init__("[%s] %s" % (code, detail) if detail else
                         "[%s]" % (code,))


def _refuse(code, detail="", consecutive_failures=None):
    raise WitnessMonitorError(code, detail, consecutive_failures)


# ---------------------------------------------------------------------------
# Dependency loading (file path, socket-free -- mirrors the partner
# layers' standalone-capable discipline).
# ---------------------------------------------------------------------------

def _load_dep(filename, standalone_name):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        filename)
    try:
        spec = importlib.util.spec_from_file_location(standalone_name,
                                                      path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except WitnessMonitorError:
        raise
    except Exception as exc:  # noqa: BLE001
        # A dependency that cannot be loaded is a broken deployment, not
        # a verification verdict: raise, never refuse-with-a-code (the
        # code would misname the failure).
        raise RuntimeError(
            "cannot load %s from %r: %s" % (filename, path, exc))
    return module


_wp = None
_wl = None


def _publish_mod():
    global _wp
    if _wp is None:
        _wp = _load_dep("witness_publish.py", "witness_publish_standalone")
    return _wp


def _wlog_mod():
    global _wl
    if _wl is None:
        _wl = _load_dep("witness_log.py", "witness_log_standalone")
    return _wl


# ---------------------------------------------------------------------------
# Input shape checks (programmer errors raise; verification failures
# refuse with a code).
# ---------------------------------------------------------------------------

def _check_last_seen(last_seen, where):
    if last_seen is None:
        return None
    if (not isinstance(last_seen, (tuple, list)) or len(last_seen) != 2):
        raise TypeError("%s must be (tree_size, root_hex) or None"
                        % (where,))
    size, root = last_seen
    if isinstance(size, bool) or not isinstance(size, int) or size < 1:
        raise TypeError("%s tree_size must be a positive int" % (where,))
    if not isinstance(root, str) or len(root) != 64:
        raise TypeError("%s root must be 64 hex chars" % (where,))
    try:
        root_b = bytes.fromhex(root)
    except ValueError:
        raise TypeError("%s root must be 64 hex chars" % (where,))
    if len(root_b) != 32 or any(c not in "0123456789abcdefABCDEF"
                                for c in root):
        raise TypeError("%s root must be 64 hex chars" % (where,))
    return (size, root_b)


def _check_witness_set(witness_set):
    if (not isinstance(witness_set, dict) or not witness_set
            or not all(isinstance(k, str) and k
                       for k in witness_set)):
        raise TypeError(
            "witness_set must be a non-empty {name: vkey} map")
    for name, vkey in witness_set.items():
        if not isinstance(vkey, str) or not vkey:
            raise TypeError(
                "witness_set[%r] vkey must be a non-empty string" % (name,))
    return witness_set


def _check_policy_inputs(policy_inputs):
    if not isinstance(policy_inputs, dict):
        raise TypeError("policy_inputs must be a mapping")
    op = policy_inputs.get("operator_vkeys")
    if not isinstance(op, (list, tuple)) or not op:
        raise TypeError("policy_inputs['operator_vkeys'] must be a "
                        "non-empty list")
    k = policy_inputs.get("quorum_k")
    if isinstance(k, bool) or not isinstance(k, int) or k < 1:
        raise TypeError("policy_inputs['quorum_k'] must be a positive int")
    pid = policy_inputs.get("policy_id")
    if not isinstance(pid, str) or not pid:
        raise TypeError("policy_inputs['policy_id'] must be a non-empty "
                        "string")
    pv = policy_inputs.get("policy_version")
    if isinstance(pv, bool) or not isinstance(pv, int) or pv < 0:
        raise TypeError("policy_inputs['policy_version'] must be a "
                        "non-negative int")
    # The witness half of verifier_inputs() may ride along; when both
    # are present they must agree (defense in depth, not a second
    # source of truth).
    vw = policy_inputs.get("witness_vkeys")
    return {"operator_vkeys": list(op), "quorum_k": k, "policy_id": pid,
            "policy_version": pv, "witness_vkeys": vw}


def _check_allowed_origins(allowed_origins):
    if (not isinstance(allowed_origins, (list, tuple))
            or not allowed_origins
            or not all(isinstance(o, str) and o
                       for o in allowed_origins)):
        raise TypeError("allowed_origins must be a non-empty list of "
                        "strings")
    return list(allowed_origins)


def _now_s(now):
    if now is None:
        return int(time.time())
    if isinstance(now, bool) or not isinstance(now, int) or now < 0:
        raise TypeError("now must be a non-negative int (unix seconds)")
    return now


# ---------------------------------------------------------------------------
# Durable state (atomic tmp + fsync + os.replace; the exemplar's
# discipline). The state file is the monitor's memory: last trusted
# head, policy-version watermark, failure counters.
# ---------------------------------------------------------------------------

def _state_shape(state, where):
    if not isinstance(state, dict):
        _refuse(WITNESS_MONITOR_STATE_CORRUPT,
                "%s: top level must be a JSON object" % (where,))
    if state.get("version") != _STATE_VERSION:
        _refuse(WITNESS_MONITOR_STATE_CORRUPT,
                "%s: unsupported state version %r" % (where,
                                                     state.get("version")))
    ls = state.get("last_seen")
    if ls is not None:
        if (not isinstance(ls, dict) or not isinstance(ls.get("size"), int)
                or ls["size"] < 1 or not isinstance(ls.get("root"), str)
                or len(ls["root"]) != 64):
            _refuse(WITNESS_MONITOR_STATE_CORRUPT,
                    "%s: last_seen must be {size: positive int, root: 64 "
                    "hex} or null" % (where,))
        try:
            bytes.fromhex(ls["root"])
        except ValueError:
            _refuse(WITNESS_MONITOR_STATE_CORRUPT,
                    "%s: last_seen.root is not hex" % (where,))
    cf = state.get("consecutive_failures")
    if isinstance(cf, bool) or not isinstance(cf, int) or cf < 0:
        _refuse(WITNESS_MONITOR_STATE_CORRUPT,
                "%s: consecutive_failures must be a non-negative int"
                % (where,))
    pv = state.get("policy_version")
    if isinstance(pv, bool) or not isinstance(pv, int) or pv < 0:
        _refuse(WITNESS_MONITOR_STATE_CORRUPT,
                "%s: policy_version must be a non-negative int" % (where,))
    if not isinstance(state.get("policy_id"), str):
        _refuse(WITNESS_MONITOR_STATE_CORRUPT,
                "%s: policy_id must be a string" % (where,))
    return state


def load_monitor_state(path):
    """Load and shape-check the monitor state file.

    Raises ``witness-monitor-state-corrupt`` on any shape violation --
    a corrupt state is a hard stop, never a silent re-baseline.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except FileNotFoundError:
        raise
    except OSError as exc:
        _refuse(WITNESS_MONITOR_STATE_CORRUPT,
                "cannot read state file %r: %s" % (path, exc))
    try:
        state = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        _refuse(WITNESS_MONITOR_STATE_CORRUPT,
                "state file %r is not valid JSON: %s" % (path, exc))
    return _state_shape(state, "state file %r" % (path,))


def _write_state_atomic(path, state, now_s):
    state = dict(state)
    state["last_run"] = now_s
    payload = (json.dumps(state, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
               + b"\n")
    directory = os.path.dirname(os.path.abspath(path)) or "."
    tmp = os.path.join(directory, ".monitor-state.%d.tmp" % (os.getpid(),))
    with open(tmp, "wb") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _new_state(size, root_hex, policy_id, policy_version, failures):
    return {"version": _STATE_VERSION,
            "last_seen": ({"size": size, "root": root_hex}
                          if size is not None else None),
            "policy_id": policy_id,
            "policy_version": policy_version,
            "consecutive_failures": failures}


# ---------------------------------------------------------------------------
# The monitor step.
# ---------------------------------------------------------------------------

def monitor_step(checkpoint_bytes, *, witness_set, last_seen,
                 policy_inputs, allowed_origins, now=None, max_age=None,
                 consistency_proof=None, require_consistency_proof=False,
                 state_path=None):
    """Run one fail-closed monitor step against a checkpoint.

    ``checkpoint_bytes`` is the published C2SP signed note (or ``None``
    when the fetch failed -- recorded as
    ``witness-monitor-fetch-failed``). ``witness_set`` is the
    policy-pinned ``{name: vkey}`` map (the lane-3 seam);
    ``policy_inputs`` is the operator half of
    ``witness_policy.verifier_inputs()`` (operator_vkeys, quorum_k,
    policy_id, policy_version). ``last_seen`` is ``(tree_size,
    root_hex)`` or ``None`` (``None`` only on the very first run, when
    no state file exists yet -- the baseline is established from the
    authenticated checkpoint). ``allowed_origins`` pins the log
    origins. ``consistency_proof`` is the optional RFC 6962 wire proof
    (list of 64-hex subtree roots) linking the old head to the new one.

    The gate (adapted from the log-monitor exemplar):
    ``authenticated and not tree_bad and leaf_verified``.

    * authenticated: the note layer verifies the operator signature,
      >= quorum_k witness cosignatures, origin pinning, and freshness.
    * not tree_bad: the note layer refuses rollback
      (``witness-publish-rollback``) and equivocation
      (``witness-consistency-fork-detected``); when a consistency proof
      is supplied it must recompute both roots
      (``witness-log-consistency-invalid`` on failure).
    * leaf_verified: when ``require_consistency_proof`` is set and the
      head advanced, a proof MUST be supplied -- its absence raises
      ``witness-monitor-stale`` LOUD. This is the fixed missing-fringe
      edge: the monitor never silently stops advancing.

    On accept, returns ``{"accepted": True, "advanced": bool, "head":
    {"size": int, "root": hex}, "policy_id", "policy_version",
    "consecutive_failures": 0, "staleness_block": bool}``. On any
    refusal, raises :class:`WitnessMonitorError` with the machine code
    -- never a soft verdict. The state file (when ``state_path`` is
    given) is updated atomically on both accept and refuse paths; a
    refused run never advances the durable head.
    """
    if checkpoint_bytes is not None and not isinstance(checkpoint_bytes,
                                                       (bytes, bytearray)):
        raise TypeError("checkpoint_bytes must be bytes or None")
    if (now is None) != (max_age is None):
        raise ValueError("now and max_age must be given together")
    witness_set = _check_witness_set(witness_set)
    policy = _check_policy_inputs(policy_inputs)
    allowed_origins = _check_allowed_origins(allowed_origins)
    # The witness half of verifier_inputs() may ride along in
    # policy_inputs; when both are present they must agree -- a
    # disagreement means the caller composed the inputs wrong, and the
    # monitor fails closed rather than guessing which set to trust.
    if (policy["witness_vkeys"] is not None
            and policy["witness_vkeys"] != witness_set):
        _refuse("witness-policy-malformed",
                "policy_inputs['witness_vkeys'] disagrees with "
                "witness_set")
    seen = _check_last_seen(last_seen, "last_seen")
    now_s = _now_s(now)
    if (consistency_proof is not None
            and not isinstance(consistency_proof, list)):
        raise TypeError("consistency_proof must be a list of 64-hex "
                        "strings or None")

    wp = _publish_mod()

    # -- Durable state: load first (a broken state is a hard stop). ----
    state = None
    if state_path is not None:
        if os.path.exists(state_path):
            state = load_monitor_state(state_path)
            state_ls = state["last_seen"]
            if state_ls is not None:
                state_seen = (state_ls["size"], state_ls["root"])
                if seen is not None and (seen[0],
                                         seen[1].hex()) != state_seen:
                    _refuse(WITNESS_MONITOR_STATE_MISMATCH,
                            "caller last_seen %r disagrees with durable "
                            "head %r: refusing (replay guard)"
                            % (last_seen, state_seen),
                            state["consecutive_failures"])
                seen = (state_seen[0], bytes.fromhex(state_seen[1]))
            if policy["policy_version"] < state["policy_version"]:
                _refuse(WITNESS_POLICY_VERSION_ROLLBACK,
                        "policy version %d older than durable watermark "
                        "%d" % (policy["policy_version"],
                                state["policy_version"]),
                        state["consecutive_failures"])
            if policy["policy_id"] != state["policy_id"]:
                _refuse("witness-policy-id-mismatch",
                        "policy_id %r does not match the durable "
                        "watermark %r: policy-family swap refused"
                        % (policy["policy_id"], state["policy_id"]),
                        state["consecutive_failures"])
        elif seen is not None:
            # The caller expected durable state and it is gone: hard
            # stop, never a silent re-baseline.
            _refuse(WITNESS_MONITOR_STATE_MISSING,
                    "state file %r absent but last_seen %r was given: "
                    "refusing to re-baseline silently" % (state_path,
                                                          last_seen))

    def _persist(failures, head_size=None, head_root=None,
                 policy_version=None):
        if state_path is None:
            return failures
        if head_size is None:
            # Refused run: only the failure counter (and watermark)
            # may change -- the durable head NEVER advances on refusal.
            # On a first-run refusal there is no head yet: persist the
            # counter with a null head.
            if state is None:
                st = _new_state(None, None, policy["policy_id"],
                                policy["policy_version"], failures)
            else:
                st = _new_state(state["last_seen"]["size"]
                                if state["last_seen"] else None,
                                state["last_seen"]["root"]
                                if state["last_seen"] else None,
                                state["policy_id"],
                                (state["policy_version"] if policy_version
                                 is None else policy_version),
                                failures)
        else:
            st = _new_state(head_size, head_root, policy["policy_id"],
                            policy["policy_version"], failures)
        _write_state_atomic(state_path, st, now_s)
        return failures

    def _fail(code, detail, base_failures):
        failures = _persist(base_failures + 1)
        _refuse(code, detail, failures)

    base_failures = state["consecutive_failures"] if state else 0

    # -- Fetch failure: availability signal, not a verification ------
    # -- verdict. The counter persists; the wrapper alerts from the ----
    # -- 3rd consecutive failure. --------------------------------------
    if checkpoint_bytes is None:
        _fail(WITNESS_MONITOR_FETCH_FAILED,
              "no checkpoint bytes: the fetch failed before verification",
              base_failures)

    # -- authenticated: the note layer verifies operator + quorum + ----
    # -- origin + freshness + monotonicity vs the durable head. --------
    try:
        verified = wp.verify_published_checkpoint(
            bytes(checkpoint_bytes),
            operator_vkeys=policy["operator_vkeys"],
            witness_vkeys=witness_set,
            quorum_k=policy["quorum_k"],
            allowed_origins=allowed_origins,
            now=now_s if max_age is not None else None,
            max_age=max_age,
            last_seen=seen)
    except wp.WitnessPublishError as exc:
        _fail(exc.code, exc.detail, base_failures)

    size = verified["tree_size"]
    root_hex = verified["root_hash"]
    root_b = bytes.fromhex(root_hex)

    advanced = seen is None or size > seen[0]

    # -- not tree_bad (continued): optional RFC 6962 consistency ------
    # -- proof between the durable head and the new checkpoint. --------
    if advanced and consistency_proof is not None and seen is not None:
        wl = _wlog_mod()
        try:
            wl.verify_consistency(seen[0], bytes(seen[1]), size, root_b,
                                  list(consistency_proof))
        except Exception as exc:  # noqa: BLE001 -- coded or internal
            code = getattr(exc, "code", "")
            detail = getattr(exc, "detail", str(exc))
            if code:
                _fail(code, "consistency proof rejected: %s" % (detail,),
                      base_failures)
            raise

    # -- leaf_verified / THE FIX: the missing-fringe edge. If the ------
    # -- caller requires consistency evidence and the head advanced ----
    # -- from a prior head without it, the monitor must NOT silently ---
    # -- keep the old head forever. It raises LOUD. (A first-run -------
    # -- baseline has no prior head to be inconsistent with, so it is --
    # -- established from the authenticated checkpoint alone.) ---------
    if (advanced and seen is not None and require_consistency_proof
            and consistency_proof is None):
        _fail(WITNESS_MONITOR_STALE,
              "head advanced %s -> %d but the required consistency "
              "proof is absent: refusing to stall silently (missing-"
              "fringe edge)" % (seen[0] if seen else "none", size),
              base_failures)

    # -- Accept: advance the durable head, reset the counter. ----------
    _persist(0, head_size=size, head_root=root_hex)
    return {"accepted": True,
            "advanced": advanced,
            "head": {"size": size, "root": root_hex},
            "policy_id": policy["policy_id"],
            "policy_version": policy["policy_version"],
            "consecutive_failures": 0,
            "staleness_block": max_age is not None,
            "witnesses": verified["witnesses"],
            "quorum_k": verified["quorum_k"]}
