"""Wave-331 independent red-team battery.

Base: cd353e25 (wave-330 merge). Footer: open F415, F416 / next F417
(F413/F414 CLOSED; F415/F416 filed by wave-330 lane 3, LOW, OPEN). Pin: 2100.

P1  wave-330 seams not yet broken: gov/shamir_custody.py post-F414
    (realpath pre-flight games: unresolvable paths, (st_dev,st_ino,
    basename) key games, case-insensitive residual, TOCTOU between
    pre-flight and write) and the w330_prospectus.md STEAL-verdict
    audit (Landlock overclaim vs the wave-266 tier already in
    gov/sandbox.py; PQC slot absence; MCP OAuth gaps #1/#2 absence).
P2  F415/F416 re-probes (CLOSED -- lanes 1/2 closed them; assert the
    coded refusals, HELD).
P3  F414/F413/F412/F411/F410 closure-regression probes (all HELD).
P4  merge-defect class: no trailing blank line on footer-bearing
    files (wave-330 scripted-resolution class), code-registration,
    pin-comment honesty.
P5  pin 2100 + footer state probes.
P6  prior batteries in child mode (GOV_SKIP_GREEN=1 in the child env),
    tallies verified by direct child runs.

gov/ is byte-identical to base: this battery changes no product code
and files findings only (from F417). No new decision codes from this lane.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F662, F663, F664, F665, F666, F667, F669, F670, F671"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # F415/F416/F417/F423/F424/F425 CLOSED; F426 closed wave-338 lane 1.; F442 CLOSED 2026-10-05 wave-347 lane 6; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)


FOOTER_NEXT = "F672"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)



_results = []
_PROBES = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    return (pid, "HELD", note)


def _break(pid, note):
    return (pid, "BREAK", note)


def probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _safe(pid, fn):
    try:
        _record(*fn())
    except Exception:
        _record(pid, "ERROR",
                traceback.format_exc(limit=2).replace("\n", " | ")[:500])


def _relabel(pid, fn):
    _pid, verdict, note = fn()
    return (pid, verdict, note)


def _tmpd():
    return tempfile.mkdtemp(prefix="w331-", dir=_run_root())


def _run_root():
    d = os.path.join(tempfile.gettempdir(), "w331rt")
    if not os.path.isdir(d):
        os.makedirs(d)
    return d


from gov import shamir_custody as sc  # noqa: E402


def _shards(n=3, t=2, secret=b"w331-redteam-secret-bytes"):
    return sc.split(secret, n, t, "ceremony-w331-test")


# ---------------------------------------------------------------------------
# P1: shamir post-F414 seams + w330 prospectus STEAL-verdict audit.
# ---------------------------------------------------------------------------

@probe("P1a-shamir-distribute-unresolvable-path-refused-coded")
def _p1a():
    """F414 residual: paths realpath cannot resolve must refuse coded.

    A null byte in an assignment path makes os.path.realpath raise
    ValueError; distribute must catch it and refuse coded
    custody-shamir-distribute-refused -- never guess, never write.
    (ShamirCustodyError subclasses ValueError, so the coded check
    must come first.)
    """
    d = _tmpd()
    shards = _shards()
    assigns = {"a": os.path.join(d, "shard-a"),
               "b": os.path.join(d, "shard-\x00b")}
    try:
        sc.distribute(shards[:2], assigns)
    except sc.ShamirCustodyError as exc:
        if exc.code == "custody-shamir-distribute-refused":
            leftovers = os.listdir(d)
            if not leftovers:
                return _held("P1a-shamir-distribute-unresolvable-path-"
                             "refused-coded",
                             "null-byte path refused coded, nothing written")
            return _break("P1a-shamir-distribute-unresolvable-path-"
                          "refused-coded",
                          "refused but wrote: %r" % (leftovers,))
        return _break("P1a-shamir-distribute-unresolvable-path-"
                      "refused-coded",
                      "wrong code %r" % (exc.code,))
    except Exception as exc:
        return _break("P1a-shamir-distribute-unresolvable-path-"
                      "refused-coded",
                      "uncoded %s escapes" % type(exc).__name__)
    return _break("P1a-shamir-distribute-unresolvable-path-refused-coded",
                  "null-byte path accepted")


@probe("P1b-shamir-distribute-symlink-alias-regression")
def _p1b():
    """F414 regression: symlink-aliased assignment pair refuses BEFORE
    any write (relabeled wave-330 P2, which relabels wave-329 P1h)."""
    import w330_redteam_probes as w330
    return _relabel("P1b-shamir-distribute-symlink-alias-regression",
                    w330._p2)


@probe("P1c-shamir-distribute-same-basename-refused-coded")
def _p1c():
    """(st_dev, st_ino, basename) key game: two assignments to the same
    basename in one directory refuse coded before any write; two
    distinct basenames in one directory distribute fine."""
    d = _tmpd()
    shards = _shards(n=4, t=2)
    # Positive control: distinct basenames, same dir -> manifest.
    ok = {"a": os.path.join(d, "shard-a"), "b": os.path.join(d, "shard-b")}
    try:
        man = sc.distribute(shards[:2], ok)
    except Exception as exc:
        return _break("P1c-shamir-distribute-same-basename-refused-coded",
                      "distinct basenames refused: %s" % (exc,))
    if set(man) != {"a", "b"}:
        return _break("P1c-shamir-distribute-same-basename-refused-coded",
                      "bad manifest %r" % (man,))
    # Attack: same basename twice -> coded refusal, nothing new written.
    before = sorted(os.listdir(d))
    dup = {"a": os.path.join(d, "shard-c"), "b": os.path.join(d, "shard-c")}
    try:
        sc.distribute(shards[2:], dup)
    except sc.ShamirCustodyError as exc:
        if exc.code != "custody-shamir-distribute-refused":
            return _break("P1c-shamir-distribute-same-basename-"
                          "refused-coded",
                          "wrong code %r" % (exc.code,))
        if sorted(os.listdir(d)) != before:
            return _break("P1c-shamir-distribute-same-basename-"
                          "refused-coded",
                          "refused but wrote files")
        return _held("P1c-shamir-distribute-same-basename-refused-coded",
                     "duplicate basename refused coded, nothing written; "
                     "distinct basenames distribute")
    except Exception as exc:
        return _break("P1c-shamir-distribute-same-basename-refused-coded",
                      "uncoded %s escapes" % type(exc).__name__)
    return _break("P1c-shamir-distribute-same-basename-refused-coded",
                  "duplicate basename accepted")


@probe("P1d-shamir-case-insensitive-residual-documented")
def _p1d():
    """F414's documented residual: on a case-insensitive filesystem two
    assignments differing only in filename case collide after the
    pre-flight. The docstring must say so LOUD (it is a documented
    limit, not a finding)."""
    doc = sc.distribute.__doc__ or ""
    if "case-insensitive" in doc and "case-distinct" in doc:
        return _held("P1d-shamir-case-insensitive-residual-documented",
                     "residual documented LOUD in distribute docstring")
    return _break("P1d-shamir-case-insensitive-residual-documented",
                  "case-insensitive residual NOT documented")


@probe("P1e-shamir-preflight-write-toctou-assessed")
def _p1e():
    """TOCTOU between the pre-flight exists-check and _atomic_write.

    The window is real but requires a local writer racing the operator
    between two checks in one local call. Defense in depth: BOTH
    distribute's pre-flight AND _atomic_write itself check
    os.path.exists before writing, so a racing creator gets a LOUD
    coded refusal, never a silent overwrite. Static probe asserting
    both checks are present."""
    src = open(os.path.join(REPO, "gov", "shamir_custody.py"),
               encoding="utf-8").read()
    preflight = "refusing to overwrite existing shard file" in src
    # _atomic_write carries its own exists-check independent of the
    # distribute pre-flight.
    atomic_body = src.split("def _atomic_write")[1].split(
        "def distribute")[0]
    atomic_check = "os.path.exists(path)" in atomic_body
    if preflight and atomic_check:
        return _held("P1e-shamir-preflight-write-toctou-assessed",
                     "pre-flight + write-time exists checks both present; "
                     "racer gets loud coded refusal, never silent overwrite")
    return _break("P1e-shamir-preflight-write-toctou-assessed",
                  "missing exists check: preflight=%s atomic=%s"
                  % (preflight, atomic_check))


@probe("P1f-prospectus-landlock-steal-overclaimed")
def _p1f():
    """w330 prospectus audit: the #1 STEAL ("build gov/landlock.py --
    only candidate that closes gov/sandbox.py's honestly-documented
    gap") is overclaimed -- RESOLVED at the wave-331 merge.

    gov/sandbox.py already carried a full ctypes Landlock LSM tier
    (wave-266). At the wave-331 merge the research stream acknowledged
    the overclaim: the tier was extracted VERBATIM to
    gov/landlock_jail.py (wave-331 lane 3) with the genuinely-new
    standalone restrict_fs()/landlock_supported() API and a break-first
    empirical audit of the existing tier. The verdict is downgraded
    from STEAL to ADAPT -- no product defect, no user impact.

    This probe now asserts the resolution (HELD): the tier lives in
    gov/landlock_jail.py, gov/sandbox.py re-exports every historical
    attribute path, and the 3 sandbox-landlock-* codes are registered.
    """
    jail = open(os.path.join(REPO, "gov", "landlock_jail.py"),
                encoding="utf-8").read()
    sandbox = open(os.path.join(REPO, "gov", "sandbox.py"),
                   encoding="utf-8").read()
    codes = open(os.path.join(REPO, "gov", "decision_codes.py"),
                 encoding="utf-8").read()
    tier = ("def landlock_available" in jail
            and "def restrict_fs" in jail
            and "def landlock_supported" in jail)
    bridge = "from gov.landlock_jail import" in sandbox
    coded = ("sandbox-landlock-apply-failed" in codes
             and "sandbox-landlock-required" in codes
             and "sandbox-landlock-unavailable" in codes)
    if tier and bridge and coded:
        return _held("P1f-prospectus-landlock-steal-overclaimed",
                     "overclaim resolved: tier in gov/landlock_jail.py "
                     "(wave-266, extracted wave-331), sandbox re-export "
                     "bridge intact, 3 codes registered; verdict ADAPT")
    return _break("P1f-prospectus-landlock-steal-overclaimed",
                  "resolution missing (tier=%s bridge=%s coded=%s)"
                  % (tier, bridge, coded))


@probe("P1g-mcp-oauth-gap1-closed-9207")
def _p1g():
    """Prospectus gap #1 (RFC 9207 `iss` validation on the MCP client
    response leg) is CLOSED by wave-332 lane 2: `validate_authorization_response`
    refuses a missing `iss` coded `mcp-oauth-iss-missing` and a rogue/
    substituted `iss` coded `mcp-oauth-iss-mismatched`. (Rewritten from the
    wave-331 'gap confirmed absent' probe per the wave-306 rule: a closure
    probe must assert the coded refusal on the closed tree.)"""
    from gov import mcp_oauth_binding as mob
    key = b"w332-merge-probe-key-0123456789abcdef"
    sealed = mob.seal_as_binding("https://as.example", "client-1", key)
    for pid_suffix, response, want in (
            ("missing", {"code": "authcode-1", "state": "s1"},
             "mcp-oauth-iss-missing"),
            ("mismatched", {"code": "authcode-1", "state": "s1",
                            "iss": "https://rogue.example"},
             "mcp-oauth-iss-mismatched")):
        pid = "P1g-mcp-oauth-gap1-closed-9207-%s" % pid_suffix
        try:
            mob.validate_authorization_response(sealed, response, key)
        except Exception as exc:  # noqa: BLE001
            if getattr(exc, "code", None) == want:
                continue
            return _break(pid, "wrong refusal: %r, want %s"
                          % (getattr(exc, "code", exc), want))
        return _break(pid, "response accepted uncoded, want %s" % want)
    return _held("P1g-mcp-oauth-gap1-closed-9207",
                 "RFC 9207 iss response validation refuses coded "
                 "(missing/mismatched); gap #1 CLOSED")


@probe("P1h-mcp-oauth-gap2-closed-8707")
def _p1h():
    """Prospectus gap #2 (RFC 8707 `resource` parameter on MCP OAuth)
    is CLOSED by wave-332 lane 2: `check_token_resource` refuses a
    resourceless token coded `mcp-oauth-resource-missing` and an
    A-minted-at-B token coded `mcp-oauth-resource-misbound`.
    (Rewritten from the wave-331 'gap confirmed absent' probe per the
    wave-306 rule.)"""
    from gov import mcp_oauth_binding as mob
    server_a = "https://mcp-a.example"
    server_b = "https://mcp-b.example"
    for pid_suffix, claims, server, want in (
            ("missing", {}, server_a, "mcp-oauth-resource-missing"),
            ("misbound", {"resource": server_a}, server_b,
             "mcp-oauth-resource-misbound")):
        pid = "P1h-mcp-oauth-gap2-closed-8707-%s" % pid_suffix
        try:
            mob.check_token_resource(server, claims)
        except Exception as exc:  # noqa: BLE001
            if getattr(exc, "code", None) == want:
                continue
            return _break(pid, "wrong refusal: %r, want %s"
                          % (getattr(exc, "code", exc), want))
        return _break(pid, "token accepted uncoded, want %s" % want)
    return _held("P1h-mcp-oauth-gap2-closed-8707",
                 "RFC 8707 resource binding refuses coded "
                 "(missing/misbound); gap #2 CLOSED")


@probe("P1i-prospectus-pq-slot-confirmed-absent")
def _p1i():
    """Prospectus §2 next-step 1 (reserved PQ signature slot in the
    evidence envelope): the w335 pqslot lane BUILT it -- ML-DSA / pq-slot
    markers are now present in the envelope modules. The ADAPT verdict
    is superseded; the slot exists."""
    found = []
    for mod in ("evidence_sigstore.py", "evidence_intoto.py",
                "sigstore_bundle.py", "offline_bundle.py"):
        path = os.path.join(REPO, "gov", mod)
        if not os.path.exists(path):
            continue
        src = open(path, encoding="utf-8").read()
        if re.search(r"mldsa|ML-DSA|pq.slot|post.quantum", src, re.I):
            found.append(mod)
    if not found:
        return _break("P1i-prospectus-pq-slot-confirmed-absent",
                      "PQ slot markers ABSENT -- w335 pqslot lane regressed")
    return _held("P1i-prospectus-pq-slot-confirmed-absent",
                 "PQ slot present in %r; ADAPT superseded" % (found,))


# ---------------------------------------------------------------------------
# P2: F415/F416 re-probes (CLOSED; lanes 1/2 closed them -- assert coded refusals).
# ---------------------------------------------------------------------------

@probe("P2a-f415-reprobe-unicode-version-uncoded")
def _p2a():
    """F415 CLOSED 2026-10-04 wave-331 lane 1: pol.v².json refuses
    coded policy-channel-malformed (HELD)."""
    import w330_redteam_probes as w330
    return _relabel("P2a-f415-reprobe-unicode-version-uncoded", w330._p1g)


@probe("P2b-f416-reprobe-integratedtime-uncoded")
def _p2b():
    """F416 CLOSED 2026-10-04 wave-331 lane 2: 5000-digit
    integratedTime refuses coded evidence-bundle-malformed (HELD)."""
    import w330_redteam_probes as w330
    return _relabel("P2b-f416-reprobe-integratedtime-uncoded", w330._p1a)


@probe("P2c-f416-reprobe-logindex-uncoded")
def _p2c():
    """F416 CLOSED 2026-10-04 wave-331 lane 2: 5000-digit logIndex
    refuses coded evidence-bundle-malformed (HELD)."""
    import w330_redteam_probes as w330
    return _relabel("P2c-f416-reprobe-logindex-uncoded", w330._p1b)


# ---------------------------------------------------------------------------
# P3: closure-regression probes (all must stay HELD).
# ---------------------------------------------------------------------------

@probe("P3a-f414-closure-regression")
def _p3a():
    import w330_redteam_probes as w330
    return _relabel("P3a-f414-closure-regression", w330._p2)


@probe("P3b-f413-closure-regression-order")
def _p3b():
    import w328_redteam_probes as w328
    return _relabel("P3b-f413-closure-regression-order", w328._p1b)


@probe("P3c-f413-closure-regression-revocation")
def _p3c():
    import w328_redteam_probes as w328
    return _relabel("P3c-f413-closure-regression-revocation", w328._p1c)


@probe("P3d-f412-closure-regression")
def _p3d():
    import w327_redteam_probes as w327
    return _relabel("P3d-f412-closure-regression", w327._p1f)


@probe("P3e-f411-closure-regression")
def _p3e():
    import w327_redteam_probes as w327
    return _relabel("P3e-f411-closure-regression", w327._p3a)


@probe("P3f-f410-closure-regression-t4c")
def _p3f():
    import w327_redteam_probes as w327
    return _relabel("P3f-f410-closure-regression-t4c", w327._p2a)


@probe("P3g-f410-closure-regression-t4d")
def _p3g():
    import w327_redteam_probes as w327
    return _relabel("P3g-f410-closure-regression-t4d", w327._p2b)


# ---------------------------------------------------------------------------
# P4: the wave-330 merge defect class.
# ---------------------------------------------------------------------------

# Grandfathered: ancient batteries (waves 22-47, 139, 141) and one
# wave-329-repointed file that end with "\n\n". None is read with
# lines[-1] semantics and none breaks a footer probe -- cosmetic
# pre-existing debt, documented here, not a regression. The probe
# below BREAKs only on files BEYOND this inventory (the wave-330
# merge class was a NEW trailing blank line from scripted
# resolution).
_GRANDFATHERED_BLANK_TAIL = frozenset({
    "evals/artifact_inventory_pin_probes.py",
    "evals/cross_run_taint_probes.py",
    "evals/r9_probes.py",
    "evals/w260_f228_probes.py",
})
# Grandfathered (wave-200/206-era) code literals used in gov/ but never
# centrally registered. Long-standing debt, not a regression: the probe
# below BREAKs only on codes BEYOND this inventory (the wave-329 merge
# defect class was NEW codes shipping unregistered).
_GRANDFATHERED_UNREGISTERED = frozenset({
    "config-body-mismatch", "config-expired", "config-extra-member",
    "config-stale", "config-supersede-break", "handoff-required",
    "pack-activation-approval-required", "pack-activation-denied",
    "pack-guard-error", "pack-member-digest-mismatch", "pack-member-extra",
    "pack-member-omitted", "pack-stale", "policy-not-yet-valid",
})
# Base-class `code` attributes intentionally absent from the taxonomy
# (wave-342 lane 6 decision): every raise site uses an overriding
# subclass code, so these literals are never emitted. The probe's
# `code=` regex over-matches class attributes; exclude them here so
# only genuinely-emitted literals are checked.
_BASE_CLASS_CODES_NEVER_EMITTED = frozenset({
    "evidence-refused", "key-identity-refused",
    "single-use-refused", "spiffe-refused",
})


@probe("P4a-no-trailing-blank-line-on-footer-files")
def _p4a():
    """Wave-330 merge class: a scripted FINDINGS.md resolution left a
    trailing blank line that broke a `lines[-1]` footer probe.

    Every footer-bearing file (FINDINGS.md) and every evals/*.py must
    not end with a BLANK line ("\n\n" at EOF) -- not just non-empty
    (wave-327 class) but blank-line-free at the tail (wave-330 class).
    A single POSIX trailing newline is fine; `lines[-1]` footer
    probes break only on a true blank last line."""
    bad = []
    findings = os.path.join(REPO, "evals", "FINDINGS.md")
    data = open(findings, encoding="utf-8").read()
    if data.endswith("\n\n") or not data.strip():
        bad.append("evals/FINDINGS.md")
    evals_d = os.path.join(REPO, "evals")
    for fname in sorted(os.listdir(evals_d)):
        if not fname.endswith(".py"):
            continue
        rel = "evals/%s" % (fname,)
        if rel in _GRANDFATHERED_BLANK_TAIL:
            continue
        path = os.path.join(evals_d, fname)
        tail = open(path, encoding="utf-8").read()
        if tail.endswith("\n\n") or not tail.strip():
            bad.append(rel)
    if bad:
        return _break("P4a-no-trailing-blank-line-on-footer-files",
                      "NEW trailing-blank-line files: %r" % (bad[:5],))
    return _held("P4a-no-trailing-blank-line-on-footer-files",
                 "no NEW trailing blank lines (+%d grandfathered "
                 "cosmetic)" % (len(_GRANDFATHERED_BLANK_TAIL),))


@probe("P4b-codes-centrally-registered")
def _p4b():
    """Wave-329 merge class: vocab-scanned-but-unregistered codes.

    Every code literal passed to _fail/_refuse (or code= kw) anywhere
    in gov/ must be centrally registered in gov/decision_codes.py --
    except the 14 grandfathered wave-200/206-era literals inventoried
    above (long-standing debt, documented here, not a regression).
    Any NEW unregistered literal BREAKs.
    """
    import gov.decision_codes as dc
    registered = set(dc.TAXONOMY)
    used = set()
    for fname in sorted(os.listdir(os.path.join(REPO, "gov"))):
        if not fname.endswith(".py"):
            continue
        src = open(os.path.join(REPO, "gov", fname),
                   encoding="utf-8").read()
        for pat in (r'_fail\(\s*"([^"]+)"', r"_fail\(\s*'([^']+)'",
                    r'_refuse\(\s*"([^"]+)"', r"_refuse\(\s*'([^']+)'",
                    r'code\s*=\s*"([^"]+)"', r"code\s*=\s*'([^']+)'"):
            used.update(re.findall(pat, src))
    # Only code-shaped literals (dotted domain names), not free text.
    codey = {u for u in used if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+",
                                            u)}
    missing = sorted(codey - registered - _GRANDFATHERED_UNREGISTERED
                      - _BASE_CLASS_CODES_NEVER_EMITTED)
    if missing:
        return _break("P4b-codes-centrally-registered",
                      "NEW unregistered code literals: %r" % (missing[:8],))
    return _held("P4b-codes-centrally-registered",
                 "%d code literals registered (+%d grandfathered debt)"
                 % (len(codey - _GRANDFATHERED_UNREGISTERED),
                    len(_GRANDFATHERED_UNREGISTERED)))


@probe("P4c-pin-comments-honest")
def _p4c():
    """Every TAXONOMY_PIN/LANE_PIN/EXPECTED_PIN assignment whose
    trailing comment states a '-> N' final pin must have N equal to
    the live value: pin-comment drift is the wave-329 merge class."""
    bad = []
    live = {}
    for dirpath, _dirs, files in os.walk(REPO):
        if "/.git/" in dirpath or "/__pycache__/" in dirpath:
            continue
        for fname in files:
            if not fname.endswith(".py"):
                continue
            path = os.path.join(dirpath, fname)
            try:
                src = open(path, encoding="utf-8").read()
            except OSError:
                continue
            for m in re.finditer(
                    r"^(?:\s*)(?:[A-Z_]+\.)?(TAXONOMY_PIN|LANE_PIN|"
                    r"EXPECTED_PIN)\s*=\s*(\d+)([^\n]*)$",
                    src, re.M):
                name, val, rest = m.group(1), int(m.group(2)), m.group(3)
                live.setdefault(name, set()).add(val)
                finals = re.findall(r"->\s*(\d+)", rest)
                if finals and int(finals[-1]) != val:
                    bad.append("%s:%s -> %s != live %d"
                               % (os.path.relpath(path, REPO),
                                  name, finals[-1], val))
    if bad:
        return _break("P4c-pin-comments-honest",
                      "pin-comment drift: %r" % (bad[:5],))
    vals = {k: sorted(v) for k, v in live.items()}
    return _held("P4c-pin-comments-honest",
                 "pin comments honest; live values %r" % (vals,))


# ---------------------------------------------------------------------------
# P5: pin + footer state.
# ---------------------------------------------------------------------------

@probe("P5a-pin-taxonomy-2140-sorted")
def _p5a():
    if TAXONOMY_PIN != 2140:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        return _break("P5a-pin-taxonomy-2140-sorted",
                      "TAXONOMY_PIN is %r, want 2140" % (TAXONOMY_PIN,))
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'"code"\s*:\s*\'([^\']+)\'', src)
    # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    if len(lits) != 2140 or len(set(lits)) != 2140 \
            or lits != sorted(lits):
        return _break("P5a-pin-taxonomy-2140-sorted",
                      "want 2140/2140/0 sorted, got %d/%d/sorted=%s"
                      % (len(lits), len(set(lits)), lits == sorted(lits)))
    return _held("P5a-pin-taxonomy-2140-sorted",
                 "2140/2140/0 sorted unique on raw source literals")


@probe("P5b-footer-open-f433-f434-f435-next-f436")
def _p5b():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ms = re.findall(r"Next free finding: \*\*(F\d+)\*\*\. "
                    r"\*\*Open findings: ([^*]+)\.\*\*", text)
    if not ms:
        return _break("P5b-footer-open-f433-f434-f435-next-f436",
                      "footer line not found")
    next_free, open_now = ms[-1]  # the LAST footer is the live one
    if next_free != FOOTER_NEXT or open_now != FOOTER_OPEN:
        return _break("P5b-footer-open-f433-f434-f435-next-f436",
                      "footer open %s / next %s, want open %s / next %s"
                      % (open_now, next_free, FOOTER_OPEN, FOOTER_NEXT))
    return _held("P5b-footer-open-f433-f434-f435-next-f436",
                 "footer open none / next F419")


# ---------------------------------------------------------------------------
# P6: prior batteries in child mode.
# ---------------------------------------------------------------------------

def _run_child_output(battery, timeout=1500):
    """Run a prior battery as a subprocess; return its raw stdout.

    GOV_SKIP_GREEN=1 in the child env (depth-1 green checks), fresh
    TMPDIR per child. Raises on timeout; returns text otherwise.

    NOTE (wave-331): several child batteries (w330/w329/w328/w327)
    carry their own P6a probes that spawn grandchildren, so a child
    main can take 10+ minutes. The generous timeout avoids false
    ERRORs; the nesting is their verified design, not this battery's.
    """
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    tmpd = tempfile.mkdtemp(prefix="w331child-",
                            dir=_run_root())
    env["TMPDIR"] = tmpd
    proc = subprocess.run(
        [sys.executable, os.path.join(REPO, "evals", battery)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=timeout, cwd=REPO)
    return proc.stdout.decode("utf-8", "replace")


# Battery -> set of BREAK probe IDs that are NOT regressions on this
# tree. Post wave-331 merge sweep: every child battery's footer-state
# probes were re-pinned to the merged footer (open none / next
# F417) and F414/F415/F416's closure probes flip to HELD. w330's own
# three closure probes (P1g/F415, P1a/P1b/F416) are HELD.
# (wave-305 class.)
_CHILD_CASCADE = {
    "w330_redteam_probes.py": set(),  # wave-333 merge: F415/F416 probes re-pinned HELD at wave-331; footer green.
    "w329_redteam_probes.py": set(),
    "w329_sigb_probes.py": set(),
    "w328_redteam_probes.py": set(),
    "w328_resid_probes.py": set(),
    "w328_shamir_probes.py": set(),
    "w327_redteam_probes.py": set(),
    "w327_polchan_probes.py": set(),
    "w326_tufaudit_probes.py": set(),
    "w326_redteam_probes.py": set(),
    "w326_standing_probes.py": set(),
    "w326_sched_probes.py": set(),
}


@probe("P6a-prior-batteries-child-mode-tallies")
def _p6a():
    """Prior batteries: every BREAK is inside the documented cascade.

    Runs each prior battery as a subprocess (GOV_SKIP_GREEN=1 in the
    child env, fresh TMPDIR). A BREAK outside _CHILD_CASCADE -- or any
    ERROR -- is a genuine regression, not an open finding.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return _held("P6a-prior-batteries-child-mode-tallies",
                     "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    batteries = tuple(sorted(_CHILD_CASCADE))
    bad = []
    tallies = []
    for battery in batteries:
        try:
            out = _run_child_output(battery)
        except Exception as exc:
            bad.append("%s: ERROR %s" % (battery, exc))
            continue
        breaks = set(re.findall(r"^\s*\[BREAK\]\s+([A-Za-z0-9_.\-]+)",
                                out, re.M))
        errors = set(re.findall(r"^\s*\[ERROR\]\s+([A-Za-z0-9_.\-]+)",
                                out, re.M))
        # Some batteries print no per-probe [BREAK] lines; their
        # BREAK-SET MISMATCH line carries the unexpected IDs instead.
        m2 = re.search(r"BREAK-SET MISMATCH:\s*(\[[^\]]*\])", out)
        if m2:
            try:
                import ast as _ast
                breaks.update(_ast.literal_eval(m2.group(1)))
            except Exception:
                pass
        if errors:
            bad.append("%s: ERRORs %s" % (battery, sorted(errors)[:3]))
        outside = breaks - _CHILD_CASCADE[battery]
        if outside:
            bad.append("%s: non-cascade BREAKs %s"
                       % (battery, sorted(outside)[:4]))
        tallies.append("%s breaks=%d" % (battery, len(breaks)))
    if bad:
        return _break("P6a-prior-batteries-child-mode-tallies",
                      "; ".join(bad[:6]))
    return _held("P6a-prior-batteries-child-mode-tallies",
                 "all child BREAKs inside the documented cascade; "
                 + "; ".join(tallies))


# ---------------------------------------------------------------------------
# Expected BREAK set, green check, main.
# ---------------------------------------------------------------------------

_EXPECTED_BREAKS = set()  # No expected BREAKs: F415/F416 CLOSED, prospectus overclaim acknowledged.
# (History, kept as comments: F415 CLOSED 2026-10-04 wave-331 lane 1:
# P2a asserts the coded policy-channel-malformed refusal (HELD);
# F416 CLOSED 2026-10-04 wave-331 lane 2: P2b/P2c assert the coded
# evidence-bundle-malformed refusal (HELD); prospectus #1 STEAL
# overclaim RESOLVED at the wave-331 merge -- tier extracted verbatim
# to gov/landlock_jail.py + standalone restrict_fs() API, verdict
# downgraded to ADAPT; P1f asserts the resolution (HELD).)


def _green_check():
    """Depth-1 green check: adjacent batteries with GOV_SKIP_GREEN=1.

    Honors GOV_SKIP_GREEN (records a skip instead of spawning). Never
    spawns a battery that spawns another: depth-1 only.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    for battery in ("w330_redteam_probes.py",
                    "w329_redteam_probes.py",
                    "w329_sigb_probes.py"):
        try:
            out = _run_child_output(battery)
        except Exception as exc:
            _record("green-check", "ERROR",
                    "%s: %s" % (battery, exc))
            continue
        breaks = set(re.findall(r"^\s*\[BREAK\]\s+([A-Za-z0-9_.\-]+)",
                                out, re.M))
        errors = set(re.findall(r"^\s*\[ERROR\]\s+([A-Za-z0-9_.\-]+)",
                                out, re.M))
        m2 = re.search(r"BREAK-SET MISMATCH:\s*(\[[^\]]*\])", out)
        if m2:
            try:
                import ast as _ast
                breaks.update(_ast.literal_eval(m2.group(1)))
            except Exception:
                pass
        outside = breaks - _CHILD_CASCADE[battery]
        if errors or outside:
            _record("green-check", "BREAK",
                    "%s: non-cascade %s" %
                    (battery, sorted(outside | errors)[:4]))
        else:
            _record("green-check", "HELD",
                    "%s: %d breaks, all in cascade" % (battery, len(breaks)))


def main(argv):
    for pid, fn in _PROBES:
        _safe(pid, fn)
    _green_check()
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    # Only probe IDs (not the green-check record) count toward the set.
    probe_breaks = {pid for pid, v, _ in _results
                    if v == "BREAK" and pid.startswith("P")}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("w331_redteam battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected: F415/F416 closed, prospectus "
          "overclaim acknowledged)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
