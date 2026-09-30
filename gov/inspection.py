"""Inspection-result consumption: verifier attribution, halt on
nonzero exit, evidence-before-link ordering.

Design input (ADAPT, not vendored): in-toto's inspection concept --
a verifier-side command whose results become link metadata. in-toto
runs inspections as bare ``exec.Command`` with verifier privileges
and no sandbox; inspection links are structurally
verifier-attributed (empty signatures). We do NOT copy that trust
model (negative lesson -- wave-219 prospecting). What we steal:

* **Explicit verifier-attribution**: every admitted inspection link
  structurally carries the inspection script's digest and the
  verifier's id. An unattributed link cannot verify.
* **Halt-on-nonzero**: a nonzero inspection exit halts admission
  with a named code (``inspection-failed``). The failed attempt is
  recorded on the evidence log first -- halt, not silent drop.
* **Post-evidence ordering**: evidence is emitted BEFORE the link is
  admitted. The link carries ``evidence_seq`` pointing at the log
  record; a link whose sequence resolves to no record (forged or
  reordered) is unverifiable.

This module consumes inspection RESULTS -- the caller runs the
inspection (under whatever confinement the deployment provides) and
reports ``(script_bytes, pinned_script_digest, exit_code, outputs)``.
It does not execute subprocesses and makes no sandbox claims.

Fail-closed seams:

* ``InspectionLog(verifier_id)`` -- the log; ``verifier_id`` is the
  deployment's name for this verifier (non-empty string).
* ``admit(name, script_bytes, pinned_script_digest, exit_code,
  outputs)`` -- refuses ``inspection-script-digest-mismatch`` when
  ``sha256(script_bytes) != pinned_script_digest`` (tampered script,
  refused before any evidence is recorded); records the evidence
  record; raises ``InspectionError("inspection-failed")`` on nonzero
  exit (the failure IS the evidence); returns the admitted link on
  exit 0.
* ``verify()`` -- the whole log verifies: sequences dense from 1,
  digest shapes well-formed, evidence records internally
  consistent. Raises ``InspectionError`` otherwise.
* ``verify_link(link)`` -- a link verifies only when its
  ``evidence_seq`` resolves to a log record whose name, script
  digest, outputs digest, verifier id, and zero exit all match the
  link, and the link claims verifier attribution. Raises
  ``InspectionError("inspection-link-unverifiable")`` otherwise.
  A hand-made link (never admitted) has no evidence and cannot
  verify.

Honest boundaries (stated, not absorbed):

* The harness consumes caller-REPORTED exit codes and outputs; it
  cannot observe the inspection's execution. A caller that lies
  ``exit_code=0`` defeats the halt -- the halt protects honest
  reporters and loud pipelines, not lying callers.
* ``pinned_script_digest`` custody is the deployment's job (same
  discipline as out-of-band key pinning elsewhere in this repo).
* Evidence ordering is enforced structurally at admission: the
  evidence record appended in step 2 IS the emitted ordered artifact
  (read it back via ``records()``); a deployment that persists the
  log must preserve sequence order or ``verify()`` fails closed.
  Durability across restarts is the deployment's job -- the same
  discipline as the wave-219 seen-version registry.

$0 spend, synthetic/local deterministic only. No network. Stdlib only.
"""

import hashlib

__all__ = [
    "InspectionError",
    "InspectionLog",
]

#: Machine-readable codes from this module.
CODE_FAILED = "inspection-failed"
CODE_DIGEST_MISMATCH = "inspection-script-digest-mismatch"
CODE_MALFORMED = "inspection-malformed"
CODE_LINK_UNVERIFIABLE = "inspection-link-unverifiable"

_HEX = set("0123456789abcdef")


class InspectionError(Exception):
    """Fail-closed inspection-consumption violation. ``code`` is the
    machine-readable failure mode."""

    def __init__(self, code, detail=""):
        super(InspectionError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _check_digest(value, where):
    if not isinstance(value, str) or len(value) != 64 \
            or any(c not in _HEX for c in value):
        raise InspectionError(
            CODE_MALFORMED, "%s must be a sha256 hex string" % (where,))
    return value


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _strict_int(value):
    """True for a genuine int, False for bools and non-ints. exit_code
    semantics need this: ``True`` is not exit code 1."""
    return isinstance(value, int) and not isinstance(value, bool)


class InspectionLog:
    """The verifier's evidence log for inspection results.

    ``verifier_id`` names this verifier (deployment-owned, non-empty
    string). Admission is ordered: every admitted (or halted) result
    appends exactly one evidence record with the next sequence number,
    and every link points back at its record.
    """

    def __init__(self, verifier_id):
        if not isinstance(verifier_id, str) or not verifier_id:
            raise InspectionError(
                CODE_MALFORMED,
                "verifier_id must be a non-empty string")
        self._verifier_id = verifier_id
        self._records = []  # evidence records, seq starts at 1

    @property
    def verifier_id(self):
        return self._verifier_id

    def _next_seq(self):
        return len(self._records) + 1

    def admit(self, name, script_bytes, pinned_script_digest, exit_code,
              outputs):
        """Consume one inspection result.

        ``name`` is the inspection step name (non-empty string);
        ``script_bytes`` the bytes of the script that ran;
        ``pinned_script_digest`` the deployment-pinned sha256 of those
        bytes; ``exit_code`` the reported process exit code (int);
        ``outputs`` the reported stdout/stderr bytes.

        Order of operations (the ordering IS the guarantee):

        1. The script digest is checked against the pin FIRST. A
           tampered script raises
           ``inspection-script-digest-mismatch`` and records
           nothing -- a forgery is not evidence.
        2. The evidence record is appended (seq, name, script digest,
           exit code, outputs digest, verifier id).
        3. A nonzero exit raises ``InspectionError("inspection-failed")``
           -- the failed attempt stays on the log, but no link is
           admitted. Never silently continues.
        4. On exit 0, the admitted link is returned: it carries
           ``verifier_attributed: True``, the script digest, the
           verifier id, the outputs digest, and ``evidence_seq``
           pointing at step 2's record.
        """
        if not isinstance(name, str) or not name:
            raise InspectionError(
                CODE_MALFORMED, "name must be a non-empty string")
        if not isinstance(script_bytes, (bytes, bytearray)):
            raise InspectionError(
                CODE_MALFORMED, "script_bytes must be bytes")
        _check_digest(pinned_script_digest, "pinned_script_digest")
        if _sha(bytes(script_bytes)) != pinned_script_digest:
            raise InspectionError(
                CODE_DIGEST_MISMATCH,
                "inspection %r: script bytes do not match the pinned "
                "digest (refusing a possibly tampered script)" % (name,))
        if not _strict_int(exit_code):
            raise InspectionError(
                CODE_MALFORMED, "exit_code must be an int")
        if not isinstance(outputs, (bytes, bytearray)):
            raise InspectionError(
                CODE_MALFORMED, "outputs must be bytes")
        outputs_digest = _sha(bytes(outputs))
        seq = self._next_seq()
        record = {
            "evidence_seq": seq,
            "name": name,
            "script_digest": pinned_script_digest,
            "exit_code": exit_code,
            "outputs_digest": outputs_digest,
            "verifier_id": self._verifier_id,
        }
        self._records.append(record)
        if exit_code != 0:
            raise InspectionError(
                CODE_FAILED,
                "inspection %r exited %d: admission halted "
                "(failure recorded as evidence seq %d)"
                % (name, exit_code, seq))
        return {
            "name": name,
            "script_digest": pinned_script_digest,
            "verifier_id": self._verifier_id,
            "verifier_attributed": True,
            "evidence_seq": seq,
            "outputs_digest": outputs_digest,
        }

    def records(self):
        """The evidence records in admission order (copies)."""
        return [dict(r) for r in self._records]

    def verify(self):
        """Verify the whole log: sequences dense from 1, digest
        shapes well-formed, every record self-consistent. Returns
        True; raises InspectionError on any inconsistency."""
        for i, record in enumerate(self._records):
            want = i + 1
            if record.get("evidence_seq") != want:
                raise InspectionError(
                    CODE_MALFORMED,
                    "evidence sequence broken at position %d "
                    "(reordered or gapped log)" % (want,))
            _check_digest(record.get("script_digest", ""),
                          "record[%d].script_digest" % want)
            _check_digest(record.get("outputs_digest", ""),
                          "record[%d].outputs_digest" % want)
            if record.get("verifier_id") != self._verifier_id:
                raise InspectionError(
                    CODE_MALFORMED,
                    "record[%d] carries a foreign verifier id" % (want,))
            if not _strict_int(record.get("exit_code")):
                raise InspectionError(
                    CODE_MALFORMED,
                    "record[%d].exit_code malformed" % (want,))
        return True

    def verify_link(self, link):
        """Verify an admitted link against this log. The link verifies
        only when its ``evidence_seq`` resolves to a record whose
        name, script digest, outputs digest, and verifier id all match
        the link, the record's exit code is 0, and the link claims
        verifier attribution. Returns True; raises
        ``InspectionError("inspection-link-unverifiable")``
        otherwise."""
        if not isinstance(link, dict):
            raise InspectionError(
                CODE_LINK_UNVERIFIABLE, "link is not a dict")
        if link.get("verifier_attributed") is not True:
            raise InspectionError(
                CODE_LINK_UNVERIFIABLE,
                "link is not verifier-attributed")
        if link.get("verifier_id") != self._verifier_id:
            raise InspectionError(
                CODE_LINK_UNVERIFIABLE,
                "link carries a foreign verifier id")
        seq = link.get("evidence_seq")
        if not isinstance(seq, int) or isinstance(seq, bool) \
                or not 1 <= seq <= len(self._records):
            raise InspectionError(
                CODE_LINK_UNVERIFIABLE,
                "evidence_seq %r resolves to no evidence on this log"
                % (seq,))
        record = self._records[seq - 1]
        for field in ("name", "script_digest", "outputs_digest"):
            if link.get(field) != record.get(field):
                raise InspectionError(
                    CODE_LINK_UNVERIFIABLE,
                    "link %s does not match evidence seq %d"
                    % (field, seq))
        if record.get("exit_code") != 0:
            raise InspectionError(
                CODE_LINK_UNVERIFIABLE,
                "evidence seq %d records a failed inspection" % (seq,))
        return True
