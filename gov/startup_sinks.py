"""Session-startup sink discipline: closed-list review sinks and
pre-trust config stripping.

Design input (ADAPT, threat-model only, no upstream code): the wave-244
prospectus GitSpawn update. Two session-startup trust paths remain open
in the wild:

* ``core.hooksPath``-class hook enumeration -- a repo-local config key
  that redirects hook resolution to an attacker-controlled directory.
  ``gov.git_sanitize`` already deny-lists the key; this module pins the
  pre-trust behavior: on an UNTRUSTED workspace the refusal is the trust
  code (trust consulted first), and provides
  :func:`strip_unknown_config_keys` for sessions that must sanitize a
  config before any subprocess runs.
* The ``ultrareview`` sink -- a session-startup review sink whose exact
  trigger name researchers withheld. A denylist cannot name what it
  cannot see, so sink resolution is a CLOSED ALLOWLIST: any sink name
  not explicitly registered refuses pre-trust. A renamed sink
  (``ultra-review``, ``ultrareviews``, ``u1trarev1ew``) can never evade,
  because evasion-by-rename only defeats denylists.

Stdlib only. No network, no subprocesses, no in-repo git invocations.
Refusals reuse the wave-244 vocabulary: ``repo-hook-pretrust-refused``
for anything unregistered pre-trust, ``session-trust-malformed`` for
malformed input. No new taxonomy codes.

Honest boundaries:

* This module proves a sink was REGISTERED by a named principal, not
  that the principal registered wisely -- a malicious insider with
  ``register_sink`` access is out of scope (same boundary as
  ``gov.session_trust``).
* ``strip_unknown_config_keys`` is syntactic: it strips unknown keys
  from the text form; it does not prove the surviving keys are safe.
  Exec-sink keys must remain deny-listed by ``gov.git_sanitize``.
* The registry is in-memory unless the deployment persists it.
"""

import re

from gov import session_trust as _st

# ---------------------------------------------------------------------------
# Closed-list sink registry
# ---------------------------------------------------------------------------

_SINK_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")

UNREGISTERED = "repo-hook-pretrust-refused"


class StartupSinkRegistry(object):
    """Closed-list registry of session-startup sinks.

    Session-startup sinks are named channels an agent may invoke while
    orienting a session (review hooks, summarize tools). Only names on
    the list resolve; everything else -- including renames of known
    sinks -- refuses :data:`UNREGISTERED` pre-trust. There is no
    default-allow, no fuzzy matching, and no case folding: exact
    registration is the only pass.
    """

    def __init__(self):
        self._sinks = {}

    def register_sink(self, name, *, declared_by):
        """Register a sink name. ``declared_by`` must name a principal;
        malformed names or unnamed principals fail closed."""
        if not isinstance(name, str) or not _SINK_NAME_RE.match(name):
            _st.raise_refusal(
                _st.MALFORMED,
                "sink name must match [a-z0-9][a-z0-9_-]{1,63}")
        if not isinstance(declared_by, str) or not declared_by.strip():
            _st.raise_refusal(
                _st.MALFORMED, "declared_by must name a principal")
        self._sinks[name] = {"declared_by": declared_by.strip()}
        return name

    def resolve(self, name):
        """Resolve a sink name to its registration, or refuse pre-trust."""
        if not isinstance(name, str) or name not in self._sinks:
            _st.raise_refusal(
                UNREGISTERED,
                "session-startup sink %r is not on the closed list; "
                "renamed or unknown sinks never fall through to allow"
                % (name,))
        return {"name": name, "declared_by": self._sinks[name][
            "declared_by"]}

    def registered_names(self):
        return sorted(self._sinks)


# ---------------------------------------------------------------------------
# Pre-trust config stripping
# ---------------------------------------------------------------------------


def _section_of(line):
    """Parse a ``[section]`` / ``[section "subsection"]`` header."""
    text = line.strip()
    if not (text.startswith("[") and text.endswith("]")):
        return None
    inner = text[1:-1].strip()
    if not inner:
        return None
    head = inner.split(None, 1)[0].strip('"').lower()
    return head if re.match(r"^[a-z0-9_.-]+$", head) else None


def _config_key(line, section):
    """Extract the dotted config key from a ``key = value`` line, or
    None. ``section`` (from :func:`_section_of`) qualifies the key:
    ``bare`` under ``[core]`` is ``core.bare``."""
    text = line.strip()
    if not text or text.startswith(("#", ";")) or text.startswith("["):
        return None
    if "=" not in text:
        return None
    key = text.split("=", 1)[0].strip().lower()
    if not key or not re.match(r"^[a-z0-9_.-]+$", key):
        return None
    if section:
        key = "%s.%s" % (section, key)
    return key


def strip_unknown_config_keys(config_text, known_keys):
    """Strip every config line whose key is not in ``known_keys``.

    Returns ``{"kept": [...], "stripped": [...]}``. Lines that parse to
    no key (comments, section headers, blank lines) are kept -- they
    carry no executable surface. A session that strips unknown keys and
    a session that preserves them are observably different: the
    ``w245_gitspawn_open_path`` battery falsifies silent preservation.

    ``known_keys`` is an iterable of dotted lowercase keys; anything not
    listed -- including exec-sink keys such as ``core.hookspath`` -- is
    stripped. Malformed input (non-string config, non-iterable keys)
    refuses ``session-trust-malformed``.
    """
    if not isinstance(config_text, str):
        _st.raise_refusal(
            _st.MALFORMED, "config text must be a string")
    try:
        known = frozenset(k.lower() for k in known_keys)
    except TypeError:
        _st.raise_refusal(
            _st.MALFORMED, "known_keys must be an iterable of strings")
    kept = []
    stripped = []
    section = None
    for line in config_text.splitlines():
        new_section = _section_of(line)
        if new_section is not None:
            section = new_section
        key = _config_key(line, section)
        if key is None or key in known:
            kept.append(line)
        else:
            stripped.append(line)
    return {"kept": kept, "stripped": stripped}
