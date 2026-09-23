"""In-memory key zeroization primitives (wave-71).

Brutally honest scope (see
``research/zeroization-design-wave71-2026-09-22.md`` for the measured
wipe inventory):

* These primitives wipe **Python-reachable, caller-owned, mutable**
  key buffers: ``bytearray`` (or a writable ``memoryview`` over one).
  After :func:`zeroize` / :func:`key_buffer` / ``KeyMaterial.destroy()``
  no live Python object graph still yields the key — proven by the
  copy-census test (``tests/test_w71_zeroization.py``).
* They do **NOT** defeat raw-memory readers (core dump,
  ``/proc/<pid>/mem``, memory-scraping malware): CPython allocator
  freelists and C-extension buffers (e.g. the ``hmac`` module's
  internal copy) are outside Python's reach and are never scrubbed.
  A self-scan suggested heap residue but could not reproduce it —
  the scanner contaminates its own reads — so this is stated as an
  architectural residual, not a measured count (see the design doc's
  E2 caveat). The real fix for that threat model is
  deployment-owned: HSM/offload signing or a C-extension
  locked-memory backend (the ``gov/kms.py`` envelope seam exists for
  exactly this migration).
* They do **NOT** wipe long-lived process keys while in use: env/file
  backends must hold the key for the process's appending lifetime,
  and ``os.environ`` values are immutable ``str`` anyway.
* Zeroing overwrites content, not length: a wiped 32-byte region still
  advertises "a key lived here".

The fail-loud rule: :func:`zeroize` **refuses** immutable inputs
(``bytes``/``str``) with :exc:`TypeError`. "Wiping" an immutable is
impossible — silently accepting it would be theater. Use
:func:`key_buffer` to get a wipable copy, or hold keys as
``bytearray`` (``KeyMaterial`` does since wave-71).

$0 spend, synthetic/local only. No credentials, no network.
"""

from contextlib import contextmanager


def zeroize(buf):
    """Overwrite a mutable key buffer with zeros, in place.

    Accepts ``bytearray`` or a *writable* ``memoryview``. Idempotent:
    wiping twice is safe (second wipe is a no-op over zeros).

    Raises :exc:`TypeError` for ``bytes``/``str`` (immutable — cannot
    be wiped; refusing loud beats pretending) and for read-only
    memoryviews. Raises :exc:`TypeError` for anything else: only real
    mutable buffers are accepted, never almost-buffers.
    """
    if isinstance(buf, bytes) or isinstance(buf, str):
        raise TypeError(
            "cannot zeroize %s: immutable — wiping it is impossible, "
            "and silently 'wiping' it would be theater. Hold the key "
            "as bytearray (see key_buffer) or wipe the mutable buffer "
            "it was copied from." % type(buf).__name__)
    if isinstance(buf, memoryview):
        if buf.readonly:
            raise TypeError(
                "cannot zeroize a read-only memoryview: the underlying "
                "buffer is not writable")
        # memoryview slice-assign of zeros works on writable views.
        buf[:] = b"\x00" * len(buf)
        return buf
    if isinstance(buf, bytearray):
        buf[:] = b"\x00" * len(buf)
        return buf
    raise TypeError(
        "cannot zeroize %s: not a mutable key buffer (need bytearray "
        "or writable memoryview)" % type(buf).__name__)


@contextmanager
def key_buffer(key):
    """Yield a wipable ``bytearray`` copy of ``key``; wipe it on exit.

    The copy is zeroized in a ``finally`` — an exception raised by the
    consumer between use and wipe cannot skip the wipe. The buffer
    never escapes the ``with`` block by design: after exit it holds
    zeros, and retaining it past the block is a caller bug (the
    zeroization tests prove a post-exit buffer no longer yields the
    key and no longer verifies under it).

    ``key`` may be ``bytes``/``bytearray``/``memoryview``; the source
    is never modified (and if the source is immutable, it obviously
    cannot be recalled — documented residual, see module docstring).
    """
    buf = bytearray(key)
    try:
        yield buf
    finally:
        zeroize(buf)
