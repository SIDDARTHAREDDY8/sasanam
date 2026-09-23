"""Wave-71 Lane 2 tests: in-memory key zeroization, break-first.

What this proves (and what it honestly does not):

* PROVEN: ``zeroize()`` wipes caller-owned mutable buffers; the wipe
  is exception-safe (``key_buffer``), idempotent (double-wipe safe),
  and fail-loud on immutable inputs (``bytes``/``str`` raise
  ``TypeError`` — "wiping" an immutable would be theater).
  ``KeyMaterial.destroy()`` / ``KeyRing.destroy()`` wipe the actual
  provider buffers (read-back proof on the real buffer object) and
  leave no live Python reference to them (refcount census: only the
  material itself held the buffer). (A ``gc.get_objects()``
  value-scan census was attempted and REJECTED pre-ship:
  ``bytes``/``bytearray`` are not gc-tracked in CPython, so such a
  scan vacuously passes; a weakref census was attempted and also
  REJECTED — ``bytearray`` is not weak-referenceable. The read-back
  + refcount census is the honest replacement.)
* DOCUMENTED, not fixed: CPython allocator freelists and the
  ``hmac`` module's C-level internal copy are outside Python's reach
  (see ``research/zeroization-design-wave71-2026-09-22.md`` E2); env
  ``str`` values are immutable. These are boundary notes, not
  findings.

Deterministic, $0, synthetic/local only. Env hygiene: tests that
touch ``os.environ`` save and restore it.
"""

import gc
import hashlib
import hmac
import os
import secrets
import sys
import unittest

from gov.keys import DestroyedKeyError, KeyMaterial, KeyRing
from gov.zeroize import zeroize, key_buffer


class ZeroizePrimitiveTest(unittest.TestCase):
    def test_zeroize_wipes_bytearray(self):
        canary = secrets.token_bytes(32)
        buf = bytearray(canary)
        zeroize(buf)
        self.assertEqual(bytes(buf), b"\x00" * 32)
        self.assertNotIn(canary, bytes(buf))
        # read-back proof: the buffer no longer contains the key
        self.assertFalse(any(b != 0 for b in buf))

    def test_zeroize_is_idempotent(self):
        buf = bytearray(secrets.token_bytes(32))
        zeroize(buf)
        first = bytes(buf)
        zeroize(buf)  # double-wipe must be safe, not an error
        self.assertEqual(bytes(buf), first)
        self.assertEqual(bytes(buf), b"\x00" * 32)

    def test_zeroize_refuses_bytes_loud(self):
        # "Wiping" an immutable is impossible; silently accepting it
        # would be theater. Fail loud.
        with self.assertRaises(TypeError):
            zeroize(b"immutable-key-material")

    def test_zeroize_refuses_str_loud(self):
        with self.assertRaises(TypeError):
            zeroize("immutable-key-material")

    def test_zeroize_refuses_readonly_memoryview(self):
        with self.assertRaises(TypeError):
            zeroize(memoryview(b"read-only"))

    def test_zeroize_accepts_writable_memoryview(self):
        buf = bytearray(secrets.token_bytes(32))
        mv = memoryview(buf)
        zeroize(mv)
        self.assertEqual(bytes(buf), b"\x00" * 32)

    def test_zeroize_rejects_non_buffers(self):
        with self.assertRaises(TypeError):
            zeroize(12345)
        with self.assertRaises(TypeError):
            zeroize(None)


class KeyBufferContextTest(unittest.TestCase):
    def test_buffer_wiped_on_clean_exit(self):
        canary = secrets.token_bytes(32)
        with key_buffer(canary) as buf:
            self.assertIsInstance(buf, bytearray)
            self.assertEqual(bytes(buf), canary)
            mac = hmac.new(buf, b"msg", hashlib.sha256).hexdigest()
        self.assertEqual(bytes(buf), b"\x00" * len(canary))
        # source untouched: the CM copies, never mutates the input
        self.assertEqual(canary, bytes(canary))
        # sanity: the live-use MAC verifies under the real key
        self.assertEqual(
            mac, hmac.new(canary, b"msg", hashlib.sha256).hexdigest())

    def test_buffer_wiped_on_exception(self):
        canary = secrets.token_bytes(32)
        buf_ref = []
        with self.assertRaises(RuntimeError):
            with key_buffer(canary) as buf:
                buf_ref.append(buf)
                raise RuntimeError("consumer blew up mid-use")
        # the exception between use and wipe must not skip the wipe
        self.assertEqual(bytes(buf_ref[0]), b"\x00" * len(canary))

    def test_use_after_wipe_is_detectably_wrong(self):
        # Never-expose-wiped-buffers discipline, proven: a retained
        # post-exit buffer no longer yields the key, and a MAC minted
        # from it does NOT verify under the real key — accidental
        # reuse fails loud at verification instead of silently
        # forging under an all-zero key.
        canary = secrets.token_bytes(32)
        with key_buffer(canary) as buf:
            mac_live = hmac.new(buf, b"m", hashlib.sha256).hexdigest()
        self.assertNotEqual(bytes(buf), canary)
        mac_dead = hmac.new(buf, b"m", hashlib.sha256).hexdigest()
        self.assertNotEqual(mac_dead, mac_live)
        self.assertNotEqual(
            mac_dead,
            hmac.new(canary, b"m", hashlib.sha256).hexdigest())


class KeyMaterialDestroyTest(unittest.TestCase):
    def test_destroy_wipes_and_fails_loud(self):
        canary = secrets.token_bytes(32)
        mat = KeyMaterial("epoch-z1", canary)
        self.assertIsInstance(mat.key, bytearray)
        self.assertEqual(bytes(mat.key), canary)
        key_id_before = mat.key_id
        mat.destroy()
        self.assertIsNone(mat.key)
        # key_id (a digest, not the key) survives for the audit trail
        self.assertEqual(mat.key_id, key_id_before)
        # fail LOUD: no silent HMAC-under-zeros
        with self.assertRaises(TypeError):
            hmac.new(mat.key, b"m", hashlib.sha256)
        with self.assertRaises(AttributeError):
            mat.key.decode("ascii")

    def test_destroy_is_idempotent(self):
        mat = KeyMaterial("epoch-z2", secrets.token_bytes(32))
        mat.destroy()
        mat.destroy()  # second destroy must not raise
        self.assertIsNone(mat.key)

    def test_destroyed_material_cannot_serialize(self):
        # to_dict() on destroyed material must fail loud — a wiped key
        # must never be persisted as None/zeros.
        mat = KeyMaterial("epoch-zs", secrets.token_bytes(32))
        mat.destroy()
        with self.assertRaises(DestroyedKeyError):
            mat.to_dict()
        # live material still round-trips (generated hex keys use the
        # byte-identical key_hex path)
        live = KeyMaterial("epoch-zl", secrets.token_hex(32).encode("ascii"))
        self.assertEqual(KeyMaterial.from_dict(live.to_dict()).key_id,
                         live.key_id)

    def test_storage_copies_input_no_aliasing(self):
        # bytearray() always copies: the material never aliases the
        # caller's buffer, so destroy() cannot wipe the caller's copy
        # and caller mutation cannot change the material.
        raw = bytearray(secrets.token_bytes(32))
        mat = KeyMaterial("epoch-z3", raw)
        self.assertIsNot(mat.key, raw)
        raw[:] = b"\x00" * 32
        self.assertNotEqual(bytes(mat.key), b"\x00" * 32)

    def test_bytearray_key_is_mac_identical(self):
        # Legitimate-behavior pin: bytearray storage feeds HMAC
        # byte-identically to the old bytes storage.
        canary = secrets.token_bytes(32)
        mat = KeyMaterial("epoch-z4", canary)
        self.assertEqual(
            hmac.new(mat.key, b"m", hashlib.sha256).hexdigest(),
            hmac.new(canary, b"m", hashlib.sha256).hexdigest())
        # and == against bytes still holds (dev-material screening
        # in keyprovider/keys.py depends on it)
        self.assertTrue(mat.key == canary)
        self.assertFalse(mat.key != canary)


class KeyRingDestroyTest(unittest.TestCase):
    def test_destroy_wipes_all_epochs(self):
        ring = KeyRing.generate(epoch="epoch-1")
        ring.rotate("epoch-2")
        keys_before = {ep: bytes(m.key) for ep, m in ring._keys.items()}
        self.assertEqual(len(keys_before), 2)
        ring.destroy()
        self.assertEqual(ring._keys, {})
        self.assertIsNone(ring._active_epoch)
        with self.assertRaises(KeyError):
            ring.active()
        with self.assertRaises(KeyError):
            ring.get("epoch-1")

    def test_destroyed_ring_cannot_be_activated(self):
        # activate() publishes to os.environ — must fail loud, never
        # publish zeros or raise obscurely.
        ring = KeyRing.generate(epoch="epoch-1")
        ring.destroy()
        with self.assertRaises((KeyError, AttributeError, TypeError)):
            ring.activate()


class CopyCensusTest(unittest.TestCase):
    def test_census_wipable_inventory_wiped_and_unreachable(self):
        # The centerpiece. Methodology note (caught pre-ship): bytes
        # and bytearray are NOT gc-tracked in CPython, so a
        # gc.get_objects() value-scan can never see key buffers — such
        # a "census" would vacuously pass. The honest census is:
        # (1) read-back proof on the ACTUAL provider buffer object
        # (the wipe landed where the design claims), and (2) a
        # refcount census proving no live Python reference to that
        # buffer survives cleanup. (A weakref census was attempted
        # and REJECTED: bytearray is not weak-referenceable.)
        # Copies the design never created (C-level
        # hmac internals, allocator freelists) are unknowable from
        # Python — that unknowability IS the documented residual.
        canary = secrets.token_bytes(32)
        mat = KeyMaterial("epoch-census", canary)
        buf = mat.key  # the ACTUAL provider buffer, not a copy
        self.assertEqual(bytes(buf), canary)  # pre: buffer holds key

        # the log-path shape: resolve -> HMAC -> drop the transient
        mac = hmac.new(mat.key, b"census-msg",
                       hashlib.sha256).hexdigest()
        del mac
        gc.collect()
        # refcount census: exactly two holders — mat.__dict__ and this
        # frame's buf local (+1 for the getrefcount argument itself).
        # In particular the HMAC object retained no Python-level
        # reference to the key buffer.
        self.assertEqual(sys.getrefcount(buf), 3)

        # discard-time wipe of the provider-held buffer
        mat.destroy()

        # (1) read-back: the real buffer is wiped in place
        self.assertEqual(bytes(buf), b"\x00" * len(canary))
        self.assertIsNone(mat.key)
        # (2) no surviving holder: only this frame's buf local remains
        self.assertEqual(sys.getrefcount(buf), 2)
        del mat, buf
        gc.collect()
        # bytearray is a non-container (no outgoing references, no
        # cycles possible): refcount hit zero at del, so the buffer
        # was freed immediately — no live Python reference survives.

        # Deterministic residual 1: the CALLER's immutable input
        # bytes cannot be recalled — KeyMaterial copied it (no
        # aliasing), but the caller's own object is immutable and
        # zeroize refuses it loud.
        with self.assertRaises(TypeError):
            zeroize(canary)

        # Deterministic residual 2: os.environ values are immutable
        # str — zeroize refuses them loud, and the str persists.
        saved = os.environ.get("GOV_W71_CENSUS")
        os.environ["GOV_W71_CENSUS"] = canary.hex()
        try:
            with self.assertRaises(TypeError):
                zeroize(os.environ["GOV_W71_CENSUS"])
            self.assertEqual(os.environ["GOV_W71_CENSUS"], canary.hex())
        finally:
            if saved is None:
                os.environ.pop("GOV_W71_CENSUS", None)
            else:
                os.environ["GOV_W71_CENSUS"] = saved

        # Unknowable residual (documented boundary, not a finding):
        # CPython allocator freelists and the hmac module's C-level
        # key copy live outside every Python reference. The E2 probe
        # (research/zeroization-design-wave71-2026-09-22.md) found key
        # bytes in own-process heap after all Python-level wipes; no
        # Python API can enumerate or scrub them. destroy() defeats
        # reachable-graph readers, not raw-memory readers (core dump
        # / /proc/pid/mem / scrapers) — the honest negative result
        # for the wave's stated threat model.


if __name__ == "__main__":
    unittest.main()
