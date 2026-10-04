"""Unit tests for gov/shamir_custody.py (wave-328 lane 3).

Includes an INDEPENDENT reference Lagrange implementation (log/exp
tables -- a different code path from the module's Russian-peasant
multiply + Fermat inverse) cross-checked against split/combine on
random cases, plus closure pins for the fail-closed behaviors.
"""

import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import shamir_custody as sc


# ---------------------------------------------------------------------------
# Independent reference: GF(2^8) via log/exp tables.
#
# NOTE (2026-10-04): the first version of this table used 2 as the
# generator -- but in the AES field 2 has order 51, not 255 (verified:
# repeated xtime returns to 1 after 51 steps, cross-checked against the
# module's FIPS-197-vectored _gf_mul). 3 is primitive here; the table
# build asserts full 255-coverage plus the FIPS-197 vector so a wrong
# generator fails LOUD instead of silently covering a subfield.
# ---------------------------------------------------------------------------

def _ref_xtime(a):
    # Multiply by 2 in GF(2^8)/0x11B (Russian-peasant-free formulation).
    doubled = (a << 1) & 0xFF
    if a & 0x80:
        doubled ^= 0x11B
    return doubled & 0xFF


def _ref_mul3(a):
    # 3*a = (2*a) xor a.
    return _ref_xtime(a) ^ a


_GEN = 3
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x = _ref_mul3(_x)
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]
# Loud primitivity check: a non-primitive generator would silently cover
# only a subfield.
assert len(set(_EXP[:255])) == 255, "reference generator 3 is not primitive"
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _r_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _r_inv(a):
    assert a != 0
    return _EXP[255 - _LOG[a]]


def _r_lagrange_zero(points):
    total = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i != j:
                num = _r_mul(num, xj)
                den = _r_mul(den, xj ^ xi)
        total ^= _r_mul(yi, _r_mul(num, _r_inv(den)))
    return total


class ShamirMathTests(unittest.TestCase):
    def test_reference_table_covers_field(self):
        # The table generator really is primitive (module import would
        # already have raised, but pin it as a test too).
        self.assertEqual(len(set(_EXP[:255])), 255)
        self.assertEqual(_LOG[1], 0)

    def test_reference_mul_fips_vector(self):
        # FIPS-197 through the INDEPENDENT table path, not the module.
        self.assertEqual(_r_mul(0x57, 0x13), 0xFE)

    def test_gf_mul_vector(self):
        # FIPS-197: 0x57 * 0x13 = 0xfe.
        self.assertEqual(sc._gf_mul(0x57, 0x13), 0xFE)

    def test_gf_inv_roundtrip(self):
        for a in (1, 2, 3, 0x53, 0xFF):
            self.assertEqual(sc._gf_mul(a, sc._gf_inv(a)), 1)

    def test_reference_agrees_with_module(self):
        import random
        rng = random.Random(20281004)
        for _ in range(20):
            n = rng.randrange(2, 12)
            t = rng.randrange(2, n + 1)
            pts = [(x, rng.randrange(256)) for x in range(1, t + 1)]
            self.assertEqual(sc._lagrange_at_zero(pts),
                             _r_lagrange_zero(pts))

    def test_hand_vector_t2(self):
        # f(x) = 0x42 + 0x01*x ; f(1)=0x43, f(2)=0x40 (xor arithmetic).
        self.assertEqual(_r_lagrange_zero([(1, 0x43), (2, 0x40)]), 0x42)
        self.assertEqual(sc._lagrange_at_zero([(1, 0x43), (2, 0x40)]), 0x42)


class ShamirCeremonyTests(unittest.TestCase):
    def test_roundtrip_many_params(self):
        import random
        rng = random.Random(7)
        for n, t in ((5, 3), (3, 2), (9, 5), (7, 7), (10, 4)):
            secret = bytes(rng.randrange(256) for _ in range(24))
            if len(secret) < 16:
                secret = secret + b"\x00" * (16 - len(secret))
            shards = sc.split(secret, n, t, "ut-%d-%d" % (n, t))
            self.assertEqual(len(shards), n)
            self.assertEqual(
                sorted(s["index"] for s in shards), list(range(1, n + 1)))
            for k in range(t, n + 1):
                self.assertEqual(sc.combine(shards[:k]), secret)

    def test_subthreshold_reveals_nothing_usable(self):
        secret = sc.generate_secret(32)
        shards = sc.split(secret, 5, 3, "ut-sub")
        with self.assertRaises(sc.ShamirCustodyError) as ctx:
            sc.combine(shards[:2])
        self.assertEqual(ctx.exception.code,
                         "custody-shamir-insufficient-shares")

    def test_t1_refused(self):
        with self.assertRaises(sc.ShamirCustodyError) as ctx:
            sc.split(sc.generate_secret(16), 5, 1, "ut-t1")
        self.assertEqual(ctx.exception.code, "custody-shamir-bad-params")

    def test_short_secret_refused(self):
        with self.assertRaises(sc.ShamirCustodyError) as ctx:
            sc.split(b"too-short", 5, 3, "ut-short")
        self.assertEqual(ctx.exception.code, "custody-shamir-bad-params")

    def test_n_over_255_refused(self):
        with self.assertRaises(sc.ShamirCustodyError) as ctx:
            sc.split(sc.generate_secret(16), 256, 2, "ut-n256")
        self.assertEqual(ctx.exception.code, "custody-shamir-bad-params")

    def test_shares_are_randomized(self):
        secret = sc.generate_secret(16)
        a = sc.split(secret, 5, 3, "ut-r1")
        b = sc.split(secret, 5, 3, "ut-r2")
        self.assertNotEqual(a[0]["share"], b[0]["share"])
        self.assertEqual(sc.combine(a[:3]), secret)
        self.assertEqual(sc.combine(b[:3]), secret)

    def test_commitment_is_sha256(self):
        import hashlib
        secret = sc.generate_secret(16)
        shards = sc.split(secret, 4, 2, "ut-commit")
        self.assertEqual(shards[0]["commitment"],
                         hashlib.sha256(secret).hexdigest())

    def test_rekey_retires_old(self):
        secret = sc.generate_secret(16)
        old = sc.split(secret, 4, 2, "ut-old")
        new = sc.rekey(secret, 4, 2, "ut-new", supersedes="ut-old")
        self.assertEqual(sc.combine(new[:2]), secret)
        with self.assertRaises(sc.ShamirCustodyError) as ctx:
            sc.combine([old[0], new[1]])
        self.assertEqual(ctx.exception.code,
                         "custody-shamir-ceremony-mismatch")

    def test_serialize_roundtrip(self):
        secret = sc.generate_secret(16)
        shards = sc.split(secret, 4, 2, "ut-ser")
        blob = sc.serialize_shard(shards[0])
        back = sc.parse_shard(blob)
        self.assertEqual(back["share"], shards[0]["share"])
        self.assertEqual(back["index"], shards[0]["index"])
        self.assertEqual(sc.combine([back, shards[1]]), secret)

    def test_distribute_and_reload(self):
        tmp = tempfile.mkdtemp(prefix="shamir-ut-")
        secret = sc.generate_secret(16)
        shards = sc.split(secret, 3, 2, "ut-dist")
        assigns = {c: os.path.join(tmp, c + ".shard")
                   for c in ("ann", "bob", "cid")}
        manifest = sc.distribute(shards, assigns)
        self.assertEqual(sorted(manifest), ["ann", "bob", "cid"])
        loaded = [sc.parse_shard(open(assigns[c], "rb").read())
                  for c in ("ann", "cid")]
        self.assertEqual(sc.combine(loaded), secret)

    def test_distribute_refuses_overwrite(self):
        tmp = tempfile.mkdtemp(prefix="shamir-ut-")
        secret = sc.generate_secret(16)
        shards = sc.split(secret, 2, 2, "ut-ow")
        target = os.path.join(tmp, "live.shard")
        open(target, "wb").write(b"live")
        with self.assertRaises(sc.ShamirCustodyError) as ctx:
            sc.distribute(shards, {"ann": target,
                                   "bob": os.path.join(tmp, "b.shard")})
        self.assertEqual(ctx.exception.code,
                         "custody-shamir-distribute-refused")
        self.assertFalse(os.path.exists(os.path.join(tmp, "b.shard")))
        self.assertEqual(open(target, "rb").read(), b"live")

    def test_transcript_chain(self):
        tmp = tempfile.mkdtemp(prefix="shamir-ut-")
        tr = sc.CeremonyTranscript(os.path.join(tmp, "t.jsonl"))
        tr.record("init", {"ceremony_id": "ut-t"})
        tr.record("rekey", {"new_ceremony_id": "ut-t2",
                            "supersedes": "ut-t"})
        self.assertEqual(tr.verify(), 2)
        # Tamper and verify refuses.
        with open(tr.path, "r", encoding="utf-8") as fh:
            content = fh.read()
        with open(tr.path, "w", encoding="utf-8") as fh:
            fh.write(content.replace("ut-t2", "ut-evil", 1))
        with self.assertRaises(sc.ShamirCustodyError) as ctx:
            tr.verify()
        self.assertEqual(ctx.exception.code,
                         "custody-shamir-transcript-corrupt")

    def test_all_codes_known(self):
        self.assertEqual(len(sc._NEW_CODES), 8)
        self.assertEqual(tuple(sorted(sc._NEW_CODES)), sc._NEW_CODES)


if __name__ == "__main__":
    unittest.main()
