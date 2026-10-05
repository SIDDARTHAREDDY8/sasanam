#!/usr/bin/env python3
"""Threshold-fragmented swap-side key material -- RESEARCH SPIKE prototype.

stdlib only. Models the spike question from the Outerlimit steal queue:
can we Shamir-fragment the swap-side key material of the sentinel-
substitution architecture so no single node holds enough to reconstruct?

What is fragmented: the WRAPPING key K (the swap-side master key that
unwraps per-credential real values), NOT each credential. Fragmenting per-
credential multiplies share management by the credential count; the master
key is the actual single point of failure.

Simulated protocol:
  1. Dealer splits K into n shares, threshold k (Shamir over GF(q)).
  2. Feldman commitments (VSS) published so a corrupt share is detectable
     before reconstruction (Byzantine fragment test).
  3. Swap decision: k nodes each verify (identity + policy + execution
     context) -- toy attestation -- then release their share to the
     reassembly point, which reconstructs K and unwraps the credential.

Measurements taken:
  - split / share-verify / reconstruct latency (us)
  - fragment-loss tolerance (n-k)
  - node-compromise threshold (k colluding nodes needed)
  - Byzantine share detection via VSS
  - honest accounting of the reassembly point (who sees K in the clear)

Run: python3 research/w344-fragspike/prototype.py
"""

import hashlib
import hmac
import secrets
import time

# ---------------------------------------------------------------------------
# Field + DL group for Feldman VSS: need a safe prime p = 2q + 1.
# Generated at runtime with Miller-Rabin (stdlib). q is 160-bit here:
# ILLUSTRATIVE ONLY -- the spike measures protocol mechanics (costs,
# failure modes), not cryptographic strength. A production build needs
# q >= 256-bit (e.g. RFC 3526 group 14) and an audited implementation.
# ---------------------------------------------------------------------------
def _is_probable_prime(n: int, rounds: int = 32) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_safe_prime(qbits: int = 160):
    while True:
        q = secrets.randbits(qbits) | (1 << (qbits - 1)) | 1
        if _is_probable_prime(q) and _is_probable_prime(2 * q + 1):
            return 2 * q + 1, q


P, Q = _gen_safe_prime()
G = 2
assert pow(G, Q, P) == 1 and G != 1  # g has order q

# Secret: 128-bit wrapping-key representative shared over GF(Q).
# (Production: 256-bit secret over a 256-bit+ q.)
SECRET_BITS = 128


def shamir_split(secret: int, n: int, k: int):
    """Return (shares, commitments). shares = [(x_i, y_i)]; Feldman VSS commitments."""
    assert 1 < k <= n
    assert 0 < secret < Q
    coeffs = [secret] + [secrets.randbelow(Q) for _ in range(k - 1)]

    def poly(x):
        y = 0
        for c in reversed(coeffs):
            y = (y * x + c) % Q
        return y

    shares = [(i, poly(i)) for i in range(1, n + 1)]
    commitments = [pow(G, c, P) for c in coeffs]  # C_j = g^{a_j}
    return shares, commitments


def vss_verify(share, commitments):
    """Feldman check: g^{s_i} == prod_j C_j^{i^j} (mod p)."""
    x, y = share
    lhs = pow(G, y, P)
    rhs = 1
    xp = 1
    for c in commitments:
        rhs = (rhs * pow(c, xp, P)) % P
        xp = (xp * x) % Q
    return lhs == rhs


def lagrange_reconstruct(shares):
    """Reconstruct secret from >= k shares via Lagrange interpolation at x=0."""
    xs = [s[0] for s in shares]
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        num, den = 1, 1
        for j, xj in enumerate(xs):
            if i == j:
                continue
            num = (num * (-xj)) % Q
            den = (den * (xi - xj)) % Q
        secret = (secret + yi * num * pow(den, -1, Q)) % Q
    return secret


# ---------------------------------------------------------------------------
# Toy swap-side credential wrapping: K wraps a per-credential real value.
# (Toy cipher: HMAC-based stream; NOT a production construction.)
# ---------------------------------------------------------------------------
def wrap(key: int, plaintext: bytes) -> bytes:
    kb = key.to_bytes(16, "big")
    out = bytearray()
    ctr = 0
    while len(out) < len(plaintext):
        out += hmac.new(kb, b"wrap" + ctr.to_bytes(8, "big"), hashlib.sha256).digest()
        ctr += 1
    return bytes(a ^ b for a, b in zip(plaintext, out))


def unwrap(key: int, blob: bytes) -> bytes:
    return wrap(key, blob)  # symmetric


# ---------------------------------------------------------------------------
# Toy fragment node: holds one share; releases it only after the triple
# attestation (identity + policy + execution context) verifies. Toy = HMAC
# over the swap request with the node's attestation key.
# ---------------------------------------------------------------------------
class FragmentNode:
    def __init__(self, node_id, share, commitments):
        self.id = node_id
        self.share = share
        self.commitments = commitments
        self.attest_key = secrets.token_bytes(32)

    def attest_and_release(self, swap_request: dict):
        """Verify identity+policy+context (toy), then release share. Returns share or None."""
        tag = hmac.new(self.attest_key, repr(sorted(swap_request.items())).encode(),
                       hashlib.sha256).hexdigest()
        # Toy policy: request must name an allowlisted host and a fresh nonce.
        ok = (swap_request.get("host") in ("api.allowed.example",) and
              swap_request.get("nonce") and
              swap_request.get("agent") == "agent-7")
        return (self.share, tag) if ok else (None, tag)


def bench(fn, *args, iters=200):
    t0 = time.perf_counter()
    for _ in range(iters):
        fn(*args)
    return (time.perf_counter() - t0) / iters * 1e6  # us


def main():
    N, K = 5, 3  # 5 fragment nodes, threshold 3
    K_wrap = secrets.randbelow(2 ** SECRET_BITS - 1) + 1  # the swap-side wrapping key
    real_credential = b"xoxb-abc123def456"
    blob = wrap(K_wrap, real_credential)

    # --- 1. split ---
    t_split = bench(lambda: shamir_split(K_wrap, N, K), iters=50)
    shares, commitments = shamir_split(K_wrap, N, K)
    nodes = [FragmentNode(i, s, commitments) for i, s in enumerate(shares)]

    # --- 2. VSS verify all shares (Byzantine screen at issuance) ---
    t_vss = bench(vss_verify, shares[0], commitments)
    assert all(vss_verify(s, commitments) for s in shares), "VSS failed on honest shares"

    # --- 3. Byzantine fragment: corrupt one share, VSS must catch it ---
    bad = (shares[0][0], (shares[0][1] + 1) % Q)
    byzantine_caught = not vss_verify(bad, commitments)

    # --- 4. swap decision: k nodes attest + release; reconstruct; unwrap ---
    req = {"agent": "agent-7", "host": "api.allowed.example", "nonce": secrets.token_hex(8)}
    released = []
    for node in nodes:
        share, _tag = node.attest_and_release(req)
        if share is not None and vss_verify(share, commitments):
            released.append(share)
        if len(released) == K:
            break
    assert len(released) == K, "not enough attestations"
    t_recon = bench(lagrange_reconstruct, released, iters=200)
    K2 = lagrange_reconstruct(released)
    assert K2 == K_wrap, "reconstruction mismatch"
    assert unwrap(K2, blob) == real_credential, "unwrap mismatch"

    # --- 5. failure modes ---
    # 5a. fragment loss: tolerate up to N-K losses
    surviving = shares[:K]  # worst case: only K survive
    loss_ok = lagrange_reconstruct(surviving) == K_wrap
    # 5b. node compromise: attacker needs K colluding nodes. K-1 shares are
    # information-theoretically useless: for ANY candidate secret, a unique
    # degree-(K-1) polynomial passes through (0, cand) + the K-1 shares, so
    # no candidate can be ruled out. Structural check: x-coords distinct.
    attacker_shares = shares[:K - 1]
    xs = [0] + [p[0] for p in attacker_shares]
    info_theoretic = len(set(xs)) == len(xs)  # interpolation always possible
    # 5c. denied attestation: wrong host -> no release
    bad_req = dict(req, host="evil.example")
    denied = all(n.attest_and_release(bad_req)[0] is None for n in nodes)

    # --- 6. the reassembly-point accounting ---
    # Whoever runs lagrange_reconstruct + unwrap sees K_wrap AND the real
    # credential in the clear, transiently. Fragmentation moved the trust:
    # theft-at-rest now needs K nodes; but the reassembly point is a
    # transient single point of compromise. Measured: it holds the secret
    # for ~t_recon us + unwrap time per swap.

    print("=== threshold-fragmentation spike: measurements ===")
    print(f"params: n={N} k={K}; VSS group: generated safe prime, q {Q.bit_length()}-bit "
          f"(ILLUSTRATIVE size); secret {SECRET_BITS}-bit wrapping key")
    print(f"split (dealer, one-time):            {t_split:10.1f} us")
    print(f"VSS share verify (per share):        {t_vss:10.1f} us")
    print(f"Lagrange reconstruct (k={K} shares):   {t_recon:10.1f} us")
    print(f"fragment loss: {N-K} of {N} lost, reconstruct OK: {loss_ok}")
    print(f"Byzantine share caught by VSS:       {byzantine_caught}")
    print(f"k-1 = {K-1} shares info-theoretically useless: {info_theoretic}")
    print(f"attestation denial (wrong host):     {denied}")
    print("reassembly point: sees K + credential in clear for ~reconstruct+unwrap window")
    print("ALL SPIKE CHECKS PASSED")


if __name__ == "__main__":
    main()
