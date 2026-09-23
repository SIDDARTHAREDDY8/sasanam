"""Wave-58 Lane 4: deterministic seeded fuzzing of the CONNECT request-line
parser and authority grammar in gov/egress_proxy.py.

Properties (all must hold for every input):
  P1: _parse_authority / decide / serve_stream NEVER raise on any input
      (bytes or str). Any exception = crash -> fix or F125.
  P2: _parse_authority never returns a target outside the grammar:
      (host, port) with host a non-empty str without whitespace/control
      chars or '@', and port a str of ASCII digits (int-able, 1..65535
      enforced by decide).
  P3: every ACCEPTED target re-serializes to itself: decide's (host, port)
      re-parsed through _parse_authority yields the identical (host, port).

Deterministic: random.Random(20260922). Corpus = hand-picked adversarial
seeds x systematic mutations. No network, no randomness at runtime.
"""
import random
import socket
import sys

sys.path.insert(0, "/home/hatch/workspace/agent-governance-demo/agent-governance-demo-main")
from gov import egress_proxy as ep

SEED = 20260922

# ---------------------------------------------------------------- seeds ---
BASE_AUTHORITIES = [
    "example.com:443", "a:1", "[::1]:443", "[2001:db8::1]:80",
    "EXAMPLE.com:443", "example.com.:443", "xn--nxasmq6b.example:443",
]
ADVERSARIAL_TOKENS = [
    "@", "user@host:443", "user@host@evil:443", "@evil:443", "host@:443",
    "host:80:evil", "host:", "host:0", "host:65536", "host:99999",
    "host:007", "host: 443", "host :443", " host:443", "host:443 ",
    "host:\u00b2", "host:\u00bd", "host:\u0668\u0660", "host:\u2460\u2461",
    "host:+443", "host:-443", "host: 443 ", "host:\t443", "host:\n443",
    "host%2ecom:443", "ex%41mple.com:443", "..:443", "...:443",
    "host\u3002com:443", "\u3000host:443", "h\u200bost:443",
    "http://host:443/", "https://host:443/x", "host:443/path",
    "host:443?x=1", "*:443", "*:*", "[::1]443", "[]:443", "[::1]:",
    "[::1]:abc", "[[::1]]:443", "v6[::1]:443", "-bad:443", "_bad:443",
    "a" * 300 + ":443", "host:" + "4" * 40, "host:443" + "\r\nX: y",
    "h\x00ost:443", "host\x00443", "\x7fhost:443", "host:443\x7f",
    "h\u0301ost:443", "\ufeffhost:443", "host\u202e:443",
]
BASE_REQUEST_LINES = [
    "CONNECT example.com:443 HTTP/1.1",
    "connect example.com:443 HTTP/1.1",
    "CONNECT  example.com:443  HTTP/1.1",
    "CONNECT example.com:443",
    "GET http://example.com/ HTTP/1.1",
    "CONNECT [::1]:443 HTTP/1.1",
    "CONNECT example.com:443 HTTP/1.1 ",
    " CONNECT example.com:443 HTTP/1.1",
]

# ------------------------------------------------------------- harness ---
def make_policy():
    return ep.parse_policy({
        "version": "fuzz-1",
        "allow": ["example.com", "xn--nxasmq6b.example"],
        "operator_pinholes": [],
        "listen": "169.254.240.1",
        "port": 18080,
        "client_subnet": "169.254.240.0/30",
    })

def fake_resolver(host):
    return ["93.184.216.34"]

POLICY = make_policy()

def check_p1_parse(auth):
    try:
        r = ep._parse_authority(auth)
    except Exception as e:  # noqa: BLE001 - any raise is a P1 violation
        return ("CRASH", "%r raised %r" % (auth, e))
    if r == (None, None):
        return ("deny-shape", None)
    host, port = r
    # P2: grammar check
    if not isinstance(host, str) or not host:
        return ("ESCAPE", "empty/non-str host from %r" % (auth,))
    if any(ord(c) < 33 or c in "@ \t\r\n" for c in host):
        return ("ESCAPE", "host outside grammar: %r from %r" % (host, auth))
    try:
        pv = int(port)
    except Exception:
        return ("ESCAPE", "port not int-able: %r from %r" % (port, auth))
    if not (1 <= pv <= 65535):
        # decide() range-checks; parser returning it is fine, but record
        return ("deny-shape", None)
    return ("ok", None)

def check_p1_decide(auth):
    try:
        d = ep.decide(POLICY, "CONNECT", auth, "169.254.240.2", resolve=fake_resolver)
    except Exception as e:  # noqa: BLE001
        return ("CRASH", "%r raised %r" % (auth, e))
    if d.verdict == "allow":
        # P3: re-serialization round-trip
        canon = "[%s]:%d" % (d.host, d.port) if ":" in d.host else "%s:%d" % (d.host, d.port)
        h2, p2 = ep._parse_authority(canon)
        if h2 != d.host or (p2 is not None and int(p2) != d.port):
            return ("ESCAPE", "round-trip failed: %r -> %r -> (%r,%r)" % (auth, canon, h2, p2))
    return ("ok", None)

def check_p1_read_request(raw):
    proxy = ep.EgressProxy(POLICY, resolver=fake_resolver)
    proxy.ready = True
    cli, srv = socket.socketpair()
    try:
        cli.sendall(raw)
        cli.shutdown(socket.SHUT_WR)
        try:
            d = proxy.serve_stream(srv, "169.254.240.2")
        except Exception as e:  # noqa: BLE001
            return ("CRASH", "request %r raised %r" % (raw[:60], e))
        return ("ok", d.rule)
    finally:
        cli.close(); srv.close()

def mutate(rng, s):
    """Deterministic byte/char-level mutations."""
    if not s:
        return s
    ops = ["dup", "del", "swap", "insert", "case", "ws"]
    op = rng.choice(ops)
    i = rng.randrange(len(s))
    if op == "dup":
        return s[:i] + s[i:i+1] * rng.randint(2, 5) + s[i+1:]
    if op == "del":
        return s[:i] + s[i+1:]
    if op == "swap" and len(s) > 1:
        j = rng.randrange(len(s)); l = list(s); l[i], l[j] = l[j], l[i]; return "".join(l)
    if op == "insert":
        return s[:i] + rng.choice([":", "@", ".", "%", " ", "\t", "[", "]", "\u00b2", "\u3000", "\x00"]) + s[i:]
    if op == "case" and s[i].isalpha():
        return s[:i] + s[i].swapcase() + s[i+1:]
    if op == "ws":
        return s[:i] + rng.choice([" ", "  ", "\t", "\r", "\n", "\r\n"]) + s[i:]
    return s

def build_corpus():
    rng = random.Random(SEED)
    corpus = list(BASE_AUTHORITIES) + list(ADVERSARIAL_TOKENS)
    seeds = BASE_AUTHORITIES + ADVERSARIAL_TOKENS
    for _ in range(4000):
        s = rng.choice(seeds)
        for _ in range(rng.randint(1, 3)):
            s = mutate(rng, s)
        corpus.append(s)
    # byte-level: latin-1 soup
    for _ in range(500):
        n = rng.randint(0, 40)
        corpus.append("".join(chr(rng.choice([rng.randint(1, 127), rng.randint(128, 255)])) for _ in range(n)))
    return corpus

def main():
    corpus = build_corpus()
    stats = {"ok": 0, "deny-shape": 0}
    problems = []
    for auth in corpus:
        for fn in (check_p1_parse, check_p1_decide):
            kind, detail = fn(auth)
            if kind in ("CRASH", "ESCAPE"):
                problems.append((fn.__name__, kind, detail))
            else:
                stats[kind] = stats.get(kind, 0) + 1
    # request-line level: deterministic smaller set
    rng = random.Random(SEED + 1)
    req_corpus = [l.encode("latin-1") for l in BASE_REQUEST_LINES]
    for _ in range(600):
        line = rng.choice(BASE_REQUEST_LINES)
        for _ in range(rng.randint(1, 2)):
            line = mutate(rng, line)
        ending = rng.choice(["\r\n\r\n", "\n\n", "\r\r", "\r\n\n", "\n\r\n", "\r\n\r\n\r\n"])
        req_corpus.append((line + ending).encode("latin-1", errors="ignore"))
    req_corpus.append(b"CONNECT " + b"a" * 9000 + b":443 HTTP/1.1\r\n\r\n")  # overlong
    req_corpus.append(b"")  # empty
    req_problems = []
    for raw in req_corpus:
        kind, detail = check_p1_read_request(raw)
        if kind == "CRASH":
            req_problems.append(detail)
    # non-str inputs to _parse_authority
    for bad in [None, 123, b"host:443", ["host:443"], {"a": 1}]:
        kind, detail = check_p1_parse(bad)
        if kind in ("CRASH", "ESCAPE"):
            problems.append(("check_p1_parse(non-str)", kind, detail))
    print("corpus: %d authorities, %d request-lines" % (len(corpus), len(req_corpus)))
    print("parse/decide outcomes:", stats)
    print("authority-level problems: %d" % len(problems))
    seen = set()
    for fn, kind, detail in problems:
        key = (kind, str(detail)[:90])
        if key in seen:
            continue
        seen.add(key)
        print("  [%s] %s: %s" % (kind, fn, detail))
    print("request-level crashes: %d" % len(req_problems))
    for d in req_problems[:10]:
        print("  [CRASH]", d)
    return 1 if (problems or req_problems) else 0

if __name__ == "__main__":
    sys.exit(main())
