"""Walk-Pad Cipher v1.3 reference implementation.

Every block is a link in a forward chain. Link i is encrypted under key_i = (W_i, C_i, e_i):
  walk table W_i = C_(i-1), combiner table C_i, start position e_i.
Its plaintext is: header(flag, e_(i+1)) || C_(i+1) || text, and the next key is (C_i, C_(i+1), e_(i+1)).
A message is one or more consecutive links; flag = 1 marks the link where a message ends.

Profiles:  hand6 = 6-bit symbols (q=64), 256-symbol pad, 512-cell grid (the standard hand block)
           byte1k = bytes, 1,024-byte pad, 2,048-cell grid
           byte16k = bytes, 16,384-byte pad, 32,768-cell grid
Not for real use: confidentiality is an untested conjecture and there is no integrity.
"""
import hashlib, os, random

PROFILES = {"hand6": (64, 256), "byte1k": (256, 1024), "byte16k": (256, 16384)}
TERM = {64: 0o77, 256: 0x80}        # end-of-text terminator; filler is 0
_R = random.SystemRandom()

class Profile:
    def __init__(self, name):
        self.name = name; self.q, self.P = PROFILES[name]; self.L = 2*self.P
        self.H = 2; self.M = self.P - self.H - self.q

def new_table(q, rng=_R):
    t = list(range(q))
    for i in range(q - 1):                       # forward Fisher-Yates
        j = i + rng.randrange(q - i); t[i], t[j] = t[j], t[i]
    return t

def inverse(t):
    inv = [0]*len(t)
    for i, s in enumerate(t): inv[s] = i
    return inv

def shifts(W, L):
    """shift(b) = (q*rank(b) + W[rank(b)+1]) mod L: rank and next symbol side by side, wrapped."""
    q = len(W); rk = inverse(W)
    return [(q*rk[b] + W[(rk[b] + 1) % q]) % L for b in range(q)]

def place(K, B, W, e, L):
    sh = shifts(W, L); g = [None]*L; c = e
    for k in K:
        while g[c] is not None: c = (c + 1) % L
        g[c] = k; c = (c + sh[k]) % L
    blanks = [i for i in range(L) if g[i] is None]
    for i, v in zip(blanks, B): g[i] = v
    return g

def extract(S, W, e, P):
    L = len(S); sh = shifts(W, L); used = [False]*L; c = e; K = []
    for _ in range(P):
        while used[c]: c = (c + 1) % L
        used[c] = True; K.append(S[c]); c = (c + sh[S[c]]) % L
    return K, [S[i] for i in range(L) if not used[i]]

def combine(plain, K, C):
    q = len(C); return [C[(p + k) % q] for p, k in zip(plain, K)]
def uncombine(body, K, C):
    q = len(C); ci = inverse(C); return [(ci[v] - k) % q for v, k in zip(body, K)]

def header(pr, flag, e):
    v = flag*pr.L + e; return [v // pr.q, v % pr.q]
def read_header(pr, h):
    v = h[0]*pr.q + h[1]
    if v >= 2*pr.L: raise ValueError("reject: header")
    return v // pr.L, v % pr.L

def new_key(pr):
    return (new_table(pr.q), new_table(pr.q), _R.randrange(pr.L))

def encrypt_link(pr, key, text, last):
    W, C, e = key
    Cn, en = new_table(pr.q), _R.randrange(pr.L)
    plain = header(pr, 1 if last else 0, en) + Cn + text
    K = [_R.randrange(pr.q) for _ in range(pr.P)]
    return place(K, combine(plain, K, C), W, e, pr.L), (C, Cn, en)

def decrypt_link(pr, key, S):
    W, C, e = key
    K, body = extract(S, W, e, pr.L // 2)
    plain = uncombine(body, K, C)
    flag, en = read_header(pr, plain[:2]); Cn = plain[2:2+pr.q]
    if sorted(Cn) != list(range(pr.q)): raise ValueError("reject: carried table")
    return flag, plain[2+pr.q:], (C, Cn, en)

def encrypt_message(pr, key, text):
    """text: list of symbols (6-bit: never the terminator 77). Returns links and the next key."""
    data = list(text) + [TERM[pr.q]]
    while len(data) % pr.M: data.append(0)
    n = len(data) // pr.M; links = []
    for i in range(n):
        S, key = encrypt_link(pr, key, data[i*pr.M:(i+1)*pr.M], i == n - 1); links.append(S)
    return links, key

def decrypt_message(pr, key, links):
    out = []
    for i, S in enumerate(links):
        flag, t, key = decrypt_link(pr, key, S); out += t
        if flag != (1 if i == len(links) - 1 else 0): raise ValueError("reject: end flag")
    while out and out[-1] == 0: out.pop()
    if not out or out[-1] != TERM[pr.q]: raise ValueError("reject: padding")
    return out[:-1], key

# ---- 6-bit code chart (octal) ------------------------------------------
CHART = {0o00: " "}
for i, ch in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"): CHART[0o01 + i] = ch
for i, ch in enumerate("0123456789"): CHART[0o33 + i] = ch
for i, ch in enumerate(".,?!'\":;-/()&@#%+=*$"): CHART[0o45 + i] = ch
for code, name in [(0o71, "<CR>"), (0o72, "<LF>"), (0o73, "<TAB>"), (0o74, "<BS>"), (0o75, "<BEL>"), (0o76, "<ESC>"), (0o77, "<END>")]:
    CHART[code] = name
assert len(CHART) == 64
TO6 = {v: k for k, v in CHART.items() if len(v) == 1}
def encode6(s): return [TO6[c] for c in s.upper()]
def decode6(sym): return "".join(CHART[x] for x in sym)
def octal(sym): return " ".join(f"{x:02o}" for x in sym)

if __name__ == '__main__':
    # ---- 6-bit reduced test vector: q = 64 tables, P = 16, L = 32 ----------
    rng = random.Random(20261006)
    W, C = new_table(64, rng), new_table(64, rng)
    e = 0o05; K = [rng.randrange(64) for _ in range(16)]
    plain = encode6("WALK PAD CIPHER.")
    body = combine(plain, K, C); S = place(K, body, W, e, 32); sh = shifts(W, 32)
    print("6-BIT TEST VECTOR (q = 64, P = 16, L = 32, e = 05 octal)")
    print("W =", octal(W)); print("C =", octal(C))
    print("plain =", octal(plain), f'("{decode6(plain)}")'); print("K     =", octal(K)); print("body  =", octal(body))
    used, c, cells = [False]*32, e, []
    for k in K:
        while used[c]: c = (c + 1) % 32
        used[c] = True; cells.append(c); c = (c + sh[k]) % 32
    print("pad cells (octal) =", " ".join(f"{x:02o}" for x in cells))
    print("S =", octal(S)); print("SHA-256(S as bytes) =", hashlib.sha256(bytes(S)).hexdigest())
    K2, B2 = extract(S, W, e, 16); print("round-trip:", K2 == K and uncombine(B2, K2, C) == plain)
    rk = inverse(W); r = 0o13
    print(f"hand-grid shift check: line {r:02o} holds {W[r]:02o}, line {r+1:02o} holds {W[r+1]:02o} -> shift = {shifts(W, 512)[W[r]]:03o}")
    print("first 3 steps:")
    used, c = [False]*32, e
    for j in range(3):
        skip = 0
        while used[c]: c = (c + 1) % 32; skip += 1
        used[c] = True; nc = (c + sh[K[j]]) % 32
        print(f"  step {j}: cell {c:02o} (skipped {skip}), pad {K[j]:02o}, shift {sh[K[j]]:02o}, next cursor {nc:02o}")
        c = nc
    # ---- chain round trips, all profiles ----------------------------------------
    for name in PROFILES:
        pr = Profile(name); k0 = new_key(pr); ks = kr = k0; ok = True
        lengths = [0, 1, pr.M - 1, pr.M, 2*pr.M + 5]
        for n in lengths:
            if pr.q == 64: text = [_R.randrange(63) for _ in range(n)]
            else: text = list(os.urandom(n))
            links, ks = encrypt_message(pr, ks, text)
            got, kr = decrypt_message(pr, kr, links)
            ok &= got == text and ks == kr
        print(f"{name}: q={pr.q} P={pr.P} L={pr.L} text/link={pr.M} key={2*pr.q+2} symbols | "
              f"5 messages ({', '.join(map(str, lengths))} symbols) on one chain round-trip: {ok}")
    pr = Profile("hand6"); k = new_key(pr)
    links, _ = encrypt_message(pr, k, encode6("ATTACK AT DAWN"))
    print("hand6 sample decrypts to:", decode6(decrypt_message(pr, k, links)[0]))
    W0, C0, e0 = k; Wb = W0[:]; Wb[0], Wb[1] = Wb[1], Wb[0]
    for nm, kk in [("wrong walk table", (Wb, C0, e0)), ("wrong start", (W0, C0, (e0 + 1) % pr.L)),
                   ("tables swapped back", (C0, W0, e0))]:
        try: decrypt_message(pr, kk, links); print(nm, ": ACCEPTED (unexpected)")
        except ValueError as err: print(nm, ":", err)
