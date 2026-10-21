"""Generate the Walk-Pad v1.3 public challenge set.

Writes challenges_PUBLIC.txt (publishable) and challenge_keys_PRIVATE.txt (keep secret).
Each challenge commits to its secret with SHA-256(salt || secret), salt kept private.
"""
import hashlib, os, json, random
from wotp_v13 import (Profile, new_key, new_table, encrypt_message, decrypt_message, encrypt_link,
                      decrypt_link, place, extract, combine, uncombine, encode6, decode6, octal, _R)

def commit(obj):
    salt = os.urandom(16)
    blob = json.dumps(obj, sort_keys=True).encode()
    return salt.hex(), hashlib.sha256(salt + blob).hexdigest()

pub, priv = [], {}

# ---- Challenge 1: ciphertext only, standard hand block, one message, English text ----
pr = Profile("hand6")
text1 = ("THE WALK PAD CHALLENGE ONE. IF YOU CAN READ THIS, YOU HAVE BROKEN THE STANDARD HAND BLOCK "
         "WITH CIPHERTEXT ALONE. SEND THE SECOND SENTENCE OF THIS MESSAGE AS PROOF.")
k1 = new_key(pr)
links1, _ = encrypt_message(pr, k1, encode6(text1))
assert decode6(decrypt_message(pr, k1, links1)[0]) == text1
s1, h1 = commit({"plaintext": text1})
pub.append(("CHALLENGE 1 - ciphertext only (q=64, P=256, L=512, one link)",
            "Goal: recover the plaintext. Plaintext is uppercase English in the 6-bit chart.\n"
            f"Commitment SHA-256(salt||plaintext json): {h1}",
            [octal(S) for S in links1]))
priv["challenge1"] = {"salt": s1, "plaintext": text1, "W": k1[0], "C": k1[1], "e": k1[2]}

# ---- Challenge 2: known plaintext, standard hand block, recover key ----
k2 = new_key(pr)
text2 = ("KNOWN PLAINTEXT CHALLENGE. THE TEXT OF THIS LINK IS PUBLISHED IN FULL. RECOVER THE WALK TABLE, "
         "THE COMBINER TABLE AND THE START CELL OF THE KEY THAT ENCRYPTED IT. GOOD LUCK.")
links2, _ = encrypt_message(pr, k2, encode6(text2))
assert len(links2) == 1
s2, h2 = commit({"W": k2[0], "C": k2[1], "e": k2[2]})
pub.append(("CHALLENGE 2 - known plaintext (q=64, P=256, L=512, one link)",
            "Goal: recover the key (W, C, e). The text portion of the plaintext is:\n" + text2 + "\n"
            "(The 2-symbol header and 64-symbol carried table are not published; padding is END then zeros.)\n"
            f"Commitment SHA-256(salt||key json): {h2}",
            [octal(S) for S in links2]))
priv["challenge2"] = {"salt": s2, "W": k2[0], "C": k2[1], "e": k2[2]}

# ---- Challenges 3-6: reduced-size scaling ladder, known random plaintext, recover key ----
for q in (8, 12, 16, 24):
    P = 4 * q; L = 2 * P
    W, C = new_table(q), new_table(q); e = _R.randrange(L)
    K = [_R.randrange(q) for _ in range(P)]
    plain = [_R.randrange(q) for _ in range(P)]
    S = place(K, combine(plain, K, C), W, e, L)
    K2, B2 = extract(S, W, e, P); assert uncombine(B2, K2, C) == plain
    s, h = commit({"W": W, "C": C, "e": e})
    pub.append((f"CHALLENGE q={q} - reduced size, known plaintext (q={q}, P={P}, L={L}, single block, no header)",
                "Goal: recover (W, C, e). Symbols are written in decimal.\n"
                "Plaintext (all P symbols, combined in order with the pad):\n" + " ".join(map(str, plain)) + "\n"
                f"Commitment SHA-256(salt||key json): {h}",
                [" ".join(map(str, S))]))
    priv[f"reduced_q{q}"] = {"salt": s, "W": W, "C": C, "e": e, "pad": K}

with open("challenges_PUBLIC.txt", "w") as f:
    f.write("WALK-PAD CIPHER v1.3 - PUBLIC CHALLENGE SET\n"
            "Reference implementation and spec: see the Walk-Pad v1.3 specification.\n"
            "Commitments: SHA-256 of a 16-byte secret salt followed by the JSON of the secret\n"
            "(sorted keys, Python json.dumps defaults). The salt is revealed when a challenge is claimed or closed.\n\n")
    for title, desc, cts in pub:
        f.write(title + "\n" + desc + "\nCiphertext:\n")
        for i, c in enumerate(cts):
            f.write(f"  link {i}: {c}\n")
        f.write("\n")
with open("challenge_keys_PRIVATE.txt", "w") as f:
    json.dump(priv, f, indent=1)
print(open("challenges_PUBLIC.txt").read()[:3000])
