"""Check a claimed key against a public challenge.

usage:  python3 verify_claim.py <challenge> <key.json>
        <challenge> is 1, 2, q8, q12, q16 or q24
        key.json is {"W": [...], "C": [...], "e": <start cell>}, symbols as integers

A key counts as a solution if it decrypts the published ciphertext to the published
plaintext (challenges 2, q8-q24) or to a valid message (challenge 1, which then prints it).
After a challenge is claimed, its salt is published and anyone can also check the
SHA-256 commitment with:  python3 verify_claim.py commit <hash> <salt hex> <secret.json>
"""
import hashlib, json, re, sys
from wotp_v13 import Profile, decrypt_message, extract, uncombine, decode6, encode6

def load_challenges(path="challenges/challenges.txt"):
    text = open(path).read()
    out = {}
    for block in text.split("\n\n"):
        m = re.match(r"CHALLENGE (\S+)", block)
        if not m:
            continue
        name = m.group(1).replace("q=", "q")
        cts = re.findall(r"link \d+: ([0-9 ]+)", block)
        pt = re.search(r"Plaintext \(all P symbols.*?\):\n([0-9 ]+)", block)
        txt = re.search(r"The text portion of the plaintext is:\n(.+)", block)
        out[name] = {"octal": name in ("1", "2"), "links": cts,
                     "plain": [int(x) for x in pt.group(1).split()] if pt else None,
                     "text": txt.group(1) if txt else None}
    return out

def main():
    if sys.argv[1] == "commit":
        h, salt, path = sys.argv[2], bytes.fromhex(sys.argv[3]), sys.argv[4]
        blob = json.dumps(json.load(open(path)), sort_keys=True).encode()
        print("commitment matches:", hashlib.sha256(salt + blob).hexdigest() == h)
        return
    ch = load_challenges()[sys.argv[1]]
    key = json.load(open(sys.argv[2]))
    W, C, e = key["W"], key["C"], key["e"]
    base = 8 if ch["octal"] else 10
    links = [[int(x, base) for x in l.split()] for l in ch["links"]]
    if ch["octal"]:
        pr = Profile("hand6")
        try:
            plain, _ = decrypt_message(pr, (W, C, e), links)
        except ValueError as err:
            print("REJECTED:", err); return
        text = decode6(plain)
        if ch["text"] is not None:
            print("solution valid:", text == ch["text"])
        else:
            print("decrypts to:", text)
    else:
        S = links[0]; P = len(S) // 2
        K, body = extract(S, W, e, P)
        print("solution valid:", uncombine(body, K, C) == ch["plain"])

if __name__ == "__main__":
    main()
