# Walk-Pad Cipher

An experimental hand cipher for graph paper, two d8 dice and a pencil. No computer ever holds the plaintext or the key, so malware on a device is not an attack surface. **Its security is unproven.** This repository exists so other people can try to break it.

- [SPEC.md](SPEC.md): the full v1.3 specification, including test vectors, analysis to date (section 15), claims and non-claims (16), threat model (18), the public challenge (19) and the field procedure (20).
- [wotp_v13.py](wotp_v13.py): reference implementation in Python 3, standard library only.
- [challenges/challenges.txt](challenges/challenges.txt): six challenge ciphertexts with SHA-256 commitments.
- [attacks/](attacks/): the guess-and-determine attack programs behind the analysis.

## How it works

Each block (a "link") mixes a random pad into a grid by a key-driven walk: jump by a shift taken from a secret permutation table, then skip forward past cells already filled. The message, combined with the pad through a second secret permutation, fills the remaining cells. Each link carries the next link's table and start position, so a single starting key of 130 symbols drives an unlimited chain of messages.

The standard hand block uses 6-bit symbols written in octal, a 256-symbol pad, a 512-cell grid and 190 message characters per link. Two byte-sized profiles exist for machine use.

## Status

- Guess-and-determine key recovery has been run on reduced versions up to 10-symbol alphabets. Its cost grows roughly with q!, which extrapolates to about 2^313 for the hand block. That is an extrapolation from one attack, not a security proof.
- Statistical distinguisher and tamper tests came back clean, apart from one known observation: pad positions clump 20 to 36% more than random. No way to exploit it has been found yet.
- There has been no outside review. Do not rely on this cipher for anything that matters until it has survived some.
- The specification and the attack code were written with help from an AI assistant and reviewed by the author; test vectors are checked against the code.

## Try it

```
python3 wotp_v13.py        # test vectors, chain round trips, wrong-key rejection
python3 check_vectors.py   # checks the 6-bit test vector printed in SPEC.md section 14
```

## The challenge

| Challenge | Size | Given | Goal |
| --- | --- | --- | --- |
| 1 | hand block (q = 64) | ciphertext only | recover the plaintext |
| 2 | hand block (q = 64) | ciphertext + message text | recover the key |
| q8, q12, q16, q24 | reduced alphabets | ciphertext + full plaintext | recover the key |

The q8 challenge is a warm-up that the included attack solves. The ladder from q12 to q24 is meant to measure how fast attack cost really grows, so please report your method's cost even for the small sizes. A distinguisher (telling these ciphertexts apart from random symbols better than chance) also counts as a break. Full rules are in SPEC.md section 19.

To check a solution, put the key in a JSON file (`{"W": [...], "C": [...], "e": 123}`, symbols as integers) and run:

```
python3 verify_claim.py q16 my_key.json
```

Claims: open an issue in this repository with the key file attached. When a challenge is claimed, its salt is published so anyone can check the commitment with `verify_claim.py commit`.

`gen_challenges.py` is the script that produced the challenge set, included for transparency. Running it makes a new, different set with new keys; it does not reproduce the published one.

## License

Code under the MIT License (see LICENSE). The specification text is licensed CC BY 4.0.
