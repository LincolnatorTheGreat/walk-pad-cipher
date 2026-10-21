import hashlib
from wotp_v13 import combine, uncombine, place, extract, shifts, decode6
o = lambda s: [int(x, 8) for x in s.split()]
W = o("77 06 55 25 76 27 46 23 72 54 30 11 64 56 73 61 22 05 20 42 33 32 01 14 74 21 17 50 34 07 24 04 36 47 26 40 16 71 31 43 41 37 02 70 15 62 66 52 12 53 65 57 45 03 13 00 67 35 63 60 75 44 51 10")
C = o("05 75 34 42 70 66 20 11 43 00 74 61 76 10 71 26 13 01 47 04 17 50 25 65 15 21 16 44 77 37 46 36 31 03 62 35 63 32 55 07 06 30 73 51 56 57 12 41 14 33 60 22 40 45 67 02 27 54 24 23 52 53 64 72")
plain = o("27 01 14 13 00 20 01 04 00 03 11 20 10 05 22 45"); K = o("72 15 57 16 74 10 67 25 51 76 35 11 64 76 72 55")
body = combine(plain, K, C); S = place(K, body, W, 0o05, 32)
print("tables valid:", sorted(W) == list(range(64)), sorted(C) == list(range(64)))
print("plain decodes:", decode6(plain))
print("body matches:", body == o("01 71 23 21 52 15 27 21 30 75 55 21 52 42 76 47"))
print("S matches:", S == o("11 74 76 57 01 72 55 71 16 23 21 52 15 35 51 27 25 15 10 67 64 21 76 30 75 72 55 21 52 42 76 47"))
print("SHA matches:", hashlib.sha256(bytes(S)).hexdigest() == "173b2818478a0d66dbb00e795a1463866affdb4437d7d5cee1a25e2bcbf028af")
print("shift(11) on 512 grid:", oct(shifts(W, 512)[0o11]))
k2, b2 = extract(S, W, 0o05, 16); print("round trip:", uncombine(b2, k2, C) == plain)
