# Walk-Pad Cipher v1.3 Specification

Version 1.3 · October 2026

## Status and changes from v1.2

v1.3 makes every block a link in a forward chain, so blocks work as separate messages, and adds a 6-bit hand block as the standard for pen and paper. Placement (jump and skip) and the combiner are unchanged from v1.2. Confidentiality remains a conjecture, and integrity is still not claimed.

| Area | v1.2 | v1.3 | Reason |
| --- | --- | --- | --- |
| Chaining | backward within one message: each block carries the previous block's key | forward: each link carries the next link's combiner table and start position | links can be sent as separate messages over time; decryption runs front to back |
| Table roles | combiner of block i = walk table of block i - 1 | walk table of link i = combiner of link i - 1 | breaking a link exposes the previous link's combiner, not its walk; section 13 |
| First block | carried its own walk table as a check | no special first block; every link carries the same fields | frees space; the check moves to the carried table and header |
| Hand profile | bytes, 1,024-byte pad, hex, d16 dice | 6-bit symbols, 256-symbol pad, 512-cell grid, octal, d8 dice | about a quarter of the work per block; d8 dice are common |
| End of message | 32-bit length field | terminator symbol plus filler, and an end flag in the header | works for every symbol size |

All attacks so far ran on shrunken instances and were designed by Claude in one session. Section 15 has the numbers.

## 1. Profiles

Three standard profiles share one algorithm; they differ in symbol size and block size. The 6-bit hand block is the standard for pen and paper.

|  | Hand block | 2K block | 32K block |
| --- | --- | --- | --- |
| Symbol | 6 bits, written as 2 octal digits | byte, 2 hex digits | byte, 2 hex digits |
| q (symbols per table) | 64 | 256 | 256 |
| P (pad length = body length) | 256 | 1,024 | 16,384 |
| L (grid cells = link length) | 512 | 2,048 | 32,768 |
| Header | 2 symbols | 2 bytes | 2 bytes |
| Carried table | 64 symbols | 256 bytes | 256 bytes |
| Text per link | 190 symbols | 766 bytes | 16,126 bytes |
| Key | 130 symbols | 514 bytes | 514 bytes |
| Cell labels | octal 000 to 777 | hex 000 to 7FF | hex 0000 to 7FFF |
| Dice | d8 | d16 | d16 |

In every profile, text per link = P - 2 - q and key size = 2q + 2. Other sizes work the same way when L is a power of two, q^2 is at least L, and 2L fits in the two header symbols.

## 2. Symbols, tables and keys

A link key is two tables and a start position; everything else is generated fresh for each link.

- A **symbol** is an integer from 0 to q - 1.
- A **table** is a sequence of q distinct symbols, a uniform permutation, stored in rank order: line r holds W\[r\]. rank\_W(b) is the line holding symbol b.
- A **link key** is (W, C, e): the walk table W, the combiner table C and the start position e, from 0 to L - 1.
- The **header** is two symbols read as a base-q number v = flag x L + e\_next. flag = 1 marks the link where a message ends; e\_next is the next link's start position. Any v of 2L or more is rejected. In the hand block the header is four octal digits: 0 or 1, then the three-digit start position.
- A **pad** is P uniformly random symbols, fresh for every link.
- A **published link** is L symbols.

## 3. Shift function

Each symbol's jump is its rank and the next table entry written side by side as a two-symbol number, wrapped to the grid.

```latex
\mathrm{shift}_W(b) = (q\cdot r + W[(r+1) \bmod q]) \bmod L, \qquad r = \mathrm{rank}_W(b)
```

Shifts are distinct for distinct symbols, because the next entries W\[r+1\] are distinct. A shift of 0 lands on the cell just filled, and the skip rule moves on to the next blank cell.

Wrapping is a matter of dropping digits:

- **Hand block (octal 000 to 777):** the last octal digit of the line number, then the next line's symbol. Line 13 followed by symbol 64 gives shift 364.
- **2K block (hex 000 to 7FF):** the last hex digit of the line number, minus 8 if 8 or more, then the next line's byte. Line 2B followed by 3B gives 33B.
- **32K block (hex 0000 to 7FFF):** the line number, minus 8 from its first digit if 8 or more, then the next line's byte. Line 2B followed by 3B gives 2B3B.

## 4. Placement: jump and skip

Pad symbols are placed on a blank grid by jumping a raw number of cells from each one, then skipping forward past cells already used; the body then fills the blank cells in order. Cell labels run 0 to L - 1 and wrap from L - 1 to 0. Jumps count every cell, filled or not, and always start from the cell actually written (or read), after any skip.

**Place(K, B, W, e)**, encryption:

```
grid <- L blank cells
c <- e
for k in K[0], K[1], ..., K[P-1]:
    while cell c is filled: c <- (c + 1) mod L
    write k in cell c
    c <- (c + shift_W(k)) mod L
write B[0], B[1], ..., B[P-1] into the blank cells in order, starting from cell 0
return grid
```

**Extract(S, W, e)**, decryption:

```
c <- e
repeat P times:
    while cell c is crossed out: c <- (c + 1) mod L
    k <- S[c]; cross out cell c; append k to pad
    c <- (c + shift_W(k)) mod L
body <- the cells not crossed out, in order from cell 0
return pad, body
```

**Correctness.** Before step j, the encryptor's filled cells and the decryptor's crossed-out cells are the same set: the cells holding pad symbols 0 to j - 1. Both cursors are equal, so both skip the same cells, land on the same cell and jump by the same shift. By induction this holds for all P steps, and the cells left over are the body cells in the same order. The grid is never more than half full, so a blank cell always exists. Skips average about 0.5 per step.

## 5. Combiner

Each plaintext symbol is added to its pad symbol modulo q, then substituted through the link's combiner table C.

```latex
\mathrm{body}[j] = C[(\mathrm{plain}[j] + K[j]) \bmod q], \qquad \mathrm{plain}[j] = (C^{-1}[\mathrm{body}[j]] - K[j]) \bmod q
```

The substitution is what defeats the v1.0 counting attack: pad symbol k sits beside C\[(p + k) mod q\], so without C nothing links the two in the link's symbol counts. By hand in the hand block, add two octal digit pairs and drop any carry past two digits. An XOR combiner, which relay machines handle more easily, has not been tested and is not part of this standard.

## 6. The chain

Link i walks with the previous link's combiner, combines with its own table C\_i, and carries the next combiner and start position forward. Each table is used twice: first as a combiner, then as the next link's walk table.

```
starting key = (C_0, C_1, e_1)

link 1:  walk with C_0   combine with C_1   carries C_2, e_2
link 2:  walk with C_1   combine with C_2   carries C_3, e_3
link 3:  walk with C_2   combine with C_3   carries C_4, e_4
   ...   each table is a combiner first, then the next link's walk table
```

Every link's plaintext has the same layout:

```
header(flag, e_next) || C_next || text
     2 symbols           q symbols   P - 2 - q symbols
```

After decrypting link i, the decryptor's next key is (C\_i, C\_next, e\_next): the table it just used as the combiner becomes the walk table, and the table and start position it just read become the combiner and start.

## 7. Encryption and the starting key

Each link is encrypted with its key (W, C, e) and hands the next key forward; nothing needs precomputing except the next combiner table.

1. Generate a fresh table C\_next and a start position e\_next, uniform in 0 to L - 1.
2. Build plain = header(flag, e\_next) || C\_next || text, where text is the next P - 2 - q symbols of the message (section 8).
3. Generate the pad K: P random symbols.
4. Compute body = combine(plain, K, C).
5. Publish S = Place(K, body, W, e).
6. The next key is (C, C\_next, e\_next).

Pad symbols can be generated, placed and combined one at a time; only the body waits for the end of the walk.

**Starting key.** The first link's key is two independent random tables and a start position, shared in person: 130 symbols for the hand block, 514 bytes for the byte blocks. Write it as W\_0, then C\_0, then a header with flag 0 and e\_0. A message is one or more consecutive links, and the next message continues the chain from the key the last link handed forward. Every key encrypts exactly one link and is never reused.

## 8. Ending a message

A message ends with a terminator symbol and filler, and its last link sets the end flag in the header.

1. Append the terminator: octal 77 (END) for the hand block, byte 80 (hex) for the byte blocks.
2. Append filler symbols of value 0 until the text fills a whole number of links. If the terminator does not fit in the last link, the message takes one more link.
3. Set flag = 1 in the header of the last link and 0 in every other link.

To remove: drop trailing zeros, then require and drop one terminator. In the hand block, END never appears in text, so the text simply stops at the first END. Padding is not authenticated.

## 9. Decryption and checks

Links are decrypted in order, front to back, each with the key the previous link handed forward.

```
for each link S, with key (W, C, e):
    (K, body) <- Extract(S, W, e)
    plain <- (C^-1[body] - K) mod q, symbol by symbol
    v <- header value of plain[0:2]; reject if v >= 2L
    flag <- v div L;  e_next <- v mod L
    C_next <- plain[2 : 2+q]; reject unless it is a table (each symbol exactly once)
    keep plain[2+q : P] as text
    key <- (C, C_next, e_next)
    if flag = 1: the message ends here; strip the padding (section 8)
```

A wrong key fails the header check about three times in four in the hand block, and almost always fails the table check, since a random sequence of 64 symbols is a permutation with probability about 3 in 10^27. These checks confirm the key; they are not a MAC and say nothing about whether the text was altered. Keep the newest key safe and destroy each used one.

## 10. Randomness and dice

Every pad symbol, table and start position must be uniformly random and used once.

- **One 6-bit symbol:** two d8, each read as an octal digit (a face of 1 to 8 counts as 0 to 7). Equivalent unbiased options: three d4 (16a + 4b + c, faces as 0 to 3), one d16 and one d4, or two d16 with the first die taken mod 4.
- **Start position, hand block:** three d8, giving octal 000 to 777 directly.
- **One byte:** two d16. Start positions for the byte blocks: three d16 minus 800 (hex) if 800 or more for the 2K block; four d16 with 8 subtracted from the first digit if 8 or more for the 32K block.
- **Tables, simplest:** draw numbered tiles blind from a well-mixed bag (64 tiles for the hand block, 256 for the byte blocks). The order drawn is the table.
- **Tables with dice:** forward Fisher-Yates. For line i from the first to the next-to-last: let m = q - i, roll one symbol's worth of dice, reroll if the value is at or above the largest multiple of m that is at most q, then swap line i with line i + (value mod m).
- **Dice quality:** inexpensive dice are often measurably biased, and any bias passes straight into the pads. Use precision dice, or rotate between several.

## 11. Standard hand block: procedure

One hand-block link carries 190 text symbols and takes very roughly 2 hours to encrypt; decryption skips the dice and is somewhat quicker. That time is an estimate from per-step timings, not a measured trial. All numbers below are octal.

**Materials:** two d8 (or an equivalent from section 10); optionally 64 numbered tiles and a bag; a preprinted grid of 512 cells in 64 rows labeled 00 to 77 and 8 columns labeled 0 to 7 (cell label = row then column); a key sheet with three 64-line columns W, C and C\_next; a blank 8 x 8 shift grid indexed by symbol (first digit = row, second = column).

**Before each link**

1. Build the shift grid from W: for each line r, at the position of the symbol on line r, write the last digit of r followed by the symbol on line r + 1 (line 77 uses line 00).
2. Generate C\_next with tiles or dice, and roll three d8 for e\_next.
3. Write the 256 plaintext symbols: the header (0, or 1 if the message ends in this link, then the three digits of e\_next), the 64 symbols of C\_next, then 190 text symbols (in the last link: END, then 00 filler).
4. Mark the start cell e from your key.

**For each of the 256 plaintext symbols, in order**

1. Roll two d8: this is the pad symbol k.
2. If the cursor cell is already filled, move to the next blank cell (777 wraps to 000).
3. Write k in that cell.
4. Add the plaintext symbol and k, keeping the last two digits. Read that line of C and append its symbol to the body list.
5. Look up k in the shift grid, add the shift to the current cell label, and keep the last three digits. That is the new cursor.

**After the link:** write the body list into the blank cells in order from 000, then transcribe cells 000 to 777 as the 512-symbol ciphertext. Your next key is W = C, C = C\_next, e = e\_next; destroy the old walk table.

**Decryption:** build the shift grid from W, and an inverse grid for C (at the position of the symbol on line r, write r). From the start cell: skip crossed-out cells, read k, cross the cell out, add k to the pad list, then jump by k's shift. After 256 pad symbols, read the uncrossed cells in order; for the j-th one, plaintext = (its inverse-grid entry) - k\_j, keeping the last two digits. The header and C\_next give the next key.

**Transmission:** send the ciphertext as raw 6-level tape or as pairs of octal digits. Never print ciphertext on a teleprinter that obeys control codes.

**Errors:** one wrong addition sends every later pad symbol to the wrong cell, which garbles the rest of the link and the next key. Check each link by decrypting it before sending.

## 12. 6-bit code chart

The hand block uses this chart: space, 26 letters, 10 digits, 20 punctuation marks, 6 teleprinter and cursor controls, and END. Row = first octal digit, column = second.

|  | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | space | A | B | C | D | E | F | G |
| 1 | H | I | J | K | L | M | N | O |
| 2 | P | Q | R | S | T | U | V | W |
| 3 | X | Y | Z | 0 | 1 | 2 | 3 | 4 |
| 4 | 5 | 6 | 7 | 8 | 9 | . | , | ? |
| 5 | ! | ' | " | : | ; | - | / | ( |
| 6 | ) | & | @ | # | % | + | = | \* |
| 7 | $ | CR | LF | TAB | BS | BEL | ESC | END |

CR is carriage return, LF line feed, BS backspace, BEL bell, and ESC escape for extensions such as lower case. END (77) ends a message and never appears in text. Correspondents may agree a different chart before first use, as long as END stays at 77.

## 13. What a compromise exposes

If link k's key is captured or broken, every later link is readable, the link before keeps its walk secret, and earlier links are untouched.

| Links | Exposure | Why |
| --- | --- | --- |
| k, k + 1, k + 2, ... | readable | each link carries the next combiner and start position, and the next walk table is the current combiner |
| k - 1 | combiner known, walk unknown | C\_(k-1) = W\_k. An attacker still has to search the walk table; with the combiner and all plaintext known, key search was 6.7 to 12.9 times faster at q = 6 to 10, roughly 4 to 5 bits at hand size (extrapolated) |
| k - 2 and earlier | nothing directly |  |

The swap matters: with v1.2's ordering, link k would reveal link k - 1's walk table, and that link would fall almost at once. Earlier links stay protected, but the chain never heals: unlike a ratchet, nothing restores secrecy after a compromise except a fresh starting key.

**Lost or garbled links break the chain.** Every later link depends on the key carried in the lost one. Number links, and keep a few spare starting keys shared in advance for restarting the chain.

## 14. Test vectors

Both vectors shrink the pad to 16 symbols and the grid to 32 cells (shifts taken mod 32) but use full-size tables. Values were computed by the reference implementation; extracting from the start position returns the pad and body, and uncombining returns the plaintext.

**6-bit (hand block tables), all values octal, e = 05:**

```
W = 77 06 55 25 76 27 46 23 72 54 30 11 64 56 73 61 22 05 20 42 33 32 01 14 74 21 17 50 34 07 24 04
    36 47 26 40 16 71 31 43 41 37 02 70 15 62 66 52 12 53 65 57 45 03 13 00 67 35 63 60 75 44 51 10
C = 05 75 34 42 70 66 20 11 43 00 74 61 76 10 71 26 13 01 47 04 17 50 25 65 15 21 16 44 77 37 46 36
    31 03 62 35 63 32 55 07 06 30 73 51 56 57 12 41 14 33 60 22 40 45 67 02 27 54 24 23 52 53 64 72

plain = 27 01 14 13 00 20 01 04 00 03 11 20 10 05 22 45   ("WALK PAD CIPHER.")
K     = 72 15 57 16 74 10 67 25 51 76 35 11 64 76 72 55
body  = 01 71 23 21 52 15 27 21 30 75 55 21 52 42 76 47

step 0: cell 05, pad 72, shift 14, next cursor 21
step 1: cell 21, pad 15, shift 22, next cursor 03
step 2: cell 03, pad 57, shift 05, next cursor 10
pad cells, in order = 05 21 03 10 01 22 23 20 16 26 15 00 24 02 31 06

S = 11 74 76 57 01 72 55 71 16 23 21 52 15 35 51 27 25 15 10 67 64 21 76 30 75 72 55 21 52 42 76 47
SHA-256(S, one byte per symbol) = 173b2818478a0d66dbb00e795a1463866affdb4437d7d5cee1a25e2bcbf028af
```

Shift-grid check on the full 512-cell grid with this W: line 13 holds 11 and line 14 holds 64, so shift(11) = 364.

**Bytes (2K and 32K block tables), hex, e = 5:**

```
W = fd15ae4cee4e8839d0984591ac93c39aecd2d41b2f1752342cd65b0baf8a7cff
    57223703a3475c2516e4cfa03b01d827e62b4261795499b3723395750abfbc3f
    e1f080ea2d5e6551b1c81855b9e8a7fc6d2ea6e75d24a1118743d982e9687f7b
    1969267ee29f40b48cf31e7d6ade8b309da8218df606e0a56b766c4197dc9bf7
    90f8daba3602efc5772a0494c0cb5a89127364e5c163813ef9cea2b53271620d
    445f0c3cd7c907e3dfb7927a9e85ed1c59c409ebb0aac2137083863d28353105
    fa66bb2010f1fb388f67d3294b4f0e1afe480f9cbd6ff5a9f2dd0058d596c7ca
    081f784aadf48423beb8cc461d3a74c656b249608e14506ea4d14dcdb6dbab53
C = f1f3ea41983e736827098008b20ae936c5d50b63cdfb7b9f18244ecb57b13151
    a747140d94e149558e292cbe5f6b374c9040ce17066ebd53a85a840fe3c9a49c
    e0a0340c69cc85ff33b746822ed73f124aece84f2889bf8fa2932d7a7e64b3e6
    16d9c4da74e47de5b0961f072f3d7f1c703c428cd830629ef972f86f2bbc1e92
    5d65c8d387996db9c1dfe23926f05e0304b5efeb618aa521f5e7c31ab4a92566
    aaf643db3832cf8bc76cd4234bab77fcd676f79b78ae97af0ed0863ba1f25860
    79671bca4d951dfd3a2a02545c5bc056a619019d88b67c13eda36ad2dd00ba91
    45fe05d181c2c650ee15b8dcf48dad52de20357571ac224810fa119abb445983

K     = 65786319c50034233d86b4adbb9cc7e1
plain = 05754fff50808b70322090ccf883c207
body  = 1f8df718fb5d60eb1ccf69729b51dfee

pad cells, in order = 5 22 0 1 10 2 26 6 4 12 9 21 11 13 14 24

S = 6319001f3d65238df7b4c5bb869cc718fb5d60eb1cad78cfe16934729b51dfee
SHA-256(S) = 509c14fa0c8b06c1dfe5619fd089a286e9907d54a4d5833ec9505d670fb65334
```

Shift-grid check with this W: line 2B holds A0 and line 2C holds 3B, so shift(A0) is 33B on the 2K grid and 2B3B on the 32K grid.

Chain round trips passed in all three profiles for five consecutive messages on one chain, of 0, 1, one-short-of-full, exactly full and just over two links of text. A swapped table entry, a start position off by one and the two tables in the wrong order were all rejected.

## 15. Analysis to date

The best attack found costs about q! x P walk steps per start-position guess: every walk table tried and walked to the end. Key-search attacks ran on shrunken instances (q = 4 to 10) with known plaintext for the text; pairing and evenness tests ran at the real sizes with chosen all-zero plaintext.

| Attack or test | Version | Result | Outcome |
| --- | --- | --- | --- |
| Byte counting, no key | v1.0 (XOR combiner) | constant message byte recovered 4 of 4 times | broken; fixed by the substitution combiner |
| Guess-and-determine | shared walk and combiner table | q = 8: about 550,000 steps per guess | fixed by separate tables |
| Locality (assume a pad-free start of block) | short steps (plus or minus 128) | 40x faster than without; key found 5 of 16 times | fixed by wide shifts |
| Step counter with secret seed | v1.1 plus counter | key-search cost unchanged | dropped |
| Four key-free trace tests, 40 full-size blocks each | v1.1 and v1.1 plus counter vs random placement | best distinguisher 55 to 61%, chance level | no trace |
| Stride placement | proposal | pad density spread 0.229 vs 0.037 random | rejected |
| Swap sweep, offsets 0 to 255 | proposal | 33 of the top 256 value pairs are true combiner pairs vs 3.8 random | leaks |
| Guess-and-determine, jump and skip | v1.2 and v1.3 | q = 6: about 68,200 steps per guess; q = 8: about 5.06 million (v1.1 walk: 68,700 and 5.05 million) | brute-force speed |
| Pairing test | 2K and 32K blocks | 4.2 and 3.5 true pairs in the top 256 vs 3.8 random | clean |
| Pairing test | hand block | 2.57 true pairs in the top 64 vs 2.61 random | clean |
| Pad density spread across windows | all profiles | 20 to 36% above random placement (hand: 0.234 vs 0.172) | mild clumping from skips |
| Known combiner plus all plaintext | v1.3 link k - 1 after link k is broken | 6.7x, 9.8x and 12.9x faster at q = 6, 8, 10; still about 12 steps per table tried | walk stays q!-hard |

No run ever accepted a wrong key. Costs were measured only up to q = 10; the trend toward q! at q = 64 and 256 is extrapolated, not proven.

## 16. Claims and non-claims

Only correctness is proved; everything else is a conjecture that has survived the attacks in section 15.

**Claims**

- **C1, correctness (theorem).** Extract inverts Place (section 4), and each link hands the decryptor exactly the key the next link was encrypted under.
- **C2, key recovery per link (conjecture).** The two tables are separable, so the cost is set by the walk: about q! x L x P walk steps. That is roughly 2^313 for the hand block, 2^1705 for the 2K block and 2^1713 for the 32K block.
- **C3, confidentiality (conjecture).** IND-CPA for each link, with each key used for one link.
- **C4, walk secrecy (conjecture).** Without W, the split of a link into pad and body cells cannot be found faster than searching most of the walk tables.
- **C5, compromise containment (conjecture).** Exposing link k reveals later links and link k - 1's combiner, but link k - 1's walk and all earlier links stay as hard as C2, less a few bits.

**Non-claims**

- **No integrity.** Changing a body symbol changes one plaintext symbol, and the checks still pass unless the header or carried table is hit.
- **Not authenticated encryption, not a MAC, not a one-time pad.** The pad is published inside the link; only its positions are hidden.
- **No proof of an exhaustive-search bound.** No practical cipher has one. Security rests on public cryptanalysis.
- **Costs.** Each link is 2P symbols for P - 2 - q symbols of text (hand block: 512 for 190, about 2.7 times), a starting key must be shared in person, and a lost link breaks the chain.

## 17. Open questions

These are the attacks and checks not yet run, roughly in order of how likely they are to find something.

- [ ] **Decryption oracle.** If a receiver reports whether tampered links decrypt, flipping one symbol at a time may label every cell as pad or body, which would make key search far cheaper. Likely the cheapest real break wherever decryption is automated.
- [ ] **Transmission errors.** One garbled pad cell ruins the rest of the link and the next key. A machine version needs a check value per link and a way to request retransmission.
- [ ] **Clumping from skips.** Pad density varies 20 to 36% more than random placement. Measure whether a locality-style attack can use it.
- [ ] **Chain links.** Each table serves as one link's combiner and the next link's walk. Look for attacks that use several consecutive links together.
- [ ] **Larger shrunken sizes.** Measure jump and skip at q = 12 and above to confirm the cost keeps tracking q! x P.
- [ ] **Ciphertext-only attacks** on realistic plaintext such as English text in the hand block's chart.
- [ ] **XOR combiner** for relay machines: test whether C\[m XOR k\] behaves like C\[(m + k) mod q\].
- [ ] **Hand trial.** Time one real hand-block link and count errors, to replace the 2-hour estimate.
- [ ] **Outside review.** All attacks so far were designed by Claude in one session. Independent cryptanalysts are the real test.

## 18. Threat model

The hand profile is for two parties who exchange a few short, high-value messages over a long period, do not trust any computer with the plaintext, and cannot safely resupply one-time pads. It removes the endpoint (malware on the device that encrypts or decrypts) as an attack surface; it does not remove the other surfaces of a person working with paper.

**Use it instead of:** a computer cipher, when the device itself is the threat. **Use a one-time pad instead** whenever fresh pad material can be delivered safely: a dice-generated pad is proven secure and faster by hand. The Walk-Pad's advantage is key economy, one 130-symbol starting key for an unlimited chain.

| Threat | Covered? | Notes |
| --- | --- | --- |
| Malware or compromised firmware on the encrypting or decrypting device | Yes | No device ever holds the plaintext or the key. |
| Cryptanalysis of intercepted ciphertext | Conjectured | Security is unproven; see Claims and the public challenge (19). Do not rely on it for life-or-death traffic until it has survived outside review. |
| Cameras: phones, laptops, smart TVs, CCTV, windows | No | Live video breaks it. The camera sees the dice, and the order cells are filled reveals the pad and the walk; a table read off paper reveals the key. The game disguise covers carrying the materials, not being filmed: encrypt and decrypt in private. |
| The paper: indentations on the sheet below, trash, stored key sheets | Partly | Encryption writes only the grid, which is the ciphertext, so impressions on the sheet below reveal nothing new. Keep key tables as tile layouts, never on paper; anything else written goes on one sheet over a hard bare surface and is burned (section 20). |
| Metadata: who sends to whom, when, how often, message length | No | The ciphertext still travels on a device and network. Pad message counts and timing if patterns matter. |
| Decryption oracle (attacker feeds altered ciphertext and watches the reaction) | By procedure | One decryption attempt per key; never reveal a failure; ask for retransmission only on a ciphertext checksum failure (section 9). |
| Coercion or a compromised partner | No | Forward chaining limits a captured key to later links plus one combiner table (section 13). |
| Hand errors | Partly | Ciphertext row and column sums locate a single garbled symbol; the sender catches encryption errors by decrypting each link before sending (section 11). |

## 19. Public challenge

Six ciphertexts invite outside attack: two at the full hand-block size and a ladder of four reduced sizes that measures how fast attack cost grows. All were made with the v1.3 reference implementation and fresh random keys; each secret is fixed in advance by a SHA-256 commitment, so a claimed solution can be checked against the hash once the salt is revealed.

| Challenge | Size | Given | Goal |
| --- | --- | --- | --- |
| 1 | q = 64, P = 256, L = 512 (hand block) | Ciphertext only | Recover the plaintext |
| 2 | q = 64, P = 256, L = 512 (hand block) | Ciphertext + the 190-symbol text of the link | Recover the key (W, C, e) |
| q=8 | q = 8, P = 32, L = 64 | Ciphertext + all 32 plaintext symbols | Recover (W, C, e) |
| q=12 | q = 12, P = 48, L = 96 | Ciphertext + all 48 plaintext symbols | Recover (W, C, e) |
| q=16 | q = 16, P = 64, L = 128 | Ciphertext + all 64 plaintext symbols | Recover (W, C, e) |
| q=24 | q = 24, P = 96, L = 192 | Ciphertext + all 96 plaintext symbols | Recover (W, C, e) |

**Rules.**

- Challenges 1 and 2 use the full chain format of section 6 (header, carried table, text, END, zero padding); symbols are octal. The reduced challenges are a single block with no header or carried table; the whole plaintext is combined with the pad, and symbols are decimal.
- Any key that reproduces the ciphertext from the published plaintext counts as a solution.
- A method that solves a reduced challenge counts too: report its cost (time, nodes searched) so the growth from q = 8 to 24 can be compared with the q!-scaling conjecture in section 15. The q = 8 challenge is a warm-up; the guess-and-determine attack in section 15 solves sizes up to q = 10.
- A distinguisher (a test that tells these ciphertexts from random symbols better than chance) also counts as a break.
- Commitments are SHA-256 of a secret 16-byte salt followed by the JSON of the secret, as written by Python's `json.dumps(..., sort_keys=True)`. The salt is published when a challenge is claimed or the challenge closes.

Open question: where solvers send claims (an email address or a repository's issue tracker), and whether there is a prize.

```text
CHALLENGE 1 - ciphertext only (q=64, P=256, L=512, one link)
Plaintext: uppercase English in the 6-bit chart.
Commitment: 9161b2c9388c4b266bf7fe651fdf2bc8b67e30fc4989caf2cdaad2c4be883738
link 0: 61 33 65 00 37 50 56 62 75 52 36 03 03 44 25 14 35 63 67 34 56 10 77 14 51 15 54 00 14 26 66 67 66 53 40 10 43 75 67 27 34 25 77 22 02 56 24 10 73 71 71 47 63 01 43 43 74 11 23 36 36 31 22 77 75 11 46 31 37 24 15 37 00 12 72 32 14 66 74 46 23 23 32 37 10 76 37 73 51 01 67 63 37 60 02 10 33 66 16 63 20 16 26 13 55 56 33 21 72 55 07 44 02 35 34 71 46 67 22 15 31 54 24 04 11 03 01 64 37 12 57 02 55 70 75 35 15 41 47 34 27 13 46 50 36 66 27 21 41 56 55 27 40 41 07 27 77 74 46 46 02 45 62 11 73 70 56 74 61 02 72 25 07 60 13 40 00 53 05 77 66 36 07 47 56 05 17 42 64 04 12 11 74 21 05 20 31 61 25 14 56 55 70 66 26 50 42 74 46 51 22 52 71 63 12 77 12 63 65 26 11 06 24 75 63 57 25 50 24 31 74 76 64 75 17 26 62 50 74 77 17 03 27 10 31 22 26 14 21 05 30 23 56 24 24 43 65 20 44 16 76 45 26 75 51 46 25 20 74 73 31 26 02 31 65 31 00 25 52 51 51 45 47 71 16 47 21 01 34 44 67 32 05 46 43 46 64 72 35 34 32 63 36 27 46 33 46 70 45 26 24 50 17 36 64 44 25 20 56 22 53 32 54 14 42 72 43 06 00 26 02 72 12 64 64 56 56 05 67 36 51 20 23 53 16 50 27 24 54 77 02 41 41 63 14 23 36 00 25 14 36 71 01 45 40 24 63 32 65 64 22 32 30 32 42 64 63 10 05 54 15 50 24 17 20 67 43 02 35 02 63 07 04 00 27 47 73 67 23 66 16 52 64 76 50 12 57 36 14 20 15 10 16 63 07 52 70 74 52 17 24 27 11 52 52 45 30 62 25 17 56 22 32 11 26 21 47 00 20 33 33 32 21 64 41 62 33 66 21 13 10 37 74 77 52 46 00 71 07 15 32 76 70 02 06 66 11 66 61 44 40 07 75 00 00 65 16 60 02 52 01 31 07 63 50 04 62 56 24 76 53 06 73 63 74 75 06 34 16 21 76 76 40 57 40 47 41 76 21 61 63 74

CHALLENGE 2 - known plaintext (q=64, P=256, L=512, one link)
Text portion of the plaintext (header and carried table not published):
KNOWN PLAINTEXT CHALLENGE. THE TEXT OF THIS LINK IS PUBLISHED IN FULL. RECOVER THE WALK TABLE, THE COMBINER TABLE AND THE START CELL OF THE KEY THAT ENCRYPTED IT. GOOD LUCK.
Commitment: e155774e5cf2727e7116e928319ac4110c38b27769adc733120932ced01d5846
link 0: 41 62 25 13 73 57 34 33 30 73 06 66 72 45 17 10 22 43 04 77 00 11 72 56 60 31 76 20 74 11 40 77 44 05 27 15 00 50 75 24 56 63 53 03 12 35 13 22 65 60 17 06 05 62 65 27 10 54 07 57 30 46 23 27 05 32 65 65 11 63 65 22 37 45 01 47 35 14 62 43 61 11 36 54 06 52 25 64 07 72 21 01 65 00 41 41 61 56 54 53 40 57 63 70 13 73 22 15 54 73 62 61 52 24 13 66 52 54 53 03 22 00 65 30 36 27 45 24 62 25 10 07 62 71 21 52 67 51 54 75 61 70 50 61 32 50 42 25 42 63 31 41 35 63 27 30 12 75 05 45 16 72 25 72 05 02 33 54 70 63 01 51 24 62 16 16 36 24 16 55 34 76 50 74 15 07 06 42 67 35 36 46 02 54 67 01 51 36 62 77 17 36 70 43 11 17 64 07 42 15 60 74 66 20 37 12 55 64 67 66 75 30 26 50 70 15 52 22 23 06 25 25 64 71 17 72 31 27 36 15 12 33 02 55 12 46 07 65 05 23 04 05 60 17 64 44 05 40 73 13 57 03 44 67 42 33 64 45 27 41 72 41 55 47 30 52 06 60 21 41 54 43 24 67 21 32 74 26 50 16 61 15 62 35 40 22 61 33 45 66 53 74 11 74 32 43 47 32 14 27 27 22 73 67 15 00 55 03 14 22 71 74 07 24 41 37 22 00 45 10 24 46 16 03 67 32 63 71 34 42 44 43 64 13 06 45 60 35 45 61 36 61 73 11 61 70 70 13 65 20 77 30 37 40 10 47 55 50 02 41 33 01 51 37 11 45 33 43 16 42 25 12 13 30 17 56 24 33 77 14 66 70 32 20 66 00 13 25 02 55 00 13 72 44 36 05 44 66 13 43 65 77 21 40 36 74 41 04 57 50 34 76 11 42 16 06 32 63 70 05 36 07 23 32 71 53 63 24 20 65 17 37 77 50 55 40 73 44 73 31 22 31 71 77 56 24 75 36 37 00 35 64 25 05 05 10 72 36 62 00 54 47 45 16 07 25 13 74 32 36 53 21 21 50 44 05 07 56 31 34 42 00 60 51 30 00 01 26 72 33 56 03 52 67 26 11 02 30 07 16 16 36

CHALLENGE q=8 - reduced, known plaintext (q=8, P=32, L=64), decimal
Plaintext: 2 7 4 4 7 0 1 5 1 4 1 5 3 0 7 6 7 3 6 2 4 4 7 0 7 5 2 1 1 0 6 5
Commitment: c38da76b8668ee83aaa175caf0f13cd031e9811cd8c00d15b855f8046dfdf7c1
Ciphertext: 0 3 3 6 7 0 1 3 5 2 4 7 1 7 3 3 5 7 4 0 6 5 5 0 4 4 5 4 6 0 6 5 1 6 0 5 3 4 6 7 7 5 6 7 4 3 0 6 7 3 2 6 4 6 7 1 3 7 4 1 7 4 6 6

CHALLENGE q=12 - reduced, known plaintext (q=12, P=48, L=96), decimal
Plaintext: 5 10 1 5 10 8 6 5 5 9 7 3 0 4 10 10 5 1 0 4 11 8 3 10 4 7 11 5 4 6 1 9 11 1 11 8 1 1 6 6 5 9 7 10 5 5 4 8
Commitment: c06bca7f037d6f2c1eefb91e59feaa40f3146196d7862db6706e0546e8c64ee7
Ciphertext: 10 1 2 4 1 5 4 4 8 10 10 2 6 1 4 6 10 4 2 4 10 2 8 10 5 8 2 11 4 4 3 6 11 9 8 11 5 11 10 1 0 8 0 8 6 3 0 2 10 1 9 0 9 6 9 5 11 6 1 7 0 2 6 3 10 1 8 9 8 9 10 4 9 0 4 6 7 4 10 2 1 9 2 6 2 6 11 1 2 9 7 2 1 8 11 10

CHALLENGE q=16 - reduced, known plaintext (q=16, P=64, L=128), decimal
Plaintext: 1 15 8 12 5 5 5 0 14 11 15 7 0 11 12 2 14 9 1 13 4 1 13 13 0 6 8 14 3 7 4 2 0 8 12 6 6 2 10 0 0 3 10 5 15 0 4 1 13 7 9 5 6 4 9 3 12 13 4 0 1 8 5 12
Commitment: 6e966a779f2eb11f33ac7f9702beb17341ca2067780b28af243b4e46f5f3d93b
Ciphertext: 5 11 9 10 12 8 9 1 12 2 6 8 4 15 11 5 10 5 7 8 15 10 7 5 13 1 10 4 13 6 13 5 6 5 11 4 12 10 2 0 13 2 4 13 7 9 15 8 6 13 0 2 5 6 14 0 0 12 14 6 10 11 6 2 5 7 14 12 2 15 1 1 13 9 3 14 15 11 1 14 10 7 0 13 7 6 0 4 0 5 7 8 14 5 12 10 15 4 7 8 8 9 10 1 15 4 7 10 5 0 5 11 15 13 0 0 0 11 7 4 0 6 8 0 1 4 12 7

CHALLENGE q=24 - reduced, known plaintext (q=24, P=96, L=192), decimal
Plaintext: 22 4 3 3 15 7 6 8 22 21 6 2 12 16 11 19 19 16 7 4 15 4 3 6 8 23 21 7 20 2 17 3 17 23 2 18 22 12 23 0 0 19 4 6 15 5 0 7 4 22 8 14 16 17 13 20 20 1 4 11 14 23 3 0 15 8 1 21 1 13 16 6 2 23 11 15 15 19 2 22 8 13 11 11 12 22 7 0 2 16 0 3 17 22 22 16
Commitment: 7353a93a14150cc101560cd19e9fd9139a8f93c6111efb6e2fa448370217aede
Ciphertext: 9 23 12 15 8 15 5 14 20 6 20 11 6 10 9 1 16 1 7 1 14 18 17 22 1 10 14 23 4 2 0 8 4 12 14 23 9 1 20 9 3 0 13 9 0 3 20 15 1 2 0 12 7 3 8 8 2 1 0 20 13 7 10 2 7 22 0 6 7 14 5 14 17 18 12 9 14 6 13 6 23 15 5 21 11 14 10 8 7 13 6 2 2 12 13 6 11 6 7 2 8 15 22 6 5 0 11 9 4 20 9 18 8 15 1 17 10 10 14 3 21 7 7 10 13 14 13 7 22 2 6 21 18 2 5 17 12 9 23 17 9 1 19 19 0 4 14 0 15 17 8 7 9 5 10 12 22 10 15 14 20 7 21 5 8 21 23 21 6 11 12 21 18 19 14 9 22 15 14 15 20 2 2 10 9 20 15 13 23 16 13 6
```

## 20. Field materials and procedure

The hand profile needs nothing that looks like cryptography, and done this way the only thing ever written is the grid, which is the ciphertext. The disguise is for carrying the kit and passing casual inspection; the work itself is done in private (section 18).

**Kit**

| Item | Use | Cover |
| --- | --- | --- |
| Graph paper | One sheet per link: 64 rows of 8 cells = 512 cells | A puzzle sheet |
| Two d8 dice and a pencil | Pad symbols (two octal digits per roll pair) | Tabletop gaming |
| 64 hand-cut tiles marked 00–77, in a zip bag | Generating and holding the walk and combiner tables | Budget Scrabble |

Cut the tiles from cardstock so all 64 are the same size, thickness and feel; a bent or marked tile can be found by touch, which biases the draws. Shake the bag thoroughly before every draw.

**Tables.** A new table is the tiles drawn from the bag one at a time and laid in a row in drawing order: line 00 first, line 77 last. The walk and combiner tables are kept as two rows of tiles on the table while working and are never written on paper. Between sessions, the current key is stored as a tile layout or a saved-game page (the only key material allowed to exist), and earlier keys are destroyed.

**Encryption.** Hold the message in your head and spell it out one letter at a time. Convert each letter to its 6-bit code, add the pad symbol mod 64, and find the result in the combiner row, all mentally or on the tiles. Shifts are read off the walk row of tiles. The grid is the only thing written. Optionally write each octal digit plus one (1–8), so the sheet reads as a number puzzle, and convert back before transmission.

**Decryption.** The text comes out in order, so a 190-character link (about 30–35 words) can be followed and remembered like a message spelled aloud, with no need to write it down. A slip in the final lookup costs one wrong letter. Two exceptions:

- The carried combiner table and start cell at the front of each link must be exact, since one wrong symbol breaks the next link. Lay them out in tiles as they are decrypted, never on paper.
- Names, numbers, coordinates and code words are hard to hold over an hour of work. Keep them short, or write only those items on one scrap over a hard bare surface and burn it immediately.

The sender's check-decrypt before sending (section 11) follows the same rules.

**Limits of the disguise.** A housemate or a border guard sees a puzzle and a game. A trained investigator who suspects you and finds sheets of uniformly random digits will recognize them for what they are.
