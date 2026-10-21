# Attack programs

Guess-and-determine key recovery against reduced-size Walk-Pad blocks. Each program builds its own random instance (random tables, start cell, pad and plaintext from the given seed), runs the search from the true start cell and from `n_wrong` wrong ones, and reports how many search nodes each took and whether the recovered pad was correct. They do not read the challenge files; they measure how attack cost grows with the alphabet size q.

Build with any C compiler:

```
cc -O2 -o guess_determine guess_determine.c
```

| Program | Attack | Arguments |
| --- | --- | --- |
| `guess_determine.c` | Known plaintext against the standard v1.3 block: guess the walk table one entry at a time while following the walk, then check the combiner is a consistent permutation. | `q P seed n_wrong node_cap` |
| `known_combiner.c` | The same, with the attacker also given the combiner table (models the chain exposure in SPEC section 13). | `q P seed n_wrong node_cap known_c` |
| `walk_everything.c` | Against an experimental authenticated mode where pads and bodies are both walked, with a running total; not part of v1.3. | `q P seed n_wrong node_cap order` |

Example: `./guess_determine 8 32 1 5 2000000` (8-symbol alphabet, 32-symbol pad, seed 1, five wrong start cells, at most two million nodes per run).

Cost in nodes grows roughly with q! across q = 6 to 10. Results are summarized in SPEC section 15. Better attacks are the point of the challenge.
