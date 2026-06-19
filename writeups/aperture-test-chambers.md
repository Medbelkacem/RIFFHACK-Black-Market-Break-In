# Aperture Test Chambers (Lights Out × 20)

- **Platform:** Riffhack CTF (Biterra) — team `ZKaMYBbs`
- **Author:** CL4Y
- **Target service:** `107.170.0.145:9000` (TCP)
- **Category:** Misc / Crypto-adjacent (linear algebra over GF(2))
- **Flag:** `bitctf{gl4d0s_s4ys_y0u_p4ss3d_4ll_ch4mb3rs}`
  *(server emitted with doubled braces — `bitctf{{...}}` — almost certainly an f-string artifact; the canonical single-brace form is the intended flag.)*

## TL;DR

The service serves 20 back-to-back **Lights Out** boards (sizes 5×5 to 7×7). Pressing
a panel toggles itself and its four orthogonal neighbours. Each board reduces to a
linear system `A · x ≡ b (mod 2)` where:

- `A` is an `n²×n²` symmetric 0/1 matrix encoding the press-affects-tile relation,
- `b` is the flattened starting grid,
- `x` is the unknown press mask.

Solve with Gaussian elimination over **GF(2)**, ship the press list back, repeat 20×,
the server replies with the flag.

## Protocol

The server is line-oriented over plain TCP:

```
APERTURE SCIENCE TEST FACILITY v1.0
GLaDOS: Welcome, test subject. Twenty chambers stand between you and the flag.
GLaDOS: Each chamber is a grid of illuminated panels. Pressing a panel toggles it
GLaDOS:   and each of its orthogonal neighbours. Extinguish all panels to proceed.
GLaDOS: Send PRESSES <count> then <count> lines of '<row> <col>' (0-indexed).
---
CHAMBER 1/20
GRID 6
1 1 0 1 0 0
0 1 0 0 0 1
...
AWAITING SOLUTION
```

Reply format:

```
PRESSES <k>
<r0> <c0>
<r1> <c1>
...
```

Server echoes `OK` after a valid press list and proceeds to the next chamber.
After chamber 20 it prints the flag and quotes *Portal*'s end credits:

```
FLAG bitctf{{gl4d0s_s4ys_y0u_p4ss3d_4ll_ch4mb3rs}}
GLaDOS: This was a triumph. I'm making a note here: HUGE SUCCESS.
```

## Solving One Board

For an `n×n` board, number the cells `i = r·n + c` (`0 ≤ i < n²`). Build the
adjacency-plus-self matrix `A ∈ GF(2)^{n²×n²}`:

- For every cell `i`, set `A[i][i] = 1` and `A[i][j] = 1` for each orthogonal
  neighbour `j` (in-bounds only — edges naturally have fewer neighbours).

Because press-effects are symmetric and commutative on/off toggles, each press is
a bit in `x`, and the requirement "all panels off" becomes `A · x = b` where `b`
is the initial grid (each lit tile must be toggled an odd number of times).

Standard row-reduce, back-substitute, emit `(r, c)` for every set bit of `x`.

### Why does this always have a solution here?

For some `n` (notably 4, 5, 9, 11, …) the Lights Out matrix has a non-trivial
kernel, so a board is solvable only if `b` lies in the column space of `A`. The
20 chambers used `n ∈ {5, 6, 7}` and every one was consistent — i.e. the
challenge generator picked solvable boards. If a chamber had been unsolvable, you
would have detected an inconsistent row during elimination (a zero LHS with a
non-zero RHS) and could have aborted gracefully — my solver returns `None` in
that case.

## Exploit

```python
# scratch/aperture_solver.py — abridged
def solve_lights_out(grid, n):
    size = n * n
    rows = []
    for i in range(size):
        r, c = divmod(i, n)
        row = [0] * (size + 1)
        for ar, ac in [(r,c),(r-1,c),(r+1,c),(r,c-1),(r,c+1)]:
            if 0 <= ar < n and 0 <= ac < n:
                row[ar*n + ac] = 1
        row[size] = grid[i]
        rows.append(row)
    # Gauss-Jordan over GF(2)
    pivot_col = [-1]*size; r = 0
    for col in range(size):
        piv = next((rr for rr in range(r, size) if rows[rr][col]), None)
        if piv is None: continue
        rows[r], rows[piv] = rows[piv], rows[r]
        for rr in range(size):
            if rr != r and rows[rr][col]:
                for cc in range(col, size+1):
                    rows[rr][cc] ^= rows[r][cc]
        pivot_col[r] = col; r += 1
    for rr in range(r, size):
        if rows[rr][size]:
            return None      # inconsistent → board not solvable
    sol = [0]*size
    for i in range(r):
        sol[pivot_col[i]] = rows[i][size]
    return [divmod(i, n) for i, v in enumerate(sol) if v]
```

Driver: connect via `socket.create_connection`, for each of 20 chambers read
until `AWAITING SOLUTION`, parse the latest `GRID n` block, solve, send back
`PRESSES <k>` + one `r c` per line, then drain the socket for the flag.

```
$ python3 aperture_solver.py
[chamber 1] grid 6x6
[chamber 2] grid 7x7
...
[chamber 20] grid 7x7
OK
FLAG bitctf{{gl4d0s_s4ys_y0u_p4ss3d_4ll_ch4mb3rs}}
```

## Why the `bitctf{{...}}` doubled braces?

The flag string almost certainly comes from a Python f-string like
`f"FLAG bitctf{{{name}}}"` where the author intended `{{` and `}}` to emit
literal braces around `{name}`. But because the value of `name` was already
`gl4d0s_s4ys_y0u_p4ss3d_4ll_ch4mb3rs` (no braces) and the template was
`bitctf{{...}}` *without* an inner `{name}` placeholder, the doubled braces leaked
verbatim. The intended (and likely accepted) flag is therefore the single-brace
form:

```
bitctf{gl4d0s_s4ys_y0u_p4ss3d_4ll_ch4mb3rs}
```

## Notes / Pitfalls

- **0-indexing** matters — the server told us so explicitly. Off-by-one would
  silently corrupt a press list and the chamber would reject the answer.
- **All 20 in one TCP session.** Don't reconnect between chambers; the server
  tracks state on the open socket.
- **No need for short solutions.** Gaussian elimination already returns the
  *minimum-weight* solution within a particular free-variable choice; the
  challenge does not bound the press count.
- **Speed is fine** — `n ≤ 7`, so the matrix is ≤ 49×49, solved instantly.

## Take-aways

Whenever a "press toggles itself and neighbours, make everything 0/1" puzzle
appears, the answer is almost always: **build the adjacency matrix in GF(2),
solve linearly**. This applies to:

- Lights Out clones (classic 5×5, variants),
- "XOR sensor grid" forensics challenges,
- some "circuit" puzzle CTFs where each switch flips a known subset.
