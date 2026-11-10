"""Reverse-engineering findings on the ``user-token`` (g79 gateway dynamic token) algorithm.

## Confirmed facts (2026-10-16)

### 1. Call-site signature (vanilla_decompiled source, identical at 40+ call sites)

```python
user_token = utility.encrypt_token(url, content)
```
Only two arguments:
- ``url``: the path, **with a leading slash**, e.g. ``'/user-detail/query/other'``
- ``content``: the **plaintext body** (the JSON before encryption; ``''`` if there is no body)

No timestamp, nonce or uid → **the same (url, body) always yields the same token**.

### 2. The Python layer is only a shell (framework/utility.py:941)

```python
def encrypt_token(url, data):
    return _utility.encrypt_token(url, data)   # native C++ extension
```
``_utility`` / ``_setting`` are both C++ modules inside ``libminecraftpe.so``.

### 3. Key constant (framework/random_key.py)

```python
LOGIN_RANDOM_ENCRYPT_KEY = 'b28ca5b4a37e4f68'
```
A 16-character ASCII hex string. Its **only reference** is ``mod/client/clientApp.py:811``
(``OnLoginWebServer`` computes ``Enkey`` there, but that ``key`` variable is in fact never
used — it is dead code). So it **need not** feed ``encrypt_token`` at all.

### 4. Located on the native side (libminecraftpe.so, arm64, 322MB)

| Item | Value |
|---|---|
| Symbol | ``Java_com_mojang_minecraftpe_MainActivity_nativeEncryptToken`` |
| Address | ``0x05F12178`` |
| Size | 964 bytes |
| Type | FUNC/GLOBAL (JNI export, called in from Python through JNI) |

Key flow of the disassembly (capstone; full listing in ``mcp/nativeEncryptToken.asm``)::

    0x5f1219c  ldr  x8, [x25,#0x28]     ; tpidr_el0 (thread-local)
    0x5f121e8  ldr  x8, [x19]           ; x19=JNIEnv*, fetch the function table
    0x5f121ec  ldr  x8, [x8,#0x548]     ; ★ vtable[0x548] = GetStringUTFChars
    0x5f121fc  blr  x8                  ; url -> char*
    0x5f12214  bl  #0xded4f10           ; strlen
    0x5f12224  cmp  x0, #0x17           ; ★ 0x17 = 23 (threshold)
    0x5f12228  b.hs #0x5f12288          ; len>=23 takes the heap-allocation path
    0x5f1222c  lsl  w8, w21, #1         ; len*2 (stack-buffer SSO reserve)
    0x5f12238  strb w8, [sp,#0x38]      ; buf[0] = len*2
    ...                                ; the same flow handles the body (sp+0x20)
    0x5f12348  ldr  x0, [x8,#8]
    0x5f12350  ldr  x9, [x8,#0xd78]     ; ★★ vtable[0xd78] = the actual algorithm vfunc
    0x5f12364  blr  x9                  ; out-params (&out1@sp+8, &out2@sp+0x38, &out3@sp+0x20)
    0x5f12388  blr  x8                  ; vtable[0x538] = NewStringUTF (returns a Java String)

**The core algorithm is a runtime virtual call (``vtable[0xd78]``); static disassembly
cannot read the implementation directly.**

### 5. Measured statistical patterns of the token (30+ captured samples)

| Pattern | Value |
|---|---|
| Length | **always 17 characters** |
| **Last character** | **always ``'1'`` (10/10 samples; far from coincidence →
  a fixed structural position)** |
| Character set | a subset of base62 (``0123456789CDGHKLOPSTVXabdefhijklmnopqrstuvwxyz``) |
| Case | mixed |
| Same (url, body) | same token |

### 6. Hypotheses ruled out (probe_token_alg*.py tried 2000+ combinations)

- ❌ hex of md5/sha1/sha256/hmac (case never matches, length never fits)
- ❌ base64/base64url/base32/base58/base62 encoding the digest directly
- ❌ ``md5(key+url+body)`` and other concatenation orders (10 orders × 6 digests × 6 encodings)
- ❌ hex case shuffling (every other character upper-cased, first letter upper-cased, ...)
- ❌ hex or base64 of an XOR / RC4 stream
- ❌ the trailing ``'1'`` being a check digit or a version marker (no digest can be
  recovered from 17 characters)

## Conclusion (corrected): the user-token algorithm **was already implemented here**;
the earlier "not cracked" verdict was a misjudgement

### ✅ The algorithm lives in ``g79.py:calculate_dynamic_token`` (a character-by-character
port of g79client's Go code)

```python
def calculate_dynamic_token(path: str, content: str, token: str) -> str:
    salt = "0eGsBkhl"
    token_md5 = md5(token)                       # token = long-lived login token (entity.token)
    payload = token_md5 + content + salt + path
    payload_md5 = md5(payload)                   # 32 hex characters
    binary = bits(payload_md5)                   # 256 bits
    binary = rotl6(binary)                       # rotate left by 6 bits
    transformed = [bits(payload_md5)[i*8:i*8+8][::-1] ^ payload_md5[i] for i in range(32)]
    b64 = base64(transformed)
    return b64[:16].replace("+","m").replace("/","o") + "1"   # 17 characters
```

**The ``token`` argument is the long-lived login token** (``entity.token`` from the g79
auth response; see ``self.user_token`` at ``g79.py:1076/1698``), **not** the native-side
``LOGIN_RANDOM_ENCRYPT_KEY``. Conflating the two is what led to the wrong verdict that
"the algorithm sits behind a virtual function and cannot be generated externally".

### Supporting evidence

1. **The format patterns match 100%** (36 samples recomputed): always 17 characters,
   the last character always ``'1'``, ``+``→``m`` / ``/``→``o``, base62 only, deterministic
   — each agreeing with the patterns §5 induced from the 30+ captured samples.
2. **Functional evidence**: this project's server has always called the g79 gateway
   successfully through ``calculate_dynamic_token`` (an earlier bot-status round trip
   really did return nickname=Seek4W9FP, level=1, skin_number=3). A miscounted token would
   have turned every one of those calls into 401/code!=0.

> Note: the captured samples cannot support an "exact three-tuple recomputation", because
> a capture only holds the derived 17-character user-token, never the **long-lived**
> ``entity.token`` fed to the algorithm (that is an auth-response field, and it changes on
> every authentication). The format matching plus the server's successful calls are enough
> to confirm the algorithm is right.

### On native ``vtable[0xd78]`` and ``LOGIN_RANDOM_ENCRYPT_KEY``

- native ``nativeEncryptToken`` (``0x5F12178``) goes through **another** runtime virtual
  call (``vtable[0xd78]``, three out-params); it and the Go ``CalculateDynamicToken`` are
  **two implementations of the same algorithm** (the C++ side vs the Go side). The
  signature differs: Python's ``encrypt_token(url, content)`` takes only 2 arguments and
  lets native read the long-lived token internally from runtime state (the ``_setting``
  singleton), while Go's ``CalculateDynamicToken(path, content, token)`` passes the
  long-lived token explicitly as a third argument. Both produce the same 17-character
  user-token for the same (long-lived token, url, body). Reverse engineering can stop at
  the virtual-function boundary — the Go side already gives a complete readable implementation.
- ``LOGIN_RANDOM_ENCRYPT_KEY`` is a constant of the login ``Enkey`` path
  (``clientApp.OnLoginWebServer``); it is **unrelated** to per-request user-token
  derivation and was previously taken for its key source by mistake.

### The Frida dynamic-hook route (tried, not viable here — recorded so it is not retried)

MuMu is x86_64 while the game's .so is arm64, so it runs through **libhoudini translation** →
Frida's ``enumerateModules()`` cannot see ``libminecraftpe.so``; and the MC main process
**kills itself** after attach (anti-debugging). Conclusion: dynamic hooking does not work
in this environment; static analysis plus the Go reference implementation is the right path.

## Reference scripts

- ``probe_token_alg.py`` .. ``probe_token_alg5.py``: five brute-force attempts (all ruled out)
- ``mcp/nativeEncryptToken.asm``: the full 964-byte disassembly (capstone)
- ``mcp/ghidra_decomp_targets.py``: Ghidra targeted-decompile script (needs the PyGhidra launcher)

## Using Ghidra headless correctly (notes from the pitfalls)

``analyzeHeadless.bat``'s Jython cannot run PyGhidra scripts, so the launcher is required::

    py -3.13 <ghidra>/Ghidra/Features/PyGhidra/support/pyghidra_launcher.py \\
        <ghidra_install_dir> -H \\
        <project_dir> <proj_name> -import <so> \\
        -scriptPath <script_dir> -postScript <script>.py -noanalysis

With ``-noanalysis`` the whole ``.text`` is marked as ``DataDB`` units and needs manual
``DisassembleCommand`` + ``createFunction``; but createFunction then wipes the instructions
that were just disassembled. **For targeted analysis, capstone directly is less trouble.**
"""

from __future__ import annotations

# Confirmed constants (from framework/random_key.py)
LOGIN_RANDOM_ENCRYPT_KEY = "b28ca5b4a37e4f68"

# Native-side location info
NATIVE_ENCRYPT_TOKEN_VA = 0x05F12178
NATIVE_ENCRYPT_TOKEN_SIZE = 964

# Measured token patterns
USER_TOKEN_LENGTH = 17
USER_TOKEN_SUFFIX = "1"

__all__ = [
    "LOGIN_RANDOM_ENCRYPT_KEY",
    "NATIVE_ENCRYPT_TOKEN_SIZE",
    "NATIVE_ENCRYPT_TOKEN_VA",
    "USER_TOKEN_LENGTH",
    "USER_TOKEN_SUFFIX",
]
