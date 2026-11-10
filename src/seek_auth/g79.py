"""SeekAuth — the G79 protocol client (NetEase "Minecraft" China edition PE client).

This is a **byte-for-byte faithful** port of the Go module ``github.com/Yeah114/g79client``:

* ``crypto.go``             -> :func:`g79_http_encrypt` / :func:`g79_http_decrypt` /
  :func:`calculate_dynamic_token` / :func:`get_valid_json` / ``x19_*`` / pkcs7
* ``utils/encryption.go``   -> :func:`pe_auth_sign` (a custom hash, **not** a standard one)
* ``client_core.go``        -> :class:`G79Client` / :data:`ENGINE_VERSION`
* ``engine_consts.go``      -> library hash / signature hash / step constants
* ``globals.go``            -> fetching the release JSON and patch metadata
* ``auth.go``               -> :meth:`G79Client.authenticate_with_cookie` and friends
* ``user_get_detail.go``    -> :meth:`G79Client.get_user_detail`
* ``rental_search_by_name.go`` / ``rental_enter_world.go`` /
  ``user_update_nickname.go`` / ``user_settings_get.go`` / ``user_settings_set.go`` /
  ``download_get_info.go`` / ``user_item_purchase.go`` / ``skin_change.go``
* ``auth/get_skin_info.go`` -> :meth:`G79Client.get_skin_info`

Porting principles
------------------
1. **Byte-identical encryption.** AES-CBC with a 16-entry hex key table (selected by
   ``(flag >> 4) & 0x0F``), a 16-byte ASCII IV, and the flag in the last byte.
2. **Explicit masks for Go's uint32/uint64 wrap-around** (``& 0xFFFFFFFF``).
3. **JSON serialization aligned with Go**: ``map[string]any`` sorts its keys (``sort_keys=True``),
   a struct keeps declaration order; Go ``encoding/json``'s HTML escaping is reproduced as well
   (``<`` ``>`` ``&`` -> ``\\u003c`` ``\\u003e`` ``\\u0026``) plus the U+2028/U+2029 escapes.
   This is **mandatory**: ``SendAuthV2Request`` computes the dynamic token from the request
   bytes, so a different key order breaks the signature outright.
4. **Fully async**, using only the standard library + ``httpx`` + ``cryptography``.
5. Errors always raise :class:`G79Error`, messages kept close to Go's (``code: N`` format).

Known, intentional differences from Go
--------------------------------------
* Go fails as a whole when the X19 release JSON cannot be fetched inside ``NewClient``; this
  port degrades that to "warn + skip", because no public API of this module depends on it (only
  X19 auth and ``user_item_purchase`` do), so an X19 upstream hiccup cannot disable the client.
  The G79 release JSON is still strict: CoreServerURL / WebServerUrl / ApiGatewayUrl /
  AuthServerURL all come from it.
* Go's ``G79AuthenticateWithCookie`` uses ``http.DefaultClient`` while ``SendAuthV2Request``
  uses ``c.httpClient``; this port uses a single ``httpx.AsyncClient`` for both.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import io
import json
import secrets
import struct
import uuid
import zipfile
from typing import Any

import httpx
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .logging_setup import get_logger

log = get_logger(__name__)

# ─────────────────────────── Constants (engine_consts.go) ───────────────────────────

ENGINE_VERSION = "3.10.0.300878"
"""Engine version, used for **PE auth** (``pe-authentication``) and the resource hash.

⚠ **Do not change it to the mobile MC version number**. Measured (2026-10-27, same fbtoken):

    engine=3.10.0.300878  -> PE auth failed code 2001 "client version too low, please upgrade"
    engine=3.9.15.297900  -> same as above
    engine=3.6.5.281774   -> success uid=3100350069

So ``pe-authentication`` belongs to the **PC launcher (WPFLauncher) branch** and only accepts
3.6.x; feeding it a mobile 3.9/3.10 gets judged "version too low" -- counter-intuitive but measured.

**For the mobile MC version see** :data:`AUTH_V2_CLIENT_VERSION` /
:data:`AUTH_V2_PATCH_VERSION`; those two are for ``authentication-v2`` only.
"""

AUTH_V2_CLIENT_VERSION = "3.10.0.300878"
"""The ``engineVersion`` of ``authentication-v2``.

**Must equal :data:`ENGINE_VERSION` (the version PE auth used when it created the session); the
mobile 3.10/3.9 must not go here.** Measured (2026-10-27, same uid=3100350069, same fbtoken,
same target server 94605989 / mc_version=1.21.130), four combinations:

    engineVersion=3.6.5.281774  patchVersion=3.6.56.288487   -> HTTP 200, chain_len=2 ✅
    engineVersion=3.6.5.281774  patchVersion=3.10.1.301063   -> HTTP 200, chain_len=2 ✅
    engineVersion=3.10.0.300878 patchVersion=3.10.1.301063   -> HTTP 401, empty body ❌
    engineVersion=3.10.0.300878 patchVersion=3.6.56.288487   -> HTTP 401, empty body ❌

Conclusion: **the server checks that engineVersion matches the session creator**. Our session
was created by PE auth (PC launcher 3.6.x branch), so AuthV2 must report 3.6.x as well; a mobile
version is judged "session does not match client" and rejected with a bare 401 (empty body, which
the client side surfaces as ``SendAuthV2Request: payload too short``).

A real 3.10 client can report 3.10 because **its session was itself created by a 3.10 client**.

``patchVersion`` is exempt (3.6 and 3.10 both pass); the newest value is fine -- see
:data:`AUTH_V2_PATCH_VERSION`.
"""

AUTH_V2_PATCH_VERSION = "3.10.6.301389"
"""The ``patchVersion`` of ``authentication-v2``.

Taken from the last entry of the ``android`` array in ``g79_rn_patchlist`` (currently the newest;
only one of the 147 entries is ``3.10.x``), matching the value measured on a 3.10 client.

Both 3.6 and 3.10 yield a chain, so the newest value is used to make the server allocate world
resources for the new version."""

G79_LIBRARY_HASH = "c4fbc0625fe2ff8f3aa0b931feb04217"
G79_SIGNATURE_HASH = "2b3e7ca013bb30a74d822579860c042b"
G79_BASE_MCP_HASH = ""
G79_ANDROID_STEP = "0"
G79_ANDROID_STEP2 = "0"
G79_ANDROID_MESSAGE_TAG = "dashen_cloudgame"

G79_LATEST_VERSION_FALLBACK = "3.10.6.301389"

PREFERRED_PATCH_VERSION = "3.10.6.301389"
"""Preferred patch version: kept in sync with the 3.10 client constant built into Shuttler, so
that the patchVersion in the chain and in the MCP check digits match (anti-cheat flags it)."""
"""Patch version fallback (PE auth path; same branch as :data:`ENGINE_VERSION`)."""

PATCH_RESOURCES_HASH_FALLBACK = "548ddfa2a67139a3e1b49dd812267445"

X19_DEFAULT_VERSION = "1.15.7.20505"

# Defaults printed by [DBG2] in the reference binary (Go uses these when patch fetching fails).
DEFAULT_DBG2 = {
    "EngineVersion": ENGINE_VERSION,
    "G79LatestVersion": G79_LATEST_VERSION_FALLBACK,
    "patchResourcesHash": PATCH_RESOURCES_HASH_FALLBACK,
    "libraryHash": G79_LIBRARY_HASH,
    "sigHash": G79_SIGNATURE_HASH,
}

G79_PATCH_LIST_URL = "https://g79.update.netease.com/patch_list/production/g79_rn_patchlist"
G79_RELEASE_JSON_URL = "https://g79.update.netease.com/serverlist/adr_release.0.17.json"
X19_RELEASE_JSON_URL = "https://x19.update.netease.com/serverlist/release.json"
X19_PATCH_LIST_URL = "https://x19.update.netease.com/pl/x19_java_patchlist"

USER_AGENT_LIBHTTP = "libhttpclient/1.0.0.0"
USER_AGENT_WPF = "WPFLauncher/0.0.0.0"

DEFAULT_SKIN_ITEM_ID = "4672395235685216085"

_DEFAULT_TIMEOUT = 30.0

# ─────────────────────────── Errors ───────────────────────────


class G79Error(Exception):
    """Any failure in the G79 protocol layer (network, parsing, crypto, upstream code != 0)."""


# ─────────────────────────── Pure functions: AES key tables ───────────────────────────

# crypto.go: var keys
AES_KEYS: tuple[str, ...] = (
    "60F1E0D1FD635362430747215CF1C2FF",
    "EA5B62D27D0338374852C4B9469D7AC6",
    "17238D55501C5F020B155FB3303591E6",
    "8C5CEAE0F443E006A050266F73ADD5B0",
    "1C02CE22FB22F0E72060217418F351F3",
    "9A01773FEBB0CFE0EBDBF37F4D23C27F",
    "43F32300BF252CC320E2572ACE766367",
    "07F161011B3101F1ED0301735631E734",
    "0454E7707A5F37565601E100406060AF",
    "647554BAD3100C43C16660F002CC10F3",
    "E157213170F842382032564265B0B043",
    "914FC59311B04151393EF6896A847636",
    "0710C0205D224237025323265C145FA1",
    "054E6F01165267025C3111F562A921E9",
    "722D1789E792E2CA0D5322211FD0F5AE",
    "91F7C751FCF671F34943430772341799",
)

# crypto.go: var x19Keys
X19_KEYS: tuple[str, ...] = (
    "MK6mipwmOUedplb6",
    "OtEylfId6dyhrfdn",
    "VNbhn5mvUaQaeOo9",
    "bIEoQGQYjKd02U0J",
    "fuaJrPwaH2cfXXLP",
    "LEkdyiroouKQ4XN1",
    "jM1h27H4UROu427W",
    "DhReQada7gZybTDk",
    "ZGXfpSTYUvcdKqdY",
    "AZwKf7MWZrJpGR5W",
    "amuvbcHw38TcSyPU",
    "SI4QotspbjhyFdT0",
    "VP4dhjKnDGlSJtbB",
    "UXDZx4KhZywQ2tcn",
    "NIK73ZNvNqzva4kd",
    "WeiW7qU766Q1YQZI",
)

# crypto.go: the charset randomString draws from
_RANDOM_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

_BLOCK_SIZE = 16


def _decode_uni_sauth_debug(raw: str) -> dict[str, Any]:
    """Decode the ``debug_message`` of a ``uni_sauth`` response.

    Measured format: base64-wrapped JSON whose Chinese text is **GBK** encoded (decoding it as
    UTF-8 gives mojibake). The content looks like::

        {"code":10204,"result":[],"message":"verification failed"}

    Some scenarios also carry SMS instructions here ("send xxx to xxx"). When it cannot be
    decoded, an empty dict is returned and the caller falls back to the generic text.
    """
    import base64 as _b64
    import json as _json

    text = (raw or "").strip()
    if not text:
        return {}
    try:
        blob = _b64.b64decode(text, validate=False)
    except Exception:
        return {}
    # Try UTF-8 first, then GBK (the Chinese text was measured to be GBK)
    for enc in ("utf-8", "gbk"):
        try:
            obj = _json.loads(blob.decode(enc))
        except Exception:
            continue
        if isinstance(obj, dict):
            return obj
    return {}


def _sms_verify_hint(debug: dict[str, Any], raw_msg: str) -> str:
    """Extract an actionable "SMS verification" hint from the ``uni_sauth`` debug_message.

    NetEase risk-control / verification scenarios put concrete instructions into debug_message
    (for example "please send the digit SMS xxx to NetEase"). The user must **send the SMS
    first, then retry** -- show the text as-is instead of leaving the user waiting.
    """
    msg = str(debug.get("message") or raw_msg or "").strip()
    if not msg:
        return ""
    # NetEase replies in Chinese, so the SMS / digit verification keywords below stay Chinese
    if not any(k in msg for k in ("短信", "发送", "数字")):
        return ""
    return msg


def _explain_login_otp_code(code: int, raw: str) -> str:
    """Replace the misleading ``login-otp`` text with an honest, actionable explanation.

    NetEase answers risk-control scenarios with generic text; the most misleading one in practice
    is ``code 32``: it claims 'the server is under maintenance, please try again later', which
    makes people think waiting will help. Real maintenance is unlikely: the same account was
    compared against the Go reference (funauth-2 g79client), where MPay clearly answered
    ``code=1351 account has a security risk``; NetEase also says 'or the original fixed device'.

    So a risk-control error is **not** disguised as maintenance here; it is reported honestly
    with actionable advice. Real maintenance still shows the word 'maintenance' in the raw text.

    ``code 105`` 'the account is abnormal, cannot log in': the account is in a bad state on the
    NetEase side (deleted, restricted); logging in again usually fixes it (:func:`_parse_done`).
    """
    if code == 32:
        return (
            f"NetEase refused this credential (login-otp code {code}, raw: {raw or 'empty'})."
            "Hint: although this code mentions 'server under maintenance', it is mostly a"
            "**risk-control block** -- the device fingerprint / egress IP is judged risky, not a"
            "real maintenance. Use 'paste a Cookie' instead (credentials produced by a real"
            "client login count as the 'original fixed device' NetEase accepts); repeated"
            "retries usually do nothing and can make the risk control worse."
        )
    if code == 105:
        return (
            f"NetEase returned an abnormal account (login-otp code {code}, raw: {raw or 'empty'})."
            "This is usually a state problem on the NetEase side (deleted / restricted),"
            "logging in once more may fix it; if it keeps failing, switch to 'paste a Cookie'"
            "or try another account."
        )
    return raw


def _random_string(length: int) -> str:
    """Equivalent of Go ``randomString``: draws ``[a-zA-Z0-9]`` uniformly from crypto/rand."""
    return "".join(secrets.choice(_RANDOM_CHARSET) for _ in range(length))


def _random_bytes(length: int) -> bytes:
    return secrets.token_bytes(length)


def _cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(data) % _BLOCK_SIZE != 0:
        # Go's cipher.CBCDecrypter.CryptBlocks panics with the same message
        raise G79Error("crypto/cipher: input not full blocks")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def g79_http_encrypt(body: bytes, *, version: int = 0x0C) -> bytes:
    """Byte-for-byte port of ``g79client.G79HttpEncrypt``.

    Layout::

        buffer = body || randomString(16) || 0x00 padding up to a multiple of 16 bytes
        flag   = (rand[0,15) << 4) | 0x0C
        iv     = randomString(16)   # 16 ASCII bytes
        result = iv || AES-CBC(key[flag>>4 & 0x0F], iv, buffer) || flag

    Note the padding is **0x00 bytes**, not PKCS#7, and the random suffix is never removed
    (the decrypt side only trims trailing 0x00; callers cut the JSON boundary via
    :func:`get_valid_json`).
    """
    target_len = ((len(body) + _BLOCK_SIZE + _BLOCK_SIZE - 1) // _BLOCK_SIZE) * _BLOCK_SIZE
    buffer = bytearray(target_len)
    buffer[: len(body)] = body

    tail = _random_string(16).encode("ascii")
    buffer[len(body) : len(body) + len(tail)] = tail

    high_nibble = secrets.randbelow(15)  # Go: rand.Int(rand.Reader, big.NewInt(15)) → [0,15)
    flag = ((high_nibble << 4) | (version & 0x0F)) & 0xFF

    iv = _random_string(16).encode("ascii")
    key_index = (flag >> 4) & 0x0F
    key = bytes.fromhex(AES_KEYS[key_index])

    cipher_text = _cbc_encrypt(key, iv, bytes(buffer))
    return iv + cipher_text + bytes([flag])


def g79_http_decrypt(payload: bytes) -> bytes:
    """Byte-for-byte port of ``g79client.G79HttpDecrypt``.

    Trims **all** trailing 0x00 bytes; if everything is 0x00, an empty byte string is returned.
    The random suffix is kept, so callers must cut the JSON boundary via :func:`get_valid_json`.
    """
    if len(payload) < 18:
        raise G79Error("payload too short")

    flag = payload[-1]
    iv = payload[:16]
    cipher_text = payload[16:-1]

    key_index = (flag >> 4) & 0x0F
    key = bytes.fromhex(AES_KEYS[key_index])

    plain = _cbc_decrypt(key, iv, cipher_text)

    last_non_zero = len(plain) - 1
    while last_non_zero >= 0 and plain[last_non_zero] == 0:
        last_non_zero -= 1
    if last_non_zero < 0:
        return b""
    return plain[: last_non_zero + 1]


def calculate_dynamic_token(path: str, content: str, token: str) -> str:
    """Character-for-character port of ``g79client.CalculateDynamicToken``.

    ``md5(token)`` hex + content + ``"0eGsBkhl"`` + ``TrimSuffix(path, "?")``
    -> md5 -> 32 hex characters expanded into a 256-bit binary string -> rotate left by 6
    -> per 8 bits, regroup as "bit j <- section[7-j]" and XOR with the original hex bytes
    -> base64 -> first 16 characters, ``+``->``m``, ``/``->``o``, then append ``"1"``.
    """
    salt = "0eGsBkhl"

    token_md5 = hashlib.md5(token.encode("utf-8")).hexdigest()

    # Go: strings.TrimSuffix(path, "?") removes **one** trailing question mark
    trimmed_path = path[:-1] if path.endswith("?") else path

    payload = token_md5 + content + salt + trimmed_path
    payload_md5 = hashlib.md5(payload.encode("utf-8")).hexdigest()

    binary_string = "".join(f"{b:08b}" for b in payload_md5.encode("ascii"))
    binary_string = binary_string[6:] + binary_string[:6]

    transformed = bytearray(payload_md5.encode("ascii"))
    for i in range(len(transformed)):
        section = binary_string[i * 8 : i * 8 + 8]
        reversed_byte = 0
        for j in range(8):
            if section[7 - j] == "1":
                reversed_byte |= 1 << j
        transformed[i] = reversed_byte ^ transformed[i]

    b64 = base64.b64encode(bytes(transformed)).decode("ascii")
    return b64[:16].replace("+", "m").replace("/", "o") + "1"


def get_valid_json(data: bytes) -> bytes:
    """Byte-for-byte port of ``g79client.GetValidJSON``.

    Truncates at the **first** position where ``i != 0`` and the brace depth is back to 0; if
    there is none, the input is returned as-is. Non-JSON input therefore yields the leading
    bytes (e.g. ``b"not json at all"`` -> ``b"not"``) -- that is Go's behaviour, kept as is.
    """
    blocks_count = 0
    readable_length = 0

    for i, b in enumerate(data):
        if b == 0x7B:  # '{'
            blocks_count += 1
        elif b == 0x7D:  # '}'
            blocks_count -= 1

        if blocks_count == 0 and i != 0:
            readable_length = i + 1
            break

    if readable_length != 0:
        return data[:readable_length]
    return data


def _load_json_object(body: bytes, what: str) -> dict[str, str]:
    """Read an upstream JSON response as ``dict[str, str]``.

    ``json.loads`` returns ``Any`` and a plain return trips mypy strict with ``no-any-return``;
    so the value is validated into an object explicitly, and anything that is not an object
    (array, scalar, null) becomes a :class:`G79Error` -- when upstream returns an unexpected
    shape, callers get one uniform exception instead of a value of unknown type.
    """
    try:
        parsed = json.loads(body)
    except ValueError as exc:
        raise G79Error(f"failed to parse {what}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise G79Error(f"{what} is not a JSON object: {type(parsed).__name__}")
    return {str(k): str(v) for k, v in parsed.items()}


def _load_json_any(body: bytes, what: str) -> dict[str, Any]:
    """Read an upstream JSON response as ``dict[str, Any]`` (value types are not narrowed).

    Difference from :func:`_load_json_object`: the original value types are kept here (entity
    fields carry numbers, booleans and nested objects) and only the outermost JSON object is
    enforced. Same purpose: silencing ``no-any-return``.
    """
    try:
        parsed = json.loads(body)
    except ValueError as exc:
        raise G79Error(f"failed to parse {what}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise G79Error(f"{what} is not a JSON object: {type(parsed).__name__}")
    return {str(k): v for k, v in parsed.items()}


# ─────────────────────────── PeAuthSign (a custom hash) ───────────────────────────

# utils/encryption.go: the constant table b inside PeAuthSign (80 bytes)
_PE_B: bytes = bytes(
    [
        0x62, 0x25, 0x1E, 0xF6, 0x40, 0xB3, 0x40, 0xC0, 0x51, 0x5A, 0x5E, 0x26, 0xAA, 0xC7, 0xB6, 0xE9,
        0x44, 0xEA, 0xBE, 0xA4, 0xA9, 0xCF, 0xDE, 0x4B, 0x60, 0x4B, 0xBB, 0xF6, 0x70, 0xBC, 0xBF, 0xBE,
        0xC3, 0x59, 0x5B, 0x65, 0x92, 0xCC, 0x0C, 0x8F, 0x7D, 0xF4, 0xEF, 0xFF, 0xD1, 0x5D, 0x84, 0x85,
        0xC6, 0x7E, 0x9B, 0x28, 0xFA, 0x27, 0xA1, 0xEA, 0x85, 0x30, 0xEF, 0xD4, 0x05, 0x1D, 0x88, 0x04,
        0xE6, 0xCD, 0xE1, 0x21, 0xD6, 0x07, 0x37, 0xC3, 0x87, 0x0D, 0xD5, 0xF4, 0xED, 0x14, 0x5A, 0x45,
    ]
)

# utils/encryption.go: qTable (20 bytes, shift amounts)
_PE_QTABLE: bytes = bytes(
    [
        0x01, 0x06, 0x0A, 0x0D, 0x02, 0x05, 0x09, 0x0E, 0x04, 0x07,
        0x0B, 0x03, 0x03, 0x08, 0x0B, 0x05, 0x01, 0x07, 0x0B, 0x0E,
    ]
)

_MASK32 = 0xFFFFFFFF


def _u32(value: int) -> int:
    """Equivalent of ``uint32(uint64(a) & 0xffffffff)`` in Go."""
    return value & _MASK32


def pe_auth_sign(v: str, sp: int, tr: int) -> str:
    """Byte-for-byte port of ``utils.PeAuthSign`` -- **a custom hash, not a standard algorithm**.

    Steps:

    1. Validate ``sp >= 0`` and ``tr > 0``; ``16*sp+16 <= 80``, ``4*sp+4 <= 20``.
    2. Pad ``v`` with ``"0"`` to a 4-byte boundary by **byte length** (Go's ``len(string)``.
    3. Pack every 4 bytes **big-endian** into a ``uint32`` in ``p``; pad ``len(p)`` with
       ``0xabcde987`` to 64 words (**note**: ``len(p)==0`` -> ``0 % 64 == 0`` -> **no pad**).
    4. From offset ``16*sp`` of ``b`` read 4 seeds ``c[0..3]`` **little-endian**; from offset
       ``4*sp`` of ``qTable`` take the 4 shift amounts.
    5. ``tr`` rounds of 4 mixing steps per ``p`` stride of 4, each wrapped with ``& 0xFFFFFFFF``.
    6. Pack ``r,u,x,z`` **little-endian** into 16 bytes, then base64.

    :raises G79Error: a parameter is out of range; the message matches Go.
    """
    if sp < 0 or tr <= 0:
        raise G79Error("invalid sp/tr parameters")
    if 16 * sp + 16 > len(_PE_B):
        raise G79Error(f"sp={sp} out of range for constant table")
    if 4 * sp + 4 > len(_PE_QTABLE):
        raise G79Error(f"sp={sp} out of range for shift table")

    data = v.encode("utf-8")
    # Go's len(v) is a byte length, so the padding is per byte
    if rem := len(data) % 4:
        data += b"0" * (4 - rem)

    p: list[int] = []
    for i in range(0, len(data), 4):
        p.append((data[i] << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3])

    if rem := len(p) % 64:
        p.extend([0xABCDE987] * (64 - rem))

    c = [
        int.from_bytes(_PE_B[16 * sp + i * 4 : 16 * sp + i * 4 + 4], "little") for i in range(4)
    ]
    q = list(_PE_QTABLE[4 * sp : 4 * sp + 4])

    r = 0x67452301
    u = 0xEFCDAB89
    x = 0x98BADCFE
    z = 0x10325476

    for _ in range(tr):
        for j in range(0, len(p), 4):
            pj = p[j]
            a1 = r + ((u & x) | (~u & _MASK32 & z))
            r = _u32(u + ((a1 + pj + c[0]) << q[0]))

            a2 = r + ((u & z) | (~z & _MASK32 & x))
            u = _u32(u + ((a2 + pj + c[1]) << q[1]))

            a3 = r + (u ^ x ^ z)
            x = _u32(u + ((a3 + pj + c[2]) << q[2]))

            term = _u32(x ^ (u | z))
            a4 = r + term
            z = _u32(u + ((a4 + pj + c[3]) << q[3]))

    out = struct.pack("<IIII", r, u, x, z)
    return base64.b64encode(out).decode("ascii")


# ─────────────────────────── X19 variant ───────────────────────────


def pkcs7_pad(data: bytes, block_size: int = _BLOCK_SIZE) -> bytes:
    pad_len = block_size - len(data) % block_size
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = _BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise G79Error("invalid padding")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size or pad_len > len(data):
        raise G79Error("invalid padding size")
    if any(b != pad_len for b in data[len(data) - pad_len :]):
        raise G79Error("invalid padding content")
    return data[: len(data) - pad_len]


def x19_http_encrypt(body: bytes) -> bytes:
    """``g79client.X19HttpEncrypt``: the PC launcher variant (PKCS#7 + plaintext ASCII key)."""
    content = bytes(body) + _random_bytes(16)
    key_index = secrets.randbelow(len(X19_KEYS))
    iv = _random_bytes(16)
    key = X19_KEYS[key_index].encode("ascii")
    encrypted = _cbc_encrypt(key, iv, pkcs7_pad(content, _BLOCK_SIZE))
    return iv + encrypted + bytes([((key_index << 4) | 0x02) & 0xFF])


def x19_http_decrypt(payload: bytes) -> bytes:
    """``g79client.X19HttpDecrypt``: does **not** strip the padding."""
    if len(payload) < 18:
        raise G79Error("payload too short")

    flag = payload[-1]
    key_index = (flag >> 4) & 0x0F
    if key_index >= len(X19_KEYS):
        raise G79Error(f"invalid key index {key_index}")

    iv = payload[:16]
    cipher_text = payload[16:-1]
    return _cbc_decrypt(X19_KEYS[key_index].encode("ascii"), iv, cipher_text)


def x19_calculate_dynamic_token(url: str, content: str, token: str) -> str:
    """``g79client.X19CalculateDynamicToken``. Note that ``url`` is not stripped of its query."""
    token_md5 = hashlib.md5(token.encode("utf-8")).hexdigest()
    magic_md5 = hashlib.md5((token_md5 + content + "0eGsBkhl" + url).encode("utf-8")).hexdigest()

    binary_magic = "".join(f"{b:08b}" for b in magic_md5.encode("ascii"))
    shifted = binary_magic[6:] + binary_magic[:6]
    shifted_str = bytes(
        int(shifted[i * 8 : (i + 1) * 8], 2) for i in range(len(shifted) // 8)
    )

    # Equal length (both derive from one md5): strict=True asserts it rather than risking it
    xor_bytes = bytes(
        a ^ b
        for a, b in zip(magic_md5.encode("ascii"), shifted_str, strict=True)
    )
    encoded = base64.b64encode(xor_bytes).decode("ascii")
    replaced = encoded.replace("/", "o").replace("+", "m")
    if len(replaced) < 16:
        raise G79Error("token too short")
    return replaced[:16] + "1"


# ─────────────────────────── Go-style JSON serialization ───────────────────────────

_JSON_SEPARATORS = (",", ":")


def _go_json_escape(text: str) -> str:
    """Reproduce Go ``encoding/json``'s default HTML escaping (plus U+2028/2029)."""
    return (
        text.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def go_json_dumps(obj: Any, *, sort_keys: bool) -> str:
    """Serialize following the rules of Go ``encoding/json``.

    :param sort_keys: True for ``map[string]any`` (Go sorts keys), False for a struct such as
        ``PeAuthData`` (Go keeps declaration order).
    """
    try:
        text = json.dumps(
            obj,
            ensure_ascii=False,
            separators=_JSON_SEPARATORS,
            sort_keys=sort_keys,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:  # Go's json.Marshal fails the same way
        raise G79Error(f"json: unsupported value: {exc}") from exc
    return _go_json_escape(text)


def _uncertain_raw(value: Any) -> str:
    """Reproduce the ``Raw`` text kept by ``Uncertain.UnmarshalJSON`` in Go."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    return str(value)


def _uncertain_int(value: Any) -> int:
    """Reproduce Go ``Uncertain.Int64()``: an empty string or a parse failure both yield 0."""
    raw = _uncertain_raw(value)
    if raw == "":
        return 0
    try:
        return int(raw, 10)
    except ValueError:
        return 0


# ─────────────────────────── Global caches (globals.go) ───────────────────────────

_global_lock = asyncio.Lock()
_global_patch_meta: dict[str, str] | None = None
_global_g79_release: dict[str, str] | None = None
_global_x19_release: dict[str, str] | None = None
_global_x19_version: str = ""


async def _get_bytes(client: httpx.AsyncClient, url: str, *, headers: dict[str, str] | None = None) -> bytes:
    try:
        resp = await client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        raise G79Error(f"GET {url} failed: {exc}") from exc
    if resp.status_code != httpx.codes.OK:
        raise G79Error(f"download {url} returned status {resp.status_code}")
    return resp.content


def _first_zip_entry(data: bytes) -> bytes:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            if not names:
                raise G79Error("zip archive is empty")
            return zf.read(names[0])
    except zipfile.BadZipFile as exc:
        raise G79Error(f"zip: not a valid zip file: {exc}") from exc


def _engine_base_prefix() -> str:
    parts = ENGINE_VERSION.split(".")
    if len(parts) < 2:
        raise G79Error(f'invalid engine version "{ENGINE_VERSION}"')
    return f"{parts[0]}.{parts[1]}"


def _select_android_patch_version(versions: list[str]) -> str:
    """Pick, from the ``android`` array of ``g79_rn_patchlist``, the patch version on the

    **same branch** as the engine version. **Matching is by exact prefix only** (the first two
    segments of the engine version, e.g. ``3.6``); with no match a :class:`G79Error` is raised so
    that :meth:`G79Client.initialize` falls back to the ``*_FALLBACK`` constants (same as Go).

    **Why it must raise instead of "taking the latest"**: ``ENGINE_VERSION`` belongs to the
    PC-launcher branch used by PE auth (``3.6.x``), whereas ``g79_rn_patchlist`` is the mobile
    branch (all ``3.9.x``/``3.10.x``) -- the two arrays are not supposed to line up at all.

    Measured (2026-10-27): being "helpful" here and falling back to the newest 3.10 entry yields a
    ``engineVersion=3.6.5.281774`` + ``patchVersion=3.10.1.301063`` +
    **cross-branch mismatch** carrying that 3.10 ``patchResourcesHash``. PE auth still returns
    success, but the resulting user_token makes every interface answer
    ``{"code":10,"message":"please log in first"}`` (NetEase sends that text in Chinese) -- the
    server flags the session as abnormal. Restoring the raise brings the PE path back to 3.6.

    For the mobile MC version use :data:`AUTH_V2_CLIENT_VERSION` / :data:`AUTH_V2_PATCH_VERSION`
    (``authentication-v2`` only); leave this function alone.

    :param versions: the ``android`` version array of the patch list (ascending order).
    """
    if not versions:
        raise G79Error("no android patch versions available")

    base = _engine_base_prefix()
    if PREFERRED_PATCH_VERSION in versions and PREFERRED_PATCH_VERSION.startswith(base):
        return PREFERRED_PATCH_VERSION
    for version in reversed(versions):
        if version.startswith(base):
            return version
    raise G79Error(f"no android patch version matches base prefix {base}")


async def _fetch_android_resources_hash(
    client: httpx.AsyncClient, version: str, base_url: str
) -> str:
    if not base_url:
        raise G79Error("empty patch base url")

    root = base_url.rstrip("/")
    pre = f"{root}/android_{version}/{version}/android"

    manifest_raw = await _get_bytes(client, f"{pre}/manifest.zip")
    manifest = json.loads(_first_zip_entry(manifest_raw))
    assets = manifest.get("assets") or {}

    hash_base = G79_BASE_MCP_HASH
    asset = assets.get("vanilla.mcp") or {}
    if asset.get("md5"):
        hash_base = asset["md5"]
    asset = assets.get("vanilla_patch.mcp") or {}
    if asset.get("md5"):
        hash_base += asset["md5"]

    rn_hash = ""
    try:
        raw = await _get_bytes(client, f"{pre}/rn/index.bundle.backup")
        payload = raw
        # When the first zip entry cannot be read, use the whole blob -- both paths end in md5
        with contextlib.suppress(G79Error):
            payload = _first_zip_entry(raw)
        rn_hash = hashlib.md5(payload).hexdigest()
    except G79Error as exc:
        log.warning("rn bundle download failed; rnHash left empty", error=str(exc))

    return hashlib.md5((hash_base + rn_hash).encode("utf-8")).hexdigest()


async def _fetch_g79_patch_metadata(client: httpx.AsyncClient) -> dict[str, str]:
    body = await _get_bytes(client, G79_PATCH_LIST_URL)
    try:
        patch_info = json.loads(body)
    except ValueError as exc:
        raise G79Error(f"failed to parse the patch list: {exc}") from exc

    version = _select_android_patch_version(list(patch_info.get("android") or []))
    resources_hash = await _fetch_android_resources_hash(client, version, patch_info.get("urlNew") or "")
    return {"Version": version, "ResourcesHash": resources_hash}


async def get_g79_patch_metadata(client: httpx.AsyncClient, *, refresh: bool = False) -> dict[str, str]:
    """Equivalent to ``GetGlobalG79PatchMetadata`` / ``RefreshG79PatchMetadata`` (cached)."""
    global _global_patch_meta
    async with _global_lock:
        if _global_patch_meta is not None and not refresh:
            return dict(_global_patch_meta)
        meta = await _fetch_g79_patch_metadata(client)
        _global_patch_meta = meta
        return dict(meta)


async def _fetch_g79_release_json(client: httpx.AsyncClient) -> dict[str, str]:
    body = await _get_bytes(client, G79_RELEASE_JSON_URL)
    parsed = _load_json_object(body, "G79 release JSON")
    return parsed


async def get_g79_release_json(client: httpx.AsyncClient, *, refresh: bool = False) -> dict[str, str]:
    """Equivalent to ``GetGlobalG79ReleaseJSON`` / ``RefreshG79ReleaseJSON`` (cached)."""
    global _global_g79_release
    async with _global_lock:
        if _global_g79_release is not None and not refresh:
            return dict(_global_g79_release)
        value = await _fetch_g79_release_json(client)
        _global_g79_release = value
        return dict(value)


async def _fetch_x19_release_json(client: httpx.AsyncClient) -> dict[str, str]:
    body = await _get_bytes(client, X19_RELEASE_JSON_URL)
    return _load_json_object(body, "X19 release JSON")


async def get_x19_release_json(client: httpx.AsyncClient, *, refresh: bool = False) -> dict[str, str]:
    """Equivalent to ``GetGlobalX19ReleaseJSON`` (cached)."""
    global _global_x19_release
    async with _global_lock:
        if _global_x19_release is not None and not refresh:
            return dict(_global_x19_release)
        value = await _fetch_x19_release_json(client)
        _global_x19_release = value
        return dict(value)


async def get_x19_latest_version(client: httpx.AsyncClient, *, refresh: bool = False) -> str:
    """Latest version key of the x19 patchlist (equivalent to ``WPLUpdaterAPI.fetch``).

    The patchlist is a JSON object glued together from ``"version": {...},\n`` lines (**no
    trailing brace**); the reference appends ``{}`` and takes the last key (order = release order).
    """
    global _global_x19_version
    async with _global_lock:
        if _global_x19_version and not refresh:
            return _global_x19_version
        body = await _get_bytes(client, X19_PATCH_LIST_URL)
        text = body.decode("utf-8", "replace").strip().rstrip(",\n")
        import re as _re

        keys = _re.findall(r'"(\d+\.\d+\.\d+\.\d+)"\s*:', "{" + text + "}")
        if not keys:
            raise G79Error("the x19 patchlist has no version key")
        _global_x19_version = keys[-1]
        return _global_x19_version


def reset_global_cache() -> None:
    """Clear the module-level caches (for tests; the Go side has the ``Refresh*`` family)."""
    global _global_patch_meta, _global_g79_release, _global_x19_release
    global _global_x19_version
    _global_patch_meta = None
    _global_g79_release = None
    _global_x19_release = None
    _global_x19_version = ""


# ─────────────────────────── Client ───────────────────────────


class G79Client:
    """G79 PE client. :meth:`authenticate_with_cookie` must be called first.

    Typical usage::

        async with G79Client() as cli:
            await cli.authenticate_with_cookie(cookie_json)
            servers = await cli.search_rental_server_by_name("Minecraft")
            world = await cli.enter_rental_server_world(servers["entities"][0]["entity_id"], "")
    """

    def __init__(self, http_client: httpx.AsyncClient | None = None) -> None:
        self._http: httpx.AsyncClient | None = http_client
        self._owns_http = http_client is None

        self.engine_version: str = ENGINE_VERSION
        self.g79_latest_version: str = ""
        self.patch_resources_hash: str = ""
        self.release_json: dict[str, str] = {}
        self.x19_release_json: dict[str, str] = {}
        self._x19_version_cache: str = ""

        self.user_id: str = ""
        self.user_token: str = ""
        self.seed: str = ""
        self.cookie: str = ""
        self.user_detail: dict[str, Any] | None = None
        # Raw authentication entity from authenticate_with_sauth (holds verify_status/is_register;
        # the binding flow uses it to decide whether to guide the user through setting a nickname)
        self._otp_entity: dict[str, Any] | None = None
        # Decoded debug_message of uni_sauth (base64 + GBK JSON).
        # In risk-control / SMS verification cases NetEase puts the concrete instruction
        # ("send xxx to xxx") here -- on failure it is extracted as actionable advice for the user.
        self._uni_debug: dict[str, Any] = {}
        # Why get_user_detail could not obtain an entity (e.g. "account logged in elsewhere").
        # bot-status turns it into a precise hint instead of a uniform "--".
        self._detail_block_reason: str = ""

        self._pe_user_login_after: dict[str, Any] | None = None
        self._initialized = False
        self._init_lock = asyncio.Lock()

    # ── Lifecycle ──

    async def __aenter__(self) -> G79Client:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the self-built httpx client (one injected from outside is left alone)."""
        if self._owns_http and self._http is not None:
            await self._http.aclose()
            self._http = None

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT)
            self._owns_http = True
        return self._http

    # ── Initialization (client_core.go: NewClient) ──

    async def initialize(self, *, force: bool = False) -> None:
        """Equivalent to ``NewClient``: fetch the patch metadata + release JSON.

        A patch metadata failure -> fall back to ``G79_LATEST_VERSION_FALLBACK`` /
        ``PATCH_RESOURCES_HASH_FALLBACK`` (same as Go);
        a G79 release JSON failure -> raise :class:`G79Error` (same as Go).
        an X19 release JSON failure -> warning only (see the differences in the module docstring).
        """
        async with self._init_lock:
            if self._initialized and not force:
                return

            try:
                meta = await get_g79_patch_metadata(self.http, refresh=force)
                self.g79_latest_version = meta["Version"]
                self.patch_resources_hash = meta["ResourcesHash"]
            except G79Error as exc:
                log.warning("G79 patch metadata fetch failed; using defaults", error=str(exc))

            if not self.g79_latest_version:
                self.g79_latest_version = G79_LATEST_VERSION_FALLBACK
            if not self.patch_resources_hash:
                self.patch_resources_hash = PATCH_RESOURCES_HASH_FALLBACK

            self.release_json = await get_g79_release_json(self.http, refresh=force)

            try:
                self.x19_release_json = await get_x19_release_json(self.http, refresh=force)
            except G79Error as exc:
                log.warning("X19 release JSON fetch failed; X19 is unavailable", error=str(exc))
                self.x19_release_json = {}

            # Newest x19 patchlist version key: needed for the OTP session swap (sa_data.app_ver).
            # A failure does not block initialization -- fall back to X19_DEFAULT_VERSION.
            try:
                self._x19_version_cache = await get_x19_latest_version(self.http, refresh=force)
            except G79Error as exc:
                log.warning("X19 patchlist fetch failed; the OTP chain falls back", error=str(exc))
                self._x19_version_cache = ""

            self._initialized = True
            log.info(
                "[DBG2] EngineVersion=%r G79LatestVersion=%r patchResourcesHash=%r "
                "libraryHash=%r sigHash=%r",
                self.engine_version,
                self.g79_latest_version,
                self.patch_resources_hash,
                G79_LIBRARY_HASH,
                G79_SIGNATURE_HASH,
            )

    async def _ensure_initialized(self) -> None:
        if not self._initialized:
            await self.initialize()

    # ── Read-only properties ──

    @property
    def user_name(self) -> str:
        """Player display name (``UserDetail.name``; AuthV2 uses the same field)."""
        if not self.user_detail:
            return ""
        name = self.user_detail.get("name")
        return name if isinstance(name, str) else ""

    @property
    def user_level(self) -> int:
        """Player level (``UserDetail.level``, parsed with Go ``Uncertain.Int64()`` semantics)."""
        if not self.user_detail:
            return 0
        return _uncertain_int(self.user_detail.get("level"))

    @property
    def display_name(self) -> str:
        """Alias of ``user_name``."""
        return self.user_name

    # ── Authentication (auth.go) ──

    async def authenticate_with_cookie(self, cookie_str: str) -> None:
        """Equivalent to ``G79AuthenticateWithCookie``.

        ``cookie_str`` is the JSON found in ``fbtokens.json``:
        ``{"sauth_json": "<embedded JSON string>", "mac_addr": ..., "ram": ..., "rom": ...}``.
        """
        await self._ensure_initialized()
        self.cookie = cookie_str

        try:
            cookie_data = json.loads(cookie_str)
        except ValueError as exc:
            raise G79Error(f"failed to parse the Cookie: {exc}") from exc
        if not isinstance(cookie_data, dict):
            raise G79Error("failed to parse the Cookie: json: cannot unmarshal into Go value of type CookieData")

        sauth_raw = cookie_data.get("sauth_json") or ""
        try:
            sauth_data = json.loads(sauth_raw)
        except ValueError as exc:
            raise G79Error(f"failed to parse the sauth JSON: {exc}") from exc

        try:
            await self._perform_pe_auth_with_cookie(sauth_data, cookie_data)
        except G79Error as exc:
            raise G79Error(f"PE authentication failed: {exc}") from exc

        try:
            detail = await self.get_user_detail()
        except G79Error as exc:
            raise G79Error(f"failed to fetch the user info: {exc}") from exc

        entity = detail.get("entity")
        self.user_detail = entity if isinstance(entity, dict) else {}

    async def _perform_pe_auth_with_cookie(
        self, sauth_data: dict[str, Any], cookie_data: dict[str, Any]
    ) -> None:
        if not isinstance(sauth_data, dict):
            raise G79Error("sauth data is missing")
        if not self.g79_latest_version or not self.patch_resources_hash:
            raise G79Error("patch info is missing; re-initialize the client")

        for field, key in (
            ("sdkuid", "sdkuid"),
            ("sessionid", "sessionid"),
            ("udid", "udid"),
            ("deviceid", "deviceid"),
        ):
            value = sauth_data.get(key)
            if not (isinstance(value, str) and value.strip()):
                raise G79Error(f"sauth_json is missing the field {field}")

        seed = str(uuid.uuid4())
        self.seed = seed

        client_login_sn = _random_bytes(16).hex().upper()

        sauth_payload = _build_android_sauth_payload(sauth_data, client_login_sn)
        sa_data_payload = _build_android_sa_data_payload(self, sauth_data, cookie_data)
        sa_data_json = go_json_dumps(sa_data_payload, sort_keys=True)

        version_message = (
            f"{self.engine_version}{G79_LIBRARY_HASH}{self.g79_latest_version}"
            f"{self.patch_resources_hash}{G79_SIGNATURE_HASH}{seed}"
        )
        try:
            sign = pe_auth_sign(version_message, 2, 8)
        except G79Error as exc:
            raise G79Error(f"failed to compute the signature: {exc}") from exc

        # Go's PeAuthData is a struct -> declaration order, not key sorting
        peauth = {
            "engine_version": self.engine_version,
            "extra_param": "extra",
            "message": version_message,
            "patch_version": self.g79_latest_version,
            "pay_channel": G79_ANDROID_MESSAGE_TAG,
            "sa_data": sa_data_json,
            "sauth_json": sauth_payload,
            "seed": seed,
            "sign": sign,
        }

        log.info(
            "[DBG2] EngineVersion=%r G79LatestVersion=%r patchResourcesHash=%r "
            "libraryHash=%r sigHash=%r",
            self.engine_version,
            self.g79_latest_version,
            self.patch_resources_hash,
            G79_LIBRARY_HASH,
            G79_SIGNATURE_HASH,
        )

        payload = go_json_dumps(peauth, sort_keys=False).encode("utf-8")
        encrypted_payload = g79_http_encrypt(payload)

        core_url = self.release_json.get("CoreServerUrl", "")
        resp_body = await self._post(
            f"{core_url}/pe-authentication",
            encrypted_payload.hex(),
            headers={
                "User-Agent": USER_AGENT_LIBHTTP,
                "Accept-Encoding": "gzip",
                "Content-Type": "application/json",
            },
        )

        try:
            encrypted_resp = bytes.fromhex(_ascii_hex(resp_body))
        except ValueError as exc:
            raise G79Error(f"hex decode failed: {exc}") from exc

        decrypted_resp = g79_http_decrypt(encrypted_resp)
        valid_json = get_valid_json(decrypted_resp)

        try:
            login_resp = json.loads(valid_json)
        except ValueError as exc:
            raise G79Error(f"failed to parse the login response: {exc}, body: {valid_json!r}") from exc

        code = int(login_resp.get("code") or 0)
        if code != 0:
            raise G79Error(f"login failed (code: {code}): {login_resp.get('message', '')}")

        entity = login_resp.get("entity") or {}
        self.user_id = str(entity.get("entity_id") or "")
        self.user_token = str(entity.get("token") or "")
        self.seed = str(entity.get("seed") or "")

    # ── User detail (user_get_detail.go) ──

    async def get_user_detail(self) -> dict[str, Any]:
        """Equivalent to ``GetUserDetail`` (``POST /pe-user-detail/get``, body ``{}``)."""
        await self._ensure_initialized()
        api = "/pe-user-detail/get"
        json_data = go_json_dumps({}, sort_keys=True)

        core_url = self.release_json.get("CoreServerUrl", "")
        resp_body = await self._post(
            f"{core_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_WPF,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )

        return _load_json_any(resp_body, 'the user detail response')

    # ── User profile query (confirmed live: /user-detail/query/other) ──
    # A 2026-10-16 mitmproxy capture of the official Android client confirms that nickname / level /
    # avatar / avatar frame / profile page are served by
    #     POST https://g79mclobt.minecraft.cn/user-detail/query/other
    # Three differences from get_user_detail above:
    #   1. **Different host**: ``g79mclobt`` (MC Lobby), not ``g79apigatewayobt``
    #   2. ``Content-Type: text/plain`` (not application/json)
    #   3. The response is **not encrypted**: plain JSON, and far richer than the old endpoint
    # body is {"entity_id":"<uid>","with_statis_data":0,"with_dynamic_head_img":1}
    # entity fields: id / nickname / signature / headImage / frame_id /
    # moment_id / public_flag / pe_growth{lv,exp,need_exp,is_vip} / tag /
    # is_developer / mark / is_friend / homepage_bg / visit_card_bg /
    # recharge_vip_level; a top-level summary_md5 is there for cache comparison.
    # **entity_id accepts any uid** -> this is how public profiles of others are queried.
    _MC_LOBBY_URL = "https://g79mclobt.minecraft.cn"

    async def query_user_detail_other(
        self,
        entity_id: str = "",
        *,
        with_statis_data: int = 0,
        with_dynamic_head_img: int = 1,
        is_need_recharge_benefit: int = 0,
    ) -> dict[str, Any]:
        """Query user detail (official ``/user-detail/query/other``; plaintext, not encrypted).

        :param entity_id: target uid; omitted means the current bot itself.
        :return: the unpacked JSON; see the class docstring's field table for ``entity``.
        """
        await self._ensure_initialized()
        api = "/user-detail/query/other"
        json_data = go_json_dumps(
            {
                "entity_id": entity_id or self.user_id,
                "with_statis_data": with_statis_data,
                "with_dynamic_head_img": with_dynamic_head_img,
                "is_need_recharge_benefit": is_need_recharge_benefit,
            },
            sort_keys=True,
        )

        resp_body = await self._post(
            f"{self._MC_LOBBY_URL}{api}",
            json_data,
            headers={
                "Content-Type": "text/plain",
                "User-Agent": USER_AGENT_WPF,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )
        return _load_json_any(resp_body, "the user detail response")
    async def refresh_user_detail(self) -> dict[str, Any]:
        """Fetch the user detail again and cache it on :attr:`user_detail`.

        For an account that has never logged into the game, NetEase returns ``code != 0`` with
        ``entity`` set to ``None`` -- the old code neither raised nor logged, so callers got an
        empty dict and the page showed empty nickname/level/skin count, which looked like "the
        refresh failed" while nothing had failed. That case is now recorded explicitly, so the
        logs can tell "fetched, but the account never entered the game" from "really failed".
        """
        detail = await self.get_user_detail()
        entity = detail.get("entity")
        if not isinstance(entity, dict):
            code = detail.get("code")
            msg = str(detail.get("message") or "")
            # "Your account logged in elsewhere" (code 22) means the **session was kicked out**:
            # NetEase is single sign-on, so a new authentication drops the old session. The
            # credentials are fine (user_token still passes refresh_authentication), but the
            # detail is gone -- the old code showed "--" on the page, which confused users.
            # NetEase replies in Chinese, so the keyword below stays Chinese.
            self._detail_block_reason = (
                "NetEase says your account logged in elsewhere: the session of this account was"
                " kicked out by a newer login (NetEase single sign-on). Unbind and bind again,"
                " or retry later -- re-authenticating makes a new session and drops the old one."
                if code == 22 or "另一处" in msg
                else ""
            )
            log.info(
                "user detail returned no entity",
                code=code,
                detail_msg=msg[:120],
                uid=self.user_id,
                kicked="另一处" in msg,  # same Chinese keyword as the gate above
            )
            self.user_detail = {}
            return detail
        self.user_detail = entity
        log.debug(
            "user detail refreshed",
            uid=self.user_id,
            name=str(entity.get("name") or "")[:24],
            # level/skin_number are logging-reserved field names; renaming them avoids
            # "_log() got multiple values" (uid collided the same way).
            user_level=entity.get("level"),
            skin_count=entity.get("skin_number"),
            need_realname_auth=entity.get("need_realname_auth"),
        )
        return detail

    # ── Rental servers (rental_search_by_name.go / rental_enter_world.go) ──

    async def search_rental_server_by_name(self, server_code: str) -> dict[str, Any]:
        """Equivalent to ``SearchRentalServerByName``
        (``POST /rental-server/query/search-by-name``).

        :param server_code: rental server name (on the Go side the parameter is ``serverName``,
            the request field ``server_name``).
        """
        await self._ensure_initialized()
        api = "/rental-server/query/search-by-name"
        json_data = go_json_dumps({"server_name": server_code}, sort_keys=True)

        web_url = self.release_json.get("WebServerUrl", "")
        resp_body = await self._post(
            f"{web_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_WPF,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )

        return _load_json_any(resp_body, 'the rental server search response')
    async def enter_rental_server_world(self, server_id: str, password: str) -> dict[str, Any]:
        """Equivalent to ``EnterRentalServerWorld`` (``POST /rental-server-world-enter/get``).

        :param server_id: the rental server ``entity_id`` (a 19-digit numeric string).
        :param password: the server password; pass an empty string when there is none (mirrors
            ``has_pwd`` on the list entity).

        A real-device capture on 2026-10-16 confirms the ``entity`` shape of the response::

            {"entity_id":"4658680138770108095",
             "mcserver_host":"1.95.233.220", "mcserver_port":13631,
             "isp_enable":true,
             "cmcc_mcserver_host":"117.187.184.37","cmcc_mcserver_port":13631,
             "ctcc_mcserver_host":"111.124.198.37","ctcc_mcserver_port":13631,
             "cucc_mcserver_host":"220.197.38.43","cucc_mcserver_port":13631,
             "state":1,"async_progress":4,"total_progress":4}

        · The three IPs sit on completely different subnets -> **BGP three-line access**: the
          client picks the IP of its own ISP, and ``mcserver_host`` is the generic fallback.
        · ``async_progress``/``total_progress`` is the **cold-start progress** -- the server
          boots on demand, so while it is not full (e.g. 2/4) poll and wait instead of dialing.
        · Even with the IP/port you still need the MC protocol auth handshake (this endpoint
          issues no MC-side token).
        """
        await self._ensure_initialized()
        api = "/rental-server-world-enter/get"
        json_data = go_json_dumps({"server_id": server_id, "pwd": password}, sort_keys=True)

        web_url = self.release_json.get("WebServerUrl", "")
        resp_body = await self._post(
            f"{web_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_WPF,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )

        return _load_json_any(resp_body, 'the rental server join response')

    # ── Online lobby (2026-10-29 addition) ──
    #
    # The online lobby and rental servers are two independent join paths:
    #
    #   rental server  search-by-name -> rental-server-world-enter/get
    #   online lobby   search-by-name-v2 -> online-lobby-room-enter/ -> online-lobby-game-enter
    #
    # Key differences (real-device capture, 2026-10-29, client 3.10.0.300878 joining room 94602):
    #
    # · game_type is ``LobbyGame`` (``RentalGame`` for rental servers) -- AuthV2 takes
    #   ``<room_id>:LobbyGame`` as ``netease_sid``.
    # · The room ID is the ``entity_id`` in the search result (19 digits), not the room number.
    # · Entering a room (``online-lobby-room-enter/``, note the trailing slash) only registers
    #   the intent; ``online-lobby-game-enter`` issues the real server address (body is ``{}``).
    # · Response fields differ from rental servers: ``server_host``/``server_port`` (no
    #   ``mcserver_`` prefix), and the three-line fields are ``cmcc_server_host`` and so on.

    async def search_online_lobby_room(
        self, keyword: str, version: str = "1.21.130"
    ) -> dict[str, Any]:
        """Equivalent to the client's ``POST /online-lobby-room/query/search-by-name-v2``.

        :param keyword: room number or a keyword of the room name (e.g. ``"94602"``).
        :param version: client world version, filters joinable rooms (default 1.21.130).
        :return: the response dict; ``entities[0]`` carries ``entity_id`` (room ID),
            ``res_id`` (lobby resource/ticket id), ``password`` (0/1), ``version``,
            ``min_level``, ``max_count``, ``cur_num`` and so on.
        """
        await self._ensure_initialized()
        api = "/online-lobby-room/query/search-by-name-v2"
        json_data = go_json_dumps(
            {
                "keyword": keyword,
                "length": 10,
                "offset": 0,
                "res_id": "",
                "version": version,
            },
            sort_keys=True,
        )

        web_url = self.release_json.get("WebServerUrl", "")
        resp_body = await self._post(
            f"{web_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_WPF,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )
        return _load_json_any(resp_body, 'the online lobby room search response')

    async def get_online_lobby_room(self, room_id: str) -> dict[str, Any]:
        """Equivalent to the client's ``POST /online-lobby-room/get``.

        :param room_id: the room ``entity_id`` (a 19-digit numeric string).
        """
        await self._ensure_initialized()
        api = "/online-lobby-room/get"
        json_data = go_json_dumps({"room_id": room_id}, sort_keys=True)

        web_url = self.release_json.get("WebServerUrl", "")
        resp_body = await self._post(
            f"{web_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_WPF,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )
        return _load_json_any(resp_body, 'the online lobby room detail response')

    async def enter_online_lobby_room(
        self, room_id: str, password: str = ""
    ) -> dict[str, Any]:
        """Equivalent to the client's ``POST /online-lobby-room-enter/`` (note the trailing slash).

        This step only registers the intent to enter the room plus a visibility/password check;
        the real server address comes from :meth:`enter_online_lobby_game`.

        :param room_id: the room ``entity_id``.
        :param password: room password (pass an empty string when ``password`` is 0).
        """
        await self._ensure_initialized()
        # Note: the path of this API ends with a slash -- the client was measured sending it,
        # and without the slash you get a 404.
        api = "/online-lobby-room-enter/"
        json_data = go_json_dumps(
            {
                "password": password,
                "room_id": room_id,
                "lobby_manifest_version": "",
                "check_visibilily": 1,
            },
            sort_keys=True,
        )

        web_url = self.release_json.get("WebServerUrl", "")
        resp_body = await self._post(
            f"{web_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_WPF,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )
        return _load_json_any(resp_body, 'the online lobby join response')

    async def enter_online_lobby_game(self) -> dict[str, Any]:
        """Equivalent to the client's ``POST /online-lobby-game-enter`` -- issues the real address.

        :meth:`enter_online_lobby_room` must be called first to register the intent, otherwise the
        server cannot know which room the player wants (the request body here is ``{}``; the room
        context lives in the server-side session).

        A real-device capture on 2026-10-29 confirms the ``entity`` shape (room 94602)::

            {"server_host":"1.95.237.131","server_port":17328,
             "server_host_v6":"",
             "isp_enable":true,
             "cmcc_server_host":"117.187.184.49","cmcc_server_host_v6":"",
             "ctcc_server_host":"111.124.198.59","ctcc_server_host_v6":"",
             "cucc_server_host":"220.197.38.50","cucc_server_host_v6":"",
             "cucc_server_port":17328,"ctcc_server_port":17328,
             "cmcc_server_port":17328}

        Field names differ from rental servers (``mcserver_host``), and there is no cold-start
        progress.
        """
        await self._ensure_initialized()
        api = "/online-lobby-game-enter"
        json_data = go_json_dumps({}, sort_keys=True)

        web_url = self.release_json.get("WebServerUrl", "")
        resp_body = await self._post(
            f"{web_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_WPF,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )
        return _load_json_any(resp_body, 'the lobby join response')

    async def purchase_lobby_item(self, res_id: str) -> dict[str, Any]:
        """Equivalent to the client's ``POST /pe-purchase-item/`` (note the trailing slash):
        order a lobby ticket.

        Entering a lobby room requires holding that room's resource/ticket (``res_id``). On the
        first attempt ``online-lobby-room-enter`` answers ``code=501 "item not obtained yet"``, so
        place the order here, poll :meth:`buy_item_result` to confirm it, and only then enter the
        room. A free room is delivered as soon as the order is placed (``buy_type=0``).

        :param res_id: the room's resource/ticket id (``entities[0].res_id`` in the room
            search response).
        :return: the response dict; ``entity.entity_id`` is the order id (pass it to
            :meth:`buy_item_result` as ``orderid``); ``entity.buy_type`` is the purchase type.
        """
        await self._ensure_initialized()
        # The trailing slash matches the client; without it you get a 404.
        api = "/pe-purchase-item/"
        json_data = go_json_dumps(
            {
                "item_id": res_id,
                "expertcomment_info": {
                    "expertcomment_id": "0",
                    "video_url": "0",
                    "expert_id": "0",
                },
                "buy_path": f"首页-联机大厅-详情页:{res_id}",  # server-side breadcrumb, keep Chinese
                "coupon_ids": [],
                "cdk_code": "",
            },
            sort_keys=True,
        )

        web_url = self.release_json.get("WebServerUrl", "")
        resp_body = await self._post(
            f"{web_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_WPF,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )
        return _load_json_any(resp_body, 'the lobby ticket order response')

    async def buy_item_result(self, orderid: str, buy_type: int = 0) -> dict[str, Any]:
        """Equivalent to the client's ``POST /buy-item-result`` -- poll to confirm the ticket.

        Called right after :meth:`purchase_lobby_item`. Measured, the first call often returns
        ``code=40 "purchase not completed yet"``, so back off briefly and retry; ``code=0``
        means the ticket is in the inventory.

        :param orderid: the ``entity.entity_id`` returned by :meth:`purchase_lobby_item`.
        :param buy_type: the ``entity.buy_type`` returned by :meth:`purchase_lobby_item`.
        """
        await self._ensure_initialized()
        api = "/buy-item-result"
        json_data = go_json_dumps({"orderid": orderid, "buy_type": buy_type}, sort_keys=True)

        web_url = self.release_json.get("WebServerUrl", "")
        resp_body = await self._post(
            f"{web_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_WPF,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )
        return _load_json_any(resp_body, 'the lobby ticket confirmation response')

    async def check_user_game_ban(self, game_type: str = "LobbyGame") -> dict[str, Any]:
        """Equivalent to the client's ``POST /check-user-game-ban`` -- ban check before joining.

        :param game_type: ``"LobbyGame"`` (lobby) or ``"RentalGame"`` (rental server).
            An ``entity`` of ``null`` in the response means the account is not banned.
        """
        await self._ensure_initialized()
        api = "/check-user-game-ban"
        json_data = go_json_dumps({"gameType": game_type}, sort_keys=True)

        web_url = self.release_json.get("WebServerUrl", "")
        resp_body = await self._post(
            f"{web_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_WPF,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )
        return _load_json_any(resp_body, 'the game ban check response')

    # Carrier key -> (host field, port field). The order is the priority hint.
    _ISP_KEYS: tuple[tuple[str, str, str], ...] = (
        ("cmcc", "cmcc_mcserver_host", "cmcc_mcserver_port"),
        ("ctcc", "ctcc_mcserver_host", "ctcc_mcserver_port"),
        ("cucc", "cucc_mcserver_host", "cucc_mcserver_port"),
    )

    @staticmethod
    def parse_rental_endpoints(entity: dict[str, Any]) -> dict[str, Any]:
        """Turn the ``entity`` of a join response into ready-to-use endpoints.

        :return: ``{"host","port","isp_enable","ready","progress","endpoints"}``, where
            ``endpoints`` is ``[{"isp","host","port"}, ...]``; ``ready`` False means the
            server is still cold-starting (``async_progress`` not full yet).
        """
        host = str(entity.get("mcserver_host") or "")
        try:
            port = int(entity.get("mcserver_port") or 0)
        except (TypeError, ValueError):
            port = 0
        endpoints: list[dict[str, Any]] = []
        if host:
            endpoints.append({"isp": "default", "host": host, "port": port})
        for isp, host_key, port_key in G79Client._ISP_KEYS:
            h = str(entity.get(host_key) or "")
            if not h:
                continue
            try:
                p = int(entity.get(port_key) or port)
            except (TypeError, ValueError):
                p = port
            endpoints.append({"isp": isp, "host": h, "port": p})

        def _as_int(v: Any, default: int = 0) -> int:
            try:
                return int(v)
            except (TypeError, ValueError):
                return default

        total = _as_int(entity.get("total_progress"))
        done = _as_int(entity.get("async_progress"))
        return {
            "host": host,
            "port": port,
            "isp_enable": bool(entity.get("isp_enable")),
            # Only full progress counts as ready; without progress fields use state==1
            "ready": (total <= 0 or done >= total) and entity.get("state") == 1,
            "progress": f"{done}/{total}" if total else "",
            "endpoints": endpoints,
        }
    # ── Auth v2 (auth.go: GenerateRentalGameAuthV2 / SendAuthV2Request) ──

    async def generate_rental_game_auth_v2(
        self,
        server_id: str,
        client_key: str,
        display_name: str = "",
        game_type: str = "RentalGame",
    ) -> bytes:
        """Equivalent to ``GenerateRentalGameAuthV2``: returns the ``json.Marshal``-ed auth v2
        byte string.

        Keys are ordered like a Go ``map[string]any``, because :meth:`send_auth_v2_request` uses
        these bytes to compute the dynamic token -- a different key order breaks the signature.

        :param display_name: explicit in-game nickname. **When empty it falls back to
        ``self.user_name``, which is often still an empty string after PE auth** -- NetEase
        answers ``/authentication-v2`` with an **empty body** for an empty ``displayName``,
        which the client side reports as ``SendAuthV2Request: payload too short`` (the comment
        in the Go reference neteaselogin.go says as much, and the official g79 example also sets
        the name before logging in). Callers should therefore fetch the real nickname from
        ``user_detail["name"]`` and pass it in.
        :param game_type: game type suffix of ``netease_sid``.

            - ``"RentalGame"`` (default) -- rental server, ``server_id`` is a 19-digit entity_id;
            - ``"LobbyGame"`` -- lobby room, ``server_id`` is the room entity_id.

            A capture from a real device on 2026-10-29 confirms the lobby AuthV2 request is::

                {"netease_sid":"4691501103784534993:LobbyGame", ...}

            The server refuses to issue a chain when the type is wrong.
        """
        await self._ensure_initialized()
        if self.user_detail is None and not self.user_id:
            raise G79Error("user info is missing; finish authentication first")

        name = (display_name or self.user_name or "").strip()
        if not name:
            raise G79Error(
                "AuthV2 needs a non-empty displayName (NetEase returns an empty body for an"
                " empty name, which surfaces as payload too short). Get the nickname first via"
                " refresh_user_detail or update_nickname."
            )

        try:
            uid = int(self.user_id, 10)
        except ValueError as exc:
            raise G79Error(f"strconv.ParseInt: parsing {self.user_id!r}: invalid syntax") from exc

        authv2 = {
            "bit": "64",
            "clientKey": client_key,
            "displayName": name,
            # **Mobile client version**, a different set from ENGINE_VERSION used by PE auth.
            # See the comment on AUTH_V2_CLIENT_VERSION: PE auth only accepts 3.6.x, whereas
            # AuthV2 must carry 3.10.x to get through to a 1.21.130 rental server.
            "engineVersion": AUTH_V2_CLIENT_VERSION,
            "netease_sid": f"{server_id}:{game_type}",
            "os_name": _OS_NAME,
            "patchVersion": AUTH_V2_PATCH_VERSION,
            "uid": uid,
        }
        return go_json_dumps(authv2, sort_keys=True).encode("utf-8")

    async def send_auth_v2_request(self, auth_v2_data: bytes) -> bytes:
        """Equivalent to ``SendAuthV2Request`` (``POST /authentication-v2``); returns valid
        JSON bytes."""
        await self._ensure_initialized()
        api = "/authentication-v2"

        encrypted_data = g79_http_encrypt(auth_v2_data)

        auth_url = self.release_json.get("AuthServerUrl", "")
        token = calculate_dynamic_token(api, auth_v2_data.decode("utf-8"), self.user_token)

        resp_body = await self._post(
            f"{auth_url}{api}",
            encrypted_data.hex(),
            headers={
                "User-Agent": USER_AGENT_LIBHTTP,
                "Accept-Encoding": "gzip",
                "Content-Type": "application/json",
                "user-id": self.user_id,
                # Go does hex.EncodeToString([]byte(token)) here
                "user-token": token.encode("utf-8").hex(),
            },
        )

        try:
            encrypted_resp = bytes.fromhex(_ascii_hex(resp_body))
        except ValueError as exc:
            raise G79Error(f"hex decode failed: {exc}") from exc

        decrypted_resp = g79_http_decrypt(encrypted_resp)
        return get_valid_json(decrypted_resp)

    # ── Skin query (user_game_skin_query.go) ──

    # ── Skin query ──
    # The /user-game-skin/query/search-by-type used by the reference implementation
    # (WPLauncherHelper api/Skin.kt) is the **old** endpoint; a 2026-10-16 mitmproxy capture
    # (official Android client, uid 3100073113) confirms that live traffic uses this set:
    #   · /pe-get-user-setting-list   {"settings":["skin_type","skin_data",...]}
    #         -> skin_data.item_id ("-1"=default Steve, "-2"=another built-in, positive=item)
    #   · /pe-item/query/get-skin-by-type  {"channel_id":5,"is_purchased":1,...}
    #         -> the skin shop / owned list
    #   · /pe-item/query/search-by-id-list {"channel_id":5,"item_id_list":[...]}
    #         -> item_id -> entity (image URL including icon/preview_icon)
    # The two sets return completely different shapes, and the old one returns nothing live --
    # so the old method is kept while the three implementations below are added to match the
    # official client; callers pick whichever they need.

    async def get_skin_by_user_id(self, user_id: str) -> dict[str, Any]:
        """Look up a skin by launcher account EntityId (**old** endpoint, kept for compatibility).

        Mirrors ``api/Skin.kt`` in ``auth/WPLauncherHelper`` -- the body is a single-line JSON:
        ``{"user_id":"<id>","game_type":null,"client_type":"all","entity_id":null}``.

        ⚠ Measured on live servers (official Android client) this endpoint returns nothing; prefer
        :meth:`get_user_setting_list` / :meth:`get_skin_by_type` /
        :meth:`get_item_by_id_list` and the other methods aligned with the official client.

        :param user_id: launcher account EntityId. An empty string queries yourself
            (i.e. the account this bot is currently bound to).
        :return: the unpacked JSON object; ``entity`` holds the skin entries, each carrying
            ``user_id`` / ``skin_id`` / ``skin_mode`` / ``client_type`` and so on.
        """
        await self._ensure_initialized()
        api = "/user-game-skin/query/search-by-type"
        uid = user_id or self.user_id
        json_data = go_json_dumps(
            {"user_id": uid, "game_type": None, "client_type": "all", "entity_id": None},
            sort_keys=True,
        )

        api_url = self.release_json.get("ApiGatewayUrl", "")
        resp_body = await self._post(
            f"{api_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_WPF,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )
        return _load_json_any(resp_body, "the skin query response")

    # ── Skin/cosmetic setting query (confirmed live; see the "User settings" section below) ──
    # Two more methods aligned with the official client are further down:
    #   · :meth:`get_user_setting_list`  -- /pe-get-user-setting-list
    #   · :meth:`set_user_setting_list`   -- /pe-set-user-setting-list
    # ···

    _SETTING_KEYS = (
        "skin_type", "skin_data", "persona_data", "screen_config",
        "outfit_type", "personal_open", "personal_ad_open",
        "personal_tags", "bag_item",
    )

    async def get_skin_by_type(
        self,
        *,
        channel_id: int = 5,
        is_purchased: int = 1,
        sort_type: int = 6,
        length: int = 50,
        offset: int = 0,
        vip_only: str = "no",
        asc_flag: int = 0,
    ) -> dict[str, Any]:
        """Query the skin list (mirrors the official ``/pe-item/query/get-skin-by-type``).

        ``is_purchased=1`` only lists owned skins (empty when the account has no item skins).
        Note that ``vip_only`` is the **string** ``"no"``, not a boolean.
        """
        await self._ensure_initialized()
        api = "/pe-item/query/get-skin-by-type"
        json_data = go_json_dumps(
            {
                "vip_only": vip_only, "channel_id": channel_id,
                "sort_type": sort_type, "offset": offset, "length": length,
                "is_purchased": is_purchased, "asc_flag": asc_flag,
            },
            sort_keys=True,
        )

        api_url = self.release_json.get("ApiGatewayUrl", "")
        resp_body = await self._post(
            f"{api_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_WPF,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )
        return _load_json_any(resp_body, "the skin list query response")

    async def get_item_by_id_list(
        self, item_ids: list[str], channel_id: int = 5
    ) -> dict[str, Any]:
        """Look up item entities by item_id in bulk (``/pe-item/query/search-by-id-list``).

        This is the "item_id -> image URL" resolution step: once a skin item_id is known,
        use it to fetch the entity with ``icon`` / ``preview_icon``. **The endpoint needs an
        extra ``hpack: 1`` request header** (the official client sends it; without it the
        request is rejected).
        """
        await self._ensure_initialized()
        api = "/pe-item/query/search-by-id-list"
        json_data = go_json_dumps(
            {"channel_id": channel_id, "item_id_list": list(item_ids)},
            sort_keys=True,
        )

        api_url = self.release_json.get("ApiGatewayUrl", "")
        resp_body = await self._post(
            f"{api_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_WPF,
                "Accept-Encoding": "gzip",
                "hpack": "1",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )
        return _load_json_any(resp_body, "the item entity query response")

    # ── Heartbeat (x19 /authentication/update) ──

    async def refresh_authentication(self) -> dict[str, Any]:
        """Heartbeat: refresh the login state, equivalent to ``/authentication/update``.

        Mirrors ``WPLauncherAccountAPI.refresh()`` in ``auth/WPLauncherHelper`` -- POST
        ``/authentication/update`` with the body ``{"entity_id":<session id>}``, and both
        the request and the response are encrypted.

        Three things matter, and all of them are required:

        1. **The path is the core domain, not the apigateway domain**. ``RefreshCookie`` in
           g79client goes through apigateway; that is not the heartbeat this project needs.
        2. **Both the request body and the response are encrypted** (``hasEncrypt``).
           A plaintext request is rejected.
        3. **The heartbeat address is hard-coded** as ``x19obtcore.nie.netease.com:8443`` --
           release.json has no such field, and http/https and the port must both be right.

        This project calls it once before joining a server: NetEase login states expire, and
        the join flow (fetch login info -> transfer -> check the check digits) spans several
        hops. Dropping offline midway makes the client see "login expired" and fail to join.
        """
        await self._ensure_initialized()
        api = "/authentication/update"
        json_data = go_json_dumps({"entity_id": int(self.user_id)}, sort_keys=True)

        # Domain and port hard-coded as in the reference impl: release.json has no such field.
        # The body is ciphertext (arbitrary bytes) and must go through the bytes channel --
        # bouncing it through a string re-encodes it as utf-8 and corrupts it (see _post_bytes).
        # encrypt only takes bytes while go_json_dumps returns str, so encode explicitly here.
        resp_body = await self._post_bytes(
            f"https://x19obtcore.nie.netease.com:8443{api}",
            g79_http_encrypt(json_data.encode("utf-8")),
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_LIBHTTP,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )

        try:
            decrypted = g79_http_decrypt(bytes(resp_body))
        except Exception as exc:  # noqa: BLE001 - keep the original text on a decrypt failure
            raise G79Error(f"failed to decrypt the heartbeat response: {exc}") from exc

        # g79_http_decrypt keeps the random tail (the 16 random bytes filled in during
        # encryption are not trimmed), so a plain json.loads reports a utf-8 decode error on
        # the garbage after the JSON -- get_valid_json must first cut out the JSON boundary by
        # matching {} pairs (the reference implementation does an equivalent boundary step
        # before json.decodeFromString).
        result = _load_json_any(get_valid_json(decrypted), "the heartbeat response")

        # **The heartbeat hands out a new user-token, and it must be adopted** (equivalent to
        # the set token / sead behaviour after a successful WM_LobbyRefreshLogin in the Go
        # reference implementation). If it is not updated, every later user-token computed by
        # calculate_dynamic_token is based on an expired seed and the server answers 401 with
        # an empty body -- which surfaces as "auth-v2 failed: payload too short" (measured: PE
        # auth had succeeded and the heartbeat returned 200, yet AuthV2 never got through).
        entity = result.get("entity") if isinstance(result, dict) else None
        if isinstance(entity, dict):
            new_token = str(entity.get("token") or "").strip()
            if new_token and new_token != self.user_token:
                log.info(
                    "heartbeat issued a new user-token, session updated",
                    old=self.user_token[:6] + "…" if self.user_token else "",
                    new=new_token[:6] + "…",
                )
                self.user_token = new_token
            new_sead = str(entity.get("sead") or "").strip()
            if new_sead:
                self.seed = new_sead
        return result

    # ── OTP session exchange (uni_sauth -> login-otp -> authentication-otp) ──

    async def authenticate_with_sauth(
        self, cookie_str: str
    ) -> dict[str, Any]:
        """Trade a sauth cookie for a login state over the OTP chain; returns the auth entity.

        Unlike :meth:`authenticate_with_cookie` (PE auth on the g79 side) this goes through
        the **x19 launcher** OTP chain (cf. ``WPLauncherAPI.login`` in
        ``auth/WPLauncherHelper``). sauth sessions that PE auth rejects can only use this
        chain; NetEase-channel cookies work on both.

        Three steps (all required, fixed order):

        1. ``uni_sauth``: register the sauth as a one-time aid (``mgbsdk.matrix.netease.com``,
           plaintext JSON, not port 8443);
        2. ``login-otp``: obtain the one-time ``otp_token`` (``x19obtcore:8443``, **plaintext**);
        3. ``authentication-otp``: package sauth + otp_token + environment fingerprint and
           submit it **encrypted**; the decrypted response yields ``entity_id``/``token``
           (the long-lived account credentials).

        Risk note: the ``login-otp`` risk-control error text is misleading -- measured,
        ``code 32`` returns "server under maintenance, please try again later", but the real
        cause is NetEase judging this device / egress IP as risky (the same account gets
        ``code=1351 account has a security risk`` on both the Go reference implementation and
        this one, and the NetEase verification page says "or log in with the original fixed
        device"). See :func:`_explain_login_otp_code`.

        ``cookie_str`` accepts two shapes (``WPLauncherCookieRaw`` semantics): one wrapping an
        outer ``sauth_json`` (one per cookies.txt line), or bare sauth JSON.
        """
        await self._ensure_initialized()
        sauth_raw = self._unwrap_sauth(cookie_str)
        try:
            sauth_data = json.loads(sauth_raw)
        except ValueError as exc:
            raise G79Error(f"failed to parse the sauth JSON: {exc}") from exc
        if not isinstance(sauth_data, dict):
            raise G79Error("the sauth JSON is not an object")
        udid = str(sauth_data.get("udid") or "0721")  # fixed udid of the Raw form
        sdk_version = str(sauth_data.get("sdk_version") or "3.12.2")

        # Debug log: profile of the OTP chain input. Credentials are logged as prefix/length
        # only, so that a whole cookie (which carries reusable info such as sessionid) stays
        # out of the log.
        log.debug(
            "OTP chain starting",
            app_channel=sauth_data.get("app_channel"),
            login_channel=sauth_data.get("login_channel"),
            sdk_version=sdk_version,
            is_guest=sauth_data.get("is_unisdk_guest"),
            sdkuid=str(sauth_data.get("sdkuid") or "")[:10],
            sessionid_len=len(str(sauth_data.get("sessionid") or "")),
            udid=str(udid)[:10],
            cookie_len=len(cookie_str),
            wrapped="sauth_json" in (cookie_str or ""),
        )

        # NetEase anti-bot: fresh or risk-flagged accounts may be asked at the uni_sauth
        # step to send NetEase a text (SMS) message.
        #
        # Note: **uni_sauth's code is not the pass/fail criterion**. Cf. the Kotlin reference
        # (``WPLauncherAPI.uniCookie`` in WPLauncherHelper) -- it only parses the response and
        # never checks code at all, and the caller ``Login.kt`` even discards the return value
        # (``.also { uniCookie(it) }``): the step exists only for the side effect of
        # registering the aid on the NetEase side.
        # The real verdict comes from login-otp (the Go ``X19AuthenticateWithCookie`` also only
        # checks ``Code != 0`` there, and never calls uni_sauth).
        #
        # This used to raise on any non-200, mistaking harmless responses such as "account
        # already registered" (code=400 on retry, measured) for failures and leaving the user
        # stuck right after completing the SMS verification. It is now best effort like the
        # reference implementation: only log a warning and let login-otp report the real error.
        uni = await self._uni_sauth(sauth_raw, udid)
        uni_code = int(uni.get("code") or 0)
        uni_msg = str(uni.get("msg") or uni.get("message") or "")
        log.debug(
            "uni_sauth done",
            code=uni_code,
            subcode=uni.get("subcode"),
            status=uni.get("status"),
            aid=uni.get("aid"),
            uni_msg=uni_msg[:120],
        )
        if uni_code != 200:
            # debug_message is base64(GBK JSON) and usually carries a more specific
            # instruction (e.g. "send NetEase the text message xxx") -- decode it and keep it
            # aside, to hand the user an actionable hint when this fails.
            self._uni_debug = _decode_uni_sauth_debug(
                str(uni.get("debug_message") or "")
            )
            log.warning(
                "uni_sauth returned non-200; continuing like the reference (not fatal)",
                code=uni_code,
                subcode=uni.get("subcode"),
                status=uni.get("status"),
                # cannot be called message: logging's _log() already uses that keyword
                uni_msg=uni_msg[:120],
                debug_decoded=str(self._uni_debug.get("message") or "")[:80],
            )

        try:
            otp = await self._login_otp(sauth_raw)
        except G79Error as e:
            # uni_sauth's message is often closer to the real cause than login-otp's.
            # **SMS verification** in particular: NetEase puts the exact instruction in
            # debug_message ("send xxx to xxx"), and the user must send it before retrying.
            # Earlier the raw text was merely appended to the error, so the user was told
            # "NetEase requires SMS verification" without what to send or where -- the
            # instruction now comes first.
            sms = _sms_verify_hint(
                getattr(self, "_uni_debug", {}), uni_msg
            )
            if sms:
                raise G79Error(
                    f"NetEase requires SMS verification: {sms}. Send that SMS as described"
                    f" above, then try binding again. (original error: {e})"
                ) from e
            if uni_code != 200 and uni_msg:
                raise G79Error(f"{e}; uni_sauth code={uni_code}: {uni_msg}") from e
            raise
        otp_token = str(otp.get("otp_token") or "")
        otp_aid = int(otp.get("aid") or 0)
        log.debug(
            "login-otp done",
            has_token=bool(otp_token),
            aid=otp_aid,
            verify_status=otp.get("verify_status"),
            open_otp=otp.get("open_otp"),
            lock_time=otp.get("lock_time"),
        )
        if not otp_token:
            raise G79Error("the login-otp response has no otp_token")

        entity = await self._authentication_otp(
            sauth_raw, udid, sdk_version, otp_token, otp_aid
        )
        self.user_id = str(entity.get("entity_id") or "")
        self.user_token = str(entity.get("token") or "")
        self.cookie = cookie_str
        log.debug(
            "authentication-otp done",
            entity_id=self.user_id,
            has_token=bool(self.user_token),
        )
        if not self.user_id or not self.user_token:
            raise G79Error(f"authentication-otp response has no credentials: {entity}")

        self._otp_entity = entity
        return entity

    # ── Export / import of the NetEase long-lived credentials ──

    def dump_session(self) -> str:
        """Export the NetEase long-lived credentials (``entity_id|token``).

        The sauth cookie is **one-shot / short-lived**: measured, taking it through the OTP
        chain a few minutes after binding finishes yields ``uni_sauth 401 auth fail`` ->
        ``login-otp code 32``, and the UI then shows "bound, but every bot state is empty".
        So after a successful authentication this credential pair must be stored and
        reused instead of re-authenticating with the old cookie every time.
        """
        if not self.user_id or not self.user_token:
            return ""
        return f"{self.user_id}|{self.user_token}"

    def load_session(self, packed: str) -> bool:
        """Import the output of :meth:`dump_session` and restore the logged-in state.

        Returns whether it worked. ``release_json`` and friends are still only fetched by
        :meth:`_ensure_initialized` after this -- the caller is responsible for that.
        """
        entity_id, _, token = (packed or "").partition("|")
        entity_id = entity_id.strip()
        token = token.strip()
        if not entity_id or not token:
            return False
        self.user_id = entity_id
        self.user_token = token
        return True

    @staticmethod
    def _unwrap_sauth(cookie_str: str) -> str:
        """Strip the outer ``sauth_json`` wrapper; bare JSON is returned unchanged
        (``WPLauncherCookieRaw``)."""
        text = (cookie_str or "").strip()
        if "sauth_json" not in text:
            return text
        try:
            outer = json.loads(text)
        except ValueError as exc:
            raise G79Error(f"failed to parse the Cookie: {exc}") from exc
        if not isinstance(outer, dict) or not outer.get("sauth_json"):
            raise G79Error("the Cookie has no sauth_json field")
        return str(outer["sauth_json"])

    def _x19_latest_version(self) -> str:
        """Newest version key of the x19 patchlist (``_x19_version_cache``, warmed in init).

        Not from the same source as the ``x19_release_json`` that :class:`G79Client.initialize`
        fetches: that JSON only holds service addresses, not the version -- the version sits
        among the patchlist keys. Falls back to ``X19_DEFAULT_VERSION`` when unavailable
        (matching the fallback of the Go reference implementation).
        """
        return getattr(self, "_x19_version_cache", "") or ""

    async def _uni_sauth(self, sauth_raw: str, udid: str) -> dict[str, Any]:
        """Step 1: register the aid (plaintext JSON, mgbsdk domain).

        The body is ``sauth + client_login_sn`` (``toCookieWithUni``) -- a random
        16-character client login serial, unrelated to the udid.
        """
        sauth_obj = json.loads(sauth_raw)
        sauth_obj["client_login_sn"] = _random_string(16)
        body = go_json_dumps(sauth_obj, sort_keys=False)
        try:
            resp = await self.http.post(
                "https://mgbsdk.matrix.netease.com/x19/sdk/uni_sauth",
                content=body.encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": USER_AGENT_WPF,
                },
            )
        except httpx.HTTPError as exc:
            raise G79Error(f"uni_sauth request failed: {exc}") from exc
        return _load_json_any(resp.content, "the uni_sauth response")

    async def _login_otp(self, sauth_raw: str) -> dict[str, Any]:
        """Step 2: obtain the one-time otp_token (**plaintext** request, port 8443)."""
        wrapped = go_json_dumps({"sauth_json": sauth_raw}, sort_keys=False)
        try:
            resp = await self.http.post(
                "https://x19obtcore.nie.netease.com:8443/login-otp",
                content=wrapped.encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": USER_AGENT_WPF,
                },
            )
        except httpx.HTTPError as exc:
            raise G79Error(f"login-otp request failed: {exc}") from exc
        body = _load_json_any(resp.content, "the login-otp response")
        code = int(body.get("code") or 0)
        # Debug log: the verdict is decided right here, so the whole raw response must be
        # recorded (code/message/HTTP status/field list). Previously only a WARNING-level
        # "credentials expired" was logged, which could not tell code 32 risk control,
        # code 401 session expiry and a malformed cookie apart.
        log.debug(
            "login-otp raw response",
            http_status=resp.status_code,
            code=code,
            message=str(body.get("message") or "")[:200],
            field_keys=sorted(body.keys())[:10],
        )
        if code != 0:
            raw_msg = str(body.get("message") or "")
            raise G79Error(
                f"login-otp failed (code {code}): "
                f"{_explain_login_otp_code(code, raw_msg)}"
            )
        entity = body.get("entity") or {}
        if not isinstance(entity, dict):
            raise G79Error("the login-otp response has no entity")
        return entity

    async def _authentication_otp(
        self,
        sauth_raw: str,
        udid: str,
        sdk_version: str,
        otp_token: str,
        aid: int,
    ) -> dict[str, Any]:
        """Step 3: submit the OTP authentication encrypted, and decode the account credentials.

        ``sa_data`` is the environment fingerprint (mac/disk/video card, ...). In the
        reference implementation most fields are hard-coded fake values -- NetEase only
        validates udid and version. The version is the newest version in the x19 release
        JSON (fetched during init) and falls back to the built-in value when missing.
        """
        # The platform must be pc (the reference implementation force-replaces it with pc).
        # The version is the newest key of the x19 patchlist (same interface and same
        # lookup as WPLUpdaterAPI.fetch -- release.json carries no version field).
        sauth_obj = json.loads(sauth_raw)
        sauth_obj["platform"] = "pc"
        sauth_json = go_json_dumps(sauth_obj, sort_keys=False)

        latest = self._x19_latest_version() or X19_DEFAULT_VERSION
        disk = "".join(secrets.choice("0123456789ABCEF") for _ in range(6))
        sa_data = go_json_dumps({
            "os_name": "windows",
            "os_ver": "Microsoft Windows 10",
            "mac_addr": "00-00-00-00-00-00",
            "udid": udid,
            "app_ver": latest,
            "sdk_ver": sdk_version,
            "network": "",
            "disk": disk,
            "is64bit": 1,
            "video_card1": "NVIDIA GeForce GTX 4060",
            "video_card2": "",
            "video_card3": "",
            "video_card4": "",
            "launcher_type": "PC_java",
            "pay_channel": "netease",
        }, sort_keys=False)

        req = {
            "otp_token": otp_token,
            "otp_pwd": "",
            "aid": aid,
            "sauth_json": sauth_json,
            "sa_data": sa_data,
            "version": {"version": latest, "launcher_md5": "", "updater_md5": ""},
        }
        payload = go_json_dumps(req, sort_keys=False).encode("utf-8")

        try:
            resp = await self.http.post(
                "https://x19obtcore.nie.netease.com:8443/authentication-otp",
                content=g79_http_encrypt(payload),
                headers={
                    "Content-Type": "application/json; charset=utf-8",
                    "User-Agent": USER_AGENT_WPF,
                    "Accept-Encoding": "gzip",
                },
            )
        except httpx.HTTPError as exc:
            raise G79Error(f"authentication-otp request failed: {exc}") from exc

        try:
            decrypted = g79_http_decrypt(bytes(resp.content))
        except Exception as exc:  # noqa: BLE001
            raise G79Error(f"authentication-otp response decryption failed: {exc}") from exc
        body = _load_json_any(get_valid_json(decrypted), "authentication-otp response")
        code = int(body.get("code") or 0)
        if code != 0:
            raise G79Error(f"authentication-otp failed (code {code}): {body.get('message', '')}")
        entity = body.get("entity") or {}
        if not isinstance(entity, dict):
            raise G79Error("authentication-otp response has no entity")
        return entity

    # ── Nickname (user_update_nickname.go) ──

    async def update_nickname(self, name: str) -> None:
        """Equivalent to ``UpdateNickname`` (``POST /pe-nickname-setting/update``)."""
        await self._ensure_initialized()
        api = "/pe-nickname-setting/update"
        json_data = go_json_dumps({"name": name}, sort_keys=True)

        api_url = self.release_json.get("ApiGatewayUrl", "")
        resp_body = await self._post(
            f"{api_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_LIBHTTP,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )

        try:
            response = json.loads(resp_body)
        except ValueError as exc:
            raise G79Error(f"failed to parse the response: {exc}") from exc

        if int(response.get("code") or 0) != 0:
            raise G79Error(f"failed to update the nickname: {response.get('message', '')}")

        if self.user_detail is not None:
            self.user_detail["name"] = name

    # ── User settings (user_settings_get.go / user_settings_set.go) ──

    async def get_user_setting_list(
        self, settings: tuple[str, ...] | None = None
    ) -> dict[str, Any]:
        """Equivalent to ``GetUserSettingList`` (``POST /pe-get-user-setting-list``).

        A capture from a real device on 2026-10-16 confirms that this is the **only correct
        entry point** for reading the current skin/cosmetic on live servers (the old
        ``/user-game-skin/query/search-by-type`` returns nothing).

        :param settings: keys to query; all of them when omitted. The server returns only
            the requested keys -- ``skin_data.item_id`` is the current skin (``"-1"``=
            default Steve, negative=a built-in free skin, positive=an item skin id, which
            needs :meth:`get_item_by_id_list` to turn into an image URL).
        """
        await self._ensure_initialized()
        api = "/pe-get-user-setting-list"
        keys = list(settings) if settings is not None else list(self._SETTING_KEYS)
        json_data = go_json_dumps({"settings": keys}, sort_keys=True)

        api_url = self.release_json.get("ApiGatewayUrl", "")
        resp_body = await self._post(
            f"{api_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_WPF,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )

        return _load_json_any(resp_body, 'the user setting list')
    async def set_user_setting_list(self, item_id: str) -> dict[str, Any]:
        """Equivalent to ``SetUserSettingList`` (``POST /pe-set-user-setting-list``).

        A capture from a real device on 2026-10-16 confirms that the official client sends
        a **partial update**:
        ``{"data": {"skin_data": {"item_id": X}, "skin_type": {"type": "skin"}, ...}}``
        so ``skin_type`` is sent along here -- sending only ``skin_data`` leaves some
        accounts unchanged (measured difference).

        ``item_id`` follows the same convention as :meth:`get_user_setting_list`:
        ``"-1"``=default Steve, ``"-2"``=another built-in skin, positive=an item skin.
        """
        await self._ensure_initialized()
        api = "/pe-set-user-setting-list"
        json_data = go_json_dumps(
            {
                "data": {
                    "skin_data": {"item_id": item_id},
                    "skin_type": {"type": "skin"},
                },
            },
            sort_keys=True,
        )

        api_url = self.release_json.get("ApiGatewayUrl", "")
        resp_body = await self._post(
            f"{api_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_WPF,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )

        return _load_json_any(resp_body, 'the set-user-setting-list response')
    # ── Item download / purchase / skin change (download_get_info.go /
    # user_item_purchase.go / skin_change.go) ──

    async def get_download_info(self, item_id: str) -> dict[str, Any]:
        """Equivalent to ``GetDownloadInfo`` (``POST /pe-download-item/get-download-info``)."""
        await self._ensure_initialized()
        api = "/pe-download-item/get-download-info"
        json_data = go_json_dumps({"item_id": item_id}, sort_keys=True)

        api_url = self.release_json.get("ApiGatewayUrl", "")
        resp_body = await self._post(
            f"{api_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_WPF,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )

        return _load_json_any(resp_body, 'the item download info')
    async def user_item_purchase(self, item_id: str) -> dict[str, Any]:
        """Equivalent to ``UserItemPurchase`` (``POST /user-item-purchase``, via DCWebUrl)."""
        await self._ensure_initialized()
        if not item_id:
            raise G79Error("itemID is empty")

        api = "/user-item-purchase"
        json_data = go_json_dumps(
            {
                "entity_id": 0,
                "item_id": item_id,
                "item_level": 0,
                "user_id": self.user_id,
                "purchase_time": 0,
                "last_play_time": 0,
                "total_play_time": 0,
                "receiver_id": "",
                "buy_path": "PC_H5_COMPONENT_DETAIL",
                "coupon_ids": [],
                "diamond": 0,
                "activity_name": "",
                "batch_count": 1,
            },
            sort_keys=True,
        )

        dc_url = self.x19_release_json.get("DCWebUrl", "")
        resp_body = await self._post(
            f"{dc_url}{api}",
            json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_LIBHTTP,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, json_data, self.user_token),
            },
        )

        return _load_json_any(resp_body, 'the item purchase response')
    async def purchase_item(self, item_id: str) -> dict[str, Any]:
        """``PurchaseItem`` as called by ``ChangeSkin`` in ``skin_change.go``
        (= :meth:`user_item_purchase`)."""
        return await self.user_item_purchase(item_id)

    async def change_skin(self, item_id: str) -> None:
        """Equivalent to ``ChangeSkin``: buy first (code 0 or 502 both pass), then write
        the settings."""
        purchase_response = await self.user_item_purchase(item_id)
        code = int(purchase_response.get("code") or 0)
        if code != 0 and code != 502:
            raise G79Error(str(purchase_response.get("message", "")))

        await self.set_user_setting_list(item_id)

    async def get_skin_info(self) -> dict[str, Any]:
        """Equivalent to ``auth.GetSkinInfo``: returns ``{"item_id", "res_url", "is_slim"}``.

        When the skin id is empty or ``-1``, change to :data:`DEFAULT_SKIN_ITEM_ID`
        first and then fetch the download URL.
        """
        setting_list = await self.get_user_setting_list()
        code = int(setting_list.get("code") or 0)
        if code != 0:
            raise G79Error(
                f"GetUserSettingList: {setting_list.get('message', '')}({code})"
            )

        entity = setting_list.get("entity") or {}
        skin_data = entity.get("skin_data") or {}
        item_id = str(skin_data.get("item_id") or "")

        if item_id in ("-1", ""):
            if not DEFAULT_SKIN_ITEM_ID:
                raise G79Error("ChangeSkin: missing default skin id")
            try:
                await self.change_skin(DEFAULT_SKIN_ITEM_ID)
            except G79Error as exc:
                raise G79Error(f"ChangeSkin: {exc}") from exc
            item_id = DEFAULT_SKIN_ITEM_ID

        download_info = await self.get_download_info(item_id)
        code = int(download_info.get("code") or 0)
        if code != 0:
            raise G79Error(
                f"GetDownloadInfo: {download_info.get('message', '')}({code})"
            )

        dl_entity = download_info.get("entity") or {}
        return {
            "item_id": item_id,
            "res_url": str(dl_entity.get("res_url") or ""),
            "is_slim": True,  # same as Go: no idea where this is supposed to come from
        }

    # ── PE login after (pe_user_login_after.go) ──

    async def get_pe_user_login_after(self) -> dict[str, Any]:
        """Equivalent to ``GetPeUserLoginAfter`` (``POST /pe-user-login-after``, result cached)."""
        if self._pe_user_login_after is not None:
            return self._pe_user_login_after

        await self._ensure_initialized()
        api = "/pe-user-login-after"
        body = go_json_dumps({"client_type": "cocos"}, sort_keys=True)

        api_url = self.release_json.get("ApiGatewayUrl", "")
        resp_body = await self._post(
            f"{api_url}{api}",
            body,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT_LIBHTTP,
                "Accept-Encoding": "gzip",
                "user-id": self.user_id,
                "user-token": calculate_dynamic_token(api, body, self.user_token),
            },
        )

        try:
            result = json.loads(resp_body)
        except ValueError as exc:
            raise G79Error(
                f"failed to parse the pe-user-login-after response: {exc}, body: {resp_body!r}"
            ) from exc

        self._pe_user_login_after = result
        return result if isinstance(result, dict) else {}

    # ── Internal HTTP ──

    async def _post(self, url: str, body: str, headers: dict[str, str]) -> bytes:
        """POST a text body and return the response bytes (httpx gunzips automatically)."""
        return await self._post_bytes(url, body.encode("utf-8"), headers)

    async def _post_bytes(self, url: str, body: bytes, headers: dict[str, str]) -> bytes:
        """POST a binary body and return the response bytes.

        The heartbeat (``/authentication/update``) request body is G79 ciphertext --
        arbitrary bytes. httpx encodes a ``content=str`` as utf-8, which expands every
        byte >0x7F into a two-byte sequence, so the server decrypts garbage -- hence the
        bytes channel is mandatory here.
        """
        try:
            resp = await self.http.post(url, content=body, headers=headers)
        except httpx.HTTPError as exc:
            raise G79Error(f"POST {url} failed: {exc}") from exc
        return resp.content


# ─────────────────────────── Payload construction (auth.go) ───────────────────────────

_OS_NAME = "android"
"""The package-level ``OSName`` variable from ``auth.go``."""

_AIM_INFO_DEFAULT = (
    '{"aim":"127.0.0.1","country":"CN","tz":"+0800","tzid":"","celluar_ip":"",'
    '"operator":"","is_vpn_enabled":"false"}'
)


def _trim(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _build_android_sauth_payload(sauth_data: dict[str, Any], client_login_sn: str) -> dict[str, Any]:
    """Equivalent to ``buildAndroidSauthPayload``."""
    aim_info = _trim(sauth_data.get("aim_info")) or _AIM_INFO_DEFAULT
    sdk_version = _trim(sauth_data.get("sdk_version")) or "5.9.0"
    ip = _trim(sauth_data.get("ip")) or "127.0.0.1"
    game_id = _trim(sauth_data.get("gameid")) or "x19"

    return {
        "aim_info": aim_info,
        "app_channel": "netease",
        "client_login_sn": client_login_sn,
        "deviceid": _str_or_empty(sauth_data.get("deviceid")),
        "gameid": game_id,
        "gas_token": _str_or_empty(sauth_data.get("gas_token")),
        "get_access_token": "1",
        "ip": ip,
        "is_unisdk_guest": 0,
        "login_channel": "netease",
        "platform": "ad",
        "sdk_version": sdk_version,
        "sdkuid": _str_or_empty(sauth_data.get("sdkuid")),
        "sessionid": _str_or_empty(sauth_data.get("sessionid")),
        "source_app_channel": "netease",
        "source_platform": "ad",
        "step": G79_ANDROID_STEP,
        "step2": G79_ANDROID_STEP2,
        "udid": _str_or_empty(sauth_data.get("udid")),
    }


def _build_android_sa_data_payload(
    client: G79Client, sauth_data: dict[str, Any], cookie_data: dict[str, Any]
) -> dict[str, Any]:
    """Equivalent to ``buildAndroidSaDataPayload`` (including the
    ``macAddress``/``ramValue`` helpers)."""
    sdk_version = _trim(sauth_data.get("sdk_version")) or "5.9.0"
    udid = _str_or_empty(sauth_data.get("udid"))
    if not udid.strip():
        udid = "0000000000000000"

    mac = _str_or_empty(cookie_data.get("mac_addr")).strip().upper()
    mac = mac.replace("-", ":") if mac else "02:00:00:00:00:00"

    ram = _str_or_empty(cookie_data.get("ram"))
    if not ram.strip():
        ram = "4294967296"

    is_guest = 1 if cookie_data.get("is_guest") is True else 0
    emulator = cookie_data.get("emulator")
    emulator_flag = int(emulator) if isinstance(emulator, int) and not isinstance(emulator, bool) else 0

    return {
        "app_channel": "netease",
        "app_ver": client.g79_latest_version,
        "core_num": "u0004",
        "cpu_digit": "64",
        "cpu_hz": "2465600",
        "cpu_name": "placeholder",
        "device_height": "900",
        "device_model": "SAMSUNG#SM-G977N",
        "device_width": "1600",
        "disk": "",
        "emulator": emulator_flag,
        "first_udid": udid,
        "is_guest": is_guest,
        "launcher_type": "PE_C++",
        "mac_addr": mac,
        "network": "mm_10086",
        "os_name": "android",
        "os_ver": "5.1.1",
        "ram": ram,
        "rom": _str_or_empty(cookie_data.get("rom")),
        "root": False,
        "sdk_ver": sdk_version,
        "start_type": "default",
        "udid": udid,
    }


def _str_or_empty(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _ascii_hex(data: bytes) -> str:
    """Read the response body as ASCII text to take the hex characters (Go does
    ``hex.DecodeString(string(body))``)."""
    return data.decode("utf-8", errors="replace").strip()


__all__ = [
    "AES_KEYS",
    "DEFAULT_DBG2",
    "DEFAULT_SKIN_ITEM_ID",
    "ENGINE_VERSION",
    "G79_ANDROID_MESSAGE_TAG",
    "G79_ANDROID_STEP",
    "G79_ANDROID_STEP2",
    "G79_BASE_MCP_HASH",
    "G79_LATEST_VERSION_FALLBACK",
    "G79_LIBRARY_HASH",
    "G79_SIGNATURE_HASH",
    "PATCH_RESOURCES_HASH_FALLBACK",
    "X19_DEFAULT_VERSION",
    "X19_KEYS",
    "G79Client",
    "G79Error",
    "calculate_dynamic_token",
    "g79_http_decrypt",
    "g79_http_encrypt",
    "get_g79_patch_metadata",
    "get_g79_release_json",
    "get_valid_json",
    "get_x19_release_json",
    "go_json_dumps",
    "pe_auth_sign",
    "pkcs7_pad",
    "pkcs7_unpad",
    "reset_global_cache",
    "x19_calculate_dynamic_token",
    "x19_http_decrypt",
    "x19_http_encrypt",
]
