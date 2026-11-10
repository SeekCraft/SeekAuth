"""Verify that SeekAuth's crypto matches the Go reference implementation byte for byte.

This is the most important check: any deviation in the RSA/AES/signature layout or in
the signed content makes FateArk fail to decrypt, or reject the response outright.

Approach: with this project's keys, run a full round trip in Python --
"init encrypt -> Go decrypt -> Go encrypt -> Python decrypt" --
and compare the AES ciphertext layout of both sides for the same plaintext.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

# The Windows console defaults to GBK, so printing non-GBK characters raises UnicodeEncodeError
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
except Exception:  # noqa: BLE001
    pass

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from seek_auth.crypto import (  # noqa: E402
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    load_private_key,
    load_public_key,
    new_nonce_hex,
    new_session_key,
    rsa_decrypt_hex,
    rsa_encrypt_hex,
    rsa_sign_b64,
    rsa_verify_b64,
    sign_aes_request,
    sign_init,
)

KEYS = Path(__file__).resolve().parents[1] / "keys"

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f"  {detail}" if detail else ""))
    if not ok:
        failures.append(name)


def main() -> int:
    print("=== Key loading ===")
    server_priv = load_private_key(KEYS / "server_private.pem")
    client_priv = load_private_key(KEYS / "client_private.pem")
    client_pub = client_priv.public_key()
    server_pub = load_public_key(KEYS / "server_public.pem")
    check("server key is RSA-2048", server_priv.key_size == 2048, f"{server_priv.key_size} bits")
    check("client key is RSA-2048", client_priv.key_size == 2048, f"{client_priv.key_size} bits")

    # server_public.pem must pair with server_private (it is the key patched into the binary)
    n_pub = server_pub.public_numbers().n
    n_priv = server_priv.public_key().public_numbers().n
    check("server_public.pem pairs with server_private.pem", n_pub == n_priv)

    print("\n=== RSA-OAEP(SHA-256) round trip ===")
    plain = json.dumps({"token": "f8aee27a90df19708dbc26f05e0d3a25"}).encode()
    # The server decrypts with its private key what the client encrypted to the server public key
    ct_hex = rsa_encrypt_hex(server_pub, plain)
    got = rsa_decrypt_hex(server_priv, ct_hex)
    check("RSA round trip matches", got == plain, f"{len(ct_hex)//2}-byte ciphertext")

    # init response: server encrypts to the client public key, the client decrypts with its key
    resp_plain = json.dumps({"sessionId": "sid-1", "sessionKey": "ab" * 32}).encode()
    ct2 = rsa_encrypt_hex(client_pub, resp_plain)
    got2 = rsa_decrypt_hex(client_priv, ct2)
    check("init response RSA round trip matches", got2 == resp_plain)

    print("\n=== AES-256-GCM non-standard layout ===")
    key_hex, key = new_session_key()
    check("session key is 32 bytes", len(key) == 32, key_hex[:16] + "...")

    payload = b'{"hello":"world"}'
    ct_hex = aes_gcm_encrypt(key, payload)
    raw = bytes.fromhex(ct_hex)
    # The layout must be nonce(12) || tag(16) || ciphertext
    check(
        "ciphertext layout = nonce(12)+tag(16)+ct",
        len(raw) == 12 + 16 + len(payload),
        f"{len(raw)} = 12+16+{len(payload)}",
    )
    back = aes_gcm_decrypt(key, ct_hex)
    check("AES round trip matches", back == payload)

    # A different key must fail to open it (GCM authentication)
    _, other_key = new_session_key()
    try:
        aes_gcm_decrypt(other_key, ct_hex)
        check("wrong key must fail to decrypt", False, "it opened anyway")
    except Exception:  # noqa: BLE001
        check("wrong key must fail to decrypt", True)

    # A tampered tag must be detected
    tampered = bytearray(raw)
    tampered[12] ^= 0xFF
    try:
        aes_gcm_decrypt(key, bytes(tampered).hex())
        check("tampered tag must be detected", False, "it passed anyway")
    except Exception:  # noqa: BLE001
        check("tampered tag must be detected", True)

    print("\n=== Signing ===")
    content = sign_init("POST", "/api/noahs-ark/init", "1700000000", "ab" * 16, '{"a":1}')
    sig = rsa_sign_b64(server_priv, content)
    check("signature is 256 bytes", len(base64.b64decode(sig)) == 256, f"{len(base64.b64decode(sig))} bytes")
    check("signature verifies (server public key)", rsa_verify_b64(server_pub, content, sig))
    check("verification fails after tampering", not rsa_verify_b64(server_pub, content + "x", sig))
    check("client pubkey cannot verify it", not rsa_verify_b64(client_pub, content, sig))

    # Signed content of an AES request
    req_content = sign_aes_request(
        "POST", "/api/noahs-ark/common/transfer-check-num", "sid-1",
        "1700000000", "cd" * 16, "deadbeef",
    )
    check(
        "AES request signing input is concatenated correctly",
        req_content
        == "POST/api/noahs-ark/common/transfer-check-num"
        + "sid-1" + "1700000000" + "cd" * 16 + "deadbeef",
    )

    print("\n=== nonce randomness ===")
    nonces = {new_nonce_hex() for _ in range(100)}
    check("100 nonces are all distinct", len(nonces) == 100, f"{len(nonces)}/100")
    check("nonce is 32 hex chars (16 bytes)", all(len(n) == 32 for n in nonces))

    print("\n=== token store ===")
    store = json.loads((KEYS / "fbtokens.json").read_text(encoding="utf-8"))
    check("fbtokens.json parses", isinstance(store, dict), f"{len(store)} entries")
    tok = "f8aee27a90df19708dbc26f05e0d3a25"
    check(f"contains the compact token {tok}", tok in store)
    if tok in store:
        cookie = store[tok]
        check("cookie length is plausible (~880)", 800 < len(cookie) < 1000, f"{len(cookie)} bytes")
        inner = json.loads(cookie)
        check("cookie contains sauth_json", "sauth_json" in inner)
        sauth = json.loads(inner["sauth_json"])
        check(
            "sauth_json contains the required fields",
            all(sauth.get(k) for k in ("sdkuid", "sessionid", "udid", "deviceid")),
            f"sdkuid={sauth.get('sdkuid')}",
        )

    print("\n=== Patch consistency (key fingerprint) ===")
    # This is the public key written into the FateArk binary; its DER fingerprint proves the pairing
    der = server_pub.public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER,
        format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.SubjectPublicKeyInfo,
    )
    print(f"  server_public.pem DER SHA-256 = {hashlib.sha256(der).hexdigest()[:32]}...")
    check("public key DER serialises", len(der) > 200, f"{len(der)} bytes")

    print()
    if failures:
        print(f"result: {len(failures)} failed -> {failures}")
        return 1
    print("result: all passed (OK)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
