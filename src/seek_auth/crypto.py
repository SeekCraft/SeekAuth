"""SeekAuth — cryptographic primitives.

Two-stage encryption as used by NetEase's "Noah's Ark" protocol:

**Stage 1 (init)** — RSA-2048
  * The request body ``{"data": "<hex>"}`` is RSA-OAEP(SHA-256) ciphertext,
    decrypted with **this verification server's private key** (the server public
    key inside the FateArk binary has been replaced with ours).
  * The response is RSA-OAEP(SHA-256) as well, encrypted with the **FateArk
    client public key** (the client then opens it with its own private key).
  * Responses carry a ``Sign`` header: RSA PKCS#1 v1.5 + SHA-256, see :func:`sign_init`.

**Stage 2 (AES-GCM)** — session key
  * The ``sessionKey`` returned by init is the hex of a 32-byte AES-256 key.
  * **The ciphertext layout is non-standard**: ``nonce(12) || tag(16) || ciphertext``,
    hex-encoded as a whole. Standard GCM is ``nonce || ciphertext || tag``, so the
    library's default concatenation cannot be used as-is.
  * Both request and response carry ``Sign``; see :func:`sign_aes_request` /
    :func:`sign_aes_response` for the signed content.

Every detail here comes from reverse engineering the FateArk binary and differs
from the public GCM conventions; changing them makes the client fail to decrypt.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
TAG_LEN = 16
SESSION_KEY_LEN = 32  # AES-256


class CryptoError(Exception):
    """Encryption, decryption or signing failed."""


# ─────────────────────────── Key loading ───────────────────────────


def load_private_key(path: Path | str) -> rsa.RSAPrivateKey:
    """Load a PEM private key (PKCS#8 and PKCS#1)."""
    data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CryptoError(f"{path} is not an RSA private key")
    return key


def load_public_key(path: Path | str) -> rsa.RSAPublicKey:
    """Load a PEM public key (SubjectPublicKeyInfo)."""
    data = Path(path).read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, rsa.RSAPublicKey):
        raise CryptoError(f"{path} is not an RSA public key")
    return key


# ─────────────────────────── RSA ───────────────────────────


def rsa_decrypt_hex(private_key: rsa.RSAPrivateKey, data_hex: str) -> bytes:
    """Decrypt hex ciphertext with RSA-OAEP(SHA-256)."""
    try:
        ciphertext = bytes.fromhex(data_hex)
    except ValueError as e:
        raise CryptoError(f"hex decode failed: {e}") from e
    try:
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:  # noqa: BLE001 - normalize everything to CryptoError
        raise CryptoError(f"RSA decryption failed: {e}") from e


def rsa_encrypt_hex(public_key: rsa.RSAPublicKey, plain: bytes) -> str:
    """Encrypt with RSA-OAEP(SHA-256) and return hex."""
    ciphertext = public_key.encrypt(
        plain,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext.hex()


def rsa_sign_b64(private_key: rsa.RSAPrivateKey, content: str) -> str:
    """Sign with RSA PKCS#1 v1.5 + SHA-256 and return base64."""
    signature = private_key.sign(
        content.encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode()


def rsa_verify_b64(public_key: rsa.RSAPublicKey, content: str, signature_b64: str) -> bool:
    """Verify an RSA PKCS#1 v1.5 + SHA-256 signature. False on failure (no raise)."""
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception:  # noqa: BLE001
        return False
    try:
        public_key.verify(
            signature,
            content.encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:  # noqa: BLE001 - a failed check is a normal branch
        return False


# ─────────────────────────── AES-GCM (non-standard layout) ───────────────────────────


def aes_gcm_encrypt(key: bytes, plain: bytes) -> str:
    """AES-256-GCM encrypt, returning the hex of ``nonce(12) || tag(16) || ciphertext``.

    Note: ``cryptography``'s ``AESGCM.encrypt`` returns ``ciphertext || tag``, which has
    to be split apart and re-joined in NetEase's order.
    """
    if len(key) != SESSION_KEY_LEN:
        raise CryptoError(f"AES key must be {SESSION_KEY_LEN} bytes, got {len(key)}")
    nonce = os.urandom(NONCE_LEN)
    sealed = AESGCM(key).encrypt(nonce, plain, None)  # ciphertext || tag
    ciphertext, tag = sealed[:-TAG_LEN], sealed[-TAG_LEN:]
    return (nonce + tag + ciphertext).hex()


def aes_gcm_decrypt(key: bytes, data_hex: str) -> bytes:
    """Decrypt hex ciphertext laid out as ``nonce(12) || tag(16) || ciphertext``."""
    if len(key) != SESSION_KEY_LEN:
        raise CryptoError(f"AES key must be {SESSION_KEY_LEN} bytes, got {len(key)}")
    try:
        full = bytes.fromhex(data_hex)
    except ValueError as e:
        raise CryptoError(f"hex decode failed: {e}") from e
    if len(full) < NONCE_LEN + TAG_LEN:
        raise CryptoError(f"ciphertext too short: {len(full)} bytes")

    nonce = full[:NONCE_LEN]
    tag = full[NONCE_LEN : NONCE_LEN + TAG_LEN]
    ciphertext = full[NONCE_LEN + TAG_LEN :]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext + tag, None)
    except Exception as e:  # noqa: BLE001
        raise CryptoError(f"AES decryption failed: {e}") from e


# ─────────────────────────── Signing-input construction ───────────────────────────


def sign_init(method: str, path: str, timestamp: str, nonce: str, plaintext: str) -> str:
    """Signed content of the init-stage response: ``method + path + ts + nonce + plaintext``.

    (init has no sessionId.)
    """
    return f"{method}{path}{timestamp}{nonce}{plaintext}"


def sign_aes_request(
    method: str, path: str, session_id: str, timestamp: str, nonce: str, data_hex: str
) -> str:
    """Signed content of a session-stage **request**:
    ``method + path + sessionId + ts + nonce + dataHex``."""
    return f"{method}{path}{session_id}{timestamp}{nonce}{data_hex}"


def sign_aes_response(
    method: str, path: str, session_id: str, timestamp: str, nonce: str, data_hex: str
) -> str:
    """Signed content of a session-stage **response** (same shape as the request,
    but over a fresh ts/nonce/ciphertext)."""
    return f"{method}{path}{session_id}{timestamp}{nonce}{data_hex}"


# ─────────────────────────── Misc ───────────────────────────


def new_nonce_hex() -> str:
    """Generate a 16-byte random nonce as hex (the ``Nonce`` response header)."""
    return os.urandom(16).hex()


def new_session_key() -> tuple[str, bytes]:
    """Generate a session key and return ``(hex, raw_bytes)``."""
    key = os.urandom(SESSION_KEY_LEN)
    return key.hex(), key


def sha256_hex(data: bytes) -> str:
    """SHA-256 digest as hex."""
    return hashlib.sha256(data).hexdigest()
