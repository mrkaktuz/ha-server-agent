"""Протокол Dim Server Agent (DSA1): підписи запитів і відповідей ключами Ed25519.

Запит (клієнт → агент) несе заголовки:
  X-DSA-Key    — ідентифікатор ключа клієнта (перші 16 hex від SHA-256 публічного ключа)
  X-DSA-Time   — час клієнта, unix-секунди
  X-DSA-Nonce  — одноразове випадкове значення (32 hex)
  X-DSA-Sig    — base64-підпис рядка req_message(...)
Відповідь (агент → клієнт) несе X-DSA-Time і X-DSA-Sig — підпис resp_message(...), прив'язаний
до nonce запиту, тож перехоплену відповідь не можна підсунути на інший запит.

Цей файл без змін копіюється в інтеграцію Home Assistant (custom_components/dim_server_agent).
"""

import base64
import hashlib
import os
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PROTOCOL = "DSA1"
MAX_SKEW = 30  # секунд розбіжності годинників клієнта й агента

H_KEY = "X-DSA-Key"
H_TIME = "X-DSA-Time"
H_NONCE = "X-DSA-Nonce"
H_SIG = "X-DSA-Sig"


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.strip().encode("ascii"), validate=True)


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body or b"").hexdigest()


def req_message(method: str, path: str, ts: str, nonce: str, body: bytes) -> bytes:
    return "\n".join([PROTOCOL, method.upper(), path, ts, nonce, body_hash(body)]).encode()


def resp_message(status: int, nonce: str, ts: str, body: bytes) -> bytes:
    return "\n".join([PROTOCOL + "-RESP", str(status), nonce, ts, body_hash(body)]).encode()


def new_nonce() -> str:
    return secrets.token_hex(16)


# ---- Ключі: зберігаємо сирі 32 байти в base64 (один рядок — зручно копіювати)

def generate_keypair():
    """Повертає (private_b64, public_b64)."""
    priv = Ed25519PrivateKey.generate()
    return private_to_b64(priv), public_to_b64(priv.public_key())


def private_to_b64(priv: Ed25519PrivateKey) -> str:
    return b64e(priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))


def public_to_b64(pub: Ed25519PublicKey) -> str:
    return b64e(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def load_private(b64: str) -> Ed25519PrivateKey:
    raw = b64d(b64)
    if len(raw) != 32:
        raise ValueError("приватний ключ має бути 32 байти (base64)")
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_public(b64: str) -> Ed25519PublicKey:
    raw = b64d(b64)
    if len(raw) != 32:
        raise ValueError("публічний ключ має бути 32 байти (base64)")
    return Ed25519PublicKey.from_public_bytes(raw)


def key_id(public_b64: str) -> str:
    return hashlib.sha256(b64d(public_b64)).hexdigest()[:16]


def public_of(private_b64: str) -> str:
    return public_to_b64(load_private(private_b64).public_key())


def sign(priv: Ed25519PrivateKey, message: bytes) -> str:
    return b64e(priv.sign(message))


def verify(pub: Ed25519PublicKey, message: bytes, sig_b64: str) -> bool:
    try:
        pub.verify(b64d(sig_b64), message)
        return True
    except Exception:  # noqa: BLE001 — будь-яка помилка = підпис недійсний
        return False


def write_secret_file(path: str, text: str, mode: int = 0o600) -> None:
    """Записати файл так, щоб він ніколи не існував з ширшими правами."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(text.strip() + "\n")
    os.chmod(path, mode)
