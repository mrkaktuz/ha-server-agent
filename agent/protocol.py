"""Протокол HA Server Agent (HSA1): підписи запитів і відповідей ключами Ed25519, сполучення, код підключення.

Запит (клієнт → агент):
  X-HSA-Key    — ідентифікатор ключа клієнта (перші 16 hex від SHA-256 публічного ключа)
  X-HSA-Time   — час клієнта, unix-секунди
  X-HSA-Nonce  — одноразове випадкове значення (32 hex)
  X-HSA-Sig    — base64-підпис req_message(...)
Відповідь (агент → клієнт): X-HSA-Time і X-HSA-Sig — підпис resp_message(...), прив'язаний до nonce запиту.

Сполучення (POST /v1/pair): клієнт ще не відомий агенту, тож доводить право одноразовим секретом із коду
підключення — HMAC-SHA256(secret, pair_message(...)). Агент додає його публічний ключ і знищує секрет.

Код підключення — те, що встановлювач показує людині: «HSA1:» + base64url(JSON {u: адреса, k: ключ агента,
f: SHA-256 сертифіката для закріплення або "", p: секрет сполучення, n: ім'я хоста}).

Цей файл без змін копіюється в інтеграцію Home Assistant (custom_components/ha_server_agent).
"""

import base64
import hashlib
import hmac
import json
import os
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PROTOCOL = "HSA1"
MAX_SKEW = 30  # секунд розбіжності годинників клієнта й агента

H_KEY = "X-HSA-Key"
H_TIME = "X-HSA-Time"
H_NONCE = "X-HSA-Nonce"
H_SIG = "X-HSA-Sig"


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


def pair_message(name: str, key: str, ts: str, nonce: str) -> bytes:
    return "\n".join([PROTOCOL + "-PAIR", name, key, ts, nonce]).encode()


def pair_mac(secret_b64: str, name: str, key: str, ts: str, nonce: str) -> str:
    return hmac.new(b64d(secret_b64), pair_message(name, key, ts, nonce), hashlib.sha256).hexdigest()


def new_nonce() -> str:
    return secrets.token_hex(16)


def new_secret() -> str:
    return b64e(secrets.token_bytes(32))


# ---- Ключі: сирі 32 байти в base64 (один рядок — зручно копіювати)

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


# ---- Код підключення

CODE_PREFIX = PROTOCOL + ":"


def make_code(url: str, agent_key: str, pair_secret: str, fingerprint: str = "", host: str = "") -> str:
    data = json.dumps({"u": url, "k": agent_key, "f": fingerprint, "p": pair_secret, "n": host}, separators=(",", ":"))
    return CODE_PREFIX + base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")


def parse_code(code: str) -> dict:
    code = "".join(code.split())
    if not code.startswith(CODE_PREFIX):
        raise ValueError("код має починатися з " + CODE_PREFIX)
    raw = code[len(CODE_PREFIX):]
    data = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    load_public(data["k"])
    b64d(data["p"])
    if not str(data.get("u", "")).startswith(("https://", "http://")):
        raise ValueError("некоректна адреса в коді")
    return data


def write_secret_file(path: str, text: str, mode: int = 0o600) -> None:
    """Записати файл так, щоб він ніколи не існував з ширшими правами."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(text.strip() + "\n")
    os.chmod(path, mode)
