"""Клієнт API агента: підписує запити ключем HA, перевіряє підпис кожної відповіді, закріплює сертифікат."""

from __future__ import annotations

import json
import time
from urllib.parse import urlsplit

import aiohttp

from . import protocol as P


class AgentError(Exception):
    """Загальна помилка зв'язку з агентом."""


class AgentAuthError(AgentError):
    """Агент не прийняв запит (ключ/секрет не ті, IP не дозволено або тимчасово заблоковано)."""


class AgentSignatureError(AgentError):
    """Відповідь не підписана ключем цього агента — можлива підміна."""


class AgentClient:
    def __init__(self, session: aiohttp.ClientSession, url: str, client_key: str, agent_key: str,
                 fingerprint: str = "") -> None:
        self._session = session
        self._base = url.rstrip("/")
        self._priv = P.load_private(client_key)
        self._pub_b64 = P.public_of(client_key)
        self._kid = P.key_id(self._pub_b64)
        self._agent_pub = P.load_public(agent_key)
        # Свій сертифікат агента: перевіряємо не центр сертифікації, а точний відбиток
        self._ssl = aiohttp.Fingerprint(bytes.fromhex(fingerprint)) if fingerprint else True

    def _check(self, status: int, headers, raw: bytes, nonce: str) -> dict:
        if status in (401, 429):
            raise AgentAuthError(f"агент відхилив запит (HTTP {status})")
        sig, rts = headers.get(P.H_SIG), headers.get(P.H_TIME)
        if not sig or not rts or not P.verify(self._agent_pub, P.resp_message(status, nonce, rts, raw), sig):
            raise AgentSignatureError("відповідь без дійсного підпису агента")
        if abs(time.time() - int(rts)) > P.MAX_SKEW * 2:
            raise AgentSignatureError("застаріла відповідь")
        data = json.loads(raw or b"{}")
        if status >= 400 and status not in (403, 500):
            raise AgentError(data.get("error") or f"HTTP {status}")
        return data

    async def _send(self, method: str, path: str, body: bytes, headers: dict, nonce: str, timeout: int) -> dict:
        try:
            async with self._session.request(method, self._base + path, data=body or None, headers=headers, ssl=self._ssl,
                                             timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                return self._check(r.status, r.headers, await r.read(), nonce)
        except aiohttp.ServerFingerprintMismatch as e:
            raise AgentSignatureError("сертифікат агента не той, що в коді підключення") from e
        except (aiohttp.ClientError, TimeoutError) as e:
            raise AgentError(f"немає зв'язку: {e}") from e

    async def _request(self, method: str, path: str, payload: dict | None = None, timeout: int = 30) -> dict:
        body = json.dumps(payload).encode() if payload is not None else b""
        ts, nonce = str(int(time.time())), P.new_nonce()
        signed_path = urlsplit(self._base + path).path or path
        headers = {P.H_KEY: self._kid, P.H_TIME: ts, P.H_NONCE: nonce,
                   P.H_SIG: P.sign(self._priv, P.req_message(method, signed_path, ts, nonce, body))}
        if body:
            headers["Content-Type"] = "application/json"
        return await self._send(method, path, body, headers, nonce, timeout)

    async def pair(self, secret: str, name: str) -> dict:
        """Сполучення одноразовим секретом із коду підключення: агент запам'ятовує публічний ключ HA."""
        ts, nonce = str(int(time.time())), P.new_nonce()
        payload = {"name": name, "key": self._pub_b64, "ts": ts, "nonce": nonce,
                   "mac": P.pair_mac(secret, name, self._pub_b64, ts, nonce)}
        return await self._send("POST", "/v1/pair", json.dumps(payload).encode(),
                                {"Content-Type": "application/json"}, nonce, 20)

    async def ping(self) -> dict:
        return await self._request("GET", "/v1/ping", timeout=15)

    async def state(self) -> dict:
        return await self._request("GET", "/v1/state", timeout=90)

    async def action(self, module: str, target: str, action: str) -> dict:
        return await self._request("POST", "/v1/action", {"module": module, "target": target, "action": action}, timeout=150)
