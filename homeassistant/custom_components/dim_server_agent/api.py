"""Клієнт API агента: підписує запити ключем HA і перевіряє підпис кожної відповіді."""

from __future__ import annotations

import json
import time
from urllib.parse import urlsplit

import aiohttp

from . import protocol as P


class AgentError(Exception):
    """Загальна помилка зв'язку з агентом."""


class AgentAuthError(AgentError):
    """Агент не прийняв ключ HA (ще не додано add-client або IP не дозволено)."""


class AgentSignatureError(AgentError):
    """Відповідь не підписана ключем цього агента — можлива підміна."""


class AgentClient:
    def __init__(self, session: aiohttp.ClientSession, url: str, client_key: str, agent_key: str) -> None:
        self._session = session
        self._base = url.rstrip("/")
        self._priv = P.load_private(client_key)
        self._kid = P.key_id(P.public_of(client_key))
        self._agent_pub = P.load_public(agent_key)

    async def _request(self, method: str, path: str, payload: dict | None = None, timeout: int = 30) -> dict:
        body = json.dumps(payload).encode() if payload is not None else b""
        ts, nonce = str(int(time.time())), P.new_nonce()
        signed_path = urlsplit(self._base + path).path or path
        headers = {
            P.H_KEY: self._kid, P.H_TIME: ts, P.H_NONCE: nonce,
            P.H_SIG: P.sign(self._priv, P.req_message(method, signed_path, ts, nonce, body)),
        }
        if body:
            headers["Content-Type"] = "application/json"
        try:
            async with self._session.request(method, self._base + path, data=body or None, headers=headers,
                                             timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                raw = await r.read()
                if r.status in (401, 429):
                    raise AgentAuthError(f"агент відхилив запит (HTTP {r.status})")
                sig, rts = r.headers.get(P.H_SIG), r.headers.get(P.H_TIME)
                if not sig or not rts or not P.verify(self._agent_pub, P.resp_message(r.status, nonce, rts, raw), sig):
                    raise AgentSignatureError("відповідь без дійсного підпису агента")
                if abs(time.time() - int(rts)) > P.MAX_SKEW * 2:
                    raise AgentSignatureError("застаріла відповідь")
                data = json.loads(raw or b"{}")
                if r.status >= 400 and r.status not in (403, 500):
                    raise AgentError(data.get("error") or f"HTTP {r.status}")
                data.setdefault("_status", r.status)
                return data
        except (aiohttp.ClientError, TimeoutError) as e:
            raise AgentError(f"немає зв'язку: {e}") from e

    async def ping(self) -> dict:
        return await self._request("GET", "/v1/ping", timeout=15)

    async def state(self) -> dict:
        return await self._request("GET", "/v1/state", timeout=90)

    async def action(self, module: str, target: str, action: str) -> dict:
        return await self._request("POST", "/v1/action", {"module": module, "target": target, "action": action}, timeout=150)
