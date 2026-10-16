"""Додавання сервера: адреса агента й його публічний ключ → HA створює свій ключ → додати його на сервері."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_NAME
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from . import protocol as P
from .api import AgentAuthError, AgentClient, AgentError, AgentSignatureError
from .const import CONF_AGENT_KEY, CONF_CLIENT_KEY, CONF_URL, DOMAIN


class DimServerAgentFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            url = user_input[CONF_URL].strip().rstrip("/")
            key = user_input[CONF_AGENT_KEY].strip()
            if not url.startswith(("https://", "http://")):
                errors[CONF_URL] = "bad_url"
            try:
                P.load_public(key)
            except Exception:  # noqa: BLE001
                errors[CONF_AGENT_KEY] = "bad_key"
            if not errors:
                await self.async_set_unique_id(P.key_id(key))
                self._abort_if_unique_id_configured()
                self._data = {CONF_NAME: user_input[CONF_NAME].strip(), CONF_URL: url, CONF_AGENT_KEY: key,
                              CONF_CLIENT_KEY: P.generate_keypair()[0]}
                return await self.async_step_authorize()
        return self.async_show_form(step_id="user", errors=errors, data_schema=vol.Schema({
            vol.Required(CONF_NAME): str,
            vol.Required(CONF_URL, default="https://"): str,
            vol.Required(CONF_AGENT_KEY): str,
        }))

    async def async_step_authorize(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        pub = P.public_of(self._data[CONF_CLIENT_KEY])
        if user_input is not None:
            client = AgentClient(async_get_clientsession(self.hass), self._data[CONF_URL],
                                 self._data[CONF_CLIENT_KEY], self._data[CONF_AGENT_KEY])
            try:
                info = await client.ping()
            except AgentAuthError:
                errors["base"] = "not_authorized"
            except AgentSignatureError:
                errors["base"] = "bad_agent_key"
            except AgentError:
                errors["base"] = "cannot_connect"
            else:
                return self.async_create_entry(title=self._data[CONF_NAME], data={
                    k: v for k, v in self._data.items() if k != CONF_NAME} | {"hostname": info.get("hostname")})
        return self.async_show_form(step_id="authorize", errors=errors, data_schema=vol.Schema({}),
                                    description_placeholders={"client_key": pub, "name": self._data[CONF_NAME]})
