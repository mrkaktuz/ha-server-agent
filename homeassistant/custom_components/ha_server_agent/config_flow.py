"""Додавання сервера: назва + код підключення (його показує встановлювач агента) → HA сам сполучається з агентом."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_NAME
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import TextSelector, TextSelectorConfig

from . import protocol as P
from .api import AgentAuthError, AgentClient, AgentError, AgentSignatureError
from .const import CONF_AGENT_KEY, CONF_CLIENT_KEY, CONF_CODE, CONF_FINGERPRINT, CONF_URL, DOMAIN


class HaServerAgentFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                code = P.parse_code(user_input[CONF_CODE])
            except Exception:  # noqa: BLE001
                errors[CONF_CODE] = "bad_code"
            else:
                await self.async_set_unique_id(P.key_id(code["k"]))
                self._abort_if_unique_id_configured()
                client_key = P.generate_keypair()[0]
                client = AgentClient(async_get_clientsession(self.hass), code["u"], client_key, code["k"], code.get("f", ""))
                try:
                    await client.pair(code["p"], "home-assistant")
                    info = await client.ping()
                except AgentAuthError:
                    errors["base"] = "pair_refused"
                except AgentSignatureError:
                    errors["base"] = "bad_identity"
                except AgentError:
                    errors["base"] = "cannot_connect"
                else:
                    return self.async_create_entry(title=user_input[CONF_NAME].strip() or code.get("n") or "Сервер", data={
                        CONF_URL: code["u"], CONF_AGENT_KEY: code["k"], CONF_CLIENT_KEY: client_key,
                        CONF_FINGERPRINT: code.get("f", ""), "hostname": info.get("hostname")})
        return self.async_show_form(step_id="user", errors=errors, data_schema=vol.Schema({
            vol.Required(CONF_NAME): str,
            vol.Required(CONF_CODE): TextSelector(TextSelectorConfig(multiline=True)),
        }))
