"""HA Server Agent: стан застосунків сервера (pm2, systemd, nginx, Duplicati, tmux, Docker…) і керування ними.

Кожен сервер — окремий запис інтеграції. Дані — з агента на сервері (підписані запити Ed25519).
Сервіс ha_server_agent.action виконує дозволену політикою агента дію й повертає результат.
"""

from __future__ import annotations

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv

from .api import AgentError
from .const import DOMAIN
from .coordinator import AgentCoordinator

PLATFORMS = [Platform.SENSOR, Platform.BINARY_SENSOR, Platform.UPDATE]

ACTION_SCHEMA = vol.Schema({
    vol.Required("server"): cv.string,
    vol.Required("module"): cv.string,
    vol.Optional("target", default=""): cv.string,
    vol.Required("action"): cv.string,
})


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    async def handle_action(call: ServiceCall) -> ServiceResponse:
        entry = hass.config_entries.async_get_entry(call.data["server"])
        if not entry or entry.domain != DOMAIN or not hasattr(entry, "runtime_data"):
            raise HomeAssistantError("Невідомий сервер")
        coord: AgentCoordinator = entry.runtime_data
        try:
            res = await coord.client.action(call.data["module"], call.data["target"], call.data["action"])
        except AgentError as e:
            raise HomeAssistantError(f"{entry.title}: {e}") from e
        await coord.async_request_refresh()
        if not res.get("ok") and not call.return_response:
            raise HomeAssistantError(f"{entry.title}: {res.get('output') or 'дія не вдалася'}")
        return {"ok": bool(res.get("ok")), "output": res.get("output", "")}

    hass.services.async_register(DOMAIN, "action", handle_action, schema=ACTION_SCHEMA,
                                 supports_response=SupportsResponse.OPTIONAL)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    coord = AgentCoordinator(hass, entry)
    await coord.async_config_entry_first_refresh()
    entry.runtime_data = coord
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
