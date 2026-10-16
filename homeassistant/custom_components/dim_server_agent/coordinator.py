"""Опитування агента раз на хвилину."""

from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import AgentClient, AgentError
from .const import CONF_AGENT_KEY, CONF_CLIENT_KEY, CONF_URL, DOMAIN, SCAN_INTERVAL

_LOGGER = logging.getLogger(__name__)


class AgentCoordinator(DataUpdateCoordinator[dict]):
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(hass, _LOGGER, name=f"{DOMAIN} {entry.title}", config_entry=entry,
                         update_interval=timedelta(seconds=SCAN_INTERVAL))
        self.client = AgentClient(async_get_clientsession(hass), entry.data[CONF_URL],
                                  entry.data[CONF_CLIENT_KEY], entry.data[CONF_AGENT_KEY])

    async def _async_update_data(self) -> dict:
        try:
            return await self.client.state()
        except AgentError as e:
            raise UpdateFailed(str(e)) from e
