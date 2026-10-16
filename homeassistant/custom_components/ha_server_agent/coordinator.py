"""Опитування агента раз на хвилину; нагадування в «Ремонтах», якщо агенту бракує секрету (напр. пароля Duplicati)."""

from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import AgentClient, AgentError
from .const import CONF_AGENT_KEY, CONF_CLIENT_KEY, CONF_FINGERPRINT, CONF_URL, DOMAIN, SCAN_INTERVAL

_LOGGER = logging.getLogger(__name__)


class AgentCoordinator(DataUpdateCoordinator[dict]):
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(hass, _LOGGER, name=f"{DOMAIN} {entry.title}", config_entry=entry,
                         update_interval=timedelta(seconds=SCAN_INTERVAL))
        self.client = AgentClient(async_get_clientsession(hass), entry.data[CONF_URL], entry.data[CONF_CLIENT_KEY],
                                  entry.data[CONF_AGENT_KEY], entry.data.get(CONF_FINGERPRINT, ""))
        self._issues: set[str] = set()

    async def _async_update_data(self) -> dict:
        try:
            data = await self.client.state()
        except AgentError as e:
            raise UpdateFailed(str(e)) from e
        self._sync_issues(data.get("modules") or {})
        return data

    def _sync_issues(self, mods: dict) -> None:
        entry = self.config_entry
        now: set[str] = set()
        for name, m in mods.items():
            ns = isinstance(m, dict) and m.get("needs_secret")
            if not ns:
                continue
            iid = f"secret_{entry.entry_id}_{name}"
            now.add(iid)
            ir.async_create_issue(
                self.hass, DOMAIN, iid, is_fixable=False, severity=ir.IssueSeverity.WARNING,
                translation_key="wrong_secret" if ns.get("wrong") else "needs_secret",
                translation_placeholders={"server": entry.title, "what": ns.get("what", name), "file": ns.get("file", ""),
                                          "key": ns.get("key", ""), "service": "ha-server-agent"})
        for iid in self._issues - now:
            ir.async_delete_issue(self.hass, DOMAIN, iid)
        self._issues = now
