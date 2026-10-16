"""Оновлення агента: агент сам дивиться в git-репозиторій; «Встановити» — агент підтягує новий код і перевстановлюється."""

from __future__ import annotations

from typing import Any

from homeassistant.components.update import UpdateEntity, UpdateEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_call_later

from .api import AgentError
from .entity import AgentEntity


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, add: AddEntitiesCallback) -> None:
    add([AgentUpdate(entry.runtime_data)])


class AgentUpdate(AgentEntity, UpdateEntity):
    _attr_supported_features = UpdateEntityFeature.INSTALL
    _attr_title = "HA Server Agent"

    def __init__(self, c):
        super().__init__(c, "agent_update", "Агент")
        self._installing = False

    @property
    def _a(self) -> dict:
        return self.mods.get("agent") or {}

    @property
    def available(self) -> bool:
        return super().available and bool(self._a.get("commit"))

    @property
    def installed_version(self) -> str | None:
        a = self._a
        return f"{a.get('version')} ({a.get('commit')})" if a.get("commit") else a.get("version")

    @property
    def latest_version(self) -> str | None:
        a = self._a
        if a.get("update_available"):
            return f"новіша ({a.get('remote_commit')})"
        return self.installed_version

    @property
    def release_summary(self) -> str | None:
        a = self._a
        if a.get("error_update"):
            return f"Не вдалося перевірити оновлення: {a['error_update']}"
        return a.get("remote_subject") if a.get("update_available") else None

    @property
    def in_progress(self) -> bool:
        return self._installing

    async def async_install(self, version: str | None, backup: bool, **kwargs: Any) -> None:
        try:
            res = await self.coordinator.client.action("agent", "", "update")
        except AgentError as e:
            raise HomeAssistantError(str(e)) from e
        if not res.get("ok"):
            raise HomeAssistantError(res.get("output") or "оновлення не запустилось")
        self._installing = True
        self.async_write_ha_state()

        async def done(_now):
            self._installing = False
            await self.coordinator.async_request_refresh()
            self.async_write_ha_state()
        # Агент перезапускається з новим кодом; за півтори хвилини перечитуємо стан
        async_call_later(self.hass, 90, done)
