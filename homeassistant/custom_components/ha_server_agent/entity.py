"""Спільна основа сутностей: пристрій = сервер."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import AgentCoordinator


class AgentEntity(CoordinatorEntity[AgentCoordinator]):
    _attr_has_entity_name = True

    def __init__(self, coord: AgentCoordinator, key: str, name: str) -> None:
        super().__init__(coord)
        entry = coord.config_entry
        self._attr_unique_id = f"{entry.entry_id}_{key}"
        self._attr_name = name
        data = coord.data or {}
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)}, name=entry.title, manufacturer="HA Server Agent",
            model=((data.get("modules") or {}).get("system") or {}).get("os"), sw_version=data.get("version"))

    @property
    def mods(self) -> dict:
        return (self.coordinator.data or {}).get("modules") or {}
