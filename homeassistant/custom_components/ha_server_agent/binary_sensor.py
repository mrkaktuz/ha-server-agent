"""Бінарні сенсори: агент на зв'язку, потрібне перезавантаження, помилка в конфігу nginx."""

from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .entity import AgentEntity


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, add: AddEntitiesCallback) -> None:
    c = entry.runtime_data
    add([Online(c), Reboot(c), NginxBad(c)])


class Online(AgentEntity, BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, c):
        super().__init__(c, "online", "Агент на зв'язку")

    @property
    def available(self):
        return True

    @property
    def is_on(self):
        return self.coordinator.last_update_success


class Reboot(AgentEntity, BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_icon = "mdi:restart-alert"

    def __init__(self, c):
        super().__init__(c, "reboot_required", "Потрібне перезавантаження")

    @property
    def is_on(self):
        return bool((self.mods.get("system") or {}).get("reboot_required"))

    @property
    def extra_state_attributes(self):
        return {"packages": (self.mods.get("system") or {}).get("reboot_pkgs")}


class NginxBad(AgentEntity, BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_icon = "mdi:nginx"

    def __init__(self, c):
        super().__init__(c, "nginx_config", "nginx: помилка конфігу")

    @property
    def available(self):
        return super().available and (self.mods.get("nginx") or {}).get("installed", False)

    @property
    def is_on(self):
        return (self.mods.get("nginx") or {}).get("config_ok") is False

    @property
    def extra_state_attributes(self):
        return {"output": (self.mods.get("nginx") or {}).get("config_output")}
