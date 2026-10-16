"""Сенсори сервера: проблеми (з повним станом в атрибутах — для дашборда), оновлення, сертифікати, pm2, копії."""

from __future__ import annotations

from datetime import datetime

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .entity import AgentEntity
from .summary import problems


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, add: AddEntitiesCallback) -> None:
    c = entry.runtime_data
    ents = [Problems(c), Updates(c), Pm2Online(c), CertDays(c), LastBackup(c)]
    add(ents)


class Problems(AgentEntity, SensorEntity):
    """Стан — кількість проблем; атрибути — список проблем і весь стан модулів (для дашборда)."""
    _attr_icon = "mdi:server-security"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _unrecorded_attributes = frozenset({"modules", "problems", "entry_id"})

    def __init__(self, c):
        super().__init__(c, "problems", "Проблеми")

    @property
    def native_value(self):
        return len(problems(self.mods))

    @property
    def extra_state_attributes(self):
        d = self.coordinator.data or {}
        return {"problems": problems(self.mods), "modules": self.mods, "agent_version": d.get("version"),
                "hostname": d.get("hostname"), "entry_id": self.coordinator.config_entry.entry_id}


class Updates(AgentEntity, SensorEntity):
    _attr_icon = "mdi:package-up"
    _attr_native_unit_of_measurement = "пакетів"

    def __init__(self, c):
        super().__init__(c, "updates", "Оновлення пакетів")

    @property
    def native_value(self):
        u = (self.mods.get("system") or {}).get("updates")
        return u.get("total") if u else None

    @property
    def extra_state_attributes(self):
        s = self.mods.get("system") or {}
        return {"security": (s.get("updates") or {}).get("security"), "reboot_required": s.get("reboot_required")}


class Pm2Online(AgentEntity, SensorEntity):
    _attr_icon = "mdi:nodejs"

    def __init__(self, c):
        super().__init__(c, "pm2_online", "pm2: працює")

    def _apps(self):
        return [a for i in (self.mods.get("pm2") or {}).get("instances") or [] for a in i.get("apps") or []]

    @property
    def available(self):
        return super().available and "pm2" in self.mods

    @property
    def native_value(self):
        return sum(1 for a in self._apps() if a.get("status") == "online")

    @property
    def extra_state_attributes(self):
        return {"total": len(self._apps()), "stopped": [a["name"] for a in self._apps() if a.get("status") != "online"]}


class CertDays(AgentEntity, SensorEntity):
    _attr_icon = "mdi:certificate"
    _attr_native_unit_of_measurement = "дн"

    def __init__(self, c):
        super().__init__(c, "cert_days", "Сертифікат: днів до кінця")

    @property
    def available(self):
        return super().available and bool((self.mods.get("certs") or {}).get("certs"))

    @property
    def native_value(self):
        return (self.mods.get("certs") or {}).get("min_days")

    @property
    def extra_state_attributes(self):
        return {"certs": [{"name": c.get("subject"), "days": c.get("days_left")} for c in (self.mods.get("certs") or {}).get("certs") or []]}


class LastBackup(AgentEntity, SensorEntity):
    """Найдавніша з останніх вдалих копій Duplicati (якщо хоч одне завдання відстає — видно тут)."""
    _attr_icon = "mdi:backup-restore"
    _attr_device_class = SensorDeviceClass.TIMESTAMP

    def __init__(self, c):
        super().__init__(c, "last_backup", "Duplicati: остання копія")

    def _b(self):
        return (self.mods.get("duplicati") or {}).get("backups") or []

    @property
    def available(self):
        return super().available and bool(self._b())

    @property
    def native_value(self):
        ts = [datetime.fromisoformat(b["last_success"]) for b in self._b() if b.get("last_success")]
        return min(ts) if ts else None
