"""Зведення стану сервера: що вважати проблемою (для сенсора «Проблеми» й дашборда)."""

from __future__ import annotations

from datetime import datetime, timezone


def _ts(v):
    try:
        return datetime.fromisoformat(v) if v else None
    except ValueError:
        return None


def problems(mods: dict) -> list[str]:
    out: list[str] = []
    s = mods.get("system") or {}
    for u in s.get("failed_units") or []:
        out.append(f"збій сервісу {u}")
    for u in (mods.get("systemd") or {}).get("units") or []:
        if u.get("oneshot") and u.get("result") == "success":
            continue  # одноразовий сервіс відпрацював і завершився — так і має бути
        if u.get("active") not in ("active", "reloading", "activating") and u.get("enabled") == "enabled" \
                and u["name"] not in (s.get("failed_units") or []):
            out.append(f"{u['name']}: {u.get('active')}")
    for inst in (mods.get("pm2") or {}).get("instances") or []:
        if inst.get("error"):
            out.append(f"pm2 ({inst['user']}): {inst['error'][:80]}")
        for a in inst.get("apps") or []:
            if a.get("status") != "online":
                out.append(f"pm2 {a.get('name')}: {a.get('status')}")
    ng = mods.get("nginx") or {}
    if ng.get("installed") and ng.get("config_ok") is False:
        out.append("nginx: помилка в конфігу")
    if ng.get("installed") and ng.get("active") in ("failed", "inactive"):
        out.append(f"nginx: {ng.get('active')}")
    c = mods.get("certs") or {}
    for cert in c.get("certs") or []:
        if not cert.get("used", True):
            continue  # лежить у Let's Encrypt, але nginx його не віддає — не проблема
        if cert.get("days_left") is not None and cert["days_left"] < (c.get("warn_days") or 14):
            out.append(f"сертифікат {cert.get('subject') or cert.get('path')}: {cert['days_left']} дн")
    d = mods.get("duplicati") or {}
    if d.get("error"):
        out.append(f"Duplicati: {d['error'][:80]}")
    for b in d.get("backups") or []:
        le, ls = _ts(b.get("last_error")), _ts(b.get("last_success"))
        if le and (not ls or le > ls):
            out.append(f"Duplicati «{b.get('name')}»: помилка")
        elif ls and (datetime.now(timezone.utc) - ls).days > 2:
            out.append(f"Duplicati «{b.get('name')}»: копії не було {(datetime.now(timezone.utc) - ls).days} дн")
    for name, m in mods.items():
        if isinstance(m, dict) and m.get("error") and name not in ("duplicati",):
            out.append(f"модуль {name}: {str(m['error'])[:80]}")
    return out
