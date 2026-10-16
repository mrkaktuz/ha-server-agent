#!/usr/bin/python3
"""dim-agent — адміністрування агента на сервері (запускати через sudo).

  dim-agent show-key                    публічний ключ агента (вставити в Home Assistant)
  dim-agent add-client NAME PUBKEY      дозволити клієнта (ключ показує Home Assistant)
  dim-agent remove-client NAME          прибрати клієнта
  dim-agent clients                     список клієнтів
  dim-agent allow-ip IP[/MASK] ...      дозволені адреси клієнтів (порожньо — будь-які)
  dim-agent detect [--write [--force]]  що знайдено на сервері / записати policy.yaml
  dim-agent test                        самоперевірка: підписаний запит до локального агента
  dim-agent status                      стан сервісу й короткий підсумок
"""

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import yaml

sys.path.insert(0, "/usr/local/lib/dim-agent")
import protocol as P  # noqa: E402

ETC = "/etc/dim-agent"
CONFIG = ETC + "/agent.yaml"
KEY = ETC + "/agent.key"
HELPER = "/usr/local/lib/dim-agent/dim-agent-helper"


def need_root():
    if os.geteuid() != 0:
        sys.exit("запусти через sudo")


def load_cfg():
    with open(CONFIG) as f:
        return yaml.safe_load(f) or {}


def save_cfg(cfg):
    tmp = CONFIG + ".tmp"
    with open(tmp, "w") as f:
        f.write("# Налаштування мережевого шару dim-agent. Клієнтів додавати: sudo dim-agent add-client\n")
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
    os.chmod(tmp, 0o640)
    os.chown(tmp, 0, _gid())
    os.replace(tmp, CONFIG)


def _gid():
    import grp
    return grp.getgrnam("dim-agent").gr_gid


def show_key():
    print(P.public_of(open(KEY).read().strip()))


def add_client(name, key):
    P.load_public(key)  # перевірка формату
    cfg = load_cfg()
    cl = [c for c in cfg.get("clients") or [] if c.get("name") != name]
    cl.append({"name": name, "key": key.strip()})
    cfg["clients"] = cl
    save_cfg(cfg)
    print(f"Клієнта «{name}» додано (ключ {P.key_id(key)}). Агент перечитає налаштування сам.")


def remove_client(name):
    cfg = load_cfg()
    before = len(cfg.get("clients") or [])
    cfg["clients"] = [c for c in cfg.get("clients") or [] if c.get("name") != name]
    save_cfg(cfg)
    print("Прибрано." if len(cfg["clients"]) < before else "Такого клієнта немає.")


def clients():
    for c in load_cfg().get("clients") or []:
        print(f"{c.get('name'):24} {P.key_id(c['key'])}")


def allow_ip(ips):
    import ipaddress
    for ip in ips:
        ipaddress.ip_network(ip, strict=False)
    cfg = load_cfg()
    cfg["allow_ips"] = ips
    save_cfg(cfg)
    print("allow_ips:", ips or "будь-які")


def selftest():
    """Тимчасовий клієнт → підписаний /v1/ping і /v1/state → перевірка підпису відповіді → клієнта прибрати."""
    priv_b64, pub_b64 = P.generate_keypair()
    priv = P.load_private(priv_b64)
    agent_pub = P.load_public(P.public_of(open(KEY).read().strip()))
    cfg = load_cfg()
    saved = cfg.get("clients")
    cfg["clients"] = (saved or []) + [{"name": "selftest", "key": pub_b64}]
    save_cfg(cfg)
    try:
        time.sleep(0.2)
        url = f"http://{cfg.get('listen', '127.0.0.1')}:{cfg.get('port', 8787)}"
        for path in ("/v1/ping", "/v1/state"):
            ts, nonce = str(int(time.time())), P.new_nonce()
            req = urllib.request.Request(url + path, headers={
                P.H_KEY: P.key_id(pub_b64), P.H_TIME: ts, P.H_NONCE: nonce,
                P.H_SIG: P.sign(priv, P.req_message("GET", path, ts, nonce, b""))})
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read()
                ok = P.verify(agent_pub, P.resp_message(r.status, nonce, r.headers[P.H_TIME], body), r.headers[P.H_SIG])
            data = json.loads(body)
            if path == "/v1/ping":
                print(f"ping: {'OK' if ok else 'ПІДПИС ВІДПОВІДІ НЕДІЙСНИЙ'} — {data.get('hostname')} v{data.get('version')}")
            else:
                mods = data.get("modules", {})
                print("state: " + ("OK" if ok else "ПІДПИС НЕДІЙСНИЙ") + " — модулі: " + ", ".join(
                    f"{k}{'(помилка)' if v.get('error') else ''}" for k, v in mods.items()))
        # Без підпису — має бути 401
        try:
            urllib.request.urlopen(url + "/v1/state", timeout=10)
            print("УВАГА: запит без підпису пройшов!")
        except urllib.error.HTTPError as e:
            print(f"без підпису: {e.code} (так і має бути)")
    finally:
        cfg = load_cfg()
        cfg["clients"] = [c for c in cfg.get("clients") or [] if c.get("name") != "selftest"]
        save_cfg(cfg)


def status():
    subprocess.run(["systemctl", "--no-pager", "status", "dim-agent", "-n", "5"])
    cfg = load_cfg()
    print(f"\nклієнтів: {len(cfg.get('clients') or [])}, allow_ips: {cfg.get('allow_ips') or 'будь-які'}, "
          f"слухає {cfg.get('listen', '127.0.0.1')}:{cfg.get('port', 8787)}")
    print("публічний ключ агента:", P.public_of(open(KEY).read().strip()))


def main():
    need_root()
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        return
    c = a[0]
    if c == "show-key":
        show_key()
    elif c == "add-client" and len(a) == 3:
        add_client(a[1], a[2])
    elif c == "remove-client" and len(a) == 2:
        remove_client(a[1])
    elif c == "clients":
        clients()
    elif c == "allow-ip":
        allow_ip(a[1:])
    elif c == "detect":
        os.execv(HELPER, [HELPER, "detect"] + a[1:])
    elif c == "test":
        selftest()
    elif c == "status":
        status()
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
