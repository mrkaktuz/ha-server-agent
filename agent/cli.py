#!/usr/bin/python3
"""ha-server-agent — адміністрування агента на сервері (запускати через sudo).

  ha-server-agent pair [--hours N]          новий код підключення для Home Assistant (діє N год, типово 24)
  ha-server-agent clients                   хто підключений
  ha-server-agent remove-client NAME        відключити клієнта
  ha-server-agent add-client NAME PUBKEY    додати клієнта вручну (без коду підключення)
  ha-server-agent allow-ip IP[/MASK] ...    дозволені адреси клієнтів (без аргументів — будь-які)
  ha-server-agent detect [--write --force]  що знайдено на сервері / перезаписати policy.yaml
  ha-server-agent test                      самоперевірка: підписаний запит до локального агента
  ha-server-agent update                    оновити агента з git (те саме робить кнопка «Встановити» в HA)
  ha-server-agent status                    стан сервісу й підсумок
"""

import grp
import json
import os
import pwd
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

import yaml

sys.path.insert(0, "/usr/local/lib/ha-server-agent")
import protocol as P  # noqa: E402

ETC = "/etc/ha-server-agent"
CONFIG = ETC + "/agent.yaml"
KEY = ETC + "/agent.key"
STATE = ETC + "/state"
CLIENTS = STATE + "/clients.yaml"
PAIRING = STATE + "/pairing.json"
HELPER = "/usr/local/lib/ha-server-agent/ha-server-agent-helper"
USER = "ha-agent"


def need_root():
    if os.geteuid() != 0:
        sys.exit("Запусти через sudo")


def load_cfg():
    with open(CONFIG) as f:
        return yaml.safe_load(f) or {}


def save_cfg(cfg):
    tmp = CONFIG + ".tmp"
    with open(tmp, "w") as f:
        f.write("# Налаштування мережевого шару ha-server-agent (див. README)\n")
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
    os.chmod(tmp, 0o640)
    os.chown(tmp, 0, grp.getgrnam(USER).gr_gid)
    os.replace(tmp, CONFIG)


def owned_by_agent(path):
    pw = pwd.getpwnam(USER)
    os.chown(path, pw.pw_uid, pw.pw_gid)
    os.chmod(path, 0o600)


def load_clients():
    try:
        with open(CLIENTS) as f:
            return (yaml.safe_load(f) or {}).get("clients") or []
    except FileNotFoundError:
        return []


def save_clients(cl):
    with open(CLIENTS, "w") as f:
        f.write("# Клієнти агента (публічні ключі)\n")
        yaml.safe_dump({"clients": cl}, f, allow_unicode=True, sort_keys=False)
    owned_by_agent(CLIENTS)


def agent_url(cfg):
    if cfg.get("public_url"):
        return cfg["public_url"]
    scheme = "https" if (cfg.get("tls") or {}).get("cert") else "http"
    return f"{scheme}://{cfg.get('listen', '127.0.0.1')}:{cfg.get('port', 8787)}"


def fingerprint(cfg):
    """Відбиток сертифіката для закріплення в HA: власний TLS агента або не довірений сертифікат nginx."""
    cert = (cfg.get("tls") or {}).get("cert") or cfg.get("pin_cert")
    if not cert:
        return ""
    pem = open(cert).read()
    pem = pem.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"  # перший (листовий)
    der = ssl.PEM_cert_to_DER_cert(pem)
    import hashlib
    return hashlib.sha256(der).hexdigest()


def pair(hours=24):
    cfg = load_cfg()
    secret = P.new_secret()
    with open(PAIRING, "w") as f:
        json.dump({"secret": secret, "expires": time.time() + hours * 3600}, f)
    owned_by_agent(PAIRING)
    code = P.make_code(agent_url(cfg), P.public_of(open(KEY).read().strip()), secret, fingerprint(cfg), socket.gethostname())
    print("Код підключення (діє %d год, одноразовий):\n\n%s\n" % (hours, code))
    print("Home Assistant → Налаштування → Пристрої та служби → Додати інтеграцію → HA Server Agent → вставити код.")


def clients():
    cl = load_clients()
    if not cl:
        print("Клієнтів немає. Код підключення: sudo ha-server-agent pair")
    for c in cl:
        print(f"{c.get('name'):24} {P.key_id(c['key'])}  {c.get('added', '')}")


def add_client(name, key):
    P.load_public(key)
    cl = [c for c in load_clients() if c.get("name") != name] + [{"name": name, "key": key.strip(), "added": time.strftime("%Y-%m-%d %H:%M")}]
    save_clients(cl)
    print(f"Клієнта «{name}» додано ({P.key_id(key)}).")


def remove_client(name):
    cl = load_clients()
    rest = [c for c in cl if c.get("name") != name]
    save_clients(rest)
    print("Прибрано." if len(rest) < len(cl) else "Такого клієнта немає.")


def allow_ip(ips):
    import ipaddress
    for ip in ips:
        ipaddress.ip_network(ip, strict=False)
    cfg = load_cfg()
    cfg["allow_ips"] = ips
    save_cfg(cfg)
    print("allow_ips:", ips or "будь-які")


def local_request(cfg, path, headers=None):
    scheme = "https" if (cfg.get("tls") or {}).get("cert") else "http"
    host = "127.0.0.1" if cfg.get("listen", "127.0.0.1") in ("0.0.0.0", "127.0.0.1") else cfg["listen"]
    ctx = ssl._create_unverified_context() if scheme == "https" else None  # свій сертифікат, перевіряємо підпис
    req = urllib.request.Request(f"{scheme}://{host}:{cfg.get('port', 8787)}{path}", headers=headers or {})
    return urllib.request.urlopen(req, timeout=60, context=ctx)


def selftest():
    """Тимчасовий клієнт → підписані /v1/ping і /v1/state → перевірка підпису відповіді → клієнта прибрати."""
    priv_b64, pub_b64 = P.generate_keypair()
    priv = P.load_private(priv_b64)
    agent_pub = P.load_public(P.public_of(open(KEY).read().strip()))
    cfg = load_cfg()
    saved = load_clients()
    save_clients(saved + [{"name": "selftest", "key": pub_b64}])
    ok_all = True
    try:
        time.sleep(0.3)
        for path in ("/v1/ping", "/v1/state"):
            ts, nonce = str(int(time.time())), P.new_nonce()
            with local_request(cfg, path, {P.H_KEY: P.key_id(pub_b64), P.H_TIME: ts, P.H_NONCE: nonce,
                                           P.H_SIG: P.sign(priv, P.req_message("GET", path, ts, nonce, b""))}) as r:
                body = r.read()
                ok = P.verify(agent_pub, P.resp_message(r.status, nonce, r.headers[P.H_TIME], body), r.headers[P.H_SIG])
            ok_all &= ok
            data = json.loads(body)
            if path == "/v1/ping":
                print(f"ping: {'OK' if ok else 'ПІДПИС ВІДПОВІДІ НЕДІЙСНИЙ'} — {data.get('hostname')} v{data.get('version')}")
            else:
                mods = data.get("modules", {})
                print("state: " + ("OK" if ok else "ПІДПИС НЕДІЙСНИЙ") + " — модулі: " + ", ".join(
                    f"{k}{'(помилка)' if v.get('error') else ''}" for k, v in mods.items()))
                for k, v in mods.items():
                    if v.get("needs_secret"):
                        ns = v["needs_secret"]
                        print(f"  ! {ns['what']}: додай у {ns['file']} рядок «{ns['key']}: \"…\"» (HA теж нагадає)")
        try:
            local_request(cfg, "/v1/state")
            print("УВАГА: запит без підпису пройшов!")
            ok_all = False
        except urllib.error.HTTPError as e:
            print(f"без підпису: {e.code} (так і має бути)")
    finally:
        save_clients(saved)
    return ok_all


def status():
    subprocess.run(["systemctl", "--no-pager", "status", "ha-server-agent", "-n", "5"])
    cfg = load_cfg()
    print(f"\nадреса для HA: {agent_url(cfg)}, клієнтів: {len(load_clients())}, allow_ips: {cfg.get('allow_ips') or 'будь-які'}")


def main():
    need_root()
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        return
    c = a[0]
    if c == "pair":
        pair(int(a[a.index("--hours") + 1]) if "--hours" in a else 24)
    elif c == "clients":
        clients()
    elif c == "add-client" and len(a) == 3:
        add_client(a[1], a[2])
    elif c == "remove-client" and len(a) == 2:
        remove_client(a[1])
    elif c == "allow-ip":
        allow_ip(a[1:])
    elif c == "detect":
        os.execv(HELPER, [HELPER, "detect"] + a[1:])
    elif c == "test":
        sys.exit(0 if selftest() else 1)
    elif c == "update":
        p = subprocess.run([HELPER, "action"], input=json.dumps({"module": "agent", "target": "", "action": "update"}),
                           capture_output=True, text=True)
        print(json.loads(p.stdout or "{}").get("output") or p.stderr)
    elif c == "status":
        status()
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
