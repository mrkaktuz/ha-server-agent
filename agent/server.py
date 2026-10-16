#!/usr/bin/python3
"""Dim Server Agent — мережевий шар (працює від непривілейованого користувача dim-agent).

Слухає лише локальну адресу (типово 127.0.0.1:8787); назовні — через nginx/Cloudflare (https).
Кожен запит має бути підписаний ключем клієнта з agent.yaml; перевірки по черзі:
  IP у списку дозволених → відомий ключ → час у межах ±30 с → nonce ще не траплявся → підпис.
Помилки автентифікації — однакова відповідь 401 без подробиць; після 10 невдач IP блокується на 15 хв.
Відповіді підписуються ключем агента (клієнт перевіряє, що говорить саме з цим сервером).
Дані й дії — через привілейований помічник (sudo helper collect|action), що звіряється з policy.yaml.

Ендпоінти: GET /v1/ping, GET /v1/state, POST /v1/action {"module","target","action"}.
"""

import http.server
import ipaddress
import json
import logging
import os
import socket
import subprocess
import sys
import threading
import time

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import protocol as P  # noqa: E402

VERSION = "0.1.0"
ETC = "/etc/dim-agent"
CONFIG = ETC + "/agent.yaml"
KEY = ETC + "/agent.key"
HELPER = "/usr/local/lib/dim-agent/dim-agent-helper"
AUDIT = "/var/log/dim-agent/audit.log"
MAX_BODY = 16 * 1024
STATE_TTL = 15  # с — кешуємо зібраний стан, щоб часті запити не навантажували сервер

log = logging.getLogger("dim-agent")


class Agent:
    def __init__(self):
        self.lock = threading.Lock()
        self.reload()
        self.nonces = {}        # nonce → час
        self.fails = {}         # ip → [час невдач]
        self.blocked = {}       # ip → до коли
        self.hits = {}          # ip → [час запитів]
        self.state_cache = (0.0, None)
        self.state_lock = threading.Lock()

    def reload(self):
        with open(CONFIG) as f:
            cfg = yaml.safe_load(f) or {}
        self.cfg = cfg
        self.priv = P.load_private(open(KEY).read().strip())
        self.clients = {}
        for c in cfg.get("clients") or []:
            try:
                self.clients[P.key_id(c["key"])] = (c.get("name") or "client", P.load_public(c["key"]))
            except Exception as e:  # noqa: BLE001
                log.error("пропускаю клієнта %s: %s", c.get("name"), e)
        self.allow = [ipaddress.ip_network(n, strict=False) for n in cfg.get("allow_ips") or []]
        self.mtime = os.path.getmtime(CONFIG)

    def maybe_reload(self):
        try:
            if os.path.getmtime(CONFIG) != self.mtime:
                with self.lock:
                    self.reload()
                log.info("agent.yaml перечитано: клієнтів %d", len(self.clients))
        except Exception as e:  # noqa: BLE001
            log.error("не вдалося перечитати agent.yaml: %s", e)

    # ---- захист від перебору й повторів

    def ip_blocked(self, ip):
        until = self.blocked.get(ip)
        return until and until > time.time()

    def note_fail(self, ip):
        now = time.time()
        f = [t for t in self.fails.get(ip, []) if now - t < 900] + [now]
        self.fails[ip] = f
        if len(f) >= int(self.cfg.get("max_failures", 10)):
            self.blocked[ip] = now + 900
            log.warning("IP %s заблоковано на 15 хв після %d невдалих спроб", ip, len(f))

    def rate_ok(self, ip):
        now = time.time()
        h = [t for t in self.hits.get(ip, []) if now - t < 60] + [now]
        self.hits[ip] = h
        return len(h) <= int(self.cfg.get("rate_per_minute", 120))

    def nonce_ok(self, nonce):
        now = time.time()
        with self.lock:
            for n, t in list(self.nonces.items()):
                if now - t > 2 * P.MAX_SKEW + 5:
                    del self.nonces[n]
            if nonce in self.nonces:
                return False
            self.nonces[nonce] = now
        return True

    # ---- робота

    def helper(self, cmd, stdin=None, timeout=120):
        p = subprocess.run(["sudo", "-n", HELPER, cmd], input=stdin, capture_output=True, text=True, timeout=timeout)
        try:
            return json.loads(p.stdout)
        except ValueError:
            raise RuntimeError((p.stderr or p.stdout or f"код {p.returncode}").strip()[:300])

    def state(self):
        with self.state_lock:
            t, data = self.state_cache
            if data is None or time.time() - t > STATE_TTL:
                data = self.helper("collect")
                self.state_cache = (time.time(), data)
            return data


def audit(line):
    try:
        with open(AUDIT, "a") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%S%z ") + line + "\n")
    except OSError:
        pass
    log.info("AUDIT %s", line)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "dim-agent"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 20  # с на запит — повільні з'єднання не тримають потоки

    def log_message(self, fmt, *args):  # пишемо самі, без зайвого
        pass

    @property
    def agent(self) -> Agent:
        return self.server.agent

    def client_ip(self):
        peer = self.client_address[0]
        hdr = self.agent.cfg.get("trusted_proxy_header", "CF-Connecting-IP")
        # Заголовку проксі віримо лише тоді, коли запит прийшов з локальної машини (nginx)
        if hdr and peer in ("127.0.0.1", "::1") and self.headers.get(hdr):
            return self.headers.get(hdr).split(",")[0].strip()
        return peer

    def send(self, status, obj, nonce=None):
        body = json.dumps(obj, ensure_ascii=False).encode()
        ts = str(int(time.time()))
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if nonce:
            self.send_header(P.H_TIME, ts)
            self.send_header(P.H_SIG, P.sign(self.agent.priv, P.resp_message(status, nonce, ts, body)))
        self.end_headers()
        self.wfile.write(body)

    def deny(self, ip, why, status=401):
        log.warning("відмова %s %s %s: %s", ip, self.command, self.path, why)
        if status == 401:
            self.agent.note_fail(ip)
        self.send(status, {"error": "unauthorized" if status == 401 else why})

    def authenticate(self, body):
        """Повертає (ім'я клієнта, nonce) або None (відповідь уже надіслано)."""
        a = self.agent
        a.maybe_reload()
        ip = self.client_ip()
        if a.ip_blocked(ip):
            self.send(429, {"error": "blocked"})
            return None
        if not a.rate_ok(ip):
            self.send(429, {"error": "rate limit"})
            return None
        try:
            ipobj = ipaddress.ip_address(ip)
        except ValueError:
            return self.deny(ip, "некоректна адреса")
        if a.allow and not any(ipobj in n for n in a.allow):
            return self.deny(ip, "IP не в allow_ips")
        kid, ts, nonce, sig = (self.headers.get(h, "") for h in (P.H_KEY, P.H_TIME, P.H_NONCE, P.H_SIG))
        if kid not in a.clients:
            return self.deny(ip, "невідомий ключ")
        if not ts.isdigit() or abs(time.time() - int(ts)) > P.MAX_SKEW:
            return self.deny(ip, "час запиту поза межами ±%d с" % P.MAX_SKEW)
        if len(nonce) != 32 or not all(c in "0123456789abcdef" for c in nonce):
            return self.deny(ip, "некоректний nonce")
        name, pub = a.clients[kid]
        if not P.verify(pub, P.req_message(self.command, self.path, ts, nonce, body), sig):
            return self.deny(ip, "підпис недійсний")
        if not a.nonce_ok(nonce):
            return self.deny(ip, "повтор nonce")
        a.fails.pop(ip, None)
        return name, nonce

    def read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("завеликий запит")
        return self.rfile.read(n) if n else b""

    def do_GET(self):
        auth = self.authenticate(b"")
        if not auth:
            return
        name, nonce = auth
        try:
            if self.path == "/v1/ping":
                self.send(200, {"ok": True, "version": VERSION, "hostname": socket.gethostname(), "client": name}, nonce)
            elif self.path == "/v1/state":
                self.send(200, {"version": VERSION, "hostname": socket.gethostname(), "time": int(time.time()),
                                "modules": self.agent.state()}, nonce)
            else:
                self.send(404, {"error": "not found"}, nonce)
        except Exception as e:  # noqa: BLE001
            log.exception("помилка %s", self.path)
            self.send(500, {"error": str(e)[:300]}, nonce)

    def do_POST(self):
        try:
            body = self.read_body()
        except ValueError:
            return self.send(413, {"error": "too large"})
        auth = self.authenticate(body)
        if not auth:
            return
        name, nonce = auth
        if self.path != "/v1/action":
            return self.send(404, {"error": "not found"}, nonce)
        try:
            req = json.loads(body or b"{}")
            req = {k: str(req.get(k, ""))[:200] for k in ("module", "target", "action")}
        except ValueError:
            return self.send(400, {"error": "bad json"}, nonce)
        try:
            res = self.agent.helper("action", json.dumps(req))
        except Exception as e:  # noqa: BLE001
            res = {"ok": False, "output": str(e)[:300]}
        audit(f"{name}@{self.client_ip()} {req['module']} {req['action']} {req['target']} → "
              f"{'ok' if res.get('ok') else ('ЗАБОРОНЕНО' if res.get('denied') else 'помилка')}")
        with self.agent.state_lock:
            self.agent.state_cache = (0.0, None)  # після дії — свіжий стан
        self.send(200 if res.get("ok") else (403 if res.get("denied") else 500), res, nonce)

    def do_PUT(self):
        self.send(405, {"error": "method not allowed"})

    do_DELETE = do_PATCH = do_HEAD = do_PUT


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stdout)
    agent = Agent()
    host, port = agent.cfg.get("listen", "127.0.0.1"), int(agent.cfg.get("port", 8787))
    cls = http.server.ThreadingHTTPServer
    if ":" in host:
        cls.address_family = socket.AF_INET6
    srv = cls((host, port), Handler)
    srv.agent = agent
    srv.daemon_threads = True
    log.info("dim-agent %s слухає %s:%d, клієнтів %d, allow_ips: %s", VERSION, host, port,
             len(agent.clients), agent.cfg.get("allow_ips") or "будь-які")
    srv.serve_forever()


if __name__ == "__main__":
    main()
