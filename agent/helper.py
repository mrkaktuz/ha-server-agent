#!/usr/bin/python3
"""HA Server Agent — привілейований помічник (працює від root через sudo).

Агент (непривілейований) викликає лише три команди:
  helper collect          — зібрати стан усіх увімкнених модулів (JSON у stdout)
  helper action           — виконати дію; запит JSON у stdin: {"module", "target", "action"}
  helper detect           — знайти, що є на сервері, і вивести пропозицію політики (YAML)
Що дозволено — лише з /etc/ha-server-agent/policy.yaml (власник root). Жодних довільних команд:
кожна дія — фіксований argv без оболонки, ціль перевіряється за поточним станом.
"""

import datetime as dt
import glob
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

import yaml

ETC = "/etc/ha-server-agent"
POLICY = ETC + "/policy.yaml"
SECRETS = ETC + "/secrets.yaml"
CACHE = "/var/cache/ha-server-agent"
ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
OUT_LIMIT = 4000


# --------------------------------------------------------------------------- утиліти

def run(argv, timeout=20, user=None, env=None, stdin=None):
    """Виконати команду без оболонки. Повертає (код, stdout, stderr)."""
    e = dict(ENV)
    if env:
        e.update(env)
    if user and user != "root":
        argv = ["runuser", "-u", user, "--", "env"] + [f"{k}={v}" for k, v in e.items()] + list(argv)
    try:
        p = subprocess.run(argv, env=e, input=stdin, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"не знайдено: {argv[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "перевищено час очікування"


ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def tail(text, n=OUT_LIMIT):
    text = ANSI.sub("", text or "").strip()
    return text if len(text) <= n else "…" + text[-n:]


def cached(name, ttl, fn):
    """Повільні перевірки (apt, nginx -t, сертифікати) — не частіше, ніж раз на ttl секунд."""
    os.makedirs(CACHE, mode=0o700, exist_ok=True)
    path = os.path.join(CACHE, name + ".json")
    try:
        if time.time() - os.path.getmtime(path) < ttl:
            with open(path) as f:
                return json.load(f)
    except (OSError, ValueError):
        pass
    data = fn()
    try:
        with open(path, "w") as f:
            json.dump(data, f)
    except OSError:
        pass
    return data


def drop_cache(name):
    try:
        os.remove(os.path.join(CACHE, name + ".json"))
    except OSError:
        pass


def load_yaml(path):
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


def user_name(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def iso(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat() if ts else None


class Denied(Exception):
    pass


# --------------------------------------------------------------------------- system

def collect_system(cfg, sec):
    with open("/proc/uptime") as f:
        uptime = float(f.read().split()[0])
    with open("/proc/loadavg") as f:
        load = [float(x) for x in f.read().split()[:3]]
    osname = ""
    for line in open("/etc/os-release"):
        if line.startswith("PRETTY_NAME="):
            osname = line.split("=", 1)[1].strip().strip('"')
    reboot = os.path.exists("/var/run/reboot-required")
    pkgs = []
    if reboot and os.path.exists("/var/run/reboot-required.pkgs"):
        pkgs = sorted(set(open("/var/run/reboot-required.pkgs").read().split()))[:20]

    def updates():
        # apt-check (update-notifier-common) пише «усього;безпеки» у stderr
        rc, out, err = run(["/usr/lib/update-notifier/apt-check"], timeout=60)
        m = re.match(r"^(\d+);(\d+)", (err or out).strip())
        return {"total": int(m.group(1)), "security": int(m.group(2))} if m else None

    rc, out, _ = run(["systemctl", "--failed", "--no-legend", "--plain", "--type=service"])
    failed = [line.split()[0] for line in out.splitlines() if line.strip()]
    return {
        "hostname": os.uname().nodename, "os": osname, "kernel": os.uname().release,
        "uptime_s": int(uptime), "load": load, "cpus": os.cpu_count(),
        "reboot_required": reboot, "reboot_pkgs": pkgs,
        "updates": cached("apt", 3600, updates), "failed_units": failed,
    }


# --------------------------------------------------------------------------- systemd

SYSTEMD_ACTIONS = {"start", "stop", "restart", "reload"}
ALWAYS_PROTECTED = {"ssh.service", "sshd.service", "ha-server-agent.service", "systemd-journald.service", "dbus.service"}


def systemd_units(cfg):
    units = cfg.get("units") or {}
    protected = set(cfg.get("protected") or []) | ALWAYS_PROTECTED
    out = {}
    for name, acts in units.items():
        n = name if "." in name else name + ".service"
        out[n] = [] if n in protected else [a for a in (acts or []) if a in SYSTEMD_ACTIONS]
    return out


def collect_systemd(cfg, sec):
    units = systemd_units(cfg)
    res = []
    for name, acts in units.items():
        rc, out, _ = run(["systemctl", "show", name, "--no-pager",
                          "-p", "Id,Description,LoadState,ActiveState,SubState,UnitFileState,MainPID,"
                                "ActiveEnterTimestamp,MemoryCurrent,NRestarts"])
        p = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
        if p.get("LoadState") == "not-found":
            continue
        mem = p.get("MemoryCurrent", "")
        res.append({
            "name": name, "description": p.get("Description", ""),
            "active": p.get("ActiveState", ""), "sub": p.get("SubState", ""),
            "enabled": p.get("UnitFileState", ""), "since": p.get("ActiveEnterTimestamp", "") or None,
            "pid": int(p.get("MainPID") or 0), "restarts": int(p.get("NRestarts") or 0) if (p.get("NRestarts") or "").isdigit() else None,
            "memory": int(mem) if mem.isdigit() else None, "actions": acts,
        })
    return {"units": res}


def act_systemd(cfg, target, action):
    units = systemd_units(cfg)
    if target not in units or action not in units[target]:
        raise Denied(f"systemd: {action} {target} не дозволено")
    rc, out, err = run(["systemctl", action, target], timeout=90)
    return {"ok": rc == 0, "output": tail(out + err)}


# --------------------------------------------------------------------------- pm2

PM2_ACTIONS = {"start", "stop", "restart", "reload"}


def pm2_env(inst):
    bindir = os.path.dirname(inst["pm2"])
    pw = pwd.getpwnam(inst["user"])
    return {"PATH": bindir + ":" + ENV["PATH"], "HOME": pw.pw_dir, "PM2_HOME": inst.get("home") or pw.pw_dir + "/.pm2"}


def pm2_list(inst):
    rc, out, err = run([inst["pm2"], "jlist"], user=inst["user"], env=pm2_env(inst), timeout=30)
    if rc != 0:
        raise RuntimeError(tail(err or out, 300) or f"pm2 jlist: код {rc}")
    # pm2 інколи пише попередження перед JSON
    start = out.find("[")
    return json.loads(out[start:]) if start >= 0 else []


def collect_pm2(cfg, sec):
    acts = [a for a in (cfg.get("actions") or ["restart"]) if a in PM2_ACTIONS]
    res = []
    for inst in cfg.get("instances") or []:
        item = {"user": inst["user"], "apps": []}
        try:
            for a in pm2_list(inst):
                env = a.get("pm2_env") or {}
                mon = a.get("monit") or {}
                item["apps"].append({
                    "name": a.get("name"), "id": a.get("pm_id"), "status": env.get("status"),
                    "cpu": mon.get("cpu"), "memory": mon.get("memory"),
                    "restarts": env.get("restart_time"), "unstable_restarts": env.get("unstable_restarts"),
                    "since": iso((env.get("pm_uptime") or 0) / 1000), "mode": env.get("exec_mode"),
                    "version": env.get("version"), "script": os.path.basename(env.get("pm_exec_path") or ""),
                    "actions": acts,
                })
        except Exception as e:  # noqa: BLE001
            item["error"] = str(e)
        res.append(item)
    return {"instances": res}


def act_pm2(cfg, target, action):
    acts = [a for a in (cfg.get("actions") or ["restart"]) if a in PM2_ACTIONS]
    if action not in acts or "/" not in target:
        raise Denied(f"pm2: {action} не дозволено")
    user, name = target.split("/", 1)
    inst = next((i for i in cfg.get("instances") or [] if i["user"] == user), None)
    if not inst or name not in [a.get("name") for a in pm2_list(inst)]:
        raise Denied(f"pm2: немає процесу {target}")
    rc, out, err = run([inst["pm2"], action, name], user=user, env=pm2_env(inst), timeout=90)
    if rc == 0 and cfg.get("save_after_action", True):
        run([inst["pm2"], "save"], user=user, env=pm2_env(inst), timeout=30)
    return {"ok": rc == 0, "output": tail(out + err)}


# --------------------------------------------------------------------------- nginx + сертифікати

NGINX_ACTIONS = {"test", "reload", "restart"}


def nginx_files():
    files = []
    for pat in ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*"]:
        files += [f for f in glob.glob(pat) if os.path.isfile(f)]
    return files


def nginx_test():
    rc, out, err = run(["nginx", "-t"], timeout=30)
    return {"ok": rc == 0, "output": tail(err or out, 800)}


def collect_nginx(cfg, sec):
    if not shutil.which("nginx", path=ENV["PATH"]):
        return {"installed": False}
    _, _, verr = run(["nginx", "-v"])
    rc, out, _ = run(["systemctl", "is-active", "nginx"])
    sites = []
    for f in sorted(glob.glob("/etc/nginx/sites-enabled/*") + glob.glob("/etc/nginx/conf.d/*.conf")):
        try:
            text = open(f, errors="replace").read()
        except OSError:
            continue
        text = re.sub(r"#[^\n]*", "", text)
        names = sorted({n for m in re.findall(r"server_name\s+([^;]+);", text) for n in m.split() if n != "_"})
        sites.append({"file": os.path.basename(f), "server_names": names[:20],
                      "ssl": bool(re.search(r"listen\s+[^;]*\b(ssl|443)\b", text))})
    test = cached("nginx_test", 600, nginx_test)
    return {"installed": True, "version": verr.strip().split("/")[-1] if verr else None,
            "active": out.strip(), "config_ok": test["ok"], "config_output": test["output"],
            "sites": sites, "actions": [a for a in (cfg.get("actions") or ["test", "reload"]) if a in NGINX_ACTIONS]}


def act_nginx(cfg, target, action):
    acts = [a for a in (cfg.get("actions") or ["test", "reload"]) if a in NGINX_ACTIONS]
    if action not in acts:
        raise Denied(f"nginx: {action} не дозволено")
    drop_cache("nginx_test")
    test = nginx_test()
    if action == "test" or not test["ok"]:
        return {"ok": test["ok"], "output": ("Конфіг з помилкою — нічого не перезавантажено.\n" if action != "test" and not test["ok"] else "") + test["output"]}
    rc, out, err = run(["systemctl", action, "nginx"], timeout=60)
    return {"ok": rc == 0, "output": tail(test["output"] + "\n" + out + err)}


def collect_certs(cfg, sec):
    def scan():
        import hashlib
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend  # обов'язковий для cryptography < 3.1 (Ubuntu 20.04)
        from cryptography.hazmat.primitives import serialization
        from cryptography.x509.oid import ExtensionOID, NameOID
        used = set()  # сертифікати, на які посилаються конфіги nginx (справді віддаються клієнтам)
        for f in nginx_files():
            try:
                for m in re.findall(r"^\s*ssl_certificate\s+([^;\s]+)\s*;", open(f, errors="replace").read(), re.M):
                    used.add(m)
            except OSError:
                pass
        paths = set(used) | set(glob.glob("/etc/letsencrypt/live/*/fullchain.pem")) | set(cfg.get("extra_paths") or [])
        by_fp = {}
        for p in sorted(paths):
            rp = os.path.realpath(p)
            if not os.path.isfile(rp):
                continue
            try:
                c = x509.load_pem_x509_certificate(open(rp, "rb").read(), default_backend())
            except Exception:  # noqa: BLE001
                continue
            fp = hashlib.sha256(c.public_bytes(serialization.Encoding.DER)).hexdigest()
            if fp in by_fp:
                by_fp[fp]["used"] = by_fp[fp]["used"] or p in used
                continue
            try:
                cn = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except IndexError:
                cn = ""
            try:
                sans = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                sans = []
            na = c.not_valid_after.replace(tzinfo=dt.timezone.utc)
            issuer = ", ".join(a.value for a in c.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME))
            by_fp[fp] = {"path": p, "subject": cn, "names": list(sans)[:10], "issuer": issuer, "used": p in used,
                         "not_after": na.isoformat(), "days_left": (na - dt.datetime.now(dt.timezone.utc)).days}
        return sorted(by_fp.values(), key=lambda x: x["days_left"])
    certs = cached("certs2", 3600, scan)
    used = [c for c in certs if c.get("used")]
    return {"certs": certs, "min_days": min((c["days_left"] for c in used), default=None),
            "warn_days": cfg.get("warn_days", 14)}


# --------------------------------------------------------------------------- Duplicati (REST API 2.1+)

def dup_listen_port():
    """Порт вебінтерфейсу Duplicati з ss: процес, у назві якого «uplicati»."""
    rc, out, _ = run(["ss", "-ltnpH"])
    for line in out.splitlines():
        if "uplicati" in line:
            m = re.search(r":(\d+)\s", line.split()[3] + " ")
            if m:
                return int(m.group(1))
    return None


DUP_URL = {}


def dup_url(cfg):
    if "url" not in DUP_URL:
        port = dup_listen_port()
        DUP_URL["url"] = f"http://127.0.0.1:{port}" if port else (cfg.get("url") or "http://127.0.0.1:8200")
    return DUP_URL["url"]


def dup_request(cfg, sec, method, path, body=None, token=None):
    url = dup_url(cfg).rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else (b"" if method == "POST" else None)
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = r.read()
        return json.loads(raw) if raw else None


def dup_token(cfg, sec):
    pw = sec.get("duplicati_password")
    if not pw:
        return None
    r = dup_request(cfg, sec, "POST", "/api/v1/auth/login", {"Password": pw, "RememberMe": False})
    return (r or {}).get("AccessToken")


def dup_time(v):
    """Duplicati віддає дати як 20240101T120000Z."""
    if not v:
        return None
    try:
        return dt.datetime.strptime(v, "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc).isoformat()
    except ValueError:
        return v


def dup_backups(cfg, sec):
    token = dup_token(cfg, sec)
    res = []
    for b in dup_request(cfg, sec, "GET", "/api/v1/backups", token=token) or []:
        bk = b.get("Backup") or {}
        md = bk.get("Metadata") or {}
        res.append({
            "id": str(bk.get("ID")), "name": bk.get("Name"),
            "last_success": dup_time(md.get("LastBackupDate")), "last_started": dup_time(md.get("LastBackupStarted")),
            "last_error": dup_time(md.get("LastErrorDate")), "last_error_message": (md.get("LastErrorMessage") or "")[:300],
            "duration": md.get("LastBackupDuration"), "source_size": md.get("SourceSizeString"),
            "target_size": md.get("TargetSizeString"), "next_run": (b.get("Schedule") or {}).get("Time"),
        })
    return res


def collect_duplicati(cfg, sec):
    acts = [a for a in (cfg.get("actions") or ["run"]) if a == "run"]
    need = {"key": "duplicati_password", "file": SECRETS, "what": "пароль вебінтерфейсу Duplicati"}
    try:
        return {"available": True, "url": dup_url(cfg), "backups": dup_backups(cfg, sec), "actions": acts}
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            # Вебінтерфейс захищено паролем: або його немає в secrets.yaml, або він неправильний
            if sec.get("duplicati_password"):
                return {"available": False, "error": "пароль Duplicati не підходить", "needs_secret": dict(need, wrong=True)}
            return {"available": False, "error": "потрібен пароль Duplicati", "needs_secret": need}
        return {"available": False, "error": f"HTTP {e.code}"}
    except urllib.error.URLError as e:
        return {"available": False, "error": f"вебінтерфейс Duplicati недоступний ({dup_url(cfg)}): {e.reason}"[:200]}
    except Exception as e:  # noqa: BLE001
        return {"available": False, "error": str(e)[:200]}


def act_duplicati(cfg, sec, target, action):
    if action != "run" or "run" not in (cfg.get("actions") or ["run"]):
        raise Denied("duplicati: дія не дозволена")
    if target not in [b["id"] for b in dup_backups(cfg, sec)]:
        raise Denied(f"duplicati: немає завдання {target}")
    token = dup_token(cfg, sec)
    for path in (f"/api/v1/backup/{target}/run", f"/api/v1/backup/{target}/start"):
        try:
            dup_request(cfg, sec, "POST", path, token=token)
            return {"ok": True, "output": "Резервну копію поставлено в чергу"}
        except urllib.error.HTTPError as e:
            if e.code != 404:
                return {"ok": False, "output": f"HTTP {e.code}"}
    return {"ok": False, "output": "API Duplicati не підтримує запуск (потрібна версія 2.1+)"}


# --------------------------------------------------------------------------- tmux

def tmux_users(cfg):
    return [u for u in cfg.get("users") or [] if re.match(r"^[a-z_][a-z0-9_-]*$", u)]


def collect_tmux(cfg, sec):
    res = []
    for u in tmux_users(cfg):
        rc, out, _ = run(["tmux", "list-sessions", "-F",
                          "#{session_name}\t#{session_windows}\t#{session_attached}\t#{session_created}\t#{session_activity}"], user=u)
        if rc != 0:
            continue  # немає сервера tmux у цього користувача
        _, pout, _ = run(["tmux", "list-panes", "-a", "-F",
                          "#{session_name}\t#{window_index}\t#{window_name}\t#{pane_current_command}"], user=u)
        panes = [p.split("\t") for p in pout.splitlines() if p.count("\t") == 3]
        for line in out.splitlines():
            f = line.split("\t")
            if len(f) < 5:
                continue
            res.append({"user": u, "name": f[0], "windows": int(f[1]), "attached": int(f[2]),
                        "created": iso(int(f[3])), "activity": iso(int(f[4])),
                        "panes": [{"window": p[1], "name": p[2], "command": p[3]} for p in panes if p[0] == f[0]][:10]})
    return {"sessions": res, "allow_kill": bool(cfg.get("allow_kill"))}


def act_tmux(cfg, target, action):
    if action != "kill" or not cfg.get("allow_kill") or "/" not in target:
        raise Denied("tmux: дія не дозволена")
    user, name = target.split("/", 1)
    if user not in tmux_users(cfg) or name not in [s["name"] for s in collect_tmux(cfg, {})["sessions"] if s["user"] == user]:
        raise Denied(f"tmux: немає сесії {target}")
    rc, out, err = run(["tmux", "kill-session", "-t", "=" + name], user=user)
    return {"ok": rc == 0, "output": tail(out + err)}


# --------------------------------------------------------------------------- docker

DOCKER_ACTIONS = {"start", "stop", "restart"}


def docker_ps():
    rc, out, err = run(["docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}"], timeout=30)
    if rc != 0:
        raise RuntimeError(tail(err, 200))
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def docker_allowed(cfg, name):
    allow = cfg.get("containers") or []
    return not allow or name in allow


def collect_docker(cfg, sec):
    if not shutil.which("docker", path=ENV["PATH"]):
        return {"available": False}
    acts = [a for a in (cfg.get("actions") or ["restart"]) if a in DOCKER_ACTIONS]
    try:
        cs = docker_ps()
    except Exception as e:  # noqa: BLE001
        return {"available": False, "error": str(e)}
    return {"available": True, "containers": [{
        "name": c.get("Names"), "image": (c.get("Image") or "")[:80], "state": c.get("State"),
        "status": c.get("Status"), "actions": acts if docker_allowed(cfg, c.get("Names")) else []} for c in cs]}


def act_docker(cfg, target, action):
    acts = [a for a in (cfg.get("actions") or ["restart"]) if a in DOCKER_ACTIONS]
    if action not in acts or not docker_allowed(cfg, target) or target not in [c.get("Names") for c in docker_ps()]:
        raise Denied(f"docker: {action} {target} не дозволено")
    rc, out, err = run(["docker", action, target], timeout=120)
    return {"ok": rc == 0, "output": tail(out + err)}


# --------------------------------------------------------------------------- fail2ban, процеси

def collect_fail2ban(cfg, sec):
    if not shutil.which("fail2ban-client", path=ENV["PATH"]):
        return {"available": False}
    rc, out, err = run(["fail2ban-client", "status"])
    m = re.search(r"Jail list:\s*(.*)", out)
    jails = []
    for j in [x.strip() for x in (m.group(1).split(",") if m else []) if x.strip()]:
        _, jo, _ = run(["fail2ban-client", "status", j])
        cur = re.search(r"Currently banned:\s*(\d+)", jo)
        tot = re.search(r"Total banned:\s*(\d+)", jo)
        jails.append({"name": j, "banned": int(cur.group(1)) if cur else None, "total_banned": int(tot.group(1)) if tot else None})
    return {"available": rc == 0, "jails": jails}


def collect_processes(cfg, sec):
    n = int(cfg.get("top") or 5)

    def top(key):
        rc, out, _ = run(["ps", "-eo", "pid,user:20,pcpu,pmem,rss,args", "--sort=-" + key, "--no-headers"])
        res = []
        for line in out.splitlines()[:n]:
            f = line.split(None, 5)
            if len(f) == 6:
                res.append({"pid": int(f[0]), "user": f[1], "cpu": float(f[2]), "mem": float(f[3]),
                            "rss_mb": round(int(f[4]) / 1024), "command": f[5][:100]})
        return res
    return {"top_cpu": top("pcpu"), "top_mem": top("rss")}



# --------------------------------------------------------------------------- самооновлення агента з git

SOURCE_FILE = ETC + "/source"  # тека з клоном репозиторію (записує install.sh)
LIB = "/usr/local/lib/ha-server-agent"


def agent_source():
    try:
        d = open(SOURCE_FILE).read().strip()
    except OSError:
        return None
    return d if os.path.isdir(os.path.join(d, ".git")) else None


def git(src, *args, timeout=60):
    # Ключ розгортання (лише читання) задає core.sshCommand у самому клоні; root — власник клону
    return run(["git", "-C", src] + list(args), timeout=timeout,
               env={"HOME": "/root", "GIT_TERMINAL_PROMPT": "0"})


def agent_version():
    try:
        m = re.search(r'^VERSION = "([^"]+)"', open(LIB + "/server.py").read(), re.M)
        return m.group(1) if m else None
    except OSError:
        return None


def collect_agent(cfg, sec):
    src = agent_source()
    out = {"version": agent_version(), "source": src, "allow_update": cfg.get("allow_update", True)}
    if not src:
        out["error_update"] = "агент встановлено не з git-клону — самооновлення недоступне"
        return out
    rc, head, _ = git(src, "rev-parse", "--short", "HEAD")
    out["commit"] = head.strip() if rc == 0 else None

    def remote():
        rc, _, err = git(src, "fetch", "--quiet", "origin", timeout=90)
        if rc != 0:
            return {"error": tail(err, 300) or "git fetch не вдався"}
        rc, ref, _ = git(src, "rev-parse", "--abbrev-ref", "origin/HEAD")
        branch = ref.strip() if rc == 0 and ref.strip() else "origin/main"
        rc, rhead, _ = git(src, "rev-parse", "--short", branch)
        rc2, subj, _ = git(src, "log", "-1", "--format=%s", branch)
        return {"remote_commit": rhead.strip(), "branch": branch, "remote_subject": subj.strip()[:200]}
    r = cached("agent_remote", int(cfg.get("check_hours", 3)) * 3600, remote)
    out.update(r)
    if r.get("error"):
        out["error_update"] = r.pop("error")
    out["update_available"] = bool(out.get("remote_commit") and out.get("commit") and out["remote_commit"] != out["commit"])
    return out


def act_agent(cfg, target, action):
    if action == "check":
        drop_cache("agent_remote")
        return {"ok": True, "output": "Перевіряю оновлення"}
    if action != "update" or not cfg.get("allow_update", True):
        raise Denied("agent: дія не дозволена")
    src = agent_source()
    if not src:
        raise Denied("агент встановлено не з git-клону")
    drop_cache("agent_remote")
    script = (f"cd {src} && git fetch --quiet origin && "
              f"git reset --quiet --hard $(git rev-parse --abbrev-ref origin/HEAD 2>/dev/null || echo origin/main) && "
              f"bash ./install.sh --update")
    log = "/var/log/ha-server-agent/update.log"
    # Окремий unit systemd: перезапуск агента не обірве оновлення (помічник живе в його cgroup)
    if shutil.which("systemd-run", path=ENV["PATH"]) and os.path.isdir("/run/systemd/system"):
        argv = ["systemd-run", "--unit", f"ha-server-agent-update-{int(time.time())}", "--collect", "--quiet",
                "--setenv=HOME=/root", "/bin/bash", "-c", f"({script}) > {log} 2>&1"]
        rc, out, err = run(argv, timeout=30)
        return {"ok": rc == 0, "output": "Оновлення запущено (журнал: " + log + ")" if rc == 0 else tail(err)}
    subprocess.Popen(["/bin/bash", "-c", f"({script}) > {log} 2>&1"], env=dict(ENV, HOME="/root"), start_new_session=True)
    return {"ok": True, "output": "Оновлення запущено (журнал: " + log + ")"}


# --------------------------------------------------------------------------- диспетчер

MODULES = {
    "system": collect_system, "systemd": collect_systemd, "pm2": collect_pm2, "nginx": collect_nginx,
    "certs": collect_certs, "duplicati": collect_duplicati, "tmux": collect_tmux, "docker": collect_docker,
    "fail2ban": collect_fail2ban, "processes": collect_processes, "agent": collect_agent,
}


DEFAULT_ON = {"agent"}  # модулі, що працюють і без секції в policy.yaml (старі встановлення)


def module_cfg(policy, name):
    cfg = policy.get(name)
    if cfg is None and name in DEFAULT_ON:
        cfg = {}
    return cfg


def enabled(policy, name):
    cfg = module_cfg(policy, name)
    return isinstance(cfg, dict) and cfg.get("enabled", True)


def cmd_collect():
    policy, sec = load_yaml(POLICY), load_yaml(SECRETS)
    out = {}
    for name, fn in MODULES.items():
        if not enabled(policy, name):
            continue
        t0 = time.time()
        try:
            out[name] = fn(module_cfg(policy, name), sec)
        except Exception as e:  # noqa: BLE001 — один модуль не валить решту
            out[name] = {"error": f"{type(e).__name__}: {e}"[:300]}
        out[name]["_ms"] = int((time.time() - t0) * 1000)
    return out


def cmd_action(req):
    policy, sec = load_yaml(POLICY), load_yaml(SECRETS)
    module, target, action = str(req.get("module", "")), str(req.get("target", "")), str(req.get("action", ""))
    if not enabled(policy, module) or len(target) > 200:
        raise Denied(f"модуль {module} вимкнено")
    cfg = module_cfg(policy, module)
    if module == "systemd":
        res = act_systemd(cfg, target, action)
    elif module == "pm2":
        res = act_pm2(cfg, target, action)
    elif module == "nginx":
        res = act_nginx(cfg, target, action)
    elif module == "duplicati":
        res = act_duplicati(cfg, sec, target, action)
    elif module == "tmux":
        res = act_tmux(cfg, target, action)
    elif module == "docker":
        res = act_docker(cfg, target, action)
    elif module == "agent":
        res = act_agent(cfg, target, action)
    else:
        raise Denied(f"модуль {module} не має дій")
    return res


# --------------------------------------------------------------------------- автовиявлення

KNOWN_UNITS = {
    "nginx": ["reload", "restart"], "apache2": ["reload", "restart"], "caddy": ["reload", "restart"],
    "duplicati": ["start", "stop", "restart"], "fail2ban": ["restart"], "docker": ["restart"],
    "postgresql": ["restart"], "mysql": ["restart"], "mariadb": ["restart"], "redis-server": ["restart"],
    "mongod": ["restart"], "supervisor": ["restart"], "cron": ["restart"], "beszel-agent": ["restart"],
}


def detect():
    rc, out, _ = run(["systemctl", "list-unit-files", "--type=service", "--no-legend", "--plain"])
    files = {line.split()[0]: line.split()[1] for line in out.splitlines() if len(line.split()) >= 2}
    units = {}
    for base, acts in KNOWN_UNITS.items():
        if base + ".service" in files:
            units[base + ".service"] = acts
    for f in files:
        if re.match(r"php[\d.]*-fpm\.service$", f) or f.startswith("pm2-"):
            units[f] = ["reload", "restart"] if "fpm" in f else ["restart"]
    # Власні сервіси (не з пакетів): /etc/systemd/system/*.service, увімкнені
    for p in glob.glob("/etc/systemd/system/*.service"):
        n = os.path.basename(p)
        if os.path.islink(p):
            continue  # псевдоніми (dbus-org.*, sshd, syslog…) і замасковані — не окремі сервіси
        if n not in units and n != "ha-server-agent.service" and files.get(n) == "enabled":
            units[n] = ["start", "stop", "restart"]

    # pm2: демони «PM2 vX: God Daemon (/home/u/.pm2)»
    pm2 = []
    for d in glob.glob("/proc/[0-9]*"):
        try:
            cmd = open(d + "/cmdline", "rb").read().replace(b"\0", b" ").decode(errors="replace")
            if "God Daemon" not in cmd or not cmd.startswith("PM2"):
                continue
            uid = os.stat(d).st_uid
        except OSError:
            continue
        try:
            exe = os.readlink(d + "/exe")  # node з nvm → pm2 поруч
        except OSError:
            exe = ""
        user = user_name(uid)
        if any(i["user"] == user for i in pm2):
            continue
        home = re.search(r"\((.+)\)", cmd)
        cand = ([os.path.join(os.path.dirname(exe), "pm2")] if exe else []) + ["/usr/local/bin/pm2", "/usr/bin/pm2"]
        binp = next((c for c in cand if os.path.exists(c)), None)
        if binp:
            pm2.append({"user": user, "pm2": binp, "home": home.group(1) if home else None})

    # tmux: користувачі з відкритим сервером tmux
    tmux = sorted({user_name(os.stat(s).st_uid) for s in glob.glob("/tmp/tmux-*/*")})

    # Duplicati: сервіс або контейнер
    dup_unit = next((u for u in files if "duplicati" in u), None)
    has_docker = bool(shutil.which("docker", path=ENV["PATH"]))
    dup_docker = None
    if has_docker:
        rc, dout, _ = run(["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Image}}"])
        dup_docker = next((l.split("\t")[0] for l in dout.splitlines() if "duplicati" in l.lower()), None)
    port = dup_listen_port()
    dup_url = f"http://127.0.0.1:{port}" if port else "http://127.0.0.1:8200"
    if dup_docker and not port:  # порт вебінтерфейсу, проброшений з контейнера
        rc, pout, _ = run(["docker", "port", dup_docker, "8200/tcp"])
        m = re.search(r":(\d+)\s*$", pout.splitlines()[0]) if pout.strip() else None
        if m:
            dup_url = f"http://127.0.0.1:{m.group(1)}"

    policy = {
        "system": {"enabled": True},
        "systemd": {"enabled": True, "units": units, "protected": sorted(ALWAYS_PROTECTED)},
        "pm2": {"enabled": bool(pm2), "instances": pm2, "actions": ["start", "stop", "restart", "reload"], "save_after_action": True},
        "nginx": {"enabled": bool(shutil.which("nginx", path=ENV["PATH"])), "actions": ["test", "reload", "restart"]},
        "certs": {"enabled": True, "warn_days": 14, "extra_paths": []},
        "duplicati": {"enabled": bool(dup_unit or dup_docker), "url": dup_url, "actions": ["run"]},
        "tmux": {"enabled": bool(tmux), "users": tmux, "allow_kill": False},
        "docker": {"enabled": has_docker, "actions": ["start", "stop", "restart"], "containers": []},
        "fail2ban": {"enabled": bool(shutil.which("fail2ban-client", path=ENV["PATH"]))},
        "processes": {"enabled": True, "top": 5},
        "agent": {"enabled": True, "allow_update": True, "check_hours": 3},
    }
    found = {"pm2": [i["user"] for i in pm2], "tmux": tmux, "duplicati": dup_unit or dup_docker,
             "systemd": list(units), "docker": has_docker}
    return policy, found


def merge_policy(old, new):
    """Доповнює чинну політику тим, що автовиявлення знайшло зараз (після оновлення агента / змін на сервері).
    Модуль, вимкнений лише тому, що його не знайшли, вмикається; keep_disabled: true — лишити вимкненим.
    Нові сервіси, користувачі pm2 і tmux додаються; наявні налаштування й дії не змінюються."""
    changes = []
    for name, sec in new.items():
        cur = old.get(name)
        if cur is None:
            old[name] = sec
            changes.append(f"додано модуль {name}")
            continue
        if not cur.get("enabled", True) and sec.get("enabled") and not cur.get("keep_disabled"):
            for k, v in sec.items():
                cur.setdefault(k, v)
            cur["enabled"] = True
            changes.append(f"увімкнено {name}")
        if name == "systemd":
            # прибрати псевдоніми, які старі версії помилково додавали (симлінки в /etc/systemd/system)
            for u in list((cur.get("units") or {})):
                if os.path.islink("/etc/systemd/system/" + u) and u.rsplit(".", 1)[0] not in KNOWN_UNITS:
                    del cur["units"][u]
                    changes.append(f"прибрано псевдонім {u}")
            for u, acts in (sec.get("units") or {}).items():
                if u not in (cur.get("units") or {}):
                    cur.setdefault("units", {})[u] = acts
                    changes.append(f"сервіс {u}")
        elif name == "pm2":
            have = {i["user"] for i in cur.get("instances") or []}
            for i in sec.get("instances") or []:
                if i["user"] not in have:
                    cur.setdefault("instances", []).append(i)
                    changes.append(f"pm2 {i['user']}")
        elif name == "tmux":
            for u in sec.get("users") or []:
                if u not in (cur.get("users") or []):
                    cur.setdefault("users", []).append(u)
                    changes.append(f"tmux {u}")
        elif name == "duplicati" and sec.get("url") and cur.get("url") in (None, "http://127.0.0.1:8200") and sec["url"] != cur.get("url"):
            cur["url"] = sec["url"]
            changes.append(f"Duplicati {sec['url']}")
    return old, changes


HEADER = """# Політика HA Server Agent: що агент бачить і чим може керувати.
# Створено автовиявленням (ha-server-agent detect). Правити вручну; після правки — нічого перезапускати не треба.
# Дії, яких тут немає, агент не виконає навіть за правильно підписаним запитом.
"""


def main():
    if os.geteuid() != 0:
        print("helper має працювати від root (через sudo)", file=sys.stderr)
        sys.exit(2)
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        if cmd == "collect":
            print(json.dumps(cmd_collect(), ensure_ascii=False))
        elif cmd == "action":
            req = json.loads(sys.stdin.read(65536) or "{}")
            print(json.dumps(cmd_action(req), ensure_ascii=False))
        elif cmd == "detect" and "--merge" in sys.argv:
            policy, found = detect()
            old = load_yaml(POLICY)
            merged, changes = merge_policy(old, policy)
            if changes:
                shutil.copy(POLICY, POLICY + ".bak")
                with open(POLICY, "w") as f:
                    f.write(HEADER + yaml.safe_dump(merged, allow_unicode=True, sort_keys=False))
                os.chmod(POLICY, 0o644)
            print("; ".join(changes) or "без змін")
        elif cmd == "detect":
            policy, found = detect()
            if "--write" in sys.argv:
                if os.path.exists(POLICY) and "--force" not in sys.argv:
                    print("policy.yaml вже існує (додай --force, щоб перезаписати)", file=sys.stderr)
                    sys.exit(1)
                with open(POLICY, "w") as f:
                    f.write(HEADER + yaml.safe_dump(policy, allow_unicode=True, sort_keys=False))
                os.chmod(POLICY, 0o644)
            print(json.dumps(found, ensure_ascii=False) if "--summary" in sys.argv
                  else HEADER + yaml.safe_dump(policy, allow_unicode=True, sort_keys=False))
        else:
            print("використання: helper collect | action | detect [--write [--force]] [--summary]", file=sys.stderr)
            sys.exit(2)
    except Denied as e:
        print(json.dumps({"ok": False, "denied": True, "output": str(e)}, ensure_ascii=False))
        sys.exit(3)


if __name__ == "__main__":
    main()
