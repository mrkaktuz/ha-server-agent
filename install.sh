#!/usr/bin/env bash
# HA Server Agent — встановлення / оновлення на Ubuntu 22.04 / 24.04.
#
#   Віддалений сервер (HA ходить через інтернет):
#     sudo ./install.sh --domain agent-dev.example.com --allow-ip 1.2.3.4
#   Якщо на сервері працює nginx — він прийматиме піддомен (https, 443) і передаватиме агенту на внутрішній
#   порт 127.0.0.1:8787; сертифікат — наявний (напр. *.example.com) або новий від Let's Encrypt.
#   Без nginx — агент сам слухає https на порту 2053 (свій сертифікат, HA закріплює його відбиток).
#   Сервер, на якому працює сам Home Assistant:
#     sudo ./install.sh --local
#   Видалення:
#     sudo ./install.sh --uninstall [--purge]
#
# Повторний запуск оновлює код і не чіпає ключі, клієнтів, сертифікат і policy.yaml.
# Наприкінці показує код підключення для Home Assistant.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "Запусти через sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/agent"
NAME=ha-server-agent
USR=ha-agent
LIB=/usr/local/lib/$NAME
ETC=/etc/$NAME
LOG=/var/log/$NAME
CACHE=/var/cache/$NAME
UNIT=/etc/systemd/system/$NAME.service
SUDOERS=/etc/sudoers.d/$NAME

DOMAIN=""; ALLOW_IP=""; PORT=""; LOCAL=0; UNINSTALL=0; PURGE=0; NO_SERVICE=0; NO_NGINX=0; PUBLIC_URL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --allow-ip) ALLOW_IP="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --local) LOCAL=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    --no-nginx) NO_NGINX=1; shift ;;      # не чіпати nginx, а слухати https самому (порт 2053)
    --public-url) PUBLIC_URL="$2"; shift 2 ;;  # для перевірок: інша адреса в коді підключення
    --no-service) NO_SERVICE=1; shift ;;  # для перевірки в контейнері без systemd
    *) echo "Невідомий параметр: $1"; exit 2 ;;
  esac
done

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33m!! %s\033[0m\n' "$*"; }

if [ "$UNINSTALL" = 1 ]; then
  systemctl disable --now $NAME 2>/dev/null || true
  rm -f "$UNIT" "$SUDOERS" /usr/local/bin/$NAME
  if [ -e /etc/nginx/sites-enabled/$NAME ] || [ -e /etc/nginx/conf.d/$NAME.conf ]; then
    rm -f /etc/nginx/sites-enabled/$NAME /etc/nginx/sites-available/$NAME /etc/nginx/conf.d/$NAME.conf
    nginx -t >/dev/null 2>&1 && nginx -s reload
  fi
  rm -rf "$LIB" "$CACHE"
  systemctl daemon-reload 2>/dev/null || true
  if command -v ufw >/dev/null && ufw status | grep -q "# $NAME"; then
    ufw status numbered | grep "# $NAME" | sed -E 's/^\[ *([0-9]+)\].*/\1/' | sort -rn | while read -r n; do yes | ufw delete "$n" >/dev/null; done
  fi
  if [ "$PURGE" = 1 ]; then rm -rf "$ETC" "$LOG"; userdel $USR 2>/dev/null || true; echo "Агента видалено разом із налаштуваннями.";
  else echo "Агента видалено (налаштування лишились у $ETC)."; fi
  exit 0
fi

# ---- Режим: перше встановлення вимагає --local або --domain + --allow-ip
FIRST=0; [ -f "$ETC/agent.yaml" ] || FIRST=1
if [ "$FIRST" = 1 ]; then
  if [ "$LOCAL" = 0 ] && { [ -z "$DOMAIN" ] || [ -z "$ALLOW_IP" ]; }; then
    echo "Перше встановлення: вкажи --local (HA на цій машині) або --domain ДОМЕН --allow-ip ДОМАШНЯ_IP"; exit 2
  fi
  if [ "$LOCAL" = 1 ]; then MODE=local
  elif [ "$NO_NGINX" = 0 ] && command -v nginx >/dev/null && pgrep -x nginx >/dev/null; then MODE=nginx
  else MODE=tls; fi
  [ -n "$PORT" ] || { [ "$MODE" = tls ] && PORT=2053 || PORT=8787; }
  if ss -ltnH "sport = :$PORT" | grep -q .; then
    echo "Порт $PORT уже зайнятий: $(ss -ltnpH "sport = :$PORT" | head -1)"; echo "Вкажи інший: --port N"; exit 2
  fi
fi

say "Залежності"
missing=""
python3 -c "import cryptography" 2>/dev/null || missing="$missing python3-cryptography"
python3 -c "import yaml" 2>/dev/null || missing="$missing python3-yaml"
command -v openssl >/dev/null || missing="$missing openssl"
command -v sudo >/dev/null || missing="$missing sudo"
if [ -n "$missing" ]; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $missing >/dev/null; fi
echo "ok"

say "Користувач $USR"
id $USR >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin $USR
echo "ok"

say "Файли"
install -d -o root -g root -m 755 "$LIB"
install -o root -g root -m 644 "$SRC/protocol.py" "$SRC/server.py" "$SRC/helper.py" "$SRC/cli.py" "$SRC/certfind.py" "$LIB/"
cat > "$LIB/$NAME-helper" <<EOF
#!/bin/sh
# Привілейований помічник $NAME: лише collect | action | detect (див. helper.py)
exec /usr/bin/python3 -I $LIB/helper.py "\$@"
EOF
chmod 755 "$LIB/$NAME-helper"
cat > /usr/local/bin/$NAME <<EOF
#!/bin/sh
exec /usr/bin/python3 -I $LIB/cli.py "\$@"
EOF
chmod 755 /usr/local/bin/$NAME
install -d -o root -g $USR -m 750 "$ETC"
install -d -o $USR -g $USR -m 700 "$ETC/state"
install -d -o $USR -g $USR -m 750 "$LOG"
install -d -o root -g root -m 700 "$CACHE"
echo "ok"

if [ ! -f "$ETC/agent.key" ]; then
  say "Ключ агента"
  python3 -I -c "import sys; sys.path.insert(0,'$LIB'); import protocol as P; print(P.generate_keypair()[0])" > "$ETC/agent.key"
  echo "створено"
fi
chown $USR:$USR "$ETC/agent.key"; chmod 600 "$ETC/agent.key"

if [ "$FIRST" = 1 ]; then
  case "$MODE" in
    local) MODE_TXT="локально, для HA на цій машині" ;;
    nginx) MODE_TXT="nginx: https://$DOMAIN → 127.0.0.1:$PORT" ;;
    *) MODE_TXT="власний https на $DOMAIN:$PORT" ;;
  esac
  say "Налаштування — $MODE_TXT"
  if [ "$MODE" = local ]; then
    cat > "$ETC/agent.yaml" <<EOF
# Налаштування мережевого шару $NAME. Режим: Home Assistant на цій самій машині.
mode: local
listen: 127.0.0.1
port: $PORT
public_url: ${PUBLIC_URL:-http://127.0.0.1:$PORT}
allow_ips: [127.0.0.1, "::1"]
rate_per_minute: 120
max_failures: 10
EOF
  elif [ "$MODE" = nginx ]; then
    cat > "$ETC/agent.yaml" <<EOF
# Налаштування мережевого шару $NAME. Режим: nginx приймає https://$DOMAIN і передає сюди.
mode: nginx
domain: $DOMAIN
listen: 127.0.0.1
port: $PORT
public_url: ${PUBLIC_URL:-https://$DOMAIN}
# Звідки дозволено запити (домашня IP); 127.0.0.1 — для самоперевірки
allow_ips: [$ALLOW_IP, 127.0.0.1]
rate_per_minute: 120
max_failures: 10
EOF
  else
    install -d -o root -g $USR -m 750 "$ETC/tls"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -subj "/CN=$DOMAIN" -addext "subjectAltName=DNS:$DOMAIN" \
      -keyout "$ETC/tls/key.pem" -out "$ETC/tls/cert.pem" 2>/dev/null
    chown root:$USR "$ETC/tls/cert.pem"; chmod 640 "$ETC/tls/cert.pem"
    chown $USR:$USR "$ETC/tls/key.pem"; chmod 600 "$ETC/tls/key.pem"
    cat > "$ETC/agent.yaml" <<EOF
# Налаштування мережевого шару $NAME. Режим: власний https (сертифікат закріплює Home Assistant).
mode: tls
domain: $DOMAIN
listen: 0.0.0.0
port: $PORT
public_url: ${PUBLIC_URL:-https://$DOMAIN:$PORT}
tls:
  cert: $ETC/tls/cert.pem
  key: $ETC/tls/key.pem
# Звідки дозволено запити (домашня IP); 127.0.0.1 — для самоперевірки
allow_ips: [$ALLOW_IP, 127.0.0.1]
rate_per_minute: 120
max_failures: 10
EOF
  fi
  echo "ok"
else
  # Оновлення: дозволені адреси / домен можна змінити повторним запуском
  if [ -n "$ALLOW_IP" ]; then /usr/local/bin/$NAME allow-ip "$ALLOW_IP" 127.0.0.1 >/dev/null; fi
fi
chown root:$USR "$ETC/agent.yaml"; chmod 640 "$ETC/agent.yaml"
# Перенесення клієнтів зі старого формату (клієнти були в agent.yaml)
touch "$ETC/state/clients.yaml"; chown $USR:$USR "$ETC/state/clients.yaml"; chmod 600 "$ETC/state/clients.yaml"

if [ ! -f "$ETC/secrets.yaml" ]; then
  cat > "$ETC/secrets.yaml" <<'EOF'
# Секрети для помічника (читає лише root). Агент сам підкаже (і Home Assistant покаже), якщо щось потрібно, напр.:
# duplicati_password: "пароль вебінтерфейсу Duplicati"
{}
EOF
fi
chown root:root "$ETC/secrets.yaml"; chmod 600 "$ETC/secrets.yaml"

if [ ! -f "$ETC/policy.yaml" ]; then
  say "Автовиявлення (що є на сервері)"
  "$LIB/$NAME-helper" detect --write >/dev/null
fi
chown root:root "$ETC/policy.yaml"; chmod 644 "$ETC/policy.yaml"
"$LIB/$NAME-helper" detect --summary | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("  pm2:", ", ".join(d["pm2"]) or "немає")
print("  tmux:", ", ".join(d["tmux"]) or "немає")
print("  Duplicati:", d["duplicati"] or "немає")
print("  Docker:", "є" if d["docker"] else "немає")
print("  сервіси:", ", ".join(s.replace(".service", "") for s in d["systemd"]) or "—")'

say "sudo: лише помічник collect / action"
cat > "$SUDOERS" <<EOF
# $USR може запускати від root тільки помічника з двома командами
Defaults:$USR !requiretty, !lecture
$USR ALL=(root) NOPASSWD: $LIB/$NAME-helper collect, $LIB/$NAME-helper action
EOF
chmod 440 "$SUDOERS"
visudo -cf "$SUDOERS" >/dev/null
echo "ok"

# ---- nginx: піддомен агента → 127.0.0.1:порт (при першому встановленні або з --domain)
CFG_MODE=$(python3 -c "import yaml;print(yaml.safe_load(open('$ETC/agent.yaml')).get('mode','local'))")
if [ "$CFG_MODE" = nginx ] && { [ "$FIRST" = 1 ] || [ -n "$DOMAIN" ]; }; then
  DOMAIN=${DOMAIN:-$(python3 -c "import yaml;print(yaml.safe_load(open('$ETC/agent.yaml'))['domain'])")}
  PORT_NOW=$(python3 -c "import yaml;print(yaml.safe_load(open('$ETC/agent.yaml')).get('port',8787))")
  say "nginx: https://$DOMAIN → 127.0.0.1:$PORT_NOW"
  if [ -d /etc/nginx/sites-enabled ]; then NGX=/etc/nginx/sites-available/$NAME; NGX_LINK=/etc/nginx/sites-enabled/$NAME
  else NGX=/etc/nginx/conf.d/$NAME.conf; NGX_LINK=""; fi
  WEBROOT=/var/www/$NAME
  install -d -m 755 "$WEBROOT"
  ngx_apply() {  # увімкнути конфіг, перевірити, перезавантажити; при помилці — відкотити
    if [ -n "$NGX_LINK" ]; then ln -sf "$NGX" "$NGX_LINK"; fi
    if nginx -t >/dev/null 2>&1; then nginx -s reload; else
      nginx -t 2>&1 | tail -3
      rm -f "$NGX"; if [ -n "$NGX_LINK" ]; then rm -f "$NGX_LINK"; fi
      nginx -s reload 2>/dev/null || true
      echo "Конфіг nginx не пройшов перевірку — зміни nginx відкочено."; exit 1
    fi
  }
  http_block() {
    cat <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root $WEBROOT; }
    location / { return 301 https://\$host\$request_uri; }
}
EOF
  }
  # Сертифікат: наявний для домену (Let's Encrypt, *.домен з конфігів nginx) або новий від Let's Encrypt
  CERTINFO=$(python3 -I "$LIB/certfind.py" "$DOMAIN" || true)
  if [ -n "$CERTINFO" ]; then
    read -r CERT KEY TRUST <<< "$CERTINFO"
    echo "  сертифікат: наявний $CERT ($([ "$TRUST" = trusted ] && echo "довірений" || echo "власний — HA закріпить відбиток"))"
  else
    http_block > "$NGX"; ngx_apply
    command -v certbot >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot >/dev/null; }
    echo "  сертифікат: запит до Let's Encrypt…"
    if certbot certonly --webroot -w "$WEBROOT" -d "$DOMAIN" --cert-name "$DOMAIN" --non-interactive --agree-tos \
         --register-unsafely-without-email --deploy-hook "nginx -s reload" >/tmp/$NAME-certbot.log 2>&1; then
      CERT=/etc/letsencrypt/live/$DOMAIN/fullchain.pem; KEY=/etc/letsencrypt/live/$DOMAIN/privkey.pem; TRUST=trusted
      echo "  отримано, оновлюватиметься автоматично"
    else
      warn "Let's Encrypt не видав сертифікат (/tmp/$NAME-certbot.log) — ставлю власний, HA закріпить його відбиток."
      install -d -o root -g root -m 755 "$ETC/tls"
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 -subj "/CN=$DOMAIN" \
        -addext "subjectAltName=DNS:$DOMAIN" -keyout "$ETC/tls/nginx-key.pem" -out "$ETC/tls/nginx-cert.pem" 2>/dev/null
      chmod 600 "$ETC/tls/nginx-key.pem"
      CERT=$ETC/tls/nginx-cert.pem; KEY=$ETC/tls/nginx-key.pem; TRUST=untrusted
    fi
  fi
  # Сертифікат не з довіреного центру — HA перевірятиме його точний відбиток (pin_cert)
  python3 - "$ETC/agent.yaml" "$CERT" "$TRUST" <<'PY'
import sys, yaml
p, cert, trust = sys.argv[1:]
cfg = yaml.safe_load(open(p))
if trust == "trusted":
    cfg.pop("pin_cert", None)
else:
    cfg["pin_cert"] = cert
open(p, "w").write("# Налаштування мережевого шару ha-server-agent (див. README)\n"
                   + yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
PY
  chown root:$USR "$ETC/agent.yaml"; chmod 640 "$ETC/agent.yaml"
  CF_RANGES="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32"
  {
    echo "# HA Server Agent: https://$DOMAIN → агент на 127.0.0.1:$PORT_NOW (створено install.sh)"
    http_block
    echo "server {"
    echo "    listen 443 ssl;"
    echo "    listen [::]:443 ssl;"
    echo "    server_name $DOMAIN;"
    echo "    ssl_certificate $CERT;"
    echo "    ssl_certificate_key $KEY;"
    echo "    # Справжня адреса клієнта, якщо запит прийшов через Cloudflare (помаранчева хмарка)"
    for r in $CF_RANGES; do echo "    set_real_ip_from $r;"; done
    echo "    real_ip_header CF-Connecting-IP;"
    echo "    client_max_body_size 16k;"
    echo "    access_log /var/log/nginx/$NAME.access.log;"
    echo "    location /v1/ {"
    echo "        proxy_pass http://127.0.0.1:$PORT_NOW;"
    echo "        proxy_http_version 1.1;"
    echo "        proxy_set_header Host \$host;"
    echo "        proxy_set_header X-Agent-Client-IP \$remote_addr;"
    echo "        proxy_read_timeout 150s;"
    echo "    }"
    echo "    location / { return 404; }"
    echo "}"
  } > "$NGX"
  ngx_apply
  echo "  ok"
fi

# ---- Фаєрвол: порт агента лише для дозволених адрес (якщо ufw увімкнений)
PORT_NOW=$(python3 -c "import yaml;print(yaml.safe_load(open('$ETC/agent.yaml')).get('port',8787))")
if command -v ufw >/dev/null && ufw status | grep -q "^Status: active"; then
  if grep -q "^mode: tls" "$ETC/agent.yaml"; then
    say "Фаєрвол (ufw): порт $PORT_NOW лише для дозволених адрес"
    for ip in $(python3 -c "import yaml;print(' '.join(str(x) for x in yaml.safe_load(open('$ETC/agent.yaml')).get('allow_ips') or [] if not str(x).startswith(('127.','::1'))))"); do
      ufw allow from "$ip" to any port "$PORT_NOW" proto tcp comment "$NAME" >/dev/null && echo "  дозволено $ip"
    done
  fi
elif grep -q "^mode: tls" "$ETC/agent.yaml"; then
  echo "(ufw вимкнений — адреси обмежує сам агент: allow_ips)"
fi

say "Сервіс"
cat > "$UNIT" <<EOF
[Unit]
Description=HA Server Agent (стан і керування застосунками для Home Assistant)
After=network-online.target
Wants=network-online.target

[Service]
User=$USR
Group=$USR
ExecStart=/usr/bin/python3 -I $LIB/server.py
Restart=on-failure
RestartSec=5
# Посилення, що не заважає sudo-помічнику
ProtectKernelModules=yes
LockPersonality=yes
RestrictRealtime=yes
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
if [ "$NO_SERVICE" = 1 ]; then
  echo "(--no-service: сервіс не запускаю)"
else
  systemctl daemon-reload
  systemctl enable $NAME >/dev/null 2>&1
  systemctl restart $NAME
  sleep 1.5
  say "Самоперевірка"
  /usr/local/bin/$NAME test || { warn "Самоперевірка не вдалася — журнал: journalctl -u $NAME -n 50"; exit 1; }
fi

if [ "$NO_SERVICE" = 0 ] && grep -q "^mode: nginx" "$ETC/agent.yaml"; then
  D=$(python3 -c "import yaml;print(yaml.safe_load(open('$ETC/agent.yaml'))['domain'])")
  code=$(python3 - "$D" <<'PY'
import socket, ssl, sys, urllib.error, urllib.request
d = sys.argv[1]
orig = socket.getaddrinfo
socket.getaddrinfo = lambda h, *a, **k: orig("127.0.0.1" if h == d else h, *a, **k)  # через локальний nginx
try:
    urllib.request.urlopen(f"https://{d}/v1/ping", timeout=10, context=ssl._create_unverified_context())
    print("200")
except urllib.error.HTTPError as e:
    print(e.code)
except Exception as e:  # noqa: BLE001
    print("помилка:", e)
PY
)
  if [ "$code" = 401 ]; then echo "nginx → агент: ок (запит без підпису — 401, як і має бути)"
  else warn "nginx → агент: неочікувана відповідь ($code)"; fi
fi
if [ -n "$DOMAIN" ]; then
  ips=$(getent ahostsv4 "$DOMAIN" | awk '{print $1}' | sort -u | tr '\n' ' ')
  [ -n "$ips" ] || warn "Домен $DOMAIN не розв'язується — перевір DNS-запис у Cloudflare."
fi
if [ "$NO_SERVICE" = 0 ]; then
  if [ "$FIRST" = 1 ] || [ ! -s "$ETC/state/clients.yaml" ] || ! grep -q "key:" "$ETC/state/clients.yaml"; then
    say "Підключення до Home Assistant"
    /usr/local/bin/$NAME pair
  else
    echo; echo "Оновлено. Підключені клієнти: $(/usr/local/bin/$NAME clients | wc -l). Новий код підключення: sudo $NAME pair"
  fi
fi
