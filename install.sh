#!/usr/bin/env bash
# Встановлення / оновлення Dim Server Agent на Ubuntu 22.04 / 24.04.
#   sudo ./install.sh [--allow-ip 1.2.3.4] [--port 8787]
#   sudo ./install.sh --uninstall [--purge]
# Повторний запуск оновлює код і не чіпає ключі, клієнтів і policy.yaml.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "Запусти через sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/agent"
LIB=/usr/local/lib/dim-agent
ETC=/etc/dim-agent
LOG=/var/log/dim-agent
CACHE=/var/cache/dim-agent
UNIT=/etc/systemd/system/dim-agent.service
SUDOERS=/etc/sudoers.d/dim-agent

ALLOW_IP=""
PORT=8787
UNINSTALL=0
PURGE=0
NO_SERVICE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --allow-ip) ALLOW_IP="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    --no-service) NO_SERVICE=1; shift ;;  # для перевірки в контейнері без systemd
    *) echo "Невідомий параметр: $1"; exit 2 ;;
  esac
done

if [ "$UNINSTALL" = 1 ]; then
  systemctl disable --now dim-agent 2>/dev/null || true
  rm -f "$UNIT" "$SUDOERS" /usr/local/bin/dim-agent
  rm -rf "$LIB" "$CACHE"
  systemctl daemon-reload
  if [ "$PURGE" = 1 ]; then rm -rf "$ETC" "$LOG"; userdel dim-agent 2>/dev/null || true; fi
  [ "$PURGE" = 1 ] && echo "Агента видалено разом із налаштуваннями." || echo "Агента видалено (налаштування лишились у $ETC)."
  exit 0
fi

echo "==> Залежності"
missing=""
python3 -c "import cryptography" 2>/dev/null || missing="$missing python3-cryptography"
python3 -c "import yaml" 2>/dev/null || missing="$missing python3-yaml"
if [ -n "$missing" ]; then apt-get update -qq && apt-get install -y -qq $missing; fi

echo "==> Користувач dim-agent"
id dim-agent >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin dim-agent

echo "==> Файли"
install -d -o root -g root -m 755 "$LIB"
install -o root -g root -m 644 "$SRC/protocol.py" "$SRC/server.py" "$SRC/helper.py" "$SRC/cli.py" "$LIB/"
cat > "$LIB/dim-agent-helper" <<'EOF'
#!/bin/sh
# Привілейований помічник dim-agent: лише collect | action | detect (див. helper.py)
exec /usr/bin/python3 -I /usr/local/lib/dim-agent/helper.py "$@"
EOF
chmod 755 "$LIB/dim-agent-helper"
cat > /usr/local/bin/dim-agent <<'EOF'
#!/bin/sh
exec /usr/bin/python3 -I /usr/local/lib/dim-agent/cli.py "$@"
EOF
chmod 755 /usr/local/bin/dim-agent

install -d -o root -g dim-agent -m 750 "$ETC"
install -d -o dim-agent -g dim-agent -m 750 "$LOG"
install -d -o root -g root -m 700 "$CACHE"

if [ ! -f "$ETC/agent.key" ]; then
  echo "==> Ключ агента"
  python3 -I -c "import sys; sys.path.insert(0,'$LIB'); import protocol as P; print(P.generate_keypair()[0])" > "$ETC/agent.key"
fi
chown dim-agent:dim-agent "$ETC/agent.key"; chmod 600 "$ETC/agent.key"

if [ ! -f "$ETC/agent.yaml" ]; then
  cat > "$ETC/agent.yaml" <<EOF
# Налаштування мережевого шару dim-agent. Клієнтів додавати: sudo dim-agent add-client
listen: 127.0.0.1
port: $PORT
# Дозволені адреси клієнтів (домашня статична IP). Порожньо — будь-які (не рекомендовано).
allow_ips: [${ALLOW_IP}]
# Справжню адресу клієнта беремо з цього заголовка (його ставить Cloudflare), лише для запитів від nginx (127.0.0.1)
trusted_proxy_header: CF-Connecting-IP
rate_per_minute: 120
max_failures: 10
clients: []
EOF
fi
chown root:dim-agent "$ETC/agent.yaml"; chmod 640 "$ETC/agent.yaml"

if [ ! -f "$ETC/secrets.yaml" ]; then
  cat > "$ETC/secrets.yaml" <<'EOF'
# Секрети для помічника (читає лише root). Напр.:
# duplicati_password: "пароль вебінтерфейсу Duplicati"
{}
EOF
fi
chown root:root "$ETC/secrets.yaml"; chmod 600 "$ETC/secrets.yaml"

if [ ! -f "$ETC/policy.yaml" ]; then
  echo "==> Автовиявлення (policy.yaml)"
  "$LIB/dim-agent-helper" detect --write >/dev/null
fi
chown root:root "$ETC/policy.yaml"; chmod 644 "$ETC/policy.yaml"

echo "==> sudo: лише помічник collect / action"
cat > "$SUDOERS" <<EOF
# dim-agent може запускати від root тільки помічника з двома командами
Defaults:dim-agent !requiretty, !lecture
dim-agent ALL=(root) NOPASSWD: $LIB/dim-agent-helper collect, $LIB/dim-agent-helper action
EOF
chmod 440 "$SUDOERS"
visudo -cf "$SUDOERS" >/dev/null

echo "==> Сервіс"
cat > "$UNIT" <<'EOF'
[Unit]
Description=Dim Server Agent (стан і керування застосунками для Home Assistant)
After=network-online.target
Wants=network-online.target

[Service]
User=dim-agent
Group=dim-agent
ExecStart=/usr/bin/python3 -I /usr/local/lib/dim-agent/server.py
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
  systemctl enable dim-agent >/dev/null 2>&1
  systemctl restart dim-agent
  sleep 1
  echo "==> Самоперевірка"
  dim-agent test || { echo "Самоперевірка не вдалася — див. journalctl -u dim-agent"; exit 1; }
fi

echo
echo "Знайдено: $("$LIB/dim-agent-helper" detect --summary)"
echo "Політика: $ETC/policy.yaml (що бачити й чим керувати; правити вручну)"
echo
echo "Публічний ключ агента (вставити в Home Assistant):"
dim-agent show-key
echo
echo "Далі: 1) nginx + Cloudflare — див. nginx/dim-agent.conf.example"
echo "      2) Home Assistant: Налаштування → Інтеграції → Dim Server Agent → покаже свій ключ"
echo "      3) sudo dim-agent add-client home-assistant <ключ HA>"
