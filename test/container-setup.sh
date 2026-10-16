#!/usr/bin/env bash
# Тестове середовище: Ubuntu 24.04 у Docker з nginx (https-сайт), tmux і pm2 (два застосунки);
# агент ставиться встановлювачем у віддаленому режимі (власний TLS на 2053), друкується код підключення.
#   docker run -d --name ha-agent-test -p 127.0.0.1:2053:2053 -v "$PWD":/src:ro ubuntu:24.04 bash /src/test/container-setup.sh
#   docker logs -f ha-agent-test      (код підключення — після READY)
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-cryptography python3-yaml sudo nginx tmux openssl nodejs npm procps iproute2 >/dev/null
npm install -g pm2 >/dev/null 2>&1
useradd -m -s /bin/bash deploy
mkdir -p /etc/ssl/test && openssl req -x509 -newkey rsa:2048 -nodes -days 40 -subj "/CN=site.test" \
  -keyout /etc/ssl/test/site.key -out /etc/ssl/test/site.pem 2>/dev/null
cat > /etc/nginx/sites-enabled/site <<'N'
server { listen 443 ssl; server_name site.test www.site.test;
  ssl_certificate /etc/ssl/test/site.pem; ssl_certificate_key /etc/ssl/test/site.key; return 200 "ok"; }
N
nginx
printf 'require("http").createServer((q,s)=>s.end("api")).listen(3000)\n' > /home/deploy/api.js
printf 'setInterval(()=>{},1000)\n' > /home/deploy/worker.js
chown deploy: /home/deploy/*.js
runuser -l deploy -c 'pm2 start /home/deploy/api.js --name api >/dev/null && pm2 start /home/deploy/worker.js --name worker >/dev/null'
runuser -l deploy -c 'tmux new -d -s build "bash"'
tmux new -d -s root-shell bash
cp -r /src /opt/agent-src
cd /opt/agent-src
# Адреса для HA на хості — localhost:2053 (порт проброшено); запити приходять з docker-шлюзу 172.17.0.1
bash ./install.sh --domain localhost --allow-ip 172.17.0.0/16 --no-service
setsid runuser -u ha-agent -- python3 -I /usr/local/lib/ha-server-agent/server.py >> /var/log/ha-server-agent/server.log 2>&1 < /dev/null &
sleep 2
ha-server-agent test
ha-server-agent pair
echo READY
sleep infinity
