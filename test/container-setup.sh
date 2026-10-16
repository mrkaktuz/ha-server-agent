#!/usr/bin/env bash
# Тестове середовище в контейнері Ubuntu: nginx з https-сайтом, tmux, pm2 з двома застосунками.
# docker run -d --name dim-agent-test -p 127.0.0.1:18787:8787 -v "$PWD":/src:ro ubuntu:24.04 bash /src/test/container-setup.sh
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-cryptography python3-yaml sudo nginx tmux openssl nodejs npm procps >/dev/null
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
cd /opt/agent-src && bash ./install.sh --no-service
sed -i 's/^listen: .*/listen: 0.0.0.0/' /etc/dim-agent/agent.yaml
runuser -u dim-agent -- python3 -I /usr/local/lib/dim-agent/server.py > /var/log/dim-agent/server.log 2>&1 &
sleep 2
dim-agent test
echo READY
sleep infinity
