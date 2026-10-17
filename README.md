# HA Server Agent

**English** · [Українська](README.uk.md)

A small agent for Ubuntu servers that lets **Home Assistant** see what runs on the server and control it:
pm2 processes, systemd services, nginx, SSL certificates, Duplicati backups, tmux sessions, Docker containers,
fail2ban, package updates. No SSH: the agent has its own HTTPS API where every request and every response is
signed (Ed25519). The agent updates itself from GitHub with one click in Home Assistant.

```
Home Assistant ──https──▶ nginx (agent's subdomain) ──▶ agent on 127.0.0.1:8787 (unprivileged user)
  integration "HA Server Agent"                               │ sudo: only "collect" / "action"
  (signs requests, checks response signatures)                ▼
                                                     root helper ── policy.yaml (what is allowed)
```

## What you get in Home Assistant

- **Sensors per server:** problems (count + full state for dashboards), package updates, pm2 processes running,
  days until the nearest certificate expires, last Duplicati backup, agent online, reboot required, nginx config error.
- **Update entity** "Agent" — new agent versions appear in *Settings → Updates*, install with one click.
- **Repairs** — if the agent needs a password (e.g. Duplicati web UI), Home Assistant tells you exactly where to put it.
- **Action** `ha_server_agent.action` — restart / stop / start a pm2 process, a service or a container,
  `nginx -t` + reload, run a Duplicati backup now.

## Requirements

- Ubuntu 20.04, 22.04 or 24.04 (root access to install).
- A (sub)domain pointing to the server, e.g. `agent.example.com` — for servers that Home Assistant reaches over the internet.
- Home Assistant 2024.12 or newer.

## Quick start

**1. On the server** — clone and install (pick one line):

```bash
sudo git clone https://github.com/mrkaktuz/ha-server-agent /opt/ha-server-agent

# server reachable over the internet (your Home Assistant's public IP in --allow-ip)
sudo /opt/ha-server-agent/install.sh --domain agent.example.com --allow-ip 203.0.113.7
# the server where Home Assistant itself runs
sudo /opt/ha-server-agent/install.sh --local
```

At the end the installer prints the **mode** it chose and a **connection code** (`HSA1:…`).

**2. In Home Assistant** — copy `homeassistant/custom_components/ha_server_agent` from this repository to
`/config/custom_components/` and restart Home Assistant (once).

**3.** *Settings → Devices & services → Add integration → **HA Server Agent*** → a name for the server + the
connection code. Done: Home Assistant pairs with the agent by itself. The code works once and expires in 24 hours;
a new one: `sudo ha-server-agent pair`.

## Network modes (chosen automatically)

| Mode | When | How Home Assistant connects |
| --- | --- | --- |
| **nginx** | nginx is running on the server | The installer adds an nginx site for `--domain` (HTTPS, port 443) that forwards `/v1/` to the agent on `127.0.0.1:8787` — the agent's port is never exposed. Certificate: an existing one that covers the domain (e.g. a wildcard), otherwise a new Let's Encrypt certificate (HTTP check through the same nginx, renews automatically). Works behind Cloudflare with the proxy on or off. |
| **own HTTPS** | no nginx (or `--no-nginx`) | The agent listens on port **2053** with its own certificate; Home Assistant pins its fingerprint. If `ufw` is active the port is opened only for `--allow-ip`. Cloudflare: DNS only (grey cloud). |
| **local** | `--local` | `http://127.0.0.1:8787`, only for Home Assistant on the same machine. |

Your other nginx sites are not touched.

## What the installer does

- Installs `python3-cryptography`, `python3-yaml`, `git` if missing; creates the system user `ha-agent`.
- **Detects** what is on the server: pm2 (all users, nvm too), nginx and its sites, certificates, Duplicati
  (service or container, its port), tmux sessions, Docker, fail2ban, custom systemd services — and writes
  `/etc/ha-server-agent/policy.yaml` (what the agent may show and do; edit it any time).
- Sets up the network mode, a systemd service, a sudo rule for the helper only, runs a self-test.

Running `install.sh` again updates the code and keeps keys, paired clients, certificates and the policy.
Uninstall: `sudo /opt/ha-server-agent/install.sh --uninstall` (`--purge` also removes settings).

## Self-update

Every 3 hours the agent runs `git fetch` in its clone and compares with GitHub. When there is a new commit,
the "Agent" update appears in Home Assistant. *Install* → the agent (in a separate systemd unit) runs
`git reset --hard origin/main` and `install.sh --update`, then restarts with the new code.
Log: `/var/log/ha-server-agent/update.log`. Manually: `sudo ha-server-agent update`.
Disable: `agent: {allow_update: false}` in `policy.yaml`.

## Security

| Layer | What it does |
| --- | --- |
| Network | The agent listens on `127.0.0.1` behind nginx (or HTTPS with its own pinned certificate); `allow_ips` (+ ufw) |
| Request signature | Every request is signed with Home Assistant's private key (Ed25519): method, path, time, one-time nonce, body hash. The agent only knows the **public** key |
| Replays | Time window ±30 s, every nonce is accepted once |
| Response signature | The agent signs every response with its own key, bound to the request nonce — Home Assistant knows it talks to *this* server |
| Pairing | One-time secret from the connection code (HMAC), valid 24 h, destroyed after use |
| Brute force | 10 failures → IP blocked for 15 min; 120 requests/min limit; the same `401` for every auth failure |
| Privileges | The network process runs as `ha-agent` (no shell). Root actions go only through a helper with two commands (sudoers); the helper performs only what `policy.yaml` allows, with a fixed argv and no shell, and checks the target against the current state |
| Protected services | `ssh`, `sshd`, the agent itself, `journald`, `dbus` can never be stopped |
| Updates | Only from the git repository; Home Assistant can start an update but cannot send code |
| Audit | Every action and pairing → `/var/log/ha-server-agent/audit.log` |

By design the agent **cannot** run arbitrary commands, read files or change configs.

## Secrets

If a module needs a password (today: a password-protected Duplicati web UI), the agent notices it and Home
Assistant shows a repair: add `duplicati_password: "…"` to `/etc/ha-server-agent/secrets.yaml` (root-only).
No restart needed.

## Policy (`/etc/ha-server-agent/policy.yaml`)

| Module | Shows | Actions (default) |
| --- | --- | --- |
| `system` | OS, kernel, uptime, load, updates (total / security), reboot required, failed services | — |
| `systemd` | Services listed in `units` | per service: `start`, `stop`, `restart`, `reload` |
| `pm2` | Processes of users in `instances`: status, CPU, memory, restarts, uptime; **whether pm2 comes back after a reboot** (`pm2-<user>` service, pm2/node paths, `pm2 save`) | `start`, `stop`, `restart`, `reload` (+ `pm2 save`); `autostart` — set up autostart (`allow_autostart: false` to forbid) |
| `nginx` | Version, state, `nginx -t`, sites and domains | `test`, `reload`, `restart` — only after a successful `nginx -t` |
| `certs` | Certificates from nginx configs and Let's Encrypt: domain, issuer, days left | — |
| `duplicati` | Backups (Duplicati 2.1+ API): last success, errors, size | `run` |
| `tmux` | Sessions of users in `users`: windows, commands, attached | `kill` only with `allow_kill: true` |
| `docker` | Containers | `start`, `stop`, `restart` (`containers: []` = any, otherwise only listed) |
| `fail2ban` | Jails: banned now / total | — |
| `processes` | Top 5 processes by CPU and memory | — |
| `agent` | Version, commit, newer commit on GitHub | `update`, `check` |

## Commands on the server

```
sudo ha-server-agent pair                new connection code
sudo ha-server-agent clients             paired clients;  remove-client NAME — unpair
sudo ha-server-agent allow-ip IP ...     allowed client addresses
sudo ha-server-agent detect              what was found;  --write --force — rewrite policy.yaml
sudo ha-server-agent test                self-test
sudo ha-server-agent update              update from GitHub
sudo ha-server-agent status
journalctl -u ha-server-agent            service log
```

## Troubleshooting

- **"Agent did not accept the code"** — the code was already used or expired (`sudo ha-server-agent pair`),
  or Home Assistant's IP is not in `allow_ips` (`sudo ha-server-agent allow-ip <IP>`).
- **"Cannot connect"** — check DNS for the domain, ports 443 (nginx mode) or 2053 (own HTTPS) in the provider's firewall.
- **Let's Encrypt failed** — the domain must resolve to the server and port 80 must be reachable; the agent then
  uses its own certificate (Home Assistant pins it) — it still works. Details: `/tmp/ha-server-agent-certbot.log`.
- Logs: `journalctl -u ha-server-agent`, `/var/log/ha-server-agent/audit.log`, `/var/log/ha-server-agent/update.log`.

## Testing without a server

`test/container-setup.sh` — Ubuntu 24.04 in Docker with nginx, tmux and pm2; installs the agent in nginx mode and
prints a connection code. `test/client.py` — signed requests from outside: actions, policy denials, a foreign
signature, a tampered body, an old timestamp, a replayed nonce.

Code comments and server messages are in Ukrainian.
