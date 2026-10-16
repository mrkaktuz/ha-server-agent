# Dim Server Agent

Маленький агент для Ubuntu-серверів: показує в Home Assistant стан застосунків і дає ними
керувати — pm2, systemd-сервіси, nginx, SSL-сертифікати, Duplicati, tmux, Docker, fail2ban,
оновлення пакетів. Без SSH: власний API з підписами Ed25519 в обидва боки.

```
Home Assistant ──https (Cloudflare)──▶ nginx ──▶ dim-agent (127.0.0.1:8787, користувач dim-agent)
   інтеграція dim_server_agent                        │ sudo — лише «collect» / «action»
   (підписує запити, перевіряє підпис відповіді)      ▼
                                              dim-agent-helper (root) ── policy.yaml
```

## Безпека

| Рівень | Що робить |
| --- | --- |
| Мережа | Агент слухає лише `127.0.0.1`; назовні — тільки через nginx/Cloudflare. `allow_ips` — домашня IP (береться з `CF-Connecting-IP`, і лише для запитів від локального nginx) |
| Підпис запиту | Кожен запит підписаний приватним ключем HA (Ed25519): метод, шлях, час, одноразовий nonce, SHA-256 тіла. Агент знає лише **публічний** ключ HA |
| Повтори | Час запиту ±30 с, nonce одноразовий — перехоплений запит повторити не можна |
| Підпис відповіді | Агент підписує відповідь своїм ключем, прив'язуючи до nonce запиту — HA перевіряє, що говорить саме з цим сервером |
| Перебір | 10 невдалих спроб — IP блокується на 15 хв; ліміт 120 запитів/хв; однакова відповідь 401 без подробиць |
| Права | Мережевий процес — системний користувач `dim-agent` без оболонки. Root-дії — лише через помічника з двома командами (sudoers); помічник виконує тільки дозволене в `policy.yaml`, фіксованим argv без оболонки, ціль звіряється з поточним станом |
| Захищені сервіси | `ssh`, `sshd`, `dim-agent`, `journald`, `dbus` не можна зупинити навіть через політику |
| Журнал | Кожна дія — `/var/log/dim-agent/audit.log` (хто, з якої IP, що, результат) |

Що агент **не вміє** навмисно: виконувати довільні команди, читати файли, змінювати конфіги.

## Встановлення на сервер (Ubuntu 22.04 / 24.04)

```bash
git clone <цей репозиторій> dim-server-agent && cd dim-server-agent
sudo ./install.sh --allow-ip <домашня IP>
```

Встановлювач: ставить `python3-cryptography`, `python3-yaml` (якщо немає), створює користувача
`dim-agent`, ключ агента, **сам знаходить** pm2 (усіх користувачів, з nvm теж), nginx, сертифікати,
Duplicati, tmux-сесії, Docker, fail2ban і власні systemd-сервіси → пише `/etc/dim-agent/policy.yaml`,
запускає сервіс і робить самоперевірку. Наприкінці показує **публічний ключ агента**.

Оновлення — `git pull && sudo ./install.sh` (ключі, клієнти й політика лишаються).
Видалення — `sudo ./install.sh --uninstall` (`--purge` — разом із налаштуваннями).

### nginx + Cloudflare

Приклад — `nginx/dim-agent.conf.example`: піддомен `agent.<домен>` через Cloudflare (проксі увімкнено),
`location /v1/` → `127.0.0.1:8787`. Бажано ще правило Cloudflare WAF «лише домашня IP» для цього піддомену.

### Підключення до Home Assistant

1. Скопіювати `homeassistant/custom_components/dim_server_agent` у `/config/custom_components/` і перезапустити HA.
2. Налаштування → Пристрої та служби → Додати інтеграцію → **Dim Server Agent**: назва, адреса
   (`https://agent.<домен>`, без шляху), публічний ключ агента.
3. HA покаже **свій** ключ — на сервері: `sudo dim-agent add-client home-assistant <ключ>` → «Надіслати».

З'являться: «Проблеми» (кількість + повний стан в атрибутах), «Оновлення пакетів», «pm2: працює»,
«Сертифікат: днів до кінця», «Duplicati: остання копія», «Агент на зв'язку», «Потрібне перезавантаження»,
«nginx: помилка конфігу». Дії — сервіс `dim_server_agent.action` (сервер, модуль, ціль, дія).

## Політика (`/etc/dim-agent/policy.yaml`)

Створюється автовиявленням; правити вручну (перезапуск не потрібен). Модуль з `enabled: false` агент не чіпає.

| Модуль | Що бачить | Дії (за замовчуванням) |
| --- | --- | --- |
| `system` | ОС, ядро, час роботи, навантаження, оновлення (усього / безпеки), чи потрібне перезавантаження, збійні сервіси | — |
| `systemd` | Сервіси зі списку `units` | для кожного свій список: `start`, `stop`, `restart`, `reload` |
| `pm2` | Процеси кожного користувача з `instances`: стан, CPU, пам'ять, перезапуски, з якого часу | `start`, `stop`, `restart`, `reload` (+ `pm2 save`) |
| `nginx` | Версія, стан, `nginx -t`, сайти й домени | `test`, `reload`, `restart` — reload/restart лише після вдалого `nginx -t` |
| `certs` | Сертифікати з конфігів nginx і Let's Encrypt: домен, видавець, днів до кінця | — |
| `duplicati` | Завдання (API Duplicati 2.1+): остання вдала копія, помилки, розмір | `run` (пароль — `secrets.yaml: duplicati_password`) |
| `tmux` | Сесії користувачів з `users`: вікна, команди, чи підключено | `kill` лише з `allow_kill: true` |
| `docker` | Контейнери | `start`, `stop`, `restart` (`containers: []` — будь-які, інакше лише перелічені) |
| `fail2ban` | Jail-и: заблоковано зараз / усього | — |
| `processes` | Топ-5 процесів за CPU і пам'яттю | — |

## Команди на сервері

```
sudo dim-agent show-key                 публічний ключ агента
sudo dim-agent add-client NAME KEY      дозволити клієнта (ключ показує HA)
sudo dim-agent remove-client NAME
sudo dim-agent clients
sudo dim-agent allow-ip 1.2.3.4         дозволені адреси (без аргументів — будь-які)
sudo dim-agent detect                   що знайдено; --write --force — перезаписати policy.yaml
sudo dim-agent test                     самоперевірка (підписаний запит, перевірка відповіді, 401 без підпису)
sudo dim-agent status
journalctl -u dim-agent                 журнал сервісу;  /var/log/dim-agent/audit.log — дії
```

## Перевірка без сервера

`test/container-setup.sh` — Ubuntu 24.04 у Docker з nginx (https-сайт), tmux і pm2 (два застосунки);
ставить агента встановлювачем і робить самоперевірку. `test/client.py` — підписані запити ззовні:
дії, відмови політики, чужий підпис, підмінене тіло, застарілий час, повтор nonce.

```bash
docker run -d --name dim-agent-test -p 127.0.0.1:18787:8787 -v "$PWD":/src:ro ubuntu:24.04 bash /src/test/container-setup.sh
```
