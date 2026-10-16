"""Константи інтеграції Dim Server Agent."""

DOMAIN = "dim_server_agent"
CONF_URL = "url"
CONF_AGENT_KEY = "agent_key"    # публічний ключ агента (перевірка відповідей)
CONF_CLIENT_KEY = "client_key"  # приватний ключ Home Assistant (підпис запитів)
SCAN_INTERVAL = 60  # с
