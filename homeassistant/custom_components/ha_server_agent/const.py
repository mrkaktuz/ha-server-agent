"""Константи інтеграції HA Server Agent."""

DOMAIN = "ha_server_agent"
CONF_URL = "url"
CONF_AGENT_KEY = "agent_key"      # публічний ключ агента (перевірка відповідей)
CONF_CLIENT_KEY = "client_key"    # приватний ключ Home Assistant (підпис запитів)
CONF_FINGERPRINT = "fingerprint"  # SHA-256 сертифіката агента (закріплення), якщо свій TLS
CONF_CODE = "code"
SCAN_INTERVAL = 60  # с
