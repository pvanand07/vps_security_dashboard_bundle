import os
from pathlib import Path

APP_NAME = "VPS Security Operations Dashboard"
DB_PATH = Path("/var/lib/vps-security-dashboard/events.db")
BASE_DIR = Path(__file__).resolve().parent.parent
FAIL2BAN_CLIENT = os.getenv("VPSDASH_FAIL2BAN_CLIENT", "fail2ban-client")
FAIL2BAN_CONFIG_DIR = Path(os.getenv("VPSDASH_FAIL2BAN_CONFIG_DIR", "/etc/fail2ban"))
FAIL2BAN_JAIL_LOCAL = Path(
    os.getenv("VPSDASH_FAIL2BAN_JAIL_LOCAL", str(FAIL2BAN_CONFIG_DIR / "jail.local"))
)
FAIL2BAN_PROFILE_DIR = Path(os.getenv("VPSDASH_FAIL2BAN_PROFILE_DIR", str(BASE_DIR / "docs")))
LOG_SOURCES = {
    "auth": ["/var/log/auth.log", "/var/log/secure"],
    "ufw": ["/var/log/ufw.log"],
    "nginx_access": ["/var/log/nginx/access.log"],
    "nginx_error": ["/var/log/nginx/error.log"],
    "fail2ban": ["/var/log/fail2ban.log"],
}
SEVERITY_WEIGHTS = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
