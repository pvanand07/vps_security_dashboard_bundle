from pathlib import Path

APP_NAME = "VPS Security Operations Dashboard"
DB_PATH = Path("/var/lib/vps-security-dashboard/events.db")
LOG_SOURCES = {
    "auth": ["/var/log/auth.log", "/var/log/secure"],
    "ufw": ["/var/log/ufw.log"],
    "nginx_access": ["/var/log/nginx/access.log"],
    "nginx_error": ["/var/log/nginx/error.log"],
    "fail2ban": ["/var/log/fail2ban.log"],
}
SEVERITY_WEIGHTS = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
