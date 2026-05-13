import hashlib, re
from datetime import datetime

IP_RE = re.compile(r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.|$)){4}")
USER_RE = re.compile(r"(?:invalid user|Failed password for(?: invalid user)?|Accepted .* for)\s+(\S+)")

def fingerprint(raw, source):
    return hashlib.sha256((source + "|" + raw.strip()).encode()).hexdigest()

def extract_ip(line):
    m = IP_RE.search(line)
    return m.group(0).rstrip('.') if m else None

def extract_user(line):
    m = USER_RE.search(line)
    return m.group(1) if m else None

def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def classify(source, line):
    l = line.lower()
    category, severity = "other", "info"
    if "failed password" in l or "invalid user" in l:
        category, severity = "ssh_bruteforce", "high"
    elif "accepted password" in l:
        category, severity = "ssh_password_login", "high"
    elif "accepted publickey" in l:
        category, severity = "ssh_success", "info"
    elif "authentication failure" in l:
        category, severity = "auth_failure", "medium"
    elif "ban " in l or "banned" in l:
        category, severity = "fail2ban_ban", "medium"
    elif "unban" in l:
        category, severity = "fail2ban_unban", "info"
    elif "ufw block" in l or "[ufw block]" in l:
        category, severity = "firewall_block", "medium"
    elif " 404 " in line or " 403 " in line:
        category, severity = "web_probe", "medium"
    elif " 500 " in line or "error" in l or "critical" in l:
        category, severity = "service_error", "high"
    elif "sudo" in l and "session opened" in l:
        category, severity = "privilege_use", "low"
    return category, severity

def parse_line(source, line):
    category, severity = classify(source, line)
    return {
        "ts": now_iso(),
        "source": source,
        "severity": severity,
        "category": category,
        "ip": extract_ip(line),
        "username": extract_user(line),
        "message": line.strip()[:240],
        "raw": line.strip(),
        "fingerprint": fingerprint(line, source),
    }
