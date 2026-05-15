# VPS Security Operations Dashboard

A lightweight FastAPI dashboard for tracking common VPS security events from SSH, Fail2Ban, UFW, Nginx, and system authentication logs.

## What it tracks
- Failed SSH logins
- Invalid SSH users
- Successful SSH logins
- Password-based SSH login events
- Fail2Ban bans/unbans
- UFW firewall blocks
- Nginx 403/404 probes and 5xx errors
- Sudo/session activity

## Fail2Ban controls
The dashboard can manage Fail2Ban from the UI and JSON API:
- Switch between bundled `standard`, `enhanced`, and `paranoid` `jail.local` profiles.
- Add or remove persistent whitelist entries in `/etc/fail2ban/jail.d/99-vps-security-dashboard-whitelist.local`.
- Search active jails and banned IPs.
- Manually ban and unban IPs in a selected jail.

These controls require access to the Fail2Ban socket and write access to `/etc/fail2ban`. Keep the dashboard behind an SSH tunnel, VPN, or authenticated reverse proxy.

See [`docs/fail2ban-dashboard-api.md`](docs/fail2ban-dashboard-api.md) for the Fail2Ban API reference.

## Install
```bash
unzip vps_security_dashboard_bundle.zip
cd vps_security_dashboard_bundle
sudo bash scripts/install.sh
```

## Docker
```bash
docker compose up -d --build
```

The Compose file binds the dashboard to `127.0.0.1:8090`, persists the SQLite database in a named volume, and mounts `/var/log` read-only so the dashboard can inspect VPS logs. Keep it behind an SSH tunnel, VPN, or authenticated reverse proxy.

Open local tunnel from your workstation:
```bash
ssh -L 8090:127.0.0.1:8090 user@YOUR_SERVER_IP
```
Then open:
```text
http://127.0.0.1:8090
```

## Do not expose directly
Run this dashboard behind VPN, SSH tunnel, or Nginx with HTTPS and authentication.
