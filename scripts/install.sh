#!/usr/bin/env bash
set -euo pipefail
APP_DIR=/opt/vps-security-dashboard
SERVICE_FILE=/etc/systemd/system/vps-security-dashboard.service
sudo mkdir -p "$APP_DIR" /var/lib/vps-security-dashboard
sudo cp -r app templates static docs requirements.txt "$APP_DIR"/
cd "$APP_DIR"
sudo python3 -m venv venv
sudo ./venv/bin/pip install --upgrade pip
sudo ./venv/bin/pip install -r requirements.txt
sudo useradd --system --no-create-home --shell /usr/sbin/nologin vpsdash || true
sudo usermod -aG adm vpsdash || true
sudo chown -R vpsdash:adm "$APP_DIR" /var/lib/vps-security-dashboard
sudo cp /opt/vps-security-dashboard/systemd/vps-security-dashboard.service "$SERVICE_FILE" 2>/dev/null || true
if [ ! -f "$SERVICE_FILE" ]; then
sudo tee "$SERVICE_FILE" >/dev/null <<SERVICE
[Unit]
Description=VPS Security Dashboard
After=network.target
[Service]
Type=simple
User=root
Group=adm
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8090
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/etc/fail2ban /var/lib/vps-security-dashboard
ProtectHome=true
[Install]
WantedBy=multi-user.target
SERVICE
fi
sudo systemctl daemon-reload
sudo systemctl enable --now vps-security-dashboard
printf '\nDashboard running locally at http://127.0.0.1:8090\nUse Nginx reverse proxy + HTTPS before public exposure.\n'
