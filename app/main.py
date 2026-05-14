import os
import time
import socket
import platform
import subprocess
from pathlib import Path
from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import psutil
from .collector import ingest_tail
from .db import query_events, summary
from .config import APP_NAME

app = FastAPI(title=APP_NAME)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    ingest_tail(2000)
    data = summary()
    events = query_events(limit=100)
    return templates.TemplateResponse("index.html", {"request": request, "data": data, "events": events, "app_name": APP_NAME})

@app.get("/api/ingest")
def api_ingest(lines: int = 2000):
    return {"ingested_lines_checked": ingest_tail(lines)}

@app.get("/api/events")
def api_events(limit: int = Query(200, le=2000), source: str | None = None, severity: str | None = None, ip: str | None = None):
    return JSONResponse(query_events(limit=limit, source=source, severity=severity, ip=ip))

@app.get("/api/summary")
def api_summary():
    ingest_tail(2000)
    return summary()

@app.get("/api/system")
def api_system():
    boot_time = psutil.boot_time()
    uptime_seconds = int(time.time() - boot_time)

    cpu_percent = psutil.cpu_percent(interval=0.5)
    cpu_count = psutil.cpu_count(logical=True)

    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    net = psutil.net_io_counters()

    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown"

    try:
        machine_id = Path("/etc/machine-id").read_text().strip()
    except Exception:
        machine_id = "unknown"

    try:
        os_release_lines = Path("/etc/os-release").read_text().splitlines()
        os_release = {}
        for line in os_release_lines:
            if "=" in line:
                k, _, v = line.partition("=")
                os_release[k.strip()] = v.strip().strip('"')
        os_name = os_release.get("PRETTY_NAME", platform.platform())
    except Exception:
        os_name = platform.platform()

    return {
        "hostname": hostname,
        "os": os_name,
        "machine_id": machine_id,
        "uptime_seconds": uptime_seconds,
        "boot_time": boot_time,
        "cpu_percent": cpu_percent,
        "cpu_count": cpu_count,
        "memory_total_bytes": mem.total,
        "memory_used_bytes": mem.used,
        "memory_percent": mem.percent,
        "disk_total_bytes": disk.total,
        "disk_used_bytes": disk.used,
        "disk_percent": disk.percent,
        "net_bytes_sent": net.bytes_sent,
        "net_bytes_recv": net.bytes_recv,
        "platform": platform.machine(),
    }

@app.post("/api/reboot")
def api_reboot():
    try:
        subprocess.Popen(["shutdown", "-r", "+1"])
        return {"status": "reboot_scheduled", "message": "System will reboot in 1 minute"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/ssh-sessions")
def api_ssh_sessions():
    import struct
    sessions = []
    # utmp entry format (Linux x86_64)
    # see /usr/include/bits/utmp.h
    UT_TYPE_USER_PROCESS = 7
    UTMP_STRUCT = "hi32s4s32s256shhiii4i20s"
    UTMP_SIZE = struct.calcsize(UTMP_STRUCT)
    utmp_path = Path("/app/host-utmp")
    try:
        with open(utmp_path, "rb") as f:
            data = f.read()
        offset = 0
        while offset + UTMP_SIZE <= len(data):
            entry = struct.unpack_from(UTMP_STRUCT, data, offset)
            offset += UTMP_SIZE
            ut_type = entry[0]
            if ut_type != UT_TYPE_USER_PROCESS:
                continue
            ut_pid = entry[1]
            ut_line = entry[2].rstrip(b"\x00").decode("utf-8", errors="replace")
            ut_user = entry[4].rstrip(b"\x00").decode("utf-8", errors="replace")
            ut_host = entry[5].rstrip(b"\x00").decode("utf-8", errors="replace")
            ut_tv_sec = entry[9]
            login_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(ut_tv_sec))
            if not ut_user:
                continue
            sessions.append({
                "user": ut_user,
                "tty": ut_line,
                "date": login_time.split()[0],
                "time": login_time.split()[1],
                "pid": str(ut_pid),
                "from": ut_host,
            })
    except Exception as e:
        return {"sessions": [], "error": str(e)}
    return {"sessions": sessions, "count": len(sessions)}


@app.get("/api/failed-usernames")
def api_failed_usernames(limit: int = Query(20, le=100)):
    from collections import Counter
    import re
    counts: Counter = Counter()
    try:
        log_paths = [
            Path("/var/log/auth.log"),
            Path("/var/log/auth.log.1"),
            Path("/var/log/secure"),
        ]
        pattern = re.compile(
            r"Invalid user (\S+)|Failed password for(?: invalid user)? (\S+) from"
        )
        for log_path in log_paths:
            if not log_path.exists():
                continue
            try:
                with open(log_path, "r", errors="replace") as f:
                    for line in f:
                        m = pattern.search(line)
                        if m:
                            username = m.group(1) or m.group(2)
                            if username:
                                counts[username] += 1
            except PermissionError:
                continue
    except Exception as e:
        return {"usernames": [], "error": str(e)}

    top = [{"username": u, "attempts": c} for u, c in counts.most_common(limit)]
    return {"usernames": top, "total_unique": len(counts), "total_attempts": sum(counts.values())}


@app.post("/api/unblock")
async def api_unblock(request: Request):
    import re
    try:
        body = await request.json()
        ip = body.get("ip", "").strip()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if not ip:
        raise HTTPException(status_code=400, detail="Missing 'ip' field")

    if not re.match(r"^[\d\.a-fA-F:]+$", ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    try:
        result = subprocess.run(
            ["fail2ban-client", "set", "sshd", "unbanip", ip],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return {"status": "unblocked", "ip": ip, "message": f"{ip} has been unblocked"}
        else:
            raise HTTPException(status_code=500, detail=result.stderr.strip() or "fail2ban-client failed")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="fail2ban-client timed out")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="fail2ban-client not found on host")
