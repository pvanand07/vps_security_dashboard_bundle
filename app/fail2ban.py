import ipaddress
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .config import (
    FAIL2BAN_CLIENT,
    FAIL2BAN_CONFIG_DIR,
    FAIL2BAN_JAIL_LOCAL,
    FAIL2BAN_PROFILE_DIR,
)


PROFILE_DEFINITIONS = {
    "standard": {
        "label": "Standard",
        "description": "Balanced defaults for personal servers and low-traffic VMs.",
        "file": "jail-standard.local",
    },
    "enhanced": {
        "label": "Enhanced",
        "description": "Incremental banning and broader production web-server coverage.",
        "file": "jail-enhanced.local",
    },
    "paranoid": {
        "label": "Paranoid",
        "description": "Aggressive rules for hardened public-facing servers.",
        "file": "jail-paranoid.local",
    },
}

JAIL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
DEFAULT_IGNORE_IPS = ["127.0.0.1/8", "::1"]
WHITELIST_DROPIN_NAME = "99-vps-security-dashboard-whitelist.local"


class Fail2BanError(RuntimeError):
    pass


def whitelist_dropin_path() -> Path:
    return FAIL2BAN_CONFIG_DIR / "jail.d" / WHITELIST_DROPIN_NAME


def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _strip_inline_comment(line: str) -> str:
    for marker in ("#", ";"):
        if marker in line:
            line = line.split(marker, 1)[0]
    return line.strip()


def _extract_ignore_ips(text: str) -> list[str]:
    values: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        key, sep, raw_value = line.partition("=")
        if sep and key.strip().lower() == "ignoreip":
            values.extend(_strip_inline_comment(raw_value).split())
    return _dedupe(values)


def _read_text(path: Path) -> str:
    try:
        return path.read_text()
    except FileNotFoundError:
        return ""
    except PermissionError as exc:
        raise Fail2BanError(f"Permission denied reading {path}") from exc
    except OSError as exc:
        raise Fail2BanError(f"Unable to read {path}: {exc}") from exc


def _write_text(path: Path, content: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    except PermissionError as exc:
        raise Fail2BanError(f"Permission denied writing {path}") from exc
    except OSError as exc:
        raise Fail2BanError(f"Unable to write {path}: {exc}") from exc


def _run_fail2ban(args: list[str], timeout: int = 15) -> str:
    try:
        result = subprocess.run(
            [FAIL2BAN_CLIENT, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise Fail2BanError(f"{FAIL2BAN_CLIENT} not found on host") from exc
    except subprocess.TimeoutExpired as exc:
        raise Fail2BanError(f"{FAIL2BAN_CLIENT} timed out") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "fail2ban-client failed"
        raise Fail2BanError(detail)
    return result.stdout.strip()


def _validate_jail(jail: str) -> str:
    jail = jail.strip()
    if not jail or not JAIL_NAME_RE.match(jail):
        raise Fail2BanError("Invalid fail2ban jail name")
    return jail


def validate_ip(value: str) -> str:
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise Fail2BanError("Invalid IP address") from exc


def validate_ignore_ip(value: str) -> str:
    value = value.strip()
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise Fail2BanError("Invalid whitelist IP or CIDR network") from exc


def available_profiles() -> list[dict[str, Any]]:
    profiles = []
    for name, definition in PROFILE_DEFINITIONS.items():
        path = FAIL2BAN_PROFILE_DIR / definition["file"]
        profiles.append(
            {
                "name": name,
                "label": definition["label"],
                "description": definition["description"],
                "available": path.exists(),
            }
        )
    return profiles


def _profile_path(profile: str) -> Path:
    if profile not in PROFILE_DEFINITIONS:
        raise Fail2BanError("Unknown fail2ban profile")
    path = FAIL2BAN_PROFILE_DIR / PROFILE_DEFINITIONS[profile]["file"]
    if not path.exists():
        raise Fail2BanError(f"Fail2ban profile file not found: {path}")
    return path


def _normalized(text: str) -> str:
    return text.replace("\r\n", "\n").strip()


def active_profile() -> str | None:
    current = _normalized(_read_text(FAIL2BAN_JAIL_LOCAL))
    if not current:
        return None

    for profile, definition in PROFILE_DEFINITIONS.items():
        profile_path = FAIL2BAN_PROFILE_DIR / definition["file"]
        if profile_path.exists() and _normalized(_read_text(profile_path)) == current:
            return profile
    return "custom"


def read_whitelist() -> list[str]:
    values = [*DEFAULT_IGNORE_IPS]
    values.extend(_extract_ignore_ips(_read_text(FAIL2BAN_JAIL_LOCAL)))
    values.extend(_extract_ignore_ips(_read_text(whitelist_dropin_path())))
    return _dedupe(values)


def write_whitelist(values: list[str]) -> list[str]:
    normalized = _dedupe([validate_ignore_ip(value) for value in values])
    for default_ip in reversed(DEFAULT_IGNORE_IPS):
        if default_ip not in normalized:
            normalized.insert(0, default_ip)

    content = (
        "# Managed by VPS Security Operations Dashboard.\n"
        "# Edits here override the profile ignoreip setting and persist profile switches.\n"
        "[DEFAULT]\n"
        f"ignoreip = {' '.join(normalized)}\n"
    )
    _write_text(whitelist_dropin_path(), content)
    return normalized


def reload_fail2ban() -> None:
    _run_fail2ban(["reload"], timeout=30)


def switch_profile(profile: str) -> dict[str, Any]:
    profile_path = _profile_path(profile)
    preserved_whitelist = read_whitelist()
    backup_path = None
    had_existing_config = FAIL2BAN_JAIL_LOCAL.exists()

    if had_existing_config:
        backup_path = FAIL2BAN_JAIL_LOCAL.with_name(
            f"{FAIL2BAN_JAIL_LOCAL.name}.vpsdash.bak.{int(time.time())}"
        )
        try:
            shutil.copy2(FAIL2BAN_JAIL_LOCAL, backup_path)
        except OSError as exc:
            raise Fail2BanError(f"Unable to back up {FAIL2BAN_JAIL_LOCAL}: {exc}") from exc

    try:
        _write_text(FAIL2BAN_JAIL_LOCAL, _read_text(profile_path))
        whitelist = write_whitelist(preserved_whitelist)
        reload_fail2ban()
    except Exception:
        if backup_path and backup_path.exists():
            shutil.copy2(backup_path, FAIL2BAN_JAIL_LOCAL)
            try:
                reload_fail2ban()
            except Fail2BanError:
                pass
        elif not had_existing_config:
            try:
                FAIL2BAN_JAIL_LOCAL.unlink(missing_ok=True)
            except OSError:
                pass
        raise

    return {
        "profile": profile,
        "backup_path": str(backup_path) if backup_path else None,
        "whitelist": whitelist,
    }


def _parse_jails(status_output: str) -> list[str]:
    for raw_line in status_output.splitlines():
        if "Jail list:" in raw_line:
            _, _, value = raw_line.partition(":")
            return [jail.strip() for jail in value.split(",") if jail.strip()]
    return []


def _clean_status_key(line: str) -> str:
    return re.sub(r"^[\s|`\\/_-]+", "", line).strip()


def _parse_int(value: str) -> int | None:
    try:
        return int(value.strip())
    except ValueError:
        return None


def jail_status(jail: str) -> dict[str, Any]:
    jail = _validate_jail(jail)
    output = _run_fail2ban(["status", jail])
    status: dict[str, Any] = {
        "jail": jail,
        "banned_ips": [],
        "currently_failed": None,
        "total_failed": None,
        "currently_banned": None,
        "total_banned": None,
    }

    for raw_line in output.splitlines():
        line = _clean_status_key(raw_line)
        key, sep, value = line.partition(":")
        if not sep:
            continue
        normalized_key = key.strip().lower().replace(" ", "_")
        value = value.strip()
        if normalized_key == "banned_ip_list":
            status["banned_ips"] = [ip for ip in value.split() if ip]
        elif normalized_key in status:
            status[normalized_key] = _parse_int(value)

    return status


def fail2ban_status(search: str = "") -> dict[str, Any]:
    search = search.strip().lower()
    output = _run_fail2ban(["status"])
    jails = []

    for jail in _parse_jails(output):
        status = jail_status(jail)
        if search:
            matching_ips = [ip for ip in status["banned_ips"] if search in ip.lower()]
            if search not in jail.lower() and not matching_ips:
                continue
            if search not in jail.lower():
                status["banned_ips"] = matching_ips
        jails.append(status)

    return {
        "available": True,
        "active_profile": active_profile(),
        "profiles": available_profiles(),
        "whitelist": read_whitelist(),
        "jails": jails,
    }


def active_jails() -> list[str]:
    return _parse_jails(_run_fail2ban(["status"]))


def add_whitelist_ip(value: str) -> dict[str, Any]:
    ignore_ip = validate_ignore_ip(value)
    whitelist = write_whitelist([*read_whitelist(), ignore_ip])
    reload_fail2ban()

    # Remove the exact address immediately when possible. CIDR unbans are not
    # universally supported by fail2ban-client, so networks take effect on reload.
    if "/" not in ignore_ip:
        for jail in active_jails():
            try:
                _run_fail2ban(["set", jail, "unbanip", ignore_ip])
            except Fail2BanError:
                pass

    return {"ip": ignore_ip, "whitelist": whitelist}


def remove_whitelist_ip(value: str) -> dict[str, Any]:
    ignore_ip = validate_ignore_ip(value)
    whitelist = [ip for ip in read_whitelist() if ip != ignore_ip]
    whitelist = write_whitelist(whitelist)
    reload_fail2ban()
    return {"ip": ignore_ip, "whitelist": whitelist}


def ban_ip(jail: str, value: str) -> dict[str, Any]:
    jail = _validate_jail(jail)
    ip = validate_ip(value)
    _run_fail2ban(["set", jail, "banip", ip])
    return {"jail": jail, "ip": ip, "status": "banned"}


def unban_ip(jail: str, value: str) -> dict[str, Any]:
    jail = _validate_jail(jail)
    ip = validate_ip(value)
    _run_fail2ban(["set", jail, "unbanip", ip])
    return {"jail": jail, "ip": ip, "status": "unbanned"}
