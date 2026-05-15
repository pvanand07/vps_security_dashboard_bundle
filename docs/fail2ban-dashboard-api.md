# Fail2Ban Dashboard API

This document covers only the API endpoints introduced by commit `6cff3370534deb4dce1f20dc39231c447f428f1b`.

Frontend agents should use `http://127.0.0.1:8090` as the default base URL during local or SSH-tunnel access.

All POST endpoints expect JSON:

```http
Content-Type: application/json
```

Fail2Ban API errors use FastAPI's default error response:

```json
{
  "detail": "Error message"
}
```

Invalid or unknown inputs return HTTP `400`. Runtime Fail2Ban, file permission, timeout, and host command failures return HTTP `500` unless otherwise handled by FastAPI.

## Shared Types

### Profile Object

```json
{
  "name": "enhanced",
  "label": "Enhanced",
  "description": "Incremental banning and broader production web-server coverage.",
  "available": true
}
```

Allowed profile names:

| Value | Label | Description |
| --- | --- | --- |
| `standard` | Standard | Balanced defaults for personal servers and low-traffic VMs. |
| `enhanced` | Enhanced | Incremental banning and broader production web-server coverage. |
| `paranoid` | Paranoid | Aggressive rules for hardened public-facing servers. |

### Jail Object

```json
{
  "jail": "sshd",
  "banned_ips": [
    "203.0.113.10"
  ],
  "currently_failed": 2,
  "total_failed": 88,
  "currently_banned": 1,
  "total_banned": 12
}
```

`currently_failed`, `total_failed`, `currently_banned`, and `total_banned` can be `null` if the local `fail2ban-client status <jail>` output does not include a parseable integer for that field.

## GET `/api/fail2ban`

Returns Fail2Ban status for active jails, the active dashboard profile, available bundled profiles, and persistent whitelist entries.

### Input Fields

| Field | Location | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- | --- |
| `search` | query | string | no | `""` | Filters returned jails by jail name or banned IP substring. |

### Curl

```bash
curl -s "http://127.0.0.1:8090/api/fail2ban?search=sshd"
```

### Output Format

```json
{
  "available": true,
  "active_profile": "enhanced",
  "profiles": [
    {
      "name": "standard",
      "label": "Standard",
      "description": "Balanced defaults for personal servers and low-traffic VMs.",
      "available": true
    },
    {
      "name": "enhanced",
      "label": "Enhanced",
      "description": "Incremental banning and broader production web-server coverage.",
      "available": true
    },
    {
      "name": "paranoid",
      "label": "Paranoid",
      "description": "Aggressive rules for hardened public-facing servers.",
      "available": true
    }
  ],
  "whitelist": [
    "127.0.0.1/8",
    "::1",
    "203.0.113.5"
  ],
  "jails": [
    {
      "jail": "sshd",
      "banned_ips": [
        "203.0.113.10"
      ],
      "currently_failed": 2,
      "total_failed": 88,
      "currently_banned": 1,
      "total_banned": 12
    }
  ]
}
```

### Frontend Notes

Use this endpoint for the main Fail2Ban dashboard view. When `search` matches only banned IPs and not the jail name, each returned jail's `banned_ips` list is narrowed to matching IPs.

## GET `/api/fail2ban/config`

Returns Fail2Ban profile and whitelist configuration without jail status details.

### Input Fields

None.

### Curl

```bash
curl -s "http://127.0.0.1:8090/api/fail2ban/config"
```

### Output Format

```json
{
  "active_profile": "standard",
  "profiles": [
    {
      "name": "standard",
      "label": "Standard",
      "description": "Balanced defaults for personal servers and low-traffic VMs.",
      "available": true
    },
    {
      "name": "enhanced",
      "label": "Enhanced",
      "description": "Incremental banning and broader production web-server coverage.",
      "available": true
    },
    {
      "name": "paranoid",
      "label": "Paranoid",
      "description": "Aggressive rules for hardened public-facing servers.",
      "available": true
    }
  ],
  "whitelist": [
    "127.0.0.1/8",
    "::1"
  ]
}
```

### Frontend Notes

`active_profile` can be `null` if no `jail.local` content exists, or `"custom"` if the active config does not exactly match a bundled profile.

## POST `/api/fail2ban/config`

Switches Fail2Ban to a bundled profile and reloads Fail2Ban. Existing whitelist entries are preserved.

### Input Fields

| Field | Location | Type | Required | Allowed Values |
| --- | --- | --- | --- | --- |
| `profile` | JSON body | string | yes | `standard`, `enhanced`, `paranoid` |

### Curl

```bash
curl -s -X POST "http://127.0.0.1:8090/api/fail2ban/config" \
  -H "Content-Type: application/json" \
  -d '{"profile":"enhanced"}'
```

### Output Format

```json
{
  "profile": "enhanced",
  "backup_path": "/etc/fail2ban/jail.local.vpsdash.bak.1778841234",
  "whitelist": [
    "127.0.0.1/8",
    "::1",
    "203.0.113.5"
  ]
}
```

### Frontend Notes

`backup_path` is `null` when there was no existing `jail.local` to back up. Disable profile buttons where `available` is `false`.

## POST `/api/fail2ban/whitelist`

Adds an IP address or CIDR network to persistent Fail2Ban `ignoreip` configuration and reloads Fail2Ban.

### Input Fields

| Field | Location | Type | Required | Notes |
| --- | --- | --- | --- | --- |
| `ip` | JSON body | string | yes | IPv4 address, IPv6 address, IPv4 CIDR, or IPv6 CIDR. |

### Curl

```bash
curl -s -X POST "http://127.0.0.1:8090/api/fail2ban/whitelist" \
  -H "Content-Type: application/json" \
  -d '{"ip":"203.0.113.5/32"}'
```

### Output Format

```json
{
  "ip": "203.0.113.5/32",
  "whitelist": [
    "127.0.0.1/8",
    "::1",
    "203.0.113.5/32"
  ]
}
```

### Frontend Notes

The API normalizes the submitted value. For example, a host address may remain an address, while CIDR input is normalized as a network. The default entries `127.0.0.1/8` and `::1` are always preserved.

## POST `/api/fail2ban/whitelist/remove`

Removes an IP address or CIDR network from persistent Fail2Ban `ignoreip` configuration and reloads Fail2Ban.

### Input Fields

| Field | Location | Type | Required | Notes |
| --- | --- | --- | --- | --- |
| `ip` | JSON body | string | yes | IPv4 address, IPv6 address, IPv4 CIDR, or IPv6 CIDR. |

### Curl

```bash
curl -s -X POST "http://127.0.0.1:8090/api/fail2ban/whitelist/remove" \
  -H "Content-Type: application/json" \
  -d '{"ip":"203.0.113.5/32"}'
```

### Output Format

```json
{
  "ip": "203.0.113.5/32",
  "whitelist": [
    "127.0.0.1/8",
    "::1"
  ]
}
```

### Frontend Notes

The default entries `127.0.0.1/8` and `::1` are reinserted by the backend even if a remove request targets them.

## POST `/api/fail2ban/ban`

Manually bans an IP address in the requested Fail2Ban jail.

### Input Fields

| Field | Location | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- | --- |
| `ip` | JSON body | string | yes | none | IPv4 or IPv6 address. CIDR is not accepted. |
| `jail` | JSON body | string | no | `sshd` | Must match `^[A-Za-z0-9_.-]+$`. |

### Curl

```bash
curl -s -X POST "http://127.0.0.1:8090/api/fail2ban/ban" \
  -H "Content-Type: application/json" \
  -d '{"jail":"sshd","ip":"203.0.113.10"}'
```

### Output Format

```json
{
  "jail": "sshd",
  "ip": "203.0.113.10",
  "status": "banned"
}
```

### Frontend Notes

Refresh `/api/fail2ban` after a successful ban to show updated jail counts and banned IP lists.

## POST `/api/fail2ban/unban`

Manually unbans an IP address from the requested Fail2Ban jail.

### Input Fields

| Field | Location | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- | --- |
| `ip` | JSON body | string | yes | none | IPv4 or IPv6 address. CIDR is not accepted. |
| `jail` | JSON body | string | no | `sshd` | Must match `^[A-Za-z0-9_.-]+$`. |

### Curl

```bash
curl -s -X POST "http://127.0.0.1:8090/api/fail2ban/unban" \
  -H "Content-Type: application/json" \
  -d '{"jail":"sshd","ip":"203.0.113.10"}'
```

### Output Format

```json
{
  "jail": "sshd",
  "ip": "203.0.113.10",
  "status": "unbanned"
}
```

### Frontend Notes

Refresh `/api/fail2ban` after a successful unban to show updated jail counts and banned IP lists.
