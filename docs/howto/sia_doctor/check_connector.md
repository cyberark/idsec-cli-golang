---
title: SIA Doctor — check-connector
description: Verify that each SIA connector can reach its backend and optionally reach target machines
---

# SIA Doctor — `check-connector`

`idsec sia doctor check-connector` asks each SIA connector to test reachability to its **own backend** (the SIA cloud-side control plane endpoints it tunnels out to). Results are grouped per connector and include the connector's hostname, IP, platform, version, and status — so you know exactly which physical machine needs attention.

By default, **every connector in the tenant** is checked. Only connectors in `Active` status are reachability-tested; connectors that are offline or in any other non-active state are listed as `skipped` (calling the reachability API on an inactive connector returns HTTP 500 and provides no useful signal).

---

## How it works

### Step 1 — Connector ID resolution

The doctor determines the set of connector IDs to check from one or more sources, in priority order:

1. **`--connector-ids`** — explicit IDs, used directly.
2. **`--connector-machines`** — machines to SSH or WinRM into; the doctor reads the connector config file from each (`/opt/cyberark/connector/connector.config.json` on Linux, `C:\Program Files\CyberArk\DPAConnector\connector.config.json` on Windows) and extracts the ID. Failures are surfaced as error rows rather than aborting the run.
3. **`--local`** — reads the connector config file from the **local machine** where `idsec` is running.
4. **(default, none of the above)** — calls the SIA API to list **all connectors** in the tenant and uses their IDs.

All three explicit sources can be combined; their resulting IDs are deduplicated.

### Step 2 — Status filtering

The full connector list from the API is fetched once (even when explicit IDs are given, so the doctor can show metadata such as hostname and version). Connectors that are not in `Active` status are marked `skipped` in the report without calling the reachability API.

### Step 3 — Backend reachability (parallel)

For each active connector, the doctor calls the SIA reachability API with `check_backend_endpoints=true`. This instructs the connector to probe its own backend connectivity from its side and report the results. All connectors are probed in parallel (bounded by `--concurrency-limit`).

Results are grouped under each connector's header, which shows:

```
CONNECTOR <id>
  Host: connector-host.corp.local   IP: 10.0.1.5   Type: ON-PREMISE
  OS: linux   Version: 15.2.3   Status: Active   Region: us-east-1
```

---

## Connector machine object

Each entry in `--connector-machines` uses the same shape as other machine objects (only `hostname` is required):

```json
{
  "hostname":         "connector1.example.com",
  "os_type":          "linux",
  "username":         "ec2-user",
  "private_key_path": "/home/me/id_rsa",
  "password":         "",
  "winrm_protocol":   "https"
}
```

---

## Examples

### Check all active connectors in the tenant (default)

```shell linenums="0"
idsec sia doctor check-connector
```

### Check only the local connector

```shell linenums="0"
idsec sia doctor check-connector --local
```

The doctor reads the connector ID from the config file on the machine running `idsec`.

### Check specific connector IDs

```shell linenums="0"
idsec sia doctor check-connector \
  --connector-ids '["CMSConnector_abc123","CMSConnector_def456"]'
```

### Read IDs from connector machines via SSH

```shell linenums="0"
idsec sia doctor check-connector --connector-machines '[
  {
    "hostname":         "connector1.corp.local",
    "os_type":          "linux",
    "username":         "ec2-user",
    "private_key_path": "/home/me/id_rsa"
  },
  {
    "hostname":         "connector2.corp.local",
    "os_type":          "linux",
    "username":         "ec2-user",
    "private_key_path": "/home/me/id_rsa"
  }
]'
```

### Read IDs from a Windows connector machine via WinRM

```shell linenums="0"
idsec sia doctor check-connector --connector-machines '[
  {
    "hostname":       "win-connector.corp.local",
    "os_type":        "windows",
    "username":       "domain\\svcaccount",
    "password":       "secret",
    "winrm_protocol": "https"
  }
]'
```

### Mix: explicit IDs and machines

```shell linenums="0"
idsec sia doctor check-connector \
  --connector-ids '["CMSConnector_abc123"]' \
  --connector-machines '[
    {"hostname": "connector2.corp.local", "os_type": "linux",
     "username": "ec2-user", "private_key_path": "/home/me/id_rsa"}
  ]'
```

### Increase the timeout for large tenants

```shell linenums="0"
idsec sia doctor check-connector --timeout-sec 120 --concurrency-limit 64
```

---

## Reading the output

Each connector gets its own section:

```
CONNECTOR CMSConnector_<tenant-id>_<pool-id>
  Host: connector-host   IP: 10.0.1.5   Type: ON-PREMISE
  OS: linux   Version: 15.2.3   Status: Active   Region: us-east-1
─────────────────────────────────────────────────────────────────────────────
  ✔   connector-backend   backend   connector-host:443   pass   12ms
```

| Status | Meaning |
|---|---|
| `pass` | Connector successfully reached its backend |
| `fail` | Backend unreachable — check egress firewall rules or proxy settings on the connector host |
| `skipped` | Connector is not active — shown for visibility, not a failure |

A connector showing `fail` on `connector-backend` cannot tunnel sessions. Common causes:
- Outbound port 443 blocked by a firewall
- Proxy not configured (or wrong proxy settings) on the connector host
- DNS resolution failure for the SIA control-plane FQDN

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `--local` | `false` | Check only the local connector (read ID from local config). |
| `--connector-ids` | (all tenant connectors) | Explicit connector IDs to check. |
| `--connector-machines` | (none) | Machines to SSH/WinRM into to read connector IDs. |
| `--timeout-sec` | `30` | Overall operation timeout in seconds. |
| `--concurrency-limit` | `32` | Max parallel connector checks. |
| `--batch-reachability` | `true` | Send all of a target's ports in one reachability API call instead of one call per port. |
