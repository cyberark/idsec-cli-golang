---
title: SIA Doctor — check-client
description: Verify that client machines can reach SIA gateways and relays, and validate SIA proxy TLS certificates against the OS trust store
---

# SIA Doctor — `check-client`

`idsec sia doctor check-client` verifies that a machine can reach every SIA gateway endpoint and every active HTTPS relay on its required port. For each reachable proxy it also performs a TLS handshake and validates the server certificate against the **host OS trust store** (SIA proxies use publicly-trusted certificates such as Let's Encrypt).

Run it from any machine that should have SIA access to confirm the network path is open end-to-end before troubleshooting access policies.

---

## How it works

### 1 — Endpoint discovery

The doctor derives the SIA gateway endpoints from your tenant JWT. Each protocol has a dedicated gateway host and port:

| Protocol | Gateway port |
|---|---|
| ssh | 443 |
| rdp | 443 |
| mysql / mariadb | 3399 |
| postgres | 5433 |
| mssql | 1434 |
| oracle | 2483 |
| db2 | 50001 |
| mongo | 27117 |
| k8s / webaccess | 443 |

In addition it lists every **active HTTPS relay** from the SIA API and tests each relay URL on port 443.

### 2 — Reachability probing

#### Local machine (default)

When no `--clients` flag is given, the doctor dials each endpoint directly from the machine running `idsec` using `net.DialTimeout`. All endpoints are probed **in parallel**.

#### Remote client machines

When `--clients` is provided, the doctor establishes one management connection to each remote client (SSH for Linux/macOS, WinRM for Windows) and runs a remote connectivity test (`/dev/tcp` bash construct or `Test-NetConnection` PowerShell) **from that machine's network perspective**. Multiple clients run in parallel; within each SSH client the endpoints are fanned out in parallel too (bounded by an internal concurrency limit). WinRM clients run endpoint checks sequentially because WinRM's connection-oriented authentication prevents concurrent commands over a single session.

### 3 — TLS certificate validation

After reachability, the doctor dials each reachable proxy endpoint from the **local SDK machine**, performs a full TLS handshake (including mTLS scenarios where the server requires a client certificate — the server's certificate is captured even if the handshake ultimately fails), and validates the certificate chain against the host OS trust store.

> **Important:** When `--clients` is provided, TLS certificate probing is automatically skipped. The reason is that reachability is measured from the remote client's perspective while TLS probing would run from the local machine — mixing those two perspectives produces misleading results. To check proxy TLS trust from a remote machine, run `check-client` on that machine directly.

---

## Client machine object

Each entry in `--clients` uses this JSON shape (only `hostname` is required):

```json
{
  "hostname":         "client1.example.com",
  "os_type":          "linux",
  "username":         "ec2-user",
  "private_key_path": "/home/me/id_rsa",
  "password":         "",
  "winrm_protocol":   "https"
}
```

| Field | Description |
|---|---|
| `hostname` | FQDN or IP of the client machine. Required. |
| `os_type` | `linux`, `darwin`, or `windows`. Required for remote connections. |
| `username` | SSH or WinRM username. |
| `private_key_path` | Path to SSH private key (Linux/macOS). |
| `private_key_contents` | SSH private key PEM inline (alternative to `private_key_path`). |
| `password` | Password (Windows WinRM or SSH password auth). |
| `winrm_protocol` | `http` or `https` (Windows only, default `https`). |

---

## Examples

### Check the local machine (no arguments)

```shell linenums="0"
idsec sia doctor check-client
```

### Filter to specific protocols

```shell linenums="0"
idsec sia doctor check-client --protocols '["rdp","ssh","mysql"]'
```

Accepted protocol values: `ssh`, `rdp`, `mysql`, `mariadb`, `postgres`, `mssql`, `oracle`, `db2`, `mongo`, `k8s`, `webaccess`, `relay`.

### Check from a remote Linux client (SSH key)

```shell linenums="0"
idsec sia doctor check-client --clients '[
  {
    "hostname": "client1.example.com",
    "os_type":  "linux",
    "username": "ec2-user",
    "private_key_path": "/home/me/id_rsa"
  }
]'
```

### Check from multiple remote clients simultaneously

```shell linenums="0"
idsec sia doctor check-client --clients '[
  {
    "hostname": "client-linux.example.com",
    "os_type":  "linux",
    "username": "ec2-user",
    "private_key_path": "/home/me/id_rsa"
  },
  {
    "hostname": "client-win.corp.local",
    "os_type":  "windows",
    "username": "domain\\user",
    "password": "secret",
    "winrm_protocol": "https"
  }
]'
```

### Increase the dial timeout

```shell linenums="0"
idsec sia doctor check-client --connect-timeout 10
```

### Disable TLS certificate validation

```shell linenums="0"
idsec sia doctor check-client --disable-certificate-check
```

---

## Reading the output

Each row represents one SIA gateway or relay endpoint:

| Field | Values |
|---|---|
| Status | `pass` — endpoint reachable; `fail` — connection refused or timed out |
| Cert status | `trusted` — cert chains to an OS-trusted root; `untrusted` — cert not trusted; `unverified` — could not probe |
| Warning | Set when cert status is `untrusted` |
| Checked from | `local` for local checks; `client:<hostname>` for remote checks |

If every gateway for a protocol is reachable and TLS-trusted the deployment is healthy for that protocol. A `fail` on all gateways for a protocol means the client machine cannot route to SIA for that access method.

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `--clients` | (empty) | JSON array of client machine objects. Empty = local machine. |
| `--protocols` | (all) | Protocol filter. |
| `--connect-timeout` | `5` | TCP dial timeout in seconds. |
| `--disable-certificate-check` | `false` | Skip TLS certificate validation against the OS trust store. |
