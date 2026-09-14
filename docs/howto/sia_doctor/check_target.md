---
title: SIA Doctor — check-target
description: Verify connector-to-target reachability across every SIA access flow and validate target TLS certificates against tenant-uploaded certificates
---

# SIA Doctor — `check-target`

`idsec sia doctor check-target` asks every SIA connector (or a specific subset) to test network reachability to one or more target machines across **all supported protocols and access flows**. In parallel, it probes each TLS-capable protocol's server certificate directly and validates the certificate chain against your **tenant-uploaded certificates**.

Use this command when users cannot reach a target through SIA — it pinpoints which connector, protocol, or flow has a routing or certificate issue.

---

## How it works

The command runs three phases in parallel under a shared deadline.

### Phase 1 — Target inspection (per target with credentials)

When a target entry includes credentials, the doctor opens one direct management connection to that machine before firing any reachability checks:

- **Linux / macOS (SSH):** runs `hostname -f` and `ip addr` / `ifconfig` to collect the target's private FQDN and IP addresses.
- **Windows (WinRM):** runs `Get-NetIPAddress` and `[System.Net.Dns]::GetHostEntry` to collect the same.

The resolved private IPs and FQDN replace the given `hostname` for all subsequent connector→target reachability probes. A `resolved-target` row in the report shows which addresses were found. This matters because **SIA connectors route to private addresses**, not to the public hostname you might have used in the target definition.

If the connection fails (wrong credentials, unreachable machine) the doctor falls back to the original `hostname` and adds a notice row.

### Phase 2 — Reachability probing (parallel across connectors and ports)

For each resolved address the doctor calls the SIA **reachability API** — one call per (connector, host, port) combination, all fired in parallel (bounded by `--concurrency-limit`):

- The first connector that successfully reaches the host is remembered as the **preferred connector** for that host. Remaining ports for the same host are tried through that connector first, which speeds up multi-port targets considerably.
- If a connector cannot route to a host at all (DNS failure, no route, network timeout) it is marked **unroutable** for that host and its remaining ports are skipped rather than timed-out individually.

**Flows and extra ports checked per protocol:**

| Protocol | Default port | Flow(s) checked |
|---|---|---|
| rdp | 3389 | `vaulted`, `zsp-local-ephemeral`, `zsp-domain-ephemeral`, `jit-elevation` |
| ssh | 22 | `vaulted`, `zsp-ssh-certs` |
| mysql | 3306 | `vaulted` |
| mariadb | 3306 | `vaulted` |
| postgres | 5432 | `vaulted` |
| mssql | 1433 | `vaulted`, `zsp-domain-ephemeral` |
| oracle | 2484 | `vaulted` |
| db2 | 50002 | `vaulted`, `zsp-domain-ephemeral` |
| mongo | 27017 | `vaulted` |
| k8s | 443 | `vaulted` |

**Additional ports for Windows targets** (when credentials are provided and the OS type is `windows`):

| Protocol | Port | Flow |
|---|---|---|
| rpc | 135 | `zsp-local-ephemeral` |
| smb | 445 | `zsp-local-ephemeral` |
| winrm-http | 5985 | `zsp-domain-ephemeral` |
| winrm-https | 5986 | `zsp-domain-ephemeral` |

When credentials are provided and the OS is Linux/macOS, the doctor also runs the **SSH CA key check** (`zsp-ssh-certs` flow), which verifies the SIA SSH CA is trusted on the target.

### Phase 3 — TLS certificate probing (parallel with Phase 2)

Concurrently with the reachability phase, the doctor dials each TLS-capable protocol **directly from the SDK host to the target**. It uses protocol-appropriate TLS negotiation:

| Protocol | TLS mechanism |
|---|---|
| rdp | X.224 connection request → negotiate TLS |
| postgres | STARTTLS via SSLRequest |
| mysql | STARTTLS via CapabilityFlags |
| mssql | TDS pre-login negotiation |
| oracle, mongo, k8s, db2, winrm-https | Direct TLS |

The server's certificate chain is extracted even in mTLS scenarios where the server requires a client certificate (the handshake is captured before it fails). The chain is then validated against the **tenant certificate pool** — the certificates uploaded to your SIA tenant via `idsec sia certificates create`. If the chain does not verify, the protocol row carries a `⚠ untrusted` warning.

For targets where FQDN was resolved (Phase 1), the cert probe first attempts the original `hostname` (which the SIA TLS cert is typically issued for) and, if that validates, propagates the `trusted` result to all resolved private IPs too.

---

## Target object

Each entry in `--targets` uses this JSON shape. Only `hostname` is required:

```json
{
  "hostname":            "db.example.com",
  "os_type":             "linux",
  "username":            "ec2-user",
  "private_key_path":    "/home/me/id_rsa",
  "private_key_contents":"",
  "password":            "",
  "winrm_protocol":      "https",
  "rdp_port":            3389,
  "ssh_port":            22,
  "mysql_port":          3306,
  "mariadb_port":        3306,
  "postgresql_port":     5432,
  "mssql_port":          1433,
  "oracle_port":         2484,
  "db2_port":            50002,
  "mongodb_port":        27017,
  "k8s_port":            443,
  "winrm_http_port":     5985,
  "winrm_https_port":    5986
}
```

| Field | Description |
|---|---|
| `hostname` | FQDN or IP. Required. |
| `os_type` | `linux`, `darwin`, or `windows`. Enables OS-specific checks (SSH CA, nltest, extra Windows ports). |
| `username` / `password` | Credentials for direct connection. Enables address resolution. |
| `private_key_path` | SSH private key path (Linux/macOS). |
| `private_key_contents` | SSH private key PEM inline. |
| `winrm_protocol` | `http` or `https` for Windows targets (default `https`). |
| `<proto>_port` | Port override for that protocol (rarely needed; defaults to standard ports). |

---

## Examples

### Minimal — local machine as single target

```shell linenums="0"
idsec sia doctor check-target
```

### Explicit target hostnames

```shell linenums="0"
idsec sia doctor check-target --targets '[
  {"hostname": "db.example.com"},
  {"hostname": "app.example.com"}
]'
```

### Linux target with SSH credentials (enables address resolution and SSH CA check)

```shell linenums="0"
idsec sia doctor check-target --targets '[
  {
    "hostname":         "10.0.0.20",
    "os_type":          "linux",
    "username":         "ec2-user",
    "private_key_path": "/home/me/id_rsa"
  }
]'
```

### Windows target with WinRM (enables address resolution and ZSP-domain port checks)

```shell linenums="0"
idsec sia doctor check-target --targets '[
  {
    "hostname":       "win-server.corp.local",
    "os_type":        "windows",
    "username":       "admin",
    "password":       "secret",
    "winrm_protocol": "https"
  }
]'
```

### Multiple targets, filter to specific protocols

```shell linenums="0"
idsec sia doctor check-target \
  --targets '[
    {"hostname": "db.example.com"},
    {"hostname": "rdp-host.corp.local", "os_type": "windows"}
  ]' \
  --protocols '["rdp","mssql","postgres"]'
```

### Use specific connectors only

```shell linenums="0"
idsec sia doctor check-target \
  --targets '[{"hostname": "db.example.com"}]' \
  --connector-ids '["conn-abc123","conn-def456"]'
```

### Include N/A results (protocols not running on the target)

```shell linenums="0"
idsec sia doctor check-target \
  --targets '[{"hostname": "db.example.com"}]' \
  --show-all
```

N/A means the base port for that protocol was unreachable — the protocol simply is not running on the target. These rows are hidden by default to keep the report clean.

### Increase timeout for large environments

```shell linenums="0"
idsec sia doctor check-target \
  --targets '[{"hostname": "db.example.com"}]' \
  --timeout-sec 120 \
  --concurrency-limit 64
```

### Disable TLS certificate validation

```shell linenums="0"
idsec sia doctor check-target \
  --targets '[{"hostname": "db.example.com"}]' \
  --disable-certificate-check
```

---

## Reading the output

| Status | Meaning |
|---|---|
| `pass` | Connector can reach the target on this port/protocol |
| `fail` | No connector could reach the target |
| `n/a` | Protocol not running on target (hidden by default) |
| `skipped` | Check requires credentials that were not provided |

| Cert status | Meaning |
|---|---|
| `trusted` | Server certificate chains to a tenant-uploaded certificate |
| `untrusted` | Certificate does not chain to any tenant certificate — add the root CA |
| `unverified` | Could not determine trust (tenant cert list unavailable) |

When cert status is `untrusted`, add the missing CA certificate with:

```shell linenums="0"
idsec sia certificates create --cert-name "my-root-ca" --cert-type PEM --file /path/to/ca.crt
```

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `--targets` | (local hostname) | JSON array of target objects. |
| `--protocols` | (all) | Protocols to check: `rdp\|ssh\|mysql\|mariadb\|postgres\|mssql\|oracle\|db2\|mongo\|k8s`. |
| `--connector-ids` | (all) | Restrict which connectors perform reachability checks. |
| `--show-all` | `false` | Include N/A results in output. |
| `--timeout-sec` | `30` | Overall operation timeout in seconds. |
| `--concurrency-limit` | `32` | Max parallel connector checks. |
| `--disable-certificate-check` | `false` | Skip TLS certificate validation against tenant certificates. |
| `--batch-reachability` | `true` | Send all of a host's ports in one reachability API call instead of one call per port. |
