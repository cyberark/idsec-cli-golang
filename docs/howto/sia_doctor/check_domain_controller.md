---
title: SIA Doctor — check-domain-controller
description: Verify connector-to-DC reachability on Kerberos/LDAP/LDAPS/RDP ports and validate LDAPS and RDP TLS certificates against tenant-uploaded certificates
---

# SIA Doctor — `check-domain-controller`

`idsec sia doctor check-domain-controller` verifies that SIA connectors can reach domain controllers on the ports required for Windows ZSP-domain-ephemeral flows (Kerberos, LDAP, LDAPS, kpasswd, RDP). In parallel, it probes the LDAPS and RDP server certificates directly and validates them against your **tenant-uploaded certificates**.

Use this command to diagnose issues with Windows domain-joined target access where SIA connectors need to authenticate users through Active Directory.

---

## How it works

The command follows the same two-phase pattern as `check-target`.

### Phase 1 — DC address resolution (when credentials are provided)

When a DC entry includes credentials, the doctor opens a WinRM (or SSH) connection to the DC **before** firing any reachability probes:

- Resolves the DC's private IPs and FQDN (`Get-NetIPAddress`, `[System.Net.Dns]::GetHostEntry`).
- These resolved addresses replace the given `hostname` for all connector→DC reachability checks.

A `resolved-dc` row appears in the report showing which addresses were found. If the connection fails, the doctor falls back to the given `hostname` and adds a notice.

When no credentials are provided, checks run against the given `hostname` directly.

### Phase 2 — Reachability and certificate probing (concurrent)

Both sub-phases run in parallel under the `--timeout-sec` deadline.

#### Connector→DC reachability

The doctor calls the SIA reachability API for every (connector, DC address, port) combination in parallel. The same preferred-connector / unroutable-connector optimisations as `check-target` apply.

**Fixed ports checked per DC:**

| Protocol | Port | Purpose |
|---|---|---|
| ldap | 389 | LDAP bind (clear-text / SASL) |
| ldaps | 636 | LDAP over TLS |
| kerberos | 88 | Kerberos ticket exchange |
| kpasswd | 464 | Kerberos password change |
| rdp | 3389 | RDP — DCs are Windows hosts |

#### TLS certificate probing

Concurrently, the doctor dials the DC from the SDK host and performs a TLS handshake on:

- **LDAPS (port 636)** — direct TLS
- **RDP (port 3389)** — X.224 connection request negotiation, then TLS

The extracted server certificates are validated against the tenant certificate pool. Because DC certificates are typically issued by an internal enterprise CA, it is common to need to upload that CA's root certificate to SIA.

If the DC's FQDN was resolved in Phase 1, the probe first tests the original `hostname` (which the DC's TLS certificate is issued for) and propagates the `trusted` / `untrusted` verdict to the resolved private addresses.

---

## DC object

Each entry in `--domain-controllers` uses this JSON shape. Only `hostname` is required:

```json
{
  "hostname":       "dc01.corp.local",
  "os_type":        "windows",
  "username":       "corp\\admin",
  "password":       "secret",
  "winrm_protocol": "https"
}
```

| Field | Description |
|---|---|
| `hostname` | FQDN or IP of the domain controller. Required. |
| `os_type` | Should be `windows` for DCs. Enables WinRM-based address resolution. |
| `username` | WinRM username (domain or local). Enables address resolution. |
| `password` | WinRM password. |
| `private_key_path` | SSH private key (if the DC is reachable over SSH — uncommon). |
| `winrm_protocol` | `http` or `https` (default `https`). |

> Kerberos/LDAP/LDAPS/kpasswd ports are not overridable in DC mode — standard ports are always used.

---

## Examples

### Minimal — local machine as DC (no arguments)

```shell linenums="0"
idsec sia doctor check-domain-controller
```

### One or more explicit DCs by hostname

```shell linenums="0"
idsec sia doctor check-domain-controller --domain-controllers '[
  {"hostname": "dc01.corp.local"},
  {"hostname": "dc02.corp.local"}
]'
```

### DC with WinRM credentials (enables private-address resolution)

```shell linenums="0"
idsec sia doctor check-domain-controller --domain-controllers '[
  {
    "hostname":       "dc01.corp.local",
    "os_type":        "windows",
    "username":       "corp\\admin",
    "password":       "secret",
    "winrm_protocol": "https"
  }
]'
```

The doctor connects over WinRM, resolves the DC's private IPs and FQDN, and then runs connector→DC reachability against those private addresses.

### Multiple DCs

```shell linenums="0"
idsec sia doctor check-domain-controller --domain-controllers '[
  {
    "hostname": "dc01.corp.local",
    "os_type":  "windows",
    "username": "corp\\admin",
    "password": "secret"
  },
  {
    "hostname": "dc02.corp.local",
    "os_type":  "windows",
    "username": "corp\\admin",
    "password": "secret"
  }
]'
```

### Restrict to specific connectors

```shell linenums="0"
idsec sia doctor check-domain-controller \
  --domain-controllers '[{"hostname": "dc01.corp.local"}]' \
  --connector-ids '["CMSConnector_abc123"]'
```

### Disable TLS certificate validation

```shell linenums="0"
idsec sia doctor check-domain-controller \
  --domain-controllers '[{"hostname": "dc01.corp.local"}]' \
  --disable-certificate-check
```

### Increase timeout for large environments

```shell linenums="0"
idsec sia doctor check-domain-controller \
  --domain-controllers '[{"hostname": "dc01.corp.local"}]' \
  --timeout-sec 120 \
  --concurrency-limit 64
```

---

## Reading the output

| Status | Meaning |
|---|---|
| `pass` | Connector can reach the DC on this port |
| `fail` | No connector could reach the DC — check network/firewall between connector and DC |
| `skipped` | Credentials not provided (address resolution skipped) |

| Cert status | Meaning |
|---|---|
| `trusted` | LDAPS or RDP certificate chains to a tenant-uploaded certificate |
| `untrusted` | Certificate not trusted — upload the enterprise CA root |
| `unverified` | Could not probe cert (port unreachable or tenant cert list unavailable) |

A `fail` on `ldap`/`ldaps`/`kerberos` means connectors cannot perform Active Directory lookups, which will break all ZSP-domain-ephemeral Windows flows (RDP, MSSQL, DB2). A `fail` on `rdp` only affects direct RDP connectivity from the connector.

An `untrusted` LDAPS cert means the connector will reject the DC's certificate during TLS negotiation. Add the issuing CA:

```shell linenums="0"
idsec sia certificates create \
  --cert-name "corp-root-ca" \
  --cert-type PEM \
  --file /path/to/corp-root-ca.crt
```

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `--domain-controllers` | (local hostname) | JSON array of DC objects. |
| `--connector-ids` | (all) | Restrict which connectors perform reachability checks. |
| `--disable-certificate-check` | `false` | Skip LDAPS and RDP TLS certificate validation. |
| `--timeout-sec` | `30` | Overall operation timeout in seconds. |
| `--concurrency-limit` | `32` | Max parallel reachability checks. |
