---
title: SIA Doctor
description: Overview of the idsec sia doctor commands for diagnosing SIA connectivity, reachability, and TLS certificate trust
---

# SIA Doctor

The `idsec sia doctor` commands run end-to-end health checks across your SIA deployment. They test network reachability, TLS certificate trust, and connector backend health — covering every perspective in the SIA data path.

| Command | Howto | What it checks |
|---|---|---|
| `idsec sia doctor check-client` | [check-client](check_client.md) | Client → SIA gateway / relay reachability; TLS certs against OS trust store |
| `idsec sia doctor check-target` | [check-target](check_target.md) | Connector → target reachability across all flows; TLS certs against tenant certificates |
| `idsec sia doctor check-connector` | [check-connector](check_connector.md) | Connector → SIA backend reachability |
| `idsec sia doctor check-domain-controller` | [check-domain-controller](check_domain_controller.md) | Connector → DC reachability (Kerberos/LDAP/LDAPS/RDP); LDAPS and RDP TLS certs |
| `idsec sia doctor check` | [check](check.md) | All of the above in one pass with a merged report |

---

## The machine object

All commands that accept machine lists (`--targets`, `--clients`, `--domain-controllers`, `--connector-machines`) share the same JSON entry shape:

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

Only `hostname` is required. Port overrides (`rdp_port`, `ssh_port`, …) default to the standard port for each protocol and rarely need to be set.

**Credentials** (`username` + `password` or `private_key_path`, plus `os_type`) are optional. When provided, the doctor opens a direct management connection (SSH for Linux/macOS, WinRM for Windows) to resolve the machine's private IPs and FQDN before running reachability checks — ensuring that connector probes run against the addresses connectors actually route to, rather than the hostname you typed. When omitted, any step requiring a direct connection is reported as `skipped` and reachability runs against the given `hostname`.

---

## Reading the report

Each row represents one check (a protocol × flow × host combination):

| Field | Values |
|---|---|
| **Status** | `pass` · `fail` · `n/a` (protocol not on target, hidden by default) · `skipped` (credentials not provided) |
| **Cert status** | `trusted` · `untrusted` · `unverified` — only on TLS-capable protocols |
| **Warning** | Non-fatal advisory, e.g. untrusted certificate |
| **Checked from** | `local` for client-mode; `connector:<id>` for API-based checks |

The report footer shows the overall duration and a pass/fail/warning/n/a/skipped summary.

---

## TLS certificate validation

### Client mode — OS trust store

SIA proxies (gateways and relays) use publicly-trusted certificates (e.g. Let's Encrypt). The doctor validates these against the **host OS trust store**. An `untrusted` result on a proxy indicates a misconfiguration or unexpected certificate.

### Target and DC modes — tenant trust store

For target and domain-controller mode, TLS certificates on the **target itself** (database, RDP host, LDAPS, etc.) are validated against the certificates you have uploaded to your SIA tenant. An `untrusted` result means the target's CA root is not in the SIA trust store. Add it with:

```shell linenums="0"
idsec sia certificates create \
  --cert-name "my-root-ca" \
  --cert-type PEM \
  --file /path/to/ca.crt
```
