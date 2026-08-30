---
title: SIA Doctor — check (unified)
description: Run all four doctor modes in a single pass and get one merged health report for your entire SIA deployment
---

# SIA Doctor — `check` (unified)

`idsec sia doctor check` runs all four doctor modes — **client**, **connector**, **target**, and **domain-controller** — in a single command and returns one merged report banded by mode. This is the fastest way to get a full picture of your SIA deployment health in one pass.

---

## How mode selection works

By default, `check` uses **auto-detect** mode selection:

| Mode | Runs when |
|---|---|
| `client` | Always (checks the local machine by default, or `--clients` if provided) |
| `connector` | Always (checks all tenant connectors by default) |
| `target` | Only when `--targets` is provided |
| `domain-controller` | Only when `--domain-controllers` is provided |

You can override this with `--modes` to run an explicit subset regardless of which inputs are given.

---

## How it works

### Concurrent execution

Each enabled mode runs as an independent goroutine with its own internal deadline derived from `--timeout-sec`. The modes do not share state or wait for each other — `client` and `connector` always start immediately; `target` and `domain-controller` start when their inputs are present.

### Partial failure handling

A failure in one mode (for example, no connectors are found in the tenant, or a connection to a remote client times out) does not abort the other modes. The failed mode is recorded as a synthetic `fail` row in the merged report with the error message, and all other modes continue to completion.

### Merged report

Results from all modes are assembled into a single report, banded in a consistent order regardless of goroutine completion order:

```
1. client
2. connector
3. target
4. domain-controller
```

The summary at the bottom aggregates counts across all modes.

---

## How each mode behaves inside `check`

The four modes run exactly as their standalone counterparts — the `check` command simply fans out their respective request objects from the unified input:

| Mode | Standalone command | What it checks |
|---|---|---|
| `client` | `check-client` | Local (or remote) machine → SIA gateway / relay reachability and OS-trusted TLS certs |
| `connector` | `check-connector` | Each connector → SIA backend reachability |
| `target` | `check-target` | Each connector → target reachability across all flows/protocols + tenant-trusted TLS certs |
| `domain-controller` | `check-domain-controller` | Each connector → DC reachability (Kerberos/LDAP/LDAPS/RDP) + LDAPS/RDP TLS certs |

See the individual howto pages for a full description of how each mode resolves addresses, probes certificates, and optimises reachability calls.

---

## Shared inputs

The following inputs are forwarded to every mode that consumes them, keeping all modes consistently configured:

| Input | Used by |
|---|---|
| `--protocols` | `client`, `target` |
| `--connector-ids` | `target`, `domain-controller`, `connector` (explicit ID filter) |
| `--concurrency-limit` | All modes |
| `--timeout-sec` | `target`, `domain-controller`, `connector` |
| `--disable-certificate-check` | All modes |

---

## Examples

### No arguments — local client + all tenant connectors

```shell linenums="0"
idsec sia doctor check
```

Runs `client` (local machine gateway reachability) and `connector` (all tenant connectors backend check).

### Add targets and DCs (enables those modes automatically)

```shell linenums="0"
idsec sia doctor check \
  --targets '[{"hostname": "db.example.com"}]' \
  --domain-controllers '[{"hostname": "dc01.corp.local"}]'
```

All four modes run. The report is banded: client → connector → target → domain-controller.

### Run specific modes only

```shell linenums="0"
idsec sia doctor check --modes '["client","connector"]'
```

Accepted values: `client`, `target`, `connector`, `domain-controller` (`dc` is an accepted alias).

### Remote client machine instead of local

```shell linenums="0"
idsec sia doctor check --clients '[
  {
    "hostname":         "client1.example.com",
    "os_type":          "linux",
    "username":         "ec2-user",
    "private_key_path": "/home/me/id_rsa"
  }
]'
```

### Filter to specific protocols across all modes

```shell linenums="0"
idsec sia doctor check \
  --targets '[{"hostname": "db.example.com"}]' \
  --protocols '["rdp","mssql","postgres"]'
```

### Check only the local connector (instead of all tenant connectors)

```shell linenums="0"
idsec sia doctor check --local-connector
```

### Full sweep — all four modes with credentials

```shell linenums="0"
idsec sia doctor check \
  --clients '[
    {
      "hostname":         "client1.example.com",
      "os_type":          "linux",
      "username":         "ec2-user",
      "private_key_path": "/home/me/id_rsa"
    }
  ]' \
  --targets '[
    {"hostname": "db.example.com"},
    {
      "hostname":       "win-server.corp.local",
      "os_type":        "windows",
      "username":       "admin",
      "password":       "secret",
      "winrm_protocol": "https"
    }
  ]' \
  --domain-controllers '[
    {
      "hostname":       "dc01.corp.local",
      "os_type":        "windows",
      "username":       "corp\\admin",
      "password":       "secret",
      "winrm_protocol": "https"
    }
  ]' \
  --timeout-sec 180 \
  --concurrency-limit 64
```

### Using a JSON input file

All flags accept JSON arrays. For complex inputs, save to a file and pass it inline:

```shell linenums="0"
idsec sia doctor check \
  --targets "$(cat targets.json)" \
  --domain-controllers "$(cat dcs.json)"
```

---

## Reading the output

The report is banded by mode with a summary per mode and an overall summary at the end:

```
═══════════════════════════════════════════════════════════════════════════
  SIA Doctor Report — CHECK  (12.4s)
═══════════════════════════════════════════════════════════════════════════

  CLIENT
  ──────────────────────────────────────────────────────────────────────────
  ✔  rdp  gw  sia-gw.example.com:443   pass   8ms   🔒 trusted
  ✔  ssh  gw  sia-gw.example.com:443   pass   7ms   🔒 trusted
  ...

  CONNECTOR CMSConnector_<id>
  ──────────────────────────────────────────────────────────────────────────
  ✔  connector-backend   backend   connector-host:443   pass   12ms
  ...

  TARGET db.example.com
  ──────────────────────────────────────────────────────────────────────────
  ✔  mysql  vaulted   db.example.com:3306   pass   15ms   🔒 trusted
  ...

  DOMAIN CONTROLLER dc01.corp.local
  ──────────────────────────────────────────────────────────────────────────
  ✔  ldap     dc  dc01.corp.local:389   pass   9ms
  ✔  ldaps    dc  dc01.corp.local:636   pass   11ms  🔒 trusted
  ...

═══════════════════════════════════════════════════════════════════════════
  Summary  ✔ 24 passed  ✗ 0 failed  ⚠ 1 warning  — 0 n/a  ○ 0 skipped
═══════════════════════════════════════════════════════════════════════════
```

The duration shown in the header is the overall wall-clock time for the entire multi-mode run.

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `--modes` | (auto) | Explicit list of modes to run: `client\|target\|connector\|domain-controller`. |
| `--clients` | (local machine) | Client machine objects for client mode. |
| `--targets` | (none) | Target machine objects — enables target mode. |
| `--domain-controllers` | (none) | DC objects — enables domain-controller mode. |
| `--connector-ids` | (all) | Connector filter shared across modes. |
| `--local-connector` | `false` | Connector mode: check only the local connector. |
| `--protocols` | (all) | Protocol filter for client and target modes. |
| `--show-all` | `false` | Include N/A results from target mode. |
| `--connect-timeout` | `5` | TCP dial timeout for client mode (seconds). |
| `--timeout-sec` | (per-mode default) | Per-mode operation timeout in seconds. |
| `--concurrency-limit` | `32` | Max parallel checks within each mode. |
| `--disable-certificate-check` | `false` | Disable TLS certificate validation across all modes. |
| `--batch-reachability` | `false` | Experimental: batch all ports per host in one API call. |
