![Idsec CLI Golang](https://github.com/cyberark/idsec-cli-golang/blob/main/assets/cli.png)

[![Go Version](https://img.shields.io/github/go-mod/go-version/cyberark/idsec-cli-golang)](https://github.com/cyberark/idsec-cli-golang)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/cyberark/idsec-cli-golang/blob/main/LICENSE.txt)

# Idsec CLI

The official command-line interface for Idira Identity Security Platform.

For the full reference documentation, see the **[docs site](https://cyberark.github.io/idsec-cli-golang/)**.

---

## Installation

### Homebrew (macOS / Linux)

```shell
brew tap cyberark/tools
brew trust cyberark/tools
brew install idsec
```

For Go and Docker install instructions, see [Getting started](docs/getting_started.md).

---

## Quickstart

1. Configure a profile:

   ```shell
   idsec configure --silent --work-with-isp --isp-username myuser
   ```

2. Log in:

   ```shell
   idsec login --silent --isp-secret mysecret
   ```

3. Run a command:

   ```shell
   idsec sia sso short-lived-password
   ```

The `exec` subcommand may be omitted — `idsec sia …` is equivalent to `idsec exec sia …`.

---

## Commands

| Command | Description | Reference |
|---------|-------------|----------|
| `configure` | Configure profiles and authentication methods | [docs](docs/commands/configure.md) |
| `login` | Log in using the configured profile | [docs](docs/commands/login.md) |
| `status` | Show authentication status and token expiry | [docs](docs/commands/status.md) |
| `exec` | Execute service commands | [docs](docs/commands/exec.md) |
| `query` | Filter JSON output with a jq expression | [docs](docs/commands/query.md) |
| `profiles` | Manage multiple profiles | [docs](docs/commands/profiles.md) |
| `cache` | Manage CLI cache | [docs](docs/commands/cache.md) |
| `upgrade` | Upgrade the CLI to the latest version | [docs](docs/commands/upgrade.md) |
| `version` | Print CLI version and build metadata | [docs](docs/commands/version.md) |

### Available services

Run via `idsec exec <service>` or directly as `idsec <service>`:

| Service | Aliases | Description |
|---------|---------|-------------|
| `cmgr` | `connectormanager`, `cm` | Connector Manager |
| `identity` | `idaptive`, `id` | Identity |
| `pcloud` | `privilegecloud`, `pc` | Privilege Cloud |
| `policy` | `accesspolicies`, `acp` | Access Policies |
| `sca` | `accesssca`, `asca` | Secure Cloud Access |
| `sechub` | `secretshub`, `sh` | Secrets Hub |
| `sia` | `dpa` | Secure Infrastructure Access |
| `sm` | `sessionmonitoring` | Session Monitoring |
| `access` | | Access |
| `ars` | `accessrequests` | Access Request Service |

For per-service examples, see [Examples](docs/examples/commands_examples.md).

---

## Configuration

| Topic | Reference |
|-------|-----------|
| Configuration file (`~/.idsec/config.yaml`) | [docs](docs/config/config_file.md) |
| Environment variables | [docs](docs/config/environment.md) |
| Credentials file | [docs](docs/config/credentials_file.md) |
| Proxy settings | [docs](docs/config/proxy.md) |
| File logging | [docs](docs/config/logging.md) |
| Telemetry | [docs](docs/config/telemetry.md) |

Common environment variables:

| Variable | Description |
|----------|-------------|
| `IDSEC_PROFILE` | Profile name to use across the CLI |
| `IDSEC_DISABLE_CERTIFICATE_VERIFICATION` | Disable HTTPS certificate verification |
| `IDSEC_FILE_LOG_PATH` | Path to the log file |
| `IDSEC_FILE_LOG_LEVEL` | Log level for file logging (`DEBUG`, `INFO`, `off`) |
| `IDSEC_DISABLE_TELEMETRY_COLLECTION` | Disable telemetry data collection |

---

## How-to guides

Step-by-step guides for common workflows:

- [Getting started](docs/getting_started.md)
- [Working with profiles](docs/howto/working_with_profiles.md)
- [End-user SSH workflow](docs/howto/enduser_ssh_workflow.md)
- [End-user database workflow](docs/howto/enduser_databases_workflow.md)
- [End-user Kubernetes workflow](docs/howto/enduser_kubernetes_workflow.md)
- [SCA just-in-time elevation](docs/howto/sca_native_cli.md)
- [Install SIA connectors](docs/howto/install_sia_connectors.md)
- [Upgrade to the latest version](docs/howto/upgrade_to_the_latest_version.md)

---

## License

This project is licensed under the Apache License 2.0 — see [LICENSE](LICENSE.txt) for details.

Copyright (c) 2026 CyberArk Software Ltd. All rights reserved.
