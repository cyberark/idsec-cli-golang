---
title: Configuration File
description: Use a YAML configuration file to set default values for Idsec CLI environment variables.
---

# Configuration File

The CLI supports an optional YAML configuration file that sets default values for environment variables. This is useful for persisting settings across sessions without exporting environment variables in your shell profile.

## File Location

The default configuration file path is `~/.idsec/config.yaml`. You can override this with:

1. The `--config` flag (highest priority)
2. The `IDSEC_CONFIG_FILE` environment variable
3. The default path `~/.idsec/config.yaml`

```shell
# Use a custom config file for a single command
idsec --config /path/to/my-config.yaml login

# Or set the env var once in your shell profile
export IDSEC_CONFIG_FILE=/path/to/my-config.yaml
```

A missing file is silently ignored. Parse errors and unrecognized keys produce warnings but do not fail the command.

## File Format

Keys are the full `IDSEC_*` environment variable names. Any key that does not start with `IDSEC_` is ignored with a warning.

```yaml
# ~/.idsec/config.yaml

# Logging
IDSEC_FILE_LOG_PATH: /var/log/idsec/cli.log
IDSEC_FILE_LOG_LEVEL: DEBUG
IDSEC_LOG_LEVEL: INFO

# Profile
IDSEC_PROFILE: myprofile
IDSEC_PROFILES_FOLDER: /custom/profiles

# Security
IDSEC_DISABLE_CERTIFICATE_VERIFICATION: true
IDSEC_EXTRA_TRUSTED_CA_CERTS_BUNDLE_PATH: /path/to/ca-bundle.pem

# Proxy
IDSEC_PROXY_ADDRESS: http://proxy.corp:8080
IDSEC_PROXY_USERNAME: user
IDSEC_PROXY_PASSWORD: secret

# Keyring
IDSEC_BASIC_KEYRING: true
IDSEC_KEYRING_FOLDER: /custom/keyring

# Telemetry
IDSEC_DISABLE_TELEMETRY_COLLECTION: true

# Upgrade
IDSEC_SUPPRESS_UPGRADE_CHECK: true
```

## Precedence

Settings are resolved in the following order (highest priority first):

| Priority | Source | Example |
| :--- | :--- | :--- |
| 1 | CLI flags | `--verbose`, `--log-level DEBUG` |
| 2 | Environment variables | `export IDSEC_FILE_LOG_LEVEL=DEBUG` |
| 3 | Configuration file | `IDSEC_FILE_LOG_LEVEL: DEBUG` in `config.yaml` |
| 4 | Built-in defaults | `INFO` for file log level |

This means environment variables always override the config file, and CLI flags always override both.

## Accepted Keys

Two kinds of keys are accepted:

1. **Any key starting with `IDSEC_`** — exported as the matching environment variable. There is no fixed whitelist; every current and future `IDSEC_*` variable consumed by the CLI or SDK can be set from the file.
2. **Standard proxy variables** — `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` and their lowercase forms (`http_proxy`, `https_proxy`, `no_proxy`). These are honored directly by Go's `net/http` package.

Any other key is ignored with a warning.

For a list of `IDSEC_*` variables actually read by the CLI and SDK, see [Environment](environment.md) or run `idsec --help`. Common examples:

```yaml
IDSEC_PROFILE: myprofile
IDSEC_FILE_LOG_LEVEL: DEBUG
IDSEC_PROXY_ADDRESS: http://proxy.corp:8080
IDSEC_DISABLE_TELEMETRY_COLLECTION: true

HTTPS_PROXY: http://proxy.corp:8080
NO_PROXY: localhost,127.0.0.1
```

## Security Note

If your configuration file contains sensitive values (e.g., `IDSEC_PROXY_PASSWORD`), ensure the file has restrictive permissions:

```shell
chmod 600 ~/.idsec/config.yaml
```
