---
title: Logging
description: How the Idsec CLI writes structured, redacted, rotated log files.
---

# File Logging

The CLI automatically writes log output to a file on disk, independent of stdout logging. This provides a persistent record of CLI operations for debugging and auditing.

## Default Behavior

File logging is enabled by default when using the CLI. No configuration is needed.

| Setting | Default |
| :--- | :--- |
| Log file path | `~/.idsec/logs/idsec-cli.log` |
| Log level | `INFO` |
| Max file size | 50 MB |
| Backup history | 5 rotated files |
| File permissions | `0600` (owner read/write only) |
| Directory permissions | `0700` (owner only) |

## Environment Variables

Both settings can be overridden via environment variables:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `IDSEC_FILE_LOG_PATH` | Path to the log file. | `~/.idsec/logs/idsec-cli.log` |
| `IDSEC_FILE_LOG_LEVEL` | Minimum level to write to file (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). Set to `none` or `off` to disable file logging. | `INFO` |

Example -- disable file logging:
```shell
export IDSEC_FILE_LOG_LEVEL=off
```

Example -- write DEBUG-level logs to a custom path:
```shell
export IDSEC_FILE_LOG_PATH=/var/log/idsec/cli.log
export IDSEC_FILE_LOG_LEVEL=DEBUG
idsec login --profile-name myprofile
```

These settings can also be set via the [Configuration File](config_file.md).

## Independence from Stdout

File logging and stdout logging are fully independent:

- **Stdout** is controlled by `--verbose`, `--log-level`, and `IDSEC_LOG_LEVEL`. Without `--verbose`, stdout is silent.
- **File** is controlled by `IDSEC_FILE_LOG_PATH` and `IDSEC_FILE_LOG_LEVEL`. It always writes regardless of `--verbose`.

This means you can keep stdout silent while still capturing detailed logs to the file:
```shell
# No --verbose: stdout is silent, but file still captures INFO+ logs
idsec exec pcloud safes list
cat ~/.idsec/logs/idsec-cli.log
```

## Credential Sanitization

Sensitive values are automatically redacted in file logs. Fields such as `password`, `secret`, `token`, `private_key`, `authorization`, and AWS credential fields are replaced with `[REDACTED]` before being written to disk. Stdout output is not sanitized.

## Log Rotation

When the log file exceeds 50 MB, it is rotated automatically:

```
~/.idsec/logs/idsec-cli.log      (current)
~/.idsec/logs/idsec-cli.log.1    (previous)
~/.idsec/logs/idsec-cli.log.2
~/.idsec/logs/idsec-cli.log.3
~/.idsec/logs/idsec-cli.log.4
~/.idsec/logs/idsec-cli.log.5    (oldest, removed on next rotation)
```
