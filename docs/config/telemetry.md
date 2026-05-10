---
title: Telemetry
description: Information about telemetry data collection in the Idsec CLI.
---

# Telemetry

The Idsec CLI collects telemetry data to help improve the product and user experience. This data includes information about command usage, errors, and performance metrics.

## Telemetry Data Collected

The following telemetry data is collected by the Idsec CLI and is sent on every API call via additional header `X-Cybr-Telemetry`:
- Environment information (e.g., Cloud Console, Region)
- Metadata about the executed command (e.g., command name, parameters)
- OS information (e.g., OS type, version)
- Tool being used (CLI)

CLI Specific telemetry 
  
| Code | Name | Description | Example |
| :--- | :--- | :--- | :--- |
| **cls** | CLI Service | The top-level service being accessed (e.g., pcloud). | `pcloud` |
| **clo** | Operation | The leaf command or action being performed. | `create` |
| **clv** | CLI Version | The specific version of the CLI tool. | `1.5.2` |
| **clr** | Resource Path | The path between service and operation, joined by hyphens. | `safes`, `accounts-members` |
## Disabling Telemetry

Telemetry collection can be disabled by setting the `IDSEC_DISABLE_TELEMETRY_COLLECTION` environment variable to `true`. This can be done in the terminal before running Idsec commands:

```shell
export IDSEC_DISABLE_TELEMETRY_COLLECTION=true
```

Alternatively, telemetry can be disabled by using the `--disable-telemetry` flag when executing Idsec commands:

```shell
idsec exec --disable-telemetry
```

When telemetry is disabled, only application metadata is collected.
