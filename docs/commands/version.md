---
title: Version
description: Version Command
---

# Version

Use the `version` command to print the Idsec CLI version and build metadata embedded into the binary at build time.

## Running
```shell linenums="0"
idsec version
```

The default output prints a multi-line block of build metadata, for example:
```text linenums="0"
Idsec v0.3.1
Build Number: 3
Build Date: 2026-05-20T13:31:52Z
Git Commit: 8e682dc6b01ac408b1e66f0162809bd877a496cc
Git Branch: main
```

When the running binary is older than the latest published GitHub release, a yellow upgrade hint is appended below the metadata block, matching the wording used by the other CLI commands that run the same check, e.g.:
```text linenums="0"
A newer version of idsec is available. Run `idsec upgrade` to upgrade to version 0.4.0.
```
The hint is best-effort: the GitHub release check is bounded by a 5-second timeout and is silently omitted on any failure (no network, GitHub unreachable, rate-limited, slow/hung response, etc.). It also honors the `IDSEC_SUPPRESS_UPGRADE_CHECK` environment variable, so offline or restricted environments see no extra noise. Unlike the incidental nag that other commands print, `idsec version` runs the check on every invocation (no 12-hour disk cache) so the answer always reflects the current state.

For machine-readable output (raw semantic version only, without the `Idsec ` or leading `v` prefix), suitable for shell scripting:
```shell linenums="0"
idsec version --silent
```

Which prints just the bare version, e.g.:
```text linenums="0"
0.3.1
```
The upgrade hint is intentionally suppressed in `--silent` mode so that callers parsing `$(idsec version --silent)` always receive only the version string.


## Usage
```shell
Print the Idsec CLI version

Usage:
  idsec version [flags]

Flags:
  -h, --help     help for version
  -s, --silent   Print only the raw semantic version, without the 'Idsec ' or leading 'v' prefix
```
