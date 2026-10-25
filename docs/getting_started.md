---
title: Getting started
description: Getting started with Idsec CLI
---

# Getting started

## Installation

### Homebrew

Install the CLI with Homebrew:

```shell linenums="0"
brew tap cyberark/tools
brew trust cyberark/tools
brew install idsec
```

### Go

You can install the CLI via go modules.

**macOS / Linux**


```shell linenums="0"
# Requires Go 1.25+
go install github.com/cyberark/idsec-cli-golang/cmd/idsec@latest
```

Make sure that the PATH environment variable points to the go binary path, for example:

```shell linenums="0"
export PATH=$PATH:$(go env GOPATH)/bin
```

**Windows (PowerShell)**


```powershell linenums="0"
# Requires Go 1.25+ and Git for Windows 2.24+ on PATH
go install github.com/cyberark/idsec-cli-golang/cmd/idsec@latest
```

The Go installer adds its own `bin` directory to PATH but not the one `go install` writes to, so add that as well:

```powershell linenums="0"
$env:Path += ";$(go env GOPATH)\bin"
```

This lasts for the current session only. To keep it, add the same directory to PATH under System Properties > Environment Variables.

## CLI Usage

The CLI supports [profiles](howto/working_with_profiles.md), which can be configured as needed and used for consecutive actions.

The CLI has the following basic commands:

- <b>configure</b>: Configure profiles and their authentication methods (see [Configure](commands/configure.md))
- <b>login</b>: Log in using the configured profile authentication methods (see [Login](commands/login.md))
- <b>status</b>: Show whether a profile is authenticated and how much time is left before its token expires (see [Status](commands/status.md))
- <b>exec</b>: Execute commands for supported services (see [Exec](commands/exec.md)). You can also skip `exec` and invoke services directly, e.g. `idsec sia sso short-lived-password`
- <b>profiles</b>: Manage multiple profiles on the machine (see [Profiles](commands/profiles.md))
- <b>cache</b>: Manage idsec cache on the machine (see [Cache](commands/cache.md))
- <b>upgrade</b>: Upgrade the CLI to the latest version (see [Upgrade](commands/upgrade.md))

### Basic flow

1. Configure a profile (either silently or interactively):

    ```shell linenums="0"
    idsec configure --silent --work-with-isp --isp-username myuser
    ```

1. After the profile is configured, log in:

    ```shell linenums="0"
    idsec login --silent --isp-secret mysecret
    ```

1. Execute actions (such as generating a short-lived SSO password):

    ```shell linenums="0"
    idsec sia sso short-lived-password
    ```

    You can also use `idsec exec sia sso short-lived-password` — both forms are equivalent.

## Exit codes

`idsec` exits with `0` on success and non-zero on failure. Since v0.14.0,
this includes `idsec exec` (and implicit `idsec <service> …` invocations):
a failed action, missing profile, expired login, or failed `--dry-run` now
exits `1`. Previously these exited `0`.

## Output streams

Since v0.14.0, `idsec` writes only command results to stdout:

- **stdout** - results: action output (JSON, tables, text), `--dry-run` plans,
  `--query` results, and help you asked for with `--help` or `idsec help`.
- **stderr** - everything else: failure messages, warnings (including the
  "newer version available" notice), retry notices, `--verbose` logs, and
  usage errors together with the help shown alongside them.

A failing command leaves stdout empty, so `idsec exec ... | jq` never receives
an error message as input. Failure messages are printed to stderr even with
`--silent`. Warnings and notices still follow `--silent` and `--allow-output`.

Before v0.14.0, failure messages and `--verbose` logs were written to stdout.
Scripts that searched stdout for messages such as `Failed to...` should check
the exit code instead, or read stderr (for example with `2>&1`).
