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
brew install idsec
```

### Go

You can install the CLI via go modules. For private repositories, configure Git credentials.

**macOS / Linux**

```shell linenums="0"
# Requires Go 1.25+ and git 2.24+
export GOPRIVATE=github.com
git config --global url."https://<username>:<token>@github.com".insteadOf "https://github.com"
go install github.com/cyberark/idsec-cli-golang/cmd/idsec@latest
```

Make sure that the PATH environment variable points to the go binary path, for example:

```shell linenums="0"
export PATH=$PATH:$(go env GOPATH)/bin
```

**Windows (PowerShell)**

```powershell linenums="0"
# Requires Go 1.25+ and Git for Windows 2.24+ on PATH
$env:GOPRIVATE = "github.com"
git config --global url."https://<username>:<token>@github.com".insteadOf "https://github.com"
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
