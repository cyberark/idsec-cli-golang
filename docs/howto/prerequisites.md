---
title: Prerequisites
description: Installation and profile setup for CLI workflows
---

# Prerequisites

The following steps are required before running most CLI workflows. Complete these once, then proceed to the specific workflow guide.

## 1. Install Idsec CLI

### Homebrew

Install the CLI with Homebrew:

```shell linenums="0"
brew tap cyberark/tools
brew install idsec
```

### Go

For private repositories, configure Git credentials.

**macOS / Linux**

```shell linenums="0"
# Requires Go 1.25+ and git 2.24+
export GOPRIVATE=github.com
git config --global url."https://<username>:<token>@github.com".insteadOf "https://github.com"
go install github.com/cyberark/idsec-cli-golang/cmd/idsec@latest
```

Make sure that the PATH environment variable points to the Go binary. For example:

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

## 2. Create a profile

* Interactively:
    ```shell linenums="0"
    idsec configure
    ```
* Silently:
    ```shell linenums="0"
    idsec configure --silent --work-with-isp --isp-username myuser
    ```

## 3. Log in to Idsec

```shell linenums="0"
idsec login --silent --isp-secret <my-idsec-secret>
```
