---
title: Prerequisites
description: Installation and profile setup for CLI workflows
---

# Prerequisites

The following steps are required before running most CLI workflows. Complete these once, then proceed to the specific workflow guide.

## 1. Install Idsec CLI

For private repositories, configure Git credentials:

```shell linenums="0"
# Requires Go 1.24+ and git 2.24+
export GOPRIVATE=github.com
git config --global url."https://<username>:<token>@github.com".insteadOf "https://github.com"
go install github.com/cyberark/idsec-cli-golang/cmd/idsec@latest
```

Make sure that the PATH environment variable points to the Go binary. For example:

```shell linenums="0"
export PATH=$PATH:$(go env GOPATH)/bin
```

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
