---
title: Configure, Login & Status examples
description: Examples for the configure, login, and status commands
---

# Configure, Login & Status examples

## Configure command examples

The `configure` command works in interactive or silent mode. When using silent mode, the required parameters need to be specified.

### Configure ISP profile (silent mode)

```shell linenums="0"
idsec configure --profile-name="PROD" --work-with-isp --isp-username="tina@cyberark.cloud.12345" --silent --allow-output
```

### Configure PVWA profile (silent mode)

For self-hosted CyberArk deployments using Password Vault Web Access (PVWA):

```shell linenums="0"
idsec configure --profile-name="PVWA-PROD" --work-with-pvwa --pvwa-username="myuser" --pvwa-url="https://pvwa.example.com" --pvwa-login-method="ldap" --silent --allow-output
```

Available PVWA login methods:

- `cyberark` - CyberArk native authentication
- `ldap` - LDAP authentication
- `windows` - Windows authentication

## Login command examples

The login command can work in interactive or silent mode.

### Login with ISP credentials

```shell linenums="0"
idsec login -s --isp-secret=CoolPassword --profile-name PROD
```

### Login with PVWA credentials

```shell linenums="0"
idsec login -s --pvwa-secret=MyPassword --profile-name PVWA-PROD
```

## Status command examples

The `status` command shows whether a profile is authenticated and how much time is left before its token expires. It reads local state only and never triggers a login.

### Show status of the current profile

```shell linenums="0"
idsec status
```

### Show status of a specific profile

```shell linenums="0"
idsec status --profile-name PROD
```

### Machine-readable status (JSON)

```shell linenums="0"
idsec status --json
```
