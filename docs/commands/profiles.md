---
title: Profiles
description: Profiles Command
---

# Profiles

Use the `profiles` command to manage multiple users and tenants, and list all existing profiles. You can create, copy, modify, and delete profiles for different users and tenant.

## Running
```shell linenums="0"
idsec profiles
```

## Filtering `list` output with `--query`

`profiles list` emits JSON — an array of profile names by default, or an array of full profile objects with `--all`. Use `--query` to apply a [jq](https://jqlang.org) expression to that JSON, evaluated in-process with [gojq](https://github.com/itchyny/gojq) (no `jq` binary required). An empty result set is always a valid JSON array (`[]`), so queries never see `null`.

Add the common `--raw` flag to print a top-level string result unquoted, useful for capturing a single value into a shell variable.

```shell linenums="0"
# Names of all profiles that use the isp authenticator
idsec profiles list --all --query '.[] | select(.auth_profiles.isp) | .profile_name'

# First profile name, unquoted
idsec profiles list --raw --query '.[0]'
```

Use `--arg name=value` / `--argjson name=json` to bind a shell value to a jq variable (`$name`) instead of interpolating it into the query string, which avoids jq-program injection when the value is user-supplied:

```shell linenums="0"
idsec profiles list --raw --query '.[] | select(. == $n)' --arg n="$PROFILE_NAME"
```

## Usage
```shell
Manage profiles

Usage:
  idsec profiles [command]

Available Commands:
  add         Add a profile from a given path
  clear       Clear all profiles
  clone       Clone a profile
  delete      Delete a specific profile
  edit        Edit a profile interactively
  list        List all profiles
  show        Show a profile

Flags:
      --allow-output                Allow stdout / stderr even when silent and not interactive
      --disable-cert-verification   Disables certificate verification on HTTPS calls, unsafe!
  -h, --help                        help for profiles
      --log-level string            Log level to use while verbose (default "INFO")
      --logger-style string         Which verbose logger style to use (default "default")
      --raw                         Whether to raw output
      --silent                      Silent execution, no interactiveness
      --trusted-cert string         Certificate to use for HTTPS calls
      --verbose                     Whether to verbose log

Use "idsec profiles [command] --help" for more information about a command.
```
