---
title: Configure
description: Configure Command
---

# Configure command

The `configure` command is used to create a profile. Profiles define user and authentication information, such as which authentication methods to use, the method settings, and other information like MFA.

Profiles are saved in the `~/.idsec/profiles` folder.

## Run

```shell linenums="0"
idsec configure
```

When you run the command without arguments, you are prompted for the required information (alternatively, add the `--silent` flag with the required arguments).

## Preview without saving (`--dry-run`)

Add `--dry-run` to build and validate the profile and print exactly what would be saved, without writing anything to `~/.idsec/profiles`:

```shell linenums="0"
idsec configure --silent --profile-name prod --work-with-isp --isp-username alice@example.com --dry-run
```

On success it prints the resulting profile JSON followed by a `Dry run: profile is valid and would be saved to <folder> (not saved)` notice and exits `0`. If the assembled profile is invalid, it prints the validation error and exits non-zero, still without writing anything.

## Filtering with `--query`

Use `--query` to apply a [jq](https://jqlang.org) expression to the profile JSON, evaluated in-process with [gojq](https://github.com/itchyny/gojq) (no `jq` binary required). The profile is saved as usual and the expression is applied to the saved profile.

Add the common `--raw` flag to print a top-level string result unquoted, for capturing a scalar into a shell variable.

```shell linenums="0"
# Print just the saved profile name, unquoted
idsec configure --silent --profile-name prod --work-with-isp \
  --isp-username alice@example.com --raw --query '.profile_name'
```

Use `--arg name=value` / `--argjson name=json` to bind a shell value to a jq variable (`$name`) rather than interpolating it into the query string, avoiding jq-program injection when the value is user-supplied.

The two flags compose: `--dry-run --query` applies the expression to the profile that *would* be saved, so a single field can be previewed without writing anything.

```shell linenums="0"
# Check the profile name a set of flags would produce, without saving
idsec configure --silent --profile-name prod --work-with-isp \
  --isp-username alice@example.com --dry-run --raw --query '.profile_name'
```

## Usage

```shell
Configure the CLI

Usage:
  idsec configure [flags]

Flags:
      --allow-output                                    Allow stdout / stderr even when silent and not interactive
      --disable-cert-verification                       Disables certificate verification on HTTPS calls, unsafe!
      --dry-run                                         Validate and print the profile that would be saved, without writing it
  -h, --help                                            help for configure
      --isp-auth-method string                          Authentication method for Identity Security Platform (default "default")
      --isp-identity-application string                 Identity Application
      --isp-identity-authorization-application string   Service User Authorization Application
      --isp-identity-mfa-interactive                    Allow Interactive MFA
      --isp-identity-mfa-method string                  MFA Method to use by default [pf, sms, email, otp]
      --isp-identity-tenant-subdomain string            Identity Tenant Subdomain
      --isp-identity-url string                         Identity Url
      --isp-username string                             Username
      --log-level string                                Log level to use while verbose (default "INFO")
      --logger-style string                             Which verbose logger style to use (default "default")
      --profile-description string                      Profile Description
      --profile-name string                             The name of the profile to use
      --arg stringArray                                 Bind a jq variable to a string value, as name=value (usable as $name); repeatable
      --argjson stringArray                             Bind a jq variable to a JSON value, as name=json (usable as $name); repeatable
      --query string                                    jq expression to apply to the profile JSON output
      --raw                                             Raw output: disable colored output; with --query, also print string results unquoted (like jq -r)
      --silent                                          Silent execution, no interactiveness
      --trusted-cert string                             Certificate to use for HTTPS calls
      --verbose                                         Whether to verbose log
      --work-with-isp                                   Whether to work with Identity Security Platform services
```
