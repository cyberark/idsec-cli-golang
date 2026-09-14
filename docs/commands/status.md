---
title: Status
description: Status Command
---

# Status

The `status` command reports the authentication state of a profile. For every authenticator configured on the profile (for example, `isp` or `pvwa`) it shows whether you are currently authenticated, the authenticated username and endpoint, when the cached token expires, and how much time is left before it expires.

The status is derived entirely from local state — the profile configuration and the cached token in the keyring — so it never triggers an interactive login or a network request. This makes it safe to run in scripts and CI.

## Run
```shell linenums="0"
idsec status
```

To check a specific profile instead of the current one, pass `--profile-name`:

```shell linenums="0"
idsec status --profile-name myprofile
```

## Output

When authenticated, the command prints a summary per authenticator:

```shell linenums="0"
Profile: idsec
Identity Security Platform: Authenticated as user@example.com
  Endpoint: https://tenant.cyberark.cloud
  Expires:  2026-09-03T18:05:00Z (1h23m5s left)
```

When a profile is not authenticated (or its token has expired), the command tells you to run [`idsec login`](login.md):

```shell linenums="0"
Profile: idsec
Password Vault Web Access: Not Authenticated (run `idsec login`)
```

## JSON output

For machine-readable output, use the `--json` flag:

```shell linenums="0"
idsec status --json
```

```json
{
  "profile": "idsec",
  "exists": true,
  "authenticated": true,
  "authenticators": [
    {
      "authenticator": "isp",
      "name": "Identity Security Platform",
      "username": "user@example.com",
      "auth_method": "identity",
      "authenticated": true,
      "endpoint": "https://tenant.cyberark.cloud",
      "expires_at": "2026-09-03T18:05:00Z",
      "time_left": "1h23m5s"
    }
  ]
}
```

The top-level `authenticated` field is `true` only when every configured authenticator is authenticated (an expired token counts as not authenticated). The `exists` field distinguishes a profile that does not exist (`exists: false`, `authenticators: []`) from one that exists but has no authenticators configured (`exists: true`, `authenticators: []`).

## Filtering with `--query`

Use `--query` to apply a [jq](https://jqlang.org) expression to the same JSON document shown above, evaluated in-process with [gojq](https://github.com/itchyny/gojq) (no `jq` binary required). It takes precedence over `--json` and the human-readable summary, and is also applied when the profile does not exist (against `{"profile": ..., "exists": false, "authenticated": false, "authenticators": []}`).

Add the common `--raw` flag to print a top-level string result unquoted, handy for capturing a scalar into a shell variable.

```shell linenums="0"
# Overall authenticated boolean
idsec status --query '.authenticated'

# Endpoint of the isp authenticator, unquoted
idsec status --raw --query '.authenticators[] | select(.authenticator == "isp") | .endpoint'
```

Use `--arg name=value` / `--argjson name=json` to bind a shell value to a jq variable (`$name`) rather than interpolating it into the query string, which avoids jq-program injection when the value is user-supplied:

```shell linenums="0"
idsec status --raw --query '.authenticators[] | select(.authenticator == $a) | .endpoint' --arg a="$AUTH"
```

## Scripting without a JSON parser

Use `--quiet` to consume the result via the exit code alone, without parsing JSON. It prints nothing; the exit code is the entire signal:

| Exit code | State |
| :--- | :--- |
| `0` | Authenticated (every configured authenticator has a valid token). |
| `2` | The profile does not exist. |
| `3` | The profile exists but has no authenticators configured. |
| `4` | Not authenticated — at least one authenticator has no cached token. |
| `5` | Token expired — a cached token exists but has expired (and none are missing). |
| `1` | Reserved for generic/unexpected errors. |

When more than one authenticator is configured, the state is chosen by priority: no-authenticators (`3`) → any-authenticator-missing-a-token (`4`) → any-expired (`5`).

```shell linenums="0"
idsec status --quiet
case $? in
  0) echo "authenticated" ;;
  2) echo "no such profile — run idsec configure" ;;
  3) echo "profile has no authenticators" ;;
  4) echo "not authenticated — run idsec login" ;;
  5) echo "token expired — run idsec login" ;;
  *) echo "unexpected error" ;;
esac
```

## Usage
```shell
Show the authentication status of a profile

Usage:
  idsec status [flags]

Flags:
      --allow-output                Allow stdout / stderr even when silent and not interactive
      --disable-cert-verification   Disables certificate verification on HTTPS calls, unsafe! Avoid using in production environments!
      --disable-telemetry           Disables telemetry data collection
  -h, --help                        help for status
      --json                        Output the status as JSON
      --log-level string            Log level to use while verbose (default "INFO")
      --logger-style string         Which verbose logger style to use (default "default")
      --profile-name string         Profile name to show status for, if not given, uses the current one (default "idsec")
      --arg stringArray             Bind a jq variable to a string value, as name=value (usable as $name); repeatable
      --argjson stringArray         Bind a jq variable to a JSON value, as name=json (usable as $name); repeatable
      --query string                jq expression to apply to the JSON status output
      --quiet                       Suppress output and exit non-zero when the profile is not authenticated (useful in scripts without a JSON parser)
      --proxy-address string        Proxy address to use for HTTP/HTTPS calls, if not given will resolve from environment variables
      --proxy-password string       Password for proxy authentication
      --proxy-username string       Username for proxy authentication
      --raw                         Raw output: disable colored output; with --query, also print string results unquoted (like jq -r)
      --silent                      Silent execution, no interactiveness
      --suppress-version-check      Whether to suppress version check
      --trusted-cert string         Certificate to use for HTTPS calls
      --verbose                     Whether to verbose log

Global Flags:
      --config string   Path to configuration file (default ~/.idsec/config.yaml)
```
