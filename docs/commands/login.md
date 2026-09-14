---
title: Login
description: Login Command
---

# Login

The `login` command is used to authenticate to Idsec using the configured profile. When you run the command, you are prompted for the required login information (such as a password and MFA verifications).

After you have logged in, the returned access tokens are stored in a secure location on your machine. After the tokens expire, a token refresh maybe attempted (see [Refresh token](../howto/refreshing_authentication.md)) or a new login is required.

## Run
```shell linenums="0"
idsec login
```

## Usage
```shell
Login to the system

Usage:
  idsec login [flags]

Flags:
      --allow-output                Allow stdout / stderr even when silent and not interactive
      --arg stringArray             Bind a jq variable to a string value, as name=value (usable as $name); repeatable
      --argjson stringArray         Bind a jq variable to a JSON value, as name=json (usable as $name); repeatable
      --credentials-file string     Path to an .idsecrc credentials file (INI). Overrides auto-discovery and IDSEC_CREDENTIALS_FILE
      --disable-cert-verification   Disables certificate verification on HTTPS calls, unsafe!
      --force                       Whether to force login even though token has not expired yet
  -h, --help                        help for login
      --isp-secret string           Secret to authenticate with to Identity Security Platform
      --isp-username string         Username to authenticate with to Identity Security Platform
      --log-level string            Log level to use while verbose (default "INFO")
      --logger-style string         Which verbose logger style to use (default "default")
      --no-credentials-file         Do not auto-discover an .idsecrc credentials file; only an explicit --credentials-file or IDSEC_CREDENTIALS_FILE is used
      --no-shared-secrets           Do not share secrets between different authenticators with the same username
      --profile-name string         Profile name to load (default "idsec")
      --query string                jq expression to apply to the JSON token output (implies --show-tokens)
      --raw                         Raw output: disable colored output; with --query, also print string results unquoted (like jq -r)
      --refresh-auth                If a cache exists, will also try to refresh it
      --show-tokens                 Print out tokens as well if not silent
      --silent                      Silent execution, no interactiveness
      --trusted-cert string         Certificate to use for HTTPS calls
      --verbose                     Whether to verbose log
```

## Querying the token output

Use `--query` to apply a [jq](https://jqlang.org) expression to the JSON token
output, evaluated in-process with [gojq](https://github.com/itchyny/gojq) (no
`jq` binary required). The queried document is a map keyed by authenticator
human-readable name, each value being that authenticator's token fields.

`--query` implies `--show-tokens`, so the expression can reach the token values.
Add the common `--raw` flag to print a top-level string result unquoted, which
is convenient for capturing a single value into a shell variable.

```shell linenums="0"
# The ISP token's expiry
idsec login --silent --query '."Identity Security Platform".expires_in'

# Capture the raw token string
TOKEN=$(idsec login --silent --raw --query '."Identity Security Platform".token')
```

Use `--arg name=value` / `--argjson name=json` to bind a shell value to a jq variable (`$name`) rather than interpolating it into the query string, avoiding jq-program injection when the value is user-supplied:

```shell linenums="0"
TOKEN=$(idsec login --silent --raw --query '.[$a].token' --arg a="Identity Security Platform")
```

## Failure exit codes and reasons

On failure (for example a missing profile or a required secret that was not
supplied), `login` exits with a non-zero status code, so scripts can branch on
the exit code instead of scraping output.

### Machine-readable failure reason

When a login fails, in addition to the human-readable message, `login` prints a
single stable, greppable line to **stderr** and exits non-zero:

```text linenums="0"
idsec: login failed reason=<REASON>[ authenticator=<name>][ key=value ...]
```

Match on this line instead of parsing the prose message, which changes over
time. The `authenticator=<name>` field is present whenever the failure is tied
to a specific authenticator (for example `isp` or `pvwa`). Additional
`key=value` fields may follow; `USERNAME_REQUIRED` and `SECRET_REQUIRED` add
`rc_available=<path>` when a [credentials file](../config/credentials_file.md)
was loaded, which distinguishes "no `.idsecrc` was found" from "an `.idsecrc`
was loaded but has no entry for this profile and authenticator".

| `reason` | Meaning |
| :--- | :--- |
| `PROFILE_NOT_FOUND` | The requested profile does not exist (and could not be configured). |
| `USERNAME_REQUIRED` | Running silently and no username was supplied for the authenticator (flag, environment variable, `.idsecrc` or profile). |
| `SECRET_REQUIRED` | Running silently and no secret was supplied for the authenticator. |
| `CONFIG_ERROR` | The credentials inputs themselves are broken, e.g. an unreadable `IDSEC_<AUTH>_SECRET_FILE` or an unparsable credentials file. |
| `MFA_REQUIRED` | Multi-factor authentication is required but cannot be completed non-interactively. |
| `ENDPOINT_UNREACHABLE` | The authentication endpoint could not be reached (DNS, connection, or timeout). |
| `CERTIFICATE_ERROR` | TLS/certificate verification failed while contacting the endpoint. |
| `KEYRING_FAILURE` | The local token cache (keyring) could not be read or written. |
| `AUTH_FAILED` | Authentication failed for a reason that could not be classified more specifically. |

```shell
# Branch on the failure reason without parsing prose
REASON_LINE=$(idsec login --silent 2>&1 >/dev/null | grep '^idsec: login failed ')
reason=${REASON_LINE#*reason=}; reason=${reason%% *}
case "$reason" in
  USERNAME_REQUIRED|SECRET_REQUIRED) echo "supply credentials and retry" ;;
  CONFIG_ERROR)                      echo "fix the credentials file / env vars" ;;
  MFA_REQUIRED)                      echo "run interactively to complete MFA" ;;
esac
```

## Supplying credentials without prompts

By default, `login` prompts interactively for each authenticator's username and
secret. You can also supply credentials non-interactively — which is required
when running with `--silent` — from three sources:

1. **CLI flags** — `--<authenticator>-username` / `--<authenticator>-secret`
   (for example `--isp-username`, `--isp-secret`, `--pvwa-secret`).
2. **Environment variables** — `IDSEC_<AUTHENTICATOR>_USERNAME` and
   `IDSEC_<AUTHENTICATOR>_SECRET`, where the authenticator name is uppercased
   (for example `IDSEC_ISP_USERNAME`, `IDSEC_ISP_SECRET`, `IDSEC_PVWA_SECRET`).
   The secret may instead be read from a file with
   `IDSEC_<AUTHENTICATOR>_SECRET_FILE` (for example `IDSEC_ISP_SECRET_FILE`),
   which keeps the secret in a `0600` file rather than the environment. The
   literal `IDSEC_<AUTHENTICATOR>_SECRET` wins if both are set; an unreadable
   secret file fails the login instead of silently proceeding.
3. **A `.idsecrc` credentials file** — an INI file with a section per profile.
   See [Credentials file](../config/credentials_file.md) for the format and
   discovery locations. Pass `--no-credentials-file` to disable auto-discovery
   entirely, so only an explicit `--credentials-file` or `IDSEC_CREDENTIALS_FILE`
   is ever read (useful when a discovered file should require explicit consent).

```shell
# Silent login using environment variables
export IDSEC_ISP_USERNAME=alice@example.com
export IDSEC_ISP_SECRET='s3cr3t'
idsec login --silent

# Silent login reading the secret from a 0600 file
export IDSEC_ISP_USERNAME=alice@example.com
export IDSEC_ISP_SECRET_FILE=~/.secrets/isp
idsec login --silent

# Silent login using a specific credentials file, without auto-discovery
idsec login --silent --credentials-file /path/to/.idsecrc --no-credentials-file
```

### Precedence

For a given authenticator, values are resolved as follows:

| Field | Order (highest first) |
| :--- | :--- |
| Secret | flag → environment variable → `.idsecrc` |
| Username | flag → environment variable → `.idsecrc` → profile |

In interactive mode the resolved value is shown as the prompt default (the
secret prompt notes when it was pre-loaded from an environment variable or the
credentials file); pressing Enter accepts it, and typing a new value overrides
it. In silent mode the resolved value is used as-is, and a required username or
secret that cannot be resolved fails the command with a non-zero exit code and a
`USERNAME_REQUIRED` / `SECRET_REQUIRED` reason line (see
[Failure exit codes and reasons](#failure-exit-codes-and-reasons)).
