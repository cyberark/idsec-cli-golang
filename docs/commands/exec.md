---
title: Exec
description: Exec Command
---

# Exec

Use the `exec` command to run commands on available services (the available services depend on the authorized user's account).

!!! tip "Shorthand"

    The `exec` subcommand may be omitted. Service commands can be invoked directly by specifying the service name after `idsec`. Both forms are equivalent:

    | Full form | Shorthand |
    |-----------|-----------|
    | `idsec exec sia sso short-lived-password` | `idsec sia sso short-lived-password` |
    | `idsec exec pcloud safes create --safe-name=safe` | `idsec pcloud safes create --safe-name=safe` |

## SIA services

The following SIA commands are supported:

- `idsec sia`: Root command for the SIA service (aliases: dpa)
    - `sso` - SSO end-user operations
    - `k8s` - Kubernetes service
    - `db` - DB service
    - `workspaces` - Workspaces service
      - `target-sets` - Target sets operations
      - `db` - Database operations
    - `secrets` - Secrets service
      - `vm` - VM operations
      - `db` - Database operations
    - `access` - Access service
    - `ssh-ca` - SSH CA key service
    - `shortened-connection-string` - Shortened connection string service
    - `settings` - Settings service
    - `certificates` - Certificates service
- `idsec cmgr`: Root command for the CMGR service (aliases: connectormanager,cm)
- `idsec pcloud`: Root command for PCloud service (aliases: privilegecloud,pc)
    - `accounts` - Accounts management
    - `safes` - Safes management
    - `platforms` - Platforms management
    - `applications` - Applications management
- `idsec identity`: Root command for the Identity service (aliases: idaptive,id)
    - `directories` - Directories management
    - `users` - Users management
    - `roles` - Roles management
    - `auth-profiles` - Auth profiles management
    - `policies` - Policies management
-  `idsec sechub`: Root command for the Secrets Hub Service (aliases: secretshub,sh)
    - `configuration` - Configuration management
    - `service-info` - Service Info management
    - `secrets` - Secrets management
    - `scans` - Scans management
    - `secret-stores` - Secret Stores management
    - `sync-policies` - Sync Policies management
- `idsec sm`: Root command for the SM service (aliases: sessionmonitoring)
- `idsec policy`: Root command for the Policy service (aliases: accesspolicies, acp)
    - `cloud-access` - Cloud Console management
    - `db` - SIA DB management
    - `vm` - SIA VM management

All commands have their own subcommands and respective arguments and aliases.

## Running
```shell linenums="0"
idsec exec
```

## Paging long list output

Use `--page-size` when a command returns a long list and you want to browse the result in the terminal.

```shell linenums="0"
idsec policy cloud-access list-policies --profile-name myprofile --page-size 10
```

When `--page-size` is set and the command is running in an interactive terminal, the CLI prints exactly that number of items and waits for a keypress:

- Press `space` or `Enter` to show the next page.
- Press `q`, `Esc`, `Ctrl+C`, or `Ctrl+D` to stop paging.

The pager controls only page boundaries and continue/quit behavior. Item rendering stays with command output formatting (currently pretty JSON for these list results). Between pages, output is appended so you can scroll up to previous pages.

Paging is client-side only. The CLI still receives the SDK result and only controls interactive paging flow. When output is piped or redirected, the interactive pager is disabled and the CLI writes a JSON array so commands remain scriptable:

```shell linenums="0"
idsec policy cloud-access list-policies --profile-name myprofile --page-size 10 | jq '.'
```

Search is not built into the interactive pager. For searching or filtering, pipe the command output to tools such as `less`, `grep`, or `jq`:

```shell linenums="0"
idsec policy cloud-access list-policies --profile-name myprofile | less
```

## Filtering output with `--query`

Use `--query` to apply a [jq](https://jqlang.org) expression to the JSON output of any exec command, without requiring `jq` to be installed — the query runs in-process using [gojq](https://github.com/itchyny/gojq).

```shell linenums="0"
# Print just the safe name from a get-safe result
idsec exec pcloud safes get --safe-id MySafe --query '.safeName'

# Extract the name of every pool whose type is ACCESS
idsec exec cmgr pools list --query '.[] | select(.type == "ACCESS") | .name'

# List pool IDs as a compact array
idsec exec cmgr pools list --query '[.[].pool_id]'
```

`--query` takes precedence over `--format` and service-defined formatters: the full JSON output is always passed to the expression, regardless of how the service would otherwise render it.

Multiple output values (e.g. from `.[]`) are each printed as a separate JSON value on its own line. Errors in the query expression (syntax, type mismatches) are returned as command errors with a non-zero exit code.

When a command produces no result value (for example an action that returns nothing), the query runs against JSON `null` — matching jq's empty-input model — instead of printing a status sentence. This keeps captures such as `ID=$(idsec ... --query '.pool_id // ""')` clean and empty rather than picking up a human-readable message.

### Binding shell values (`--arg` / `--argjson`)

Never interpolate a shell value into the query string — a name like `x") | .credentials, ("` would rewrite the expression (jq-program injection). Instead bind it to a jq variable and reference it as `$name`:

```shell linenums="0"
# Safe: the name is data, not program
idsec exec cmgr pools list --query '.[] | select(.name == $n) | .pool_id' --arg n="$POOL_NAME"

# --argjson binds a JSON value (number, bool, object, array)
idsec exec cmgr pools list --query '.[] | select(.size > $min)' --argjson min=10
```

Both flags are repeatable and take a single `name=value` token (the value is split on the first `=`). The variable name must be a valid identifier. These work the same on `login`, `status`, `profiles list`, and `configure`, and on the standalone [`query`](query.md) command.

### Raw string output (`--raw`)

By default a string result is printed quoted, so the output stays valid JSON and can be piped onward. Add the common `--raw` flag to print a top-level string result unquoted, like `jq -r` — useful when capturing a single scalar into a shell variable (`--raw` also disables colored output, which keeps the captured value clean):

```shell linenums="0"
# Quoted (default): "pool-123"
idsec exec cmgr pools get-by-name --name mypool --query '.pool_id'

# Raw: pool-123
POOL_ID=$(idsec exec cmgr pools get-by-name --name mypool --raw --query '.pool_id')
```

`--raw` only affects top-level string results; objects, arrays, numbers, and booleans are always rendered as JSON.

## Dry run

Use `--dry-run` to preview what a command would do without authenticating or executing it. Instead of running the action, the CLI prints a JSON plan describing the operation, the profile it would use, the resolved arguments (the flags you provided plus any applied defaults), and which of those arguments are secrets.

`--dry-run` is a purely local preview: it does not load a profile, contact any service, or require you to be logged in, and it never performs the action. Under `--dry-run`, normally required flags are not enforced, so you can preview a plan without re-specifying every required argument.

`--dry-run` reads `--request-file` too: the request file's values are merged into `resolved_args` (an explicit flag wins over a request-file value), and any secrets it carries are masked and listed in `secret_fields`. Because the request file is the recommended channel for secrets, the plan reflects them accurately rather than reporting `secret_fields: []`.

```shell linenums="0"
idsec sia access install-connector --dry-run \
  --profile-name prod \
  --target-machine db-01 \
  --connector-pool-id pool-123 \
  --password s3cr3t
```

```json
{
  "operation": "sia.access.install_connector",
  "profile": "prod",
  "resolved_args": {
    "connector-os": "linux",
    "connector-pool-id": "pool-123",
    "connector-type": "ON-PREMISE",
    "password": "***",
    "retry-count": "10",
    "retry-delay": "5",
    "target-machine": "db-01",
    "winrm-protocol": "https"
  },
  "secret_fields": ["password"]
}
```

The plan fields are:

- `operation` - the dotted service path and action that would run, e.g. `sia.access.install_connector`.
- `profile` - the effective profile name that would be used (resolved from `--profile-name`, not loaded).
- `resolved_args` - the effective arguments keyed by flag name. Includes flags you provided and any schema defaults that would be applied; arguments you did not set and that have no default are omitted.
- `secret_fields` - the `resolved_args` keys whose values are secrets.

Secret arguments (passwords, private keys, access keys, tokens, etc.) are always masked as `***` in `resolved_args` and listed under `secret_fields`, so the plan is safe to share or log. Secrets are identified by the service model definitions, so masking stays correct as new commands are added.

### Querying the plan

`--query` applies to the plan as well, so an expression can be rehearsed against a plan before the command is run for real, and a single plan field can be pulled out for a script or an assertion:

```shell linenums="0"
# Which pool would this actually target?
idsec sia access install-connector --dry-run --connector-pool-id pool-123 \
  --target-machine db-01 --raw --query '.resolved_args["connector-pool-id"]'

# Fail a pre-flight check if the plan carries any secret
idsec sia access install-connector --dry-run --target-machine db-01 \
  --query '.secret_fields | length == 0'
```


## Usage
```shell
Exec an action

Usage:
  idsec exec [command]

Available Commands:
  cmgr        (aliases: connectormanager, cm)
  identity    (aliases: idaptive, id)
  pcloud      (aliases: privilegecloud, pc)
  sechub      (aliases: secretshub, sh)
  sia         (aliases: dpa)
  sm          (aliases: sessionmonitoring)
  policy      (aliases: accesspolicies, acp)

Flags:
      --allow-output                Allow stdout / stderr even when silent and not interactive
      --disable-cert-verification   Disables certificate verification on HTTPS calls, unsafe!
      --disable-telemetry           Disables telemetry data collection
      --dry-run                     Print the action, operation, resolved arguments, and secret fields as JSON without authenticating or executing
  -h, --help                        help for exec
      --log-level string            Log level to use while verbose (default "INFO")
      --logger-style string         Which verbose logger style to use (default "default")
      --output-path string          Output file to write data to
      --page-size int               Show N items per page in interactive output, pausing between pages (0 = disabled)
      --profile-name string         Profile name to load (default "idsec")
      --arg stringArray             Bind a jq variable to a string value, as name=value (usable as $name); repeatable
      --argjson stringArray         Bind a jq variable to a JSON value, as name=json (usable as $name); repeatable
      --query string                jq expression applied to the JSON output (e.g. '.name', '.[] | select(.active)')
      --raw                         Raw output: disable colored output; with --query, also print string results unquoted (like jq -r)
      --refresh-auth                If a cache exists, will also try to refresh it
      --request-file string         Request file containing the parameters for the exec action
      --retry-count int             Retry count for execution (default 1)
      --silent                      Silent execution, no interactiveness
      --trusted-cert string         Certificate to use for HTTPS calls
      --verbose                     Whether to verbose log

Use "idsec exec [command] --help" for more information about a command.
```
