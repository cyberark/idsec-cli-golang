---
title: Query
description: Query Command
---

# Query

The `query` command runs a [jq](https://jqlang.org) expression against JSON produced by an idsec command — read from a file (for example output saved with `--output-path`) or from standard input. The expression is evaluated in-process using [gojq](https://github.com/itchyny/gojq), so the `jq` binary does not need to be installed.

This is the standalone counterpart to the inline `--query` flag available on commands such as [`exec`](exec.md): instead of querying a command's live output, `query` filters JSON you already have — from a saved file or piped in.

## Run

```shell linenums="0"
# Save a command's output, then query it later
idsec exec cmgr pools list --output-path pools.json
idsec query --path pools.json --query '.[] | select(.type == "ACCESS") | .name'

# Or pipe JSON in without ever writing it to disk
idsec exec cmgr pools list | idsec query --query '.[] | select(.type == "ACCESS") | .name'
```

## Options

- `--path` — path to a JSON file produced by an idsec command. Use `-`, or omit `--path` entirely, to read JSON from **stdin**. Reading from stdin keeps secret-bearing JSON off disk.
- `--query` (required) — the jq expression to evaluate against the JSON content.
- `-n`, `--null-input` — do not read any input; run the query against `null`, like `jq -n`. Use this to construct JSON purely from `--arg`/`--argjson` bindings.
- `--arg <name>=<value>` — bind the string `value` to the jq variable `$name`. Repeatable.
- `--argjson <name>=<json>` — bind the parsed JSON `json` to the jq variable `$name`. Repeatable.
- `--raw` — print a top-level string result unquoted, like `jq -r` (this common flag also disables colored output). Objects, arrays, numbers, and booleans are always rendered as JSON.

### Constructing JSON with no input (`-n`)

Use `-n` when you want to build a JSON object from shell values rather than filter existing JSON — for example, a planner emitting a plan object or a resolver assembling a result. No file or stdin is read:

```shell linenums="0"
# Build a result object from bound values, no input needed
idsec query -n \
  --query '{safe: $s, account: $a, rotated: $r}' \
  --arg s="$SAFE_NAME" \
  --arg a="$ACCOUNT_NAME" \
  --argjson r=true
```

### Passing shell values safely (`--arg` / `--argjson`)

Never interpolate a shell value into the query string — a value such as a safe, role, or pool name is user-supplied, and a name like `x") | .credentials, ("` would rewrite the expression (jq-program injection). Instead, bind the value to a variable and reference it with `$name`:

```shell linenums="0"
# Safe: the name is data, not program. Even hostile names can't alter the query.
SAFE_NAME='Prod DB'
idsec query --path safes.json \
  --query '.[] | select(.safeName == $n) | .safeUrlId' \
  --arg n="$SAFE_NAME"

# --argjson binds a JSON value (number, bool, object, array)
idsec query --path pools.json --query '.[] | select(.size > $min)' --argjson min=10
```

Unlike jq, each binding is a single `name=value` token (not two separate arguments). The value is split on the first `=`, so later `=` characters are preserved. The variable name must be a valid identifier (`[A-Za-z_][A-Za-z0-9_]*`).

### Reading the environment (`env` / `$ENV`)

As in jq, the process environment is reachable through the `env` function and the `$ENV` variable, so an expression can resolve a value the caller places in the environment. This is useful for secrets: environment is a safer channel than argv, which is world-readable via `ps` for the process's lifetime.

```shell linenums="0"
# Resolve a secret whose variable name is named in the input (env[$v])
export DB_PASSWORD='s3cr3t'
echo '{"password_from_env":"DB_PASSWORD"}' \
  | idsec query --raw --query '.password_from_env as $v | env[$v]'

# JSON-encode a raw secret without it ever reaching argv (jq -Rs . equivalent)
export SECRET_VALUE='a"b'
idsec query -n --query 'env.SECRET_VALUE'   # → "a\"b"
```

Because query expressions are constants written by the caller and any user-supplied values are `--arg`-bound rather than interpolated, exposing the environment carries no injection risk here.

### Notes

Multiple output values (for example from `.[]`) are each printed on their own line. A missing key follows jq semantics — `.pool_id` yields `null`, so use `.pool_id // ""` when capturing a scalar into a shell variable:

```shell linenums="0"
# Capture a single value, unquoted, with a safe fallback
POOL_ID=$(idsec query --path pool.json --raw --query '.pool_id // ""')
```

The command exits non-zero when the input cannot be read, its contents are not valid JSON, a variable binding is malformed, or the query expression is invalid or fails, so scripts can branch on the exit code.

## Usage

```shell
Run a jq query on JSON produced by an idsec command (from a file or stdin)

Usage:
  idsec query [flags]

Flags:
      --allow-output                Allow stdout / stderr even when silent and not interactive
      --arg stringArray             Bind a jq variable to a string value, as name=value (usable as $name); repeatable
      --argjson stringArray         Bind a jq variable to a JSON value, as name=json (usable as $name); repeatable
      --disable-cert-verification   Disables certificate verification on HTTPS calls, unsafe!
  -h, --help                        help for query
      --log-level string            Log level to use while verbose (default "INFO")
      --logger-style string         Which verbose logger style to use (default "default")
  -n, --null-input                  Do not read any input; run the query against null (like jq -n)
      --path string                 Path to a JSON file produced by an idsec command; use '-' or omit to read JSON from stdin
      --query string                jq expression to evaluate against the JSON content
      --raw                         Raw output: disable colored output; with --query, also print string results unquoted (like jq -r)
      --silent                      Silent execution, no interactiveness
      --trusted-cert string         Certificate to use for HTTPS calls
      --verbose                     Whether to verbose log
```
