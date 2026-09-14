---
title: Credentials File
description: Use an .idsecrc file to supply login credentials non-interactively.
---

# Credentials File

The `login` command can read authenticator credentials from an `.idsecrc` file,
so you don't have to type them at the prompt or pass them as flags. This is
especially useful for silent, non-interactive logins (`idsec login --silent`).

The file is INI-formatted, similar to an AWS credentials file, with one section
per profile.

## File Location

The credentials file is resolved in the following order. The **first existing
file** wins; there is no merging across locations.

1. The `--credentials-file` flag (highest priority)
2. The `IDSEC_CREDENTIALS_FILE` environment variable
3. `./.idsecrc` (current directory)
4. `./.idsec/.idsecrc`
5. `~/.idsec/.idsecrc`
6. `~/.idsecrc`

```shell
# Use a specific credentials file for a single command
idsec login --silent --credentials-file /path/to/.idsecrc

# Or point at it with an environment variable
export IDSEC_CREDENTIALS_FILE=/path/to/.idsecrc
idsec login --silent
```

When the file is provided explicitly (via the flag or `IDSEC_CREDENTIALS_FILE`)
it must exist and be parseable, otherwise the command fails. Auto-discovered
files that are missing are silently ignored, and a parse error in an
auto-discovered file produces a warning without failing the command.

Credentials-file warnings (insecure permissions, unrecognized keys, and parse
errors in an auto-discovered file) are written to **stderr** and are always
shown — they do not require `--verbose` — so they remain visible in the
non-interactive mode automation uses. They go to stderr (never stdout), so they
never interfere with a command's machine-readable output. Each is prefixed with
`idsec: warning:`.

Pass `--no-credentials-file` to disable auto-discovery (locations 3–6 above)
entirely. Only an explicit `--credentials-file` or `IDSEC_CREDENTIALS_FILE` is
then honored, so a discovered file is never read without you naming it — useful
when reading a credentials file should require explicit consent.

## File Format

Each section name is a profile name; the credentials in that section are used
when logging in with that profile. Keys are `<authenticator>_username` and
`<authenticator>_secret`, where `<authenticator>` is the authenticator name
(for example `isp`, `pvwa`).

```ini
# ~/.idsecrc

[default]
isp_username  = alice@example.com
isp_secret    = s3cr3t
pvwa_username = svc_pvwa
pvwa_secret   = pvwa-secret

[prod]
isp_username = prod@example.com
isp_secret   = prod-secret
```

When logging in with `--profile-name prod`, the `[prod]` section is used. If the
named section is missing, or a specific key is not present in it, the `[default]`
section is used as a fallback. Keys that do not end with `_username` or
`_secret` are ignored with a warning.

## Precedence

For a given authenticator, credentials are resolved in the following order
(highest priority first):

| Field | Order |
| :--- | :--- |
| Secret | CLI flag → environment variable → `.idsecrc` |
| Username | CLI flag → environment variable → `.idsecrc` → profile |

The relevant environment variables are `IDSEC_<AUTHENTICATOR>_USERNAME` and
`IDSEC_<AUTHENTICATOR>_SECRET` (see [Environment](environment.md)). In
interactive mode the resolved value becomes the prompt default and can be
overridden by typing a new value; in silent mode it is used as-is.

## Security Note

The credentials file stores secrets in plaintext. Restrict its permissions:

```shell
chmod 600 ~/.idsecrc
```

On non-Windows systems, `login` emits a warning (on stderr, always shown) when
the credentials file is group- or world-readable.
