---
title: Environment
description: Useful environment variables for configuring the Idsec CLI.
---

# Environment

The Idsec CLI uses environment variables to configure its behavior and settings. Below are some of the key environment variables that can be set:

- `IDSEC_PROFILE`: Specifies the profile to use for authentication and service interactions. If not set, the default profile will be used.
- `IDSEC_<AUTHENTICATOR>_USERNAME`: Supplies the username for an authenticator during `login`, where `<AUTHENTICATOR>` is the uppercased authenticator name (for example `IDSEC_ISP_USERNAME`, `IDSEC_PVWA_USERNAME`).
- `IDSEC_<AUTHENTICATOR>_SECRET`: Supplies the secret/password for an authenticator during `login` (for example `IDSEC_ISP_SECRET`, `IDSEC_PVWA_SECRET`). Useful for silent, non-interactive logins.
- `IDSEC_<AUTHENTICATOR>_SECRET_FILE`: Path to a file whose contents are the secret for an authenticator during `login` (for example `IDSEC_ISP_SECRET_FILE`). Preferred over `IDSEC_<AUTHENTICATOR>_SECRET` because the secret can live in a `0600` file instead of the environment. A single trailing newline is stripped. If both are set, the literal `IDSEC_<AUTHENTICATOR>_SECRET` wins; a configured-but-unreadable file is a hard error rather than a silent fallback.
- `IDSEC_CREDENTIALS_FILE`: Path to an `.idsecrc` credentials file used by `login`. Overrides auto-discovery. See [Credentials file](credentials_file.md).
- `IDSEC_LOG_LEVEL`: Sets the logging level for the CLI. Possible values include `DEBUG`, `INFO`, `WARNING`, `ERROR`, and `CRITICAL`. The default level is `CRITICAL`.
- `IDSEC_DISABLE_CERTIFICATE_VERIFICATION`: If set to `true`, disables SSL certificate verification for HTTPS requests. This is not recommended for production environments.
- `IDSEC_DISABLE_TELEMETRY_COLLECTION`: If set to `true`, disables telemetry data collection.
- `IDSEC_BASIC_KEYRING`: If set to `true`, uses a basic keyring for storing sensitive information instead of the system's secure storage.
- `IDSEC_KEYRING_FOLDER`: Specifies a custom folder path for the basic keyring storage when `IDSEC_BASIC_KEYRING` is enabled.
- `IDSEC_KEYRING_KEY_FILE`: Specifies a custom path for the file holding the key material that protects the basic keyring storage. It defaults to `$HOME/.idsec/keys/keyring.key` and is set independently of `IDSEC_KEYRING_FOLDER`, which does not relocate this file.
- `IDSEC_SUPPRESS_UPGRADE_CHECK`: If set to `true`, suppresses the automatic upgrade check when running Idsec commands.
- `IDSEC_PROXY_ADDRESS`: Specifies the proxy address to be used by the CLI for all requests.
- `IDSEC_PROXY_USERNAME`: Specifies the username for proxy authentication.
- `IDSEC_PROXY_PASSWORD`: Specifies the password for proxy authentication.
- `HTTP_PROXY`: Sets the HTTP proxy for all HTTP requests.
- `HTTPS_PROXY`: Sets the HTTPS proxy for all HTTPS requests.
- `NO_PROXY`: A comma-separated list of hostnames that should bypass the proxy.
