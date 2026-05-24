![Idsec CLI Golang](https://github.com/cyberark/idsec-cli-golang/blob/main/assets/cli.png)

<p align="center">
    <a alt="Go Version">
        <img src="https://img.shields.io/github/go-mod/go-version/cyberark/idsec-cli-golang" />
    </a>
    <a href="https://github.com/cyberark/idsec-cli-golang/blob/main/LICENSE.txt" alt="License">
        <img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License" />
    </a>
</p>

Idsec CLI Golang
==============

CyberArk's Official Command-Line Interface for Identity Security Platform operations

Installation
============

Install the CLI via go modules. For private repositories, configure Git credentials:

```shell
# Requires Go 1.24+ and git 2.24+
export GOPRIVATE=github.com
git config --global url."https://<username>:<token>@github.com".insteadOf "https://github.com"
go install github.com/cyberark/idsec-cli-golang/cmd/idsec@latest
```

Docker
------

A pre-built `linux/amd64` image is published to Docker Hub at [`cyberark/idsec-cli-golang`](https://hub.docker.com/r/cyberark/idsec-cli-golang). Pin a specific version for reproducible installs:

```shell
docker pull cyberark/idsec-cli-golang:<version>   # e.g. 1.2.3
```

The image's `ENTRYPOINT` is `idsec` and its working directory is `/data`, so files in the directory you launch from are reachable as `./<filename>`. Mount `~/.idsec` to persist profiles and the keyring between runs:

```shell
docker run --rm -it \
  -v "$(pwd):/data" \
  -v "$HOME/.idsec:/idsec" \
  cyberark/idsec-cli-golang:<version> \
  configure
```

CLI Usage
============
Both the SDK and the CLI works with profiles

The profiles can be configured upon need and be used for the consecutive actions

The CLI has the following basic commands:
- <b>configure</b> - Configures profiles and their respective authentication methods
- <b>login</b> - Logs into the profile authentication methods
- <b>exec</b> - Executes different commands based on the supported services
- <b>profiles</b> - Manage multiple profiles on the machine
- <b>cache</b> - Manage the cache of the authentication methods
- <b>upgrade</b> - Upgrade the CLI to the latest version
- <b>version</b> - Print the Idsec CLI version


configure
---------
The configure command is used to create a profile to work on<br>
The profile consists of infomration regarding which authentication methods to use and what are their method settings, along with other related information such as MFA

How to run:
```shell
idsec configure
```


The profiles are saved to ~/.idsec/profiles

No arguments are required, and interactive questions will be asked

If you wish to only supply arguments in a silent fashion, --silent can be added along with the arugments

Usage:
```shell
Configure the CLI

Usage:
  idsec configure [flags]

Flags:
      --allow-output                                    Allow stdout / stderr even when silent and not interactive
      --disable-cert-verification                       Disables certificate verification on HTTPS calls, unsafe!
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
      --pvwa-login-method string                        PVWA Login Method [cyberark, ldap, windows]
      --pvwa-url string                                 PVWA Base URL
      --pvwa-username string                            Username
      --raw                                             Whether to raw output
      --silent                                          Silent execution, no interactiveness
      --trusted-cert string                             Certificate to use for HTTPS calls
      --verbose                                         Whether to verbose log
      --work-with-isp                                   Whether to work with Identity Security Platform services
      --work-with-pvwa                                  Whether to work with Password Vault Web Access services
```


login
-----
The login command is used to login to the authentication methods configured for the profile

You will be asked to write a password for each respective authentication method that supports password, and alongside that, any needed MFA prompt

Once the login is done, the access tokens are stored on the computer keystore for their lifetime

Once they are expired, a consecutive login will be required

How to run:
```shell
idsec login
```

Usage:
```shell
Login to the system

Usage:
  idsec login [flags]

Flags:
      --allow-output                Allow stdout / stderr even when silent and not interactive
      --disable-cert-verification   Disables certificate verification on HTTPS calls, unsafe!
      --force                       Whether to force login even though token has not expired yet
  -h, --help                        help for login
      --isp-secret string           Secret to authenticate with to Identity Security Platform
      --isp-username string         Username to authenticate with to Identity Security Platform
      --pvwa-secret string          Secret to authenticate with to Password Vault Web Access
      --pvwa-username string        Username to authenticate with to Password Vault Web Access
      --log-level string            Log level to use while verbose (default "INFO")
      --logger-style string         Which verbose logger style to use (default "default")
      --no-shared-secrets           Do not share secrets between different authenticators with the same username
      --profile-name string         Profile name to load (default "idsec")
      --raw                         Whether to raw output
      --refresh-auth                If a cache exists, will also try to refresh it
      --show-tokens                 Print out tokens as well if not silent
      --silent                      Silent execution, no interactiveness
      --trusted-cert string         Certificate to use for HTTPS calls
      --verbose                     Whether to verbose log
```

Notes:

- You may disable certificate validation for login to different authenticators using the --disable-certificate-verification or supply a certificate to be used, not recommended to disable


exec
----
The exec command is used to execute various commands based on supported services for the fitting logged in authenticators

The following services and commands are supported:
- <b>sia</b> - Secure Infrastructure Access Services
  - <b>sso</b> - SIA SSO Management
  - <b>k8s</b> - SIA K8S Management
  - <b>db</b> - SIA DB Management
  - <b>workspaces-db</b> - SIA DB Workspaces Management
  - <b>workspaces-target-sets</b> - SIA VM Target Sets Management
  - <b>secrets-db</b> - SIA DB Secrets Management
  - <b>secrets-vm</b> - SIA VM Secrets Management
  - <b>access</b> - SIA Access Management
  - <b>ssh-ca</b> - SIA SSH Ca Key Management
  - <b>settings</b> - SIA Settings Management
  - <b>certificates</b> - SIA Certificates Management
- <b>cmgr</b> - Connector Manager
- <b>pcloud</b> - PCloud Service
  - <b>accounts</b> - PCloud Accounts Management
  - <b>safes</b> - PCloud Safes Management
  - <b>applications</b> - PCloud Applications Management
- <b>identity</b> - Identity Service
  - <b>directories</b> - Identity Directories Management
  - <b>roles</b> - Identity Roles Management
  - <b>users</b> - Identity Users Management
  - <b>auth-profiles</b> - Identity Auth Profiles Management
  - <b>policies</b> - Identity Policies Management
- <b>policy</b> - Access Control Policies Services
  - <b>cloud-access</b> - secure cloud access policies management
  - <b>db</b> - databases access policies management
  - <b>vm</b> - virtual machines access policies management

Any command has its own subcommands, with respective arguments

For example, generating a short lived password for DB
```shell
idsec exec sia sso short-lived-password
```

Or a short lived password for RDP
```shell
idsec exec sia sso short-lived-password --service DPA-RDP
```

Add SIA VM Target Set
```shell
idsec exec sia workspaces-target-sets create --name mydomain.com --type Domain
```

Add SIA VM Secret
```shell
idsec exec sia secrets-vm create --secret-type ProvisionerUser --provisioner-username=myuser --provisioner-password=mypassword
```

List connector pools
```shell
idsec exec exec cmgr pools list
```

Get connector installation script
```shell
idsec exec sia access connector-setup-script --connector-type ON-PREMISE --connector-os windows --connector-pool-id 588741d5-e059-479d-b4c4-3d821a87f012
```

Create a PCloud Safe
```shell
idsec exec pcloud safes create --safe-name=safe
```

Create a PCloud Account
```shell
idsec exec pcloud accounts create --name account --safe-name safe --platform-id='UnixSSH' --username root --address 1.2.3.4 --secret-type=password --secret mypass
```

Retrieve a PCloud Account Credentials
```shell
idsec exec pcloud accounts get-credentials --account-id 11_1
```

Create an Identity User
```shell
idsec exec identity users create --roles "DpaAdmin" --username "myuser"
```

Create an Identity service / oauth user
```shell
idsec exec identity users create-user --roles "DpaAdmin" --username "myuser" --is-service-user --is-oauth-client
```

Configure User Attributes Schema
```shell
idsec exec identity users upsert-attributes-schema --columns '[{"name": "department_attr1", "Title": "department_attr1", "Type": "Text", "Description": "Department attribute 1"}, {"name": "location_attr2", "Title": "location_attr2", "Type": "Text", "Description": "Location attribute 2"}]'
```

Remove User Attributes Schema Columns
```shell
idsec exec identity users delete-attributes-schema --column-names department_attr1,location_attr2
```

Get User Attributes Schema
```shell
idsec exec identity users attributes-schema
```

Set User Attributes
```shell
idsec exec identity users upsert-attributes --user-id 692d75bf-a7a5-4abe-8e37-7056d3337beb --attributes department_attr1:engineering --attributes location_attr2:NYC
```

Remove User Attributes
```shell
idsec exec identity users delete-attributes --user-id 692d75bf-a7a5-4abe-8e37-7056d3337beb --attribute-names department_attr1,location_attr2
```

Get User Attributes
```shell
idsec exec identity users get-attributes --user-id 692d75bf-a7a5-4abe-8e37-7056d3337beb
```

Create an Identity Role
```shell
idsec exec identity roles create-role --role-name myrole
```

List all directories identities
```shell
idsec exec identity directories list-entities
```

Add SIA Database Strong Account
```shell
idsec exec sia db-strong-accounts create --store-type managed --name "my-postgres-account" --platform PostgreSQL --address "db.example.com" --username "dbuser" --port 5432 --database "mydb" --password "mypassword"
```

Delete SIA Database Secret
```shell
idsec exec sia secrets-db delete --secret-name mysecret
```

Add SIA database
```shell
idsec exec sia workspaces-db create --name mydatabase --provider-engine aurora-mysql --read-write-endpoint myrds.com
```

Delete SIA database
```shell
idsec exec sia workspaces-db delete --id databaseid
```

List all SIA Settings
```shell
idsec exec sia settings list-settings
```

Get specific SIA setting
```shell
idsec exec sia settings adb-mfa-caching
```

Set specific SIA setting
```shell
idsec exec sia settings set-rdp-mfa-caching --is-mfa-caching-enabled=true --client-ip-enforced=false
```

Get Secrets Hub Configuration
```shell
idsec exec sechub configurations get
```
Update Secrets Hub Configuration
```shell
idsec exec sechub configurations update --sync-settings 360
```

Get Secrets Hub Filters
```shell
idsec exec sechub filters get --store-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667
```
Add Secrets Hub Filter
```shell
idsec exec sechub filters create --type "PAM_SAFE" --store-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667 --data-safe-name "example-safe"
```
Delete Secrets Hub Filter
```shell
idsec exec sechub filters delete --filter-id filter-7f3d187d-7439-407f-b968-ec27650be692 --store-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667
```

Get Secrets Hub Scans
```shell
idsec exec sechub scans get
```
Trigger Secrets Hub Scan
```shell
idsec exec sechub scans trigger --id default --secret-stores-ids store-e488dd22-a59c-418c-bbe3-3f061dd9b667 type secret-store
```

Create Secrets Hub Secret Store
```shell
idsec exec sechub secret-stores create --type AWS_ASM --description sdk-testing --name "SDK Testing" --state ENABLED --data-aws-account-alias ALIAS-NAME-EXAMPLE --data-aws-region-id us-east-1 --data-aws-account-id 123456789123 --data-aws-rolename Secrets-Hub-IAM-Role-Name-Created-For-Secrets-Hub
```
Retrieve Secrets Hub Secret Store
```shell
idsec exec sechub secret-stores get --secret-store-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667
```
Update Secrets Hub Secret Store
```shell
idsec exec sechub secret-stores update --secret-store-id store-7f3d187d-7439-407f-b968-ec27650be692 --name "New Name" --description "Updated Description" --data-aws-account-alias "Test2"
```
Delete Secrets Hub Secret Store
```shell
idsec exec sechub secret-stores delete --secret-store-id store-fd11bc7c-22d0-4d9b-ac1b-f8458161935f
```

Get Secrets Hub Secrets
```shell
idsec exec sechub secrets get-secrets
```
Get Secrets Hub Secrets using a filter
```shell
idsec exec sechub secrets get-secrets-by --limit 5 --projection EXTEND --filter "name CONTAINS EXAMPLE"
```

Get Secrets Hub Service Information
```shell
idsec exec sechub service-info get
```

List Secrets Hub Sync Policies
```shell
idsec exec sechub sync-policies list
```
Get Secrets Hub Sync Policy
```shell
idsec exec sechub sync-policies get --policy-id policy-7f3d187d-7439-407f-b968-ec27650be692 --projection EXTEND
```
Create Secrets Hub Sync Policy
```shell
idsec exec sechub sync-policies create --name "New Sync Policy" --description "New Sync Policy Description" --filter-type PAM_SAFE --filter-data-safe-name EXAMPLE-SAFE-NAME --source-id store-e488dd22-a59c-418c-bbe3-3f061dd12367 --target-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667
```
Delete Secrets Hub Sync Policy
```shell
idsec exec sechub sync-policies delete --policy-id policy-7f3d187d-7439-407f-b968-ec27650be692
```

List Sessions
```shell
idsec exec sm sessions list
```

Count Sessions
```shell
idsec exec sm sessions count
```

List Sessions By Filter
```shell
idsec exec sm sessions list-by --search "duration LE 01:00:00"
```

Count Sessions By Filter
```shell
idsec exec sm sessions count-by --search "command STARTSWITH ls"
```

Get Session
```shell
idsec exec sm sessions get --session-id my-id
```

Get Sessions Statistics
```shell
idsec exec sm sessions stats
```

List Session Activities
```shell
idsec exec sm session-activities list --session-id my-id
```

Count Session Activities
```shell
idsec exec sm session-activities count --session-id my-id
```

List Session Activities By Filter
```shell
idsec exec sm session-activities list-by --session-id my-id --command-contains "ls"
```

Count Session Activities By Filter
```shell
idsec exec sm session-activities count-by --session-id my-id --command-contains "chmod"
```

List all policies
```shell
idsec exec policy list-policies
```

Delete DB Policy
```shell
idsec exec policy db delete-policy --policy-id my-policy-id
```

List DB Policies
```shell
idsec exec policy db list-policies
```

Get DB Policy
```shell
idsec exec policy db policy --policy-id my-policy-id
```

Create DB Policy
```shell
idsec exec policy db create-policy --request-file /path/to/policy-request.json
```

List Cloud Access Policies
```shell
idsec exec policy cloud-access list-policies
```

Get Cloud Access Policy
```shell
idsec exec policy cloud-access policy --policy-id my-policy-id
```

Create Cloud Access Policy
```shell
idsec exec policy cloud-access create-policy --request-file /path/to/policy-request.json
```

Delete Cloud Access Policy
```shell
idsec exec policy cloud-access delete-policy --policy-id my-policy-id
```

List VM Policies
```shell
idsec exec policy vm list-policies
```

Get VM Policy
```shell
idsec exec policy vm policy --policy-id my-policy-id
```

Delete VM Policy
```shell
idsec exec policy vm delete-policy --policy-id my-policy-id
```

Connect to MySQL ZSP with the mysql cli via Idsec CLI
```shell
idsec exec sia db mysql --target-address myaddress.com
```

Connect to PostgreSQL Vaulted with the psql cli via Idsec CLI
```shell
idsec exec sia db psql --target-address myaddress.com --target-user myuser
```

Generate a connection string alias for a given raw connection string
```shell
idsec exec sia shortened-connection-string generate --raw-connection-string=jack.sparrow@caribbean.airlines#caribbean-airlines@the.black.pearl.com103639
```

Install SIA SSH public key on a target machine
```shell
idsec exec sia ssh-ca install-public-key --private-key-path /path/to/key.pem --target-machine 1.1.1.1 --username user
```

Remove SIA SSH public key from a target machine
```shell
idsec exec sia ssh-ca uninstall-public-key --private-key-path /path/to/key.pem --target-machine 1.1.1.1 --username user
```

Check if SIA SSH public key is installed on a target machine
```shell
idsec exec sia ssh-ca is-public-key-installed --private-key-path /path/to/key.pem --target-machine 1.1.1.1 --username user
```

Add a SIA certificate
```shell
idsec exec sia certificates create --cert-name name --cert-type PEM --file /path/to/cert.crt
```

Update a SIA certificate
```shell
idsec exec sia certificates update --certificate-id cert-id --cert-name new-name --file /path/to/new-cert.crt
```

List all SIA certificates
```shell
idsec exec sia certificates list
```

Import a pCloud Platform
```shell
idsec exec pcloud platforms import --platform-zip-path /path/to/zip
```

Import a pCloud Target Platform
```shell
idsec exec pcloud target-platforms import --platform-zip-path /path/to/zip
```

Export a pCloud Platform
```shell
idsec exec pcloud platforms export --platform-id myid --output-folder /path/to/folder
```

Export a pCloud Target Platform
```shell
idsec exec pcloud target-platforms export --target-platform-id 123 --output-folder /path/to/folder
```

List pCloud Target Platforms
```shell
idsec exec pcloud target-platforms list
```

Activate a pCloud Target Platform
```shell
idsec exec pcloud target-platforms activate --target-platform-id 123
```

Deactivate a pCloud Target Platform
```shell
idsec exec pcloud target-platforms deactivate --target-platform-id 123
```

Delete a pCloud Target Platform
```shell
idsec exec pcloud target-platforms delete --target-platform-id 123
```

Create an Identity Auth Profile
```shell
idsec exec identity auth-profiles create-auth-profile --auth-profile-name myprofile --first-challenges UP --second-challenges EMAIL,OTP
```

List Identity Auth Profiles
```shell
idsec exec identity auth-profiles list-auth-profiles
```

Delete an Identity Auth Profile
```shell
idsec exec identity auth-profiles delete-auth-profile --auth-profile-id ab75c8da-b04b-4c6e-9b6e-165e36c24018
```

Create an Identity Policy
```shell
idsec exec identity policies create-policy --policy-name mypolicy --auth-profile-name "myprofile"
```

List Identity Policies
```shell
idsec exec identity policies list-policies
```

Make an Identity Policy Inactive
```shell
idsec exec identity policies update-policy --policy-name mypolicy --policy-status Inactive
```

Delete an Identity Policy
```shell
idsec exec identity policies delete-policy --policy-name mypolicy
```

Create a pCloud Application
```shell
idsec exec pcloud applications create --app-id myapp --business-owner-f-name "user" --business-owner-l-name "name" --business-owner-email user@name.com
```

List pCloud Applications
```shell
idsec exec pcloud applications list
```

Delete pCloud Application
```shell
idsec exec pcloud applications delete --app-id myapp
```

Create a pCloud Application Auth Method
```shell
idsec exec pcloud applications create-auth-method --app-id myapp --auth-type hash --auth-value myhash --comment mycomment
```

Delete a pCloud Application Auth Method
```shell
idsec exec pcloud applications delete-auth-method --app-id myapp --auth-id 1
```

You can view all of the commands via the --help for each respective exec action

Notes:

- You may disable certificate validation for login to different authenticators using the --disable-certificate-verification or supply a certificate to be used, not recommended to disable


Useful Env Vars:
- IDSEC_PROFILE - Sets the profile to be used across the CLI
- IDSEC_DISABLE_CERTIFICATE_VERIFICATION - Disables certificate verification on REST API's


profiles
-------
As one may have multiple environments to manage, this would also imply that multiple profiles are required, either for multiple users in the same environment or multiple tenants

Therefore, the profiles command manages those profiles as a convenient set of methods

Using the profiles as simply running commands under:
```shell
idsec profiles
```

Usage:
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
      --disable-telemetry           Disables telemetry data collection
  -h, --help                        help for profiles
      --log-level string            Log level to use while verbose (default "INFO")
      --logger-style string         Which verbose logger style to use (default "default")
      --raw                         Whether to raw output
      --silent                      Silent execution, no interactiveness
      --trusted-cert string         Certificate to use for HTTPS calls
      --verbose                     Whether to verbose log

Use "idsec profiles [command] --help" for more information about a command.
```


cache
-------
Use the cache command to manage the Idsec data cached on your machine. Currently, you can only clear the filesystem cache (not data cached in the OS's keystore).


Using the cache as simply running commands under:
```shell
idsec cache
```

Usage:
```shell
Manage cache

Usage:
  idsec cache [command]

Available Commands:
  clear       Clears all profiles cache

Flags:
      --allow-output                Allow stdout / stderr even when silent and not interactive
      --disable-cert-verification   Disables certificate verification on HTTPS calls, unsafe!
  -h, --help                        help for cache
      --log-level string            Log level to use while verbose (default "INFO")
      --logger-style string         Which verbose logger style to use (default "default")
      --raw                         Whether to raw output
      --silent                      Silent execution, no interactiveness
      --trusted-cert string         Certificate to use for HTTPS calls
      --verbose                     Whether to verbose log

Use "idsec cache [command] --help" for more information about a command.
```


upgrade
-------

Use the `upgrade` command to upgrade to the latest idsec version or check what is the latest.

Using the upgrade as simply running:
```shell
idsec upgrade
```

Usage:
```shell
Manage upgrades

Usage:
  idsec upgrade [flags]

Flags:
      --allow-output                Allow stdout / stderr even when silent and not interactive
      --disable-cert-verification   Disables certificate verification on HTTPS calls, unsafe! Avoid using in production environments!
      --dry-run                     Whether to dry run
  -h, --help                        help for upgrade
      --log-level string            Log level to use while verbose (default "INFO")
      --logger-style string         Which verbose logger style to use (default "default")
      --raw                         Whether to raw output
      --silent                      Silent execution, no interactiveness
      --suppress-version-check      Whether to suppress version check
      --trusted-cert string         Certificate to use for HTTPS calls
      --verbose                     Whether to verbose log
      --version string              Version to upgrade to (default: latest)
```


version
-------

Use the `version` command to print the Idsec CLI version and build metadata embedded into the binary at build time.

Run:
```shell
idsec version
```

The default output prints a multi-line block of build metadata, for example:
```text
Idsec v0.3.1
Build Number: 3
Build Date: 2026-05-20T13:31:52Z
Git Commit: 8e682dc6b01ac408b1e66f0162809bd877a496cc
Git Branch: main
```

For machine-readable output (raw semantic version, without the `Idsec ` or leading `v` prefix), suitable for shell scripting:
```shell
idsec version --silent
```

This prints just the bare version on a single line, e.g.:
```text
0.3.1
```


Configuration File
==================

The CLI supports an optional YAML configuration file that sets default values for environment variables. This is useful for persisting settings across sessions without exporting environment variables in your shell profile.

### File Location

The default configuration file path is `~/.idsec/config.yaml`. You can override this with:

1. The `--config` flag (highest priority)
2. The `IDSEC_CONFIG_FILE` environment variable
3. The default path `~/.idsec/config.yaml`

```shell
# Use a custom config file for a single command
idsec --config /path/to/my-config.yaml login

# Or set the env var once in your shell profile
export IDSEC_CONFIG_FILE=/path/to/my-config.yaml
```

### File Format

Keys are the full `IDSEC_*` environment variable names. Any key that does not start with `IDSEC_` is ignored with a warning.

```yaml
# ~/.idsec/config.yaml

# Logging
IDSEC_FILE_LOG_PATH: /var/log/idsec/cli.log
IDSEC_FILE_LOG_LEVEL: DEBUG
IDSEC_LOG_LEVEL: INFO

# Profile
IDSEC_PROFILE: myprofile
IDSEC_PROFILES_FOLDER: /custom/profiles

# Security
IDSEC_DISABLE_CERTIFICATE_VERIFICATION: true
IDSEC_EXTRA_TRUSTED_CA_CERTS_BUNDLE_PATH: /path/to/ca-bundle.pem

# Proxy
IDSEC_PROXY_ADDRESS: http://proxy.corp:8080
IDSEC_PROXY_USERNAME: user
IDSEC_PROXY_PASSWORD: secret

# Keyring
IDSEC_BASIC_KEYRING: true
IDSEC_KEYRING_FOLDER: /custom/keyring

# Telemetry
IDSEC_DISABLE_TELEMETRY_COLLECTION: true

# Upgrade
IDSEC_SUPPRESS_UPGRADE_CHECK: true
```

### Precedence

Settings are resolved in the following order (highest priority first):

| Priority | Source | Example |
| :--- | :--- | :--- |
| 1 | CLI flags | `--verbose`, `--log-level DEBUG` |
| 2 | Environment variables | `export IDSEC_FILE_LOG_LEVEL=DEBUG` |
| 3 | Configuration file | `IDSEC_FILE_LOG_LEVEL: DEBUG` in `config.yaml` |
| 4 | Built-in defaults | `INFO` for file log level |

This means environment variables always override the config file, and CLI flags always override both.

### Accepted Keys

Two kinds of keys are accepted:

1. **Any key starting with `IDSEC_`** — exported as the matching environment variable. There is no fixed whitelist; every current and future `IDSEC_*` variable consumed by the CLI or SDK can be set from the file.
2. **Standard proxy variables** — `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` and their lowercase forms (`http_proxy`, `https_proxy`, `no_proxy`). These are honored directly by Go's `net/http` package.

Any other key is ignored with a warning.

For a list of `IDSEC_*` variables actually read by the CLI and SDK, run `idsec --help` or refer to the SDK documentation. Common examples:

```yaml
IDSEC_PROFILE: myprofile
IDSEC_FILE_LOG_LEVEL: DEBUG
IDSEC_PROXY_ADDRESS: http://proxy.corp:8080
IDSEC_DISABLE_TELEMETRY_COLLECTION: true

HTTPS_PROXY: http://proxy.corp:8080
NO_PROXY: localhost,127.0.0.1
```

### Security Note

If your configuration file contains sensitive values (e.g., `IDSEC_PROXY_PASSWORD`), ensure the file has restrictive permissions:

```shell
chmod 600 ~/.idsec/config.yaml
```

File Logging
============

The CLI automatically writes log output to a file on disk, independent of stdout logging. This provides a persistent record of CLI operations for debugging and auditing.

### Default Behavior

File logging is enabled by default when using the CLI. No configuration is needed.

| Setting | Default |
| :--- | :--- |
| Log file path | `~/.idsec/logs/idsec-cli.log` |
| Log level | `INFO` |
| Max file size | 50 MB |
| Backup history | 5 rotated files |
| File permissions | `0600` (owner read/write only) |
| Directory permissions | `0700` (owner only) |

### Environment Variables

Both settings can be overridden via environment variables:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `IDSEC_FILE_LOG_PATH` | Path to the log file. | `~/.idsec/logs/idsec-cli.log` |
| `IDSEC_FILE_LOG_LEVEL` | Minimum level to write to file (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). Set to `none` or `off` to disable file logging. | `INFO` |

Example -- disable file logging:
```shell
export IDSEC_FILE_LOG_LEVEL=off
```

Example -- write DEBUG-level logs to a custom path:
```shell
export IDSEC_FILE_LOG_PATH=/var/log/idsec/cli.log
export IDSEC_FILE_LOG_LEVEL=DEBUG
idsec login --profile-name myprofile
```

### Independence from Stdout

File logging and stdout logging are fully independent:

- **Stdout** is controlled by `--verbose`, `--log-level`, and `IDSEC_LOG_LEVEL`. Without `--verbose`, stdout is silent.
- **File** is controlled by `IDSEC_FILE_LOG_PATH` and `IDSEC_FILE_LOG_LEVEL`. It always writes regardless of `--verbose`.

This means you can keep stdout silent while still capturing detailed logs to the file:
```shell
# No --verbose: stdout is silent, but file still captures INFO+ logs
idsec exec pcloud safes list
cat ~/.idsec/logs/idsec-cli.log
```

### Credential Sanitization

Sensitive values are automatically redacted in file logs. Fields such as `password`, `secret`, `token`, `private_key`, `authorization`, and AWS credential fields are replaced with `[REDACTED]` before being written to disk. Stdout output is not sanitized.

### Log Rotation

When the log file exceeds 50 MB, it is rotated automatically:

```
~/.idsec/logs/idsec-cli.log      (current)
~/.idsec/logs/idsec-cli.log.1    (previous)
~/.idsec/logs/idsec-cli.log.2
~/.idsec/logs/idsec-cli.log.3
~/.idsec/logs/idsec-cli.log.4
~/.idsec/logs/idsec-cli.log.5    (oldest, removed on next rotation)
```

## Development Guidelines

### CLI Command Structure

To maintain a consistent and predictable user experience across the Idsec CLI, all commands must adhere to the following structural and naming conventions.

#### Command Hierarchy

The command hierarchy is strictly defined as **Service** → **Resource** → **Action**.

**Syntax:**
```bash
idsec <service> <resource> <action> [flags/parameters]
```

**Definitions:**
- **Service:** The high-level product or domain (e.g., `pcloud`, `cmgr`, `sia`).
- **Resource:** The specific entity being manipulated (e.g., `safes`, `networks`, `pools`). Plural nouns are preferred for resources.
- **Action:** The operation to perform on the resource (e.g., `create`, `list`, `delete`).

#### Resource & Action Separation

Do not repeat the resource name inside the action name. The context is provided by the resource command that precedes it.

**Examples:**
- ❌ **Bad:** `idsec pcloud safes create-safe` (Redundant)
- ✅ **Good:** `idsec pcloud safes create` (Clean)

#### Standard Actions & Verbs

To prevent confusion (e.g., users guessing between "remove", "delete", or "destroy"), use the following standard verbs for common CRUD operations:

| Intent | Canonical Verb | Accepted Aliases | Description |
| :--- | :--- | :--- | :--- |
| **Create** | `create` | `add` | Creates a new resource. |
| **Read Many** | `list` | `ls` | Returns a list of resources. Should support filtering. |
| **Read One** | `get` | `read` | Returns details of a specific resource. Usually requires an ID or name. |
| **Update** | `update` | `edit` | Modifies an existing resource. |
| **Delete** | `delete` | `rm` | Permanently removes a resource. |

#### Command Examples

**Creating a Safe:**
```bash
# Correct
idsec pcloud safes create --safe-name="MySafe"

# Incorrect (Redundant naming)
idsec pcloud safes create-safe --safe-name="MySafe"
```

**Listing connector pools:**
```bash
# Correct
idsec cmgr pools list

# Incorrect (Wrong hierarchy)
idsec cmgr list-pools
```

### Adding an Action to an Existing Resource

This guide walks through adding a new action to a resource that already exists (e.g., adding `get-credentials` to `pcloud/accounts`). The process involves changes in both the **SDK** (`idsec-sdk-golang`) and the **CLI** (`idsec-cli-golang`) repositories.

#### Architecture Overview

The CLI uses a reflection-based execution model. When a user runs:

```bash
idsec exec pcloud accounts get-credentials --account-id 11_1
```

The CLI resolves this as a method chain via reflection:

```
api.Pcloud() → .Accounts() → .GetCredentials(input)
```

The action name `get-credentials` is converted to the method name `GetCredentials` (hyphens removed, TitleCase). The `--account-id` flag is parsed from the model struct's `flag` tag and populated into the input struct.

Here is how the pieces fit together across both repos:

```
idsec-sdk-golang                              idsec-cli-golang
├── pkg/services/<svc>/<res>/                 ├── pkg/services/<svc>/<res>/
│   ├── models/                               │   └── actions/
│   │   └── request/response structs          │       └── *_cli_actions.go
│   ├── actions/                              │           (imports ActionToSchemaMap from SDK)
│   │   └── *_actions_schemas.go              │
│   │       (maps action names → model structs)│
│   ├── *_service.go                          │
│   │   └── API methods (Create, Get, etc.)   │
│   └── *_service_config.go                   │
│       └── service registration              │
```

The SDK owns the models, the service methods, and the `ActionToSchemaMap` that maps action names to model structs. The CLI imports `ActionToSchemaMap` from the SDK, so schema definitions are maintained in a single place.

**Key files you will touch:**

| File | Repo | Purpose |
| :--- | :--- | :--- |
| `pkg/services/<svc>/<res>/models/*.go` | SDK | Model struct defining the action's input parameters |
| `pkg/services/<svc>/<res>/*_service.go` | SDK | Method implementing the API call |
| `pkg/services/<svc>/<res>/actions/*_actions_schemas.go` | SDK | Maps the action name to the model struct (shared by CLI and Terraform) |

#### Step 1: Define the Model in the SDK

Create a model struct for the action's input parameters in the SDK's `models/` directory for the resource.

**File naming convention:** `idsec_<service>_<action_description>.go`

```go
// idsec-sdk-golang/pkg/services/pcloud/accounts/models/idsec_pcloud_get_account_credentials.go
package models

type IdsecPCloudGetAccountCredentials struct {
    AccountID string `json:"account_id,omitempty" mapstructure:"account_id" desc:"The account ID" flag:"account-id" validate:"required"`
    Reason    string `json:"reason,omitempty" mapstructure:"reason,omitempty" desc:"Reason for retrieving credentials" flag:"reason"`
}
```

Each field uses struct tags that control how it behaves across the system:

| Tag | Purpose | Example |
| :--- | :--- | :--- |
| `json` | JSON field name for the API request/response | `json:"account_id,omitempty"` |
| `mapstructure` | Field mapping for internal config parsing | `mapstructure:"account_id"` |
| `desc` | Description shown in CLI `--help` output | `desc:"The account ID"` |
| `flag` | CLI flag name (always use kebab-case) | `flag:"account-id"` |
| `validate` | Validation rules, checked before execution | `validate:"required"` |
| `default` | Default value applied when flag is not provided | `default:"false"` |

If the action takes **no parameters** (e.g., a simple `list`), skip this step — you'll use `nil` in the schema map.

You may also need a **response model** if the action returns data that needs to be structured (e.g., `IdsecPCloudAccountCredentials`). Response models typically only need `json` tags.

#### Step 2: Implement the Method in the SDK

Add the method to the existing service file. The method name **must** match the CLI action name converted to TitleCase with hyphens removed:

| CLI action name | SDK method name |
| :--- | :--- |
| `get-credentials` | `GetCredentials()` |
| `list-by` | `ListBy()` |
| `add-member` | `AddMember()` |
| `create` | `Create()` |
| `stats` | `Stats()` |

```go
// idsec-sdk-golang/pkg/services/pcloud/accounts/idsec_pcloud_accounts_service.go

func (s *IdsecPCloudAccountsService) GetCredentials(input *models.IdsecPCloudGetAccountCredentials) (*models.IdsecPCloudAccountCredentials, error) {
    url := fmt.Sprintf("%s/%s/credentials", accountsURL, input.AccountID)
    resp, err := s.client.Get(url, nil)
    if err != nil {
        return nil, err
    }
    var result models.IdsecPCloudAccountCredentials
    err = common.UnmarshalResponse(resp, &result)
    return &result, err
}
```

**Method signature rules:**
- The method receiver is on the existing service struct
- Input parameter: pointer to the model struct you defined in Step 1 (or no input for parameterless actions)
- Return: response struct pointer + error

#### Step 3: Add the Schema Mapping in the SDK

Edit the existing `actions_schemas.go` in the **SDK** repo and add a new entry to the `ActionToSchemaMap`:

```go
// idsec-sdk-golang/pkg/services/pcloud/accounts/actions/idsec_pcloud_accounts_actions_schemas.go

var ActionToSchemaMap = map[string]interface{}{
    "create":          &accountsmodels.IdsecPCloudAddAccount{},
    "get":             &accountsmodels.IdsecPCloudGetAccount{},
    // ... existing actions ...
    "get-credentials": &accountsmodels.IdsecPCloudGetAccountCredentials{},  // add this line
}
```

**Schema mapping rules:**
- The key is the action name as it appears in the CLI (kebab-case)
- The value is a pointer to an empty instance of the model struct
- Use `nil` for actions that take no parameters (e.g., `"list": nil`)
- The CLI framework automatically generates flags from the struct's `flag` tags, validates using `validate` tags, and populates the struct before calling the SDK method
- The `ActionToSchemaMap` is defined once in the SDK and imported by the CLI via an `sdkactions` alias

**No CLI changes are needed.** The action is automatically available because:
1. The resource is already registered in `pkg/registry/init.go`
2. The `CLIAction` already references `sdkactions.ActionToSchemaMap` (imported from the SDK)
3. Adding a new entry to the SDK's map is all it takes to expose a new action in the CLI

#### Step 4: Build and Verify

```bash
# In the CLI repo, update the SDK dependency to pick up the new action
go get github.com/cyberark/idsec-sdk-golang@<branch-or-commit>
go mod tidy

# Build the CLI
make all

# Check the new action appears in help
idsec exec pcloud accounts --help

# Inspect the generated flags
idsec exec pcloud accounts get-credentials --help

# Test the action
idsec exec pcloud accounts get-credentials --account-id 11_1
```

#### Summary

Adding an action to an existing resource is a 3-file change, all in the SDK:

1. **SDK** — model struct (`models/idsec_<svc>_<action>.go`)
2. **SDK** — service method (`*_service.go`)
3. **SDK** — one line in `ActionToSchemaMap` (`actions/*_actions_schemas.go`)

No changes to the CLI repo are required. The CLI imports `ActionToSchemaMap` from the SDK, so new actions are picked up automatically after updating the SDK dependency.

### Enable Attribute

The Enable attribute controls whether services and actions are available in the CLI. Use it to hide work-in-progress features from releases.

#### When to Use the Enable Attribute

- New services that are not ready for production
- Experimental actions that need more testing
- Features waiting for approval or documentation

#### How to Disable an Action

Set `Enabled` to `false` in the action definition. The action will be filtered out.

```go
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
    IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
        ActionName: "experimental-action",
        Enabled:    boolPtr(false),  // Will be filtered out
    },
}
```

#### Build Flag

The Enable attribute filtering is controlled by a build flag. By default, filtering is OFF and all services and actions are available.

**Default build (filtering OFF):**
```bash
go build ./...
```

**Release build (filtering ON):**
```bash
go build -ldflags "-X github.com/cyberark/idsec-sdk-golang/pkg/services.releasedFeaturesOnly=true" ./...
```

When filtering is ON, services and actions with `Enabled: false` are excluded.

#### Best Practices

1. Default is enabled. Omit the field or set it to `nil` for normal behavior.
2. Remove the attribute when the feature is ready. Do not leave disabled attributes in production code.
3. The Enable attribute is checked at startup. It cannot be changed at runtime.
4. Use the build flag to enable filtering for release builds.

## License

This project is licensed under Apache License 2.0 - see [`LICENSE`](LICENSE.txt) for more details

Copyright (c) 2026 CyberArk Software Ltd. All rights reserved.
