---
title: Commands examples
description: Commands Examples
---

# Commands examples

This page lists some useful CLI examples.

!!! note

    You can disable certificate validation for login to an authenticator using the `--disable-certificate-verification` flag. **This option is not recommended.**

    **Useful environment variables**

    - `IDSEC_PROFILE`: Sets the profile to be used across the CLI
    - `IDSEC_DISABLE_CERTIFICATE_VERIFICATION`: Disables certificate verification for REST APIs

## Configure command examples

The `configure` command works in interactive or silent mode. When using silent mode, the required parameters need to be specified.

### Configure ISP profile (silent mode)

```bash linenums="0"
idsec configure --profile-name="PROD" --work-with-isp --isp-username="tina@cyberark.cloud.12345" --silent --allow-output
```

### Configure PVWA profile (silent mode)

For self-hosted CyberArk deployments using Password Vault Web Access (PVWA):

```bash linenums="0"
idsec configure --profile-name="PVWA-PROD" --work-with-pvwa --pvwa-username="myuser" --pvwa-url="https://pvwa.example.com" --pvwa-login-method="ldap" --silent --allow-output
```

Available PVWA login methods:

- `cyberark` - CyberArk native authentication
- `ldap` - LDAP authentication
- `windows` - Windows authentication

## Login command examples

The login command can work in interactive or silent mode.

### Login with ISP credentials

```bash linenums="0"
idsec login -s --isp-secret=CoolPassword --profile-name PROD
```

### Login with PVWA credentials

```bash linenums="0"
idsec login -s --pvwa-secret=MyPassword --profile-name PVWA-PROD
```

## Exec command examples

Use the `--help` flag to view all `exec` options.

!!! tip "Shorthand"

    `exec` is the default command, so you can omit it and invoke services directly: `idsec sia sso short-lived-password` is equivalent to `idsec exec sia sso short-lived-password`.

### Generate a short-lived SSO password for a database connection
```shell linenums="0"
idsec sia sso short-lived-password
```

### Generate a short-lived SSO password for an RDP connection
```shell linenums="0"
idsec sia sso short-lived-password --service DPA-RDP
```

### Generate a short-lived SSO Oracle wallet for an Oracle database connection
```shell linenums="0"
idsec sia sso short-lived-oracle-wallet --folder ~/wallet
```

### Generate a kubectl config file
```shell linenums="0"
idsec sia k8s generate-kubeconfig
```

### Generate a kubectl config file and save it in the specified path
```shell linenums="0"
idsec sia k8s generate-kubeconfig --folder=/Users/My.User/.kube
```

### Add SIA VM target set
```shell linenums="0"
idsec sia workspaces-target-sets create --name mydomain.com --type Domain
```

### Add SIA VM secret
```shell linenums="0"
idsec sia secrets-vm create --secret-type ProvisionerUser --provisioner-username=myuser --provisioner-password=mypassword
```

### Generate new SSH CA key version
```shell linenums="0"
idsec sia ssh-ca generate-new-ca
```

### Deactivate previous SSH CA key version
```shell linenums="0"
idsec sia ssh-ca deactivate-previous-ca
```

### Reactivate previous SSH CA key version
```shell linenums="0"
idsec sia ssh-ca reactivate-previous-ca
```

### List CMGR connector pools
```shell linenums="0"
idsec cmgr pools list
```

### Add CMGR network
```shell linenums="0"
idsec cmgr networks create --name mynetwork
```

### Add CMGR connector pool
```shell linenums="0"
idsec cmgr pools create --name mypool --assigned-network-ids mynetwork_id
```

### Create a pCloud Safe
```shell linenums="0"
idsec pcloud safes create --safe-name=safe
```

### Create a pCloud account
```shell linenums="0"
idsec pcloud accounts create --name account --safe-name safe --platform-id='UnixSSH' --username root --address 1.2.3.4 --secret-type=password --secret mypass
```

### Retrieve a pCloud account credentials
```shell linenums="0"
idsec pcloud accounts get-credentials --account-id 11_1
```

### Create an Identity user
```shell linenums="0"
idsec identity users create --roles "DpaAdmin" --username "myuser"
```

### Create an Identity service / oauth user
```shell linenums="0"
idsec identity users create --roles "DpaAdmin" --username "myuser" --is-service-user --is-oauth-client
```

### Add SIA database strong account
```shell linenums="0"
idsec sia db-strong-accounts create --store-type managed --name "my-postgres-account" --platform PostgreSQL --address "db.example.com" --username "dbuser" --port 5432 --database "mydb" --password "mypassword"
```

### Delete SIA database secret
```shell linenums="0"
idsec sia secrets-db delete --secret-name mysecret
```

### Add SIA database
```shell linenums="0"
idsec sia workspaces-db create --name mydatabase --provider-engine aurora-mysql --read-write-endpoint myrds.com
```

### Delete SIA database
```shell linenums="0"
idsec sia workspaces-db delete --id databaseid
```

### List all SIA Settings
```shell linenums="0"
idsec sia settings list-settings
```

### Get specific SIA setting
```shell linenums="0"
idsec sia settings adb-mfa-caching
```

### Set specific SIA setting
```shell linenums="0"
idsec sia settings set-rdp-mfa-caching --is-mfa-caching-enabled=true --client-ip-enforced=false
```

### Get Secrets Hub Configuration
```shell linenums="0"
idsec sechub configurations get
```

### Update Secrets Hub Configuration
```shell linenums="0"
idsec sechub configurations update --sync-settings 360
```

### List all policies
```shell linenums="0"
idsec policy list-policies
```

### Delete DB Policy
```shell linenums="0"
idsec policy db delete-policy --policy-id my-policy-id
```

### List DB Policies
```shell linenums="0"
idsec policy db list-policies
```

### Get DB Policy
```shell linenums="0"
idsec policy db policy --policy-id my-policy-id
```

### Create DB Policy
```shell linenums="0"
idsec policy db create-policy --request-file /path/to/policy-request.json
```

### List Cloud Access Policies
```shell linenums="0"
idsec policy cloud-access list-policies
```

### Get Cloud Access Policy
```shell linenums="0"
idsec policy cloud-access policy --policy-id my-policy-id
```

### Create Cloud Access Policy
```shell linenums="0"
idsec policy cloud-access create-policy --request-file /path/to/policy-request.json
```

### Delete Cloud Access Policy
```shell linenums="0"
idsec policy cloud-access delete-policy --policy-id my-policy-id
```

### List VM Policies
```shell
idsec policy vm list-policies
```

### Get VM Policy
```shell
idsec policy vm policy --policy-id my-policy-id
```

### Delete VM Policy
```shell
idsec policy vm delete-policy --policy-id my-policy-id
```

### Connect to MySQL ZSP with the mysql cli via Idsec CLI
```shell linenums="0"
idsec sia db mysql --target-address myaddress.com
```

### Connect to PostgreSQL Vaulted with the psql cli via Idsec CLI
```shell linenums="0"
idsec sia db psql --target-address myaddress.com --target-user myuser
```

### Generate a connection string alias for a given raw connection string
```shell linenums="0"
idsec sia shortened-connection-string generate --raw-connection-string=jack.sparrow@caribbean.airlines#caribbean-airlines@the.black.pearl.com103639
```

### Install SIA SSH public key on a target machine
```shell linenums="0"
idsec sia ssh-ca install-public-key --private-key-path /path/to/key.pem --target-machine 1.1.1.1 --username user
```

### Remove SIA SSH public key from a target machine
```shell linenums="0"
idsec sia ssh-ca uninstall-public-key --private-key-path /path/to/key.pem --target-machine 1.1.1.1 --username user
```

### Check if SIA SSH public key is installed on a target machine
```shell linenums="0"
idsec sia ssh-ca is-public-key-installed --private-key-path /path/to/key.pem --target-machine 1.1.1.1 --username user
```

### Add a SIA certificate
```shell linenums="0"
idsec sia certificates create --cert-name name --cert-type PEM --file /path/to/cert.crt
```

### Update a SIA certificate
```shell linenums="0"
idsec sia certificates update --certificate-id cert-id --cert-name new-name --file /path/to/new-cert.crt
```

### List all SIA certificates
```shell linenums="0"
idsec sia certificates list
```

### Import a pCloud Platform
```shell linenums="0"
idsec pcloud platforms import --platform-zip-path /path/to/zip
```

### Import a pCloud Target Platform
```shell linenums="0"
idsec pcloud target-platforms import --platform-zip-path /path/to/zip
```

### Export a pCloud Platform
```shell linenums="0"
idsec pcloud platforms export --platform-id myid --output-folder /path/to/folder
```

### Export a pCloud Target Platform
```shell linenums="0"
idsec pcloud target-platforms export --target-platform-id 123 --output-folder /path/to/folder
```

### List pCloud Target Platforms
```shell linenums="0"
idsec pcloud target-platforms list
```

### Activate a pCloud Target Platform
```shell linenums="0"
idsec pcloud target-platforms activate --target-platform-id 123
```

### Deactivate a pCloud Target Platform
```shell linenums="0"
idsec pcloud target-platforms deactivate --target-platform-id 123
```

### Delete a pCloud Target Platform
```shell linenums="0"
idsec pcloud target-platforms delete --target-platform-id 123
```

### Create an Identity Auth Profile
```shell linenums="0"
idsec identity auth-profiles create-auth-profile --auth-profile-name myprofile --first-challenges UP --second-challenges EMAIL,OTP
```

### List Identity Auth Profiles
```shell linenums="0"
idsec identity auth-profiles list-auth-profiles
```

### Delete an Identity Auth Profile
```shell linenums="0"
idsec identity auth-profiles delete-auth-profile --auth-profile-id ab75c8da-b04b-4c6e-9b6e-165e36c24018
```

### Create an Identity Policy
```shell linenums="0"
idsec identity policies create-policy --policy-name mypolicy --auth-profile-name "myprofile"
```

### List Identity Policies
```shell linenums="0"
idsec identity policies list-policies
```

### Make an Identity Policy Inactive
```shell linenums="0"
idsec identity policies update-policy --policy-name mypolicy --policy-status Inactive
```

### Delete an Identity Policy
```shell linenums="0"
idsec identity policies delete-policy --policy-name mypolicy
```

### Set Identity Policy Order
```shell linenums="0"
idsec identity policies set-order --policy-names mypolicy1,mypolicy2,mypolicy3
```

### Move a policy to a specific place in the order before another policy
```shell linenums="0"
idsec identity policies update-policy --policy-name mypolicy --before-policy otherpolicy
```

### Move a policy to a specific place in the order after another policy
```shell linenums="0"
idsec identity policies update-policy --policy-name mypolicy --after-policy otherpolicy
```

### Create a pCloud Application
```shell linenums="0"
idsec pcloud applications create --app-id myapp --business-owner-f-name "user" --business-owner-l-name "name" --business-owner-email user@name.com
```

### List pCloud Applications
```shell linenums="0"
idsec pcloud applications list
```

### Delete pCloud Application
```shell linenums="0"
idsec pcloud applications delete --app-id myapp
```

### Create a pCloud Application Auth Method
```shell linenums="0"
idsec pcloud applications create-auth-method --app-id myapp --auth-type hash --auth-value myhash --comment mycomment
```

### Delete a pCloud Application Auth Method
```shell linenums="0"
idsec pcloud applications delete-auth-method --app-id myapp --auth-id 1
```

## Access Space examples

### List all accessible assets
```shell linenums="0"
idsec access assets list
```

### List only recently accessed assets
```shell linenums="0"
idsec access assets list-by --recents-only
```

### List only favorite assets
```shell linenums="0"
idsec access assets list-by --favorites-only
```

### List assets filtered by access method (vaulted or zsp)
```shell linenums="0"
idsec access assets list-by --access-method vaulted
```

### List assets with a keyword search and sort
```shell linenums="0"
idsec access assets list-by --search "address contains 10.0.0" --sort address.asc
```

### List assets with a result limit
```shell linenums="0"
idsec access assets list-by --limit 50
```

### Retrieve credentials for an asset
```shell linenums="0"
idsec access assets secret --asset-id your-asset-id
```

### Retrieve credentials with an audit reason
```shell linenums="0"
idsec access assets secret --asset-id your-asset-id --reason "Break-glass troubleshooting"
```

### List SCA cloud-access targets across all providers
```shell linenums="0"
idsec sca cloud-access list-targets
```

### List SCA cloud-access targets for a single provider
```shell linenums="0"
idsec sca cloud-access list-targets --csp aws
```

### List SCA cloud-access targets for GCP
```shell linenums="0"
idsec sca cloud-access list-targets --csp gcp
```

### Elevate into a single AWS account
Omit `--organization-id` — it is not relevant for single accounts. AWS accepts exactly one role ID per elevation.

```shell linenums="0"
idsec sca cloud-access elevate --csp aws --workspace-id 123456789012 --roleIds arn:aws:iam::123456789012:role/SCA-ReadOnly
```

### Elevate into an AWS account managed by an AWS organization
Add `--organization-id` with the AWS organization ID. `--workspace-id` remains the member account ID.

```shell linenums="0"
idsec sca cloud-access elevate --csp aws --workspace-id 210987654321 --organization-id o-a1b2c3d4e5 --roleIds arn:aws:iam::210987654321:role/SCA-PowerUser
```

### Elevate into an Azure resource scope
Works for a subscription, resource group, resource, or management group. `--organization-id` is the Entra tenant ID.

```shell linenums="0"
idsec sca cloud-access elevate --csp azure --workspace-id subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05 --organization-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --roleIds /providers/Microsoft.Authorization/roleDefinitions/3498e952-d568-435e-9b2c-8d77e338d7f7
```

### Elevate into an Azure resource scope with multiple roles
Azure accepts up to five role IDs per call, all applied to the same `--workspace-id`.

```shell linenums="0"
idsec sca cloud-access elevate --csp azure --workspace-id subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05 --organization-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --roleIds /providers/Microsoft.Authorization/roleDefinitions/3498e952-d568-435e-9b2c-8d77e338d7f7,/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7
```

### Elevate into a Microsoft Entra ID directory role
Directory role IDs are bare GUIDs. Pass the Entra directory (tenant) ID as both `--workspace-id` and `--organization-id`.

```shell linenums="0"
idsec sca cloud-access elevate --csp azure --workspace-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --organization-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --roleIds fe930be7-5e62-47db-91af-98c3a49a38b1
```

### Elevate into a GCP project
`--organization-id` is required for GCP and holds the GCP organization ID. GCP accepts up to five role IDs per call, all applied to the same `--workspace-id`.

```shell linenums="0"
idsec sca cloud-access elevate --csp gcp --workspace-id acme-prod-payments-458213 --organization-id 884271936502 --roleIds roles/iam.securityReviewer
```

### Elevate into a GCP project with multiple roles
```shell linenums="0"
idsec sca cloud-access elevate --csp gcp --workspace-id acme-prod-payments-458213 --organization-id 884271936502 --roleIds roles/iam.securityReviewer,roles/compute.admin
```

### List SCA group-access targets (Azure only)
```shell linenums="0"
idsec sca group-access list-targets --csp azure
```

### Elevate into one or more Microsoft Entra ID groups
Pass a comma-separated list of group object IDs (not display names), up to 5 per call. All groups must belong to the directory given by `--directory-id`.

```shell linenums="0"
idsec sca group-access elevate --csp azure --directory-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --groups 9d3b6f41-8c27-4e59-b1a0-5f7e2c84d913,1f8c5a20-4b76-49e3-9d82-6c015be7f4a9
```

!!! tip "Full SCA workflow"

    For the complete SCA workflow — reading `list-targets` output, per-provider flows, partial-success handling, and elevation limits — see [SCA commands in the idsec CLI](../howto/sca_native_cli.md).
