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

    You can omit `exec` and invoke services directly: `idsec sia sso short-lived-password` is equivalent to `idsec exec sia sso short-lived-password`.

### Generate a short-lived SSO password for a database connection
```shell linenums="0"
idsec exec sia sso short-lived-password
```

### Generate a short-lived SSO password for an RDP connection
```shell linenums="0"
idsec exec sia sso short-lived-password --service DPA-RDP
```

### Generate a short-lived SSO Oracle wallet for an Oracle database connection
```shell linenums="0"
idsec exec sia sso short-lived-oracle-wallet --folder ~/wallet
```

### Generate a kubectl config file
```shell linenums="0"
idsec exec sia k8s generate-kubeconfig
```

### Generate a kubectl config file and save it in the specified path
```shell linenums="0"
idsec exec sia k8s generate-kubeconfig --folder=/Users/My.User/.kube
```

### Add SIA VM target set
```shell linenums="0"
idsec exec sia workspaces-target-sets create --name mydomain.com --type Domain
```

### Add SIA VM secret
```shell linenums="0"
idsec exec sia secrets-vm create --secret-type ProvisionerUser --provisioner-username=myuser --provisioner-password=mypassword
```

### Generate new SSH CA key version
```shell linenums="0"
idsec exec sia ssh-ca generate-new-ca
```

### Deactivate previous SSH CA key version
```shell linenums="0"
idsec exec sia ssh-ca deactivate-previous-ca
```

### Reactivate previous SSH CA key version
```shell linenums="0"
idsec exec sia ssh-ca reactivate-previous-ca
```

### List CMGR connector pools
```shell linenums="0"
idsec exec cmgr pools list
```

### Add CMGR network
```shell linenums="0"
idsec exec cmgr networks create --name mynetwork
```

### Add CMGR connector pool
```shell linenums="0"
idsec exec cmgr pools create --name mypool --assigned-network-ids mynetwork_id
```

### Create a pCloud Safe
```shell linenums="0"
idsec exec pcloud safes create --safe-name=safe
```

### Create a pCloud account
```shell linenums="0"
idsec exec pcloud accounts create --name account --safe-name safe --platform-id='UnixSSH' --username root --address 1.2.3.4 --secret-type=password --secret mypass
```

### Retrieve a pCloud account credentials
```shell linenums="0"
idsec exec pcloud accounts get-credentials --account-id 11_1
```

### Create an Identity user
```shell linenums="0"
idsec exec identity users create --roles "DpaAdmin" --username "myuser"
```

### Create an Identity service / oauth user
```shell linenums="0"
idsec exec identity users create --roles "DpaAdmin" --username "myuser" --is-service-user --is-oauth-client
```

### Add SIA database strong account
```shell linenums="0"
idsec exec sia db-strong-accounts create --store-type managed --name "my-postgres-account" --platform PostgreSQL --address "db.example.com" --username "dbuser" --port 5432 --database "mydb" --password "mypassword"
```

### Delete SIA database secret
```shell linenums="0"
idsec exec sia secrets-db delete --secret-name mysecret
```

### Add SIA database
```shell linenums="0"
idsec exec sia workspaces-db create --name mydatabase --provider-engine aurora-mysql --read-write-endpoint myrds.com
```

### Delete SIA database
```shell linenums="0"
idsec exec sia workspaces-db delete --id databaseid
```

### List all SIA Settings
```shell linenums="0"
idsec exec sia settings list-settings
```

### Get specific SIA setting
```shell linenums="0"
idsec exec sia settings adb-mfa-caching
```

### Set specific SIA setting
```shell linenums="0"
idsec exec sia settings set-rdp-mfa-caching --is-mfa-caching-enabled=true --client-ip-enforced=false
```

### Get Secrets Hub Configuration
```shell linenums="0"
idsec exec sechub configurations get
```

### Update Secrets Hub Configuration
```shell linenums="0"
idsec exec sechub configurations update --sync-settings 360
```

### List all policies
```shell linenums="0"
idsec exec policy list-policies
```

### Delete DB Policy
```shell linenums="0"
idsec exec policy db delete-policy --policy-id my-policy-id
```

### List DB Policies
```shell linenums="0"
idsec exec policy db list-policies
```

### Get DB Policy
```shell linenums="0"
idsec exec policy db policy --policy-id my-policy-id
```

### Create DB Policy
```shell linenums="0"
idsec exec policy db create-policy --request-file /path/to/policy-request.json
```

### List Cloud Access Policies
```shell linenums="0"
idsec exec policy cloud-access list-policies
```

### Get Cloud Access Policy
```shell linenums="0"
idsec exec policy cloud-access policy --policy-id my-policy-id
```

### Create Cloud Access Policy
```shell linenums="0"
idsec exec policy cloud-access create-policy --request-file /path/to/policy-request.json
```

### Delete Cloud Access Policy
```shell linenums="0"
idsec exec policy cloud-access delete-policy --policy-id my-policy-id
```

### List VM Policies
```shell
idsec exec policy vm list-policies
```

### Get VM Policy
```shell
idsec exec policy vm policy --policy-id my-policy-id
```

### Delete VM Policy
```shell
idsec exec policy vm delete-policy --policy-id my-policy-id
```

### Connect to MySQL ZSP with the mysql cli via Idsec CLI
```shell linenums="0"
idsec exec sia db mysql --target-address myaddress.com
```

### Connect to PostgreSQL Vaulted with the psql cli via Idsec CLI
```shell linenums="0"
idsec exec sia db psql --target-address myaddress.com --target-user myuser
```

### Generate a connection string alias for a given raw connection string
```shell linenums="0"
idsec exec sia shortened-connection-string generate --raw-connection-string=jack.sparrow@caribbean.airlines#caribbean-airlines@the.black.pearl.com103639
```

### Install SIA SSH public key on a target machine
```shell linenums="0"
idsec exec sia ssh-ca install-public-key --private-key-path /path/to/key.pem --target-machine 1.1.1.1 --username user
```

### Remove SIA SSH public key from a target machine
```shell linenums="0"
idsec exec sia ssh-ca uninstall-public-key --private-key-path /path/to/key.pem --target-machine 1.1.1.1 --username user
```

### Check if SIA SSH public key is installed on a target machine
```shell linenums="0"
idsec exec sia ssh-ca is-public-key-installed --private-key-path /path/to/key.pem --target-machine 1.1.1.1 --username user
```

### Add a SIA certificate
```shell linenums="0"
idsec exec sia certificates create --cert-name name --cert-type PEM --file /path/to/cert.crt
```

### Update a SIA certificate
```shell linenums="0"
idsec exec sia certificates update --certificate-id cert-id --cert-name new-name --file /path/to/new-cert.crt
```

### List all SIA certificates
```shell linenums="0"
idsec exec sia certificates list
```

### Import a pCloud Platform
```shell linenums="0"
idsec exec pcloud platforms import --platform-zip-path /path/to/zip
```

### Import a pCloud Target Platform
```shell linenums="0"
idsec exec pcloud target-platforms import --platform-zip-path /path/to/zip
```

### Export a pCloud Platform
```shell linenums="0"
idsec exec pcloud platforms export --platform-id myid --output-folder /path/to/folder
```

### Export a pCloud Target Platform
```shell linenums="0"
idsec exec pcloud target-platforms export --target-platform-id 123 --output-folder /path/to/folder
```

### List pCloud Target Platforms
```shell linenums="0"
idsec exec pcloud target-platforms list
```

### Activate a pCloud Target Platform
```shell linenums="0"
idsec exec pcloud target-platforms activate --target-platform-id 123
```

### Deactivate a pCloud Target Platform
```shell linenums="0"
idsec exec pcloud target-platforms deactivate --target-platform-id 123
```

### Delete a pCloud Target Platform
```shell linenums="0"
idsec exec pcloud target-platforms delete --target-platform-id 123
```

### Create an Identity Auth Profile
```shell linenums="0"
idsec exec identity auth-profiles create-auth-profile --auth-profile-name myprofile --first-challenges UP --second-challenges EMAIL,OTP
```

### List Identity Auth Profiles
```shell linenums="0"
idsec exec identity auth-profiles list-auth-profiles
```

### Delete an Identity Auth Profile
```shell linenums="0"
idsec exec identity auth-profiles delete-auth-profile --auth-profile-id ab75c8da-b04b-4c6e-9b6e-165e36c24018
```

### Create an Identity Policy
```shell linenums="0"
idsec exec identity policies create-policy --policy-name mypolicy --auth-profile-name "myprofile"
```

### List Identity Policies
```shell linenums="0"
idsec exec identity policies list-policies
```

### Make an Identity Policy Inactive
```shell linenums="0"
idsec exec identity policies update-policy --policy-name mypolicy --policy-status Inactive
```

### Delete an Identity Policy
```shell linenums="0"
idsec exec identity policies delete-policy --policy-name mypolicy
```

### Set Identity Policy Order
```shell linenums="0"
idsec exec identity policies set-order --policy-names mypolicy1,mypolicy2,mypolicy3
```

### Move a policy to a specific place in the order before another policy
```shell linenums="0"
idsec exec identity policies update-policy --policy-name mypolicy --before-policy otherpolicy
```

### Move a policy to a specific place in the order after another policy
```shell linenums="0"
idsec exec identity policies update-policy --policy-name mypolicy --after-policy otherpolicy
```

### Create a pCloud Application
```shell linenums="0"
idsec exec pcloud applications create --app-id myapp --business-owner-f-name "user" --business-owner-l-name "name" --business-owner-email user@name.com
```

### List pCloud Applications
```shell linenums="0"
idsec exec pcloud applications list
```

### Delete pCloud Application
```shell linenums="0"
idsec exec pcloud applications delete --app-id myapp
```

### Create a pCloud Application Auth Method
```shell linenums="0"
idsec exec pcloud applications create-auth-method --app-id myapp --auth-type hash --auth-value myhash --comment mycomment
```

### Delete a pCloud Application Auth Method
```shell linenums="0"
idsec exec pcloud applications delete-auth-method --app-id myapp --auth-id 1
```
