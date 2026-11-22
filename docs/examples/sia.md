---
title: SIA examples
description: Secure Infrastructure Access command examples
---

# SIA examples

!!! tip "Shorthand"

    `exec` is the default command, so you can omit it and invoke services directly: `idsec sia sso short-lived-password` is equivalent to `idsec exec sia sso short-lived-password`.

## SSO

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

## Kubernetes

### Generate a kubectl config file
```shell linenums="0"
idsec sia k8s generate-kubeconfig
```

### Generate a kubectl config file and save it in the specified path
```shell linenums="0"
idsec sia k8s generate-kubeconfig --folder=/Users/My.User/.kube
```

## VM Target Sets

### Add SIA VM target set
```shell linenums="0"
idsec sia workspaces-target-sets create --name mydomain.com --type Domain
```

## VM Secrets

### Add SIA VM secret
```shell linenums="0"
idsec sia secrets-vm create --secret-type ProvisionerUser --provisioner-username=myuser --provisioner-password=mypassword
```

## Databases

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
idsec sia workspaces-db delete --id 123
```

### Connect to MySQL ZSP with the mysql cli via Idsec CLI
```shell linenums="0"
idsec sia db mysql --target-address myaddress.com
```

### Connect to PostgreSQL Vaulted with the psql cli via Idsec CLI
```shell linenums="0"
idsec sia db psql --target-address myaddress.com --target-username myuser
```

### Generate a connection string alias for a given raw connection string
```shell linenums="0"
idsec sia shortened-connection-string generate --raw-connection-string=jack.sparrow@caribbean.airlines#caribbean-airlines@the.black.pearl.com103639
```

## Settings

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

## SSH CA

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

## Certificates

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

## Access

### Get SIA connector setup script
```shell linenums="0"
idsec sia access connector-setup-script --connector-type ON-PREMISE --connector-os windows --connector-pool-id 588741d5-e059-479d-b4c4-3d821a87f012
```
