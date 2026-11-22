---
title: Secrets Hub examples
description: Secrets Hub command examples
---

# Secrets Hub examples

## Configuration

### Get Secrets Hub Configuration
```shell linenums="0"
idsec sechub configuration get
```

### Update Secrets Hub Configuration
```shell linenums="0"
idsec sechub configuration update --sync-settings-secret-validity 360
```

## Filters

### Get a Secrets Hub filter
```shell linenums="0"
idsec sechub filters get --store-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667 --filter-id filter-7f3d187d-7439-407f-b968-ec27650be692
```

### List Secrets Hub filters
```shell linenums="0"
idsec sechub filters list --store-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667
```

### Add Secrets Hub filter
```shell linenums="0"
idsec sechub filters create --type "PAM_SAFE" --store-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667 --data-safe-name "example-safe"
```

### Delete Secrets Hub filter
```shell linenums="0"
idsec sechub filters delete --filter-id filter-7f3d187d-7439-407f-b968-ec27650be692 --store-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667
```

## Scans

### Get Secrets Hub Scans
```shell linenums="0"
idsec sechub scans get
```

### Trigger Secrets Hub Scan
```shell linenums="0"
idsec sechub scans trigger --id default --type secret-store --secret-stores-ids store-e488dd22-a59c-418c-bbe3-3f061dd9b667
```

## Secrets

### Get Secrets Hub Secrets
```shell linenums="0"
idsec sechub secrets get
```

### Get Secrets Hub secrets using a filter
```shell linenums="0"
idsec sechub secrets list-by --limit 5 --projection EXTEND --filter "name CONTAINS EXAMPLE"
```

## Secret Stores

### Create Secrets Hub Secret Store (AWS Secrets Manager)
```shell linenums="0"
idsec sechub secret-stores create --type AWS_ASM --description sdk-testing --name "SDK Testing" --state ENABLED --data-aws-account-alias ALIAS-NAME-EXAMPLE --data-aws-region-id us-east-1 --data-aws-account-id 123456789123 --data-role-name Secrets-Hub-IAM-Role-Name-Created-For-Secrets-Hub
```

### Retrieve Secrets Hub Secret Store
```shell linenums="0"
idsec sechub secret-stores get --secret-store-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667
```

### Update Secrets Hub Secret Store
```shell linenums="0"
idsec sechub secret-stores update --secret-store-id store-7f3d187d-7439-407f-b968-ec27650be692 --name "New Name" --description "Updated Description" --data-aws-account-alias "Test2"
```

### Delete Secrets Hub Secret Store
```shell linenums="0"
idsec sechub secret-stores delete --secret-store-id store-fd11bc7c-22d0-4d9b-ac1b-f8458161935f
```

## Service Info

### Get Secrets Hub Service Information
```shell linenums="0"
idsec sechub service-info get
```

## Sync Policies

### List Secrets Hub Sync Policies
```shell linenums="0"
idsec sechub sync-policies list
```

### Get Secrets Hub Sync Policy
```shell linenums="0"
idsec sechub sync-policies get --policy-id policy-7f3d187d-7439-407f-b968-ec27650be692 --projection EXTEND
```

### Delete Secrets Hub Sync Policy
```shell linenums="0"
idsec sechub sync-policies delete --policy-id policy-7f3d187d-7439-407f-b968-ec27650be692
```
