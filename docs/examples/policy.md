---
title: Policy examples
description: Access Control Policy command examples
---

# Policy examples

### List all policies
```shell linenums="0"
idsec policy list-policies
```

## DB Policies

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
<!-- idsec-example: skip reason="--request-file requires a fixture file that is not shipped with the docs" -->
```shell linenums="0"
idsec policy db create-policy --request-file /path/to/policy-request.json
```

## Cloud Access Policies

### List Cloud Access Policies
```shell linenums="0"
idsec policy cloud-access list-policies
```

### Get Cloud Access Policy
```shell linenums="0"
idsec policy cloud-access policy --policy-id my-policy-id
```

### Create Cloud Access Policy
<!-- idsec-example: skip reason="--request-file requires a fixture file that is not shipped with the docs" -->
```shell linenums="0"
idsec policy cloud-access create-policy --request-file /path/to/policy-request.json
```

### Delete Cloud Access Policy
```shell linenums="0"
idsec policy cloud-access delete-policy --policy-id my-policy-id
```

## VM Policies

### List VM Policies
```shell linenums="0"
idsec policy vm list-policies
```

### Get VM Policy
```shell linenums="0"
idsec policy vm policy --policy-id my-policy-id
```

### Delete VM Policy
```shell linenums="0"
idsec policy vm delete-policy --policy-id my-policy-id
```
