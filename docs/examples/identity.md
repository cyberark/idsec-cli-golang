---
title: Identity examples
description: Identity Service command examples
---

# Identity examples

## Users

### Create an Identity user
```shell linenums="0"
idsec identity users create --username "myuser"
```

### Create an Identity service / oauth user
```shell linenums="0"
idsec identity users create --username "myuser" --is-service-user --is-oauth-client
```

### Get user attribute schema
```shell linenums="0"
idsec identity users attributes-schema
```

### Configure user attribute schema columns
```shell linenums="0"
idsec identity users upsert-attributes-schema --columns '[{"name": "department_attr1", "Title": "department_attr1", "Type": "Text", "Description": "Department attribute 1"}, {"name": "location_attr2", "Title": "location_attr2", "Type": "Text", "Description": "Location attribute 2"}]'
```

### Remove user attribute schema columns
```shell linenums="0"
idsec identity users delete-attributes-schema --column-names department_attr1,location_attr2
```

### Set user attributes
```shell linenums="0"
idsec identity users upsert-attributes --user-id 692d75bf-a7a5-4abe-8e37-7056d3337beb --attributes department_attr1:engineering --attributes location_attr2:NYC
```

### Get user attributes
```shell linenums="0"
idsec identity users get-attributes --user-id 692d75bf-a7a5-4abe-8e37-7056d3337beb
```

### Remove user attributes
```shell linenums="0"
idsec identity users delete-attributes --user-id 692d75bf-a7a5-4abe-8e37-7056d3337beb --attribute-names department_attr1,location_attr2
```

## Roles

### Create an Identity Role
```shell linenums="0"
idsec identity roles create --role-name myrole
```

## Directories

### List all directory entities
```shell linenums="0"
idsec identity directories list-entities
```

## Auth Profiles

### Create an Identity Auth Profile
```shell linenums="0"
idsec identity auth-profiles create --auth-profile-name myprofile --first-challenges UP --second-challenges EMAIL,OTP
```

### List Identity Auth Profiles
```shell linenums="0"
idsec identity auth-profiles list
```

### Delete an Identity Auth Profile
```shell linenums="0"
idsec identity auth-profiles delete --auth-profile-id ab75c8da-b04b-4c6e-9b6e-165e36c24018
```

## Policies

### Create an Identity Policy
```shell linenums="0"
idsec identity policies create --policy-name mypolicy --auth-profile-name "myprofile"
```

### List Identity Policies
```shell linenums="0"
idsec identity policies list
```

### Make an Identity Policy Inactive
```shell linenums="0"
idsec identity policies update --policy-name mypolicy --policy-status Inactive
```

### Delete an Identity Policy
```shell linenums="0"
idsec identity policies delete --policy-name mypolicy
```

### Set Identity Policy Order
```shell linenums="0"
idsec identity policies set-order --policies-order mypolicy1,mypolicy2,mypolicy3
```

### Move a policy to a specific place in the order before another policy
```shell linenums="0"
idsec identity policies update --policy-name mypolicy --before-policy otherpolicy
```

### Move a policy to a specific place in the order after another policy
```shell linenums="0"
idsec identity policies update --policy-name mypolicy --after-policy otherpolicy
```
