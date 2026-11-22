---
title: pCloud examples
description: Privilege Cloud command examples
---

# pCloud examples

## Safes

### Create a pCloud Safe
```shell linenums="0"
idsec pcloud safes create --safe-name=safe
```

## Accounts

### Create a pCloud account
```shell linenums="0"
idsec pcloud accounts create --name account --safe-name safe --platform-id='UnixSSH' --username root --address 1.2.3.4 --secret-type=password --secret mypass
```

### Retrieve a pCloud account credentials
```shell linenums="0"
idsec pcloud accounts get-credentials --account-id 11_1
```

## Platforms

### Import a pCloud Platform
```shell linenums="0"
idsec pcloud platforms import --platform-zip-path /path/to/zip
```

### Export a pCloud Platform
```shell linenums="0"
idsec pcloud platforms export --platform-id myid --output-folder /path/to/folder
```

## Target Platforms

### Import a pCloud Target Platform
```shell linenums="0"
idsec pcloud target-platforms import --platform-zip-path /path/to/zip
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

## Applications

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
