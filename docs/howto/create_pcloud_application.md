---
title: Create pCloud Application
description: Create pCloud Application
---

# Create pCloud Application
Here is an example workflow for creating a pCloud application and auth method:

1. Create a pCloud application:
    ```shell linenums="0"
    idsec pcloud applications create --app-id myapp --business-owner-f-name "user" --business-owner-l-name "name" --business-owner-email user@name.com
    ```
1. Create a pCloud application auth method:
    ```shell linenums="0"
    idsec pcloud applications create-auth-method --app-id myapp --auth-type hash --auth-value myhash --comment mycomment
    ```
