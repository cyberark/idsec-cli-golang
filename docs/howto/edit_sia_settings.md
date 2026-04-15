---
title: Edit SIA Settings
description: Edit SIA Settings
---

# Edit SIA Settings
Here is an example workflow for editing SIA settings:

1. Retrieve all settings:
    ```shell linenums="0"
    idsec sia settings list-settings
    ```
1. Edit a specific setting:
    ```shell linenums="0"
    idsec sia settings set-rdp-mfa-caching --is-mfa-caching-enabled=true --client-ip-enforced=false
    ```
