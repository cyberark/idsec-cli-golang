---
title: Onboard pCloud Account
description: Onboard pCloud Account
---

# Onboard pCloud Account
Here is an example workflow for onboarding a pCloud safe and creating a Safe:

1. Create a new safe:
    ```shell linenums="0"
    idsec pcloud safes create --safe-name=safe
    ```
1. Create a new account in the Safe:
    ```shell linenums="0"
    idsec pcloud accounts create --name account --safe-name safe --platform-id='UnixSSH' --username root --address 1.2.3.4 --secret-type=password --secret mypass
    ```
