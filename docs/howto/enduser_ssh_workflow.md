---
title: End-user ssh workflow
description: End-user ssh Workflow
---

# End-user SSH workflow
Here is an example workflow for connecting to a linux box using SSH:

1. Get a short-lived SSH private key for a linux box from the SIA service:
    ```shell linenums="0"
    idsec sia sso short-lived-ssh-key
    ```
1. Log in directly to the linux box:
    ```shell linenums="0"
    ssh -i ~/.ssh/sia_ssh_key.pem myuser@suffix@targetuser@targetaddress@sia_proxy
    ```
