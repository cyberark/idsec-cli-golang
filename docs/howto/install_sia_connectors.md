---
title: Install SIA connectors
description: Install SIA connectors
---

# Install SIA connectors
Here is an example workflow for installing a connector on a linux or windows box:

1. Create a network and connector pool:
    ```shell linenums="0"
    idsec cmgr add-network --name mynetwork
    idsec cmgr add-pool --name mypool --assigned-network-ids mynetwork_id
    ```
1. Install a connector:
       * Windows:
           ```shell linenums="0"
           idsec sia access install-connector --connector-pool-id 89b4f0ff-9b06-445a-9ca8-4ca9a4d72e8c --username myuser --password mypassword --target-machine 1.2.3.4 --connector-os windows --connector-type ON-PREMISE
           ```
       * Linux:
           ```shell linenums="0"
           idsec sia access install-connector --connector-pool-id 89b4f0ff-9b06-445a-9ca8-4ca9a4d72e8c --username myuser --private-key-path /path/to/private_key.pem --target-machine 1.2.3.4 --connector-os linux --connector-type ON-PREMISE
           ```
