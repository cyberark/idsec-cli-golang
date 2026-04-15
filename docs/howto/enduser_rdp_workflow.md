---
title: End-user rdp workflow
description: End-user rdp Workflow
---

# End-user rdp Workflow
Here is an example workflow for connecting to a windows box using rdp:

1. Get a short-lived SSO RDP file or password for a windows box from the SIA service:
   * RDP file single usage for a windows box from the SIA service:
       ```shell linenums="0"
       idsec sia sso short-lived-rdp-file -ta targetaddress -td targetdomain -tu targetuser
       ```
   * Password for continous usage for a windows box from the SIA service:
       ```shell linenums="0"
       idsec sia sso short-lived-password --service DPA-RDP
       ```
1. Use the RDP file or password with mstsc or any other RDP client to connect
