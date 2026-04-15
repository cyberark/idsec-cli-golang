---
title: Create Identity Policy
description: Create Identity Policy
---

# Create Identity Policy
Here is an example workflow for creating an identity auth profile and policy:

1. Create an auth profile:
    ```shell linenums="0"
    idsec identity auth-profiles create-auth-profile --auth-profile-name myprofile --first-challenges UP --second-challenges EMAIL,OTP
    ```
1. Create a policy:
    ```shell linenums="0"
    idsec identity policies create-policy --policy-name mypolicy --auth-profile-name myprofile
    ```
