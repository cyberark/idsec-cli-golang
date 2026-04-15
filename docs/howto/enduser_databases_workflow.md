---
title: End-user database workflow
description: End-user Database Workflow
---

# End-user database Workflow
Here is an example workflow for connecting to a database:

1. Get a short-lived SSO password for a database from the SIA service:
    ```shell linenums="0"
    idsec sia sso short-lived-password
    ```
1. Log in directly to the database:
    ```shell linenums="0"
    psql "host=mytenant.postgres.cyberark.cloud user=user@cyberark.cloud.12345@postgres@mypostgres.fqdn.com"
    ```
