---
title: End-user database with short connstring workflow
description: End-user Database with Short Connection String Workflow
---

# End-user database Workflow
Here is an example workflow for connecting to a psql DB via idsec CLI with a shortened connection string, which assumes a DB was already onboarded:

1. Generate a shortened connection string:
    ```shell linenums="0"
    idsec sia shortened-connection-string generate --raw-connection-string=jack.sparrow@caribbean.airlines#caribbean-airlines@the.black.pearl.com103639
    ```
1. Get a short-lived SSO password for a database from the SIA service:
    ```shell linenums="0"
    idsec sia sso short-lived-password
    ```
1. Log in directly to the database:
    ```shell linenums="0"
    psql "host=mytenant.postgres.cyberark.cloud user=c897186c-c550-474f-9726-5d8d1e4f8cc6"
    ```
