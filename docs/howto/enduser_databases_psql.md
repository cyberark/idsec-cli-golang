---
title: End-user database psql
description: End-user Database psql
---

# End-user database Workflow
Here is an example workflow for connecting to a psql DB via idsec CLI, which assumes a DB was already onboarded:

1. Connect to postgres using the CLI with an MFA caching token behind the scenes:
    ```shell linenums="0"
    idsec sia db psql --target-address myaddress.com --target-user myuser
    ```
