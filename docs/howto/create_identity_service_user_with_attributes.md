---
title: Create Identity Service User With Attributes
description: Create Identity Service User With Attributes
---

# Create Identity Service User With Attributes
Here is an example workflow for creating an identity service user, and modifying its attributes alongside the schema:

1. Create a service user with random password
    ```shell linenums="0"
    idsec identity users create-user --roles "DpaAdmin" --username "myuser" --is-service-user --is-oauth-client
    ```
1. Configure user attributes schema
    ```shell linenums="0"
    idsec identity users upsert-attributes-schema --columns '[{"name": "department_attr1", "Title": "department_attr1", "Type": "Text", "Description": "Department attribute 1"}, {"name": "location_attr2", "Title": "location_attr2", "Type": "Text", "Description": "Location attribute 2"}]'
    ```
1. Set service user attributes
    ```shell linenums="0"
    idsec identity users upsert-attributes --user-id 692d75bf-a7a5-4abe-8e37-7056d3337beb --attributes department_attr1:engineering --attributes location_attr2:NYC
    ```
