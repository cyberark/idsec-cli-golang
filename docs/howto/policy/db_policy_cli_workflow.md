---
title: Database policy CLI workflow
description: Creating a DB Policy using Idsec CLI
---

# Database policy CLI workflow
Here is an example workflow for adding a DB policy alongside all needed assets via the CLI:

1. Add SIA DB Strong Account
    ```shell
    idsec sia db-strong-accounts create --store-type managed --name "my-postgres-account" --platform PostgreSQL --address "db.example.com" --username "dbuser" --port 5432 --database "mydb" --password "mypassword"
    ```
1. Add SIA Database
    ```shell
    idsec sia workspaces-db create-target \
      --name mydomain.com \
      --provider-engine postgres-sh \
      --read-write-endpoint myendpoint.mydomain.com \
      --secret-id <SECRET_ID_FROM_PREVIOUS_STEP>
    ```
1. Create DB Policy using a defined json file
    ```json
    {
      "metadata": {
        "name": "Cool Policy",
        "description": "Cool Policy Description",
        "status": { "status": "ACTIVE" },
        "timeFrame": { "fromTime": null, "toTime": null },
        "policyEntitlement": {
          "targetCategory": "DB",
          "locationType": "FQDN_IP",
          "policyType": "RECURRING"
        },
        "policyTags": ["cool_tag", "cool_tag2"],
        "timeZone": "Asia/Jerusalem"
      },
      "principals": [
        {
          "id": "principal_id",
          "name": "tester@cyberark.cloud",
          "sourceDirectoryName": "CyberArk Cloud Directory",
          "sourceDirectoryId": "source_directory_id",
          "type": "USER"
        }
      ],
      "conditions": {
        "accessWindow": {
          "daysOfTheWeek": [0, 1, 2, 3, 4, 5, 6],
          "fromHour": "05:00",
          "toHour": "23:59"
        },
        "maxSessionDuration": 2,
        "idleTime": 1
      },
      "targets": {
        "FQDN_IP": {
          "instances": [
            {
              "instanceName": "Mongo-atlas_ephemeral_user",
              "instanceType": "Mongo",
              "instanceId": "1234",
              "authenticationMethod": "MONGO_AUTH",
              "mongoAuthProfile": {
                "globalBuiltinRoles": ["readWriteAnyDatabase"],
                "databaseBuiltinRoles": {
                  "mydb1": ["userAdmin"],
                  "mydb2": ["dbAdmin"]
                },
                "databaseCustomRoles": {
                  "mydb1": ["myCoolRole"]
                }
              }
            }
          ]
        }
      }
    }
    ```

    ```shell
    idsec --request-file /path/to/policy-request.json policy db create-policy
    ```
