---
title: Cloud Access policy CLI workflow
description: Creating a Cloud Access Policy using Idsec CLI
---

# Cloud Access policy CLI workflow
Here is an example workflow for adding a Cloud Access policy via the CLI:

1. Create Cloud Access Policy using a defined json file
    ```json
    {
      "metadata": {
        "name": "Cool Cloud Policy",
        "description": "Cool Cloud Policy Description",
        "policyTags": [
          "cool_tag",
          "cool_tag2"
        ],
        "policyEntitlement": {
          "targetCategory": "Cloud console",
          "locationType": "AWS",
          "policyType": "Recurring"
        },
        "timeFrame": {
          "fromTime": null,
          "toTime": null
        },
        "status": {
          "status": "Validating",
          "statusCode": null,
          "statusDescription": "Example status description",
          "link": null
        }
      },
      "principals": [
        {
          "id": "c2c7bcc6-9560-44e0-8dff-5be221cd37ee",
          "name": "user@cyberark.cloud.12345",
          "type": "USER",
          "sourceDirectoryName": "CyberArk Cloud Directory",
          "sourceDirectoryId": "09B9A9B0-6CE8-465F-AB03-65766D33B05E"
        }
      ],
      "conditions": {
        "accessWindow": {
          "daysOfTheWeek": [
            0,
            1,
            2,
            3,
            4,
            5,
            6
          ],
          "fromHour": "05:00:00",
          "toHour": "23:59:00"
        },
        "maxSessionDuration": 2
      },
      "delegationClassification": "Unrestricted",
      "targets": {
        "awsAccountTargets": [
          {
            "roleId": "arn:aws:iam::123456789012:role/RoleName",
            "workspaceId": "123456789012",
            "roleName": "RoleName",
            "workspaceName": "WorkspaceName"
          }
        ]
      }
    }
    ```

    ```shell
    idsec --request-file /path/to/policy-request.json policy cloud-access create-policy
    ```
