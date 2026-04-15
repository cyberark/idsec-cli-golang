---
title: VM policy CLI workflow
description: Creating a VM Policy using Idsec CLI
---

# VM policy CLI workflow
Here is an example workflow for adding a VM policy via the CLI:

1. Create VM Policy using a defined json file
    ```json
    {
      "metadata": {
        "name": "Cool Policy",
        "description": "Cool Policy Description",
        "status": {
          "status": "Active",
          "statusDescription": "Example status description"
        },
        "timeFrame": {
          "fromTime": null,
          "toTime": null
        },
        "policyEntitlement": {
          "targetCategory": "VM",
          "locationType": "FQDN/IP",
          "policyType": "Recurring"
        },
        "createdBy": {
          "user": "cool_user",
          "time": "2025-02-08T22:46:06"
        },
        "updatedOn": {
          "user": "cool_user",
          "time": "2025-02-08T22:46:06"
        },
        "policyTags": [
          "cool_tag",
          "cool_tag2"
        ],
        "timeZone": "Asia/Jerusalem"
      },
      "principals": [
        {
          "id": "principal_id",
          "name": "tester@cyberark.cloud",
          "type": "User",
          "sourceDirectoryName": "CyberArk Cloud Directory",
          "sourceDirectoryId": "source_directory_id"
        }
      ],
      "delegationClassification": "Unrestricted",
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
          "fromHour": "05:00",
          "toHour": "23:59"
        },
        "maxSessionDuration": 2,
        "idleTime": 1
      },
      "targets": {
        "fqdnipResource": {
          "fqdnRules": [
            {
              "operator": "EXACTLY",
              "computernamePattern": "myvm.mydomain.com",
              "domain": "domain.com"
            }
          ],
          "ipRules": [
            {
              "operator": "EXACTLY",
              "ipAddresses": [
                "192.168.12.34"
              ],
              "logicalName": "CoolLogicalName"
            }
          ]
        }
      },
      "behavior": {
        "sshProfile": {
          "username": "ssh_user"
        },
        "rdpProfile": {
          "domainEphemeralUser": {
            "assignGroups": [
              "rdp_users"
            ],
            "enableEphemeralUserReconnect": false,
            "assignDomainGroups": [
              "domain_rdp_users"
            ]
          }
        }
      }
    }
    ```

    ```shell
    idsec --request-file /path/to/policy-request.json policy vm create-policy
    ```
