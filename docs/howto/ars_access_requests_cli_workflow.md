---
title: ARS access requests CLI workflow
description: Handling VM access requests that require approval using Idsec CLI
---

# ARS access requests CLI workflow
The Access Request Service (ARS) lets users request access to targets that require approval.
For a virtual machine, a request is matched to a VM access policy that requires access approval (dual control).
When an end user requests access, the policy approvers can approve or reject the request, and the requester can cancel it.

Here is an example workflow for handling VM access requests via the CLI:

1. Create a VM policy that requires access approval, using a defined json file
    - The principals are the users that can request access to the targets of the policy
    - The approvers are the users that approve or reject the requests, up to 5 identities

    ```json
    {
      "metadata": {
        "name": "VM Dual Control Policy",
        "description": "VM access that requires approval",
        "status": {
          "status": "Active"
        },
        "policyEntitlement": {
          "targetCategory": "VM",
          "locationType": "FQDN/IP",
          "policyType": "Recurring"
        },
        "policyTags": [],
        "timeZone": "GMT"
      },
      "principals": [
        {
          "id": "requester_user_id",
          "name": "requester@cyberark.cloud.12345",
          "type": "USER",
          "sourceDirectoryName": "CyberArk",
          "sourceDirectoryId": "cyberark.cloud.12345"
        }
      ],
      "delegationClassification": "Unrestricted",
      "conditions": {
        "accessWindow": {
          "daysOfTheWeek": [0, 1, 2, 3, 4, 5, 6],
          "fromHour": "00:00",
          "toHour": "23:59"
        },
        "maxSessionDuration": 1,
        "idleTime": 10,
        "accessApproval": {
          "required": true,
          "approvers": [
            {
              "id": "approver_user_id",
              "name": "approver@cyberark.cloud.12345",
              "type": "USER",
              "sourceDirectoryName": "CyberArk",
              "sourceDirectoryId": "cyberark.cloud.12345"
            }
          ]
        }
      },
      "targets": {
        "fqdnipResource": {
          "fqdnRules": [
            {
              "operator": "EXACTLY",
              "computernamePattern": "myvm.mydomain.com"
            }
          ]
        }
      },
      "behavior": {
        "sshProfile": {
          "username": "root"
        }
      }
    }
    ```

    <!-- idsec-example: skip reason="reads a placeholder request file" -->
    ```shell linenums="0"
    idsec --request-file /path/to/policy-request.json policy vm create-policy
    ```

2. List the request form of VM dual control access requests, to see which details a requester provides
    ```shell linenums="0"
    idsec exec ars requests list-request-forms --target-category VM --request-type DUAL_CONTROL
    ```

3. As the requester, submit an access request for a target of the policy, answering the request form in a request file, and wait until it is pending approval
    ```json
    {
      "requestDetails": {
        "targetType": "Linux",
        "targetAddress": "myvm.mydomain.com",
        "reason": "Maintenance",
        "requestDate": "2026-12-01",
        "requestEndDate": "2026-12-02",
        "timeFrom": "08:00",
        "timeTo": "17:00",
        "timezone": "GMT",
        "priority": "High"
      }
    }
    ```

    <!-- idsec-example: skip reason="reads a placeholder request file" -->
    ```shell linenums="0"
    idsec exec --request-file /path/to/access-request.json ars requests submit --target-category VM --request-type DUAL_CONTROL --poll
    ```

4. List the access requests, newest first, and find the request
    ```shell linenums="0"
    idsec exec ars requests list-by --extended --sort '[{"field": "createdAt", "direction": "desc"}]'
    ```

5. Get the request, a request that waits for approval is in the `PENDING` state
    ```shell linenums="0"
    idsec exec ars requests get --request-id my-request-id
    ```

6. As the approver, approve the request and wait until it finishes
    ```shell linenums="0"
    idsec exec ars requests finalize --request-id my-request-id --result APPROVED --poll --wait-until-finished
    ```

    Or reject it with a reason
    ```shell linenums="0"
    idsec exec ars requests finalize --request-id my-request-id --result REJECTED --finalization-reason "Not allowed"
    ```

7. As the requester, cancel a request that is no longer needed, and wait until it finishes
    ```shell linenums="0"
    idsec exec ars requests cancel --request-id my-request-id --cancel-reason "No longer needed" --poll
    ```

8. Show the access requests statistics by category, state and result
    ```shell linenums="0"
    idsec exec ars requests stats
    ```
