---
title: SCA commands in the idsec CLI
description: idsec CLI commands and examples for Secure Cloud Access just-in-time elevation
---

# SCA commands in the idsec CLI

The idsec CLI provides Secure Cloud Access (SCA) just-in-time elevation from your terminal. You no longer need the web console to obtain temporary cloud access.

The feature is built around a consistent two-step workflow. First you **discover** what you are entitled to with a `list-targets` command. Then you **elevate** into a specific target to activate that access for a policy-defined period of time. Discovery reflects your live eligibility, so the values you pass to `elevate` always come from a preceding `list-targets` call rather than being hand-written.

This workflow describes two command groups:

- `idsec sca cloud-access` — elevate into a cloud workspace with a role, across AWS, Azure, and GCP. This covers single AWS IAM accounts, AWS accounts managed by an AWS organization, Azure resource scopes (subscription, resource group, resource, management group), Microsoft Entra ID directory roles, and GCP projects, folders, and organizations.
- `idsec sca group-access` — request just-in-time membership in Microsoft Entra ID groups. This command group is Azure-only.

The sections below are organized by cloud provider and flow — AWS IAM, AWS organization, Azure resource, Azure Entra ID, GCP, and Group membership.

## Before you begin

All SCA commands use the Identity Security Platform authenticator from your active profile, so configure a profile once, then authenticate once per session. See [Prerequisites](https://cyberark.github.io/idsec-cli-golang/0.7.0/howto/prerequisites/).

## Command surface


| Command                               | Purpose                                                        |
| ------------------------------------- | -------------------------------------------------------------- |
| `idsec sca cloud-access list-targets` | List the workspaces and roles you are eligible to elevate into |
| `idsec sca cloud-access elevate`      | Activate access to a workspace with one or more roles          |
| `idsec sca group-access list-targets` | List the Entra ID groups you are eligible to join              |
| `idsec sca group-access elevate`      | Request just-in-time membership in one or more Entra ID groups |




### cloud-access flags



#### list-target

`list-targets` has no required flags:


| Flag             | Type   | Description                                                                            |
| ---------------- | ------ | ---------------------------------------------------------------------------------------- |
| `--csp`          | string | Cloud provider, `AWS`, `AZURE`, or `GCP` (case-insensitive). Omit to list all three.      |
| `--all`          | bool   | Explicitly list targets for all default providers. Cannot be combined with `--csp`.      |
| `--workspace-id` | string | Filter the results to a single workspace.                                                |
| `--limit`        | int    | Page size per API request, up to 50.                                                     |
| `--next-token`   | string | Start from a specific pagination token.                                                  |




#### elevate

`elevate` requires `--csp`, `--workspace-id`, and `--roleIds`:


| Flag                | Type   | Description                                                                                                                    |
| ------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------- |
| `--csp`             | string | **Required.** `AWS`, `AZURE`, or `GCP`.                                                                                          |
| `--workspace-id`    | string | **Required.** The `workspaceId` of the target from `list-targets`.                                                               |
| `--roleIds`         | string | **Required.** Comma-separated role IDs. Maximum 1 for AWS, 5 for Azure and GCP.                                                  |
| `--organization-id` | string | The organization or tenant ID. Required for Azure, GCP, and for AWS accounts in an Organization; omit for single AWS accounts.   |




### group-access flags



#### list-targets

`list-targets` accepts the same flags as its cloud-access counterpart, but `--csp AZURE` is effectively mandatory because group access is Azure-only. `--all` does not satisfy it, and `--workspace-id` has no meaning for Entra groups.

#### elevate

`elevate` requires all three of its flags:


| Flag             | Type   | Description                                                       |
| ---------------- | ------ | ----------------------------------------------------------------- |
| `--csp`          | string | **Required.** Must be `AZURE`.                                    |
| `--directory-id` | string | **Required.** The Entra directory (tenant) ID.                    |
| `--groups`       | string | **Required.** Comma-separated Entra group object IDs. Maximum 50. |




## Read list-targets output

Every cloud-access target has a `workspaceType` field. Use that value to pick the flow and options below:


| `workspaceType`                                                  | Flow                               | Section                               |
| ---------------------------------------------------------------- | ----------------------------------- | ------------------------------------- |
| `ACCOUNT`, no `organizationId`                                   | Single AWS account                 | [AWS IAM](#aws-iam)                   |
| `ACCOUNT`, with `organizationId`                                 | AWS account in an Organization     | [AWS organization](#aws-organization) |
| `SUBSCRIPTION`, `RESOURCE_GROUP`, `RESOURCE`, `MANAGEMENT_GROUP` | Azure resource scope               | [Azure resource](#azure-resource)     |
| `DIRECTORY`                                                      | Microsoft Entra ID directory role  | [Azure Entra ID](#azure-entra-id)     |
| `PROJECT`, `FOLDER`, `GCP_ORGANIZATION`                          | GCP project, folder, or org        | [GCP](#gcp)                           |


To list your eligibility across all providers at once, omit `--csp`:

```shell linenums="0"
idsec sca cloud-access list-targets
```

The output is then grouped by provider, and a failure from one provider does not abort the others:

```json
{
  "aws": {
    "response": [
      {
        "workspaceId": "123456789012",
        "workspaceName": "Production-Payments",
        "role": { "id": "arn:aws:iam::123456789012:role/SCA-ReadOnly", "name": "SCA-ReadOnly" },
        "workspaceType": "ACCOUNT"
      }
    ],
    "total": 1
  },
  "azure": {
    "response": [
      {
        "workspaceId": "subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05",
        "workspaceName": "Payments-Prod-Subscription",
        "role": {
          "id": "/providers/Microsoft.Authorization/roleDefinitions/3498e952-d568-435e-9b2c-8d77e338d7f7",
          "name": "Contributor"
        },
        "organizationId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
        "workspaceType": "SUBSCRIPTION"
      }
    ],
    "total": 1
  },
  "gcp": {
    "response": [
      {
        "workspaceId": "acme-prod-payments-458213",
        "workspaceName": "acme-prod-payments",
        "role": {
          "id": "roles/iam.securityReviewer",
          "name": "Security Reviewer"
        },
        "organizationId": "884271936502",
        "workspaceType": "PROJECT"
      }
    ],
    "total": 1
  }
}
```

Output is always pretty-printed JSON, so pipe it to `jq` to filter or restructure it.  

**NOTE:**  `--limit` sets the page size for each API request rather than capping the result: the CLI follows pagination tokens internally and returns every page.

## AWS IAM

Use this flow for a single AWS account that was connected for SCA on its own (standalone), without an AWS organization. These targets appear with `workspaceType: ACCOUNT` and no `organizationId`.

### List eligible AWS targets

```shell linenums="0"
idsec sca cloud-access list-targets --csp aws
```

```json
{
  "response": [
    {
      "workspaceId": "123456789012",
      "workspaceName": "Production-Payments",
      "role": {
        "id": "arn:aws:iam::123456789012:role/SCA-ReadOnly",
        "name": "SCA-ReadOnly"
      },
      "workspaceType": "ACCOUNT"
    }
  ],
  "total": 1
}
```



### Elevate into an AWS account

Omit `--organization-id` — it is not relevant for single accounts. AWS accepts exactly one role ID per elevation:

```shell linenums="0"
idsec sca cloud-access elevate --csp aws --workspace-id 123456789012 --roleIds arn:aws:iam::123456789012:role/SCA-ReadOnly
```

```json
{
  "response": {
    "organizationId": "",
    "csp": "AWS",
    "results": [
      {
        "workspaceId": "123456789012",
        "roleId": "arn:aws:iam::123456789012:role/SCA-ReadOnly",
        "sessionId": "b7f31d84-2a6c-4e19-9c05-8d42fb7a1e63",
        "accessCredentials": "{\"aws_access_key\":\"ASIAEXAMPLEKEY123456\",\"aws_secret_access_key\":\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\",\"aws_session_token\":\"IQoJb3JpZ2luX2VjEExampleSessionToken\"}"
      }
    ]
  }
}
```

For AWS, `accessCredentials` holds short-lived STS credentials as a JSON-encoded string nested inside the JSON response. Decode it twice to reach the `aws_access_key`, `aws_secret_access_key`, and `aws_session_token` fields.

## AWS organization

Use this flow for a member account managed by an AWS organization. These targets look the same as single accounts except that `organizationId` is populated, and that value must be passed to `elevate`.

### List eligible AWS organization targets

```shell linenums="0"
idsec sca cloud-access list-targets --csp aws
```

```json
{
  "response": [
    {
      "workspaceId": "210987654321",
      "workspaceName": "Org-Sandbox-Account",
      "role": {
        "id": "arn:aws:iam::210987654321:role/SCA-PowerUser",
        "name": "SCA-PowerUser"
      },
      "organizationId": "o-a1b2c3d4e5",
      "workspaceType": "ACCOUNT"
    }
  ],
  "total": 1
}
```

To narrow a long list down to one account, filter server-side with `--workspace-id`:

```shell linenums="0"
idsec sca cloud-access list-targets --csp aws --workspace-id 210987654321
```



### Elevate into an AWS organization account

Add `--organization-id` with the AWS organization ID. `--workspace-id` remains the member account ID, not the management account:

```shell linenums="0"
idsec sca cloud-access elevate --csp aws --workspace-id 210987654321 --organization-id o-a1b2c3d4e5 --roleIds arn:aws:iam::210987654321:role/SCA-PowerUser
```

```json
{
  "response": {
    "organizationId": "o-a1b2c3d4e5",
    "csp": "AWS",
    "results": [
      {
        "workspaceId": "210987654321",
        "roleId": "arn:aws:iam::210987654321:role/SCA-PowerUser",
        "sessionId": "4e28c9b7-6d15-4f83-a0e2-91b7cd35fa48",
        "accessCredentials": "{\"aws_access_key\":\"ASIAEXAMPLEKEY654321\",\"aws_secret_access_key\":\"je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY\",\"aws_session_token\":\"IQoJb3JpZ2luX2VjEExampleOrgSessionToken\"}"
      }
    ]
  }
}
```

As with a single account, `accessCredentials` is a JSON-encoded string that must be decoded to reach the individual STS credential fields.

## Azure resource

Use this flow to elevate into an Azure resource scope — a subscription, resource group, individual resource, or management group. These targets carry `workspaceType: SUBSCRIPTION`, `RESOURCE_GROUP`, `RESOURCE`, or `MANAGEMENT_GROUP`, and `organizationId` holds the Entra tenant (directory) ID.

### List eligible Azure targets

```shell linenums="0"
idsec sca cloud-access list-targets --csp azure
```

```json
{
  "response": [
    {
      "workspaceId": "subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05",
      "workspaceName": "Payments-Prod-Subscription",
      "role": {
        "id": "/providers/Microsoft.Authorization/roleDefinitions/3498e952-d568-435e-9b2c-8d77e338d7f7",
        "name": "Contributor"
      },
      "organizationId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
      "workspaceType": "SUBSCRIPTION"
    },
    {
      "workspaceId": "/subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05/resourcegroups/rg-payments-shared",
      "workspaceName": "rg-payments-shared",
      "role": {
        "id": "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
        "name": "Reader"
      },
      "organizationId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
      "workspaceType": "RESOURCE_GROUP"
    }
  ],
  "total": 2
}
```

An Azure resource role ID is an Azure role definition resource ID of the form `/providers/Microsoft.Authorization/roleDefinitions/<guid>`, not a bare GUID. The `workspaceId` is likewise a resource path rather than a plain UUID. Its structure follows the scope: `subscriptions/<subscription-id>` for a subscription, and a full `/subscriptions/.../resourcegroups/...` path for a resource group or resource. Copy both values verbatim from `list-targets`.

### Elevate into an Azure resource scope

`--organization-id` is required for Azure and holds the Entra tenant ID from `organizationId`. `--workspace-id` is the `workspaceId` of the scope you want, whatever its type:

```shell linenums="0"
idsec sca cloud-access elevate --csp azure --workspace-id subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05 --organization-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --roleIds /providers/Microsoft.Authorization/roleDefinitions/3498e952-d568-435e-9b2c-8d77e338d7f7
```



### Elevate with multiple roles

Azure accepts up to five role IDs in one call. All of them are applied to the single workspace provided by `--workspace-id`. To elevate in more than one workspace, run `elevate` once per workspace:

```shell linenums="0"
idsec sca cloud-access elevate --csp azure --workspace-id subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05 --organization-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --roleIds /providers/Microsoft.Authorization/roleDefinitions/3498e952-d568-435e-9b2c-8d77e338d7f7,/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7
```

Whitespace around the commas is tolerated, so `--roleIds "role-a, role-b"` also works.

```json
{
  "response": {
    "organizationId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
    "csp": "AZURE",
    "results": [
      {
        "workspaceId": "subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05",
        "roleId": "/providers/Microsoft.Authorization/roleDefinitions/3498e952-d568-435e-9b2c-8d77e338d7f7",
        "sessionId": "e91c74a3-5b28-4d60-8f13-6a2be7d94c05"
      },
      {
        "workspaceId": "subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05",
        "roleId": "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
        "sessionId": "c38a15f6-9d47-4b2e-a70c-51e9f8b32d64"
      }
    ]
  }
}
```

**NOTE - No credentials are returned for Azure:**
Azure elevation activates a role assignment for your existing identity rather than minting a separate credential set, so the results contain a `sessionId` and no `accessCredentials`. Continue with your normal Azure tooling — for example `az login` followed by `az account set --subscription <id>` — and the newly assigned role applies to that identity.

## Azure Entra ID

Use this flow for Microsoft Entra ID **directory roles**, such as Global Reader or User Administrator, which are scoped to the whole directory rather than to a subscription or resource. These targets are distinguished by `workspaceType: DIRECTORY`.

The command surface is identical to the [Azure resource](#azure-resource) flow, but the identifier formats differ. A directory role ID is a **bare GUID**, not a `/providers/Microsoft.Authorization/roleDefinitions/...` resource path, and `--workspace-id` is the directory ID itself rather than a resource path.

### List eligible Entra ID directory targets

```shell linenums="0"
idsec sca cloud-access list-targets --csp azure
```

```json
{
  "response": [
    {
      "workspaceId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
      "workspaceName": "contoso.onmicrosoft.com",
      "role": {
        "id": "fe930be7-5e62-47db-91af-98c3a49a38b1",
        "name": "User Administrator"
      },
      "organizationId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
      "workspaceType": "DIRECTORY"
    },
    {
      "workspaceId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
      "workspaceName": "contoso.onmicrosoft.com",
      "role": {
        "id": "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
        "name": "Global Reader"
      },
      "organizationId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
      "workspaceType": "DIRECTORY"
    }
  ],
  "total": 2
}
```

**NOTE:** For a directory role, `workspaceId` and `organizationId` are the same value — the Entra directory (tenant) ID — because the role is scoped to the directory itself rather than to a resource inside it.

### Elevate into an Entra ID directory role

Pass the Entra directory (tenant) ID as both `--workspace-id` and `--organization-id`, and the directory role ID as `--roleIds`:

```shell linenums="0"
idsec sca cloud-access elevate --csp azure --workspace-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --organization-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --roleIds fe930be7-5e62-47db-91af-98c3a49a38b1
```

```json
{
  "response": {
    "organizationId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
    "csp": "AZURE",
    "results": [
      {
        "workspaceId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
        "roleId": "fe930be7-5e62-47db-91af-98c3a49a38b1",
        "sessionId": "a15fd739-4c82-4e06-b9d1-73c8a2f4e561"
      }
    ]
  }
}
```



### Elevate with multiple directory roles

The Azure limit of five role IDs per call applies here too. Because every directory role shares the same workspace — the directory itself — several roles can be activated in a single command:

```shell linenums="0"
idsec sca cloud-access elevate --csp azure --workspace-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --organization-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --roleIds fe930be7-5e62-47db-91af-98c3a49a38b1,f2ef992c-3afb-46b9-b7cf-a126ee74c451
```

```json
{
  "response": {
    "organizationId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
    "csp": "AZURE",
    "results": [
      {
        "workspaceId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
        "roleId": "fe930be7-5e62-47db-91af-98c3a49a38b1",
        "sessionId": "a15fd739-4c82-4e06-b9d1-73c8a2f4e561"
      },
      {
        "workspaceId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
        "roleId": "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
        "sessionId": "d746b0e8-1f39-4a25-8c94-3b7e05af2d18"
      }
    ]
  }
}
```

As with Azure resource scopes, Azure does not return an `accessCredentials` field. The directory role is assigned to your existing identity, and a fresh sign-in might be required before a token reflects it.

## GCP

Use this flow to elevate into a GCP project, folder, or organization with a predefined or custom IAM role. These targets carry `workspaceType: PROJECT`, `FOLDER`, or `GCP_ORGANIZATION`, and `organizationId` always holds the GCP organization ID — GCP requires organization context even for a single project.

### List eligible GCP targets

```shell linenums="0"
idsec sca cloud-access list-targets --csp gcp
```

```json
{
  "response": [
    {
      "workspaceId": "acme-prod-payments-458213",
      "workspaceName": "acme-prod-payments",
      "role": {
        "id": "roles/iam.securityReviewer",
        "name": "Security Reviewer"
      },
      "organizationId": "884271936502",
      "workspaceType": "PROJECT"
    },
    {
      "workspaceId": "folders/778899001122",
      "workspaceName": "Payments-Folder",
      "role": {
        "id": "roles/resourcemanager.folderViewer",
        "name": "Folder Viewer"
      },
      "organizationId": "884271936502",
      "workspaceType": "FOLDER"
    }
  ],
  "total": 2
}
```

A GCP role ID is an IAM role path of the form `roles/<service>.<role>` (predefined) or `organizations/<id>/roles/<name>` (custom), not a bare name. `workspaceId` follows the scope: a plain project ID for a project, `folders/<id>` for a folder, and `organizations/<id>` for an organization. Copy `workspaceId`, `role.id`, and `organizationId` verbatim from `list-targets`.

### Elevate into a GCP project

`--organization-id` is required for GCP and holds the GCP organization ID from `organizationId`. `--workspace-id` is the `workspaceId` of the scope you want, whatever its type:

```shell linenums="0"
idsec sca cloud-access elevate --csp gcp --workspace-id acme-prod-payments-458213 --organization-id 884271936502 --roleIds roles/iam.securityReviewer
```

```json
{
  "response": {
    "organizationId": "884271936502",
    "csp": "GCP",
    "results": [
      {
        "workspaceId": "acme-prod-payments-458213",
        "roleId": "roles/iam.securityReviewer",
        "sessionId": "f3d81b6a-7c42-4e05-9b81-2ce7f4a83d61"
      }
    ]
  }
}
```

### Elevate with multiple roles

GCP accepts up to five role IDs in one call, all applied to the single workspace given by `--workspace-id`. To elevate in more than one workspace (for example, two different projects), run `elevate` once per workspace:

```shell linenums="0"
idsec sca cloud-access elevate --csp gcp --workspace-id acme-prod-payments-458213 --organization-id 884271936502 --roleIds roles/iam.securityReviewer,roles/compute.admin
```

```json
{
  "response": {
    "organizationId": "884271936502",
    "csp": "GCP",
    "results": [
      {
        "workspaceId": "acme-prod-payments-458213",
        "roleId": "roles/iam.securityReviewer",
        "sessionId": "f3d81b6a-7c42-4e05-9b81-2ce7f4a83d61"
      },
      {
        "workspaceId": "acme-prod-payments-458213",
        "roleId": "roles/compute.admin",
        "sessionId": "0c6a2e94-8b17-4c5d-9a3f-1e7d5c02b6a9"
      }
    ]
  }
}
```

Elevating into a folder or organization scope works the same way — pass the `folders/<id>` or `organizations/<id>` value from `workspaceId` as `--workspace-id`.

**NOTE - No credentials are returned for GCP:**
Like Azure, GCP elevation grants an IAM role binding to your existing identity rather than minting a separate credential set, so the results contain a `sessionId` and no `accessCredentials`. Continue with your normal GCP tooling — for example `gcloud auth login` followed by `gcloud config set project <id>` — and the newly assigned role applies to that identity.

## Group Access

Use `idsec sca group-access` to request just-in-time membership in Microsoft Entra ID groups. Instead of granting a role on a cloud scope, this adds you to a group for a policy-defined period, so you inherit whatever that group confers.

This command group is **Azure-only**; `--csp AZURE` is required and any other provider is rejected.

### List eligible groups

```shell linenums="0"
idsec sca group-access list-targets --csp azure
```

```json
{
  "response": [
    {
      "directoryId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
      "groupId": "9d3b6f41-8c27-4e59-b1a0-5f7e2c84d913",
      "groupName": "Payments-Prod-Operators"
    },
    {
      "directoryId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
      "groupId": "1f8c5a20-4b76-49e3-9d82-6c015be7f4a9",
      "groupName": "Security-Auditors"
    }
  ],
  "total": 2
}
```

Each row gives you everything `elevate` needs: `directoryId` becomes `--directory-id` and `groupId` becomes `--groups`.

### Page through a long group list

Set `--limit` as the page size, then pass the returned `nextToken` back with `--next-token` to resume:

```shell linenums="0"
idsec sca group-access list-targets --csp azure --limit 20
```



### Elevate into a single group

```shell linenums="0"
idsec sca group-access elevate --csp azure --directory-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --groups 9d3b6f41-8c27-4e59-b1a0-5f7e2c84d913
```

```json
{
  "response": {
    "directoryId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
    "csp": "AZURE",
    "results": [
      {
        "sessionId": "6b74e912-38ac-4d51-9f08-2e5c7ab41d36",
        "groupId": "9d3b6f41-8c27-4e59-b1a0-5f7e2c84d913",
        "groupName": "Payments-Prod-Operators"
      }
    ]
  }
}
```



### Elevate into multiple groups

Pass a comma-separated list of group object IDs, up to 50 per call. All groups must belong to the directory given by `--directory-id`:

```shell linenums="0"
idsec sca group-access elevate --csp azure --directory-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --groups 9d3b6f41-8c27-4e59-b1a0-5f7e2c84d913,1f8c5a20-4b76-49e3-9d82-6c015be7f4a9
```

`--groups` takes group **object IDs**, not display names.

**NOTE - Group membership propagation:**  
Entra ID group membership changes are not always instantaneous, and tokens issued before the elevation do not carry the new membership. If a downstream tool still reports insufficient permissions, sign in again so a fresh token picks up the group.

## Partial success and error handling

A successful HTTP response can still contain per-target failures. When a specific role or group cannot be elevated, that entry carries an `errorInfo` object while the other entries succeed, and the command still exits 0. Always inspect the individual results rather than relying on the exit code alone:

```json
{
  "response": {
    "organizationId": "o-a1b2c3d4e5",
    "csp": "AWS",
    "results": [
      {
        "workspaceId": "210987654321",
        "roleId": "arn:aws:iam::210987654321:role/SCA-PowerUser",
        "errorInfo": {
          "code": "CA1009",
          "message": "We can't connect you to the cloud console",
          "description": "It looks like your user is not eligible to access this target",
          "link": "https://docs.cyberark.com/sca/latest/en/Content/Troubleshooting/sca_error-codes.htm"
        }
      }
    ]
  }
}
```



## Elevation limits

Each `elevate` call is capped on the number of roles or groups it can carry. Exceeding a cap fails the command before any API call is made:


| Flow                               | Limit        | Error when exceeded                           |
| ---------------------------------- | ------------ | --------------------------------------------- |
| `cloud-access elevate --csp aws`   | 1 role ID    | `maximum 1 role IDs allowed for AWS, got 2`   |
| `cloud-access elevate --csp azure` | 5 role IDs   | `maximum 5 role IDs allowed for AZURE, got 6` |
| `cloud-access elevate --csp gcp`   | 5 role IDs   | `maximum 5 role IDs allowed for GCP, got 6`   |
| `group-access elevate`             | 5 group IDs | `maximum 5 group IDs allowed, got 6`        |


The limit of five applies to Azure resource scopes and Entra ID directory roles, and to GCP projects, folders, and organizations alike. In every case, all role IDs in one call must belong to the same `--workspace-id`.