---
title: Secure Cloud Access (SCA) examples
description: Secure Cloud Access command examples
---

# Secure Cloud Access (SCA) examples

## Cloud Access

### List SCA cloud-access targets across all providers
```shell linenums="0"
idsec sca cloud-access list-targets
```

### List SCA cloud-access targets for a single provider
```shell linenums="0"
idsec sca cloud-access list-targets --csp aws
```

### List SCA cloud-access targets for GCP
```shell linenums="0"
idsec sca cloud-access list-targets --csp gcp
```

### Elevate into a single AWS account
Omit `--organization-id` — it is not relevant for standalone AWS IAM accounts. AWS accepts exactly one role ID per elevation.

```shell linenums="0"
idsec sca cloud-access elevate --csp aws --workspace-id 123456789012 --role-ids arn:aws:iam::123456789012:role/SCA-ReadOnly
```

### Elevate into an AWS account managed by an AWS organization
Add `--organization-id` with the AWS organization ID. `--workspace-id` remains the member account ID.

```shell linenums="0"
idsec sca cloud-access elevate --csp aws --workspace-id 210987654321 --organization-id o-a1b2c3d4e5 --role-ids arn:aws:iam::210987654321:role/SCA-PowerUser
```

### Elevate into an Azure resource scope
Works for a subscription, resource group, resource, or management group. `--organization-id` is the Entra tenant ID.

```shell linenums="0"
idsec sca cloud-access elevate --csp azure --workspace-id subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05 --organization-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --role-ids /subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05/providers/Microsoft.Authorization/roleDefinitions/3498e952-d568-435e-9b2c-8d77e338d7f7
```

### Elevate into an Azure resource scope with multiple roles
Azure accepts up to five role IDs per call, all applied to the same `--workspace-id`.

```shell linenums="0"
idsec sca cloud-access elevate --csp azure --workspace-id subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05 --organization-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --role-ids /subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05/providers/Microsoft.Authorization/roleDefinitions/3498e952-d568-435e-9b2c-8d77e338d7f7,/subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7
```

### Elevate into a Microsoft Entra ID directory role
Directory role IDs are bare GUIDs. Pass the Entra directory (tenant) ID as both `--workspace-id` and `--organization-id`.

```shell linenums="0"
idsec sca cloud-access elevate --csp azure --workspace-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --organization-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --role-ids fe930be7-5e62-47db-91af-98c3a49a38b1
```

### Elevate into a GCP project
`--organization-id` is required for GCP and holds the GCP organization ID. GCP accepts up to five role IDs per call, all applied to the same `--workspace-id`.

```shell linenums="0"
idsec sca cloud-access elevate --csp gcp --workspace-id acme-prod-payments-458213 --organization-id 884271936502 --role-ids roles/iam.securityReviewer
```

### Elevate into a GCP project with multiple roles
```shell linenums="0"
idsec sca cloud-access elevate --csp gcp --workspace-id acme-prod-payments-458213 --organization-id 884271936502 --role-ids roles/iam.securityReviewer,roles/compute.admin
```

## Group Access

### List group-access targets (Entra ID or Google groups)
```shell linenums="0"
idsec sca group-access list-targets --csp azure
idsec sca group-access list-targets --csp gcp
```

### Elevate access to one or more Entra ID groups
Pass a comma-separated list of group object IDs (not display names), up to 5 per call. All groups must belong to the directory given by `--directory-id`.

```shell linenums="0"
idsec sca group-access elevate --csp azure --directory-id 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632 --groups 9d3b6f41-8c27-4e59-b1a0-5f7e2c84d913,1f8c5a20-4b76-49e3-9d82-6c015be7f4a9
```

### Elevate access to one or more Google groups
Pass the full `groups/<id>` values from `list-targets`, up to five per call. All groups must be members of the specified organization (`--organization-id`).

!!! info "Google groups access"

    The capability of defining Google group access is available upon request. Contact support to enable this capability for your tenant.

```shell linenums="0"
idsec sca group-access elevate --csp gcp --organization-id 123456789012 --groups groups/03b2xy4k1q9z7mn
```

!!! tip "Full group access workflow"

    For the complete group access workflow — listing available targets (`list-targets`), per-provider flows, partial-success handling, and elevation limits — see [the idsec CLI reference](../howto/sca_native_cli.md).

## Kubernetes

### List Amazon Elastic Kubernetes Service (EKS) cluster targets only
```shell linenums="0"
idsec sca k8s list-targets --csp aws
```

### List Azure Kubernetes Service (AKS) cluster targets for Azure only
```shell linenums="0"
idsec sca k8s list-targets --csp azure
```

### Filter cloud-managed Kubernetes cluster targets to a specific workspace
```shell linenums="0"
idsec sca k8s list-targets --csp aws --workspace-id 123456789012
```

### List cloud-managed Kubernetes cluster targets across all providers
```shell linenums="0"
idsec sca k8s list-targets
```

### Generate kubeconfig for Amazon Elastic Kubernetes Service (EKS) only
<!-- idsec-example: skip reason="generate-kubeconfig bypasses --dry-run, requires an authenticated session" -->
```shell linenums="0"
idsec sca k8s generate-kubeconfig --csp aws
```

### Generate kubeconfig for Azure Kubernetes Service only
<!-- idsec-example: skip reason="generate-kubeconfig bypasses --dry-run, requires an authenticated session" -->
```shell linenums="0"
idsec sca k8s generate-kubeconfig --csp azure
```

### Generate kubeconfig to a custom file path (single cloud provider)
<!-- idsec-example: skip reason="generate-kubeconfig bypasses --dry-run, requires an authenticated session" -->
```shell linenums="0"
idsec sca k8s generate-kubeconfig --csp azure --kubeconfig-location /tmp/my-aks.yaml
```

### Generate kubeconfig to a custom directory (all cloud providers)
Writes `/tmp/kubeconfigs/aws.yaml` and `/tmp/kubeconfigs/azure.yaml`.

<!-- idsec-example: skip reason="generate-kubeconfig bypasses --dry-run, requires an authenticated session" -->
```shell linenums="0"
idsec sca k8s generate-kubeconfig --kubeconfig-location /tmp/kubeconfigs/
```

### Generate kubeconfig for all cloud providers (default)
Writes `~/.kube/idsec-cli/aws.yaml` and `~/.kube/idsec-cli/azure.yaml`.

<!-- idsec-example: skip reason="generate-kubeconfig bypasses --dry-run, requires an authenticated session" -->
```shell linenums="0"
idsec sca k8s generate-kubeconfig
```

### Run kubectl after generating kubeconfig

Point kubectl at the generated file and run any command. The embedded exec plugin handles elevation automatically on every request:

```shell linenums="0"
export KUBECONFIG=~/.kube/config:~/.kube/idsec-cli/aws.yaml:~/.kube/idsec-cli/azure.yaml
kubectl get pods
```

!!! tip "Full cloud-managed Kubernetes cluster workflow"
    For the complete workflow — discovering clusters, kubeconfig output paths, how the exec credential plugin works, and how to refresh credentials — see [Commands for cloud-managed Kubernetes cluster access](../howto/sca_k8s_cli.md).
