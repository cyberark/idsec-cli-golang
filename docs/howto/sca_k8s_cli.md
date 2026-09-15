---
title: Commands for cloud-managed Kubernetes cluster access
description: idsec CLI commands and examples for cloud-managed Kubernetes cluster access
---

# Commands for cloud-managed Kubernetes cluster access

The idsec CLI provides just-in-time elevation to cloud-managed Kubernetes clusters, through the Idira platform, from your terminal. You no longer need the web console to discover which clusters you are eligible to accesss or to generate the kubeconfig that enables `kubectl` access.

The workflow:

1. **Discover** your eligible clusters with `idsec sca k8s list-targets`.
2. **Generate a kubeconfig** with `idsec sca k8s generate-kubeconfig`. This writes a kubeconfig file that embeds `idsec kubectl-login` as a [kubectl exec credential plugin](https://kubernetes.io/docs/reference/config-api/client-authentication.v1beta1/).
3. **Use `kubectl` as you usually would.** Each time `kubectl` invokes the exec plugin, `idsec kubectl-login` automatically elevates your access, acquires a short-lived token, and returns it to kubectl — no additional flags required.

## Before you begin

All `sca k8s` commands use the Identity Security Platform authenticator from your active profile. Authenticate once per session before running any `sca k8s` command:

```shell linenums="0"
idsec login
```

See [Prerequisites](https://cyberark.github.io/idsec-cli-golang/latest/howto/prerequisites/) for full setup instructions.

## Command surface

| Command | Purpose |
| ------- | ------- |
| `idsec sca k8s list-targets` | Discover the clusters and roles you are eligible to access |
| `idsec sca k8s generate-kubeconfig` | Write a kubeconfig file that configures `kubectl` for idsec-managed access |

### list-targets flags

`list-targets` has no required flags:

| Flag | Type | Description |
| ---- | ---- | ----------- |
| `--csp` | string | Cloud provider, `AWS` or `AZURE` (case-insensitive). Omit to list both. |
| `--all` | bool | Explicitly list targets for all default providers. Cannot be combined with `--csp`. |
| `--workspace-id` | string | Filter results to a single workspace (AWS organization ID or Azure Entra tenant ID). |
| `--limit` | int | Page size per API request. |
| `--next-token` | string | Start from a specific pagination token. |

### generate-kubeconfig flags

`generate-kubeconfig` has no required flags:

| Flag | Type | Description |
| ---- | ---- | ----------- |
| `--csp` | string | Cloud provider, `aws` or `azure` (case-insensitive). Omit to generate for all cloud providers. |
| `--all` | bool | Generate kubeconfig for all supported cloud providers (default: `true`). |
| `--kubeconfig-location` | string | Custom file path or directory to write the kubeconfig. Overrides the default `~/.kube/idsec-cli/<csp>.yaml`. |

## Step 1 — Discover your eligible clusters

### List only Amazon Elastic Kubernetes Service (EKS) clusters

```shell linenums="0"
idsec sca k8s list-targets --csp aws
```

```json
{
  "response": [
    {
      "workspaceId": "123456789012",
      "workspaceName": "Production-EKS",
      "workspaceType": "account",
      "role": {
        "id": "arn:aws:iam::123456789012:role/k8s-readonly-role",
        "name": "k8s-readonly-role"
      },
      "target": {
        "scope": "cluster",
        "region": "us-east-1",
        "clusterId": "arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster",
        "fqdn": "745445889F087548523CF96B3D365FF0.gr7.us-east-1.eks.amazonaws.com"
      }
    }
  ],
  "total": 1
}
```

### List only Azure Kubernetes Service clusters

```shell linenums="0"
idsec sca k8s list-targets --csp azure
```

```json
{
  "response": [
    {
      "workspaceId": "subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05",
      "workspaceName": "Payments-AKS",
      "workspaceType": "subscription",
      "organizationId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
      "role": {
        "id": "/subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05/providers/Microsoft.Authorization/roleDefinitions/8393591c-06b9-48a2-a542-1bd6b377f6a2",
        "name": "AKS-ReadOnly"
      },
      "target": {
        "scope": "cluster",
        "region": "eastus",
        "clusterId": "arn:azure:aks:eastus:5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05:cluster/prod-aks",
        "fqdn": "prod-aks-rg-payments-efab80-f32tfdrj.hcp.eastus.azmk8s.io"
      }
    }
  ],
  "total": 1
}
```

### Filter to a single workspace

Use `--workspace-id` to narrow a long list to a single workspace. For AWS this is the account or organization ID; for Azure it is the Entra tenant (directory) ID:

```shell linenums="0"
idsec sca k8s list-targets --csp aws --workspace-id 123456789012
```

### Paginate through a large result set

Set `--limit` as the page size, then pass the returned `nextToken` back with `--next-token` to resume:

```shell linenums="0"
idsec sca k8s list-targets --csp azure --limit 20
```

### List clusters for all providers

Omit `--csp` to list cluster targets from all cloud providers. A failure from one cloud provider does not abort the other:

```shell linenums="0"
idsec sca k8s list-targets
```

```json
{
  "aws": {
    "response": [
      {
        "workspaceId": "123456789012",
        "workspaceName": "Production-EKS",
        "workspaceType": "account",
        "role": {
          "id": "arn:aws:iam::123456789012:role/k8s-readonly-role",
          "name": "k8s-readonly-role"
        },
        "target": {
          "scope": "cluster",
          "region": "us-east-1",
          "clusterId": "arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster",
          "fqdn": "745445889F087548523CF96B3D365FF0.gr7.us-east-1.eks.amazonaws.com"
        }
      }
    ],
    "total": 1
  },
  "azure": {
    "response": [
      {
        "workspaceId": "subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05",
        "workspaceName": "Payments-AKS",
        "workspaceType": "subscription",
        "organizationId": "3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632",
        "role": {
          "id": "/subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05/providers/Microsoft.Authorization/roleDefinitions/8393591c-06b9-48a2-a542-1bd6b377f6a2",
          "name": "AKS-ReadOnly"
        },
        "target": {
          "scope": "cluster",
          "region": "eastus",
          "clusterId": "arn:azure:aks:eastus:5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05:cluster/prod-aks",
          "fqdn": "prod-aks-rg-payments-efab80-f32tfdrj.hcp.eastus.azmk8s.io"
        }
      }
    ],
    "total": 1
  }
}
```

## Step 2 — Generate a kubeconfig

`generate-kubeconfig` calls the Idira platform backend and writes a kubeconfig file that embeds `idsec kubectl-login` as the exec credential plugin. The default output path is `~/.kube/idsec-cli/<csp>.yaml`. If the file already exists, it is **overwritten**; no backup is created.

### Generate kubeconfig for Amazon Elastic Kubernetes Service (EKS) only

```shell linenums="0"
idsec sca k8s generate-kubeconfig --csp aws
```

```json
{
  "aws": "file created at location /Users/alice/.kube/idsec-cli/aws.yaml"
}
```

The generated file at `~/.kube/idsec-cli/aws.yaml` contains one context per eligible EKS cluster and role combination. Each user entry configures the exec plugin that `kubectl` calls automatically:

```yaml
apiVersion: v1
kind: Config
current-context: arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster-k8s-readonly-role
clusters:
- cluster:
    server: https://745445889F087548523CF96B3D365FF0.gr7.us-east-1.eks.amazonaws.com
    certificate-authority-data: <base64-encoded-ca>
  name: arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster
contexts:
- context:
    cluster: arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster
    user: arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster-k8s-readonly-role
  name: arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster-k8s-readonly-role
users:
- name: arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster-k8s-readonly-role
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: idsec
      args:
      - kubectl-login
      - --csp
      - aws
      - --fqdn
      - 745445889F087548523CF96B3D365FF0.gr7.us-east-1.eks.amazonaws.com
      - --role-id
      - arn:aws:iam::123456789012:role/k8s-readonly-role
      interactiveMode: IfAvailable
```

### Generate kubeconfig for Azure Kubernetes Service only

```shell linenums="0"
idsec sca k8s generate-kubeconfig --csp azure
```

```json
{
  "azure": "file created at location /Users/alice/.kube/idsec-cli/azure.yaml"
}
```

The generated file at `~/.kube/idsec-cli/azure.yaml` contains one context per eligible AKS cluster and role combination:

```yaml
apiVersion: v1
kind: Config
current-context: Payments-AKS_rg-payments_prod-aks_AKS-ReadOnly
clusters:
- cluster:
    server: https://prod-aks-rg-payments-efab80-f32tfdrj.hcp.eastus.azmk8s.io:443
    certificate-authority-data: <base64-encoded-ca>
  name: Payments-AKS_rg-payments_prod-aks
contexts:
- context:
    cluster: Payments-AKS_rg-payments_prod-aks
    user: Payments-AKS_rg-payments_prod-aks_AKS-ReadOnly
  name: Payments-AKS_rg-payments_prod-aks_AKS-ReadOnly
users:
- name: Payments-AKS_rg-payments_prod-aks_AKS-ReadOnly
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: idsec
      args:
      - kubectl-login
      - --csp
      - azure
      - --organization-id
      - 3c9f7b2e-51d4-4a86-9f0c-7e15d8a4b632
      - --fqdn
      - prod-aks-rg-payments-efab80-f32tfdrj.hcp.eastus.azmk8s.io
      - --role-id
      - /subscriptions/5a1c8e77-2b93-41d0-8f6e-c94b2d7a1e05/providers/Microsoft.Authorization/roleDefinitions/8393591c-06b9-48a2-a542-1bd6b377f6a2
      interactiveMode: IfAvailable
```

### Write kubeconfig to a custom path

Use `--kubeconfig-location` to set a custom output destination. Supply a full file path when targeting a single cloud provider, or a directory path when generating configs for all cloud providers (files are saved as `<csp>.yaml`):

```shell linenums="0"
# Single cloud provider — write to an explicit file path
idsec sca k8s generate-kubeconfig --csp azure --kubeconfig-location /tmp/my-aks.yaml

# All cloud providers — write to a custom directory (/tmp/kubeconfigs/aws.yaml, /tmp/kubeconfigs/azure.yaml)
idsec sca k8s generate-kubeconfig --kubeconfig-location /tmp/kubeconfigs/
```

### Generate kubeconfig for cloud-managed Kubernetes services from all cloud providers (default)

With no flags (or with `--all`), kubeconfigs are generated for all supported cloud providers in parallel. A failure for one cloud provider does not block the others:

```shell linenums="0"
idsec sca k8s generate-kubeconfig
```

```json
{
  "aws": "file created at location /Users/alice/.kube/idsec-cli/aws.yaml",
  "azure": "file created at location /Users/alice/.kube/idsec-cli/azure.yaml"
}
```

## Step 3 — Run kubectl commands

Once `generate-kubeconfig` has written the kubeconfig file, point `kubectl` at it and run any command. The exec credential plugin embedded in the kubeconfig automatically calls `idsec kubectl-login`, elevates your access via the Idira backend, and returns a short-lived bearer token or certificate to `kubectl` — no extra flags are needed.

### Point kubectl at the generated kubeconfig

The `KUBECONFIG` environment variable accepts a colon-separated list, so you can merge the idsec-generated files alongside your existing kubeconfig:

```shell linenums="0"
export KUBECONFIG=~/.kube/config:~/.kube/idsec-cli/aws.yaml:~/.kube/idsec-cli/azure.yaml
```

Or use the `--kubeconfig` flag per command:

```shell linenums="0"
kubectl --kubeconfig ~/.kube/idsec-cli/aws.yaml get pods
```

### Select the context

Each context in the generated file corresponds to one cluster-and-role combination from `list-targets`. Switch between contexts with `kubectl config use-context`:

```shell linenums="0"
# List all available contexts
kubectl config get-contexts

# Switch to a specific EKS context
kubectl config use-context arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster-k8s-readonly-role

# Switch to a specific AKS context
kubectl config use-context Payments-AKS_rg-payments_prod-aks_AKS-ReadOnly
```

### Run any kubectl command

With the context selected, run any `kubectl` command as usual. `idsec kubectl-login` is invoked automatically to obtain and cache credentials:

```shell linenums="0"
kubectl get pods
kubectl get nodes
kubectl describe deployment my-app
```
!!! note:

    - If prompted for a PIN code, enter it now to complete the connection.
    - **AWS IAM Identity Center only**: If your browser opens the Connections page during device authorization, click **Go directly to cloud console**. In the device authorization page that opens, complete the authorization. Then continue working with kubectl as usual.

!!! tip "Azure: ensure `az login` matches your idsec identity"
    
    The Azure path requires the `az` CLI session to belong to the same user as your idsec profile. If `kubectl-login` reports `az login user does not match elevate user`, run `az login` with the same account you used for `idsec login`.

## Output path reference

| Flags | Output path |
| ----- | ----------- |
| (none) | `~/.kube/idsec-cli/aws.yaml`, `~/.kube/idsec-cli/azure.yaml` |
| `--all` | `~/.kube/idsec-cli/aws.yaml`, `~/.kube/idsec-cli/azure.yaml` |
| `--csp aws` | `~/.kube/idsec-cli/aws.yaml` |
| `--csp azure` | `~/.kube/idsec-cli/azure.yaml` |
| `--csp aws --kubeconfig-location /tmp/k.yaml` | `/tmp/k.yaml` |
| `--kubeconfig-location /tmp/dir/` | `/tmp/dir/aws.yaml`, `/tmp/dir/azure.yaml` |

## Refreshing credentials

Kubeconfig files do not contain credentials — they only reference the exec plugin. To refresh the list of clusters and roles (for example, after your eligibility changes), re-run `generate-kubeconfig`:

```shell linenums="0"
idsec sca k8s generate-kubeconfig
```

This overwrites the existing files and picks up any new clusters or role changes from `list-targets`.

If the idsec session has expired, authenticate first:

```shell linenums="0"
idsec login
idsec sca k8s generate-kubeconfig
```
