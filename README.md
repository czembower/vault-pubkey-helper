# vault-pubkey-helper

Utility to push public keys sourced from a k8s cluster into a Vault JWT auth
method. Intended to run in Azure DevOps pipeline.

## Prerequisites

* kubeconfig availabile locally, with context set to the appropriate k8s
cluster
* Azure Managed Identity assigned to the pipeline instance
* Existing Vault JWT Auth Method mount point, configured to authenticate with
static public keys
