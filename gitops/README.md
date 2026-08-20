GitOps layout for ACROS AI

Structure:

  gitops/
    apps/            # ArgoCD Applications per component
    bootstrap/       # AppProject, SecretStore, initial bootstrapping manifests

Usage:
- Replace REPLACE_WITH_REPO in Application manifests with your repository URL.
- Install ArgoCD into the cluster and point it at `gitops/bootstrap/project.yaml` and apps.
- Install External Secrets Operator or HashiCorp Vault per your secret strategy.

Notes:
- Secrets in these manifests are placeholders. Use ExternalSecrets or Vault to inject secrets at runtime.
- Application paths point at `deployment/kubernetes/k8s/overlays/dev` — adjust to the overlay you want ArgoCD to sync.
