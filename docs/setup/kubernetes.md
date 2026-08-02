# Enterprise Kubernetes Deployment

Aegis-AI supports enterprise-grade deployment via Kubernetes and GitOps (ArgoCD).

## Helm Charts

The platform is packaged into 3 distinct Helm charts located in the `deployment/` directory:
1. `backend-chart`
2. `frontend-chart`
3. `sandbox-worker-chart`

### Deploying manually

```bash
helm upgrade --install aegis-backend ./deployment/backend-chart -n Aegis
helm upgrade --install aegis-frontend ./deployment/frontend-chart -n Aegis
helm upgrade --install sandbox-worker ./deployment/sandbox-worker-chart -n Aegis
```

## GitOps with ArgoCD

For automated syncing, apply the `Application` manifests located in `gitops/`:

```bash
kubectl apply -f gitops/backend-app.yaml
kubectl apply -f gitops/frontend-app.yaml
kubectl apply -f gitops/sandbox-worker-app.yaml
```

*Note: The Sandbox Worker requires privileged container execution (or Kata Containers/gVisor) to successfully hook OS-level events via `sys.addaudithook`. Do not run the Sandbox Worker on the same nodes as the rest of the cluster workloads.*
