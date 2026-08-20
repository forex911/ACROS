# Enterprise Kubernetes Deployment

ACROS supports enterprise-grade deployment via Kubernetes and GitOps (ArgoCD).

## Helm Charts

The platform is packaged into 3 distinct Helm charts located in the `deployment/` directory:
1. `backend-chart`
2. `frontend-chart`
3. `sandbox-worker-chart`

### Deploying manually

```bash
helm upgrade --install acros-backend ./deployment/backend-chart -n ACROS
helm upgrade --install acros-frontend ./deployment/frontend-chart -n ACROS
helm upgrade --install sandbox-worker ./deployment/sandbox-worker-chart -n ACROS
```

## GitOps with ArgoCD

For automated syncing, apply the `Application` manifests located in `gitops/`:

```bash
kubectl apply -f gitops/backend-app.yaml
kubectl apply -f gitops/frontend-app.yaml
kubectl apply -f gitops/sandbox-worker-app.yaml
```

*Note: The Sandbox Worker requires privileged container execution (or Kata Containers/gVisor) to successfully hook OS-level events via `sys.addaudithook`. Do not run the Sandbox Worker on the same nodes as the rest of the cluster workloads.*
