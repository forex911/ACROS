Hardened sandbox-worker Docker artifacts
=====================================

Files:
- `Dockerfile.node` - multi-stage Node.js Dockerfile configured to run as a non-root user and use `tini` for signal forwarding.
- `entrypoint.sh` - runtime entrypoint (must be executable) that starts the Node process.
- `seccomp_profile.json` - conservative seccomp profile template. Adjust as needed.

Recommended `docker run` flags for local testing (use Kubernetes for production):

```bash
docker build -t sentinel/sandbox-worker:latest -f Dockerfile.node .

docker run --rm -it \
  --security-opt seccomp=./seccomp_profile.json \
  --cap-drop=ALL \
  --read-only \
  --tmpfs /tmp:rw,size=100m \
  --pids-limit=512 \
  --memory=1g --cpus=1.0 \
  --user 1000:1000 \
  --no-new-privileges \
  -p 8080:8080 \
  sentinel/sandbox-worker:latest
```

Production notes:
- Prefer running untrusted binaries inside microVMs (Firecracker) or gVisor for higher isolation.
- Apply Kubernetes PodSecurityPolicies / OPA Gatekeeper policies to enforce seccomp, cap-drop, and non-root.
- Use ephemeral volumes (CSI ephemeral) for runtime artifacts. Do not mount host paths.
- Combine seccomp with AppArmor/SELinux profiles for defense-in-depth.
