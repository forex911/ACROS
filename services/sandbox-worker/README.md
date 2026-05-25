sandbox-worker service
======================

This service is a minimal Celery-based worker that demonstrates how to consume
sandbox execution jobs and run artifacts inside a hardened ephemeral container.

Configuration (env):
- `CELERY_BROKER_URL` - Redis broker URL (default: `redis://localhost:6379/0`)
- `SECCOMP_PROFILE_PATH` - optional path to seccomp profile file mounted into the worker image

Notes:
- For production, replace Docker-based execution with microVMs (Firecracker) or gVisor.
- Ensure this service runs with limited privileges and cannot access host mounts.
- Use Keda or HorizontalPodAutoscaler to scale workers based on queue depth.

Run locally (requires Redis and Docker accessible):

```bash
python -m pip install -r requirements.txt
export CELERY_BROKER_URL=redis://localhost:6379/0
celery -A worker.celery_app worker --loglevel=info
```
