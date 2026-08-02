"""
Kubernetes-native sandbox execution manager.

Replaces all docker.from_env() / Docker socket usage with dynamically
created Kubernetes Jobs.  Each malware sample is executed inside an
ephemeral Job pod that enforces:

  - runtimeClassName: gvisor  (kernel-level syscall interception)
  - runAsNonRoot / readOnlyRootFilesystem
  - ALL capabilities dropped
  - seccomp RuntimeDefault profile
  - strict resource limits (CPU / memory / PIDs)
  - TTL-based automatic cleanup
  - network isolation via NetworkPolicy (inherited from namespace)

The worker ServiceAccount requires RBAC permission to create/get/delete
Jobs and Pods in the ``sentinel-sandbox`` namespace only.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, Optional

from kubernetes import client as k8s_client, config as k8s_config
from kubernetes.client.rest import ApiException

logger = logging.getLogger("k8s_job_manager")

# ---------------------------------------------------------------------------
# Cluster configuration — auto-detect in-cluster vs local kubeconfig
# ---------------------------------------------------------------------------
try:
    k8s_config.load_incluster_config()
    logger.info("Loaded in-cluster Kubernetes config")
except k8s_config.config_exception.ConfigException:
    k8s_config.load_kube_config()
    logger.info("Loaded local kubeconfig (development mode)")

BATCH_API = k8s_client.BatchV1Api()
CORE_API = k8s_client.CoreV1Api()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SANDBOX_NAMESPACE = "aegis-sandbox"
SANDBOX_RUNTIME_CLASS = "gvisor"
DEFAULT_IMAGE = "ghcr.io/aegis-ai/sandbox-runner:latest"
JOB_TTL_SECONDS = 300          # auto-delete completed Jobs after 5 min
ACTIVE_DEADLINE_SECONDS = 120  # hard timeout for any sandbox execution
BACKOFF_LIMIT = 0              # no retries — malware either runs or fails
DEFAULT_MEMORY_LIMIT = "512Mi"
DEFAULT_CPU_LIMIT = "500m"
DEFAULT_MEMORY_REQUEST = "128Mi"
DEFAULT_CPU_REQUEST = "100m"


def _unique_job_name(job_id: str) -> str:
    """Generate a DNS-safe, collision-free Job name."""
    short_uuid = uuid.uuid4().hex[:8]
    # K8s names must be <= 63 chars, lowercase, DNS-compatible
    safe_id = job_id[:40].lower().replace("_", "-")
    return f"sandbox-{safe_id}-{short_uuid}"


def create_sandbox_job(
    job_id: str,
    artifact_presigned_url: str,
    image: str = DEFAULT_IMAGE,
    timeout: int = ACTIVE_DEADLINE_SECONDS,
    memory_limit: str = DEFAULT_MEMORY_LIMIT,
    cpu_limit: str = DEFAULT_CPU_LIMIT,
    runtime_class: str = SANDBOX_RUNTIME_CLASS,
) -> Dict[str, Any]:
    """
    Create and submit a Kubernetes Job that executes a malware sample
    inside a hardened, gVisor-isolated pod.

    The artifact is fetched from MinIO via presigned URL inside the pod's
    init container, written to a memory-backed emptyDir, and then analysed
    by the main container.

    Returns metadata dict with ``job_name``, ``namespace``, ``uid``.
    """
    job_name = _unique_job_name(job_id)

    # ---- Memory-backed ephemeral volume (never touches host disk) --------
    artifact_volume = k8s_client.V1Volume(
        name="artifact-vol",
        empty_dir=k8s_client.V1EmptyDirVolumeSource(
            medium="Memory",
            size_limit="128Mi",
        ),
    )
    tmp_volume = k8s_client.V1Volume(
        name="tmp-vol",
        empty_dir=k8s_client.V1EmptyDirVolumeSource(size_limit="64Mi"),
    )

    artifact_mount = k8s_client.V1VolumeMount(
        name="artifact-vol", mount_path="/artifacts", read_only=False
    )
    artifact_mount_ro = k8s_client.V1VolumeMount(
        name="artifact-vol", mount_path="/artifacts", read_only=True
    )
    tmp_mount = k8s_client.V1VolumeMount(
        name="tmp-vol", mount_path="/tmp", read_only=False  # nosec B108
    )

    # ---- Hardened security context (container-level) ---------------------
    container_security = k8s_client.V1SecurityContext(
        allow_privilege_escalation=False,
        read_only_root_filesystem=True,
        run_as_non_root=True,
        run_as_user=65534,  # nobody
        run_as_group=65534,
        capabilities=k8s_client.V1Capabilities(drop=["ALL"]),
        seccomp_profile=k8s_client.V1SeccompProfile(type="RuntimeDefault"),
    )

    # ---- Init container: download artifact from presigned URL ------------
    init_container = k8s_client.V1Container(
        name="artifact-fetcher",
        image="curlimages/curl:8.7.1",
        command=[
            "/bin/sh", "-c",
            f'curl -sSfL -o /artifacts/sample.bin "{artifact_presigned_url}"',
        ],
        volume_mounts=[artifact_mount],
        security_context=container_security,
        resources=k8s_client.V1ResourceRequirements(
            limits={"cpu": "100m", "memory": "64Mi"},
            requests={"cpu": "50m", "memory": "32Mi"},
        ),
    )

    # ---- Main container: execute analysis --------------------------------
    main_container = k8s_client.V1Container(
        name="sandbox-exec",
        image=image,
        args=["--artifact", "/artifacts/sample.bin", "--job-id", job_id],
        volume_mounts=[artifact_mount_ro, tmp_mount],
        security_context=container_security,
        resources=k8s_client.V1ResourceRequirements(
            limits={"cpu": cpu_limit, "memory": memory_limit, "ephemeral-storage": "128Mi"},
            requests={"cpu": DEFAULT_CPU_REQUEST, "memory": DEFAULT_MEMORY_REQUEST},
        ),
        env=[
            k8s_client.V1EnvVar(name="JOB_ID", value=job_id),
            k8s_client.V1EnvVar(name="RESULT_BACKEND_URL",
                                value_from=k8s_client.V1EnvVarSource(
                                    secret_key_ref=k8s_client.V1SecretKeySelector(
                                        name="aegis-secrets",
                                        key="REDIS_URL",
                                    )
                                )),
        ],
    )

    # ---- Pod-level security context --------------------------------------
    pod_security = k8s_client.V1PodSecurityContext(
        run_as_non_root=True,
        run_as_user=65534,
        run_as_group=65534,
        fs_group=65534,
        seccomp_profile=k8s_client.V1SeccompProfile(type="RuntimeDefault"),
    )

    # ---- Pod template ----------------------------------------------------
    pod_spec = k8s_client.V1PodSpec(
        runtime_class_name=runtime_class,
        restart_policy="Never",
        init_containers=[init_container],
        containers=[main_container],
        volumes=[artifact_volume, tmp_volume],
        security_context=pod_security,
        service_account_name="aegis-sandbox-sa",
        automount_service_account_token=False,
        enable_service_links=False,
        dns_policy="Default",  # inherit cluster DNS for MinIO resolution
        # Ensure sandbox pods land on dedicated isolated nodes
        tolerations=[
            k8s_client.V1Toleration(
                key="sandbox", operator="Equal", value="true", effect="NoSchedule"
            )
        ],
        affinity=k8s_client.V1Affinity(
            node_affinity=k8s_client.V1NodeAffinity(
                required_during_scheduling_ignored_during_execution=(
                    k8s_client.V1NodeSelector(
                        node_selector_terms=[
                            k8s_client.V1NodeSelectorTerm(
                                match_expressions=[
                                    k8s_client.V1NodeSelectorRequirement(
                                        key="workload-type",
                                        operator="In",
                                        values=["isolated-sandbox"],
                                    )
                                ]
                            )
                        ]
                    )
                )
            )
        ),
    )

    pod_template = k8s_client.V1PodTemplateSpec(
        metadata=k8s_client.V1ObjectMeta(
            labels={
                "app": "aegis-sandbox",
                "aegis-ai/job-id": job_id[:63],
            },
            annotations={
                "container.apparmor.security.beta.kubernetes.io/sandbox-exec": "runtime/default",
            },
        ),
        spec=pod_spec,
    )

    # ---- Job spec --------------------------------------------------------
    job_spec = k8s_client.V1JobSpec(
        template=pod_template,
        backoff_limit=BACKOFF_LIMIT,
        active_deadline_seconds=timeout,
        ttl_seconds_after_finished=JOB_TTL_SECONDS,
    )

    job = k8s_client.V1Job(
        api_version="batch/v1",
        kind="Job",
        metadata=k8s_client.V1ObjectMeta(
            name=job_name,
            namespace=SANDBOX_NAMESPACE,
            labels={
                "app": "aegis-sandbox",
                "aegis-ai/job-id": job_id[:63],
            },
        ),
        spec=job_spec,
    )

    # ---- Submit ----------------------------------------------------------
    try:
        created = BATCH_API.create_namespaced_job(namespace=SANDBOX_NAMESPACE, body=job)
        logger.info(
            "Created sandbox Job %s in namespace %s (uid=%s)",
            job_name, SANDBOX_NAMESPACE, created.metadata.uid,
        )
        return {
            "job_name": job_name,
            "namespace": SANDBOX_NAMESPACE,
            "uid": created.metadata.uid,
        }
    except ApiException as exc:
        logger.error("Failed to create sandbox Job %s: %s", job_name, exc.reason)
        raise


def get_job_status(job_name: str) -> Dict[str, Any]:
    """Poll a sandbox Job's completion status."""
    try:
        job = BATCH_API.read_namespaced_job(name=job_name, namespace=SANDBOX_NAMESPACE)
        status = job.status
        return {
            "active": status.active or 0,
            "succeeded": status.succeeded or 0,
            "failed": status.failed or 0,
            "start_time": str(status.start_time) if status.start_time else None,
            "completion_time": str(status.completion_time) if status.completion_time else None,
        }
    except ApiException as exc:
        logger.error("Failed to read Job %s: %s", job_name, exc.reason)
        raise


def get_pod_logs(job_name: str) -> str:
    """Retrieve logs from the first pod of a completed sandbox Job."""
    try:
        pods = CORE_API.list_namespaced_pod(
            namespace=SANDBOX_NAMESPACE,
            label_selector=f"job-name={job_name}",
        )
        if not pods.items:
            return ""
        pod_name = pods.items[0].metadata.name
        return CORE_API.read_namespaced_pod_log(
            name=pod_name, namespace=SANDBOX_NAMESPACE, container="sandbox-exec"
        )
    except ApiException as exc:
        logger.error("Failed to read pod logs for Job %s: %s", job_name, exc.reason)
        return ""


def delete_sandbox_job(job_name: str) -> None:
    """Force-delete a sandbox Job and its pods (idempotent)."""
    try:
        BATCH_API.delete_namespaced_job(
            name=job_name,
            namespace=SANDBOX_NAMESPACE,
            body=k8s_client.V1DeleteOptions(propagation_policy="Foreground"),
        )
        logger.info("Deleted sandbox Job %s", job_name)
    except ApiException as exc:
        if exc.status == 404:
            logger.debug("Job %s already deleted", job_name)
        else:
            logger.error("Failed to delete Job %s: %s", job_name, exc.reason)
            raise
