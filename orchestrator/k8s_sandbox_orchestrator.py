import os
import asyncio
import logging
from kubernetes import client, config
from datetime import datetime

logger = logging.getLogger("k8s_orchestrator")

class KubernetesSandboxOrchestrator:
    def __init__(self, namespace="sandbox"):
        self.namespace = namespace
        try:
            config.load_incluster_config()
        except:
            config.load_kube_config()
        self.batch_v1 = client.BatchV1Api()
        self.core_v1 = client.CoreV1Api()

    async def execute_job(self, job_id: str, runtime_mode: str, artifact_url: str):
        job_name = f"sandbox-{runtime_mode}-{job_id.lower()}"
        
        # Select runtime class based on mode
        runtime_class = "gvisor" if runtime_mode == "gvisor" else "kata" if runtime_mode == "kata" else None

        pod_spec = client.V1PodSpec(
            runtime_class_name=runtime_class,
            restart_policy="Never",
            node_selector={"sandbox-enabled": "true"},
            tolerations=[
                client.V1Toleration(key="sandbox", operator="Equal", value="true", effect="NoSchedule")
            ],
            containers=[
                client.V1Container(
                    name="sandbox-worker",
                    image="sentinel-ai-worker:latest",
                    command=["python", "executor.py"],
                    security_context=client.V1SecurityContext(
                        privileged=False,
                        read_only_root_filesystem=True,
                        capabilities=client.V1Capabilities(drop=["ALL"])
                    ),
                    env=[
                        client.V1EnvVar(name="JOB_ID", value=job_id),
                        client.V1EnvVar(name="ARTIFACT_URL", value=artifact_url),
                        client.V1EnvVar(name="REDIS_URI", value=os.environ.get("REDIS_URI", "redis://sentinel-redis:6379"))
                    ]
                )
            ]
        )

        job = client.V1Job(
            api_version="batch/v1",
            kind="Job",
            metadata=client.V1ObjectMeta(name=job_name),
            spec=client.V1JobSpec(
                backoff_limit=0,
                ttl_seconds_after_finished=60,
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(
                        labels={"job_id": job_id, "sandbox": "true"},
                        annotations={"seccomp.security.alpha.kubernetes.io/pod": "runtime/default"}
                    ),
                    spec=pod_spec
                )
            )
        )

        try:
            self.batch_v1.create_namespaced_job(namespace=self.namespace, body=job)
            logger.info(f"Deployed K8s Sandbox Job: {job_name}")
            # The telemetry agent running inside the job pod will stream results directly to Redis.
            # We simply wait here for the job to complete or timeout.
            await self._wait_for_completion(job_name)
        except Exception as e:
            logger.error(f"Failed to orchestrate K8s job {job_name}: {e}")

    async def _wait_for_completion(self, job_name, timeout=30):
        start = datetime.utcnow().timestamp()
        while datetime.utcnow().timestamp() - start < timeout:
            job = self.batch_v1.read_namespaced_job(name=job_name, namespace=self.namespace)
            if job.status.succeeded:
                return True
            if job.status.failed:
                return False
            await asyncio.sleep(2)
        
        # Timeout reached, destroy the job
        logger.warning(f"Job {job_name} timed out. Deleting.")
        self.batch_v1.delete_namespaced_job(
            name=job_name,
            namespace=self.namespace,
            body=client.V1DeleteOptions(propagation_policy="Background")
        )
        return False
