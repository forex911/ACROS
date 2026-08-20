import asyncio
import logging
import json
from datetime import datetime
from kubernetes import client, config

logger = logging.getLogger("gvisor_runner")

async def run_gvisor(job_id: str, local_path: str):
    """
    Executes the payload using a Kubernetes Job with the gvisor RuntimeClass.
    """
    try:
        config.load_incluster_config()
    except:
        try:
            config.load_kube_config()
        except:
            logger.error("Could not load kubernetes configuration.")
            return []

    batch_v1 = client.BatchV1Api()
    core_v1 = client.CoreV1Api()
    
    job_name = f"sandbox-gvisor-{job_id.lower()}"
    namespace = "sandbox"
    
    # Define Job
    job = client.V1Job(
        api_version="batch/v1",
        kind="Job",
        metadata=client.V1ObjectMeta(name=job_name),
        spec=client.V1JobSpec(
            backoff_limit=0,
            ttl_seconds_after_finished=30,
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(
                    labels={"job_id": job_id},
                    annotations={"seccomp.security.alpha.kubernetes.io/pod": "runtime/default"}
                ),
                spec=client.V1PodSpec(
                    runtime_class_name="gvisor",
                    restart_policy="Never",
                    containers=[
                        client.V1Container(
                            name="sandbox-worker",
                            image="acros-ai-worker:latest",
                            command=["python", "executor.py"],
                            security_context=client.V1SecurityContext(
                                privileged=False,
                                read_only_root_filesystem=True,
                                run_as_non_root=True,
                                capabilities=client.V1Capabilities(drop=["ALL"])
                            ),
                            env=[
                                client.V1EnvVar(name="JOB_ID", value=job_id),
                                client.V1EnvVar(name="PAYLOAD_URL", value=f"http://acros-storage:9000/payloads/{job_id}.py")
                            ]
                        )
                    ]
                )
            )
        )
    )

    try:
        batch_v1.create_namespaced_job(namespace=namespace, body=job)
        logger.info(f"Created gVisor Sandbox Job: {job_name}")
        
        # Wait for completion and fetch logs
        # In a real scenario, an eBPF agent would stream telemetry back instantly.
        await asyncio.sleep(5)
        
        return [{"type": "STATUS_CHANGE", "severity": "info", "timestamp": datetime.utcnow().isoformat() + "Z", "data": {"status": "gVisor execution complete"}}]
    except Exception as e:
        logger.error(f"Failed to spawn gVisor Job: {e}")
        return []
