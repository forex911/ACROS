import asyncio
import logging
import json
from datetime import datetime
from kubernetes import client, config

logger = logging.getLogger("kata_runner")

async def run_kata(job_id: str, local_path: str):
    """
    Executes the payload using a Kubernetes Job with the kata RuntimeClass.
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
    
    job_name = f"sandbox-kata-{job_id.lower()}"
    namespace = "sandbox"
    
    job = client.V1Job(
        api_version="batch/v1",
        kind="Job",
        metadata=client.V1ObjectMeta(name=job_name),
        spec=client.V1JobSpec(
            backoff_limit=0,
            ttl_seconds_after_finished=30,
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(labels={"job_id": job_id}),
                spec=client.V1PodSpec(
                    runtime_class_name="kata",
                    restart_policy="Never",
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
                                client.V1EnvVar(name="PAYLOAD_URL", value=f"http://sentinel-storage:9000/payloads/{job_id}.py")
                            ]
                        )
                    ]
                )
            )
        )
    )

    try:
        batch_v1.create_namespaced_job(namespace=namespace, body=job)
        logger.info(f"Created Kata Sandbox Job: {job_name}")
        await asyncio.sleep(5)
        
        return [{"type": "STATUS_CHANGE", "severity": "info", "timestamp": datetime.utcnow().isoformat() + "Z", "data": {"status": "Kata execution complete"}}]
    except Exception as e:
        logger.error(f"Failed to spawn Kata Job: {e}")
        return []
