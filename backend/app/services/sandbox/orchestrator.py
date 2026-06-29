import logging
import asyncio
from app.core.config import settings
from app.database.redis import redis_client
import json
import datetime

logger = logging.getLogger("orchestrator")

async def publish_state(job_id: str, state: str, extra_data: dict = None):
    channel = f"job_updates:{job_id}"
    payload = {
        "type": "STATUS_CHANGE",
        "severity": "info",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "data": {"status": state}
    }
    if extra_data:
        payload["data"].update(extra_data)
        
    logger.info(f"[Orchestrator] Job {job_id} -> {state}")
    await redis_client.publish(channel, json.dumps(payload))
    
    # Also update mongodb job status if needed, but handled by caller usually
    from app.models.job_model import update_job_status, append_log
    await update_job_status(job_id, state)
    await append_log(job_id, f"[Orchestrator] State transitioned to {state}")


async def orchestrate_sandbox(job_id: str, local_path: str):
    """
    Main state machine for sandbox orchestration.
    States: CREATED -> BOOTING -> RUNNING -> ANALYZING -> COLLECTING -> COMPLETED/FAILED -> DESTROYED
    """
    try:
        await publish_state(job_id, "BOOTING")
        
        telemetry_events = []
        if settings.SANDBOX_MODE == 'mock':
            from app.services.sandbox.mock_sandbox import run_mock_sandbox
            
            await publish_state(job_id, "RUNNING")
            # In mock mode, the mock sandbox simulates the running, analyzing and collecting phases
            await publish_state(job_id, "ANALYZING")
            telemetry_events = await run_mock_sandbox(job_id, local_path)
            
            # Broadcast live telemetry back to the UI so it can render the process tree & network logs
            for event in telemetry_events:
                await redis_client.publish(f"job_updates:{job_id}", json.dumps(event))
                
            await publish_state(job_id, "COLLECTING")
            
        elif settings.SANDBOX_MODE == 'firecracker':
            from app.services.sandbox.firecracker_manager import FirecrackerManager
            from app.services.sandbox.vsock_client import VsockClient
            import base64
            import os

            # Resolve paths for Firecracker
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../vm-image"))
            kernel_path = os.path.join(base_dir, "vmlinux")
            rootfs_path = os.path.join(base_dir, "rootfs.ext4")
            
            manager = FirecrackerManager(job_id, kernel_path, rootfs_path)
            
            try:
                # 1. BOOTING
                logger.info(f"Starting Firecracker VM for {job_id}")
                # We use asyncio.to_thread because manager calls are blocking
                await asyncio.to_thread(manager.start_firecracker)
                await asyncio.to_thread(manager.configure_vm)
                await asyncio.to_thread(manager.start_instance)
                
                # 2. RUNNING
                await publish_state(job_id, "RUNNING")
                await asyncio.sleep(2.0) # Wait for guest OS to boot and agent to bind vsock
                
                # 3. ANALYZING (Send payload)
                client = VsockClient(manager.cid, 5000)
                await asyncio.to_thread(client.connect)
                
                with open(local_path, "rb") as f:
                    content_b64 = base64.b64encode(f.read()).decode('utf-8')
                
                filename = os.path.basename(local_path)
                await publish_state(job_id, "ANALYZING")
                await asyncio.to_thread(client.send_payload, job_id, filename, content_b64)
                
                # 4. COLLECTING (Stream telemetry)
                await publish_state(job_id, "COLLECTING")
                
                # We consume the generator
                async for event in client.stream_telemetry():
                    # Format as needed and publish live
                    telemetry_events.append(event)
                    await redis_client.publish(f"job_updates:{job_id}", json.dumps(event))
                    
                    if event.get("event_type") == "EXECUTION_ERROR" or event.get("event_type") == "SANDBOX_COMPLETE":
                        break
                        
            finally:
                await asyncio.to_thread(manager.cleanup)
                if 'client' in locals():
                    client.close()
            
        elif settings.SANDBOX_MODE == 'kubernetes':
            from app.services.kubernetes_job_manager import create_sandbox_job, get_job_status, get_pod_logs, delete_sandbox_job
            from app.utils.object_store import generate_presigned_url
            from app.models.job_model import get_job
            
            logger.info(f"Starting Kubernetes sandbox Job for {job_id}")
            job_record = await get_job(job_id)
            if not job_record:
                raise ValueError(f"Job {job_id} not found in database")
                
            bucket = job_record.get('artifact_bucket')
            key = job_record.get('artifact_key')
            
            if not bucket or not key:
                presigned_url = "http://localhost/dummy"
            else:
                presigned_url = await asyncio.to_thread(generate_presigned_url, bucket, key, 3600)
                
            job_meta = await asyncio.to_thread(create_sandbox_job, job_id, presigned_url)
            job_name = job_meta["job_name"]
            
            try:
                await publish_state(job_id, "RUNNING")
                await publish_state(job_id, "ANALYZING")
                
                while True:
                    status = await asyncio.to_thread(get_job_status, job_name)
                    if status.get("succeeded") or status.get("failed"):
                        break
                    await asyncio.sleep(2.0)
                    
                await publish_state(job_id, "COLLECTING")
                
                raw_logs = await asyncio.to_thread(get_pod_logs, job_name)
                for line in raw_logs.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        if event.get("__telemetry__"):
                            telemetry_events.append(event)
                            await redis_client.publish(f"job_updates:{job_id}", json.dumps(event))
                    except json.JSONDecodeError:
                        pass
            finally:
                # Optionally delete or keep it based on JOB_TTL_SECONDS
                pass
                
        elif settings.SANDBOX_MODE == 'kata':
            # Kata Containers: same as Kubernetes mode but with kata RuntimeClass.
            # Reuses the existing kubernetes_job_manager with runtime_class override.
            from app.services.kubernetes_job_manager import create_sandbox_job, get_job_status, get_pod_logs
            from app.utils.object_store import generate_presigned_url
            from app.models.job_model import get_job
            
            logger.info(f"Starting Kata Containers sandbox Job for {job_id}")
            job_record = await get_job(job_id)
            if not job_record:
                raise ValueError(f"Job {job_id} not found in database")
                
            bucket = job_record.get('artifact_bucket')
            key = job_record.get('artifact_key')
            
            if not bucket or not key:
                presigned_url = "http://localhost/dummy"
            else:
                presigned_url = await asyncio.to_thread(generate_presigned_url, bucket, key, 3600)
            
            # Pass runtime_class='kata' to select the kata-qemu RuntimeClass
            job_meta = await asyncio.to_thread(create_sandbox_job, job_id, presigned_url, runtime_class='kata')
            job_name = job_meta["job_name"]
            
            try:
                await publish_state(job_id, "RUNNING")
                await publish_state(job_id, "ANALYZING")
                
                while True:
                    status = await asyncio.to_thread(get_job_status, job_name)
                    if status.get("succeeded") or status.get("failed"):
                        break
                    await asyncio.sleep(2.0)
                    
                await publish_state(job_id, "COLLECTING")
                
                raw_logs = await asyncio.to_thread(get_pod_logs, job_name)
                for line in raw_logs.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        if event.get("__telemetry__"):
                            telemetry_events.append(event)
                            await redis_client.publish(f"job_updates:{job_id}", json.dumps(event))
                    except json.JSONDecodeError:
                        pass
            finally:
                pass

        else:
            raise ValueError(f"Unknown SANDBOX_MODE: {settings.SANDBOX_MODE}")

        return telemetry_events
        
    except Exception as e:
        logger.error(f"Orchestration failed for {job_id}: {e}")
        await publish_state(job_id, "FAILED", {"error": str(e)})
        raise
    finally:
        # Guarantee destruction
        await publish_state(job_id, "DESTROYED")
