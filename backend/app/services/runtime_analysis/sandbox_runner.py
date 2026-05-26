import asyncio
import os
import json
import logging
from app.database.redis import redis_client

logger = logging.getLogger("sandbox_runner")

async def publish_event(job_id: str, event_type: str, payload: dict):
    channel = f"job_updates:{job_id}"
    # Payload already contains type, severity, timestamp, and data
    if "type" not in payload:
        payload["type"] = event_type
    if "timestamp" not in payload:
        payload["timestamp"] = __import__("datetime").datetime.utcnow().isoformat() + "Z"
    await redis_client.publish(channel, json.dumps(payload))

async def run_sandbox(job_id: str, local_path: str):
    """
    Executes the python script safely using the sandbox wrapper.
    Parses telemetry from stdout and publishes to Redis.
    """
    if not local_path.endswith('.py'):
        # For non-python files (e.g. PE), we just emit a generic event since we don't have a safe PE sandbox
        await publish_event(job_id, "STATUS_CHANGE", {"type": "STATUS_CHANGE", "severity": "info", "data": {"status": "analyzing"}})
        await asyncio.sleep(1)
        return []

    # We use our true local sandbox wrapper now for basic isolation
    wrapper_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "sandbox", "local_sandbox.py")
    
    # Run the wrapper as a subprocess
    process = await asyncio.create_subprocess_exec(
        "python", wrapper_path, job_id, local_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    telemetry_events = []

    async def read_stream(stream):
        while True:
            line = await stream.readline()
            if not line:
                break
            try:
                line_str = line.decode('utf-8').strip()
                if not line_str:
                    continue
                
                # Check if it's our telemetry JSON
                try:
                    data = json.loads(line_str)
                    if data.get("__telemetry__"):
                        event_type = data["event_type"]
                        event_data = data["data"]
                        severity = data.get("severity", "info")
                        event_timestamp = data.get("timestamp")
                        
                        event_payload = {
                            "type": event_type,
                            "severity": severity,
                            "timestamp": event_timestamp,
                            "data": event_data
                        }
                        
                        telemetry_events.append(event_payload)
                        await publish_event(job_id, event_type, event_payload)
                        continue
                except json.JSONDecodeError:
                    pass
                
                # If not telemetry, it might be script output
                logger.debug(f"[Sandbox {job_id}]: {line_str}")
                
            except Exception as e:
                logger.error(f"Error reading stream: {e}")

    # Wait for completion (max 10 seconds timeout for safety)
    try:
        await asyncio.wait_for(
            asyncio.gather(
                read_stream(process.stdout),
                read_stream(process.stderr)
            ),
            timeout=10.0
        )
    except asyncio.TimeoutError:
        logger.warning(f"Sandbox execution for {job_id} timed out. Terminating.")
        process.terminate()
        await publish_event(job_id, "EXECUTION_TIMEOUT", {"type": "EXECUTION_TIMEOUT", "severity": "high", "data": {}})

    return telemetry_events
