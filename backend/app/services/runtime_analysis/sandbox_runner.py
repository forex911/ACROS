import asyncio
import subprocess
import sys
import os
import json
import logging
import datetime
import threading
from app.database.redis import redis_client

logger = logging.getLogger("sandbox_runner")

async def publish_event(job_id: str, event_type: str, payload: dict):
    channel = f"job_updates:{job_id}"
    # Payload already contains type, severity, timestamp, and data
    if "type" not in payload:
        payload["type"] = event_type
    if "timestamp" not in payload:
        payload["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
    
    logger.info(f"[REDIS PUBLISH] {event_type}")
    logger.info(json.dumps(payload))
    await redis_client.publish(channel, json.dumps(payload))


def _run_subprocess_blocking(job_id: str, local_path: str):
    """
    Runs the sandbox subprocess synchronously (meant to be called via asyncio.to_thread).
    Uses subprocess.Popen which works on all platforms regardless of the asyncio event loop policy.
    Returns a list of telemetry event dicts.
    """
    telemetry_events = []
    is_python = local_path.endswith('.py')

    if is_python:
        wrapper_path = os.path.join(os.path.dirname(__file__), "sandbox_wrapper.py")
        cmd = [sys.executable, wrapper_path, job_id, local_path]
        shell = False
    else:
        cmd = local_path
        shell = True

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=shell,
        )
    except Exception as e:
        logger.error(f"Failed to start sandbox process: {e}")
        return telemetry_events

    def _read_stream(stream):
        for raw_line in stream:
            try:
                line_str = raw_line.decode('utf-8', errors='replace').strip()
                if not line_str:
                    continue

                is_telemetry = False
                if is_python:
                    try:
                        data = json.loads(line_str)
                        if data.get("__telemetry__"):
                            is_telemetry = True
                            event_payload = {
                                "type": data["event_type"],
                                "severity": data.get("severity", "info"),
                                "timestamp": data.get("timestamp") or (datetime.datetime.utcnow().isoformat() + "Z"),
                                "data": data["data"],
                            }
                            # Classify and filter
                            from app.services.runtime_analysis.telemetry_classifier import classify_event
                            classified = classify_event(event_payload)
                            if classified:
                                logger.info(f"Telemetry Collected: {json.dumps(classified)}")
                                telemetry_events.append(classified)
                    except json.JSONDecodeError:
                        pass

                if not is_telemetry:
                    # Raw process output is discarded from structured telemetry stream by the classifier
                    # but we can optionally keep it here if we want to store it in a different log.
                    # Since Phase 1 says "Everything else should be discarded", we skip appending PROCESS_OUTPUT to telemetry_events.
                    logger.debug(f"[Sandbox {job_id}]: {line_str}")
            except Exception as e:
                logger.error(f"Error reading stream: {e}")

    # Read stdout and stderr concurrently in threads
    stdout_thread = threading.Thread(target=_read_stream, args=(process.stdout,))
    stderr_thread = threading.Thread(target=_read_stream, args=(process.stderr,))
    stdout_thread.start()
    stderr_thread.start()

    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        logger.warning(f"Sandbox execution for {job_id} timed out. Terminating.")
        process.kill()
        telemetry_events.append({
            "type": "EXECUTION_TIMEOUT",
            "severity": "high",
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "data": {},
        })

    stdout_thread.join(timeout=2)
    stderr_thread.join(timeout=2)

    return telemetry_events


async def run_sandbox(job_id: str, local_path: str):
    """
    Executes the script. If it's a python script, runs safely using the sandbox wrapper.
    If it's not a python script, executes it natively and captures stdout/stderr.
    Parses telemetry from stdout and publishes to Redis.

    Uses subprocess.Popen in a thread pool to avoid the Windows SelectorEventLoop
    limitation where asyncio.create_subprocess_exec raises NotImplementedError.
    """
    await publish_event(job_id, "STATUS_CHANGE", {"type": "STATUS_CHANGE", "severity": "info", "data": {"status": "analyzing"}})

    logger.info("SANDBOX_STARTED")

    # Run the blocking subprocess in a thread pool so we don't block the event loop
    telemetry_events = await asyncio.to_thread(_run_subprocess_blocking, job_id, local_path)

    logger.info("FILE_EXECUTED")
    logger.info("SANDBOX_FINISHED")

    # Publish all collected telemetry events to Redis
    for event in telemetry_events:
        await publish_event(job_id, event["type"], event)

    return telemetry_events
