import asyncio
import subprocess
import sys
import os
import json
import logging
import datetime
import threading
import tempfile
import shutil
from app.database.redis import redis_client

logger = logging.getLogger("sandbox_runner")

# Environment variables to STRIP from sandbox
STRIPPED_ENV_VARS = [
    "MONGO_URI", "REDIS_URL", "JWT_SECRET", "SECRET_KEY",
    "DATABASE_URL", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "NEO4J_URI", "NEO4J_PASSWORD", "API_KEY",
]

async def publish_event(job_id: str, event_type: str, payload: dict):
    channel = f"job_updates:{job_id}"
    if "type" not in payload:
        payload["type"] = event_type
    if "timestamp" not in payload:
        payload["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
    
    logger.info(f"[REDIS PUBLISH] {event_type}")
    logger.info(json.dumps(payload))
    await redis_client.publish(channel, json.dumps(payload))


def _run_subprocess_blocking(job_id: str, local_path: str):
    """
    Runs the sandbox subprocess in an isolated jail directory.
    - Copies sample into a temp directory
    - Sets cwd to jail so any created files land there, not in backend
    - Strips secrets from the environment
    - Cleans up jail after execution
    """
    telemetry_events = []
    jail_dir = None

    try:
        # ── Create jail ──────────────────────────────────────────
        jail_dir = os.path.join(tempfile.gettempdir(), "aegis_sandbox", job_id)
        os.makedirs(jail_dir, exist_ok=True)

        filename = os.path.basename(local_path)
        jailed_path = os.path.join(jail_dir, filename)
        shutil.copy2(local_path, jailed_path)

        is_python = jailed_path.endswith('.py')

        if is_python:
            wrapper_path = os.path.join(os.path.dirname(__file__), "sandbox_wrapper.py")
            cmd = [sys.executable, wrapper_path, job_id, jailed_path]
            shell = False
        else:
            cmd = jailed_path
            shell = True

        # ── Build restricted env ─────────────────────────────────
        safe_env = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "TEMP": os.environ.get("TEMP", tempfile.gettempdir()),
            "TMP": os.environ.get("TMP", tempfile.gettempdir()),
            "AEGIS_JOB_ID": job_id,
            "AEGIS_SANDBOX": "1",
            "SENTINEL_JOB_ID": job_id,
            "SENTINEL_SANDBOX": "1",
            "PYTHONIOENCODING": "utf-8",
        }
        for var in STRIPPED_ENV_VARS:
            safe_env.pop(var, None)

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=shell,
                cwd=jail_dir,
                env=safe_env,
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
                                from app.services.runtime_analysis.telemetry_classifier import classify_event
                                classified = classify_event(event_payload)
                                if classified:
                                    logger.info(f"Telemetry Collected: {json.dumps(classified)}")
                                    telemetry_events.append(classified)
                        except json.JSONDecodeError:
                            pass

                    if not is_telemetry:
                        logger.debug(f"[Sandbox {job_id}]: {line_str}")
                except Exception as e:
                    logger.error(f"Error reading stream: {e}")

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

    finally:
        # ── Cleanup jail ─────────────────────────────────────────
        if jail_dir:
            try:
                shutil.rmtree(jail_dir, ignore_errors=True)
            except Exception:
                pass

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
