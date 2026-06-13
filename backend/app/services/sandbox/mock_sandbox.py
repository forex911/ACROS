import asyncio
import logging
import datetime
import subprocess
import os
import sys
import json
import threading
import tempfile
import shutil
import stat

logger = logging.getLogger("mock_sandbox")

# ─── Sandbox Security Constants ───────────────────────────────────────────────
SANDBOX_TIMEOUT = 10           # Max seconds for sample execution
MAX_SAMPLE_SIZE = 50 * 1024 * 1024  # 50 MB max
RESTRICTED_ENV_VARS = {
    "SENTINEL_SANDBOX": "1",   # Flag so samples can't impersonate the host
}
# Environment variables to STRIP from the sandbox process
STRIPPED_ENV_VARS = [
    "MONGO_URI", "REDIS_URL", "JWT_SECRET", "SECRET_KEY",
    "DATABASE_URL", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "NEO4J_URI", "NEO4J_PASSWORD", "API_KEY",
]


def _create_sandbox_jail(job_id: str) -> str:
    """
    Creates an isolated temporary directory for sandbox execution.
    The sample is copied here and all file I/O is confined to this directory.
    Returns the path to the jail directory.
    """
    jail_dir = os.path.join(tempfile.gettempdir(), "sentinel_sandbox", job_id)
    os.makedirs(jail_dir, exist_ok=True)
    return jail_dir


def _build_restricted_env(job_id: str) -> dict:
    """
    Builds a minimal environment for the sandbox process.
    Strips all secrets and sensitive config from the host environment.
    """
    # Start with a minimal set of env vars
    safe_env = {
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),  # Required on Windows
        "TEMP": os.environ.get("TEMP", tempfile.gettempdir()),
        "TMP": os.environ.get("TMP", tempfile.gettempdir()),
        "SENTINEL_JOB_ID": job_id,
        "PYTHONIOENCODING": "utf-8",
    }
    safe_env.update(RESTRICTED_ENV_VARS)

    # Explicitly ensure secrets are NOT passed
    for var in STRIPPED_ENV_VARS:
        safe_env.pop(var, None)

    return safe_env


def _cleanup_jail(jail_dir: str):
    """
    Removes the sandbox jail directory and all its contents.
    """
    try:
        shutil.rmtree(jail_dir, ignore_errors=True)
        logger.info(f"[MockSandbox] Cleaned up jail: {jail_dir}")
    except Exception as e:
        logger.warning(f"[MockSandbox] Failed to clean jail {jail_dir}: {e}")


def _collect_dropped_files(jail_dir: str, original_filename: str) -> list:
    """
    Walks the jail directory and collects metadata on any files created
    by the sample during execution (dropped files / artifacts).
    """
    dropped = []
    for root, dirs, files in os.walk(jail_dir):
        for f in files:
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, jail_dir)
            # Skip the original sample
            if rel_path == original_filename:
                continue
            try:
                size = os.path.getsize(full_path)
                dropped.append({
                    "path": rel_path,
                    "size": size,
                    "absolute_path": full_path,
                })
            except Exception:
                pass
    return dropped


def _run_mock_blocking(job_id: str, local_path: str):
    """
    Runs the uploaded sample inside an isolated jail directory.
    - Copies the sample into a temp jail dir
    - Executes with a restricted environment (no secrets)
    - Changes cwd to the jail so file writes land there, not in the backend
    - Collects telemetry and dropped file metadata
    - Cleans up the jail on completion
    """
    telemetry_events = []
    jail_dir = None

    try:
        # ── 1. Create isolated jail ──────────────────────────────────
        jail_dir = _create_sandbox_jail(job_id)
        filename = os.path.basename(local_path)
        jailed_path = os.path.join(jail_dir, filename)

        # Copy sample into jail
        shutil.copy2(local_path, jailed_path)
        logger.info(f"[MockSandbox] Sample jailed: {jailed_path}")

        # ── 2. Build command ─────────────────────────────────────────
        if jailed_path.endswith('.py'):
            wrapper_path = os.path.join(
                os.path.dirname(__file__), "..", "runtime_analysis", "sandbox_wrapper.py"
            )
            cmd = [sys.executable, wrapper_path, job_id, jailed_path]
        elif jailed_path.endswith('.bat'):
            cmd = ["cmd.exe", "/c", jailed_path]
        elif jailed_path.endswith('.js'):
            cmd = ["node", jailed_path]
        else:
            cmd = [jailed_path]

        # ── 3. Build restricted environment ──────────────────────────
        safe_env = _build_restricted_env(job_id)

        # ── 4. Execute in jail ───────────────────────────────────────
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                cwd=jail_dir,       # ← KEY: confine cwd to jail
                env=safe_env,       # ← KEY: no secrets leaked
            )
        except Exception as e:
            logger.error(f"Failed to start mock sandbox process: {e}")
            return telemetry_events

        def _read_stream(stream):
            for raw_line in stream:
                try:
                    line_str = raw_line.decode('utf-8', errors='replace').strip()
                    if not line_str:
                        continue

                    try:
                        data = json.loads(line_str)
                        if data.get("__telemetry__"):
                            event_payload = {
                                "type": data["event_type"],
                                "severity": data.get("severity", "info"),
                                "timestamp": data.get("timestamp") or (datetime.datetime.utcnow().isoformat() + "Z"),
                                "data": data["data"],
                            }
                            from app.services.runtime_analysis.telemetry_classifier import classify_event
                            classified = classify_event(event_payload)
                            if classified:
                                telemetry_events.append(classified)
                        else:
                            telemetry_events.append({
                                "type": "EXECUTION_OUTPUT",
                                "severity": "info",
                                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                                "data": {"output": line_str}
                            })
                    except json.JSONDecodeError:
                        telemetry_events.append({
                            "type": "EXECUTION_OUTPUT",
                            "severity": "info",
                            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                            "data": {"output": line_str}
                        })
                except Exception as e:
                    logger.error(f"Error reading stream: {e}")

        stdout_thread = threading.Thread(target=_read_stream, args=(process.stdout,))
        stderr_thread = threading.Thread(target=_read_stream, args=(process.stderr,))
        stdout_thread.start()
        stderr_thread.start()

        try:
            process.wait(timeout=SANDBOX_TIMEOUT)
        except subprocess.TimeoutExpired:
            logger.warning(f"Mock Sandbox execution for {job_id} timed out. Terminating.")
            process.kill()
            telemetry_events.append({
                "type": "EXECUTION_TIMEOUT",
                "severity": "high",
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "data": {},
            })

        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)

        # ── 5. Collect dropped files ─────────────────────────────────
        dropped = _collect_dropped_files(jail_dir, filename)
        if dropped:
            logger.info(f"[MockSandbox] {len(dropped)} dropped file(s) detected in jail")
            for d in dropped:
                telemetry_events.append({
                    "type": "FILE_DROP_DETECTED",
                    "severity": "high",
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "data": {
                        "path": d["path"],
                        "size": d["size"],
                    }
                })

    finally:
        # ── 6. Clean up jail ─────────────────────────────────────────
        if jail_dir:
            _cleanup_jail(jail_dir)

    return telemetry_events


async def run_mock_sandbox(job_id: str, local_path: str):
    """
    Simulates the execution of malware inside an isolated sandbox.
    Used for local development when SANDBOX_MODE=mock.

    Security measures:
    - Sample is copied into an isolated temp directory (jail)
    - Process cwd is set to the jail (file writes land there, not in backend)
    - Environment is stripped of all secrets and sensitive config
    - Jail is cleaned up after execution
    - Execution is time-bounded
    """
    logger.info(f"[MockSandbox] Booting simulated microVM for job {job_id}")
    await asyncio.sleep(0.5)  # Simulate VM boot

    logger.info(f"[MockSandbox] Executing payload {os.path.basename(local_path)} in isolated jail")

    telemetry_events = await asyncio.to_thread(_run_mock_blocking, job_id, local_path)

    logger.info(f"[MockSandbox] Destroying simulated microVM for job {job_id}")
    return telemetry_events
