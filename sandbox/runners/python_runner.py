"""
Python Runner — Sandbox Python File Executor

Executes Python files inside the sandbox container using audit hooks
for syscall monitoring. Follows the same telemetry protocol as
local_sandbox.py and sandbox_wrapper.py.

Designed to run inside the Dockerfile.runner container.
"""

import sys
import os
import json
import datetime
import shutil
import tempfile
import hashlib
import logging

logger = logging.getLogger("python_runner")


def send_telemetry(job_id: str, event_type: str, data: dict):
    """Emit telemetry in the standard ACROS JSON protocol."""
    msg = {
        "__telemetry__": True,
        "job_id": job_id,
        "event_type": event_type,
        "data": data,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }
    print(json.dumps(msg), flush=True)


WRITTEN_FILES = set()


def finalize_file_writes(job_id: str):
    """Hash and report all files written during execution."""
    for file_path in list(WRITTEN_FILES):
        if not os.path.exists(file_path):
            continue
        try:
            size = os.path.getsize(file_path)
            sha256_hash = ""
            if size <= 50 * 1024 * 1024:
                sha256 = hashlib.sha256()
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        sha256.update(chunk)
                sha256_hash = sha256.hexdigest()

            send_telemetry(job_id, "FILE_CREATE", {
                "path": file_path,
                "size": size,
                "sha256": sha256_hash,
            })
        except Exception:
            pass


def create_audit_hook(job_id: str):
    """Create an audit hook function bound to the given job_id."""

    def audit_hook(event, args):
        try:
            # Process spawning
            if event == "os.system":
                cmd = args[0].decode("utf-8") if isinstance(args[0], bytes) else args[0]
                send_telemetry(job_id, "PROCESS_CREATE", {"cmdline": cmd})

            elif event == "subprocess.Popen":
                try:
                    cmd_args = args[1] if len(args) > 1 else args[0]
                    if isinstance(cmd_args, list):
                        cmd = " ".join(str(x) for x in cmd_args)
                    elif isinstance(cmd_args, str):
                        cmd = cmd_args
                    else:
                        cmd = str(cmd_args)
                    send_telemetry(job_id, "PROCESS_CREATE", {"cmdline": cmd})
                except Exception:
                    pass

            # Networking
            elif event == "socket.connect":
                try:
                    addr = args[1]
                    if isinstance(addr, tuple) and len(addr) >= 2:
                        ip, port = addr[:2]
                        send_telemetry(job_id, "SOCKET_CONNECT", {
                            "dest_ip": str(ip),
                            "dest_port": int(port),
                            "protocol": "TCP",
                        })
                except Exception:
                    pass

            elif event == "socket.getaddrinfo":
                try:
                    host = args[0]
                    if isinstance(host, str) and not host.startswith("127.") and host != "localhost":
                        send_telemetry(job_id, "DNS_QUERY", {"domain": host})
                except Exception:
                    pass

            # File I/O
            elif event == "open":
                file_path = args[0]
                mode = args[1] if len(args) > 1 and args[1] is not None else "r"
                if isinstance(file_path, str):
                    if "w" in str(mode) or "a" in str(mode) or "+" in str(mode):
                        if not file_path.endswith(".pyc") and "__pycache__" not in file_path:
                            abs_path = os.path.abspath(file_path)
                            WRITTEN_FILES.add(abs_path)
                            send_telemetry(job_id, "FILE_WRITE", {"path": abs_path})

            # Dynamic code execution
            elif event == "exec":
                target = str(args[0])[:200] if args else ""
                send_telemetry(job_id, "EXECUTION", {"type": "exec", "target": target})

            elif event == "compile":
                source = args[0]
                if isinstance(source, bytes):
                    source = source.decode("utf-8", errors="ignore")
                elif not isinstance(source, str):
                    source = str(source)
                if len(source) > 0 and source != "<module>":
                    send_telemetry(job_id, "EXECUTION", {
                        "type": "compile",
                        "target": source[:200],
                    })

        except Exception:
            pass

    return audit_hook


def run_python(job_id: str, file_path: str, timeout: int = 120) -> int:
    """
    Execute a Python file with audit hook instrumentation.

    Args:
        job_id: Unique job identifier for telemetry tagging.
        file_path: Path to the Python file to execute.
        timeout: Max execution time in seconds (enforced by caller).

    Returns:
        Exit code (0 = success, non-zero = error).
    """
    if not os.path.exists(file_path):
        send_telemetry(job_id, "EXECUTION_ERROR", {"error": f"File not found: {file_path}"})
        return 1

    # Set environment
    os.environ["AEGIS_JOB_ID"] = job_id
    os.environ["SENTINEL_JOB_ID"] = job_id

    # Create isolated execution directory
    jail_dir = tempfile.mkdtemp(prefix="aegis_py_runner_")

    try:
        # Copy script to jail
        target_name = os.path.basename(file_path)
        jailed_path = os.path.join(jail_dir, target_name)
        shutil.copy2(file_path, jailed_path)

        # Restrict working directory
        original_cwd = os.getcwd()
        os.chdir(jail_dir)

        # Install audit hook
        audit_hook = create_audit_hook(job_id)
        sys.addaudithook(audit_hook)

        # Emit start telemetry
        send_telemetry(job_id, "STATUS_CHANGE", {"status": "analyzing"})
        send_telemetry(job_id, "PROCESS_CREATE", {"cmdline": f"python {target_name}"})

        # Execute
        try:
            import runpy
            runpy.run_path(jailed_path, run_name="__main__")
            return 0
        except SystemExit as e:
            return e.code if isinstance(e.code, int) else 0
        except Exception as e:
            send_telemetry(job_id, "EXECUTION_ERROR", {"error": str(e)})
            return 1

    finally:
        # Finalize file tracking
        finalize_file_writes(job_id)

        # Cleanup jail
        try:
            os.chdir(original_cwd)
            shutil.rmtree(jail_dir, ignore_errors=True)
        except Exception:
            pass


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python python_runner.py <job_id> <target_script.py>")
        sys.exit(1)

    job_id = sys.argv[1]
    target = sys.argv[2]

    exit_code = run_python(job_id, target)
    sys.exit(exit_code)
