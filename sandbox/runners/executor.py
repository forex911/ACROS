import subprocess
import os
import sys

def execute_artifact(file_path: str, file_type: str, timeout: int = 120) -> int:
    """
    Executes the artifact based on its type.
    Blocks until completion or timeout.
    Returns the exit code.
    """
    cmd = []
    
    if file_type == "python":
        cmd = [sys.executable, file_path]
    elif file_type == "shell":
        cmd = ["/bin/bash", file_path]
    elif file_type == "elf":
        # Make sure it's executable
        os.chmod(file_path, 0o755)
        cmd = [file_path]
    else:
        raise ValueError(f"Unsupported execution type: {file_type}")

    try:
        # Run the process
        # We redirect stdout/stderr so it doesn't pollute the telemetry JSON stream,
        # or we could capture it and emit as telemetry. We will just DEVNULL it for now
        # to ensure strict JSON output on stdout.
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False
        )
        return result.returncode
    except subprocess.TimeoutExpired:
        return 124  # Standard timeout exit code
    except Exception as e:
        return -1
