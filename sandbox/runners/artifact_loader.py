import os
import subprocess
import json
import sys

def identify_file_type(file_path: str) -> str:
    """Uses the `file` utility to determine the file type."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Artifact not found: {file_path}")

    try:
        result = subprocess.run(
            ["file", "-b", file_path],
            capture_output=True,
            text=True,
            check=True
        )
        file_desc = result.stdout.strip().lower()
        
        if "pe32" in file_desc or "ms-dos" in file_desc:
            return "windows_pe"
        elif "elf" in file_desc:
            return "elf"
        elif "python" in file_desc or file_path.endswith(".py"):
            return "python"
        elif "shell" in file_desc or "bash" in file_desc or file_path.endswith(".sh"):
            return "shell"
        else:
            # Fallback based on extension or just treat as unknown
            return "unknown"
    except Exception as e:
        # Fallback to extension matching if `file` command fails
        if file_path.endswith(".exe") or file_path.endswith(".dll"):
            return "windows_pe"
        elif file_path.endswith(".py"):
            return "python"
        elif file_path.endswith(".sh"):
            return "shell"
        return "unknown"

def load_artifact(file_path: str):
    """
    Identifies the artifact. If PE, emits telemetry and exits 0.
    Returns the file type string if valid.
    """
    file_type = identify_file_type(file_path)
    
    if file_type == "windows_pe":
        print(json.dumps({
            "status": "unsupported",
            "file_type": "windows_pe"
        }), flush=True)
        sys.exit(0)
        
    return file_type
