import os
import tempfile
import pytest
import sys

# Adjust path to import runners
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runners')))

from artifact_loader import identify_file_type
from executor import execute_artifact

def test_identify_python_file():
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
        f.write(b"print('hello')\n")
        path = f.name
    try:
        ftype = identify_file_type(path)
        assert ftype == "python"
    finally:
        os.remove(path)

def test_identify_shell_file():
    with tempfile.NamedTemporaryFile(suffix=".sh", delete=False) as f:
        f.write(b"#!/bin/bash\necho 'hello'\n")
        path = f.name
    try:
        # Might return "shell" based on #!/bin/bash via `file` command,
        # or fallback to "shell" from extension
        ftype = identify_file_type(path)
        assert ftype == "shell"
    finally:
        os.remove(path)

def test_identify_pe_file():
    # Write a fake PE signature (MZ...)
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
        path = f.name
    try:
        ftype = identify_file_type(path)
        assert ftype == "windows_pe"
    finally:
        os.remove(path)

def test_executor_python():
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
        f.write(b"import sys; sys.exit(42)\n")
        path = f.name
    try:
        exit_code = execute_artifact(path, "python", timeout=5)
        assert exit_code == 42
    finally:
        os.remove(path)

def test_executor_timeout():
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
        f.write(b"import time\ntime.sleep(10)\n")
        path = f.name
    try:
        exit_code = execute_artifact(path, "python", timeout=1)
        assert exit_code == 124
    finally:
        os.remove(path)
