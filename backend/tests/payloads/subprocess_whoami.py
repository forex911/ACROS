import subprocess
import os

print("Running whoami...")
subprocess.run(["whoami"], capture_output=True)
os.system("echo Hello from os.system")
