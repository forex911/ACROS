import ctypes
import subprocess
import time

def simulate_process_injection():
    # T1055 Process Injection
    # We simulate loading kernel32 and using it, which the static/dynamic analyzer
    # might flag as suspicious API usage.
    
    # Normally a malware would do:
    # OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
    try:
        kernel32 = ctypes.windll.kernel32
        
        # Start a suspended notepad (or just normal)
        print("Starting target process...")
        p = subprocess.Popen(["notepad.exe"])
        time.sleep(1)
        
        # We just grab the handle for simulation purposes to trigger hooks
        # If the sandbox wrapper hooks ctypes or OpenProcess, it will see this
        PROCESS_ALL_ACCESS = 0x1F0FFF
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, p.pid)
        
        if h_process:
            print(f"Obtained handle to notepad.exe (PID: {p.pid})")
            kernel32.CloseHandle(h_process)
        
        print("Injection simulation completed.")
        p.kill()
    except Exception as e:
        print(f"Injection failed: {e}")

if __name__ == "__main__":
    simulate_process_injection()
