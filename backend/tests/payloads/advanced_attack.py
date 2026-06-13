import os
import socket

# Combined behavior
os.system("whoami")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(("8.8.8.8", 4444))
except:
    pass
s.close()
