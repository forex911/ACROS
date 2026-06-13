import socket

try:
    print("Resolving google.com...")
    ip = socket.gethostbyname("google.com")
    print(f"Resolved to {ip}")
except Exception as e:
    print(f"Error: {e}")
