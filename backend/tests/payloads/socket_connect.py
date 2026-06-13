import socket

try:
    print("Connecting to 1.1.1.1:80...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(("1.1.1.1", 80))
    s.close()
    print("Connected successfully")
except Exception as e:
    print(f"Error: {e}")
