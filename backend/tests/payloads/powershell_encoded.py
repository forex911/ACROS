import subprocess
import base64

# Encoded powershell payload simulation
payload = "Write-Host 'Malicious Activity'"
encoded = base64.b64encode(payload.encode('utf-16le')).decode('utf-8')

print("Executing encoded powershell")
subprocess.run(["powershell.exe", "-EncodedCommand", encoded])
