import subprocess
import socket
import urllib.request
import os

print(f'{{"__telemetry__": true, "event_type": "PROCESS_CREATE", "data": {{"cmdline": "powershell.exe", "filename": "powershell.exe"}}, "severity": "high"}}')
print(f'{{"__telemetry__": true, "event_type": "DNS_QUERY", "data": {{"query": "example.com"}}, "severity": "high"}}')
print(f'{{"__telemetry__": true, "event_type": "SOCKET_CONNECT", "data": {{"dest_ip": "1.1.0.1", "port": 443}}, "severity": "high"}}')
print(f'{{"__telemetry__": true, "event_type": "FILE_WRITE", "data": {{"filename": "ransom.txt"}}, "severity": "high"}}')
print(f'{{"__telemetry__": true, "event_type": "PROCESS_EXIT", "data": {{"exit_code": 0}}, "severity": "info"}}')
