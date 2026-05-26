import requests
import json

print("Logging in...")
res = requests.post("http://127.0.0.1:8000/auth/login", data={"username":"my_user", "password":"password123"}, timeout=5)
token = res.json().get("access_token")

print("Uploading...")
headers = {"Authorization": f"Bearer {token}"}
with open("benign_test.py", "rb") as f:
    res = requests.post("http://127.0.0.1:8000/upload", headers=headers, files={"file": f}, timeout=10)
    
print("Upload status:", res.status_code)
print("Upload response:", res.text)

if res.status_code in (200, 202):
    job_id = res.json().get("file_id")
    print(f"Fetching /analysis/{job_id}...")
    res = requests.get(f"http://127.0.0.1:8000/analysis/{job_id}", headers=headers, timeout=5)
    print("Analysis status:", res.status_code)
    print("Analysis response:", res.text)
