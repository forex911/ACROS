import asyncio
import httpx
import os
import tempfile
import time

BASE_URL = "http://127.0.0.1:8000"

async def test_path_traversal(client):
    print("\n[+] Testing Path Traversal on Upload")
    files = {
        "file": ("../../../windows/system32/cmd.exe", b"print('fake malware')", "text/x-python")
    }
    resp = await client.post(f"{BASE_URL}/upload", files=files)
    print(f"Status: {resp.status_code}")
    if resp.status_code in [200, 202]:
        print("    [WARNING] Backend accepted path traversal payload! Ensure file basename is sanitized.")
    else:
        print("    [OK] Backend rejected or sanitized traversal payload.")


async def test_oversized_payload(client):
    print("\n[+] Testing Oversized Payload (DoS Protection)")
    # Create a dummy 101MB file (assuming 100MB is the limit)
    print("    Generating 101MB dummy payload...")
    with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as tmp:
        tmp.write(b"x" * (101 * 1024 * 1024))
        tmp_path = tmp.name

    try:
        with open(tmp_path, "rb") as f:
            files = {"file": ("huge_file.py", f, "text/x-python")}
            resp = await client.post(f"{BASE_URL}/upload", files=files)
        print(f"Status: {resp.status_code}")
        if resp.status_code == 413:
            print("    [OK] Backend correctly rejected oversized payload (413 Payload Too Large).")
        else:
            print(f"    [WARNING] Backend accepted payload or returned unexpected status: {resp.status_code}")
    finally:
        os.remove(tmp_path)


async def test_mime_type_spoofing(client):
    print("\n[+] Testing MIME Type Spoofing / Magic Bytes Validation")
    # File has .py extension, but is actually an MZ executable or just junk
    fake_python = b"MZ\x90\x00\x03\x00\x00\x00" + b"A" * 100 
    files = {
        "file": ("fake_script.py", fake_python, "text/x-python")
    }
    resp = await client.post(f"{BASE_URL}/upload", files=files)
    print(f"Status: {resp.status_code}")
    if resp.status_code == 400:
        print("    [OK] Backend detected signature mismatch and rejected.")
    else:
        print("    [WARNING] Backend accepted file with mismatched extension and magic bytes.")


async def test_nosql_injection(client):
    print("\n[+] Testing NoSQL Injection on Search/Jobs API")
    # Attempting to bypass auth or fetch all jobs using MongoDB $ne or $gt operators
    injection_payload = {"$ne": None}
    
    # Passing injection as a query param (FastAPI usually blocks this via Pydantic typing)
    resp = await client.get(f"{BASE_URL}/jobs?status[$ne]=null")
    print(f"Status: {resp.status_code}")
    if resp.status_code in [400, 422]:
        print("    [OK] Pydantic successfully blocked NoSQL injection payload.")
    else:
        print(f"    [WARNING] Endpoint returned {resp.status_code} - check for injection vulnerability.")


async def test_rate_limiting(client):
    print("\n[+] Testing API Rate Limiting")
    print("    Spamming 150 requests to /health...")
    
    async def fetch():
        return await client.get(f"{BASE_URL}/health")
        
    tasks = [fetch() for _ in range(150)]
    results = await asyncio.gather(*tasks)
    
    statuses = [r.status_code for r in results]
    too_many_requests = statuses.count(429)
    print(f"    200 OK: {statuses.count(200)}")
    print(f"    429 Too Many Requests: {too_many_requests}")
    
    if too_many_requests > 0:
        print("    [OK] Rate limiter is active and working.")
    else:
        print("    [WARNING] Rate limiter did not trigger! (Check limiter configuration).")


async def main():
    print("==================================================")
    print("        ACROS AI - BACKEND SECURITY TESTER        ")
    print("==================================================")
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        await test_path_traversal(client)
        await test_mime_type_spoofing(client)
        await test_nosql_injection(client)
        await test_rate_limiting(client)
        await test_oversized_payload(client)
        
    print("\n[!] Security testing complete.")

if __name__ == "__main__":
    asyncio.run(main())
