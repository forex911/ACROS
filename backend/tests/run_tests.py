import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from app.services.report_generator import generate_report_pipeline
import json

async def run_all():
    payloads = [
        "benign_hello.py",
        "exec_usage.py",
        "subprocess_whoami.py",
        "socket_connect.py",
        "powershell_encoded.py",
        "ransomware_simulator.py"
    ]
    
    payloads_dir = os.path.join(os.path.dirname(__file__), "payloads")
    
    for payload in payloads:
        print(f"\n{'='*50}\nTESTING: {payload}\n{'='*50}")
        path = os.path.join(payloads_dir, payload)
        
        job_id = f"test_{payload.split('.')[0]}"
        
        try:
            report = await generate_report_pipeline(job_id, path, payload)
            
            print(f"Risk Score: {report.get('risk_score')}")
            print(f"Tactics: {len(report.get('mitre_tactics', []))}")
            for t in report.get('mitre_tactics', []):
                print(f"  - {t['id']}: {t['name']}")
                
        except Exception as e:
            print(f"Error testing {payload}: {e}")

if __name__ == "__main__":
    asyncio.run(run_all())
