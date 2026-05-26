import asyncio
import json
import random
import time
from datetime import datetime
from app.database.redis import redis_client
from app.models.job_model import update_job_status
import logging

logger = logging.getLogger("telemetry_simulator")

# Realistic behaviors based on common malware
MALWARE_BEHAVIORS = [
    {
        "processes": [
            {"cmd": "cmd.exe /c vssadmin.exe Delete Shadows /All /Quiet", "technique": "T1490", "desc": "Inhibit System Recovery"},
            {"cmd": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABz...", "technique": "T1059.001", "desc": "PowerShell Execution"},
            {"cmd": "schtasks /create /tn \"Update\" /tr \"C:\\Users\\Public\\malware.exe\" /sc onlogon", "technique": "T1053.005", "desc": "Scheduled Task Persistence"}
        ],
        "network": [
            {"ip": "185.11.23.4", "port": 443, "desc": "C2 Callback"},
            {"ip": "193.201.224.1", "port": 80, "desc": "Payload Download"},
            {"ip": "91.214.124.23", "port": 8080, "desc": "Tor Exit Node"}
        ],
        "dns": [
            {"query": "update.windows-services-domain.com", "desc": "DGA Domain"},
            {"query": "pastebin.com", "desc": "Code Hosting Query"}
        ],
        "iocs": [
            "Ransom_LockBit_v2",
            "Suspicious_Packed_UPX",
            "Trojan_Emotet_Heur"
        ]
    }
]

async def publish_event(job_id: str, event_type: str, data: dict):
    """Publish an event to Redis pubsub for WebSockets."""
    channel = f"job_updates:{job_id}"
    message = {
        "type": event_type,
        "data": data,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    await redis_client.publish(channel, json.dumps(message))

async def simulate_sandbox_execution(job_id: str, filename: str):
    """Simulates a live malware sandbox execution, generating realistic telemetry over time."""
    logger.info(f"Starting telemetry simulation for job {job_id}")
    
    # 1. Start execution
    await update_job_status(job_id, "analyzing")
    await publish_event(job_id, "STATUS_CHANGE", {"status": "analyzing"})
    await asyncio.sleep(random.uniform(1.0, 2.5))
    
    behavior = random.choice(MALWARE_BEHAVIORS)
    
    # 2. Initial execution
    await publish_event(job_id, "PROCESS_CREATE", {"pid": 4192, "image": filename, "cmdline": f"{filename}"})
    await asyncio.sleep(random.uniform(0.5, 1.5))
    
    # 3. Process activity (ATT&CK techniques)
    for proc in behavior["processes"]:
        await publish_event(job_id, "PROCESS_CREATE", {"pid": random.randint(5000, 9000), "image": proc["cmd"].split()[0], "cmdline": proc["cmd"]})
        await publish_event(job_id, "ATTACK_MAPPED", {"technique_id": proc["technique"], "description": proc["desc"]})
        await asyncio.sleep(random.uniform(1.0, 3.0))
        
    # 4. Network and DNS
    for dns in behavior["dns"]:
        await publish_event(job_id, "DNS_QUERY", {"domain": dns["query"]})
        await asyncio.sleep(random.uniform(0.2, 0.8))
        
    for net in behavior["network"]:
        await publish_event(job_id, "NETWORK_CONNECT", {"dest_ip": net["ip"], "dest_port": net["port"], "protocol": "TCP"})
        await asyncio.sleep(random.uniform(0.5, 1.5))
        
    # 5. Extract IOCs and finalize
    for ioc in behavior["iocs"]:
        # Randomly emit IOCs
        if random.random() > 0.5:
            await publish_event(job_id, "YARA_MATCH", {"rule": ioc})
            await asyncio.sleep(random.uniform(0.1, 0.5))
            
    # 6. Generate final AI summary
    risk_score = random.randint(75, 99)
    summary = f"The analyzed sample {filename} exhibits highly suspicious behaviors. It initiated network connections to known C2 IPs and attempted persistence via scheduled tasks. AI classification indicates a {risk_score}% probability of being malicious."
    
    from app.database.mongodb import db
    # Persist the final report into MongoDB
    await db["sandbox_jobs"].update_one(
        {"job_id": job_id},
        {"$set": {
            "status": "completed", 
            "risk_score": risk_score, 
            "ai_summary": summary,
            "yara_matches": behavior["iocs"],
            "mitre_tactics": [{"id": p["technique"], "name": p["desc"]} for p in behavior["processes"]]
        }}
    )
    
    await publish_event(job_id, "ANALYSIS_COMPLETE", {"risk_score": risk_score, "summary": summary})
    await update_job_status(job_id, "completed")
    logger.info(f"Finished telemetry simulation for job {job_id}")
