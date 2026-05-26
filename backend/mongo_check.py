import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import json

async def check_mongo():
    client = AsyncIOMotorClient("mongodb://localhost:27017/")
    db = client["sentinel_ai"]
    job = await db.sandbox_jobs.find_one({"job_id": "0d423767-ced9-443c-b575-bca82e8c6701"})
    
    # Simulate what analysis.py does
    res = {
        "file_id": job.get("job_id"),
        "filename": job.get("filename"),
        "status": job.get("status"),
        "risk_score": job.get("risk_score"),
        "ai_summary": job.get("ai_summary", "Analysis in progress..."),
        "yara_matches": job.get("yara_matches", []),
        "mitre_tactics": job.get("mitre_tactics", []),
        "metadata": job.get("extra", {})
    }
    print(json.dumps(res, indent=2))

if __name__ == "__main__":
    asyncio.run(check_mongo())
