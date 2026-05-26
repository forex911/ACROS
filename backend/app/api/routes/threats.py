from fastapi import APIRouter, Depends
from typing import List, Dict, Any
from app.database.mongodb import db
from app.api.dependencies.auth import get_current_user

router = APIRouter()

@router.get("/threats/matrix")
async def get_attack_matrix(user=Depends(get_current_user)):
    """
    Returns active MITRE ATT&CK techniques derived from recent live telemetry.
    Aggregates techniques from sandbox_jobs.
    """
    # In a fully functional Neo4j setup we'd query the graph for active correlations.
    # Here we aggregate from MongoDB sandbox_jobs mitre_tactics.
    
    pipeline = [
        {"$unwind": "$mitre_tactics"},
        {"$group": {
            "_id": "$mitre_tactics.id",
            "name": {"$first": "$mitre_tactics.name"},
            "frequency": {"$sum": 1},
            "recent_job_id": {"$last": "$job_id"}
        }},
        {"$sort": {"frequency": -1}}
    ]
    
    cursor = db["sandbox_jobs"].aggregate(pipeline)
    results = await cursor.to_list(length=100)
    
    tactics = []
    for r in results:
        # Determine the top-level tactic mapping based on technique ID prefix or just dummy mapping
        # since we don't have the full MITRE DB locally.
        technique_id = r["_id"]
        tactic_name = "Execution" # default
        if technique_id.startswith("T14"):
            tactic_name = "Impact"
        elif technique_id.startswith("T1059"):
            tactic_name = "Execution"
        elif technique_id.startswith("T1053"):
            tactic_name = "Persistence"
        elif technique_id.startswith("T1090"):
            tactic_name = "Command and Control"
            
        tactics.append({
            "id": tactic_name,
            "name": tactic_name,
            "techniques": [{
                "id": technique_id,
                "name": r["name"],
                "active": True,
                "frequency": r["frequency"]
            }]
        })
        
    # Group by tactic name
    grouped = {}
    for t in tactics:
        name = t["name"]
        if name not in grouped:
            grouped[name] = {"id": t["id"], "name": name, "techniques": []}
        grouped[name]["techniques"].extend(t["techniques"])
        
    return list(grouped.values())
