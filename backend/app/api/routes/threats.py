from fastapi import APIRouter, Depends
from typing import List, Dict, Any
from app.database.mongodb import db
from app.api.dependencies.auth import get_current_user

router = APIRouter()

# ── MITRE ATT&CK Technique → Tactic Mapping ─────────────────────────────────
# Maps technique ID prefixes to their primary tactic category.
# This provides proper horizontal distribution across the matrix columns.
TECHNIQUE_TACTIC_MAP = {
    # Reconnaissance
    "T1595": "Reconnaissance",
    "T1592": "Reconnaissance",
    "T1589": "Reconnaissance",
    "T1590": "Reconnaissance",
    # Initial Access
    "T1566": "Initial Access",
    "T1190": "Initial Access",
    "T1133": "Initial Access",
    "T1078": "Initial Access",
    # Execution
    "T1059": "Execution",
    "T1204": "Execution",
    "T1203": "Execution",
    "T1047": "Execution",
    "T1053": "Execution",
    "T1569": "Execution",
    # Persistence
    "T1547": "Persistence",
    "T1546": "Persistence",
    "T1136": "Persistence",
    "T1543": "Persistence",
    "T1098": "Persistence",
    # Privilege Escalation
    "T1548": "Privilege Escalation",
    "T1134": "Privilege Escalation",
    "T1068": "Privilege Escalation",
    # Defense Evasion
    "T1027": "Defense Evasion",
    "T1036": "Defense Evasion",
    "T1070": "Defense Evasion",
    "T1140": "Defense Evasion",
    "T1562": "Defense Evasion",
    "T1055": "Defense Evasion",
    "T1218": "Defense Evasion",
    # Credential Access
    "T1003": "Credential Access",
    "T1555": "Credential Access",
    "T1110": "Credential Access",
    "T1056": "Credential Access",
    # Discovery
    "T1046": "Discovery",
    "T1082": "Discovery",
    "T1083": "Discovery",
    "T1057": "Discovery",
    "T1016": "Discovery",
    "T1049": "Discovery",
    "T1018": "Discovery",
    "T1033": "Discovery",
    "T1087": "Discovery",
    "T1135": "Discovery",
    # Lateral Movement
    "T1021": "Lateral Movement",
    "T1091": "Lateral Movement",
    "T1570": "Lateral Movement",
    # Collection
    "T1005": "Collection",
    "T1074": "Collection",
    "T1113": "Collection",
    "T1119": "Collection",
    # Command and Control
    "T1071": "Command and Control",
    "T1573": "Command and Control",
    "T1090": "Command and Control",
    "T1095": "Command and Control",
    "T1572": "Command and Control",
    "T1571": "Command and Control",
    "T1132": "Command and Control",
    "T1105": "Command and Control",
    # Exfiltration
    "T1041": "Exfiltration",
    "T1048": "Exfiltration",
    "T1567": "Exfiltration",
    # Impact
    "T1486": "Impact",
    "T1489": "Impact",
    "T1490": "Impact",
    "T1498": "Impact",
    "T1496": "Impact",
    "T1485": "Impact",
    "T1529": "Impact",
    "T1531": "Impact",
}

# Ordered tactic phases (MITRE kill chain order)
TACTIC_ORDER = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]


def _resolve_tactic(technique_id: str) -> str:
    """Resolve a technique ID to its tactic using prefix matching."""
    # Try exact match first (e.g. T1059)
    if technique_id in TECHNIQUE_TACTIC_MAP:
        return TECHNIQUE_TACTIC_MAP[technique_id]
    # Try base ID without sub-technique (e.g. T1059.001 → T1059)
    base_id = technique_id.split(".")[0]
    if base_id in TECHNIQUE_TACTIC_MAP:
        return TECHNIQUE_TACTIC_MAP[base_id]
    # Fallback heuristic by ID range
    try:
        num = int(base_id.replace("T", ""))
        if num >= 1595: return "Reconnaissance"
        if num >= 1480: return "Impact"
        if num >= 1560: return "Command and Control"
        if num >= 1040: return "Exfiltration"
    except ValueError:
        pass
    return "Execution"


@router.get("/threats/matrix")
async def get_attack_matrix(user=Depends(get_current_user)):
    """
    Returns active MITRE ATT&CK techniques grouped by tactic phase.
    Aggregates from all sandbox job results for the matrix view.
    """
    is_admin = "admin" in user.get("roles", [])
    base_query = {} if is_admin else {"$or": [{"submitted_by": user["username"]}, {"shared_with": user["username"]}]}
    
    pipeline = [
        {"$match": base_query},
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
    
    # Group techniques under their resolved tactic
    grouped: Dict[str, Dict] = {}
    for r in results:
        technique_id = r["_id"]
        tactic_name = _resolve_tactic(technique_id)
        
        if tactic_name not in grouped:
            grouped[tactic_name] = {
                "id": tactic_name.upper().replace(" ", "_"),
                "name": tactic_name,
                "techniques": []
            }
        
        grouped[tactic_name]["techniques"].append({
            "id": technique_id,
            "name": r["name"],
            "active": True,
            "frequency": r["frequency"]
        })
    
    # Return in kill chain order
    ordered = []
    for tactic in TACTIC_ORDER:
        if tactic in grouped:
            ordered.append(grouped[tactic])
    
    # Append any that didn't match known order
    for name, data in grouped.items():
        if name not in TACTIC_ORDER:
            ordered.append(data)
    
    return ordered
