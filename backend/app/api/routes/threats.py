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



TECHNIQUE_DESCRIPTIONS = {
    # Execution
    "T1059": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms.",
    "T1059.001": "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.",
    "T1204": "Adversaries may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious payloads by clicking links or opening attachments.",
    "T1047": "Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads. WMI is an administration feature that provides a uniform environment to access Windows system components.",
    
    # Defense Evasion
    "T1027": "Adversaries may obfuscate content or information to impede analysis or prevent detection. This can include hiding payloads in legitimate files or using encryption/encoding.",
    "T1027.010": "Adversaries may use command obfuscation to hide malicious commands from defenders and security products. This often involves string manipulation, base64 encoding, or variable substitution.",
    "T1140": "Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis. They may require mechanisms to deobfuscate/decode files or information to use them during their operations.",
    "T1036": "Adversaries may masquerade as legitimate programs or files. Masquerading occurs when the name or location of an executable, legitimate or malicious, is manipulated to evade defenses.",
    "T1070": "Adversaries may clear or remove evidence of their presence or actions. This can include deleting logs, command history, or specific files to evade detection.",
    
    # Command and Control
    "T1071": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic (e.g. HTTP, HTTPS, DNS).",
    "T1105": "Adversaries may transfer tools or other files from an external system into a compromised environment. Files may be copied from an external adversary-controlled system to the victim network.",
    "T1090": "Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections.",
    
    # Discovery
    "T1082": "Adversaries may attempt to get detailed information about the operating system and hardware, including version, patches, architecture, and network configuration.",
    "T1083": "Adversaries may enumerate files and directories or search in specific locations of a host or network share for certain information.",
    "T1057": "Adversaries may attempt to get information about running processes on a system to identify defensive capabilities or other potential targets.",
    
    # Persistence / Privilege Escalation
    "T1547": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key to execute when a user logs in.",
    "T1068": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program.",
    
    # Impact
    "T1486": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.",
    "T1490": "Adversaries may inhibit access to data by modifying or deleting backups, shadow copies, or other recovery mechanisms."
}

def _get_description(tech_id: str, name: str) -> str:
    if tech_id in TECHNIQUE_DESCRIPTIONS:
        return TECHNIQUE_DESCRIPTIONS[tech_id]
    base_id = tech_id.split(".")[0]
    if base_id in TECHNIQUE_DESCRIPTIONS:
        return TECHNIQUE_DESCRIPTIONS[base_id]
    return f"{name} is a tactic used by adversaries to achieve their objectives during a cyber attack."

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
            "description": _get_description(technique_id, r["name"]),
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
