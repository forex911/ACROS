"""
MITRE ATT&CK Severity Mapping
==============================
Assigns weighted severity scores to ATT&CK techniques based on their
tactical category. Impact techniques (like ransomware) score far higher
than generic execution techniques.
"""

from typing import List, Dict, Tuple

# Tactic → base severity score per technique
TACTIC_SEVERITY = {
    "Execution": 10,
    "Discovery": 10,
    "Resource Development": 10,
    "Reconnaissance": 10,
    "Collection": 15,
    "Persistence": 20,
    "Defense Evasion": 25,
    "Credential Access": 30,
    "Lateral Movement": 30,
    "Privilege Escalation": 25,
    "Command and Control": 35,
    "Exfiltration": 35,
    "Impact": 40,
}

# Known technique ID → tactic mapping
TECHNIQUE_TACTIC = {
    # Execution
    "T1059": "Execution",
    "T1059.001": "Execution",
    "T1059.003": "Execution",
    "T1059.005": "Execution",
    "T1059.006": "Execution",

    # Defense Evasion
    "T1055": "Defense Evasion",
    "T1027": "Defense Evasion",
    "T1027.002": "Defense Evasion",
    "T1027.007": "Defense Evasion",
    "T1027.010": "Defense Evasion",
    "T1140": "Defense Evasion",
    "T1497.001": "Defense Evasion",
    "T1112": "Defense Evasion",

    # Impact
    "T1490": "Impact",
    "T1486": "Impact",

    # Persistence
    "T1547.001": "Persistence",
    "T1053": "Persistence",
    "T1053.003": "Persistence",
    "T1053.005": "Persistence",
    "T1543.003": "Persistence",

    # Command and Control
    "T1071": "Command and Control",
    "T1571": "Command and Control",
    "T1105": "Command and Control",

    # Discovery
    "T1033": "Discovery",
    "T1046": "Discovery",
    "T1082": "Discovery",

    # Credential Access
    "T1555.003": "Credential Access",
    "T1539": "Credential Access",
    "T1528": "Credential Access",
    "T1552": "Credential Access",
    "T1056.001": "Credential Access",

    # Collection
    "T1113": "Collection",
    "T1125": "Collection",
    "T1074": "Collection",

    # Exfiltration
    "T1048": "Exfiltration",

    # Privilege Escalation
    "T1134": "Privilege Escalation",
    "T1548": "Privilege Escalation",
}


def get_technique_severity(technique_id: str) -> int:
    """Return the severity score for a single technique ID."""
    tactic = TECHNIQUE_TACTIC.get(technique_id)
    if tactic:
        return TACTIC_SEVERITY.get(tactic, 10)
    return 10  # default for unknown techniques


def score_mitre_techniques(mitre_techniques: List[Dict]) -> Tuple[int, List[str]]:
    """
    Score a list of MITRE technique mappings using severity-weighted scoring.
    
    Returns:
        (score, reasoning): score capped at 100, plus human-readable reasoning.
    """
    if not mitre_techniques:
        return 0, []

    total = 0
    reasoning = []
    seen_ids = set()

    for tech in mitre_techniques:
        tech_id = tech.get("id", "")
        tech_name = tech.get("name", tech_id)

        if tech_id in seen_ids:
            continue
        seen_ids.add(tech_id)

        severity = get_technique_severity(tech_id)
        tactic = TECHNIQUE_TACTIC.get(tech_id, "Unknown")
        total += severity
        reasoning.append(f"{tech_id} {tech_name} [{tactic}] → +{severity}")

    capped = min(100, total)
    return capped, reasoning
