import logging
from typing import List, Dict, Any
from app.database.neo4j import get_neo4j_async_session

logger = logging.getLogger("threat_correlation")

# Event type priority for timeline ordering
EVENT_PRIORITY = {
    "PROCESS_CREATE": 1,
    "EXECUTION": 1,
    "FILE_WRITE": 2,
    "FILE_READ": 2,
    "REGISTRY_MODIFY": 3,
    "DNS_QUERY": 4,
    "SOCKET_CONNECT": 5,
    "NETWORK_CONNECT": 5,
    "HTTP_REQUEST": 6,
}

# Human-readable stage labels
STAGE_LABELS = {
    "PROCESS_CREATE": "Process Spawned",
    "EXECUTION": "Code Executed",
    "FILE_WRITE": "File Written",
    "FILE_READ": "File Read",
    "REGISTRY_MODIFY": "Registry Modified",
    "DNS_QUERY": "DNS Resolved",
    "SOCKET_CONNECT": "Network Connection",
    "NETWORK_CONNECT": "Network Connection",
    "HTTP_REQUEST": "HTTP Request",
}


def build_attack_timeline(telemetry_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Builds a chronologically ordered attack timeline from telemetry events.
    Groups events into attack stages and creates a cause-effect chain.
    
    Returns a list of timeline stages:
    [
        {"stage": 1, "label": "File Executed", "type": "EXECUTION", "detail": "...", "timestamp": "..."},
        {"stage": 2, "label": "PowerShell Spawned", "type": "PROCESS_CREATE", "detail": "...", "timestamp": "..."},
        ...
    ]
    """
    if not telemetry_events:
        return []

    # Sort by timestamp if available, otherwise maintain original order
    sorted_events = sorted(
        telemetry_events,
        key=lambda e: (
            e.get("timestamp", ""),
            EVENT_PRIORITY.get(e.get("type", ""), 99)
        )
    )

    timeline = []
    seen_details = set()  # Deduplicate identical events

    for event in sorted_events:
        evt_type = event.get("type", "")
        data = event.get("data", {})
        timestamp = event.get("timestamp", "")

        if evt_type not in STAGE_LABELS:
            continue

        # Build detail string based on event type
        detail = _build_detail(evt_type, data)
        dedup_key = f"{evt_type}:{detail}"

        if dedup_key in seen_details:
            continue
        seen_details.add(dedup_key)

        timeline.append({
            "stage": len(timeline) + 1,
            "label": STAGE_LABELS.get(evt_type, evt_type),
            "type": evt_type,
            "detail": detail,
            "timestamp": timestamp,
            "data": data
        })

    return timeline


def _build_detail(evt_type: str, data: dict) -> str:
    """Generate a human-readable detail string for a timeline entry."""
    if evt_type in ("PROCESS_CREATE", "EXECUTION"):
        cmd = data.get("cmdline", data.get("target", ""))
        name = data.get("name", data.get("executable", ""))
        return f"{name}: {cmd[:80]}" if cmd else name

    elif evt_type == "FILE_WRITE":
        return data.get("path", data.get("filename", "unknown"))

    elif evt_type == "REGISTRY_MODIFY":
        return data.get("key", "unknown")

    elif evt_type == "DNS_QUERY":
        return data.get("query", "unknown")

    elif evt_type in ("SOCKET_CONNECT", "NETWORK_CONNECT"):
        ip = data.get("dest_ip", "")
        port = data.get("dest_port", "")
        return f"{ip}:{port}"

    elif evt_type == "HTTP_REQUEST":
        return data.get("url", "unknown")

    return str(data)[:80]


async def ingest_timeline_to_graph(job_id: str, timeline: List[Dict[str, Any]]):
    """
    Creates a :FOLLOWED_BY chain in Neo4j connecting timeline stages
    sequentially, enabling graph-based attack path traversal.
    """
    if len(timeline) < 2:
        return

    try:
        async with get_neo4j_async_session() as session:
            # Create all timeline nodes
            for entry in timeline:
                create_query = """
                MATCH (j:SandboxJob {job_id: $job_id})
                MERGE (s:TimelineStage {job_id: $job_id, stage: $stage})
                SET s.label = $label, s.type = $type, s.detail = $detail, s.timestamp = $timestamp
                MERGE (j)-[:HAS_STAGE]->(s)
                """
                await session.run(create_query,
                    job_id=job_id,
                    stage=entry["stage"],
                    label=entry["label"],
                    type=entry["type"],
                    detail=entry["detail"],
                    timestamp=entry.get("timestamp", "")
                )

            # Chain stages with :FOLLOWED_BY
            for i in range(len(timeline) - 1):
                chain_query = """
                MATCH (a:TimelineStage {job_id: $job_id, stage: $stage_a})
                MATCH (b:TimelineStage {job_id: $job_id, stage: $stage_b})
                MERGE (a)-[:FOLLOWED_BY]->(b)
                """
                await session.run(chain_query,
                    job_id=job_id,
                    stage_a=timeline[i]["stage"],
                    stage_b=timeline[i + 1]["stage"]
                )

            logger.info(f"[Timeline] Ingested {len(timeline)} stages for job {job_id}")
    except Exception as e:
        logger.error(f"[Timeline] Graph ingestion failed for {job_id}: {e}")
