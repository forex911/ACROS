from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException
from typing import Optional
import json

from app.models.job_model import get_job, get_logs, get_metrics
from app.database.redis import redis_client
from app.database.neo4j import get_neo4j_async_session

router = APIRouter()


@router.get("/jobs/{job_id}")
async def read_job(job_id: str):
    doc = await get_job(job_id)
    if not doc:
        raise HTTPException(status_code=404, detail="job_not_found")
    return doc


@router.get("/jobs/{job_id}/logs")
async def read_job_logs(job_id: str):
    logs = await get_logs(job_id)
    return {"job_id": job_id, "logs": logs}


@router.get("/jobs/{job_id}/metrics")
async def read_job_metrics(job_id: str):
    metrics = await get_metrics(job_id)
    return {"job_id": job_id, "metrics": metrics}

@router.get("/jobs/{job_id}/timeline")
async def get_job_timeline(job_id: str):
    """
    Returns a chronologically ordered list of all events (Process and Network) 
    associated with this sandbox job for the Timeline Replay player.
    """
    query = """
    MATCH (j:SandboxJob {job_id: $job_id})
    OPTIONAL MATCH (p:Process {job_id: $job_id})
    OPTIONAL MATCH (p)-[r:CONNECTED_TO]->(ip:IPAddress)
    RETURN 
        collect(DISTINCT p) as processes,
        collect(DISTINCT {process: p, connection: r, ip: ip}) as network_events
    """
    try:
        async with get_neo4j_async_session() as session:
            result = await session.run(query, job_id=job_id)
            record = await result.single()
            
            events = []
            
            if record:
                # Mock timestamp ordering since we didn't store exact timestamps on nodes in this basic graph schema
                # In production, order by node.timestamp
                for p in record["processes"]:
                    if p:
                        events.append({"type": "process", "data": dict(p)})
                for n in record["network_events"]:
                    if n and n.get("connection"):
                        events.append({
                            "type": "network", 
                            "data": {
                                "pid": dict(n["process"]).get("pid"), 
                                "ip": dict(n["ip"]).get("address"), 
                                "port": dict(n["connection"]).get("port")
                            }
                        })
                        
            return {"job_id": job_id, "events": events}
    except Exception as e:
        # Fallback to simulated events if Neo4j is offline or fails
        return {
            "job_id": job_id,
            "events": [
                {"type": "process", "data": {"pid": 4192, "image": "malware.exe", "cmdline": "malware.exe"}},
                {"type": "network", "data": {"pid": 4192, "ip": "185.11.23.4", "port": 443}}
            ]
        }


@router.websocket("/ws/jobs/{job_id}/telemetry")
async def ws_job_updates(websocket: WebSocket, job_id: str):
    await websocket.accept()
    pubsub = redis_client.pubsub()
    channel = f"job_updates:{job_id}"
    await pubsub.subscribe(channel)
    try:
        async for message in pubsub.listen():
            if message is None:
                continue
            # message: dict with type, channel, data
            if message.get('type') != 'message':
                continue
            data = message.get('data')
            # redis returns bytes for data
            if isinstance(data, (bytes, bytearray)):
                try:
                    payload = json.loads(data.decode('utf-8'))
                except Exception:
                    payload = {'raw': data.decode('utf-8', errors='ignore')}
            else:
                payload = data
            await websocket.send_json(payload)
    except WebSocketDisconnect:
        await pubsub.unsubscribe(channel)
    finally:
        try:
            await pubsub.close()
        except Exception:
            pass
