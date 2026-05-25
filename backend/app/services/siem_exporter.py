import logging
import httpx
from typing import Dict, Any, List
import json
from datetime import datetime
from app.database.mongodb import db

logger = logging.getLogger("siem_exporter")

class SIEMExporter:
    
    @staticmethod
    async def export_alert(alert_data: Dict[str, Any]):
        """
        Exports high-fidelity threat alerts to configured SIEM integrations (e.g., Splunk, Elastic, Webhooks).
        """
        # Fetch active integrations from MongoDB
        integrations = []
        if db is not None:
            cursor = db.integrations.find({"active": True})
            async for doc in cursor:
                integrations.append(doc)
                
        for integration in integrations:
            itype = integration.get("type")
            if itype == "webhook":
                await SIEMExporter._send_webhook(integration.get("url"), integration.get("secret"), alert_data)
            elif itype == "splunk":
                await SIEMExporter._send_splunk_hec(integration.get("url"), integration.get("token"), alert_data)
            elif itype == "elastic":
                # Simulated Elastic streaming
                logger.info(f"Simulating Elastic export for alert: {alert_data.get('alert_id')}")

    @staticmethod
    async def _send_webhook(url: str, secret: str, data: Dict[str, Any]):
        headers = {"Content-Type": "application/json", "X-Sentinel-Signature": secret}
        try:
            async with httpx.AsyncClient() as client:
                await client.post(url, json=data, headers=headers)
        except Exception as e:
            logger.error(f"Failed to export webhook to {url}: {e}")

    @staticmethod
    async def _send_splunk_hec(url: str, token: str, data: Dict[str, Any]):
        headers = {"Authorization": f"Splunk {token}"}
        payload = {
            "time": datetime.utcnow().timestamp(),
            "source": "sentinel-ai",
            "sourcetype": "_json",
            "event": data
        }
        try:
            async with httpx.AsyncClient() as client:
                await client.post(url, json=payload, headers=headers)
        except Exception as e:
            logger.error(f"Failed to export Splunk HEC to {url}: {e}")

    @staticmethod
    async def simulate_kafka_stream(topic: str, events: List[Dict[str, Any]]):
        """
        Simulates pushing raw telemetry directly into a Kafka pipeline.
        In a real deployment, this would use aiokafka.
        """
        logger.info(f"Streaming {len(events)} events to Kafka topic '{topic}'")
