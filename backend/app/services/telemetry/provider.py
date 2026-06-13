"""
Abstract Telemetry Provider — defines the common schema that all runtime-specific
collectors must emit. Downstream systems (GraphIngester, IOC pipeline, MITRE mapper)
consume only these normalized dataclasses.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, AsyncIterator, Optional
from datetime import datetime


@dataclass
class ProcessEvent:
    pid: int
    ppid: int
    name: str
    cmdline: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class NetworkEvent:
    pid: int
    dest_ip: str
    dest_port: int
    protocol: str = "TCP"
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class FileEvent:
    pid: int
    path: str
    operation: str = "WRITE"  # WRITE | READ | DELETE
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class DnsEvent:
    pid: int
    query: str
    resolved_ip: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)


class TelemetryProvider(ABC):
    """
    All runtime-specific providers must implement this interface.
    The `collect()` method yields normalized events from the sandbox.
    """

    @abstractmethod
    async def collect(self, job_id: str) -> AsyncIterator:
        """
        Yields a stream of ProcessEvent | NetworkEvent | FileEvent | DnsEvent.
        The caller consumes this iterator until the sandbox execution finishes.
        """
        ...

    @staticmethod
    def event_to_dict(event) -> dict:
        """Convert a dataclass event to the telemetry dict format used by the pipeline."""
        ts_str = event.timestamp.isoformat() if isinstance(event.timestamp, datetime) else str(event.timestamp)
        if isinstance(event, ProcessEvent):
            return {
                "type": "PROCESS_CREATE",
                "timestamp": ts_str,
                "data": {
                    "pid": event.pid,
                    "ppid": event.ppid,
                    "name": event.name,
                    "cmdline": event.cmdline,
                }
            }
        elif isinstance(event, NetworkEvent):
            return {
                "type": "SOCKET_CONNECT",
                "timestamp": ts_str,
                "data": {
                    "pid": event.pid,
                    "dest_ip": event.dest_ip,
                    "dest_port": event.dest_port,
                    "protocol": event.protocol,
                }
            }
        elif isinstance(event, FileEvent):
            return {
                "type": "FILE_WRITE" if event.operation == "WRITE" else "FILE_READ",
                "timestamp": ts_str,
                "data": {
                    "pid": event.pid,
                    "path": event.path,
                }
            }
        elif isinstance(event, DnsEvent):
            return {
                "type": "DNS_QUERY",
                "timestamp": ts_str,
                "data": {
                    "pid": event.pid,
                    "query": event.query,
                    "resolved_ip": event.resolved_ip,
                }
            }
        return {}
