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


@dataclass
class RegistryEvent:
    """Registry key creation, modification, or deletion."""
    pid: int
    key: str
    value_name: str = ""
    value_data: str = ""
    operation: str = "CREATE"  # CREATE | MODIFY | DELETE
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class MemoryInjectionEvent:
    """Cross-process memory injection (VirtualAllocEx, WriteProcessMemory, etc.)."""
    source_pid: int
    target_pid: int
    api_call: str  # VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, etc.
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PersistenceEvent:
    """Persistence mechanism installation."""
    pid: int
    mechanism: str  # registry_run_key, scheduled_task, startup_folder, service
    target: str     # the key/path/task name
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PrivilegeEscalationEvent:
    """Privilege escalation attempt."""
    pid: int
    technique: str  # token_manipulation, uac_bypass, named_pipe_impersonation, etc.
    timestamp: datetime = field(default_factory=datetime.utcnow)


class TelemetryProvider(ABC):
    """
    All runtime-specific providers must implement this interface.
    The `collect()` method yields normalized events from the sandbox.
    """

    @abstractmethod
    async def collect(self, job_id: str) -> AsyncIterator:
        """
        Yields a stream of telemetry event dataclasses.
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
        elif isinstance(event, RegistryEvent):
            return {
                "type": "REGISTRY_MODIFY" if event.operation == "MODIFY" else "REGISTRY_CREATE",
                "timestamp": ts_str,
                "data": {
                    "pid": event.pid,
                    "key": event.key,
                    "value_name": event.value_name,
                    "value_data": event.value_data,
                    "operation": event.operation,
                }
            }
        elif isinstance(event, MemoryInjectionEvent):
            return {
                "type": "MEMORY_INJECTION",
                "timestamp": ts_str,
                "data": {
                    "source_pid": event.source_pid,
                    "target_pid": event.target_pid,
                    "api_call": event.api_call,
                }
            }
        elif isinstance(event, PersistenceEvent):
            return {
                "type": "PERSISTENCE_EVENT",
                "timestamp": ts_str,
                "data": {
                    "pid": event.pid,
                    "mechanism": event.mechanism,
                    "target": event.target,
                }
            }
        elif isinstance(event, PrivilegeEscalationEvent):
            return {
                "type": "PRIVILEGE_ESCALATION",
                "timestamp": ts_str,
                "data": {
                    "pid": event.pid,
                    "technique": event.technique,
                }
            }
        return {}
