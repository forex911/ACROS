"""
Process tracking orchestrator.

Delegates execution tracing to the highly-efficient eBPF collector
rather than expensive and slow psutil polling.
"""

import logging
from typing import List, Dict, Any

from monitor.ebpf_collector import EBPFCollector

logger = logging.getLogger(__name__)

class ProcessTracker:
    def __init__(self, target_pid: int = None):
        """
        Initializes the event-driven eBPF process tracker.
        The psutil implementation has been formally deprecated.
        """
        self.target_pid = target_pid
        self.collector = EBPFCollector(target_pid=target_pid)
        self.process_tree = {}

    def scan_processes(self) -> List[Dict[str, Any]]:
        """
        Drains the eBPF perf ring buffer for new events.
        Maintains the API signature for backward compatibility with monitor loop.
        """
        # Poll the kernel for new exec events
        events = self.collector.poll()
        
        for event in events:
            # Build an internal process tree representation
            pid = event["details"]["pid"]
            self.process_tree[pid] = event["details"]
            
        return events

    def get_events(self) -> List[Dict[str, Any]]:
        return self.collector.get_events()
