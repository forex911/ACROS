import json
import datetime
import sys
import queue
import threading

class TelemetryManager:
    """
    Manages telemetry events, enforces schema, and flushes to stdout 
    in a thread-safe manner so the Kubernetes job manager can read it.
    """
    def __init__(self):
        self._queue = queue.Queue()
        self._stop_event = threading.Event()
        self._worker_thread = threading.Thread(target=self._process_queue, daemon=True)

    def start(self):
        self._worker_thread.start()

    def stop(self):
        self._stop_event.set()
        self._worker_thread.join(timeout=2.0)
        # Flush remaining
        while not self._queue.empty():
            self._emit(self._queue.get_nowait())

    def _process_queue(self):
        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                event = self._queue.get(timeout=0.1)
                self._emit(event)
            except queue.Empty:
                continue

    def _emit(self, event_data: dict):
        # Ensure schema compliance
        out = {
            "__telemetry__": True,
            "event_type": event_data.get("event_type", "UNKNOWN"),
            "timestamp": event_data.get("timestamp", datetime.datetime.utcnow().isoformat() + "Z"),
            "process": event_data.get("process", {}),
            "metadata": event_data.get("metadata", {})
        }
        print(json.dumps(out), flush=True)

    def emit_event(self, event_type: str, process_info: dict, metadata: dict, timestamp: str = None):
        """
        Pushes a new telemetry event to the queue.
        """
        self._queue.put({
            "event_type": event_type,
            "process": process_info,
            "metadata": metadata,
            "timestamp": timestamp or (datetime.datetime.utcnow().isoformat() + "Z")
        })

# Global singleton
telemetry_manager = TelemetryManager()
