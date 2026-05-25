import time
import logging
import json
from typing import List, Dict, Any
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger(__name__)

class FileEventTracker(FileSystemEventHandler):
    def __init__(self):
        self.events = []

    def on_any_event(self, event):
        evt = {
            "timestamp": time.time(),
            "event_type": "file_system",
            "details": {
                "action": event.event_type,
                "path": event.src_path,
                "is_directory": event.is_directory
            }
        }
        
        # Check for persistence or critical modifications
        if not event.is_directory:
            lower_path = event.src_path.lower()
            suspicious_paths = [
                'start menu\\programs\\startup',
                'system32',
                'syswow64',
                '.ssh',
                'autorun'
            ]
            
            if any(p in lower_path for p in suspicious_paths) or lower_path.endswith(('.exe', '.dll', '.sys', '.ps1', '.bat')):
                evt["details"]["suspicious"] = True
                
        self.events.append(evt)

class FileTracker:
    def __init__(self, watch_dirs: List[str]):
        self.watch_dirs = watch_dirs
        self.observer = Observer()
        self.handler = FileEventTracker()
        
    def start(self):
        for directory in self.watch_dirs:
            try:
                self.observer.schedule(self.handler, directory, recursive=True)
                logger.info(f"Started file tracker for {directory}")
            except Exception as e:
                logger.error(f"Failed to start file tracker for {directory}: {e}")
                
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()
        logger.info("Stopped file tracker")

    def get_events(self) -> List[Dict[str, Any]]:
        events = self.handler.events.copy()
        self.handler.events.clear()
        return events
