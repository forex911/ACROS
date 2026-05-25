import threading
import time
import json
import logging
from typing import List, Dict, Any
from scapy.all import sniff, IP, TCP, UDP, DNSQR

logger = logging.getLogger(__name__)

class NetworkTracker:
    def __init__(self, interface: str = None):
        self.interface = interface
        self.events = []
        self._stop_event = threading.Event()
        self.sniffer_thread = None

    def start(self):
        self._stop_event.clear()
        self.sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniffer_thread.start()
        logger.info(f"Started network tracker on interface {self.interface}")

    def stop(self):
        self._stop_event.set()
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2.0)
        logger.info("Stopped network tracker")

    def _sniff_loop(self):
        # We use a relatively short timeout so we can check the stop event
        while not self._stop_event.is_set():
            try:
                sniff(iface=self.interface, prn=self._process_packet, timeout=1.0, store=False)
            except Exception as e:
                logger.error(f"Error sniffing packets: {e}")
                time.sleep(1)

    def _process_packet(self, packet):
        try:
            event = {
                "timestamp": time.time(),
                "event_type": "network_flow",
                "details": {}
            }
            
            if IP in packet:
                event["details"]["src_ip"] = packet[IP].src
                event["details"]["dst_ip"] = packet[IP].dst
                event["details"]["protocol"] = packet[IP].proto

                if TCP in packet:
                    event["details"]["src_port"] = packet[TCP].sport
                    event["details"]["dst_port"] = packet[TCP].dport
                elif UDP in packet:
                    event["details"]["src_port"] = packet[UDP].sport
                    event["details"]["dst_port"] = packet[UDP].dport
                    
            if packet.haslayer(DNSQR):
                event["event_type"] = "dns_query"
                event["details"]["query"] = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                
            if event["details"]:
                self.events.append(event)
                
        except Exception as e:
            logger.debug(f"Failed to process packet: {e}")

    def get_events(self) -> List[Dict[str, Any]]:
        events = self.events.copy()
        self.events.clear()
        return events
