import argparse
import sys
import threading
import time
import os

from artifact_loader import load_artifact
from telemetry_manager import telemetry_manager
from executor import execute_artifact

# Make sure monitor is in python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from monitor.ebpf_collector import EBPFCollector

def main():
    parser = argparse.ArgumentParser(description="Sandbox Runner Entrypoint")
    parser.add_argument("--artifact", required=True, help="Path to the downloaded artifact")
    parser.add_argument("--job-id", required=True, help="Job ID for telemetry tagging")
    args = parser.parse_args()

    # 1. Start Telemetry Queue
    telemetry_manager.start()

    # 2. Start eBPF Collector Thread
    collector = EBPFCollector(telemetry_manager=telemetry_manager)
    
    # We use a flag to stop the ebpf polling loop
    stop_ebpf = False
    
    def run_ebpf():
        while not stop_ebpf:
            collector.poll()
            time.sleep(0.01)

    ebpf_thread = threading.Thread(target=run_ebpf, daemon=True)
    ebpf_thread.start()

    try:
        # 3. Load & Validate Artifact
        telemetry_manager.emit_event("SANDBOX_START", {}, {"job_id": args.job_id, "artifact": args.artifact})
        file_type = load_artifact(args.artifact)
        
        # 4. Execute Artifact
        telemetry_manager.emit_event("EXECUTION_START", {}, {"file_type": file_type})
        exit_code = execute_artifact(args.artifact, file_type, timeout=120)
        
        telemetry_manager.emit_event("EXECUTION_COMPLETE", {}, {"exit_code": exit_code})
        
    except Exception as e:
        telemetry_manager.emit_event("EXECUTION_ERROR", {}, {"error": str(e)})
    finally:
        # 5. Cleanup
        stop_ebpf = True
        ebpf_thread.join(timeout=1.0)
        telemetry_manager.stop()

if __name__ == "__main__":
    main()
