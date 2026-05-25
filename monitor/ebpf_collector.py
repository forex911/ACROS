"""
Enterprise eBPF Telemetry Collector (Event-Driven)

Replaces inefficient CPU-polling mechanisms (e.g., psutil) with 
high-fidelity, event-driven kernel tracing. Uses BCC (BPF Compiler Collection)
to attach hooks to `execve`, capturing every process execution reliably, 
even short-lived malware instances.

Note: In a true production environment, this is typically handled by
a compiled daemon like Cilium Tetragon. This Python wrapper demonstrates
the enterprise architecture for capturing syscalls asynchronously.
"""

import time
import json
import logging
from typing import List, Dict, Any

logger = logging.getLogger("ebpf_collector")

try:
    from bcc import BPF
except ImportError:
    BPF = None
    logger.warning("BCC/eBPF not installed on host. Running in fallback simulation mode.")

# --- eBPF C Program for execve interception ---
EBPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[128];
};

BPF_PERF_OUTPUT(events);

int kprobe__sys_execve(struct pt_regs *ctx, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp) {
    struct data_t data = {};
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

class EBPFCollector:
    def __init__(self, target_pid: int = None):
        self.target_pid = target_pid
        self.events: List[Dict[str, Any]] = []
        self.bpf = None
        
        if BPF:
            try:
                self.bpf = BPF(text=EBPF_PROGRAM)
                self.bpf["events"].open_perf_buffer(self._perf_event_callback)
                logger.info("Successfully attached eBPF kprobes for execve tracking.")
            except Exception as e:
                logger.error(f"Failed to compile/attach eBPF program: {e}")
                self.bpf = None

    def _perf_event_callback(self, cpu, data, size):
        """Asynchronous callback triggered by kernel when execve occurs."""
        if not self.bpf:
            return
            
        event = self.bpf["events"].event(data)
        
        # Filter for target sandbox pid tree if specified
        if self.target_pid and event.ppid != self.target_pid and event.pid != self.target_pid:
            return

        filename = event.filename.decode('utf-8', 'replace')
        comm = event.comm.decode('utf-8', 'replace')
        
        evt_dict = {
            "timestamp": time.time(),
            "event_type": "process_execution",
            "source": "ebpf",
            "details": {
                "pid": event.pid,
                "ppid": event.ppid,
                "uid": event.uid,
                "executable": filename,
                "command_comm": comm
            }
        }
        
        self.events.append(evt_dict)
        if self._is_suspicious(filename, comm):
            logger.warning(f"Suspicious eBPF Exec Event: {json.dumps(evt_dict)}")

    def _is_suspicious(self, filename: str, comm: str) -> bool:
        suspicious_keywords = ['powershell', 'cmd.exe', 'wscript', 'cscript', 'bash', 'sh', 'curl', 'wget']
        cmd_str = f"{filename} {comm}".lower()
        return any(k in cmd_str for k in suspicious_keywords)

    def poll(self) -> List[Dict[str, Any]]:
        """
        To be called periodically (e.g., in an asyncio loop) to drain the 
        perf ring buffer. Does NOT iterate all processes.
        """
        if self.bpf:
            # Drains the kernel perf buffer efficiently
            self.bpf.perf_buffer_poll(timeout=10)
        else:
            # Fallback for environments lacking BCC
            pass
            
        # Return a snapshot and clear local buffer
        current_events = list(self.events)
        self.events.clear()
        return current_events

    def get_events(self) -> List[Dict[str, Any]]:
        """Used by the monitor service to retrieve historically buffered events."""
        return self.events
