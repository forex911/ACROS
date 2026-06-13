"""
Enterprise eBPF Telemetry Collector (Event-Driven)
Captures execve, fork, clone, file opens, and network connections.
"""

import time
import json
import logging
import socket
import struct
from typing import List, Dict, Any

logger = logging.getLogger("ebpf_collector")

try:
    from bcc import BPF
except ImportError:
    BPF = None
    logger.warning("BCC/eBPF not installed on host. Running in fallback simulation mode.")

# --- eBPF C Program ---
EBPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 event_type; // 1=execve, 2=fork/clone, 3=openat, 4=connect
    char comm[TASK_COMM_LEN];
    char arg1[256];
    u32 dest_ip;
    u16 dest_port;
};

BPF_PERF_OUTPUT(events);

// 1: execve
int syscall__execve(struct pt_regs *ctx, const char __user *filename) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.ppid = task->real_parent->tgid;
    event.event_type = 1;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.arg1, sizeof(event.arg1), filename);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// 2: clone/fork
int syscall__clone(struct pt_regs *ctx) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.ppid = task->real_parent->tgid;
    event.event_type = 2;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// 3: openat
int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.ppid = task->real_parent->tgid;
    event.event_type = 3;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.arg1, sizeof(event.arg1), filename);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// 4: connect (ipv4)
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.ppid = task->real_parent->tgid;
    event.event_type = 4;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    u32 daddr = sk->__sk_common.skc_daddr;
    u16 dport = sk->__sk_common.skc_dport;
    
    event.dest_ip = daddr;
    event.dest_port = ntohs(dport);
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

class EBPFCollector:
    def __init__(self, target_pid: int = None, telemetry_manager=None):
        self.target_pid = target_pid
        self.telemetry_manager = telemetry_manager
        self.bpf = None
        
        if BPF:
            try:
                self.bpf = BPF(text=EBPF_PROGRAM)
                
                # Attach kprobes
                execve_fnname = self.bpf.get_syscall_fnname("execve")
                self.bpf.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
                
                clone_fnname = self.bpf.get_syscall_fnname("clone")
                self.bpf.attach_kprobe(event=clone_fnname, fn_name="syscall__clone")
                
                # fork is often implemented via clone, but we can hook fork too if needed
                try:
                    fork_fnname = self.bpf.get_syscall_fnname("fork")
                    self.bpf.attach_kprobe(event=fork_fnname, fn_name="syscall__clone")
                except Exception:
                    pass
                
                openat_fnname = self.bpf.get_syscall_fnname("openat")
                self.bpf.attach_kprobe(event=openat_fnname, fn_name="syscall__openat")
                
                # tcp_v4_connect is hooked directly via kprobe__ prefix in C code
                
                self.bpf["events"].open_perf_buffer(self._perf_event_callback)
                logger.info("Successfully attached eBPF kprobes.")
            except Exception as e:
                logger.error(f"Failed to compile/attach eBPF program: {e}")
                self.bpf = None

    def _perf_event_callback(self, cpu, data, size):
        if not self.bpf:
            return
            
        event = self.bpf["events"].event(data)
        
        if self.target_pid and event.ppid != self.target_pid and event.pid != self.target_pid:
            # Note: in a real sandbox, you'd track process trees.
            return

        comm = event.comm.decode('utf-8', 'replace')
        arg1 = event.arg1.decode('utf-8', 'replace') if event.event_type in [1, 3] else ""
        
        process_info = {
            "pid": event.pid,
            "ppid": event.ppid,
            "uid": event.uid,
            "comm": comm
        }
        
        metadata = {}
        event_type = "UNKNOWN"
        
        if event.event_type == 1:
            event_type = "PROCESS_EXEC"
            metadata = {"filename": arg1}
        elif event.event_type == 2:
            event_type = "PROCESS_CLONE"
        elif event.event_type == 3:
            event_type = "FILE_OPEN"
            metadata = {"filename": arg1}
        elif event.event_type == 4:
            event_type = "NETWORK_CONNECT"
            ip_str = socket.inet_ntoa(struct.pack("<L", event.dest_ip))
            metadata = {
                "dest_ip": ip_str,
                "dest_port": event.dest_port
            }

        if self.telemetry_manager:
            self.telemetry_manager.emit_event(event_type, process_info, metadata)

    def poll(self):
        """Drains the kernel perf buffer efficiently."""
        if self.bpf:
            self.bpf.perf_buffer_poll(timeout=100)
