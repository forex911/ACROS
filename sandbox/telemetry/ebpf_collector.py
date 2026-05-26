# Note: This collector runs inside a privileged DaemonSet on the sandbox nodes,
# or as a sidecar with CAP_BPF, observing the sandboxed containers.

from bcc import BPF
import json
import asyncio
import os
from datetime import datetime
import redis.asyncio as redis

# BPF program to hook execve
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

int syscall__execve(struct pt_regs *ctx, const char __user *filename) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

class EBPFCollector:
    def __init__(self, job_id, redis_uri):
        self.job_id = job_id
        self.b = BPF(text=bpf_text)
        self.b.attach_kprobe(event=self.b.get_syscall_fnname("execve"), fn_name="syscall__execve")
        self.redis_client = redis.from_url(redis_uri)

    def print_event(self, cpu, data, size):
        event = self.b["events"].event(data)
        payload = {
            "type": "PROCESS_CREATE",
            "severity": "high",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "data": {
                "pid": event.pid,
                "comm": event.comm.decode('utf-8', 'replace'),
                "filename": event.filename.decode('utf-8', 'replace'),
                "source": "eBPF"
            }
        }
        # Synchronous publish for BPF callback, in production use a queue/async worker
        asyncio.run(self.publish_event(payload))

    async def publish_event(self, payload):
        channel = f"job_updates:{self.job_id}"
        await self.redis_client.publish(channel, json.dumps(payload))

    def run(self):
        self.b["events"].open_perf_buffer(self.print_event)
        try:
            while True:
                self.b.perf_buffer_poll()
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    job_id = os.environ.get("JOB_ID", "local")
    redis_uri = os.environ.get("REDIS_URI", "redis://localhost:6379")
    collector = EBPFCollector(job_id, redis_uri)
    collector.run()
