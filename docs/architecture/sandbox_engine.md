# Sandbox Engine

The ACROS-AI Sandbox Engine is responsible for safely executing untrusted artifacts in an isolated environment while capturing comprehensive OS-level telemetry. It supports multiple isolation backends ranging from a lightweight development wrapper to hardware-virtualized microVMs.

---

## Threat Model

In malware analysis, the primary threat is that an executing binary escapes the sandbox and infects the host system or pivots into the internal network. The architecture mitigates this through layered isolation.

### Defense-in-Depth Layers

```
┌──────────────────────────────────────┐
│  Layer 4: Network Isolation          │  NetworkPolicy DENY + INetSim sinkhole
├──────────────────────────────────────┤
│  Layer 3: Container Runtime          │  gVisor / Kata / Firecracker microVM
├──────────────────────────────────────┤
│  Layer 2: Kubernetes Pod Security    │  readOnlyRootFilesystem, cap_drop ALL
├──────────────────────────────────────┤
│  Layer 1: Dedicated Node Pool        │  Tainted nodes, no shared workloads
└──────────────────────────────────────┘
```

---

## Execution Modes

ACROS-AI supports an `engine_selector.py` that delegates payload detonation to one of four backends:

| Mode | Isolation Level | Telemetry Method | Use Case |
|---|---|---|---|
| **Local Dev** (`local_dev`) | ⚠️ None | Python `sys.addaudithook` | Development and testing ONLY |
| **gVisor** (`gvisor`) | 🟡 Strong | eBPF + gVisor syscall interception | Standard production workloads |
| **Kata Containers** (`kata`) | 🟢 Very Strong | eBPF + QEMU/KVM hardware virtualization | High-security environments |
| **Firecracker** (`firecracker`) | 🟢 Maximum | eBPF + Firecracker microVM | Cloud-native, minimal boot time |

### Local Dev Mode

Used exclusively for development. The sandbox:

1. Creates a temporary directory (`tempfile.mkdtemp`).
2. Copies the target script into the isolated directory.
3. Restricts `sys.path` and CWD to prevent access to ACROS-AI source code.
4. Injects `sys.addaudithook` to monitor Python calls (`subprocess.Popen`, `socket.connect`, file `open`, etc.).
5. Executes the script via `runpy` within the modified environment.

> **⚠️ Security Warning**: This mode relies entirely on Python's audit hook system. A malicious script can bypass it using `ctypes`, C-extensions, or raw syscalls. **Never use this mode with real malware.**

### Production Modes (gVisor / Kata / Firecracker)

All production modes execute the payload inside an isolated container or microVM managed by Kubernetes. Telemetry is collected via eBPF probes attached to kernel syscalls (`execve`, `connect`, `open`, etc.), which cannot be bypassed by user-space code.

---

## Zero-Trust Kubernetes Orchestration

All production sandbox jobs are scheduled onto a dedicated Kubernetes cluster with strict security controls:

### Node Isolation
- **Dedicated Node Pool**: Taints (`sandbox=true:NoSchedule`) and Tolerations ensure malicious jobs never land on control-plane nodes or general application workers.
- **Separate Instance Type**: Sandbox nodes use ephemeral, disposable VM instances that are automatically recycled.

### Pod Security
- **Read-Only Filesystem**: `readOnlyRootFilesystem: true` prevents the payload from modifying the container image.
- **Privilege Dropping**: All Linux capabilities are dropped (`cap_drop: ALL`). OPA Gatekeeper constraints block privileged mode.
- **Non-Root Execution**: Containers run as a non-root user.

### Network Isolation
- **Default DENY**: NetworkPolicies block all egress traffic by default.
- **INetSim Sinkhole**: Payloads can only communicate with the `inetsim` sinkhole container, which simulates HTTP, DNS, and SMTP services to capture network telemetry without allowing actual internet access.
- **Allowed Internal Traffic**: Only Redis (telemetry publishing) and MinIO (artifact download) are whitelisted.

---

## Telemetry Pipeline

### Local Mode (Development)
```
Python Script → sys.addaudithook → stdout JSON → sandbox_runner.py → Redis PubSub
```

### Production Mode (eBPF)
```
Binary/Script → Kernel Syscalls → eBPF Probes (ebpf_collector.py) → Redis PubSub
```

eBPF probes attach to:
| Syscall | Captured Event |
|---|---|
| `execve` | `PROCESS_CREATE` |
| `connect` | `SOCKET_CONNECT` |
| `open` / `openat` | `FILE_WRITE` / `FILE_READ` |
| `sendto` / `recvfrom` | Network data transfer |

All captured events are normalized into the standard telemetry schema and published to Redis for real-time streaming to the SOC dashboard.

---

## Decoy Generation

To defeat malware anti-analysis checks, `sandbox/decoys/generate_decoys.py` executes before detonation to populate the sandbox environment with:
- Fake browser profiles and credential databases
- Financial PDFs and tax documents
- Browser history and bookmarks
- Cryptocurrency wallet files
- Discord and Telegram data directories

This ensures that malware which checks for the presence of target data before executing will proceed with its malicious behavior, enabling full telemetry capture.

---

## Sandbox Lifecycle

```
1. User uploads artifact
     │
2. Pipeline triggers sandbox orchestrator
     │
3. Orchestrator selects execution backend (engine_selector.py)
     │
4. [Production] K8s Job created with appropriate RuntimeClass
   [Local Dev] Subprocess spawned in temp directory
     │
5. Artifact downloaded from MinIO / copied to temp dir
     │
6. Decoys generated (production only)
     │
7. Telemetry collection begins (eBPF / audit hook)
     │
8. Execution proceeds (max 10–60 seconds configurable)
     │
9. Telemetry events published to Redis in real-time
     │
10. Execution completes or times out
     │
11. Container/VM destroyed, automatic snapshot rollback
     │
12. Telemetry array returned to report_generator.py
```
