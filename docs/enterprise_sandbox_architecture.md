# Sentinel-AI Enterprise Malware Sandbox Architecture

This document details the transition from a local development wrapper to a multi-node, orchestrator-driven, highly isolated malware detonation environment.

## Threat Model & Isolation Guarantees

In malware analysis, the primary threat is that an executing binary escapes the analysis sandbox and infects the host system or pivot into the internal network. The new architecture guarantees isolation through layers of hardware and software virtualization.

### Execution Modes
Sentinel-AI now supports an `engine_selector.py` that delegates payload detonation to one of four backends:
1. **Local Dev (`local_dev`)**: ONLY for debugging. Uses Python `sys.addaudithook`. Highly insecure.
2. **gVisor (`gvisor`)**: Re-implements the Linux kernel in user-space. Intercepts all syscalls from the payload. Strong isolation.
3. **Kata Containers (`kata`)**: Uses QEMU/KVM hardware virtualization to wrap containers inside microVMs. Very strong isolation.
4. **Firecracker (`firecracker`)**: AWS-developed microVMs tailored for serverless/ephemeral workloads. Maximum isolation, minimal boot time.

### Zero-Trust Kubernetes Orchestration
All jobs (except local) are now scheduled onto a Kubernetes cluster.
- **Dedicated Nodes**: Taints and Tolerations (`sandbox=true:NoSchedule`) ensure that malicious jobs NEVER land on control-plane nodes or general application workers.
- **Immutable State**: Containers run with `readOnlyRootFilesystem=true`.
- **Privilege Dropping**: Containers drop `ALL` capabilities and are governed by OPA Gatekeeper constraints blocking privileged mode.
- **Network Virtualization**: NetworkPolicies default to `DENY`. Payloads can only communicate with the `inetsim` sinkhole container to capture HTTP/DNS telemetry without letting malware reach the actual internet.

## Telemetry Pipeline (eBPF)
Instead of relying on Python hooks which can be easily bypassed by C-extensions, telemetry is now collected directly from the Linux Kernel using eBPF (`ebpf_collector.py`).
- Hooks attach to `execve`, `connect`, `open`, etc.
- Captured telemetry is published to Redis and surfaced instantly via WebSockets to the SOC Dashboard.

## Decoy Generation
To defeat malware anti-analysis checks, `sandbox/decoys/generate_decoys.py` executes before detonation to populate fake credentials, financial PDFs, and browser history.

## Sandbox Lifecycle
1. User uploads artifact.
2. `sandbox_orchestrator` requests a K8s Job with the selected `RuntimeClass`.
3. The isolated Node downloads the payload from MinIO.
4. eBPF sidecars begin monitoring.
5. Execution proceeds for a max of 10-60 seconds.
6. The container/VM is destroyed, enforcing an automatic snapshot rollback.
