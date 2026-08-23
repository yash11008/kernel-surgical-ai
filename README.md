# 🔬 KernelSurgical AI

> Dynamic Kernel Attack Surface Reduction with Zero Downtime

Containers run with way more kernel privileges than they actually need. Traditional security tools just kill the container or force a reboot when something looks off. 

**KernelSurgical AI** fixes this. It uses eBPF-LSM telemetry alongside AI threat reasoning to catch dangerous syscalls (`ptrace`, `unshare`, `memfd_create`) and hot-patches the kernel in real time—dropping the attack surface without restarting the app.

---

### ⚡ The Core Impact
* **Kernel Exposure Index (KEI):** Drops from **84.5 (High Risk)** ➔ **12.0 (Hardened)**
* **App Availability:** 100% (Zero Downtime)
* **Reboots Required:** 0

---

### 💡 How It Works
1. **eBPF Telemetry:** Ingests live system calls from target workloads.
2. **AI Reasoning Engine:** Maps active syscalls against threat intel (CISA KEV) to catch breakout risks.
3. **BPF-LSM Enforcement:** Injects granular security hooks directly into kernel space (`bpf_lsm_ptrace_access_check`).
4. **Instant Hardening:** Blocks high-risk vectors while leaving normal traffic (`read`, `write`, `accept4`) untouched[cite: 1].

---

### 🚀 Quick Start

1. **Clone the repo:**
   ```bash
   git clone [https://github.com/yash11008/kernel-surgical-ai.git](https://github.com/yash11008/kernel-surgical-ai.git)
   cd kernel-surgical-ai
