<div align="center">

```text
██╗  ██╗███████╗██████╗ ███╗   ██╗███████╗██╗     
██║ ██╔╝██╔════╝██╔══██╗████╗  ██║██╔════╝██║     
█████╔╝ █████╗  ██████╔╝██╔██╗ ██║█████╗  ██║     
██╔═██╗ ██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝  ██║     
██║  ██╗███████╗██║  ██║██║ ╚████║███████╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

███████╗██╗   ██╗██████╗  ██████╗ ██╗ ██████╗ ███╗   ██╗ █████╗ ██╗
██╔════╝██║   ██║██╔══██╗██╔════╝ ██║██╔════╝ ████╗  ██║██╔══██╗██║
███████╗██║   ██║██████╔╝██║  ███╗██║██║  ███╗██╔██╗ ██║███████║██║
╚════██║██║   ██║██╔══██╗██║   ██║██║██║   ██║██║╚██╗██║██╔══██║██║
███████║╚██████╔╝██║  ██║╚██████╔╝██║╚██████╔╝██║ ╚████║██║  ██║██║
╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝
```

# KERNELSURGICAL AI

### Dynamic Kernel Attack Surface Reduction & Zero-Downtime Auto-Remediation

**Observe → Reason → Surgically Enforce → Verify**

<br>

![Active Telemetry](https://img.shields.io/badge/Telemetry-Active-00E5FF?style=for-the-badge\&logo=linux)
![BPF-LSM](https://img.shields.io/badge/BPF--LSM-Surgical%20Enforcement-00E58A?style=for-the-badge\&logo=linux)
![Availability](https://img.shields.io/badge/App%20Availability-100%25-00E58A?style=for-the-badge)
![Reboots](https://img.shields.io/badge/Reboots-0-00E58A?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge\&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=for-the-badge\&logo=streamlit)

<br>

> **KernelSurgical AI continuously profiles workload–kernel interactions, identifies unnecessary high-risk kernel capabilities, correlates exposure with vulnerability intelligence, generates workload-scoped restrictions, and verifies the resulting security state without requiring an application restart or host reboot.**

</div>

---

## ⚡ Why KernelSurgical AI?

Modern container workloads frequently have access to far more kernel functionality than they actually need.

That creates an uncomfortable security problem:

```text
Application requires
        │
        ▼
   20 kernel interfaces
        │
        │        but may be exposed to
        ▼
   hundreds of kernel capabilities
        │
        ▼
   larger attack surface
```

Traditional hardening approaches often depend on static policies established before deployment.

KernelSurgical AI takes a runtime-first approach:

```text
┌──────────────┐
│ LIVE WORKLOAD│
└──────┬───────┘
       │
       ▼
┌──────────────────┐
│ OBSERVE           │  eBPF-style runtime telemetry
└────────┬─────────┘
         ▼
┌──────────────────┐
│ PROFILE           │  actual workload behavior
└────────┬─────────┘
         ▼
┌──────────────────┐
│ REASON            │  risk + threat intelligence
└────────┬─────────┘
         ▼
┌──────────────────┐
│ SURGICALLY ENFORCE│ workload-scoped restrictions
└────────┬─────────┘
         ▼
┌──────────────────┐
│ VERIFY            │ zero-downtime security state
└──────────────────┘
```

The result is **security reduction targeted at what the workload actually exposes**, rather than indiscriminate blocking.

---

# 🎯 Core Security Concept

KernelSurgical AI focuses on three classes of high-risk kernel operations:

| Syscall        | Security Concern                          | Demo Treatment |
| -------------- | ----------------------------------------- | -------------- |
| `ptrace`       | Process inspection / injection capability | 🔴 Restricted  |
| `unshare`      | Namespace manipulation / isolation risk   | 🔴 Restricted  |
| `memfd_create` | Fileless execution primitive              | 🔴 Restricted  |
| `read`         | Normal application I/O                    | 🟢 Allowed     |
| `write`        | Normal application I/O                    | 🟢 Allowed     |
| `connect`      | Normal network operation                  | 🟢 Allowed     |
| `accept4`      | Normal server operation                   | 🟢 Allowed     |

The important distinction is:

> **KernelSurgical AI does not attempt to block everything suspicious-looking. It attempts to restrict unnecessary high-risk functionality while preserving the workload's expected behavior.**

---

# 📊 Live Enforcement Matrix

The primary demo demonstrates a before/after security transformation.

```text
┌────────────────────────────────────────────────────────────────────┐
│                    KERNEL ATTACK SURFACE                           │
├──────────────────────────────┬─────────────────────────────────────┤
│ BEFORE — HIGH EXPOSURE       │ AFTER — HARDENED                    │
├──────────────────────────────┼─────────────────────────────────────┤
│ KEI              ~84.5       │ KEI                    ~12.0        │
│ Risk             HIGH        │ Risk                   HARDENED     │
│                              │                                     │
│ ptrace           EXPOSED     │ ptrace                 BLOCKED      │
│ unshare          EXPOSED     │ unshare                BLOCKED      │
│ memfd_create     EXPOSED     │ memfd_create           BLOCKED      │
│                              │                                     │
│ read             ALLOWED     │ read                   ALLOWED      │
│ write            ALLOWED     │ write                  ALLOWED      │
│ connect          ALLOWED     │ connect                ALLOWED      │
│ accept4          ALLOWED     │ accept4                ALLOWED      │
│                              │                                     │
│ Availability     100%        │ Availability            100%        │
│ Reboots          0           │ Reboots                 0           │
└──────────────────────────────┴─────────────────────────────────────┘
```

### The security objective

```text
HIGH EXPOSURE
    84.5
      │
      │  Observe
      ▼
   Profile
      │
      │  Reason
      ▼
  Generate Policy
      │
      │  Enforce
      ▼
HARDENED EXPOSURE
   ~12.0

WITHOUT:
✗ Application restart
✗ Host reboot
✗ Blocking legitimate workload traffic
```

> **Demo note:** KEI values represent the project's workload security model/simulation unless native enforcement and runtime measurements are available on the host.

---

# 🧠 Architecture

```text
                         ┌─────────────────────┐
                         │   WORKLOAD / DEMO   │
                         └──────────┬──────────┘
                                    │
                                    ▼
                     ┌──────────────────────────┐
                     │     TELEMETRY ENGINE     │
                     │ syscall / process events │
                     └────────────┬─────────────┘
                                  │
                                  ▼
                     ┌──────────────────────────┐
                     │    WORKLOAD PROFILING    │
                     │ syscalls / caps / modules│
                     └────────────┬─────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
          ┌──────────────────┐        ┌──────────────────┐
          │  THREAT INTEL    │        │  AI REASONING    │
          │ CISA KEV / CVEs  │───────►│ risk assessment  │
          └────────┬─────────┘        └────────┬─────────┘
                   │                           │
                   └─────────────┬─────────────┘
                                 ▼
                     ┌──────────────────────────┐
                     │     KEI SCORING ENGINE   │
                     │ exposure quantification  │
                     └────────────┬─────────────┘
                                  │
                                  ▼
                     ┌──────────────────────────┐
                     │     POLICY ENGINE        │
                     │ least-privilege rules    │
                     └────────────┬─────────────┘
                                  │
                                  ▼
                     ┌──────────────────────────┐
                     │       BPF-LSM            │
                     │ surgical enforcement      │
                     └────────────┬─────────────┘
                                  │
                                  ▼
                     ┌──────────────────────────┐
                     │      VERIFICATION        │
                     │ availability + security  │
                     └──────────────────────────┘
```

---

# 🔄 8-Phase Execution Pipeline

KernelSurgical AI turns the security workflow into an explicit execution pipeline:

```text
┌────────────┐
│ 01         │
│ TELEMETRY  │
└─────┬──────┘
      ▼
┌────────────┐
│ 02         │
│ PROFILE    │
└─────┬──────┘
      ▼
┌────────────┐
│ 03         │
│ MAP        │
└─────┬──────┘
      ▼
┌────────────┐
│ 04         │
│ CORRELATE  │
└─────┬──────┘
      ▼
┌────────────┐
│ 05         │
│ REASON     │
└─────┬──────┘
      ▼
┌────────────┐
│ 06         │
│ GENERATE   │
└─────┬──────┘
      ▼
┌────────────┐
│ 07         │
│ ENFORCE    │
└─────┬──────┘
      ▼
┌────────────┐
│ 08         │
│ VERIFY     │
└────────────┘
```

### What happens at each stage?

| Phase | Engine                 | Purpose                                                     |
| ----- | ---------------------- | ----------------------------------------------------------- |
| `01`  | Telemetry              | Observe workload/kernel activity                            |
| `02`  | Profiling              | Establish actual workload behavior                          |
| `03`  | Attack-Surface Mapping | Identify unnecessary exposed interfaces                     |
| `04`  | Threat Intel           | Correlate kernel components with vulnerability intelligence |
| `05`  | AI Reasoning           | Assess risk and explain why behavior matters                |
| `06`  | Policy Engine          | Generate workload-specific restrictions                     |
| `07`  | BPF-LSM                | Apply targeted runtime controls                             |
| `08`  | Verification           | Confirm security state and application availability         |

---

# 🛡️ Attack Surface Matrix

```text
┌─────────────────┬───────────────┬───────────────┬──────────────────────┐
│ Kernel Interface │ Expected Use │ Risk Profile  │ Surgical Decision    │
├─────────────────┼───────────────┼───────────────┼──────────────────────┤
│ read            │ Required      │ LOW           │ ✓ ALLOW              │
│ write           │ Required      │ LOW           │ ✓ ALLOW              │
│ connect         │ Required      │ LOW           │ ✓ ALLOW              │
│ accept4         │ Required      │ LOW           │ ✓ ALLOW              │
│ openat          │ Required      │ LOW           │ ✓ ALLOW              │
│ execve          │ Conditional   │ MEDIUM        │ ◐ REVIEW             │
│ ptrace          │ Unnecessary   │ CRITICAL      │ ✕ BLOCK              │
│ unshare         │ Unnecessary   │ CRITICAL      │ ✕ BLOCK              │
│ memfd_create    │ Unnecessary   │ CRITICAL      │ ✕ BLOCK              │
└─────────────────┴───────────────┴───────────────┴──────────────────────┘
```

The policy objective is **least privilege at runtime**:

```text
                 WORKLOAD
                    │
          ┌─────────┴─────────┐
          │                   │
          ▼                   ▼
   REQUIRED PATHS        HIGH-RISK PATHS
          │                   │
          ▼                   ▼
       ALLOW              RESTRICT
          │                   │
          └─────────┬─────────┘
                    ▼
              HARDENED STATE
```

---

# ⚡ Key Features

### 📡 Real-Time Kernel Telemetry

Continuously models workload interactions with kernel interfaces and surfaces:

* timestamps
* PIDs
* process names
* syscall activity
* risk classifications
* enforcement decisions

### 🧠 AI Security Reasoning

Converts telemetry into concise security decisions:

```text
DETECTED
ptrace invoked by demo-web-svc

WHY RISKY
Process inspection/injection capability is inconsistent
with the expected workload profile.

ACTION
Restrict ptrace while preserving normal application operations.
```

### 🛡️ BPF-LSM Surgical Enforcement

Generates workload-scoped enforcement decisions around high-risk kernel operations rather than indiscriminately disabling functionality.

### 📉 Kernel Exposure Index

Quantifies the workload's modeled kernel exposure and makes the security transformation visible.

```text
84.5  ───────────────────────────────►  ~12.0
HIGH                                   HARDENED
```

### ♻️ Zero-Downtime Hardening

The target security state preserves:

```text
Application Availability   100%
Application Restart        0
Host Reboot                0
```

### 🧬 Offline Threat Intelligence

The repository includes a local threat-intelligence cache so the demo can operate without requiring an external API during execution.

---

# 🗂️ Repository Structure

```text
kernel-surgical-ai/
│
├── backend/
│   ├── bpf_lsm.py             # BPF-LSM hook/state abstraction
│   ├── policy_engine.py       # Least-privilege policy synthesis
│   ├── reasoning.py           # Security reasoning engine
│   ├── scoring.py             # Kernel Exposure Index calculation
│   ├── simulator.py           # Runtime telemetry simulation
│   ├── threat_intel.py        # CISA KEV/CVE correlation
│   ├── system.py              # Engine orchestration
│   ├── scenario.py            # Demo execution state machine
│   ├── models.py              # Security data models
│   ├── workload.py            # Workload representation
│   └── cisa_kev_cache.json    # Offline threat-intelligence cache
│
├── frontend/
│   ├── app.py                 # Streamlit dashboard
│   └── theme.py               # Cybersecurity visual system
│
├── tests/
│   ├── test_scoring.py
│   ├── test_simulator.py
│   └── test_policy_engine.py
│
├── requirements.txt
├── setup.sh
├── setup.bat
├── run_demo.sh
├── run_demo.bat
└── README.md
```

---

# 🚀 Quick Start

## Prerequisites

* Python 3.10+
* `pip`
* Git
* Modern web browser

For native Linux BPF-LSM experimentation:

* Linux kernel with BPF-LSM support
* appropriate privileges
* required kernel/BPF tooling

The included demonstration can run using the project's simulation path without requiring native kernel enforcement.

---

## 1. Clone

```bash
git clone <YOUR-REPOSITORY-URL>
cd kernel-surgical-ai
```

---

## 2. Install

### Linux / macOS

```bash
chmod +x setup.sh
./setup.sh
```

### Windows

```powershell
setup.bat
```

Or manually:

```bash
python -m pip install -r requirements.txt
```

---

## 3. Launch the Dashboard

### Direct Streamlit launch

```bash
python -m streamlit run frontend/app.py
```

Then open:

```text
http://localhost:8501
```

### Linux / macOS

```bash
./run_demo.sh
```

### Windows

```powershell
run_demo.bat
```

---

# 🧪 Verification

Run the project's automated tests:

```bash
python -m pytest
```

You can also perform a Python compilation/import sanity check:

```bash
python -m compileall backend frontend tests
```

A successful verification should leave the project ready for the Streamlit demo.

---

# 🎬 Judge Demo Walkthrough

The fastest way to evaluate KernelSurgical AI is to follow the security transformation.

## 01 — Open the Dashboard

Launch:

```bash
python -m streamlit run frontend/app.py
```

Open:

```text
http://localhost:8501
```

Immediately inspect:

* Workload Exposure
* High-Risk Syscalls
* Application Availability
* Enforcement State
* Reboot Count

---

## 02 — Observe the Baseline

Before enforcement, look for suspicious activity such as:

```text
ptrace
unshare
memfd_create
```

alongside normal workload activity such as:

```text
read
write
connect
accept4
```

The objective is to demonstrate that the system distinguishes **required behavior from unnecessary high-risk behavior**.

---

## 03 — Inspect AI Security Reasoning

Review the reasoning panel.

Confirm that the system explains:

```text
WHAT WAS DETECTED
        ↓
WHY IT IS RISKY
        ↓
WHAT SHOULD BE RESTRICTED
        ↓
WHAT SHOULD REMAIN ALLOWED
```

---

## 04 — Execute Surgical Enforcement

Trigger:

```text
⚡ EXECUTE SURGICAL ENFORCEMENT
```

Watch the eight-phase pipeline progress:

```text
TELEMETRY
   ↓
PROFILE
   ↓
MAP
   ↓
CORRELATE
   ↓
REASON
   ↓
GENERATE
   ↓
ENFORCE
   ↓
VERIFY
```

---

## 05 — Watch the Attack Surface Change

The central result should be visible as:

```text
KEI

~84.5  ───────────────────────►  ~12.0
 HIGH                             HARDENED
```

At the same time:

```text
APP AVAILABILITY     100%
REBOOTS REQUIRED       0
```

---

## 06 — Verify Selective Enforcement

Confirm that the demo does **not** simply block everything.

Expected pattern:

```text
ptrace          ✕ BLOCKED
unshare         ✕ BLOCKED
memfd_create    ✕ BLOCKED

read            ✓ ALLOWED
write           ✓ ALLOWED
connect         ✓ ALLOWED
accept4         ✓ ALLOWED
```

This demonstrates the central idea of **surgical** attack-surface reduction.

---

## 07 — Inspect Threat Intelligence

Review the threat-intelligence correlation generated from the repository's local vulnerability cache.

The system can associate workload/kernel observations with relevant vulnerability records and expose why a particular interface deserves additional scrutiny.

---

## 08 — Verify the Final State

The final dashboard should communicate:

```text
┌──────────────────────────────────────────┐
│       SURGICAL ENFORCEMENT COMPLETE      │
├──────────────────────────────────────────┤
│ Kernel Exposure Index       ~12.0        │
│ Application Availability    100.0%       │
│ Reboots Required            0            │
│ High-Risk Paths              Reduced     │
│ Legitimate Operations        Preserved   │
└──────────────────────────────────────────┘
```

---

# 🧩 Security Model

KernelSurgical AI follows a closed-loop runtime security model:

```text
┌─────────┐
│ OBSERVE │
└────┬────┘
     │
     ▼
┌─────────┐
│ PROFILE │
└────┬────┘
     │
     ▼
┌─────────┐
│ REASON  │◄─────────────┐
└────┬────┘              │
     │                   │
     ▼                   │
┌─────────┐               │
│ ENFORCE │               │
└────┬────┘               │
     │                    │
     ▼                    │
┌─────────┐               │
│ VERIFY  │───────────────┘
└─────────┘
```

This feedback loop is designed around a simple principle:

> **Only restrict kernel functionality when there is evidence that the workload does not require it and the security value of restricting it outweighs the operational risk.**

---

# 🔐 Threat Intelligence

The project includes an offline vulnerability intelligence cache used by the threat-intelligence engine.

The engine can correlate:

```text
Observed Syscall
      +
Kernel Subsystem
      +
Capability
      +
Loaded Module
      │
      ▼
Threat Intelligence
      │
      ▼
Runtime Relevance
      │
      ▼
Security Recommendation
```

This allows the demo to remain self-contained instead of depending on a live external API.

---

# 🧱 Technology Stack

| Layer                | Technology                                  |
| -------------------- | ------------------------------------------- |
| Language             | Python 3.10+                                |
| Dashboard            | Streamlit                                   |
| Visualization        | Plotly                                      |
| Data Models          | Pydantic                                    |
| Numerical Processing | NumPy                                       |
| Kernel Security      | eBPF / BPF-LSM                              |
| Threat Intelligence  | CISA KEV / CVE local cache                  |
| Testing              | Pytest                                      |
| Runtime Demo         | Deterministic simulation + security engines |

---

# 🧪 Native vs. Demonstration Mode

KernelSurgical AI is designed to communicate two execution environments clearly.

### Demonstration / Simulation

Used for portable hackathon demonstrations.

```text
Simulated workload
      ↓
Telemetry simulation
      ↓
Security reasoning
      ↓
Policy generation
      ↓
Simulated enforcement state
      ↓
Verification dashboard
```

### Native Linux Environment

Where the required Linux kernel capabilities and privileges are available, the BPF-LSM layer can serve as the integration point for runtime kernel enforcement.

```text
Linux workload
      ↓
eBPF telemetry
      ↓
BPF-LSM hooks
      ↓
Policy enforcement
      ↓
Runtime verification
```

**Important:** the dashboard should distinguish simulated enforcement from verified native kernel enforcement. The project does not claim native kernel modification when running only in simulation mode.

---

# 📈 Success Criteria

KernelSurgical AI is designed around four measurable outcomes:

```text
             SECURITY
                ▲
                │
                │
      ┌─────────┴─────────┐
      │                   │
  ATTACK SURFACE      AVAILABILITY
    REDUCTION            PRESERVED
      │                   │
      ▼                   ▼
   KEI ↓↓↓             100%
      │
      └──────────┬──────────┘
                 ▼
          ZERO-DOWNTIME
            HARDENING
                 │
                 ▼
             0 REBOOTS
```

### Target Demonstration Result

| Metric                   | Baseline |   Hardened |
| ------------------------ | -------: | ---------: |
| Kernel Exposure Index    |    ~84.5 |      ~12.0 |
| Risk State               |     High |   Hardened |
| Application Availability |     100% |       100% |
| Reboots                  |        0 |          0 |
| High-Risk Paths          |  Exposed | Restricted |
| Required Operations      |  Allowed |    Allowed |

---

# 🛠️ Development

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run tests:

```bash
python -m pytest
```

Launch development dashboard:

```bash
python -m streamlit run frontend/app.py
```

---

# 🗺️ Roadmap

* [x] Workload telemetry simulation
* [x] Runtime syscall profiling
* [x] Kernel Exposure Index
* [x] Threat-intelligence correlation
* [x] Security reasoning engine
* [x] Policy generation
* [x] BPF-LSM enforcement abstraction
* [x] Runtime verification flow
* [x] Interactive Streamlit dashboard
* [x] Automated demonstration scenario

### Future

 [ ] Native eBPF syscall tracing across broader Linux environments
 [ ] Production-grade BPF-LSM policy attachment
 [ ] Expanded CISA KEV/NVD synchronization
 [ ] Persistent workload baselines
 [ ] Kubernetes admission/runtime integration
 [ ] Multi-workload policy orchestration
 [ ] Policy rollback and audit trails
 [ ] Extended kernel subsystem coverage

---

 ⚠️ Security & Accuracy Disclaimer

KernelSurgical AI is a security research and hackathon project.

The dashboard's simulation mode is designed to demonstrate the architecture and security workflow in a portable environment.

Metrics such as:

```text
KEI ~84.5 → ~12.0
Availability 100%
Reboots 0
```

represent the project's demonstration/security model unless explicitly backed by native runtime measurements.

Native BPF-LSM enforcement depends on the host Linux kernel, configuration, privileges, and available BPF-LSM capabilities.

Do not deploy generated policies to production systems without independent security validation.
