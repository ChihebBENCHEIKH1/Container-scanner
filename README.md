# 🛡️ Modular Container Security Scanner

A modular, extensible security analysis tool for Docker images. This project implements a "Defense in Depth" approach to container security by performing analysis at three distinct lifecycle stages: **Configuration Analysis**, **Static Analysis (SAST)**, and **Dynamic Analysis (DAST)**.

## 🏗️ Architecture & Philosophy

The core philosophy behind this project is **Modular Extensibility**. Most scanners are monolithic; this engine uses a **Plugin-Based Provider Pattern**.

### Workflow
1.  **Discovery**: The Orchestrator pulls/finds the target image using the Docker SDK.
2.  **Context Building**: A shared context (Docker client, temp directories, image metadata) is created.
3.  **Parallel-Ready Execution**: The engine iterates through a list of registered `BaseScanner` objects.
4.  **Consolidated Reporting**: Results are aggregated and outputted via a Rich-formatted CLI or exported as JSON.

### Why this design?
-   **Decoupling**: The orchestrator doesn't need to know *how* to find a secret or *how* to probe a port. It only knows the `BaseScanner` interface.
-   **Scalability**: Adding a new scan type (e.g., checking for OS vulnerabilities) is as simple as dropping a new class into `scanners/`.
-   **Resource Efficiency**: The SAST scanner uses **tar-stream processing** to analyze filesizes without extracting the entire container to the host disk, saving I/O and storage.

---

## 🔍 Scanning Capabilities

### 1. Image Config Audit (Static Metadata)
Inspects the container manifest for industry best practices:
-   **User Validation**: Flags containers running as `root` (UID 0).
-   **Healthcheck Presence**: Ensures the image defines a `HEALTHCHECK` for orchestration reliability.
-   **Exposed Ports**: Scans for "dangerous" ports (22, 3306, etc.) that shouldn't be exposed in metadata.

### 2. Secret Scanner (SAST - Filesystem)
Performs a deep-dive scan into the container's file layers:
-   **Stream Analysis**: Iterates through the `docker export` tarball in memory.
-   **Regex Engine**: Identifies AWS Keys, Private Keys, and hardcoded passwords within configuration files.

### 3. Runtime Prober (DAST - Dynamic)
Spins up an **ephemeral infrastructure** to test the "living" container:
-   **Dynamic Mapping**: Spawns the container with random host ports to avoid conflicts.
-   **HTTP Security Audit**: Probes web services for missing headers (`CSP`, `HSTS`, `X-Frame-Options`) and information leakage (Server banners).

---

## 🚀 Getting Started

### Prerequisites
-   Docker Engine
-   Python 3.10+

### Installation
```bash
pip install -r requirements.txt
```

### Usage
```bash
# Basic scan with Rich console output
python3 main.py <target_image>

# Scan and export findings to JSON
python3 main.py <target_image> --json report.json
```

## 🧪 Technical Verification
The project includes a comprehensive test suite using `unittest.mock` to simulate Docker interactions, ensuring high reliability without requiring a privileged environment for CI/CD runs.

```bash
export PYTHONPATH=$PYTHONPATH:.
python3 -m unittest discover tests
```

---

*Developed as a Senior Portfolio Project to demonstrate expertise in DevSecOps, System Architecture, and Infrastructure Automation.*
