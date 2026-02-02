# Container Security Scanner

A modular and extensible security analysis engine designed for Docker images. This tool implements a multi-stage security audit process, covering configuration analysis, Static Application Security Testing (SAST), and Dynamic Application Security Testing (DAST).

## Architecture and Design

The system is built on a plugin-based provider pattern, ensuring high levels of decoupling and scalability.

### Core Workflow

1.  **Image Discovery**: The orchestrator utilizes the Docker SDK to pull or locate the target container image.
2.  **Context Initialization**: A shared execution context is established, comprising the Docker client, temporary working directories, and image metadata.
3.  **Plugin Execution**: The engine sequentially executes all registered scanner modules derived from the BaseScanner interface.
4.  **Reporting**: Findings are aggregated and presented via a structured CLI output or exported as a JSON report.

### Design Objectives

-   **Decoupling**: The orchestrator remains agnostic to the internal logic of individual scanners, maintaining a strict interface-based interaction.
-   **Scalability**: The modular architecture allows for the seamless integration of new scan modules (e.g., OS vulnerability scanners) by extending the base classes.
-   **Resource Optimization**: The SAST module employs stream-based processing to analyze image layers without requiring full extraction to the host disk, significantly reducing I/O overhead.

## Capabilities

### 1. Configuration Audit
Analyzes image metadata for compliance with security best practices:
-   **User Identity**: Detects containers configured to run with root privileges.
-   **Healthchecks**: Verifies the presence of health monitoring instructions.
-   **Exposed Ports**: Identifies potentially sensitive ports (e.g., SSH, database ports) declared in image metadata.
-   **Environment Analysis**: Scans environment variables for sensitive keywords that may indicate hardcoded credentials.

### 2. Static Analysis (SAST)
Performs deep-layer inspection of the container filesystem:
-   **Secret Detection**: Identifies credentials, private keys, and API tokens (AWS, GCP, Azure, Slack) within the image layers.
-   **Dependency Inventory**: Detects package manifests and dependency files for further inventory management.

### 3. Dynamic Analysis (DAST)
Probes the container in a controlled, ephemeral runtime environment:
-   **Network Validation**: Spawns the container with dynamic port mapping to prevent host conflicts.
-   **Security Header Audit**: Evaluates web services for the presence of defensive HTTP headers such as CSP, HSTS, and X-Frame-Options.
-   **Information Leakage**: Scans for server banners and headers that may expose underlying infrastructure details.

## Getting Started

### Prerequisites
-   Docker Engine
-   Python 3.10 or higher

### Installation
Install the required dependencies using the following command:
```bash
pip install -r requirements.txt
```

### Usage
Run a standard scan with formatted console output:
```bash
python3 main.py <target_image>
```

Export scan findings to a JSON file:
```bash
python3 main.py <target_image> --json report.json
```

## Technical Verification
The project includes a comprehensive test suite. To run the automated tests, execute:
```bash
export PYTHONPATH=$PYTHONPATH:.
python3 -m unittest discover tests
```

---
*This project demonstrates expertise in DevSecOps system architecture and infrastructure automation.*
