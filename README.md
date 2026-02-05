# GuardContainer

High-performance container security orchestration and scanning engine rewritten in Go. GuardContainer provides a modular framework for auditing Docker images against configuration best practices, static analysis (SAST), and dynamic probing (DAST).

![GuardContainer Dashboard](screenshots/dashboard.png)

## Overview

GuardContainer is a senior-level security tool designed to identify vulnerabilities and misconfigurations in Docker images before they reach production. By leveraging the official Go Moby SDK, it offers superior performance and concurrency compared to traditional scripting approaches.

## Key Features

- **Multi-Layer Scanning Engine**:
    - **Config Audit**: Inspects image metadata for root user execution, missing healthchecks, and exposed sensitive ports.
    - **Secret Detection (SAST)**: Performs high-speed filesystem analysis to detect leaked credentials, API keys, and private certificates.
    - **Dynamic Probing (DAST)**: Spins up ephemeral containers to verify HTTP security headers and identify leaked server metadata.
- **Premium Web Dashboard**: A modern, glassmorphic React interface for visual scan orchestration and real-time reporting.
- **CLI first**: Full support for automated CI/CD pipelines with JSON export capabilities.
- **Senior Architecture**: Built with a clean, modular Go structure (`/cmd`, `/internal`, `/web`) for maximum maintainability.

## Installation

### Prerequisites
- Go 1.23+
- Docker Engine
- Node.js (for frontend modifications)

### Build
```bash
# Clone the repository
git clone <repository-url>
cd Container-scanner

# Build the binary
go build -o container-scanner cmd/container-scanner/main.go
```

## Usage

### Web Interface
Launch the premium dashboard:
```bash
sudo -E ./container-scanner serve --port 8080
```
Then navigate to `http://localhost:8080`.

### CLI Scanning
Perform a fast, one-time scan:
```bash
sudo -E ./container-scanner scan <image_name> --json report.json
```

## Project Structure

- `cmd/container-scanner`: Main application entry point.
- `internal/scanners`: Core scanning logic and interface definitions.
- `internal/api`: REST API implementation for the web interface.
- `internal/utils`: Docker SDK wrappers and filesystem utilities.
- `web/ui`: Modern React frontend source code and assets.

## License
MIT
