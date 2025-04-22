
---

# ops-mcp-server

[![中文](https://img.shields.io/badge/Language-中文-blue.svg)](README_zh.md)

`ops-mcp-server`: an AI-driven IT operations platform that fuses LLMs and MCP architecture to enable intelligent monitoring, anomaly detection, and natural human-infrastructure interaction with enterprise-grade security and scalability.

---

## 📖 Table of Contents

- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [Demo Videos](#demo-videos)
- [Installation](#installation)
- [Deployment](#deployment)
- [Local MCP Server Configuration](#local-mcp-server-configuration)
- [Interactive Client Usage](#interactive-client-usage)
- [License](#license)
- [Notes](#notes)

---

## 🚀 Project Overview

`ops-mcp-server` is an IT operations management solution for the AI era. It achieves intelligent IT operations through the seamless integration of the Model Context Protocol (MCP) and Large Language Models (LLMs). By leveraging the power of LLMs and MCP's distributed architecture, it transforms traditional IT operations into an AI-driven experience, enabling automated server monitoring, intelligent anomaly detection, and context-aware troubleshooting. The system acts as a bridge between human operators and complex IT infrastructure, providing natural language interaction for tasks ranging from routine maintenance to complex problem diagnosis, while maintaining enterprise-grade security and scalability.

---

## 🌟 Key Features

### 🖥️ Server Monitoring

- Real-time CPU, memory, disk inspections.
- System load and process monitoring.
- Service and network interface checks.
- Log analysis and configuration backup.
- Security vulnerability scans (SSH login, firewall status).
- Detailed OS information retrieval.

### 📦 Container Management (Docker)

- Container, image, and volume management.
- Container resource usage monitoring.
- Log retrieval and health checks.

### 🌐 Network Device Management

- Multi-vendor support (Cisco, Huawei, H3C).
- Switch port, VLAN, and router route checks.
- ACL security configuration analysis.
- Optical module and device performance monitoring.

### ➕ Additional Capabilities

- Extensible plugin architecture.
- Batch operations across multiple devices.
- Tool listing and descriptive commands.

---

## 🎬 Demo Videos

### 📌 Project Demo

_On Cherry Studio_

![Demo Animation](assets/demo.gif)

### 📌 Interactive Client Demo

_On Terminal_

![Client Demo Animation](assets/client.gif)

---

## ⚙️ Installation

Ensure you have **Python 3.10+** installed. This project uses [`uv`](https://github.com/astral-sh/uv) for dependency and environment management.

### 1. Install UV

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Set Up Virtual Environment

```bash
uv venv .venv

# Activate the environment
source .venv/bin/activate      # Linux/macOS
.\.venv\Scripts\activate       # Windows
```

### 3. Install Dependencies

```bash
uv pip install -r requirements.txt
```

> Dependencies are managed via `pyproject.toml`.

---

## 🚧 Deployment

### 📡 SSE Remote Deployment (UV)

```bash
cd server_monitor_sse

# Install dependencies
pip install -r requirements.txt

# Start service
cd ..
uv run server_monitor_sse --transport sse --port 8000
```

### 🐳 SSE Remote Deployment (Docker Compose)

Ensure Docker and Docker Compose are installed.

```bash
cd server_monitor_sse
docker compose up -d

# Check status
docker compose ps

# Logs monitoring
docker compose logs -f
```

---

## 🛠️ Local MCP Server Configuration (Stdio)

Add this configuration to your MCP settings:

```json
{
  "ops-mcp-server": {
    "command": "uv",
    "args": [
      "--directory", "YOUR_PROJECT_PATH_HERE",
      "run", "server_monitor.py"
    ],
    "env": {},
    "disabled": true,
    "autoApprove": ["list_available_tools"]
  },
  "network_tools": {
    "command": "uv",
    "args": [
      "--directory", "YOUR_PROJECT_PATH_HERE",
      "run", "network_tools.py"
    ],
    "env": {},
    "disabled": false,
    "autoApprove": []
  },
}
```

> **Note**: Replace `YOUR_PROJECT_PATH_HERE` with your project's actual path.

---

## 💬 Interactive Client Usage

An interactive client (`client.py`) allows you to interact with MCP services using natural language.

### 1. Install Client Dependencies

```bash
uv pip install openai rich
```

### 2. Configure Client

Edit these configurations within `client.py`:

```python
# Initialize OpenAI client
self.client = AsyncOpenAI(
    base_url="https://your-api-endpoint",
    api_key="YOUR_API_KEY"
)

# Set model
self.model = "your-preferred-model"
```

### 3. Run the Client

```bash
uv run client.py [path/to/server.py]
```

Example:

```bash
uv run client.py ./server_monitor.py
```

### Client Commands

- `help` - Display help.
- `quit` - Exit client.
- `clear` - Clear conversation history.
- `model <name>` - Switch models.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 📌 Notes

- Ensure remote SSH access is properly configured.
- Adjust tool parameters based on actual deployment conditions.
- This project is under active development; feedback and contributions are welcome.

---