<div style="text-align: right; margin-bottom: 20px;">
  <a href="README_zh.md" style="padding: 8px 15px; background: #007bff; color: white; text-decoration: none; border-radius: 4px;">中文</a>
</div>

# ops-mcp-server Project

## Project Overview
ops-mcp-server is a toolset for server inspection and monitoring, providing a series of tools for remote server operations including network interface checks, service status monitoring, firewall configuration inspection, and more.

## Features

### Server Monitoring Tools
- **Get Memory Info**: Get local server memory information
- **Remote Server Inspection**: Perform remote server inspection including CPU, memory, disk and other modules
- **System Load Monitoring**: Get system load information
- **Process Monitoring**: Monitor remote server processes, return top resource-consuming processes
- **Service Status Check**: Check running status of specified services
- **Network Interface Check**: Check network interfaces and connection status
- **Log Analysis**: Analyze error and warning messages in server log files
- **Configuration Backup**: Backup important system configuration files
- **Security Vulnerability Scan**: Perform basic security vulnerability scanning
- **SSH Login Risk Check**: Check SSH login risks including failed attempts and suspicious IPs
- **Firewall Configuration Check**: Check firewall configuration and open ports
- **OS Details**: Get detailed operating system information

### Network Device Management
- **Device Identification**: Identify network device types and basic information
- **Switch Port Check**: Check switch port status
- **Routing Table Check**: Check router routing tables
- **Network Config Backup**: Backup network device configurations
- **ACL Config Check**: Check security ACL configurations
- **VLAN Config Check**: Check switch VLAN configurations

### Additional Features
- **Tool Listing**: List all available tools and their descriptions
- **Batch Operations**: Support simultaneous inspection tasks across multiple devices

## Installation
This project uses [`uv`](https://github.com/astral-sh/uv) for Python dependency and virtual environment management.

### 1. Install uv
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Create and activate virtual environment
```bash
uv venv .venv
source .venv/bin/activate  # Linux/macOS
# or
.\.venv\Scripts\activate   # Windows
```

### 3. Install project dependencies
Make sure you have Python 3.10 or higher installed, then use the following command to install project dependencies:
```bash
uv pip install -r requirements.txt
```

Note: Dependency information can be found in the `pyproject.toml` file.

## MCP Server Configuration
To add this project as an MCP server, add the following configuration to your settings file:

```json
"ops-mcp-server": {
      "command": "uv",
      "args": [
        "--directory",
        "YOUR_PROJECT_PATH_HERE",  // Replace with your actual project path
        "run", 
        "main.py"
      ],
      "env": {},
      "disabled": true,
      "autoApprove": [
        "list_available_tools"
      ]
    }
```

## License
This project is licensed under the [MIT License](LICENSE).

## Notes
- Ensure the remote server's SSH service is running properly and you have appropriate permissions.
- Adjust parameters according to actual conditions when using tools.
- The project is currently being improved...

