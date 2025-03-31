# ops-mcp-server 项目

## 项目简介
mcptest 是一个用于服务器巡检和监控的工具集合，提供了一系列远程操作服务器的工具，包括检查网络接口、服务状态、防火墙配置等功能。

## 功能特性

### 服务器监控工具
- **系统资源巡检**：全面的CPU、内存、磁盘资源监控
- **服务状态管理**：检查服务运行状态和开机启动配置
- **网络诊断**：接口状态、连接检测和端口扫描
- **安全审计**：SSH风险登录检测、防火墙配置检查
- **日志分析**：实时日志监控和错误模式识别
- **系统信息**：获取操作系统详情和硬件信息
- **进程管理**：监控高资源占用进程
- **自动化备份**：关键系统文件和配置备份

### 网络设备管理
- **设备识别**：自动识别网络设备类型和型号
- **端口状态**：交换机端口状态和VLAN配置检查
- **路由分析**：路由器路由表和ACL配置检查
- **配置备份**：自动化备份网络设备配置

### 辅助功能
- **工具清单**：列出所有可用工具和功能描述
- **批量操作**：支持多设备同时执行巡检任务

## 安装方法
本项目使用 [`uv`](https://github.com/astral-sh/uv) 来管理 Python 依赖和虚拟环境。

### 1. 安装uv
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. 创建并激活虚拟环境
```bash
uv venv .venv
source .venv/bin/activate  # Linux/macOS
# 或
\.venv\Scripts\activate   # Windows
```

### 3. 安装项目依赖
确保你已经安装了 Python 3.10 或更高版本，然后使用以下命令安装项目依赖：
```bash
uv pip install -r requirements.txt
```

注：依赖信息可在 `pyproject.toml` 文件中查看。

## MCP服务器配置
要将此项目添加为MCP服务器，请在配置文件中添加以下配置：

```json
"mytestmcp/mcptest": {
      "command": "uv",
      "args": [
        "--directory",
        "YOUR_PROJECT_PATH_HERE",  // 请替换为你的项目实际路径
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

## 开源协议
本项目采用 [MIT 许可证](LICENSE)。

## 注意事项
- 请确保远程服务器的 SSH 服务正常运行，并且你有相应的权限。
- 在使用工具时，请根据实际情况调整参数。
- 当前项目正在完善···
