<div style="text-align: right; margin-bottom: 20px;">
  <a href="README.md" style="padding: 8px 15px; background: #007bff; color: white; text-decoration: none; border-radius: 4px;">English</a>
</div>

# ops-mcp-server 项目

## 项目简介
ops-mcp-server 是一个用于服务器巡检和监控的工具集合，提供了一系列远程操作服务器的工具，包括检查网络接口、服务状态、防火墙配置等功能。

## 功能特性

### 服务器监控工具
- **获取内存信息**：获取本地服务器内存信息
- **远程服务器巡检**：执行远程服务器巡检，包括CPU、内存、磁盘等模块
- **系统负载监控**：获取系统负载信息
- **进程监控**：监控远程服务器进程，返回占用资源最多的进程
- **服务状态检查**：检查指定服务的运行状态
- **网络接口检查**：检查网络接口和连接状态
- **日志分析**：分析服务器日志文件中的错误和警告
- **配置备份**：备份重要系统配置文件
- **安全漏洞扫描**：执行基础安全漏洞扫描
- **SSH登录风险检查**：检查SSH登录风险，包括失败尝试和可疑IP
- **防火墙配置检查**：检查防火墙配置和开放端口
- **操作系统信息获取**：获取操作系统详细信息

### 网络设备管理
- **设备识别**：识别网络设备类型和基本信息
- **交换机端口检查**：检查交换机端口状态
- **路由表检查**：检查路由器路由表
- **网络配置备份**：备份网络设备配置
- **ACL配置检查**：检查安全ACL配置
- **VLAN配置检查**：检查交换机VLAN配置

### 辅助功能
- **工具列表**：列出所有可用的工具及其描述
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
.\.venv\Scripts\activate   # Windows
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
"ops-mcp-server": {
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
- 当前项目正在完善····

