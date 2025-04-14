<div style="text-align: right; margin-bottom: 20px;">
  <a href="README.md" style="padding: 8px 15px; background: #007bff; color: white; text-decoration: none; border-radius: 4px;">English</a>
</div>

# ops-mcp-server 项目

## 项目简介
ops-mcp-server 是一个革命性的 IT 运维管理解决方案，它通过多智能体协作协议（MCP）与大语言模型（LLMs）的无缝集成，实现了智能化的 IT 运维。通过利用大语言模型的强大能力和 MCP 的分布式架构，该系统将传统 IT 运维转变为 AI 驱动的体验，实现了服务器监控自动化、智能异常检测和上下文感知的故障排查。系统充当人类运维人员和复杂 IT 基础设施之间的桥梁，通过自然语言交互来处理从日常维护到复杂问题诊断的各类任务，同时保持企业级的安全性和可扩展性。

### 核心特点
- **实时监控**：持续监控系统资源、服务和性能指标
- **自动化巡检**：支持定时和按需的服务器健康和安全状态检查
- **多厂商支持**：兼容多个网络设备厂商，包括思科、华为和 H3C
- **容器支持**：内置 Docker 容器管理和监控功能
- **安全导向**：集成安全扫描和风险评估工具
- **插件系统**：可扩展的插件架构，支持添加新的监控和管理功能

### 演示视频
在Cherry Studio
![演示动画](assets/demo.gif)

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

### 容器管理工具
- **Docker容器列表**：列出所有Docker容器及其资源使用情况
- **Docker镜像列表**：列出服务器上的所有Docker镜像
- **Docker卷列表**：列出所有Docker卷及其大小信息
- **容器日志获取**：获取指定容器的日志
- **容器资源监控**：监控容器的资源使用情况
- **Docker健康检查**：检查Docker服务的健康状态和基本信息

### 网络设备管理工具
- **设备识别**：识别网络设备类型和基本信息，自动检测设备厂商（思科、华为、H3C等）
- **交换机端口检查**：检查交换机端口状态和配置
- **路由器路由表检查**：按协议检查路由器路由表
- **网络设备配置备份**：备份网络设备配置文件
- **ACL配置检查**：检查安全ACL配置和规则
- **VLAN配置检查**：检查交换机VLAN配置和端口
- **光模块检测**：检查光模块状态、功率、温度等关键指标，支持多厂商设备
- **设备性能监控**：监控网络设备CPU、内存、温度、接口流量及缓冲区使用情况

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
        "YOUR_PROJECT_PATH_HERE",  // Replace with your actual project path
        "run",
        "server_monitor.py"
      ],
      "env": {},
      "disabled": true,
      "autoApprove": [
        "list_available_tools"
      ]
    },
"network_tools": {
      "command": "uv",
      "args": [
        "--directory",
        "YOUR_PROJECT_PATH_HERE",  // Replace with your actual project path
        "run",
        "network_tools.py"
      ],
      "env": {},
      "disabled": false,
      "autoApprove": []
    }
```
## 客户端使用说明
本项目提供了一个交互式客户端 `client.py`，可以通过自然语言与 MCP 服务进行交互。

### 客户端演示视频
在 Terminal
![演示动画](assets/client.gif)

### 安装客户端依赖
客户端需要额外安装 `openai` 和 `rich` 库：
```bash
uv pip install openai rich
```

### 启动客户端
使用以下命令启动客户端：
```bash
uv run client.py [server.py的路径]
```
例如：
```bash
uv run client.py ./server_monitor.py
```

### 配置客户端
在使用前，需要修改 `client.py` 中的以下配置：
1. `api_key` - 设置为您的大模型 API 密钥
2. `base_url` - 设置为您使用的大模型 API 地址
3. `model` - 设置为您想使用的模型名称

修改位置在 `client.py` 的 `MCPClient` 类初始化部分：
```python
# 初始化 OpenAI 客户端
api_key = "您的API密钥"
base_url="https://您的API地址"
self.client = AsyncOpenAI(
    base_url=base_url,
    api_key=api_key,
)

# 设置 model
self.model = "您想使用的模型"
```

### 客户端命令
在客户端中可以使用以下命令：
- `help` - 显示帮助信息
- `quit` - 退出程序
- `clear` - 清除对话历史
- `model <名称>` - 切换模型

## 开源协议
本项目采用 [MIT 许可证](LICENSE)。


## 注意事项
- 请确保远程服务器的 SSH 服务正常运行，并且你有相应的权限。
- 在使用工具时，请根据实际情况调整参数。
- 当前项目正在完善····

