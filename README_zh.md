# ops-mcp-server

[![中文](https://img.shields.io/badge/Language-中文-blue.svg)](README_zh.md)

`ops-mcp-server`：一个面向AI时代的智能运维平台，融合了大语言模型（LLMs）与MCP架构，实现智能监控、异常检测以及人与IT基础设施的自然交互，同时具备企业级安全性与可扩展性。

---

## 📖 目录

- [项目概览](#项目概览)
- [核心功能](#核心功能)
- [演示视频](#演示视频)
- [安装指南](#安装指南)
- [部署说明](#部署说明)
- [本地MCP服务器配置](#本地mcp服务器配置)
- [交互式客户端使用](#交互式客户端使用)
- [许可证](#许可证)
- [注意事项](#注意事项)

---

## 🚀 项目概览

`ops-mcp-server` 是一个面向AI时代的IT运维管理解决方案。通过无缝集成模型上下文协议（MCP）与大语言模型（LLMs），实现智能化运维体验。借助LLMs的强大能力与MCP的分布式架构，它将传统IT运维转型为AI驱动的模式，支持自动服务器监控、智能异常检测和上下文感知故障排查。系统在运维人员与复杂IT基础设施之间架起桥梁，支持自然语言交互，从日常维护到复杂故障诊断，同时保障企业级的安全性与可扩展性。

---

## 🌟 核心功能

### 🖥️ 服务器监控

- 实时CPU、内存、磁盘检测
- 系统负载与进程监控
- 服务与网络接口检查
- 日志分析与配置备份
- 安全漏洞扫描（如SSH登录、防火墙状态）
- 详细操作系统信息获取

### 📦 容器管理（Docker）

- 容器、镜像与卷管理
- 容器资源使用情况监控
- 日志检索与健康检查

### 🌐 网络设备管理

- 支持多厂商设备（Cisco、华为、H3C等）
- 交换机端口、VLAN、路由器路由检查
- ACL安全配置分析
- 光模块与设备性能监控

### ➕ 附加能力

- 可扩展的插件架构
- 跨设备批量操作
- 工具列表与描述性命令支持

---

## 🎬 演示视频

### 📌 项目演示

_在 Cherry Studio 上_

![Demo Animation](assets/demo.gif)

### 📌 交互式客户端演示

_在终端上_

![Client Demo Animation](assets/client.gif)

---

## ⚙️ 安装指南

确保安装了 **Python 3.10+**。本项目使用 [`uv`](https://github.com/astral-sh/uv) 进行依赖与环境管理。

### 1. 安装 UV

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. 设置虚拟环境

```bash
uv venv .venv

# 激活环境
source .venv/bin/activate      # Linux/macOS
.\.venv\Scripts\activate       # Windows
```

### 3. 安装依赖

```bash
uv pip install -r requirements.txt
```

> 依赖项通过 `pyproject.toml` 管理。

---

## 🚧 部署说明

### 📡 SSE远程部署（UV）

```bash
cd server_monitor_sse

# 安装依赖
pip install -r requirements.txt

# 启动服务
cd ..
uv run server_monitor_sse --transport sse --port 8000
```

### 🐳 SSE远程部署（Docker Compose）

确保已安装 Docker 和 Docker Compose。

```bash
cd server_monitor_sse
docker compose up -d

# 查看状态
docker compose ps

# 查看日志
docker compose logs -f
```

---

## 🛠️ 本地MCP服务器配置（Stdio模式）

在你的MCP配置中添加如下内容：

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
  }
}
```

> **注意**：请将 `YOUR_PROJECT_PATH_HERE` 替换为你的实际项目路径。

---

## 💬 交互式客户端使用

项目提供交互式客户端（`client.py`），支持通过自然语言与MCP服务交互。

### 1. 安装客户端依赖

```bash
uv pip install openai rich
```

### 2. 配置客户端

在 `client.py` 中进行如下配置：

```python
# 初始化OpenAI客户端
self.client = AsyncOpenAI(
    base_url="https://your-api-endpoint",
    api_key="YOUR_API_KEY"
)

# 设置模型
self.model = "your-preferred-model"
```

### 3. 运行客户端

```bash
uv run client.py [path/to/server.py]
```

示例：

```bash
uv run client.py ./server_monitor.py
```

### 客户端支持命令

- `help` - 显示帮助信息
- `quit` - 退出客户端
- `clear` - 清空会话记录
- `model <name>` - 切换使用的模型

---

## 📄 许可证

本项目基于 [MIT License](LICENSE) 开源许可协议发布。

---

## 📌 注意事项

- 请确保远程SSH访问配置正确。
- 根据实际部署环境调整工具参数。
- 本项目处于积极开发中，欢迎反馈与贡献。

---