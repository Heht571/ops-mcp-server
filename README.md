# mcptest 项目

## 项目简介
mcptest 是一个用于服务器巡检和监控的工具集合，提供了一系列远程操作服务器的工具，包括检查网络接口、服务状态、防火墙配置等功能。

## 功能特性
- **远程服务器巡检**：支持对 CPU、内存、磁盘等资源进行巡检。
- **服务状态检查**：可检查指定服务的运行状态和开机启动情况。
- **网络检查**：检查网络接口和连接状态，包括监听端口和公网连接情况。
- **防火墙配置检查**：检测防火墙类型和开放端口。
- **进程监控**：监控远程服务器上占用资源最多的进程。

## 安装方法
本项目使用 [`uv`](https://github.com/astral-sh/uv) 来管理 Python 依赖和虚拟环境。

确保你已经安装了 Python 3.10 或更高版本，然后使用以下命令安装项目依赖：
```bash
uv pip install -r requirements.txt
```
注：依赖信息可在 `pyproject.toml` 文件中查看。

## 使用方法
### 列出所有可用工具
```python
from main import list_available_tools

tools = list_available_tools()
print(tools)
```
### 执行远程服务器巡检
```python
from main import remote_server_inspection

result = remote_server_inspection(hostname='your_hostname', username='your_username', password='your_password')
print(result)
```
### 其他工具使用方法类似，可参考 `main.py` 文件中的函数定义。

## 贡献指南
请参考 [CONTRIBUTING.md](CONTRIBUTING.md) 文件了解如何参与项目贡献。

## 开源协议
本项目采用 [MIT 许可证](LICENSE)。

## 注意事项
- 请确保远程服务器的 SSH 服务正常运行，并且你有相应的权限。
- 在使用工具时，请根据实际情况调整参数。
