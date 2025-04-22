FROM python:3.10-slim

# 安装依赖
RUN apt-get update && apt-get install -y curl

# 创建目录结构
RUN mkdir -p /root/ops-mcp-server/server_monitor_sse/logs

# 设置工作目录
WORKDIR /root/ops-mcp-server

# 复制整个项目
COPY .. /root/ops-mcp-server/

# 安装依赖
RUN pip install --no-cache-dir mcp paramiko psutil pydantic httpx anyio click starlette uvicorn

# 暴露端口
EXPOSE 8000

# 健康检查已移除

# 设置启动命令
CMD ["python", "-m", "server_monitor_sse", "--transport", "sse", "--port", "8000"]
