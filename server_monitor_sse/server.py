import anyio
import click
import json
import mcp.types as types
from mcp.server.lowlevel import Server

# 导入服务器监控工具
from tools import (
    remote_server_inspection,
    get_system_load,
    monitor_processes,
    check_service_status,
    get_os_details,
    check_ssh_risk_logins,
    check_firewall_config,
    security_vulnerability_scan,
    backup_critical_files,
    inspect_network,
    analyze_logs,
    list_docker_containers,
    list_docker_images,
    list_docker_volumes,
    get_container_logs,
    monitor_container_stats,
    check_docker_health,
    list_available_tools
)
from core.ssh_manager import SSHManager
from config.logger import logger


@click.command()
@click.option("--port", default=8000, help="Port to listen on for SSE")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse"]),
    default="stdio",
    help="Transport type",
)
def main(port: int, transport: str) -> int:
    print(f"Starting server with transport={transport} on port={port}")
    logger.info(f"Starting server with transport={transport} on port={port}")
    app = Server("server-monitor-sse")

    @app.call_tool()
    async def tool_handler(
        name: str, arguments: dict
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        result = None

        # 处理各种工具调用
        if name == "remote_server_inspection":
            required_args = ["hostname", "username"]
            for arg in required_args:
                if arg not in arguments:
                    raise ValueError(f"Missing required argument '{arg}'")

            result = remote_server_inspection(
                hostname=arguments["hostname"],
                username=arguments["username"],
                password=arguments.get("password", ""),
                port=arguments.get("port", 22),
                inspection_modules=arguments.get("inspection_modules", ["cpu", "memory", "disk"]),
                timeout=arguments.get("timeout", 30),
                use_connection_cache=arguments.get("use_connection_cache", True)
            )

        elif name == "get_system_load":
            required_args = ["hostname", "username"]
            for arg in required_args:
                if arg not in arguments:
                    raise ValueError(f"Missing required argument '{arg}'")

            result = get_system_load(
                hostname=arguments["hostname"],
                username=arguments["username"],
                password=arguments.get("password", ""),
                port=arguments.get("port", 22),
                timeout=arguments.get("timeout", 30)
            )

        elif name == "monitor_processes":
            required_args = ["hostname", "username"]
            for arg in required_args:
                if arg not in arguments:
                    raise ValueError(f"Missing required argument '{arg}'")

            result = monitor_processes(
                hostname=arguments["hostname"],
                username=arguments["username"],
                password=arguments.get("password", ""),
                port=arguments.get("port", 22),
                top_n=arguments.get("top_n", 10),
                sort_by=arguments.get("sort_by", "cpu"),
                timeout=arguments.get("timeout", 30)
            )

        elif name == "check_service_status":
            required_args = ["hostname", "username"]
            for arg in required_args:
                if arg not in arguments:
                    raise ValueError(f"Missing required argument '{arg}'")

            result = check_service_status(
                hostname=arguments["hostname"],
                username=arguments["username"],
                password=arguments.get("password", ""),
                port=arguments.get("port", 22),
                service_names=arguments.get("service_names", []),
                timeout=arguments.get("timeout", 30)
            )

        elif name == "get_os_details":
            required_args = ["hostname", "username"]
            for arg in required_args:
                if arg not in arguments:
                    raise ValueError(f"Missing required argument '{arg}'")

            result = get_os_details(
                hostname=arguments["hostname"],
                username=arguments["username"],
                password=arguments.get("password", ""),
                port=arguments.get("port", 22),
                timeout=arguments.get("timeout", 30)
            )

        elif name == "check_ssh_risk_logins":
            required_args = ["hostname", "username"]
            for arg in required_args:
                if arg not in arguments:
                    raise ValueError(f"Missing required argument '{arg}'")

            result = check_ssh_risk_logins(
                hostname=arguments["hostname"],
                username=arguments["username"],
                password=arguments.get("password", ""),
                port=arguments.get("port", 22),
                log_file=arguments.get("log_file", "/var/log/auth.log"),
                threshold=arguments.get("threshold", 5),
                timeout=arguments.get("timeout", 30)
            )

        elif name == "check_firewall_config":
            required_args = ["hostname", "username"]
            for arg in required_args:
                if arg not in arguments:
                    raise ValueError(f"Missing required argument '{arg}'")

            result = check_firewall_config(
                hostname=arguments["hostname"],
                username=arguments["username"],
                password=arguments.get("password", ""),
                port=arguments.get("port", 22),
                timeout=arguments.get("timeout", 30)
            )

        elif name == "security_vulnerability_scan":
            required_args = ["hostname", "username"]
            for arg in required_args:
                if arg not in arguments:
                    raise ValueError(f"Missing required argument '{arg}'")

            result = security_vulnerability_scan(
                hostname=arguments["hostname"],
                username=arguments["username"],
                password=arguments.get("password", ""),
                port=arguments.get("port", 22),
                scan_type=arguments.get("scan_type", "basic"),
                timeout=arguments.get("timeout", 60)
            )

        elif name == "backup_critical_files":
            required_args = ["hostname", "username"]
            for arg in required_args:
                if arg not in arguments:
                    raise ValueError(f"Missing required argument '{arg}'")

            result = backup_critical_files(
                hostname=arguments["hostname"],
                username=arguments["username"],
                password=arguments.get("password", ""),
                port=arguments.get("port", 22),
                backup_dir=arguments.get("backup_dir", "/tmp/backup"),
                files_to_backup=arguments.get("files_to_backup", ["/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config"]),
                timeout=arguments.get("timeout", 30)
            )

        elif name == "inspect_network":
            required_args = ["hostname", "username"]
            for arg in required_args:
                if arg not in arguments:
                    raise ValueError(f"Missing required argument '{arg}'")

            result = inspect_network(
                hostname=arguments["hostname"],
                username=arguments["username"],
                password=arguments.get("password", ""),
                port=arguments.get("port", 22),
                timeout=arguments.get("timeout", 30)
            )

        elif name == "analyze_logs":
            required_args = ["hostname", "username"]
            for arg in required_args:
                if arg not in arguments:
                    raise ValueError(f"Missing required argument '{arg}'")

            result = analyze_logs(
                hostname=arguments["hostname"],
                username=arguments["username"],
                password=arguments.get("password", ""),
                port=arguments.get("port", 22),
                log_file=arguments.get("log_file", "/var/log/syslog"),
                pattern=arguments.get("pattern", "error|fail|critical"),
                lines=arguments.get("lines", 100),
                timeout=arguments.get("timeout", 30)
            )

        elif name == "list_docker_containers":
            required_args = ["hostname", "username"]
            for arg in required_args:
                if arg not in arguments:
                    raise ValueError(f"Missing required argument '{arg}'")

            result = list_docker_containers(
                hostname=arguments["hostname"],
                username=arguments["username"],
                password=arguments.get("password", ""),
                port=arguments.get("port", 22),
                show_all=arguments.get("show_all", False),
                timeout=arguments.get("timeout", 30)
            )

        elif name == "list_docker_images":
            required_args = ["hostname", "username"]
            for arg in required_args:
                if arg not in arguments:
                    raise ValueError(f"Missing required argument '{arg}'")

            result = list_docker_images(
                hostname=arguments["hostname"],
                username=arguments["username"],
                password=arguments.get("password", ""),
                port=arguments.get("port", 22),
                timeout=arguments.get("timeout", 30)
            )

        elif name == "list_docker_volumes":
            required_args = ["hostname", "username"]
            for arg in required_args:
                if arg not in arguments:
                    raise ValueError(f"Missing required argument '{arg}'")

            result = list_docker_volumes(
                hostname=arguments["hostname"],
                username=arguments["username"],
                password=arguments.get("password", ""),
                port=arguments.get("port", 22),
                timeout=arguments.get("timeout", 30)
            )

        elif name == "get_container_logs":
            required_args = ["hostname", "username", "container"]
            for arg in required_args:
                if arg not in arguments:
                    raise ValueError(f"Missing required argument '{arg}'")

            result = get_container_logs(
                hostname=arguments["hostname"],
                username=arguments["username"],
                password=arguments.get("password", ""),
                port=arguments.get("port", 22),
                container=arguments["container"],
                tail=arguments.get("tail", 100),
                since=arguments.get("since", ""),
                timeout=arguments.get("timeout", 30)
            )

        elif name == "monitor_container_stats":
            required_args = ["hostname", "username"]
            for arg in required_args:
                if arg not in arguments:
                    raise ValueError(f"Missing required argument '{arg}'")

            result = monitor_container_stats(
                hostname=arguments["hostname"],
                username=arguments["username"],
                password=arguments.get("password", ""),
                port=arguments.get("port", 22),
                containers=arguments.get("containers", []),
                timeout=arguments.get("timeout", 30)
            )

        elif name == "check_docker_health":
            required_args = ["hostname", "username"]
            for arg in required_args:
                if arg not in arguments:
                    raise ValueError(f"Missing required argument '{arg}'")

            result = check_docker_health(
                hostname=arguments["hostname"],
                username=arguments["username"],
                password=arguments.get("password", ""),
                port=arguments.get("port", 22),
                timeout=arguments.get("timeout", 30)
            )

        elif name == "list_available_tools":
            result = list_available_tools(app)

        else:
            raise ValueError(f"Unknown tool: {name}")

        # 将结果转换为文本内容
        if result is not None:
            if isinstance(result, dict) or isinstance(result, list):
                result_text = json.dumps(result, ensure_ascii=False, indent=2)
            else:
                result_text = str(result)

            return [types.TextContent(type="text", text=result_text)]

        return []

    @app.list_tools()
    async def list_tools() -> list[types.Tool]:
        tools = []

        # 添加服务器监控工具
        tool_descriptions = list_available_tools(app)
        for tool in tool_descriptions:
            # 构建输入模式
            properties = {}
            required = []

            for param in tool["parameters"]:
                param_name = param["name"]
                param_type = param["type"]
                param_default = param.get("default")

                # 确定参数类型
                if param_type == "str":
                    param_schema = {"type": "string"}
                elif param_type == "int":
                    param_schema = {"type": "integer"}
                elif param_type == "bool":
                    param_schema = {"type": "boolean"}
                elif param_type.startswith("list"):
                    param_schema = {"type": "array"}
                    if "str" in param_type:
                        param_schema["items"] = {"type": "string"}
                    elif "int" in param_type:
                        param_schema["items"] = {"type": "integer"}
                else:
                    param_schema = {"type": "string"}

                # 添加描述
                param_schema["description"] = f"{param_name} ({param_type})"

                # 添加到属性
                properties[param_name] = param_schema

                # 如果没有默认值且不是密码，则为必需参数
                if param_default is None and param_name not in ["password"]:
                    required.append(param_name)

            # 特殊处理某些工具的必需参数
            if tool["name"] == "get_container_logs":
                if "container" not in required:
                    required.append("container")

            # 创建工具定义
            tools.append(
                types.Tool(
                    name=tool["name"],
                    description=tool["description"],
                    inputSchema={
                        "type": "object",
                        "required": required,
                        "properties": properties
                    }
                )
            )

        return tools

    if transport == "sse":
        print("Initializing SSE transport")
        logger.info("Initializing SSE transport")

        from mcp.server.sse import SseServerTransport
        from starlette.applications import Starlette
        from starlette.routing import Mount, Route

        sse = SseServerTransport("/messages/")
        print("Created SseServerTransport")
        logger.info("Created SseServerTransport")

        async def handle_sse(request):
            print(f"Handling SSE connection from {request.client}")
            logger.info(f"Handling SSE connection from {request.client}")
            async with sse.connect_sse(
                request.scope, request.receive, request._send
            ) as streams:
                print("SSE connection established, running app")
                logger.info("SSE connection established, running app")
                await app.run(
                    streams[0], streams[1], app.create_initialization_options()
                )

        starlette_app = Starlette(
            debug=True,
            routes=[
                Route("/sse", endpoint=handle_sse),
                Mount("/messages/", app=sse.handle_post_message),
            ],
        )
        print("Created Starlette app with routes")
        logger.info("Created Starlette app with routes")

        import uvicorn
        print(f"Starting Uvicorn server on 0.0.0.0:{port}")
        logger.info(f"Starting Uvicorn server on 0.0.0.0:{port}")

        uvicorn.run(starlette_app, host="0.0.0.0", port=port)
    else:
        from mcp.server.stdio import stdio_server

        async def arun():
            async with stdio_server() as streams:
                await app.run(
                    streams[0], streams[1], app.create_initialization_options()
                )

        anyio.run(arun)

    # 清理资源
    try:
        SSHManager.clear_cache()
        logger.info("Cleaned up all resources")
    except Exception as e:
        logger.error(f"Error cleaning up resources: {str(e)}")

    return 0