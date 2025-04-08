"""工具函数辅助模块"""

from typing import List
from server_monitor.models.schemas import ToolInfo

def list_available_tools(mcp_instance) -> List[ToolInfo]:
    """列出所有可用的工具及其描述"""
    tools = []

    # 获取所有被装饰为工具的函数
    for tool_name in dir(mcp_instance.tool):
        if tool_name.startswith("__"):  # 跳过内部属性
            continue

        tool_func = getattr(mcp_instance.tool, tool_name, None)
        if callable(tool_func) and hasattr(tool_func, "__doc__") and tool_func.__doc__:
            # 获取参数信息
            params = []
            if hasattr(tool_func, "__annotations__"):
                for param_name, param_type in tool_func.__annotations__.items():
                    if param_name != "return":
                        # 尝试获取默认值
                        default_value = None
                        if hasattr(tool_func, "__defaults__") and tool_func.__defaults__:
                            # 计算参数在默认值元组中的索引
                            param_index = list(tool_func.__annotations__.keys()).index(param_name) - len(tool_func.__annotations__.keys()) + len(tool_func.__defaults__)
                            if 0 <= param_index < len(tool_func.__defaults__):
                                default_value = tool_func.__defaults__[param_index]

                        params.append({
                            "name": param_name,
                            "type": str(param_type),
                            "default": default_value
                        })

            tools.append({
                "name": tool_name,
                "description": tool_func.__doc__.strip(),
                "parameters": params
            })

    # 手动列出所有工具，确保返回所有已定义的函数
    tool_descriptions = [
        {"name": "get_memory_info", "description": "获取本地服务器内存信息", "parameters": []},
        {"name": "remote_server_inspection", "description": "执行远程服务器巡检", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "inspection_modules", "type": "list[str]", "default": ["cpu", "memory", "disk"]},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "get_system_load", "description": "获取系统负载信息", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "list_available_tools", "description": "列出所有可用的工具及其描述", "parameters": []},
        {"name": "monitor_processes", "description": "监控远程服务器进程，返回占用资源最多的进程", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "top_n", "type": "int", "default": 10},
            {"name": "sort_by", "type": "str", "default": "cpu"},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "check_service_status", "description": "检查指定服务的运行状态", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "services", "type": "list[str]", "default": []},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "inspect_network", "description": "检查网络接口和连接状态", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "analyze_logs", "description": "分析服务器日志文件中的错误和警告", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "log_file", "type": "str", "default": "/var/log/syslog"},
            {"name": "pattern", "type": "str", "default": "error|fail|critical"},
            {"name": "lines", "type": "int", "default": 100},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "backup_critical_files", "description": "备份重要系统配置文件", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "files", "type": "list[str]", "default": ["/etc/passwd", "/etc/shadow", "/etc/fstab", "/etc/hosts"]},
            {"name": "backup_dir", "type": "str", "default": "/tmp/backup"},
            {"name": "timeout", "type": "int", "default": 60}
        ]},
        {"name": "security_vulnerability_scan", "description": "执行基础安全漏洞扫描", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "scan_type", "type": "str", "default": "basic"},
            {"name": "timeout", "type": "int", "default": 60}
        ]},
        {"name": "check_ssh_risk_logins", "description": "检查SSH登录风险，包括失败尝试和可疑IP", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "log_file", "type": "str", "default": "/var/log/auth.log"},
            {"name": "threshold", "type": "int", "default": 5},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "check_firewall_config", "description": "检查防火墙配置和开放端口", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "get_os_details", "description": "获取操作系统详细信息", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "timeout", "type": "int", "default": 30}
        ]}
    ]

    # 如果自动检测的工具不足，则使用手动定义的工具列表
    if len(tools) < len(tool_descriptions):
        return tool_descriptions

    return tools