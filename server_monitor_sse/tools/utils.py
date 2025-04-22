"""工具函数辅助模块"""

from typing import List, Dict, Any
from config.logger import logger

def list_available_tools(app) -> List[Dict[str, Any]]:
    """列出所有可用的工具及其描述"""
    tools = []

    # 手动列出所有工具，确保返回所有已定义的函数
    tool_descriptions = [
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
        {"name": "monitor_processes", "description": "监控远程服务器进程，返回占用资源最多的进程", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "top_n", "type": "int", "default": 10},
            {"name": "sort_by", "type": "str", "default": "cpu"},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "check_service_status", "description": "检查服务状态", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "service_names", "type": "list[str]", "default": []},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "get_os_details", "description": "获取操作系统详细信息", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "timeout", "type": "int", "default": 30}
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
        {"name": "check_firewall_config", "description": "检查防火墙配置", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "security_vulnerability_scan", "description": "执行安全漏洞扫描", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "scan_type", "type": "str", "default": "basic"},
            {"name": "timeout", "type": "int", "default": 60}
        ]},
        {"name": "backup_critical_files", "description": "备份关键系统文件", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "backup_dir", "type": "str", "default": "/tmp/backup"},
            {"name": "files_to_backup", "type": "list[str]", "default": ["/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config"]},
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
        {"name": "list_docker_containers", "description": "列出Docker容器及其信息", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "show_all", "type": "bool", "default": False},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "list_docker_images", "description": "列出Docker镜像及其信息", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "list_docker_volumes", "description": "列出Docker卷及其信息", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "get_container_logs", "description": "获取Docker容器的日志", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "container", "type": "str", "default": ""},
            {"name": "tail", "type": "int", "default": 100},
            {"name": "since", "type": "str", "default": ""},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "monitor_container_stats", "description": "监控容器的资源使用情况", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "containers", "type": "list[str]", "default": []},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "check_docker_health", "description": "检查Docker服务健康状态", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "timeout", "type": "int", "default": 30}
        ]}
    ]

    return tool_descriptions
