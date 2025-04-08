"""服务器监控主模块"""

from mcp.server.fastmcp import FastMCP
from .config.logger import logger
from .core.ssh_manager import SSHManager
import importlib

# 获取所有工具功能
from .tools import (
    get_memory_info, 
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

def cleanup_resources():
    """清理资源"""
    SSHManager.clear_cache()
    logger.info("Cleaned up all resources")

def init_mcp():
    """初始化MCP服务"""
    # 初始化MCP服务
    mcp = FastMCP("ServerMonitor")

    # 注册所有工具函数
    tools_dict = {
        'get_memory_info': get_memory_info,
        'remote_server_inspection': remote_server_inspection,
        'get_system_load': get_system_load,
        'monitor_processes': monitor_processes,
        'check_service_status': check_service_status,
        'get_os_details': get_os_details,
        'check_ssh_risk_logins': check_ssh_risk_logins,
        'check_firewall_config': check_firewall_config,
        'security_vulnerability_scan': security_vulnerability_scan,
        'backup_critical_files': backup_critical_files,
        'inspect_network': inspect_network,
        'analyze_logs': analyze_logs,
        'list_docker_containers': list_docker_containers,
        'list_docker_images': list_docker_images,
        'list_docker_volumes': list_docker_volumes,
        'get_container_logs': get_container_logs,
        'monitor_container_stats': monitor_container_stats,
        'check_docker_health': check_docker_health
    }
    
    # 使用装饰器动态注册所有工具
    for name, func in tools_dict.items():
        mcp.tool()(func)
    
    # 特殊处理list_available_tools，因为它需要mcp实例
    @mcp.tool()
    def _list_available_tools():
        return list_available_tools(mcp)
    
    return mcp

if __name__ == "__main__":
    try:
        mcp = init_mcp()
        mcp.run(transport='stdio')
    finally:
        cleanup_resources()