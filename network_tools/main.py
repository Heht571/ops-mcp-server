from __future__ import annotations
import logging
from mcp.server.fastmcp import FastMCP
from .tools.device_tools import identify_network_device, check_switch_ports, check_router_routes, backup_network_config
from .tools.config_tools import check_acl_config, inspect_vlans
from .tools.performance_tools import check_optical_modules, check_device_performance
from .tools.log_tools import analyze_device_logs
from .tools.session_tools import check_device_sessions
from .tools.security_tools import analyze_security_policy
from .managers.ssh_manager import SSHManager

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('network_tools')

# 创建MCP实例
mcp = FastMCP("network_tools")

# 注册工具
mcp.add_tool(identify_network_device)
mcp.add_tool(check_switch_ports)
mcp.add_tool(check_router_routes)
mcp.add_tool(backup_network_config)
mcp.add_tool(check_acl_config)
mcp.add_tool(inspect_vlans)
mcp.add_tool(check_optical_modules)
mcp.add_tool(check_device_performance)
mcp.add_tool(analyze_device_logs)
mcp.add_tool(check_device_sessions)
mcp.add_tool(analyze_security_policy)

if __name__ == "__main__":
    try:
        # 运行MCP服务
        mcp.run(transport='stdio')
    finally:
        # 清理SSH连接缓存
        SSHManager.clear_cache()
        logger.info("Network tools terminated.") 