from typing import List
import logging
from mcp.server.fastmcp import FastMCP
from network_tools.models.base_models import InspectionResult
from network_tools.managers.ssh_manager import SSHManager
from network_tools.inspectors.network_inspector import NetworkInspector

# 配置日志
logger = logging.getLogger('network_tools.device_tools')

# 创建MCP实例
mcp = FastMCP(__name__)

@mcp.tool()
def identify_network_device(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    timeout: int = 30
) -> dict:
    """识别网络设备类型和基本信息"""
    result = InspectionResult()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 执行命令收集设备信息
            commands = {
                "version": "show version",
                "inventory": "show inventory",
                "system": "show system",
                "hostname": "hostname"
            }
            
            outputs = {}
            for key, cmd in commands.items():
                try:
                    stdin, stdout, stderr = ssh.exec_command(cmd)
                    output = stdout.read().decode('utf-8').strip()
                    error = stderr.read().decode('utf-8').strip()
                    
                    if output:
                        outputs[key] = output
                    elif error:
                        outputs[key] = f"Error: {error}"
                except Exception as e:
                    logger.warning(f"命令 '{cmd}' 执行失败: {str(e)}")
                    outputs[key] = f"执行失败: {str(e)}"
            
            # 合并所有输出便于解析
            combined_output = "\n".join(outputs.values())
            
            # 解析设备信息
            device_info = NetworkInspector.parse_device_info(combined_output)
            
            # 设置结果
            result.status = "success"
            result.data = {"device_info": device_info}
            result.raw_outputs = outputs
            
            device_type = device_info.get("device_type", "unknown")
            model = device_info.get("model", "未知型号")
            result.summary = f"识别到{device_type}设备，型号: {model}"
            
    except Exception as e:
        result.status = "error"
        result.error = f"识别网络设备失败: {str(e)}"
        logger.error(f"识别网络设备失败: {str(e)}")
    
    return result.dict()

@mcp.tool()
def check_switch_ports(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    include_interfaces: List[str] = [],  # 指定要检查的接口，为空则检查所有接口
    timeout: int = 30
) -> dict:
    """检查交换机端口状态"""
    result = InspectionResult()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 执行命令收集端口信息
            commands = {
                "interfaces": "show interfaces",
                "interfaces_status": "show interfaces status",
                "interfaces_description": "show interfaces description"
            }
            
            outputs = {}
            for key, cmd in commands.items():
                try:
                    stdin, stdout, stderr = ssh.exec_command(cmd)
                    output = stdout.read().decode('utf-8').strip()
                    error = stderr.read().decode('utf-8').strip()
                    
                    if output:
                        outputs[key] = output
                    elif error:
                        outputs[key] = f"Error: {error}"
                except Exception as e:
                    logger.warning(f"命令 '{cmd}' 执行失败: {str(e)}")
                    outputs[key] = f"执行失败: {str(e)}"
            
            # 如果指定了特定接口，获取详细信息
            if include_interfaces:
                for interface in include_interfaces:
                    cmd = f"show interface {interface}"
                    try:
                        stdin, stdout, stderr = ssh.exec_command(cmd)
                        output = stdout.read().decode('utf-8').strip()
                        if output:
                            outputs[f"interface_{interface}"] = output
                    except Exception as e:
                        logger.warning(f"命令 '{cmd}' 执行失败: {str(e)}")
            
            # 合并所有输出便于解析
            combined_output = "\n".join(outputs.values())
            
            # 解析端口信息
            ports = NetworkInspector.parse_switch_ports(combined_output)
            
            # 如果指定了特定接口，过滤结果
            if include_interfaces:
                ports = [p for p in ports if any(intf.lower() in p["interface"].lower() for intf in include_interfaces)]
            
            # 统计端口状态
            up_ports = len([p for p in ports if p["status"].lower() == "up"])
            down_ports = len([p for p in ports if p["status"].lower() == "down" or p["status"].lower() == "notconnect"])
            disabled_ports = len([p for p in ports if p["status"].lower() == "disabled"])
            
            # 设置结果
            result.status = "success"
            result.data = {
                "ports": ports,
                "statistics": {
                    "total": len(ports),
                    "up": up_ports,
                    "down": down_ports,
                    "disabled": disabled_ports
                }
            }
            result.raw_outputs = outputs
            result.summary = f"共检查 {len(ports)} 个端口，{up_ports} 个UP，{down_ports} 个DOWN，{disabled_ports} 个已禁用"
            
    except Exception as e:
        result.status = "error"
        result.error = f"检查交换机端口失败: {str(e)}"
        logger.error(f"检查交换机端口失败: {str(e)}")
    
    return result.dict()

@mcp.tool()
def check_router_routes(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    route_type: str = "all",  # all, static, ospf, bgp, connected
    timeout: int = 30
) -> dict:
    """检查路由器路由表"""
    result = InspectionResult()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 执行命令收集路由信息
            commands = {
                "ip_route": "show ip route",
                "route_summary": "show ip route summary"
            }
            
            # 添加特定路由类型的命令
            if route_type.lower() != "all":
                route_cmd = f"show ip route {route_type.lower()}"
                commands[f"route_{route_type}"] = route_cmd
            
            outputs = {}
            for key, cmd in commands.items():
                try:
                    stdin, stdout, stderr = ssh.exec_command(cmd)
                    output = stdout.read().decode('utf-8').strip()
                    error = stderr.read().decode('utf-8').strip()
                    
                    if output:
                        outputs[key] = output
                    elif error:
                        outputs[key] = f"Error: {error}"
                except Exception as e:
                    logger.warning(f"命令 '{cmd}' 执行失败: {str(e)}")
                    outputs[key] = f"执行失败: {str(e)}"
            
            # 合并所有输出便于解析
            combined_output = "\n".join(outputs.values())
            
            # 解析路由信息
            routes = NetworkInspector.parse_routes(combined_output)
            
            # 如果指定了特定路由类型，过滤结果
            if route_type.lower() != "all":
                routes = [r for r in routes if r["protocol"].lower() == route_type.lower()]
            
            # 按协议统计路由数量
            route_counts = {}
            for route in routes:
                protocol = route["protocol"].lower() if route["protocol"] else "unknown"
                route_counts[protocol] = route_counts.get(protocol, 0) + 1
            
            # 设置结果
            result.status = "success"
            result.data = {
                "routes": routes,
                "statistics": {
                    "total": len(routes),
                    "by_protocol": route_counts
                }
            }
            result.raw_outputs = outputs
            
            summary_parts = []
            for protocol, count in route_counts.items():
                summary_parts.append(f"{protocol}: {count}")
            
            result.summary = f"共 {len(routes)} 条路由 ({', '.join(summary_parts)})"
            
    except Exception as e:
        result.status = "error"
        result.error = f"检查路由表失败: {str(e)}"
        logger.error(f"检查路由表失败: {str(e)}")
    
    return result.dict()

@mcp.tool()
def backup_network_config(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    backup_dir: str = "/tmp/network_config_backup",
    timeout: int = 60
) -> dict:
    """备份网络设备配置"""
    result = InspectionResult()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 创建备份目录
            mkdir_command = f"mkdir -p {backup_dir}"
            stdin, stdout, stderr = ssh.exec_command(mkdir_command)
            error = stderr.read().decode('utf-8').strip()
            if error:
                logger.warning(f"创建备份目录时出现警告: {error}")
            
            # 获取当前时间作为备份标识
            date_command = "date +%Y%m%d_%H%M%S"
            stdin, stdout, stderr = ssh.exec_command(date_command)
            date_string = stdout.read().decode('utf-8').strip()
            
            # 执行命令收集设备配置
            commands = {
                "running_config": "show running-config",
                "startup_config": "show startup-config",
                "version": "show version"
            }
            
            backup_files = []
            for key, cmd in commands.items():
                try:
                    stdin, stdout, stderr = ssh.exec_command(cmd)
                    output = stdout.read().decode('utf-8').strip()
                    error = stderr.read().decode('utf-8').strip()
                    
                    if error and not output:
                        logger.warning(f"命令 '{cmd}' 执行出现错误: {error}")
                        continue
                    
                    # 保存配置到文件
                    backup_file = f"{backup_dir}/{hostname}_{key}_{date_string}.txt"
                    write_command = f"cat > {backup_file} << 'EOT'\n{output}\nEOT"
                    stdin, stdout, stderr = ssh.exec_command(write_command)
                    error = stderr.read().decode('utf-8').strip()
                    
                    if error:
                        logger.warning(f"保存配置到 {backup_file} 时出现错误: {error}")
                    else:
                        # 检查文件是否创建成功
                        check_command = f"[ -f {backup_file} ] && echo 'success' || echo 'failed'"
                        stdin, stdout, stderr = ssh.exec_command(check_command)
                        check_result = stdout.read().decode('utf-8').strip()
                        
                        if check_result == "success":
                            backup_files.append({
                                "file": backup_file,
                                "size": f"获取大小失败",
                                "config_type": key
                            })
                            
                            # 获取文件大小
                            size_command = f"du -h {backup_file} | cut -f1"
                            stdin, stdout, stderr = ssh.exec_command(size_command)
                            size_output = stdout.read().decode('utf-8').strip()
                            if size_output:
                                backup_files[-1]["size"] = size_output
                
                except Exception as e:
                    logger.warning(f"备份 {key} 配置失败: {str(e)}")
            
            # 设置结果
            if backup_files:
                result.status = "success"
                result.data = {"backup_files": backup_files}
                result.summary = f"共备份 {len(backup_files)} 个配置文件到 {backup_dir}"
            else:
                result.status = "error"
                result.error = "未能备份任何配置文件"
            
    except Exception as e:
        result.status = "error"
        result.error = f"备份网络设备配置失败: {str(e)}"
        logger.error(f"备份网络设备配置失败: {str(e)}")
    
    return result.dict() 