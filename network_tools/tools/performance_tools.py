import re
from typing import List, Dict
import logging
from mcp.server.fastmcp import FastMCP
from network_tools.models.base_models import InspectionResult, NetworkVendor
from network_tools.managers.ssh_manager import SSHManager
from network_tools.inspectors.network_inspector import NetworkInspector

# 配置日志
logger = logging.getLogger('network_tools.performance_tools')

# 创建MCP实例
mcp = FastMCP(__name__)

@mcp.tool()
def check_optical_modules(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    interface: str = "",  # 指定要检查的接口，为空则检查所有接口
    timeout: int = 30
) -> dict:
    """检查网络设备光模块状态和信息
    
    Args:
        hostname: 设备主机名或IP地址
        username: SSH用户名
        password: SSH密码
        port: SSH端口
        interface: 指定要检查的接口，为空则检查所有接口
        timeout: SSH连接超时时间(秒)
        
    Returns:
        包含光模块信息的结果字典
    """
    result = InspectionResult()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 先识别设备厂商类型
            stdin, stdout, stderr = ssh.exec_command("show version")
            version_output = stdout.read().decode('utf-8', errors='ignore')
            vendor = NetworkInspector.detect_vendor(version_output)
            
            # 根据不同厂商执行不同的命令
            optical_commands = {
                NetworkVendor.CISCO: [
                    "show interfaces transceiver detail",
                    "show interfaces transceiver",
                    "show inventory"
                ],
                NetworkVendor.HUAWEI: [
                    "display transceiver verbose",
                    "display transceiver interface",
                    "display elabel"
                ],
                NetworkVendor.H3C: [
                    "display transceiver verbose",
                    "display transceiver interface",
                    "display device manuinfo"
                ],
                NetworkVendor.JUNIPER: [
                    "show interfaces diagnostics optics",
                    "show chassis hardware"
                ],
                NetworkVendor.ARISTA: [
                    "show interfaces transceiver detail",
                    "show inventory"
                ],
                NetworkVendor.RUIJIE: [
                    "show interfaces transceiver",
                    "show optical-module summary"
                ]
            }
            
            # 获取命令列表，如果未识别出厂商则尝试常用命令
            commands = optical_commands.get(vendor, [
                "show interfaces transceiver detail",
                "display transceiver verbose",
                "show interfaces diagnostics optics"
            ])
            
            # 如果指定了接口，添加接口参数
            if interface:
                interface_commands = []
                for cmd in commands:
                    if "transceiver" in cmd:
                        if "cisco" in vendor or "arista" in vendor:
                            interface_commands.append(f"{cmd} interface {interface}")
                        elif "huawei" in vendor or "h3c" in vendor:
                            interface_commands.append(f"{cmd} interface {interface}")
                        else:
                            interface_commands.append(f"{cmd} {interface}")
                commands = interface_commands if interface_commands else commands
            
            # 执行命令并收集输出
            combined_output = ""
            for cmd in commands:
                try:
                    stdin, stdout, stderr = ssh.exec_command(cmd)
                    cmd_output = stdout.read().decode('utf-8', errors='ignore')
                    combined_output += f"\n--- Command: {cmd} ---\n{cmd_output}\n"
                    
                    # 如果这个命令返回了有用的信息，可以提前结束
                    if "transceiver" in cmd_output.lower() or "optical" in cmd_output.lower():
                        break
                except Exception as e:
                    logger.warning(f"Command '{cmd}' failed: {str(e)}")
            
            # 解析光模块信息
            optical_modules = NetworkInspector.parse_optical_modules(combined_output)
            
            # 生成结果
            result.status = "success"
            result.data = {
                "optical_modules": optical_modules,
                "vendor": vendor,
                "total_modules": len(optical_modules)
            }
            result.raw_outputs = {"command_output": combined_output}
            
            # 生成摘要
            warning_modules = [m for m in optical_modules if m["status"] == "Warning"]
            alarm_modules = [m for m in optical_modules if m["status"] == "Alarm"]
            result.summary = f"共检测到{len(optical_modules)}个光模块，{len(warning_modules)}个警告状态，{len(alarm_modules)}个告警状态"
            
    except Exception as e:
        result.status = "error"
        result.error = f"检查光模块失败: {str(e)}"
        logger.error(f"Failed to check optical modules on {hostname}: {str(e)}")
    
    return result.dict()

@mcp.tool()
def check_device_performance(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    timeout: int = 30,
    interfaces: List[str] = []  # 指定要检查的接口，为空则检查主要接口
) -> dict:
    """检查网络设备性能，包括CPU、内存、温度、接口流量等
    
    Args:
        hostname: 设备主机名或IP地址
        username: SSH用户名
        password: SSH密码
        port: SSH端口
        timeout: SSH连接超时时间(秒)
        interfaces: 指定要检查的接口，为空则检查主要接口
        
    Returns:
        包含设备性能信息的结果字典
    """
    result = InspectionResult()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 先识别设备厂商类型
            stdin, stdout, stderr = ssh.exec_command("show version")
            version_output = stdout.read().decode('utf-8', errors='ignore')
            vendor = NetworkInspector.detect_vendor(version_output)
            
            # 根据不同厂商执行不同的命令
            performance_commands = {
                NetworkVendor.CISCO: {
                    "cpu": "show processes cpu sorted",
                    "memory": "show processes memory sorted",
                    "temperature": "show environment temperature",
                    "interfaces": "show interfaces | include rate",
                    "buffers": "show buffers",
                    "processes": "show processes cpu sorted 5sec | include CPU|[0-9][0-9]%"
                },
                NetworkVendor.HUAWEI: {
                    "cpu": "display cpu-usage",
                    "memory": "display memory-usage",
                    "temperature": "display environment",
                    "interfaces": "display interface | include rate|utilization",
                    "buffers": "display buffer-usage",
                    "processes": "display cpu-usage verbose"
                },
                NetworkVendor.H3C: {
                    "cpu": "display cpu-usage",
                    "memory": "display memory",
                    "temperature": "display environment",
                    "interfaces": "display interface | include rate|utilization",
                    "buffers": "display buffering",
                    "processes": "display process cpu"
                },
                NetworkVendor.JUNIPER: {
                    "cpu": "show chassis routing-engine",
                    "memory": "show system memory",
                    "temperature": "show chassis environment",
                    "interfaces": "show interfaces extensive | match \"rate|traffic\"",
                    "buffers": "show system buffers",
                    "processes": "show system processes extensive"
                },
                NetworkVendor.ARISTA: {
                    "cpu": "show processes top",
                    "memory": "show system resources",
                    "temperature": "show system environment temperature",
                    "interfaces": "show interfaces counters rates",
                    "buffers": "show hardware capacity",
                    "processes": "show processes top once"
                }
            }
            
            # 获取命令字典，如果未识别出厂商则使用通用命令
            cmd_dict = performance_commands.get(vendor, {
                "cpu": "show processes cpu",
                "memory": "show processes memory",
                "temperature": "show environment",
                "interfaces": "show interfaces",
                "buffers": "show buffers",
                "processes": "show processes"
            })
            
            # 执行命令并收集输出
            outputs = {}
            performance_data = {}
            
            for key, cmd in cmd_dict.items():
                try:
                    # 对于接口命令，如果指定了接口列表，则为每个接口执行命令
                    if key == "interfaces" and interfaces:
                        interface_outputs = []
                        for interface in interfaces:
                            interface_cmd = cmd.replace("interfaces", f"interface {interface}")
                            stdin, stdout, stderr = ssh.exec_command(interface_cmd)
                            interface_output = stdout.read().decode('utf-8', errors='ignore')
                            interface_outputs.append(interface_output)
                        outputs[key] = "\n".join(interface_outputs)
                    else:
                        stdin, stdout, stderr = ssh.exec_command(cmd)
                        outputs[key] = stdout.read().decode('utf-8', errors='ignore')
                except Exception as e:
                    logger.warning(f"Command '{cmd}' failed: {str(e)}")
                    outputs[key] = f"Failed to execute: {str(e)}"
            
            # 解析CPU使用率
            cpu_usage = "Unknown"
            if "cpu" in outputs:
                cpu_output = outputs["cpu"]
                # Cisco格式
                if "five seconds" in cpu_output.lower():
                    cpu_match = re.search(r'five seconds: (\d+)%', cpu_output)
                    if cpu_match:
                        cpu_usage = f"{cpu_match.group(1)}%"
                # Huawei/H3C格式
                elif "utilization" in cpu_output.lower():
                    cpu_match = re.search(r'utilization\s*:\s*(\d+)%', cpu_output, re.IGNORECASE)
                    if cpu_match:
                        cpu_usage = f"{cpu_match.group(1)}%"
                # 通用格式：尝试匹配百分比
                else:
                    cpu_match = re.search(r'(\d+)%', cpu_output)
                    if cpu_match:
                        cpu_usage = f"{cpu_match.group(1)}%"
            
            # 解析内存使用率
            memory_usage = "Unknown"
            if "memory" in outputs:
                mem_output = outputs["memory"]
                # Cisco格式
                if "processor" in mem_output.lower() and "used" in mem_output.lower():
                    mem_match = re.search(r'Processor Pool Total:\s*(\d+) Used:\s*(\d+)', mem_output)
                    if mem_match:
                        total = int(mem_match.group(1))
                        used = int(mem_match.group(2))
                        if total > 0:
                            memory_usage = f"{int(used/total*100)}%"
                # Huawei格式
                elif "memory utilization" in mem_output.lower():
                    mem_match = re.search(r'Memory utilization\s*:\s*(\d+)%', mem_output, re.IGNORECASE)
                    if mem_match:
                        memory_usage = f"{mem_match.group(1)}%"
                # 通用格式：尝试匹配百分比
                else:
                    mem_match = re.search(r'(\d+)%', mem_output)
                    if mem_match:
                        memory_usage = f"{mem_match.group(1)}%"
            
            # 解析温度
            temperature = "Unknown"
            if "temperature" in outputs:
                temp_output = outputs["temperature"]
                # 尝试匹配温度值
                temp_match = re.search(r'(\d+(?:\.\d+)?) ?(C|F|degree|celsius)', temp_output, re.IGNORECASE)
                if temp_match:
                    temperature = f"{temp_match.group(1)}°{temp_match.group(2)[0].upper()}"
            
            # 解析接口流量
            interface_traffic = []
            if "interfaces" in outputs:
                intf_output = outputs["interfaces"]
                # 分析接口流量行
                for line in intf_output.splitlines():
                    # 跳过非数据行
                    if not re.search(r'(input|output|rx|tx) rate', line, re.IGNORECASE):
                        continue
                    
                    # 尝试匹配接口名称
                    intf_name = "Unknown"
                    for prev_line in intf_output.splitlines():
                        if line in prev_line:
                            continue
                        if prev_line.strip() and not re.search(r'(input|output|rx|tx) rate', prev_line, re.IGNORECASE):
                            intf_match = re.match(r'^([A-Za-z0-9\/\.-]+)', prev_line)
                            if intf_match:
                                intf_name = intf_match.group(1)
                                break
                    
                    # 分析流量信息
                    input_match = re.search(r'input rate (\d+) ([bkm]bits/sec)', line, re.IGNORECASE)
                    output_match = re.search(r'output rate (\d+) ([bkm]bits/sec)', line, re.IGNORECASE)
                    
                    traffic_info = {
                        "interface": intf_name,
                        "input_rate": f"{input_match.group(1)} {input_match.group(2)}" if input_match else "Unknown",
                        "output_rate": f"{output_match.group(1)} {output_match.group(2)}" if output_match else "Unknown"
                    }
                    
                    interface_traffic.append(traffic_info)
            
            # 解析缓冲区使用
            buffer_usage = "Unknown"
            if "buffers" in outputs:
                buffer_output = outputs["buffers"]
                buffer_match = re.search(r'Buffer utilization\s*:\s*(\d+)%', buffer_output, re.IGNORECASE)
                if buffer_match:
                    buffer_usage = f"{buffer_match.group(1)}%"
                else:
                    # 尝试从总体信息中计算
                    total_match = re.search(r'total\s*:\s*(\d+)', buffer_output, re.IGNORECASE)
                    used_match = re.search(r'used\s*:\s*(\d+)', buffer_output, re.IGNORECASE)
                    if total_match and used_match:
                        total = int(total_match.group(1))
                        used = int(used_match.group(1))
                        if total > 0:
                            buffer_usage = f"{int(used/total*100)}%"
            
            # 解析进程信息
            process_info = []
            if "processes" in outputs:
                process_output = outputs["processes"]
                # 提取CPU使用率最高的进程
                process_lines = process_output.splitlines()
                for line in process_lines:
                    # 跳过标题行
                    if "CPU" in line and "Process" in line:
                        continue
                    # 匹配进程信息
                    process_match = re.search(r'(\d+(?:\.\d+)?)%\s+(\d+(?:\.\d+)?)%\s+(\d+(?:\.\d+)?)%\s+(\S+)', line)
                    if process_match:
                        process = {
                            "cpu_5sec": f"{process_match.group(1)}%",
                            "cpu_1min": f"{process_match.group(2)}%",
                            "cpu_5min": f"{process_match.group(3)}%",
                            "process_name": process_match.group(4)
                        }
                        process_info.append(process)
                    
                    # 限制进程数量
                    if len(process_info) >= 5:
                        break
            
            # 合并所有性能数据
            performance_data = {
                "cpu_usage": cpu_usage,
                "memory_usage": memory_usage,
                "temperature": temperature,
                "interface_traffic": interface_traffic,
                "buffer_usage": buffer_usage,
                "process_info": process_info
            }
            
            # 生成结果
            result.status = "success"
            result.data = performance_data
            result.raw_outputs = outputs
            
            # 生成摘要
            summary_parts = [
                f"CPU使用率: {cpu_usage}",
                f"内存使用率: {memory_usage}",
                f"设备温度: {temperature}"
            ]
            
            if interface_traffic:
                intf_count = len(interface_traffic)
                summary_parts.append(f"已检查{intf_count}个接口流量")
            
            result.summary = "，".join(summary_parts)
            
    except Exception as e:
        result.status = "error"
        result.error = f"检查设备性能失败: {str(e)}"
        logger.error(f"Failed to check device performance on {hostname}: {str(e)}")
    
    return result.dict() 