from typing import List, Optional
import logging
import os
from datetime import datetime
from mcp.server.fastmcp import FastMCP
from network_tools.models.base_models import InspectionResult
from network_tools.managers.ssh_manager import SSHManager
from network_tools.inspectors.network_inspector import NetworkInspector

# 配置日志
logger = logging.getLogger('network_tools.log_tools')

# 创建MCP实例
mcp = FastMCP(__name__)

@mcp.tool()
def analyze_device_logs(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    log_type: str = "auth",  # auth, system, all
    timeframe: str = "1d",   # 1h, 6h, 1d, 1w, 1m
    max_logs: int = 1000,
    timeout: int = 60
) -> dict:
    """分析网络设备的登录和系统日志，识别异常访问和行为模式"""
    result = InspectionResult()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 根据设备类型收集日志数据
            logs_data = collect_logs(ssh, log_type, timeframe, max_logs)
            
            if not logs_data:
                result.status = "error"
                result.error = "未能收集到日志数据"
                return result.dict()
            
            # 检测设备类型和厂商
            vendor = detect_device_vendor(ssh)
            
            # 解析日志
            parsed_logs = NetworkInspector.parse_logs(logs_data, vendor)
            
            if not parsed_logs:
                result.status = "error"
                result.error = "未能解析到有效日志条目"
                return result.dict()
            
            # 分析日志
            analysis_result = NetworkInspector.analyze_device_logs(parsed_logs)
            
            # 设置返回结果
            result.status = "success"
            result.data = {
                "analysis": analysis_result,
                "logs": parsed_logs[:100]  # 只返回前100条原始日志
            }
            
            # 生成总结信息
            summary_parts = []
            summary_parts.append(f"共分析 {analysis_result['log_count']} 条日志")
            
            if log_type in ["auth", "all"]:
                summary_parts.append(f"登录成功: {analysis_result['auth_success_count']} 次")
                summary_parts.append(f"登录失败: {analysis_result['auth_failure_count']} 次")
            
            if analysis_result['unusual_access_ips']:
                unusual_ips_count = len(analysis_result['unusual_access_ips'])
                summary_parts.append(f"发现 {unusual_ips_count} 个异常访问IP")
            
            if analysis_result['unusual_access_times']:
                unusual_times_count = len(analysis_result['unusual_access_times'])
                summary_parts.append(f"发现 {unusual_times_count} 次非工作时间访问")
            
            if analysis_result['config_change_count'] > 0:
                summary_parts.append(f"配置变更: {analysis_result['config_change_count']} 次")
            
            if analysis_result['error_events_count'] > 0:
                summary_parts.append(f"错误事件: {analysis_result['error_events_count']} 次")
            
            result.summary = "，".join(summary_parts)
            
    except Exception as e:
        result.status = "error"
        result.error = f"分析网络设备日志失败: {str(e)}"
        logger.error(f"分析网络设备日志失败: {str(e)}")
    
    return result.dict()

def collect_logs(ssh, log_type: str, timeframe: str, max_logs: int) -> str:
    """根据设备类型和日志类型收集日志"""
    # 尝试识别设备类型
    try:
        stdin, stdout, stderr = ssh.exec_command("show version")
        device_info = stdout.read().decode('utf-8')
    except:
        device_info = ""
    
    # 解析时间范围
    time_param = parse_timeframe(timeframe)
    
    # 基于设备信息确定厂商
    vendor = NetworkInspector.detect_vendor(device_info)
    
    # 收集命令集
    commands = []
    
    if vendor == "cisco":
        if log_type == "auth" or log_type == "all":
            commands.append(f"show logging | include auth|login|failed|AAA|user")
        if log_type == "system" or log_type == "all":
            commands.append(f"show logging | last {max_logs}")
        if log_type == "config":
            commands.append("show archive log config all")
    
    elif vendor == "juniper":
        if log_type == "auth" or log_type == "all":
            commands.append("show log messages | match \"authentication|login|user|failed\"")
        if log_type == "system" or log_type == "all":
            commands.append(f"show log messages | last {max_logs}")
        if log_type == "config":
            commands.append("show system commit")
    
    elif vendor == "huawei":
        if log_type == "auth" or log_type == "all":
            commands.append("display logbuffer | include auth|login|failed|AAA|user")
        if log_type == "system" or log_type == "all":
            commands.append(f"display logbuffer")
        if log_type == "config":
            commands.append("display configuration commit list")
    
    elif vendor == "fortinet":
        if log_type == "auth" or log_type == "all":
            commands.append("get log memory filter category auth")
        if log_type == "system" or log_type == "all":
            commands.append("get log memory")
        if log_type == "config":
            commands.append("get system config-revision")
            
    elif vendor == "zte":
        if log_type == "auth" or log_type == "all":
            commands.append("show logging | include LOGIN|login|user|auth|failed")
        if log_type == "system" or log_type == "all":
            commands.append(f"show logging buffer")
        if log_type == "config":
            commands.append("show configuration commit")
    
    else:
        # 通用命令，尝试不同的日志命令格式
        generic_commands = [
            "show logging",
            "display log",
            "get log",
            "show log",
            "display logbuffer"
        ]
        commands.extend(generic_commands)
    
    # 执行命令并收集日志
    all_logs = []
    for cmd in commands:
        try:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode('utf-8', errors='ignore')
            if output:
                all_logs.append(output)
        except Exception as e:
            logger.warning(f"执行命令 '{cmd}' 失败: {str(e)}")
    
    return "\n".join(all_logs)

def detect_device_vendor(ssh) -> str:
    """检测设备厂商"""
    try:
        # 尝试执行通用的版本命令
        commands = [
            "show version", 
            "display version",
            "get system status",
            "show system information"
        ]
        
        for cmd in commands:
            try:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                output = stdout.read().decode('utf-8')
                if output:
                    return NetworkInspector.detect_vendor(output)
            except:
                continue
                
        return "unknown"
    except Exception as e:
        logger.error(f"检测设备厂商失败: {str(e)}")
        return "unknown"

def parse_timeframe(timeframe: str) -> str:
    """解析时间范围参数"""
    if not timeframe:
        return "1d"  # 默认1天
        
    # 解析格式：数字+单位(h=小时,d=天,w=周,m=月)
    try:
        value = int(timeframe[:-1])
        unit = timeframe[-1].lower()
        
        if unit == 'h':
            return f"{value}h"  # 小时
        elif unit == 'd':
            return f"{value}d"  # 天
        elif unit == 'w':
            return f"{value * 7}d"  # 周转换为天
        elif unit == 'm':
            return f"{value * 30}d"  # 月转换为天(近似)
        else:
            return "1d"  # 默认1天
    except:
        return "1d"  # 默认1天 