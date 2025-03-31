from __future__ import annotations
from typing import Optional, Sequence, Literal, TypedDict, List, Dict, Any
from enum import Enum
import re
import psutil
import paramiko
import json
import platform
import socket
import datetime
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP
from io import StringIO

# ======================
# 数据模型定义
# ======================
class InspectionResult(BaseModel):
    """统一巡检结果模型"""
    status: Literal["success", "error", "unknown"] = Field(default="unknown")
    data: dict = Field(default_factory=dict)
    raw_outputs: dict = Field(default_factory=dict)
    error: str = Field(default="")
    summary: Optional[str] = None  # 新增汇总字段

class ServerMetric(BaseModel):
    """服务器资源指标基础模型"""
    total: float
    used: float
    free: float
    usage: float

class CPUStats(TypedDict):
    """CPU指标数据结构"""
    usage: Optional[float]
    loadavg: Optional[str]

class DiskInfo(TypedDict):
    """磁盘信息数据结构"""
    mount_point: str
    total: str
    used: str
    usage: float

class LoginRecord(TypedDict):
    """登录记录数据结构"""
    time: str
    user: str
    ip: str

class ProcessInfo(TypedDict):
    """进程信息数据结构"""
    pid: int
    name: str
    user: str
    cpu_percent: float
    memory_percent: float
    status: str
    created: str

class ServiceStatus(TypedDict):
    """服务状态数据结构"""
    name: str
    status: str
    active: bool
    enabled: bool

class NetworkInterface(TypedDict):
    """网络接口数据结构"""
    name: str
    ip_address: str
    mac_address: str
    status: str
    rx_bytes: int
    tx_bytes: int

class ToolInfo(TypedDict):
    """工具信息数据结构"""
    name: str
    description: str
    parameters: List[Dict[str, Any]]

# ======================
# 工具枚举
# ======================
class ServerTools(str, Enum):
    """服务器工具枚举"""
    MEMORY_INFO = "get_memory_info"
    REMOTE_INSPECTION = "remote_server_inspection"
    SSH_RISK_CHECK = "check_ssh_risk_logins"
    FIREWALL_CHECK = "check_firewall_config"
    OS_DETAILS = "get_os_details"
    SYSTEM_LOAD = "get_system_load"  # 获取系统负载
    LIST_TOOLS = "list_available_tools"  # 列出可用工具
    PROCESS_MONITOR = "monitor_processes"  # 进程监控
    SERVICE_STATUS = "check_service_status"  # 服务状态检查
    NETWORK_INSPECTION = "inspect_network"  # 网络检查
    LOG_ANALYZER = "analyze_logs"  # 日志分析
    FILE_BACKUP = "backup_critical_files"  # 关键文件备份
    SECURITY_SCAN = "security_vulnerability_scan"  # 安全漏洞扫描
    # 新增网络设备工具
    DEVICE_IDENTIFY = "identify_network_device"  # 识别网络设备类型
    SWITCH_PORT_STATUS = "check_switch_ports"  # 检查交换机端口状态
    ROUTER_ROUTING_TABLE = "check_router_routes"  # 检查路由表
    DEVICE_CONFIG_BACKUP = "backup_network_config"  # 备份网络设备配置
    ACL_CHECK = "check_acl_config"  # 检查ACL安全配置
    VLAN_INSPECTION = "inspect_vlans"  # 检查VLAN配置

class DeviceType(str, Enum):
    """网络设备类型枚举"""
    CISCO_IOS = "cisco_ios"
    CISCO_NXOS = "cisco_nxos"
    HUAWEI = "huawei"
    H3C = "h3c"
    ARISTA = "arista"
    JUNIPER = "juniper"
    FORTINET = "fortinet"
    PALO_ALTO = "palo_alto"
    CHECKPOINT = "checkpoint"
    UNKNOWN = "unknown"

class SwitchPortInfo(TypedDict):
    """交换机端口信息数据结构"""
    name: str
    status: str
    vlan: str
    duplex: str
    speed: str
    description: str

class RouteInfo(TypedDict):
    """路由信息数据结构"""
    destination: str
    mask: str
    next_hop: str
    interface: str
    protocol: str
    metric: int

class ACLInfo(TypedDict):
    """ACL配置信息数据结构"""
    name: str
    type: str
    rules: List[str]
    interfaces: List[str]

class VLANInfo(TypedDict):
    """VLAN信息数据结构"""
    id: str
    name: str
    status: str
    ports: List[str]

# ======================
# 核心工具类
# ======================
class SSHManager:
    """SSH连接管理器（上下文管理器）"""
    def __init__(
        self,
        hostname: str,
        username: str,
        password: str = "",
        port: int = 22,
        timeout: int = 30
    ):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.connect_params = {
            "hostname": hostname,
            "username": username,
            "password": password,
            "port": port,
            "timeout": timeout
        }

    def __enter__(self) -> paramiko.SSHClient:
        self.client.connect(**self.connect_params)
        return self.client

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.close()

class NetworkDeviceManager:
    """网络设备连接管理器"""
    def __init__(
        self,
        hostname: str, 
        username: str,
        password: str = "",
        port: int = 22,
        device_type: DeviceType = DeviceType.UNKNOWN,
        timeout: int = 30
    ):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.device_type = device_type
        self.timeout = timeout
        self.shell = None
        self.connected = False
        self.prompt = ""
    
    def connect(self) -> bool:
        """连接到网络设备"""
        try:
            self.ssh.connect(
                hostname=self.hostname,
                username=self.username,
                password=self.password,
                port=self.port,
                timeout=self.timeout
            )
            self.shell = self.ssh.invoke_shell()
            self.shell.settimeout(self.timeout)
            
            # 等待初始提示符
            output = self._read_until_prompt()
            self.connected = True
            return True
        except Exception as e:
            print(f"连接错误: {str(e)}")
            self.connected = False
            return False
    
    def close(self) -> None:
        """关闭连接"""
        if self.shell:
            self.shell.close()
        if self.ssh:
            self.ssh.close()
        self.connected = False
    
    def _read_until_prompt(self, timeout: int = None) -> str:
        """读取直到发现提示符为止"""
        timeout = timeout or self.timeout
        buffer = ""
        start_time = datetime.datetime.now()
        
        while True:
            if (datetime.datetime.now() - start_time).total_seconds() > timeout:
                raise TimeoutError("读取设备输出超时")
            
            if self.shell.recv_ready():
                chunk = self.shell.recv(1024).decode('utf-8', errors='ignore')
                buffer += chunk
                
                # 检测常见提示符
                prompt_patterns = [
                    r"[\r\n](\S+)[#>]\s*$",           # 思科类设备
                    r"[\r\n]<(\S+)>\s*$",             # 华为类设备
                    r"[\r\n]\[(\S+)\]>\s*$",          # Juniper类设备
                    r"[\r\n](\S+)@(\S+):~[$#]\s*$"    # Linux/FortiGate类设备
                ]
                
                for pattern in prompt_patterns:
                    match = re.search(pattern, buffer)
                    if match:
                        self.prompt = match.group(0).strip()
                        return buffer
            
    def send_command(self, command: str, timeout: int = None) -> str:
        """发送命令并返回结果"""
        if not self.connected or not self.shell:
            raise ConnectionError("设备未连接")
        
        # 发送命令
        self.shell.send(command + "\n")
        # 读取输出直到提示符
        output = self._read_until_prompt(timeout)
        
        # 清理输出（移除命令回显和提示符）
        lines = output.splitlines()
        if len(lines) > 1:
            # 跳过第一行（命令回显）并忽略最后一行（提示符）
            return "\n".join(lines[1:-1])
        return ""
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    @staticmethod
    def identify_device_type(output: str) -> DeviceType:
        """根据版本信息识别设备类型"""
        output = output.lower()
        
        if "cisco ios" in output:
            return DeviceType.CISCO_IOS
        elif "cisco nexus" in output or "nx-os" in output:
            return DeviceType.CISCO_NXOS
        elif "huawei" in output or "vrp" in output:
            return DeviceType.HUAWEI
        elif "h3c" in output or "comware" in output:
            return DeviceType.H3C
        elif "arista" in output or "eos" in output:
            return DeviceType.ARISTA
        elif "juniper" in output or "junos" in output:
            return DeviceType.JUNIPER
        elif "fortinet" in output or "fortigate" in output:
            return DeviceType.FORTINET
        elif "palo alto" in output or "pan-os" in output:
            return DeviceType.PALO_ALTO
        elif "checkpoint" in output or "gaia" in output:
            return DeviceType.CHECKPOINT
        else:
            return DeviceType.UNKNOWN

class NetworkInspector:
    """网络设备指标解析器"""
    
    @staticmethod
    def parse_device_info(device_type: DeviceType, raw_output: str) -> dict:
        """解析设备信息"""
        info = {
            "device_type": device_type,
            "model": "Unknown",
            "serial": "Unknown",
            "version": "Unknown",
            "uptime": "Unknown"
        }
        
        if device_type == DeviceType.CISCO_IOS or device_type == DeviceType.CISCO_NXOS:
            # 解析思科设备信息
            model_match = re.search(r"[Mm]odel\s+[Nn]umber\s*:\s*(\S+)", raw_output)
            if model_match:
                info["model"] = model_match.group(1)
                
            serial_match = re.search(r"[Ss]erial\s+[Nn]umber\s*:\s*(\S+)", raw_output)
            if serial_match:
                info["serial"] = serial_match.group(1)
                
            version_match = re.search(r"[Vv]ersion\s+(\S+)", raw_output)
            if version_match:
                info["version"] = version_match.group(1)
                
            uptime_match = re.search(r"uptime is\s+(.+)", raw_output)
            if uptime_match:
                info["uptime"] = uptime_match.group(1).strip()
        
        elif device_type == DeviceType.HUAWEI or device_type == DeviceType.H3C:
            # 解析华为/H3C设备信息
            version_match = re.search(r"(VRP|COMWARE) Software, Version (.+?),", raw_output)
            if version_match:
                info["version"] = version_match.group(2)
                
            model_match = re.search(r"(HUAWEI|H3C)\s+(\S+)\s+uptime", raw_output, re.IGNORECASE)
            if model_match:
                info["model"] = model_match.group(2)
                
            uptime_match = re.search(r"uptime is\s+(.+)", raw_output)
            if uptime_match:
                info["uptime"] = uptime_match.group(1).strip()
        
        return info
    
    @staticmethod
    def parse_switch_ports(device_type: DeviceType, raw_output: str) -> list[SwitchPortInfo]:
        """解析交换机端口信息"""
        ports = []
        
        if device_type == DeviceType.CISCO_IOS or device_type == DeviceType.CISCO_NXOS:
            # 解析思科交换机端口
            for line in raw_output.splitlines():
                if line.strip() and not line.startswith("Port"):
                    parts = line.split()
                    if len(parts) >= 6:
                        ports.append({
                            "name": parts[0],
                            "status": parts[1],
                            "vlan": parts[2],
                            "duplex": parts[3],
                            "speed": parts[4],
                            "description": " ".join(parts[5:]) if len(parts) > 5 else ""
                        })
        
        elif device_type == DeviceType.HUAWEI:
            # 解析华为交换机端口
            for line in raw_output.splitlines():
                if line.strip() and not line.startswith("Interface"):
                    parts = line.split()
                    if len(parts) >= 4:
                        ports.append({
                            "name": parts[0],
                            "status": parts[2],
                            "vlan": "N/A",  # 华为需要单独命令获取VLAN
                            "duplex": parts[3] if len(parts) > 3 else "N/A",
                            "speed": parts[4] if len(parts) > 4 else "N/A",
                            "description": " ".join(parts[5:]) if len(parts) > 5 else ""
                        })
        
        return ports
    
    @staticmethod
    def parse_routes(device_type: DeviceType, raw_output: str) -> list[RouteInfo]:
        """解析路由表信息"""
        routes = []
        
        if device_type == DeviceType.CISCO_IOS:
            # 解析思科IOS路由表
            for line in raw_output.splitlines():
                if "via" in line:
                    parts = line.split()
                    if len(parts) >= 6:
                        routes.append({
                            "destination": parts[1],
                            "mask": parts[2].strip("[]"),
                            "next_hop": parts[4],
                            "interface": parts[-1],
                            "protocol": parts[0],
                            "metric": int(parts[5].strip(",")) if parts[5].strip(",").isdigit() else 0
                        })
        
        elif device_type == DeviceType.HUAWEI:
            # 解析华为路由表
            for line in raw_output.splitlines():
                if not line.startswith("Destination") and line.strip():
                    parts = line.split()
                    if len(parts) >= 7:
                        routes.append({
                            "destination": parts[0],
                            "mask": parts[1],
                            "next_hop": parts[3],
                            "interface": parts[5],
                            "protocol": parts[2],
                            "metric": int(parts[4]) if parts[4].isdigit() else 0
                        })
        
        return routes
    
    @staticmethod
    def parse_acls(device_type: DeviceType, raw_output: str) -> list[ACLInfo]:
        """解析ACL配置信息"""
        acls = []
        
        if device_type == DeviceType.CISCO_IOS:
            current_acl = None
            current_rules = []
            
            for line in raw_output.splitlines():
                if line.startswith("Extended IP access list") or line.startswith("Standard IP access list"):
                    if current_acl:
                        acls.append({
                            "name": current_acl,
                            "type": "extended" if "Extended" in current_acl else "standard",
                            "rules": current_rules,
                            "interfaces": []
                        })
                    
                    current_acl = line.split("list")[1].strip()
                    current_rules = []
                elif current_acl and line.strip():
                    current_rules.append(line.strip())
            
            if current_acl:
                acls.append({
                    "name": current_acl,
                    "type": "extended" if "Extended" in current_acl else "standard",
                    "rules": current_rules,
                    "interfaces": []
                })
        
        elif device_type == DeviceType.HUAWEI:
            # 解析华为ACL配置
            current_acl = None
            current_type = None
            current_rules = []
            
            for line in raw_output.splitlines():
                if "acl" in line.lower() and "currenttype" not in line.lower():
                    if current_acl:
                        acls.append({
                            "name": current_acl,
                            "type": current_type or "unknown",
                            "rules": current_rules,
                            "interfaces": []
                        })
                    
                    acl_match = re.search(r"ACL (\d+|[a-zA-Z0-9_-]+)", line, re.IGNORECASE)
                    if acl_match:
                        current_acl = acl_match.group(1)
                        current_rules = []
                        
                        if "basic" in line.lower():
                            current_type = "basic"
                        elif "advanced" in line.lower():
                            current_type = "advanced"
                        else:
                            current_type = "unknown"
                
                elif current_acl and "rule" in line.lower():
                    current_rules.append(line.strip())
            
            if current_acl:
                acls.append({
                    "name": current_acl,
                    "type": current_type or "unknown",
                    "rules": current_rules,
                    "interfaces": []
                })
        
        return acls
    
    @staticmethod
    def parse_vlans(device_type: DeviceType, raw_output: str) -> list[VLANInfo]:
        """解析VLAN配置信息"""
        vlans = []
        
        if device_type == DeviceType.CISCO_IOS:
            current_vlan = None
            current_name = ""
            current_status = ""
            current_ports = []
            
            for line in raw_output.splitlines():
                vlan_match = re.match(r"^(\d+)\s+(\S+)\s+(\S+)", line)
                if vlan_match:
                    if current_vlan:
                        vlans.append({
                            "id": current_vlan,
                            "name": current_name,
                            "status": current_status,
                            "ports": current_ports
                        })
                    
                    current_vlan = vlan_match.group(1)
                    current_name = vlan_match.group(2)
                    current_status = vlan_match.group(3)
                    current_ports = []
                
                elif current_vlan and line.strip() and "VLAN Type" not in line:
                    ports_line = line.strip()
                    if ports_line:
                        current_ports.extend(ports_line.split(", "))
            
            if current_vlan:
                vlans.append({
                    "id": current_vlan,
                    "name": current_name,
                    "status": current_status,
                    "ports": current_ports
                })
        
        elif device_type == DeviceType.HUAWEI:
            for line in raw_output.splitlines():
                if not line.startswith("VLAN") and line.strip():
                    parts = line.split()
                    if len(parts) >= 3 and parts[0].isdigit():
                        vlans.append({
                            "id": parts[0],
                            "name": parts[1],
                            "status": parts[2],
                            "ports": []  # 华为需要单独命令获取端口
                        })
        
        return vlans

class ServerInspector:
    """服务器指标解析器"""
    
    @staticmethod
    def parse_cpu(raw_output: str) -> CPUStats:
        """解析CPU使用率和负载"""
        cpu_usage = re.search(r'(\d+\.\d+)%? id', raw_output)
        load_avg = re.search(r'load average: ([\d\.]+), ([\d\.]+), ([\d\.]+)', raw_output)
        return {
            "usage": 100 - float(cpu_usage.group(1)) if cpu_usage else None,
            "loadavg": ", ".join(load_avg.groups()) if load_avg else None
        }

    @staticmethod
    def parse_memory(raw_output: str) -> ServerMetric:
        """解析内存使用情况"""
        mem_lines = [line.split() for line in raw_output.split('\n') if line]
        total = int(mem_lines[1][1]) / 1024  # 转换为GB
        used = (int(mem_lines[1][2] ) - int(mem_lines[1][5])) / 1024
        return ServerMetric(
            total=round(total, 2),
            used=round(used, 2),
            free=round(total - used, 2),
            usage=round(used / total * 100, 1)
        )

    @staticmethod
    def parse_disk(raw_output: str) -> list[DiskInfo]:
        """解析磁盘使用情况"""
        disks = []
        for line in raw_output.split('\n')[1:]:  # 跳过标题行
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 5:
                disks.append({
                    "mount_point": parts[5],
                    "total": parts[1],
                    "used": parts[2],
                    "usage": float(parts[4].replace('%', ''))
                })
        return disks

    @staticmethod
    def parse_auth_log(raw_log: str) -> tuple[dict[str, int], list[LoginRecord]]:
        """解析SSH认证日志"""
        failed_logins = {}
        success_logins = []

        for line in raw_log.split('\n'):
            # 解析失败登录
            if "Failed password" in line:
                ip = line.split()[-4] if "invalid user" not in line else line.split()[-6]
                failed_logins[ip] = failed_logins.get(ip, 0) + 1
            
            # 解析成功登录
            if "Accepted password" in line:
                parts = line.split()
                success_logins.append({
                    "time": f"{parts[0]} {parts[1]} {parts[2]}",
                    "user": parts[8] if "invalid user" not in line else parts[10],
                    "ip": parts[-4] if "port" not in line else parts[-6]
                })
        
        return failed_logins, success_logins[-10:]  # 返回最近10条成功登录

    @staticmethod
    def parse_processes(raw_output: str) -> list[ProcessInfo]:
        """解析进程信息"""
        processes = []
        lines = raw_output.strip().split('\n')
        
        # 跳过标题行
        for line in lines[1:]:
            if not line:
                continue
                
            parts = line.split()
            if len(parts) >= 11:
                try:
                    processes.append({
                        "pid": int(parts[1]),
                        "user": parts[0],
                        "cpu_percent": float(parts[8]),
                        "memory_percent": float(parts[9]),
                        "status": parts[7],
                        "created": parts[4],
                        "name": ' '.join(parts[11:]) if len(parts) > 11 else parts[11]
                    })
                except (ValueError, IndexError):
                    continue
                    
        return processes

    @staticmethod
    def parse_services(raw_output: str) -> list[ServiceStatus]:
        """解析服务状态"""
        services = []
        for line in raw_output.strip().split('\n'):
            if not line or "UNIT" in line or "LOAD" in line:
                continue
                
            parts = line.split()
            if len(parts) >= 3:
                services.append({
                    "name": parts[0],
                    "status": parts[3] if len(parts) > 3 else "未知",
                    "active": "active" in line.lower(),
                    "enabled": "enabled" in line.lower()
                })
        return services

    @staticmethod
    def parse_network_interfaces(raw_output: str) -> list[NetworkInterface]:
        """解析网络接口信息"""
        interfaces = []
        current_interface = None
        
        for line in raw_output.strip().split('\n'):
            if not line:
                continue
                
            # 新接口开始
            if not line.startswith(' ') and ':' in line:
                name = line.split(':')[0]
                current_interface = {
                    "name": name,
                    "ip_address": "",
                    "mac_address": "",
                    "status": "DOWN" if "DOWN" in line else "UP" if "UP" in line else "UNKNOWN",
                    "rx_bytes": 0,
                    "tx_bytes": 0
                }
                interfaces.append(current_interface)
            
            # IP地址
            elif "inet " in line and current_interface:
                current_interface["ip_address"] = line.split()[1].split('/')[0]
            
            # MAC地址
            elif "ether " in line and current_interface:
                current_interface["mac_address"] = line.split()[1]
            
            # 接收字节
            elif "RX packets" in line and current_interface:
                rx_line = next((l for l in raw_output.strip().split('\n') if "RX bytes" in l), "")
                if rx_line:
                    try:
                        current_interface["rx_bytes"] = int(rx_line.split('bytes')[1].split()[0])
                    except (ValueError, IndexError):
                        pass
            
            # 发送字节
            elif "TX packets" in line and current_interface:
                tx_line = next((l for l in raw_output.strip().split('\n') if "TX bytes" in l), "")
                if tx_line:
                    try:
                        current_interface["tx_bytes"] = int(tx_line.split('bytes')[1].split()[0])
                    except (ValueError, IndexError):
                        pass
                        
        return interfaces

# ======================
# MCP服务初始化
# ======================
mcp = FastMCP("ServerMonitor")

# ======================
# 工具函数
# ======================
@mcp.tool()
def get_memory_info() -> dict:
    """获取本地服务器内存信息"""
    mem = psutil.virtual_memory()
    return {
        "total": mem.total, 
        "used": mem.used,
        "free": mem.free,
        "usage": mem.percent
    }

@mcp.tool()
def remote_server_inspection(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    inspection_modules: list[str] = ["cpu", "memory", "disk"],
    timeout: int = 30
) -> InspectionResult:
    """执行远程服务器巡检"""
    result = InspectionResult()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            commands = {
                "cpu": "top -bn1 | grep 'Cpu(s)' && uptime",
                "memory": "free -m",
                "disk": "df -h"
            }

            for module in inspection_modules:
                if module not in commands:
                    continue
                
                # 执行命令
                stdin, stdout, stderr = ssh.exec_command(commands[module], timeout=timeout)
                raw_output = stdout.read().decode().strip()
                result.raw_outputs[module] = raw_output

                # 解析结果
                match module:
                    case "cpu":
                        result.data[module] = ServerInspector.parse_cpu(raw_output)
                    case "memory":
                        result.data[module] = ServerInspector.parse_memory(raw_output).dict()
                    case "disk":
                        result.data[module] = ServerInspector.parse_disk(raw_output)
            
            result.status = "success"
            result.summary = "服务器巡检成功"

    except paramiko.AuthenticationException:
        result.status = "error"
        result.error = "SSH认证失败"
        result.summary = "SSH认证失败"
    except Exception as e:
        result.status = "error"
        result.error = f"巡检失败: {str(e)}"
        result.summary = "巡检失败"
    
    return result.dict()

@mcp.tool()
def get_system_load(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    timeout: int = 30
) -> dict:
    """获取系统负载信息"""
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            stdin, stdout, stderr = ssh.exec_command("uptime")
            load_output = stdout.read().decode().strip()
            load_avg = re.search(r'load average: (.*)', load_output)
            return {"load_average": load_avg.group(1) if load_avg else "unknown"}
    except Exception as e:
        return {"error": str(e)}

# ======================
# 新增工具函数
# ======================
@mcp.tool()
def list_available_tools() -> list[ToolInfo]:
    """列出所有可用的工具及其描述"""
    tools = []
    
    # 获取所有被装饰为工具的函数
    for tool_name in dir(mcp.tool):
        if tool_name.startswith("__"):  # 跳过内部属性
            continue
            
        tool_func = getattr(mcp.tool, tool_name, None)
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
        ]},
        # 添加网络设备相关工具
        {"name": "identify_network_device", "description": "识别网络设备类型和基本信息", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "check_switch_ports", "description": "检查交换机端口状态", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "include_interfaces", "type": "list[str]", "default": []},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "check_router_routes", "description": "检查路由器路由表", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "route_type", "type": "str", "default": "all"},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "backup_network_config", "description": "备份网络设备配置", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "backup_dir", "type": "str", "default": "/tmp/network_config_backup"},
            {"name": "timeout", "type": "int", "default": 60}
        ]},
        {"name": "check_acl_config", "description": "检查安全ACL配置", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "acl_name", "type": "str", "default": ""},
            {"name": "timeout", "type": "int", "default": 30}
        ]},
        {"name": "inspect_vlans", "description": "检查交换机VLAN配置", "parameters": [
            {"name": "hostname", "type": "str", "default": None},
            {"name": "username", "type": "str", "default": None},
            {"name": "password", "type": "str", "default": ""},
            {"name": "port", "type": "int", "default": 22},
            {"name": "vlan_id", "type": "str", "default": ""},
            {"name": "timeout", "type": "int", "default": 30}
        ]}
    ]
    
    # 如果自动检测的工具不足，则使用手动定义的工具列表
    if len(tools) < len(tool_descriptions):
        return tool_descriptions
    
    return tools

@mcp.tool()
def monitor_processes(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    top_n: int = 10,
    sort_by: str = "cpu",
    timeout: int = 30
) -> dict:
    """监控远程服务器进程，返回占用资源最多的进程"""
    result = {"status": "unknown", "processes": [], "error": ""}
    
    sort_options = {
        "cpu": "-pcpu",
        "memory": "-pmem",
        "time": "-time"
    }
    
    sort_param = sort_options.get(sort_by, "-pcpu")
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 使用ps命令获取进程信息，并按指定条件排序
            command = f"ps aux --sort={sort_param} | head -n {top_n + 1}"  # +1 是为了包含标题行
            stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
            raw_output = stdout.read().decode().strip()
            
            # 解析进程信息
            result["processes"] = ServerInspector.parse_processes(raw_output)
            result["status"] = "success"
            
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

@mcp.tool()
def check_service_status(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    services: list[str] = [],
    timeout: int = 30
) -> dict:
    """检查指定服务的运行状态"""
    result = {"status": "unknown", "services": [], "error": ""}
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            if services:
                # 检查特定服务
                service_statuses = []
                for service in services:
                    command = f"systemctl status {service}"
                    stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
                    output = stdout.read().decode().strip()
                    
                    # 分析输出判断服务状态
                    service_status = {
                        "name": service,
                        "status": "unknown",
                        "active": False,
                        "enabled": False
                    }
                    
                    if "Active: active" in output:
                        service_status["status"] = "running"
                        service_status["active"] = True
                    elif "Active: inactive" in output:
                        service_status["status"] = "stopped"
                    elif "not-found" in output or "could not be found" in output:
                        service_status["status"] = "not found"
                    
                    # 检查是否开机启动
                    enabled_command = f"systemctl is-enabled {service}"
                    stdin, stdout, stderr = ssh.exec_command(enabled_command, timeout=timeout)
                    enabled_output = stdout.read().decode().strip()
                    service_status["enabled"] = enabled_output == "enabled"
                    
                    service_statuses.append(service_status)
                
                result["services"] = service_statuses
            else:
                # 列出所有活跃的服务
                command = "systemctl list-units --type=service --state=running"
                stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
                raw_output = stdout.read().decode().strip()
                
                # 解析服务状态
                result["services"] = ServerInspector.parse_services(raw_output)
            
            result["status"] = "success"
            
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

@mcp.tool()
def inspect_network(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    timeout: int = 30
) -> dict:
    """检查网络接口和连接状态"""
    result = {"status": "unknown", "interfaces": [], "connections": {}, "error": ""}
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 获取网络接口信息
            interfaces_command = "ip a"
            stdin, stdout, stderr = ssh.exec_command(interfaces_command, timeout=timeout)
            interfaces_output = stdout.read().decode().strip()
            
            # 解析网络接口信息
            result["interfaces"] = ServerInspector.parse_network_interfaces(interfaces_output)
            
            # 获取网络连接信息
            connections_command = "ss -tuln"
            stdin, stdout, stderr = ssh.exec_command(connections_command, timeout=timeout)
            connections_output = stdout.read().decode().strip()
            
            # 解析监听端口
            listening_ports = []
            for line in connections_output.split('\n')[1:]:  # 跳过标题行
                if "LISTEN" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        address_port = parts[4]
                        if ":" in address_port:
                            port = address_port.split(":")[-1]
                            listening_ports.append(port)
            
            result["connections"]["listening_ports"] = listening_ports
            
            # 检查是否可以连接公网
            internet_check = ssh.exec_command("ping -c 1 -W 2 8.8.8.8", timeout=timeout)
            internet_output = internet_check[1].read().decode().strip()
            result["connections"]["internet_connectivity"] = "1 received" in internet_output
            
            result["status"] = "success"
            
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

@mcp.tool()
def analyze_logs(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    log_file: str = "/var/log/syslog",
    pattern: str = "error|fail|critical",
    lines: int = 100,
    timeout: int = 30
) -> dict:
    """分析服务器日志文件中的错误和警告"""
    result = {"status": "unknown", "entries": [], "summary": {}, "error": ""}
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 获取日志的最后几行
            tail_command = f"tail -n {lines} {log_file}"
            stdin, stdout, stderr = ssh.exec_command(tail_command, timeout=timeout)
            log_output = stdout.read().decode().strip()
            
            if not log_output:
                result["error"] = f"无法读取日志文件 {log_file}"
                result["status"] = "error"
                return result
            
            # 搜索匹配的日志条目
            grep_command = f"grep -E '{pattern}' <<< '{log_output}'"
            stdin, stdout, stderr = ssh.exec_command(grep_command, timeout=timeout)
            matched_output = stdout.read().decode().strip()
            
            # 解析匹配的日志条目
            entries = []
            pattern_counts = {"error": 0, "warning": 0, "critical": 0, "fail": 0, "other": 0}
            
            for line in matched_output.split('\n'):
                if not line:
                    continue
                
                # 尝试提取时间戳
                timestamp = ""
                try:
                    # 假设日志的前部分是时间戳
                    timestamp_part = ' '.join(line.split()[:3])
                    timestamp = timestamp_part
                except:
                    pass
                
                # 确定日志级别
                level = "other"
                line_lower = line.lower()
                if "critical" in line_lower:
                    level = "critical"
                    pattern_counts["critical"] += 1
                elif "error" in line_lower:
                    level = "error"
                    pattern_counts["error"] += 1
                elif "warning" in line_lower or "warn" in line_lower:
                    level = "warning"
                    pattern_counts["warning"] += 1
                elif "fail" in line_lower:
                    level = "fail"
                    pattern_counts["fail"] += 1
                else:
                    pattern_counts["other"] += 1
                
                entries.append({
                    "timestamp": timestamp,
                    "level": level,
                    "message": line
                })
            
            result["entries"] = entries
            result["summary"] = {
                "total_entries": len(entries),
                "counts_by_level": pattern_counts
            }
            
            result["status"] = "success"
            
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

@mcp.tool()
def backup_critical_files(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    files: list[str] = ["/etc/passwd", "/etc/shadow", "/etc/fstab", "/etc/hosts"],
    backup_dir: str = "/tmp/backup",
    timeout: int = 60
) -> dict:
    """备份重要系统配置文件"""
    result = {"status": "unknown", "backups": [], "error": ""}
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 创建备份目录
            mkdir_command = f"mkdir -p {backup_dir}"
            stdin, stdout, stderr = ssh.exec_command(mkdir_command, timeout=timeout)
            
            # 获取当前时间作为备份标识
            date_command = "date +%Y%m%d_%H%M%S"
            stdin, stdout, stderr = ssh.exec_command(date_command, timeout=timeout)
            date_string = stdout.read().decode().strip()
            
            backups = []
            for file_path in files:
                # 提取文件名
                file_name = file_path.split("/")[-1]
                backup_path = f"{backup_dir}/{file_name}.{date_string}.bak"
                
                # 检查文件是否存在
                check_command = f"[ -f {file_path} ] && echo 'exists' || echo 'not found'"
                stdin, stdout, stderr = ssh.exec_command(check_command, timeout=timeout)
                file_exists = stdout.read().decode().strip() == "exists"
                
                if file_exists:
                    # 复制文件
                    copy_command = f"cp {file_path} {backup_path}"
                    stdin, stdout, stderr = ssh.exec_command(copy_command, timeout=timeout)
                    
                    # 检查备份是否成功
                    check_backup = f"[ -f {backup_path} ] && echo 'success' || echo 'failed'"
                    stdin, stdout, stderr = ssh.exec_command(check_backup, timeout=timeout)
                    backup_status = stdout.read().decode().strip() == "success"
                    
                    backups.append({
                        "original_file": file_path,
                        "backup_file": backup_path,
                        "status": "success" if backup_status else "failed"
                    })
                else:
                    backups.append({
                        "original_file": file_path,
                        "backup_file": "",
                        "status": "file not found"
                    })
            
            result["backups"] = backups
            result["status"] = "success"
            
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

@mcp.tool()
def security_vulnerability_scan(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    scan_type: str = "basic",  # basic, sshd, packages
    timeout: int = 60
) -> dict:
    """执行基础安全漏洞扫描"""
    result = {"status": "unknown", "vulnerabilities": [], "summary": "", "error": ""}
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            vulnerabilities = []
            
            # 基础安全检查
            if scan_type == "basic" or scan_type == "all":
                # 检查密码策略
                passwd_check = "grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE' /etc/login.defs"
                stdin, stdout, stderr = ssh.exec_command(passwd_check, timeout=timeout)
                passwd_policy = stdout.read().decode().strip()
                
                # 检查是否存在空密码账户
                empty_passwd = "grep -E '^[^:]+::' /etc/shadow"
                stdin, stdout, stderr = ssh.exec_command(empty_passwd, timeout=timeout)
                empty_passwd_accounts = stdout.read().decode().strip()
                
                if empty_passwd_accounts:
                    vulnerabilities.append({
                        "type": "security_issue",
                        "level": "critical",
                        "description": "存在空密码账户",
                        "details": empty_passwd_accounts,
                        "recommendation": "为所有账户设置强密码"
                    })
                
                # 检查sudo权限
                sudo_check = "grep -E '^[^#].*ALL=\\(ALL\\)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true"
                stdin, stdout, stderr = ssh.exec_command(sudo_check, timeout=timeout)
                sudo_all = stdout.read().decode().strip()
                
                if sudo_all and "NOPASSWD" in sudo_all:
                    vulnerabilities.append({
                        "type": "security_issue",
                        "level": "high",
                        "description": "存在无需密码的sudo权限",
                        "details": sudo_all,
                        "recommendation": "移除NOPASSWD选项，要求输入密码"
                    })
            
            # SSH配置检查
            if scan_type == "sshd" or scan_type == "all":
                # 检查SSH密码认证是否启用
                sshd_check = "grep -E '^PasswordAuthentication|^PermitRootLogin|^PermitEmptyPasswords|^X11Forwarding' /etc/ssh/sshd_config"
                stdin, stdout, stderr = ssh.exec_command(sshd_check, timeout=timeout)
                sshd_config = stdout.read().decode().strip()
                
                if "PermitRootLogin yes" in sshd_config:
                    vulnerabilities.append({
                        "type": "security_issue",
                        "level": "high",
                        "description": "允许SSH直接登录root账户",
                        "details": "PermitRootLogin yes",
                        "recommendation": "设置 PermitRootLogin no 并使用普通用户登录后切换到root"
                    })
                
                if "PasswordAuthentication yes" in sshd_config:
                    vulnerabilities.append({
                        "type": "security_issue",
                        "level": "medium",
                        "description": "SSH密码认证已启用",
                        "details": "PasswordAuthentication yes",
                        "recommendation": "考虑使用密钥认证替代密码认证"
                    })
                
                if "PermitEmptyPasswords yes" in sshd_config:
                    vulnerabilities.append({
                        "type": "security_issue",
                        "level": "critical",
                        "description": "SSH允许空密码登录",
                        "details": "PermitEmptyPasswords yes",
                        "recommendation": "设置 PermitEmptyPasswords no"
                    })
            
            # 软件包安全检查
            if scan_type == "packages" or scan_type == "all":
                # 检查系统更新状态
                stdin, stdout, stderr = ssh.exec_command("which apt-get && echo found || echo not found", timeout=timeout)
                has_apt = stdout.read().decode().strip() == "found"
                
                stdin, stdout, stderr = ssh.exec_command("which yum && echo found || echo not found", timeout=timeout)
                has_yum = stdout.read().decode().strip() == "found"
                
                if has_apt:
                    # Debian/Ubuntu系统
                    updates_check = "apt-get --simulate upgrade | grep -i 'security'"
                    stdin, stdout, stderr = ssh.exec_command(updates_check, timeout=timeout)
                    security_updates = stdout.read().decode().strip()
                    
                    if security_updates:
                        vulnerabilities.append({
                            "type": "security_issue",
                            "level": "high",
                            "description": "有可用的安全更新未安装",
                            "details": security_updates[:200] + ("..." if len(security_updates) > 200 else ""),
                            "recommendation": "运行 apt-get upgrade 安装更新"
                        })
                
                elif has_yum:
                    # CentOS/RHEL系统
                    updates_check = "yum check-update --security"
                    stdin, stdout, stderr = ssh.exec_command(updates_check, timeout=timeout)
                    security_updates = stdout.read().decode().strip()
                    
                    if "needed for security" in security_updates.lower():
                        vulnerabilities.append({
                            "type": "security_issue",
                            "level": "high",
                            "description": "有可用的安全更新未安装",
                            "details": security_updates[:200] + ("..." if len(security_updates) > 200 else ""),
                            "recommendation": "运行 yum update --security 安装更新"
                        })
            
            # 填充结果
            result["vulnerabilities"] = vulnerabilities
            
            # 生成摘要
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for vuln in vulnerabilities:
                if "level" in vuln and vuln["level"] in severity_counts:
                    severity_counts[vuln["level"]] += 1
            
            total_vulns = sum(severity_counts.values())
            if total_vulns == 0:
                result["summary"] = "未发现安全漏洞。"
            else:
                result["summary"] = f"发现 {total_vulns} 个安全问题: "
                for level, count in severity_counts.items():
                    if count > 0:
                        result["summary"] += f"{count} 个{level}级, "
                result["summary"] = result["summary"].rstrip(", ")
            
            result["status"] = "success"
            
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

@mcp.tool()
def check_ssh_risk_logins(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    log_file: str = "/var/log/auth.log",
    threshold: int = 5,
    timeout: int = 30
) -> dict:
    """检查SSH登录风险，包括失败尝试和可疑IP"""
    result = {"status": "unknown", "suspicious_ips": [], "failed_logins": {}, "success_logins": [], "error": ""}
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 检查日志文件是否存在
            file_check = f"[ -f {log_file} ] && echo 'exists' || echo 'not found'"
            stdin, stdout, stderr = ssh.exec_command(file_check, timeout=timeout)
            file_exists = stdout.read().decode().strip() == "exists"
            
            # 如果主日志不存在，尝试备用日志文件
            if not file_exists:
                alternative_logs = ["/var/log/secure", "/var/log/audit/audit.log"]
                for alt_log in alternative_logs:
                    file_check = f"[ -f {alt_log} ] && echo 'exists' || echo 'not found'"
                    stdin, stdout, stderr = ssh.exec_command(file_check, timeout=timeout)
                    if stdout.read().decode().strip() == "exists":
                        log_file = alt_log
                        file_exists = True
                        break
            
            if not file_exists:
                result["error"] = "找不到SSH日志文件"
                result["status"] = "error"
                return result
            
            # 获取日志内容
            log_command = f"grep 'sshd' {log_file} | tail -n 1000"
            stdin, stdout, stderr = ssh.exec_command(log_command, timeout=timeout)
            log_content = stdout.read().decode().strip()
            
            # 解析日志
            failed_logins, success_logins = ServerInspector.parse_auth_log(log_content)
            
            # 找出超过阈值的可疑IP
            suspicious_ips = [
                {"ip": ip, "attempts": count, "risk_level": "high" if count > threshold * 2 else "medium"}
                for ip, count in failed_logins.items()
                if count >= threshold
            ]
            
            # 按尝试次数排序
            suspicious_ips.sort(key=lambda x: x["attempts"], reverse=True)
            
            result["suspicious_ips"] = suspicious_ips
            result["failed_logins"] = failed_logins
            result["success_logins"] = success_logins
            result["status"] = "success"
            
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

@mcp.tool()
def check_firewall_config(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    timeout: int = 30
) -> dict:
    """检查防火墙配置和开放端口"""
    result = {"status": "unknown", "firewall": {"active": False, "type": "unknown"}, "open_ports": [], "rules": [], "error": ""}
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 检查UFW状态（Ubuntu/Debian）
            ufw_command = "which ufw > /dev/null && ufw status || echo 'ufw not found'"
            stdin, stdout, stderr = ssh.exec_command(ufw_command, timeout=timeout)
            ufw_output = stdout.read().decode().strip()
            
            # 检查firewalld状态（CentOS/RHEL）
            firewalld_command = "which firewall-cmd > /dev/null && firewall-cmd --state || echo 'firewalld not found'"
            stdin, stdout, stderr = ssh.exec_command(firewalld_command, timeout=timeout)
            firewalld_output = stdout.read().decode().strip()
            
            # 检查iptables状态
            iptables_command = "which iptables > /dev/null && iptables -L -n || echo 'iptables not found'"
            stdin, stdout, stderr = ssh.exec_command(iptables_command, timeout=timeout)
            iptables_output = stdout.read().decode().strip()
            
            # 确定防火墙类型和状态
            if "Status: active" in ufw_output:
                result["firewall"]["type"] = "ufw"
                result["firewall"]["active"] = True
                
                # 获取UFW规则
                ufw_rules_command = "ufw status numbered"
                stdin, stdout, stderr = ssh.exec_command(ufw_rules_command, timeout=timeout)
                ufw_rules = stdout.read().decode().strip()
                
                # 解析UFW规则和开放端口
                for line in ufw_rules.split('\n'):
                    if "ALLOW" in line or "DENY" in line:
                        result["rules"].append(line.strip())
                        # 提取端口
                        port_match = re.search(r'(\d+)/tcp', line)
                        if port_match:
                            result["open_ports"].append(port_match.group(1))
                
            elif "running" in firewalld_output:
                result["firewall"]["type"] = "firewalld"
                result["firewall"]["active"] = True
                
                # 获取firewalld区域和规则
                zones_command = "firewall-cmd --list-all-zones"
                stdin, stdout, stderr = ssh.exec_command(zones_command, timeout=timeout)
                zones_output = stdout.read().decode().strip()
                
                # 解析firewalld规则
                current_zone = None
                for line in zones_output.split('\n'):
                    if line.endswith("(active)"):
                        current_zone = line.split()[0]
                    if current_zone and "ports:" in line:
                        ports = line.split("ports:")[1].strip()
                        for port in ports.split():
                            if "/" in port:
                                result["open_ports"].append(port.split("/")[0])
                                result["rules"].append(f"{current_zone} zone: {port}")
            
            elif "Chain INPUT" in iptables_output:
                result["firewall"]["type"] = "iptables"
                result["firewall"]["active"] = True
                
                # 解析iptables规则
                for line in iptables_output.split('\n'):
                    if "ACCEPT" in line and "dpt:" in line:
                        port_match = re.search(r'dpt:(\d+)', line)
                        if port_match:
                            result["open_ports"].append(port_match.group(1))
                            result["rules"].append(line.strip())
            
            else:
                result["firewall"]["type"] = "none"
                result["firewall"]["active"] = False
                result["rules"].append("未检测到活动的防火墙")
            
            # 如果没有检测到防火墙规则，尝试使用netstat或ss检查开放端口
            if not result["open_ports"]:
                ports_command = "ss -tuln || netstat -tuln"
                stdin, stdout, stderr = ssh.exec_command(ports_command, timeout=timeout)
                ports_output = stdout.read().decode().strip()
                
                for line in ports_output.split('\n'):
                    if "LISTEN" in line:
                        port_match = re.search(r':(\d+)', line)
                        if port_match:
                            result["open_ports"].append(port_match.group(1))
            
            # 去重开放端口
            result["open_ports"] = list(set(result["open_ports"]))
            result["status"] = "success"
            
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

@mcp.tool()
def get_os_details(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    timeout: int = 30
) -> dict:
    """获取操作系统详细信息"""
    result = {"status": "unknown", "os_info": {}, "error": ""}
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 收集各种系统信息
            commands = {
                "hostname": "hostname",
                "os_release": "cat /etc/os-release || cat /etc/redhat-release || cat /etc/debian_version || uname -a",
                "kernel": "uname -r",
                "architecture": "uname -m",
                "uptime": "uptime -p",
                "last_boot": "who -b"
            }
            
            os_info = {}
            for key, command in commands.items():
                stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
                output = stdout.read().decode().strip()
                os_info[key] = output
            
            # 解析OS分发版和版本
            distro = "Unknown"
            version = "Unknown"
            
            if "NAME=" in os_info["os_release"]:
                distro_match = re.search(r'NAME="?(.*?)"?', os_info["os_release"], re.MULTILINE)
                if distro_match:
                    distro = distro_match.group(1)
                
                version_match = re.search(r'VERSION="?(.*?)"?', os_info["os_release"], re.MULTILINE)
                if version_match:
                    version = version_match.group(1)
                else:
                    version_id_match = re.search(r'VERSION_ID="?(.*?)"?', os_info["os_release"], re.MULTILINE)
                    if version_id_match:
                        version = version_id_match.group(1)
            
            os_info["distro"] = distro
            os_info["version"] = version
            
            # 检查是否为虚拟机
            vm_check_command = "systemd-detect-virt || dmesg | grep -i virtual || dmidecode | grep -i vmware || dmidecode | grep -i virtualbox || echo 'Unknown'"
            stdin, stdout, stderr = ssh.exec_command(vm_check_command, timeout=timeout)
            vm_output = stdout.read().decode().strip()
            
            os_info["virtualization"] = "Unknown"
            if vm_output != "Unknown":
                for vm_type in ["kvm", "vmware", "virtualbox", "xen", "docker", "lxc", "openvz", "parallels"]:
                    if vm_type.lower() in vm_output.lower():
                        os_info["virtualization"] = vm_type
                        break
            
            result["os_info"] = os_info
            result["status"] = "success"
            
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

if __name__ == "__main__":
    mcp.run(transport='stdio')

@mcp.tool()
def identify_network_device(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    timeout: int = 30
) -> dict:
    """识别网络设备类型和基本信息"""
    result = {"status": "unknown", "device_info": {}, "error": ""}
    
    try:
        # 尝试连接设备
        with NetworkDeviceManager(hostname, username, password, port, timeout=timeout) as device:
            # 尝试发送设备信息命令
            version_commands = [
                "show version",         # 思科、Arista等
                "display version",      # 华为、H3C等
                "get system status",    # FortiGate
                "show system info"      # 其他通用命令
            ]
            
            version_output = ""
            device_type = DeviceType.UNKNOWN
            
            # 尝试不同命令直到成功
            for cmd in version_commands:
                try:
                    output = device.send_command(cmd)
                    if output:
                        version_output = output
                        # 识别设备类型
                        device_type = NetworkDeviceManager.identify_device_type(output)
                        if device_type != DeviceType.UNKNOWN:
                            break
                except:
                    continue
            
            if device_type == DeviceType.UNKNOWN:
                result["error"] = "无法识别设备类型"
                result["status"] = "error"
                return result
            
            # 解析设备信息
            device_info = NetworkInspector.parse_device_info(device_type, version_output)
            device_info["device_type"] = device_type.value
            
            result["device_info"] = device_info
            result["status"] = "success"
            
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

@mcp.tool()
def check_switch_ports(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    include_interfaces: list[str] = [],
    timeout: int = 30
) -> dict:
    """检查交换机端口状态"""
    result = {"status": "unknown", "ports": [], "summary": {}, "error": ""}
    
    try:
        # 连接到设备并识别设备类型
        with NetworkDeviceManager(hostname, username, password, port, timeout=timeout) as device:
            # 首先识别设备类型
            version_command = "show version" if device.device_type == DeviceType.UNKNOWN else "display version"
            version_output = device.send_command(version_command)
            device_type = NetworkDeviceManager.identify_device_type(version_output)
            
            # 根据设备类型选择合适的命令
            if device_type == DeviceType.CISCO_IOS or device_type == DeviceType.CISCO_NXOS:
                port_command = "show interfaces status"
            elif device_type == DeviceType.HUAWEI:
                port_command = "display interface brief"
            else:
                result["error"] = f"不支持的设备类型: {device_type}"
                result["status"] = "error"
                return result
            
            # 获取端口状态
            port_output = device.send_command(port_command)
            
            # 解析端口信息
            ports = NetworkInspector.parse_switch_ports(device_type, port_output)
            
            # 如果指定了特定接口，则过滤结果
            if include_interfaces:
                ports = [p for p in ports if any(interface in p["name"] for interface in include_interfaces)]
            
            # 生成端口状态摘要
            status_counts = {"up": 0, "down": 0, "disabled": 0, "other": 0}
            for port in ports:
                status = port["status"].lower()
                if "up" in status:
                    status_counts["up"] += 1
                elif "down" in status:
                    status_counts["down"] += 1
                elif "disabled" in status or "admin" in status:
                    status_counts["disabled"] += 1
                else:
                    status_counts["other"] += 1
            
            result["ports"] = ports
            result["summary"] = {
                "total_ports": len(ports),
                "status_counts": status_counts
            }
            result["status"] = "success"
            
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

@mcp.tool()
def check_router_routes(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    route_type: str = "all",  # all, static, connected, bgp, ospf
    timeout: int = 30
) -> dict:
    """检查路由器路由表"""
    result = {"status": "unknown", "routes": [], "summary": {}, "error": ""}
    
    try:
        # 连接到设备并识别设备类型
        with NetworkDeviceManager(hostname, username, password, port, timeout=timeout) as device:
            # 首先识别设备类型
            version_command = "show version" if device.device_type == DeviceType.UNKNOWN else "display version"
            version_output = device.send_command(version_command)
            device_type = NetworkDeviceManager.identify_device_type(version_output)
            
            # 根据设备类型和路由类型选择合适的命令
            routes_command = ""
            if device_type == DeviceType.CISCO_IOS or device_type == DeviceType.CISCO_NXOS:
                if route_type == "all":
                    routes_command = "show ip route"
                else:
                    routes_command = f"show ip route {route_type}"
            elif device_type == DeviceType.HUAWEI:
                if route_type == "all":
                    routes_command = "display ip routing-table"
                else:
                    protocol_map = {
                        "static": "static",
                        "connected": "direct",
                        "bgp": "bgp",
                        "ospf": "ospf"
                    }
                    protocol = protocol_map.get(route_type, route_type)
                    routes_command = f"display ip routing-table protocol {protocol}"
            else:
                result["error"] = f"不支持的设备类型: {device_type}"
                result["status"] = "error"
                return result
            
            # 获取路由信息
            routes_output = device.send_command(routes_command)
            
            # 解析路由信息
            routes = NetworkInspector.parse_routes(device_type, routes_output)
            
            # 生成路由表摘要
            protocol_counts = {}
            for route in routes:
                protocol = route["protocol"].lower()
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
            
            result["routes"] = routes
            result["summary"] = {
                "total_routes": len(routes),
                "protocol_counts": protocol_counts
            }
            result["status"] = "success"
            
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

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
    result = {"status": "unknown", "backup_file": "", "config_size": 0, "error": ""}
    
    try:
        # 连接到设备并识别设备类型
        with NetworkDeviceManager(hostname, username, password, port, timeout=timeout) as device:
            # 首先识别设备类型
            version_command = "show version" if device.device_type == DeviceType.UNKNOWN else "display version"
            version_output = device.send_command(version_command)
            device_type = NetworkDeviceManager.identify_device_type(version_output)
            
            # 根据设备类型选择合适的命令
            config_command = ""
            if device_type == DeviceType.CISCO_IOS or device_type == DeviceType.CISCO_NXOS:
                config_command = "show running-config"
            elif device_type == DeviceType.HUAWEI:
                config_command = "display current-configuration"
            elif device_type == DeviceType.FORTINET:
                config_command = "show full-configuration"
            else:
                result["error"] = f"不支持的设备类型: {device_type}"
                result["status"] = "error"
                return result
            
            # 获取配置
            config_output = device.send_command(config_command)
            
            if not config_output:
                result["error"] = "无法获取设备配置"
                result["status"] = "error"
                return result
            
            # 创建备份文件名 (设备类型_主机名_日期时间.cfg)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            hostname_safe = hostname.replace(".", "_")
            backup_filename = f"{device_type.value}_{hostname_safe}_{timestamp}.cfg"
            
            # 创建备份目录
            with SSHManager(hostname, username, password, port, timeout) as ssh:
                # 确保本地备份目录存在
                mkdir_command = f"mkdir -p {backup_dir}"
                ssh.exec_command(mkdir_command)
                
                # 将配置写入文件
                backup_path = f"{backup_dir}/{backup_filename}"
                write_command = f"cat > {backup_path} << 'EOF'\n{config_output}\nEOF"
                stdin, stdout, stderr = ssh.exec_command(write_command)
                
                # 检查文件是否已创建
                check_command = f"ls -la {backup_path}"
                stdin, stdout, stderr = ssh.exec_command(check_command)
                ls_output = stdout.read().decode()
                
                if backup_filename in ls_output:
                    # 获取文件大小
                    size_command = f"stat -c %s {backup_path}"
                    stdin, stdout, stderr = ssh.exec_command(size_command)
                    size_output = stdout.read().decode().strip()
                    config_size = int(size_output) if size_output.isdigit() else 0
                    
                    result["backup_file"] = backup_path
                    result["config_size"] = config_size
                    result["status"] = "success"
                else:
                    result["error"] = "备份文件创建失败"
                    result["status"] = "error"
            
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

@mcp.tool()
def check_acl_config(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    acl_name: str = "",
    timeout: int = 30
) -> dict:
    """检查安全ACL配置"""
    result = {"status": "unknown", "acls": [], "summary": "", "error": ""}
    
    try:
        # 连接到设备并识别设备类型
        with NetworkDeviceManager(hostname, username, password, port, timeout=timeout) as device:
            # 首先识别设备类型
            version_command = "show version" if device.device_type == DeviceType.UNKNOWN else "display version"
            version_output = device.send_command(version_command)
            device_type = NetworkDeviceManager.identify_device_type(version_output)
            
            # 根据设备类型选择合适的命令
            acl_command = ""
            if device_type == DeviceType.CISCO_IOS:
                if acl_name:
                    acl_command = f"show access-lists {acl_name}"
                else:
                    acl_command = "show access-lists"
            elif device_type == DeviceType.HUAWEI:
                if acl_name:
                    acl_command = f"display acl {acl_name}"
                else:
                    acl_command = "display acl all"
            else:
                result["error"] = f"不支持的设备类型: {device_type}"
                result["status"] = "error"
                return result
            
            # 获取ACL配置
            acl_output = device.send_command(acl_command)
            
            # 解析ACL信息
            acls = NetworkInspector.parse_acls(device_type, acl_output)
            
            # 如果有特定ACL名称，过滤结果
            if acl_name:
                acls = [acl for acl in acls if acl_name.lower() in acl["name"].lower()]
            
            # 获取ACL应用情况
            if device_type == DeviceType.CISCO_IOS:
                interface_command = "show running-config | include interface|access-group"
                interface_output = device.send_command(interface_command)
                
                current_interface = None
                for line in interface_output.splitlines():
                    if "interface" in line.lower():
                        current_interface = line.split()[1]
                    elif current_interface and "access-group" in line.lower():
                        parts = line.split()
                        if len(parts) >= 2:
                            acl_name_applied = parts[1]
                            for acl in acls:
                                if acl["name"] == acl_name_applied:
                                    acl["interfaces"].append(current_interface)
            
            # 生成摘要信息
            if acls:
                result["summary"] = f"找到 {len(acls)} 个ACL配置。"
                applied_count = sum(1 for acl in acls if acl["interfaces"])
                result["summary"] += f" {applied_count} 个ACL已应用到接口上。"
            else:
                result["summary"] = "未找到ACL配置。"
            
            result["acls"] = acls
            result["status"] = "success"
            
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

@mcp.tool()
def inspect_vlans(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    vlan_id: str = "",
    timeout: int = 30
) -> dict:
    """检查交换机VLAN配置"""
    result = {"status": "unknown", "vlans": [], "summary": "", "error": ""}
    
    try:
        # 连接到设备并识别设备类型
        with NetworkDeviceManager(hostname, username, password, port, timeout=timeout) as device:
            # 首先识别设备类型
            version_command = "show version" if device.device_type == DeviceType.UNKNOWN else "display version"
            version_output = device.send_command(version_command)
            device_type = NetworkDeviceManager.identify_device_type(version_output)
            
            # 根据设备类型选择合适的命令
            vlan_command = ""
            if device_type == DeviceType.CISCO_IOS:
                if vlan_id:
                    vlan_command = f"show vlan id {vlan_id}"
                else:
                    vlan_command = "show vlan brief"
            elif device_type == DeviceType.HUAWEI:
                if vlan_id:
                    vlan_command = f"display vlan {vlan_id}"
                else:
                    vlan_command = "display vlan"
            else:
                result["error"] = f"不支持的设备类型: {device_type}"
                result["status"] = "error"
                return result
            
            # 获取VLAN信息
            vlan_output = device.send_command(vlan_command)
            
            # 解析VLAN信息
            vlans = NetworkInspector.parse_vlans(device_type, vlan_output)
            
            # 如果有特定VLAN ID，过滤结果
            if vlan_id:
                vlans = [vlan for vlan in vlans if vlan["id"] == vlan_id]
            
            # 生成摘要信息
            if vlans:
                result["summary"] = f"找到 {len(vlans)} 个VLAN。"
                active_count = sum(1 for vlan in vlans if vlan["status"].lower() == "active")
                result["summary"] += f" {active_count} 个VLAN处于活动状态。"
            else:
                result["summary"] = "未找到VLAN配置。"
            
            result["vlans"] = vlans
            result["status"] = "success"
            
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result