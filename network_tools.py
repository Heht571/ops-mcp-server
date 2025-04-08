
from __future__ import annotations
from typing import Optional, Literal, TypedDict, List, Dict, Any, Union, Callable, cast
import re
import paramiko
import logging
import json
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP
from enum import Enum
import datetime

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('network_tools')

# 创建MCP实例
mcp = FastMCP(__name__)

# ======================
# 数据模型定义
# ======================
class InspectionResult(BaseModel):
    """统一巡检结果模型"""
    status: Literal["success", "error", "unknown"] = Field(default="unknown")
    data: dict = Field(default_factory=dict)
    raw_outputs: dict = Field(default_factory=dict)
    error: str = Field(default="")
    summary: Optional[str] = None

class NetworkDevice(TypedDict):
    """网络设备信息数据结构"""
    hostname: str
    device_type: str
    model: str
    os_version: str
    serial_number: str
    uptime: str

class SwitchPort(TypedDict):
    """交换机端口数据结构"""
    interface: str
    status: str
    vlan: str
    duplex: str
    speed: str
    type: str
    description: str

class Route(TypedDict):
    """路由表条目数据结构"""
    destination: str
    mask: str
    gateway: str
    interface: str
    metric: str
    protocol: str

class ACLRule(TypedDict):
    """ACL规则数据结构"""
    rule_id: str
    action: str
    protocol: str
    source: str
    destination: str
    port: str
    description: str

class VLAN(TypedDict):
    """VLAN数据结构"""
    vlan_id: str
    name: str
    status: str
    ports: List[str]

# ======================
# 网络设备类型枚举
# ======================
class NetworkDeviceType(str, Enum):
    """网络设备类型枚举"""
    SWITCH = "switch"
    ROUTER = "router"
    FIREWALL = "firewall"
    LOAD_BALANCER = "load_balancer"
    WIFI_AP = "wifi_ap"
    UNKNOWN = "unknown"

# ======================
# 设备厂商枚举
# ======================
class NetworkVendor(str, Enum):
    """网络设备厂商枚举"""
    CISCO = "cisco"
    HUAWEI = "huawei"
    H3C = "h3c"
    JUNIPER = "juniper"
    ARISTA = "arista"
    FORTINET = "fortinet"
    PALO_ALTO = "palo_alto"
    CHECKPOINT = "checkpoint"
    F5 = "f5"
    RUIJIE = "ruijie"  # 锐捷
    DELL = "dell"
    HPE = "hpe"
    ZYXEL = "zyxel"
    UNKNOWN = "unknown"

# ======================
# 光模块数据结构
# ======================
class OpticalModule(TypedDict):
    """光模块数据结构"""
    port: str
    type: str  # SFP, SFP+, QSFP, QSFP+, etc.
    serial_number: str
    vendor: str
    part_number: str
    wavelength: str  # nm
    distance: str  # m
    temperature: str  # Celsius
    tx_power: str  # dBm
    rx_power: str  # dBm
    status: str  # Normal, Warning, Alarm

# ======================
# 工具枚举
# ======================
class NetworkTools(str, Enum):
    """网络设备工具枚举"""
    IDENTIFY_DEVICE = "identify_network_device"
    CHECK_SWITCH_PORTS = "check_switch_ports"
    CHECK_ROUTER_ROUTES = "check_router_routes"
    BACKUP_CONFIG = "backup_network_config"
    CHECK_ACL = "check_acl_config"
    INSPECT_VLANS = "inspect_vlans"
    CHECK_OPTICAL_MODULES = "check_optical_modules"  # 新增光模块检查工具
    CHECK_DEVICE_PERFORMANCE = "check_device_performance"  # 新增设备性能检查工具

# ======================
# 核心工具类
# ======================
class SSHManager:
    """SSH连接管理器（上下文管理器）"""
    _connection_cache = {}  # 类级别的连接缓存

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str = "",
        port: int = 22,
        timeout: int = 30,
        use_cache: bool = True
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
        self.connection_key = f"{username}@{hostname}:{port}"
        self.use_cache = use_cache
        self.is_new_connection = False

    def __enter__(self) -> paramiko.SSHClient:
        try:
            # 尝试从缓存获取连接
            if self.use_cache and self.connection_key in self._connection_cache:
                cached_client = self._connection_cache[self.connection_key]
                # 检查连接是否仍然有效
                try:
                    cached_client.exec_command("echo 1", timeout=5)
                    logger.debug(f"Using cached SSH connection for {self.connection_key}")
                    self.client = cached_client
                    return self.client
                except Exception:
                    # 连接已失效，从缓存中移除
                    logger.debug(f"Cached connection invalid for {self.connection_key}, creating new one")
                    self._connection_cache.pop(self.connection_key, None)

            # 创建新连接
            logger.debug(f"Creating new SSH connection to {self.connection_key}")
            self.client.connect(**self.connect_params)
            self.is_new_connection = True

            # 添加到缓存
            if self.use_cache:
                self._connection_cache[self.connection_key] = self.client

            return self.client
        except paramiko.AuthenticationException as e:
            logger.error(f"SSH authentication failed for {self.connection_key}: {str(e)}")
            raise
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error for {self.connection_key}: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error connecting to {self.connection_key}: {str(e)}")
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        # 只有新创建的连接且不使用缓存时才关闭
        if not self.use_cache and self.is_new_connection:
            logger.debug(f"Closing SSH connection to {self.connection_key}")
            self.client.close()

    @classmethod
    def clear_cache(cls):
        """清除连接缓存"""
        for client in cls._connection_cache.values():
            try:
                client.close()
            except:
                pass
        cls._connection_cache.clear()
        logger.info("SSH connection cache cleared")

# ======================
# 网络设备解析器
# ======================
class NetworkInspector:
    """网络设备解析器"""
    
    @staticmethod
    def detect_device_type(output: str) -> str:
        """检测网络设备类型"""
        output_lower = output.lower()
        
        # 检测设备类型的规则
        if any(kw in output_lower for kw in ["switch", "catalyst", "nexus", "arista", "3com"]):
            return NetworkDeviceType.SWITCH
        elif any(kw in output_lower for kw in ["router", "gateway", "routing", "ios-xr", "junos"]):
            return NetworkDeviceType.ROUTER
        elif any(kw in output_lower for kw in ["firewall", "palo alto", "fortinet", "checkpoint", "asa"]):
            return NetworkDeviceType.FIREWALL
        elif any(kw in output_lower for kw in ["load balancer", "f5", "netscaler", "haproxy"]):
            return NetworkDeviceType.LOAD_BALANCER
        elif any(kw in output_lower for kw in ["access point", "ap", "wap", "wifi", "wireless"]):
            return NetworkDeviceType.WIFI_AP
        else:
            return NetworkDeviceType.UNKNOWN
    
    @staticmethod
    def detect_vendor(output: str) -> str:
        """检测网络设备厂商"""
        output_lower = output.lower()
        
        # 检测厂商的规则
        if any(kw in output_lower for kw in ["cisco", "catalyst", "nexus", "ios", "ios-xe", "ios-xr", "nx-os"]):
            return NetworkVendor.CISCO
        elif any(kw in output_lower for kw in ["huawei", "vrp", "huaweicloud"]):
            return NetworkVendor.HUAWEI
        elif any(kw in output_lower for kw in ["h3c", "comware"]):
            return NetworkVendor.H3C
        elif any(kw in output_lower for kw in ["juniper", "junos"]):
            return NetworkVendor.JUNIPER
        elif any(kw in output_lower for kw in ["arista", "eos"]):
            return NetworkVendor.ARISTA
        elif any(kw in output_lower for kw in ["fortinet", "fortigate", "fortios"]):
            return NetworkVendor.FORTINET
        elif any(kw in output_lower for kw in ["palo alto", "pan-os"]):
            return NetworkVendor.PALO_ALTO
        elif any(kw in output_lower for kw in ["checkpoint", "gaia"]):
            return NetworkVendor.CHECKPOINT
        elif any(kw in output_lower for kw in ["f5", "big-ip"]):
            return NetworkVendor.F5
        elif any(kw in output_lower for kw in ["ruijie", "锐捷"]):
            return NetworkVendor.RUIJIE
        elif any(kw in output_lower for kw in ["dell", "force10", "powerconnect"]):
            return NetworkVendor.DELL
        elif any(kw in output_lower for kw in ["hpe", "procurve", "aruba"]):
            return NetworkVendor.HPE
        elif any(kw in output_lower for kw in ["zyxel"]):
            return NetworkVendor.ZYXEL
        else:
            return NetworkVendor.UNKNOWN
    
    @staticmethod
    def parse_device_info(output: str) -> NetworkDevice:
        """解析网络设备基本信息"""
        device_info = {
            "hostname": "",
            "device_type": "",
            "model": "",
            "os_version": "",
            "serial_number": "",
            "uptime": ""
        }
        
        # 提取主机名
        hostname_match = re.search(r'hostname[:\s]+([^\s\n]+)', output, re.IGNORECASE)
        if hostname_match:
            device_info["hostname"] = hostname_match.group(1)
        
        # 提取设备型号
        model_patterns = [
            r'model[:\s]+([^\s\n]+)',
            r'model number[:\s]+([^\s\n]+)',
            r'cisco (catalyst \d+|nexus \d+|asr \d+)',
            r'juniper (srx\d+|ex\d+|mx\d+)',
            r'palo alto (pa-\d+)',
            r'fortinet (fortigate-\d+)'
        ]
        
        for pattern in model_patterns:
            model_match = re.search(pattern, output, re.IGNORECASE)
            if model_match:
                device_info["model"] = model_match.group(1)
                break
        
        # 提取操作系统版本
        os_patterns = [
            r'software[:\s]+(version[:\s]+)?([^\s\n,]+)',
            r'version[:\s]+([^\s\n,]+)',
            r'ios version[:\s]+([^\s\n,]+)',
            r'junos[:\s]+([^\s\n,]+)',
            r'fortios[:\s]+([^\s\n,]+)'
        ]
        
        for pattern in os_patterns:
            os_match = re.search(pattern, output, re.IGNORECASE)
            if os_match:
                device_info["os_version"] = os_match.group(1) if os_match.group(2) is None else os_match.group(2)
                break
        
        # 提取序列号
        sn_patterns = [
            r'serial[:\s]+number[:\s]+([^\s\n,]+)',
            r'serial[:\s]+([^\s\n,]+)',
            r'sn[:\s]+([^\s\n,]+)'
        ]
        
        for pattern in sn_patterns:
            sn_match = re.search(pattern, output, re.IGNORECASE)
            if sn_match:
                device_info["serial_number"] = sn_match.group(1)
                break
        
        # 提取运行时间
        uptime_patterns = [
            r'uptime[:\s]+is[:\s]+(.+?)[\n\r]',
            r'uptime[:\s]+(.+?)[\n\r]',
            r'system[:\s]+up[:\s]+time[:\s]+(.+?)[\n\r]'
        ]
        
        for pattern in uptime_patterns:
            uptime_match = re.search(pattern, output, re.IGNORECASE)
            if uptime_match:
                device_info["uptime"] = uptime_match.group(1).strip()
                break
        
        # 设置设备类型
        device_info["device_type"] = NetworkInspector.detect_device_type(output)
        
        # 添加厂商信息
        device_info["vendor"] = NetworkInspector.detect_vendor(output)
        
        return device_info
    
    @staticmethod
    def parse_switch_ports(output: str) -> List[SwitchPort]:
        """解析交换机端口信息"""
        ports = []
        
        # 尝试匹配不同格式的端口信息
        # Cisco/Juniper格式
        port_blocks = re.findall(r'([A-Za-z0-9\/\.-]+)\s+(up|down|notconnect|disabled)\s+([0-9]+|trunk|routed|)\s+(full|half|auto)\s+([0-9]+[GMK]?|auto)\s+([A-Za-z0-9\-\/\.]+)?', output)
        
        for block in port_blocks:
            port = {
                "interface": block[0],
                "status": block[1],
                "vlan": block[2],
                "duplex": block[3],
                "speed": block[4],
                "type": block[5] if len(block) > 5 else "",
                "description": ""
            }
            
            # 尝试匹配端口描述
            desc_match = re.search(rf'{re.escape(block[0])}\s+.*?description\s+([^\n]+)', output)
            if desc_match:
                port["description"] = desc_match.group(1).strip()
            
            ports.append(port)
        
        # 如果没有匹配到标准格式，尝试更宽松的模式
        if not ports:
            lines = output.strip().split('\n')
            current_interface = ""
            
            for line in lines:
                # 尝试匹配接口行
                intf_match = re.match(r'^([A-Za-z0-9\/\.-]+) is (up|down)', line)
                if intf_match:
                    current_interface = intf_match.group(1)
                    status = intf_match.group(2)
                    
                    port = {
                        "interface": current_interface,
                        "status": status,
                        "vlan": "",
                        "duplex": "",
                        "speed": "",
                        "type": "",
                        "description": ""
                    }
                    
                    # 提取更多信息
                    if "duplex" in line.lower():
                        duplex_match = re.search(r'(full|half|auto)[ -]duplex', line, re.IGNORECASE)
                        if duplex_match:
                            port["duplex"] = duplex_match.group(1).lower()
                    
                    if "speed" in line.lower():
                        speed_match = re.search(r'speed (\d+[GMK]?b?|auto)', line, re.IGNORECASE)
                        if speed_match:
                            port["speed"] = speed_match.group(1)
                    
                    # 提取VLAN信息
                    vlan_match = re.search(r'vlan[:\s]+(\d+|trunk)', line, re.IGNORECASE)
                    if vlan_match:
                        port["vlan"] = vlan_match.group(1)
                    
                    ports.append(port)
                
                # 尝试匹配描述行
                elif current_interface and "description" in line.lower():
                    desc_match = re.search(r'description[:\s]+(.+)', line, re.IGNORECASE)
                    if desc_match and ports:
                        for p in ports:
                            if p["interface"] == current_interface:
                                p["description"] = desc_match.group(1).strip()
                                break
        
        return ports
    
    @staticmethod
    def parse_routes(output: str) -> List[Route]:
        """解析路由表信息"""
        routes = []
        
        # 尝试匹配不同格式的路由表条目
        # Cisco格式
        cisco_routes = re.findall(r'([0-9\.]+/[0-9]+|[0-9\.]+)\s+([0-9\.]+|directly)\s+([0-9\.]+)\s+([A-Za-z0-9\/\.-]+)\s+([0-9]+)\s+([A-Z]+)', output)
        
        for route in cisco_routes:
            routes.append({
                "destination": route[0],
                "mask": "",  # 可能包含在目标网络中
                "gateway": route[2],
                "interface": route[3],
                "metric": route[4],
                "protocol": route[5]
            })
        
        # 如果没有匹配到标准格式，尝试更宽松的模式
        if not routes:
            lines = output.strip().split('\n')
            for line in lines:
                # 跳过标题行和空行
                if not line.strip() or "Destination" in line or "Gateway" in line:
                    continue
                
                # 尝试提取路由信息
                parts = line.split()
                if len(parts) >= 4:
                    route = {
                        "destination": parts[0],
                        "mask": parts[1] if len(parts) > 4 else "",
                        "gateway": parts[2] if len(parts) > 4 else parts[1],
                        "interface": parts[-1],
                        "metric": "",
                        "protocol": ""
                    }
                    
                    # 尝试提取协议信息
                    for part in parts:
                        if part.upper() in ["OSPF", "RIP", "BGP", "STATIC", "CONNECTED", "LOCAL"]:
                            route["protocol"] = part.upper()
                            break
                    
                    routes.append(route)
        
        return routes
    
    @staticmethod
    def parse_acl_rules(output: str) -> List[ACLRule]:
        """解析ACL规则信息"""
        rules = []
        
        # 尝试匹配不同格式的ACL规则
        # Cisco格式
        lines = output.strip().split('\n')
        current_acl = ""
        rule_id = 0
        
        for line in lines:
            # 匹配ACL名称
            acl_match = re.match(r'(ip )?access-list (standard|extended) (.+)', line, re.IGNORECASE)
            if acl_match:
                current_acl = acl_match.group(3)
                rule_id = 0
                continue
            
            # 匹配规则行
            if current_acl and re.match(r'^\s*(\d+|permit|deny)', line):
                rule_id += 10
                
                # 提取动作(permit/deny)
                action_match = re.search(r'(permit|deny)', line, re.IGNORECASE)
                action = action_match.group(1) if action_match else "unknown"
                
                # 提取协议
                protocol_match = re.search(r'(permit|deny)\s+(\w+)', line, re.IGNORECASE)
                protocol = protocol_match.group(2) if protocol_match else "any"
                
                # 提取源和目标
                src_dst_match = re.search(r'(permit|deny)\s+\w+\s+([0-9\.]+|any|host [0-9\.]+)(?:\s+(?:[0-9\.]+))?(?:\s+([0-9\.]+|any|host [0-9\.]+))?', line, re.IGNORECASE)
                source = src_dst_match.group(2) if src_dst_match else "any"
                destination = src_dst_match.group(3) if src_dst_match and len(src_dst_match.groups()) > 2 else "any"
                
                # 提取端口
                port_match = re.search(r'eq (\d+|www|ftp|ssh|telnet)', line, re.IGNORECASE)
                port = port_match.group(1) if port_match else "any"
                
                # 提取备注
                remark_match = re.search(r'remark (.+)', line, re.IGNORECASE)
                description = remark_match.group(1) if remark_match else ""
                
                rules.append({
                    "rule_id": str(rule_id),
                    "action": action,
                    "protocol": protocol,
                    "source": source,
                    "destination": destination,
                    "port": port,
                    "description": description
                })
        
        return rules
    
    @staticmethod
    def parse_vlans(output: str) -> List[VLAN]:
        """解析VLAN信息"""
        vlans = []
        
        # 尝试匹配不同格式的VLAN信息
        # Cisco格式
        vlan_blocks = re.findall(r'(\d+)\s+([^\s].*?)\s+(active|inactive|suspended)\s+([^\n]*)', output)
        
        for block in vlan_blocks:
            vlan = {
                "vlan_id": block[0],
                "name": block[1].strip(),
                "status": block[2],
                "ports": []
            }
            
            # 提取端口信息
            ports_str = block[3].strip() if len(block) > 3 else ""
            if ports_str:
                vlan["ports"] = [p.strip() for p in ports_str.split(",")]
            
            vlans.append(vlan)
        
        # 如果没有匹配到标准格式，尝试更宽松的模式
        if not vlans:
            lines = output.strip().split('\n')
            for line in lines:
                # 跳过标题行和空行
                if not line.strip() or "VLAN" in line and "Name" in line:
                    continue
                
                # 尝试提取VLAN信息
                parts = line.split()
                if len(parts) >= 3 and parts[0].isdigit():
                    vlan = {
                        "vlan_id": parts[0],
                        "name": parts[1],
                        "status": parts[2] if len(parts) > 2 else "unknown",
                        "ports": []
                    }
                    
                    # 提取端口信息
                    ports_str = " ".join(parts[3:]) if len(parts) > 3 else ""
                    if ports_str:
                        vlan["ports"] = [p.strip() for p in ports_str.split(",")]
                    
                    vlans.append(vlan)
        
        return vlans

    @staticmethod
    def parse_optical_modules(output: str) -> List[OpticalModule]:
        """解析光模块信息"""
        modules = []
        
        # 尝试匹配多种格式的光模块信息
        # Cisco格式
        cisco_pattern = r'(?P<port>[\w\/]+)\s+(?P<type>[\w\-\/]+)\s+(?P<serial>[\w\-\/]+)\s+(?P<vendor>[\w\-\/\.]+)\s+'
        cisco_sections = re.findall(rf'{cisco_pattern}[\s\S]+?(?=\n\n|\Z)', output)
        
        # Huawei格式
        huawei_pattern = r'(?P<port>[\w\/]+):\s+(?P<vendor>[\w\-\/\.]+)\s+(?P<type>[\w\-\/]+)\s+'
        huawei_sections = re.findall(rf'{huawei_pattern}[\s\S]+?(?=\n\n|\Z)', output)
        
        # 通用格式(尝试提取端口和详细信息区块)
        general_pattern = r'(interface|port)\s+(?P<port>[\w\/]+)[\s\S]+?temperature\s*:\s*(?P<temp>[^\n]+)[\s\S]+?tx\s*power\s*:\s*(?P<tx>[^\n]+)[\s\S]+?rx\s*power\s*:\s*(?P<rx>[^\n]+)'
        general_matches = re.finditer(general_pattern, output, re.IGNORECASE)
        
        # 处理Cisco格式
        for i, section in enumerate(cisco_sections):
            port_match = re.search(r'(?P<port>[\w\/]+)', section)
            type_match = re.search(r'(?P<type>[\w\-\/]+)', section)
            sn_match = re.search(r'(?P<serial>[\w\-\/]+)', section)
            vendor_match = re.search(r'(?P<vendor>[\w\-\/\.]+)', section)
            wavelength_match = re.search(r'wavelength\s*:\s*(?P<wavelength>[\d\.]+)\s*nm', section, re.IGNORECASE)
            distance_match = re.search(r'distance\s*:\s*(?P<distance>[\d\.]+)\s*m', section, re.IGNORECASE)
            temp_match = re.search(r'temperature\s*:\s*(?P<temp>[\d\.\-]+)\s*celsius', section, re.IGNORECASE)
            tx_match = re.search(r'tx\s*power\s*:\s*(?P<tx>[\d\.\-]+)\s*dbm', section, re.IGNORECASE)
            rx_match = re.search(r'rx\s*power\s*:\s*(?P<rx>[\d\.\-]+)\s*dbm', section, re.IGNORECASE)
            
            if port_match:
                module: OpticalModule = {
                    "port": port_match.group("port") if port_match else f"Unknown-{i}",
                    "type": type_match.group("type") if type_match else "Unknown",
                    "serial_number": sn_match.group("serial") if sn_match else "",
                    "vendor": vendor_match.group("vendor") if vendor_match else "",
                    "part_number": "",
                    "wavelength": wavelength_match.group("wavelength") + " nm" if wavelength_match else "",
                    "distance": distance_match.group("distance") + " m" if distance_match else "",
                    "temperature": temp_match.group("temp") + " °C" if temp_match else "",
                    "tx_power": tx_match.group("tx") + " dBm" if tx_match else "",
                    "rx_power": rx_match.group("rx") + " dBm" if rx_match else "",
                    "status": "Normal"
                }
                
                # 根据收发光功率判断状态
                if tx_match and rx_match:
                    try:
                        tx_power = float(tx_match.group("tx"))
                        rx_power = float(rx_match.group("rx"))
                        
                        if tx_power < -10 or rx_power < -15:
                            module["status"] = "Warning"
                        if tx_power < -15 or rx_power < -20:
                            module["status"] = "Alarm"
                    except ValueError:
                        pass
                
                modules.append(module)
        
        # 处理通用格式
        for match in general_matches:
            port = match.group("port")
            temp = match.group("temp")
            tx_power = match.group("tx")
            rx_power = match.group("rx")
            
            # 尝试提取其他信息
            section = match.group(0)
            vendor_match = re.search(r'vendor\s*:\s*(?P<vendor>[^\n]+)', section, re.IGNORECASE)
            type_match = re.search(r'type\s*:\s*(?P<type>[^\n]+)', section, re.IGNORECASE)
            sn_match = re.search(r'serial\s*:\s*(?P<serial>[^\n]+)', section, re.IGNORECASE)
            pn_match = re.search(r'part\s*number\s*:\s*(?P<part>[^\n]+)', section, re.IGNORECASE)
            wavelength_match = re.search(r'wavelength\s*:\s*(?P<wavelength>[^\n]+)', section, re.IGNORECASE)
            
            module: OpticalModule = {
                "port": port,
                "type": type_match.group("type").strip() if type_match else "Unknown",
                "serial_number": sn_match.group("serial").strip() if sn_match else "",
                "vendor": vendor_match.group("vendor").strip() if vendor_match else "",
                "part_number": pn_match.group("part").strip() if pn_match else "",
                "wavelength": wavelength_match.group("wavelength").strip() if wavelength_match else "",
                "distance": "",
                "temperature": temp.strip() if temp else "",
                "tx_power": tx_power.strip() if tx_power else "",
                "rx_power": rx_power.strip() if rx_power else "",
                "status": "Normal"
            }
            
            # 判断状态
            if "tx_power" in module and "rx_power" in module:
                try:
                    tx_value = float(module["tx_power"].split()[0])
                    rx_value = float(module["rx_power"].split()[0])
                    
                    if tx_value < -10 or rx_value < -15:
                        module["status"] = "Warning"
                    if tx_value < -15 or rx_value < -20:
                        module["status"] = "Alarm"
                except (ValueError, IndexError):
                    pass
            
            # 避免重复添加
            if not any(m["port"] == port for m in modules):
                modules.append(module)
        
        return modules

# ======================
# 性能数据结构
# ======================
class DevicePerformance(TypedDict):
    """设备性能数据结构"""
    cpu_usage: str  # CPU使用率
    memory_usage: str  # 内存使用率
    temperature: str  # 温度
    interface_traffic: List[Dict[str, str]]  # 接口流量信息
    buffer_usage: str  # 缓冲区使用率
    process_info: List[Dict[str, str]]  # 关键进程信息

# ======================
# 工具实现
# ======================
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

@mcp.tool()
def check_acl_config(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    acl_name: str = "",  # 指定要检查的ACL名称，为空则检查所有ACL
    timeout: int = 30
) -> dict:
    """检查安全ACL配置"""
    result = InspectionResult()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 执行命令收集ACL信息
            commands = {
                "acl_all": "show access-lists",
                "ip_access": "show ip access-lists"
            }
            
            # 如果指定了特定ACL，添加相应命令
            if acl_name:
                commands[f"acl_{acl_name}"] = f"show access-list {acl_name}"
            
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
            
            # 解析ACL规则
            acl_rules = NetworkInspector.parse_acl_rules(combined_output)
            
            # 统计规则
            permit_rules = len([r for r in acl_rules if r["action"].lower() == "permit"])
            deny_rules = len([r for r in acl_rules if r["action"].lower() == "deny"])
            
            # 设置结果
            result.status = "success"
            result.data = {
                "acl_rules": acl_rules,
                "statistics": {
                    "total": len(acl_rules),
                    "permit": permit_rules,
                    "deny": deny_rules
                }
            }
            result.raw_outputs = outputs
            
            if acl_name:
                result.summary = f"ACL '{acl_name}' 包含 {len(acl_rules)} 条规则（{permit_rules} 条允许，{deny_rules} 条拒绝）"
            else:
                result.summary = f"共 {len(acl_rules)} 条ACL规则（{permit_rules} 条允许，{deny_rules} 条拒绝）"
            
    except Exception as e:
        result.status = "error"
        result.error = f"检查ACL配置失败: {str(e)}"
        logger.error(f"检查ACL配置失败: {str(e)}")
    
    return result.dict()

@mcp.tool()
def inspect_vlans(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    vlan_id: str = "",  # 指定要检查的VLAN ID，为空则检查所有VLAN
    timeout: int = 30
) -> dict:
    """检查交换机VLAN配置"""
    result = InspectionResult()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 执行命令收集VLAN信息
            commands = {
                "vlan_brief": "show vlan brief",
                "vlan_summary": "show vlan summary"
            }
            
            # 如果指定了特定VLAN，添加相应命令
            if vlan_id:
                commands[f"vlan_{vlan_id}"] = f"show vlan id {vlan_id}"
                commands[f"vlan_{vlan_id}_ports"] = f"show vlan id {vlan_id} ports"
            
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
            
            # 解析VLAN信息
            vlans = NetworkInspector.parse_vlans(combined_output)
            
            # 如果指定了特定VLAN，过滤结果
            if vlan_id:
                vlans = [v for v in vlans if v["vlan_id"] == vlan_id]
            
            # 统计VLAN
            active_vlans = len([v for v in vlans if v["status"].lower() == "active"])
            
            # 设置结果
            result.status = "success"
            result.data = {
                "vlans": vlans,
                "statistics": {
                    "total": len(vlans),
                    "active": active_vlans
                }
            }
            result.raw_outputs = outputs
            
            if vlan_id:
                if vlans:
                    ports_count = len(vlans[0]["ports"])
                    result.summary = f"VLAN {vlan_id} 状态为 {vlans[0]['status']}，包含 {ports_count} 个端口"
                else:
                    result.summary = f"未找到VLAN {vlan_id}"
            else:
                result.summary = f"共 {len(vlans)} 个VLAN，{active_vlans} 个活跃"
            
    except Exception as e:
        result.status = "error"
        result.error = f"检查VLAN配置失败: {str(e)}"
        logger.error(f"检查VLAN配置失败: {str(e)}")
    
    return result.dict()

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

if __name__ == "__main__":
    mcp.run(transport='stdio')
