import re
from typing import List
from network_tools.models.base_models import (
    NetworkDevice, SwitchPort, Route, ACLRule, VLAN, 
    OpticalModule, NetworkDeviceType, NetworkVendor,
    LogEntry, LogAnalysisResult
)
from datetime import datetime
import ipaddress

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
        elif any(kw in output_lower for kw in ["zte", "zxr", "zxun", "zxa", "中兴"]):
            return NetworkVendor.ZTE
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

    @staticmethod
    def parse_logs(output: str, vendor: str = "") -> List[LogEntry]:
        """解析网络设备日志"""
        logs = []
        
        # 根据厂商确定日志解析方法
        if not vendor:
            vendor = NetworkInspector.detect_vendor(output)
        
        if vendor == NetworkVendor.CISCO:
            logs = NetworkInspector._parse_cisco_logs(output)
        elif vendor == NetworkVendor.HUAWEI:
            logs = NetworkInspector._parse_huawei_logs(output)
        elif vendor == NetworkVendor.H3C:
            logs = NetworkInspector._parse_h3c_logs(output)
        elif vendor == NetworkVendor.JUNIPER:
            logs = NetworkInspector._parse_juniper_logs(output)
        elif vendor == NetworkVendor.FORTINET:
            logs = NetworkInspector._parse_fortinet_logs(output)
        elif vendor == NetworkVendor.ZTE:
            logs = NetworkInspector._parse_zte_logs(output)
        else:
            # 通用日志解析方法
            logs = NetworkInspector._parse_generic_logs(output)
        
        return logs
    
    @staticmethod
    def _parse_cisco_logs(output: str) -> List[LogEntry]:
        """解析思科设备日志"""
        logs = []
        
        # 思科日志格式: Month Day Year HH:MM:SS timezone: %facility-severity-MNEMONIC: Message
        # 例如: Jun 4 2023 10:15:22 UTC: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (192.168.1.100)
        pattern = r'(\w{3}\s+\d+\s+\d{4}\s+\d{2}:\d{2}:\d{2}).*?%(\w+)-(\d)-(\w+):\s+(.*)'
        
        for line in output.split('\n'):
            if not line.strip():
                continue
                
            match = re.search(pattern, line)
            if match:
                timestamp = match.group(1)
                component = match.group(2)
                log_level = match.group(3)
                event_type = match.group(4)
                message = match.group(5)
                
                log_entry = {
                    "timestamp": timestamp,
                    "log_level": log_level,
                    "component": component,
                    "message": message,
                    "event_type": event_type,
                    "source_ip": None,
                    "username": None,
                    "target": None
                }
                
                # 提取源IP和用户名
                ip_match = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
                if ip_match:
                    log_entry["source_ip"] = ip_match.group(1)
                
                user_match = re.search(r'by\s+(\w+)', message)
                if user_match:
                    log_entry["username"] = user_match.group(1)
                
                logs.append(log_entry)
            else:
                # 尝试匹配其他思科日志格式
                alt_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*?(\w+):\s+(.*)', line)
                if alt_match:
                    logs.append({
                        "timestamp": alt_match.group(1),
                        "log_level": "info",
                        "component": alt_match.group(2),
                        "message": alt_match.group(3),
                        "event_type": "system",
                        "source_ip": None,
                        "username": None,
                        "target": None
                    })
        
        return logs
    
    @staticmethod
    def _parse_huawei_logs(output: str) -> List[LogEntry]:
        """解析华为设备日志"""
        logs = []
        
        # 华为日志格式: YYYY-MM-DD HH:MM:SS-timezone hostname %%modname/level/submodname(slot)[context]:message
        # 例如: 2023-06-04 10:15:22-08:00 HUAWEI-Router %%01SHELL/5/CMDRECORD(l)[1]:command:display this by huawei(192.168.1.100)
        pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?%%(\w+)/(\d)/(\w+).*?:(.*)'
        
        for line in output.split('\n'):
            if not line.strip():
                continue
                
            match = re.search(pattern, line)
            if match:
                timestamp = match.group(1)
                component = match.group(2)
                log_level = match.group(3)
                subcomponent = match.group(4)
                message = match.group(5)
                
                log_entry = {
                    "timestamp": timestamp,
                    "log_level": log_level,
                    "component": f"{component}/{subcomponent}",
                    "message": message,
                    "event_type": NetworkInspector._classify_event_type(message),
                    "source_ip": None,
                    "username": None,
                    "target": None
                }
                
                # 提取源IP和用户名
                ip_match = re.search(r'\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)', message)
                if ip_match:
                    log_entry["source_ip"] = ip_match.group(1)
                
                user_match = re.search(r'by\s+(\w+)', message)
                if user_match:
                    log_entry["username"] = user_match.group(1)
                
                logs.append(log_entry)
        
        return logs
    
    @staticmethod
    def _parse_h3c_logs(output: str) -> List[LogEntry]:
        """解析H3C设备日志"""
        logs = []
        
        # H3C日志格式: 通常与华为类似，但有细微差别
        # 例如: 2023-06-04 10:15:22 H3C %%10SHELL/5/SHELL_LOGIN: admin(192.168.1.100) in unit1 login
        pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?%%(\d+)(\w+)/(\d)/(\w+):\s+(.*)'
        
        for line in output.split('\n'):
            if not line.strip():
                continue
                
            match = re.search(pattern, line)
            if match:
                timestamp = match.group(1)
                unit = match.group(2)
                component = match.group(3)
                log_level = match.group(4)
                event_type = match.group(5)
                message = match.group(6)
                
                log_entry = {
                    "timestamp": timestamp,
                    "log_level": log_level,
                    "component": component,
                    "message": message,
                    "event_type": event_type,
                    "source_ip": None,
                    "username": None,
                    "target": None
                }
                
                # 提取源IP和用户名
                ip_match = re.search(r'(\w+)\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)', message)
                if ip_match:
                    log_entry["username"] = ip_match.group(1)
                    log_entry["source_ip"] = ip_match.group(2)
                
                logs.append(log_entry)
        
        return logs
    
    @staticmethod
    def _parse_juniper_logs(output: str) -> List[LogEntry]:
        """解析Juniper设备日志"""
        logs = []
        
        # Juniper日志格式: Month Day HH:MM:SS hostname process[pid]: %component:level: message
        # 例如: Jun 4 10:15:22 juniper-router mgd[1234]: %DAEMON-6: User 'admin' authenticated from 192.168.1.100
        pattern = r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*?(\w+)\[\d+\]:\s+%(\w+)-(\d+):\s+(.*)'
        
        for line in output.split('\n'):
            if not line.strip():
                continue
                
            match = re.search(pattern, line)
            if match:
                timestamp = match.group(1)
                process = match.group(2)
                component = match.group(3)
                log_level = match.group(4)
                message = match.group(5)
                
                log_entry = {
                    "timestamp": timestamp,
                    "log_level": log_level,
                    "component": f"{process}/{component}",
                    "message": message,
                    "event_type": NetworkInspector._classify_event_type(message),
                    "source_ip": None,
                    "username": None,
                    "target": None
                }
                
                # 提取源IP和用户名
                ip_match = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
                if ip_match:
                    log_entry["source_ip"] = ip_match.group(1)
                
                user_match = re.search(r"User\s+'(\w+)'", message)
                if user_match:
                    log_entry["username"] = user_match.group(1)
                
                logs.append(log_entry)
        
        return logs
    
    @staticmethod
    def _parse_fortinet_logs(output: str) -> List[LogEntry]:
        """解析Fortinet设备日志"""
        logs = []
        
        # Fortinet日志格式较为复杂，通常包含多个字段
        # 尝试匹配: date=YYYY-MM-DD time=HH:MM:SS ...其他字段...
        pattern = r'date=(\d{4}-\d{2}-\d{2})\s+time=(\d{2}:\d{2}:\d{2}).*?level=(\w+).*?type=(\w+).*?user=\"?(\w*)\"?.*?(srcip=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?.*?msg=\"(.*?)\"'
        
        for line in output.split('\n'):
            if not line.strip():
                continue
                
            match = re.search(pattern, line)
            if match:
                date = match.group(1)
                time = match.group(2)
                log_level = match.group(3)
                event_type = match.group(4)
                username = match.group(5)
                source_ip = match.group(7)
                message = match.group(8)
                
                log_entry = {
                    "timestamp": f"{date} {time}",
                    "log_level": log_level,
                    "component": event_type,
                    "message": message,
                    "event_type": event_type,
                    "source_ip": source_ip,
                    "username": username if username else None,
                    "target": None
                }
                
                logs.append(log_entry)
            else:
                # 尝试其他格式
                alt_pattern = r'id=(\d+).*?time=\"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\".*?level=\"(\w+)\".*?user=\"(\w*)\".*?src=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?.*?msg=\"(.*?)\"'
                alt_match = re.search(alt_pattern, line)
                if alt_match:
                    logs.append({
                        "timestamp": alt_match.group(2),
                        "log_level": alt_match.group(3),
                        "component": "system",
                        "message": alt_match.group(6),
                        "event_type": "system",
                        "source_ip": alt_match.group(5),
                        "username": alt_match.group(4) if alt_match.group(4) else None,
                        "target": None
                    })
        
        return logs
    
    @staticmethod
    def _parse_zte_logs(output: str) -> List[LogEntry]:
        """解析中兴设备日志"""
        logs = []
        
        # 中兴设备日志格式: YYYY-MM-DD HH:MM:SS %%[模块名-级别-告警类型-标识码]:告警描述
        # 例如: 2023-06-04 10:15:22 %%[SHELL-5-LOGIN-SUCCESS-5]:User admin login successfully from 192.168.1.100.
        pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+%%\[(\w+)-(\d+)-(\w+)(?:-\w+)*\]:(.*)'
        
        for line in output.split('\n'):
            if not line.strip():
                continue
            
            match = re.search(pattern, line)
            if match:
                timestamp = match.group(1)
                component = match.group(2)
                log_level = match.group(3)
                event_type = match.group(4)
                message = match.group(5)
                
                log_entry = {
                    "timestamp": timestamp,
                    "log_level": log_level,
                    "component": component,
                    "message": message,
                    "event_type": event_type,
                    "source_ip": None,
                    "username": None,
                    "target": None
                }
                
                # 提取源IP和用户名
                ip_match = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
                if ip_match:
                    log_entry["source_ip"] = ip_match.group(1)
                
                user_match = re.search(r'[Uu]ser\s+(\w+)', message)
                if user_match:
                    log_entry["username"] = user_match.group(1)
                
                logs.append(log_entry)
            else:
                # 尝试匹配其他中兴日志格式
                alt_pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(\w+):\s+(.*)'
                alt_match = re.search(alt_pattern, line)
                if alt_match:
                    logs.append({
                        "timestamp": alt_match.group(1),
                        "log_level": "info",
                        "component": alt_match.group(2),
                        "message": alt_match.group(4),
                        "event_type": NetworkInspector._classify_event_type(alt_match.group(4)),
                        "source_ip": None,
                        "username": None,
                        "target": None
                    })
        
        return logs
    
    @staticmethod
    def _parse_generic_logs(output: str) -> List[LogEntry]:
        """通用日志解析方法，尝试匹配常见模式"""
        logs = []
        
        # 尝试匹配常见日志格式
        patterns = [
            # ISO标准时间戳格式 (2022-01-01T12:34:56)
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*?(\w+)\s+(\w+):\s+(.*)',
            # 标准日期时间格式 (YYYY-MM-DD HH:MM:SS)
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?(\w+).*?(\w+):\s+(.*)',
            # 英文月份格式 (Jun 1 12:34:56)
            r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*?(\w+).*?(\w+):\s+(.*)',
            # 简单时间格式 (HH:MM:SS)
            r'(\d{2}:\d{2}:\d{2}).*?(\w+).*?(\w+):\s+(.*)'
        ]
        
        for line in output.split('\n'):
            if not line.strip():
                continue
            
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    timestamp = match.group(1)
                    level_or_component = match.group(2)
                    component_or_type = match.group(3)
                    message = match.group(4)
                    
                    # 判断哪个是日志级别，哪个是组件
                    log_level = "info"  # 默认值
                    component = component_or_type
                    
                    if level_or_component.lower() in ["info", "warning", "error", "debug", "critical", "notice", "alert", "emergency"]:
                        log_level = level_or_component.lower()
                    else:
                        component = level_or_component
                    
                    log_entry = {
                        "timestamp": timestamp,
                        "log_level": log_level,
                        "component": component,
                        "message": message,
                        "event_type": NetworkInspector._classify_event_type(message),
                        "source_ip": None,
                        "username": None,
                        "target": None
                    }
                    
                    # 尝试提取额外信息
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
                    if ip_match:
                        try:
                            # 验证是否为有效IP
                            if ipaddress.ip_address(ip_match.group(1)):
                                log_entry["source_ip"] = ip_match.group(1)
                        except:
                            pass
                    
                    user_match = re.search(r'user[:\s]+(\w+)', message, re.IGNORECASE)
                    if not user_match:
                        user_match = re.search(r'(\w+) logged in', message, re.IGNORECASE)
                    if user_match:
                        log_entry["username"] = user_match.group(1)
                    
                    logs.append(log_entry)
                    break  # 找到匹配项后跳出内部循环
        
        return logs
    
    @staticmethod
    def _classify_event_type(message: str) -> str:
        """根据消息内容分类事件类型"""
        message_lower = message.lower()
        
        if any(kw in message_lower for kw in ["login", "logged in", "authentication success", "authenticated", "user access"]):
            return "auth_success"
        elif any(kw in message_lower for kw in ["failed login", "authentication failed", "auth fail", "denied", "incorrect password"]):
            return "auth_failure"
        elif any(kw in message_lower for kw in ["configuration", "config", "configured", "changed", "modify", "commit"]):
            return "config_change"
        elif any(kw in message_lower for kw in ["error", "failure", "failed", "crash", "down"]):
            return "error"
        elif any(kw in message_lower for kw in ["warning", "warn"]):
            return "warning"
        elif any(kw in message_lower for kw in ["interface", "link", "port", "connection"]):
            return "interface"
        elif any(kw in message_lower for kw in ["system", "boot", "shutdown", "restart", "reload"]):
            return "system"
        elif any(kw in message_lower for kw in ["security", "attack", "violation", "blocked"]):
            return "security"
        else:
            return "info"
    
    @staticmethod
    def analyze_device_logs(logs: List[LogEntry]) -> LogAnalysisResult:
        """分析设备日志"""
        # 初始化分析结果
        result = {
            "log_count": len(logs),
            "auth_success_count": 0,
            "auth_failure_count": 0,
            "config_change_count": 0,
            "system_events_count": 0,
            "error_events_count": 0,
            "warning_events_count": 0,
            "unusual_access_ips": [],
            "unusual_access_times": [],
            "top_users": [],
            "time_distribution": {},
            "recent_config_changes": []
        }
        
        # 初始化统计数据
        user_access_count = {}
        ip_access_count = {}
        hour_distribution = {f"{h:02d}": 0 for h in range(24)}
        config_changes = []
        
        # 业务时间范围（非工作时间检测）
        business_hours_start = 9  # 早上9点
        business_hours_end = 18   # 晚上6点
        
        # 遍历分析日志
        for log in logs:
            # 按事件类型分类统计
            event_type = log.get("event_type", "")
            if event_type == "auth_success":
                result["auth_success_count"] += 1
            elif event_type == "auth_failure":
                result["auth_failure_count"] += 1
            elif event_type == "config_change":
                result["config_change_count"] += 1
                # 记录配置变更
                config_changes.append({
                    "timestamp": log.get("timestamp", ""),
                    "user": log.get("username", "unknown"),
                    "message": log.get("message", "")
                })
            elif event_type == "system":
                result["system_events_count"] += 1
            
            # 按日志级别统计
            log_level = log.get("log_level", "")
            if log_level in ["error", "critical", "alert", "emergency"]:
                result["error_events_count"] += 1
            elif log_level == "warning":
                result["warning_events_count"] += 1
            
            # 用户访问统计
            username = log.get("username")
            if username:
                if username not in user_access_count:
                    user_access_count[username] = 0
                user_access_count[username] += 1
            
            # IP访问统计
            source_ip = log.get("source_ip")
            if source_ip:
                if source_ip not in ip_access_count:
                    ip_access_count[source_ip] = 0
                ip_access_count[source_ip] += 1
            
            # 时间分布统计
            try:
                timestamp = log.get("timestamp", "")
                # 尝试不同的时间格式解析
                dt = None
                formats = [
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S",
                    "%b %d %H:%M:%S",
                    "%b %d %Y %H:%M:%S"
                ]
                
                for fmt in formats:
                    try:
                        dt = datetime.strptime(timestamp, fmt)
                        break
                    except ValueError:
                        continue
                
                if dt:
                    hour = dt.hour
                    hour_key = f"{hour:02d}"
                    hour_distribution[hour_key] = hour_distribution.get(hour_key, 0) + 1
                    
                    # 检测非工作时间的访问
                    if (hour < business_hours_start or hour >= business_hours_end) and event_type == "auth_success":
                        result["unusual_access_times"].append({
                            "timestamp": timestamp,
                            "user": username or "unknown",
                            "source_ip": source_ip or "unknown",
                            "hour": hour
                        })
            except Exception:
                pass
        
        # 处理统计结果
        # 1. 排序用户访问次数
        sorted_users = sorted(
            [{"username": k, "access_count": v} for k, v in user_access_count.items()],
            key=lambda x: x["access_count"],
            reverse=True
        )
        result["top_users"] = sorted_users[:10]  # 取前10名
        
        # 2. 排序配置变更，取最近的
        result["recent_config_changes"] = sorted(
            config_changes,
            key=lambda x: x["timestamp"],
            reverse=True
        )[:20]  # 取最近20条
        
        # 3. 检测异常IP (根据访问频率，简单实现)
        ip_threshold = 10  # 设定阈值，访问超过此次数的IP视为异常
        result["unusual_access_ips"] = [
            {"ip": ip, "count": count}
            for ip, count in ip_access_count.items()
            if count > ip_threshold
        ]
        
        # 4. 设置时间分布
        result["time_distribution"] = hour_distribution
        
        return result 