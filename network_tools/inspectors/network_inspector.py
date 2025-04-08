import re
from typing import List
from network_tools.models.base_models import (
    NetworkDevice, SwitchPort, Route, ACLRule, VLAN, 
    OpticalModule, NetworkDeviceType, NetworkVendor
)

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