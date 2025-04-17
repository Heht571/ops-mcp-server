from typing import List, Dict, Any, Optional
import logging
import re
from datetime import datetime
from mcp.server.fastmcp import FastMCP
from network_tools.models.base_models import InspectionResult, DeviceSession, DeviceSessionsResult
from network_tools.managers.ssh_manager import SSHManager
from network_tools.inspectors.network_inspector import NetworkInspector

# 配置日志
logger = logging.getLogger('network_tools.session_tools')

# 创建MCP实例
mcp = FastMCP(__name__)

@mcp.tool()
def check_device_sessions(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    include_protocols: List[str] = [],  # 例如: ["SSH", "Telnet", "Console"]
    timeout: int = 30
) -> dict:
    """分析网络设备的当前会话连接信息，识别在线用户和连接特征"""
    result = InspectionResult()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 检测设备类型和厂商
            vendor = detect_device_vendor(ssh)
            
            # 收集会话数据
            sessions_data = collect_sessions(ssh, vendor)
            
            if not sessions_data:
                result.status = "error"
                result.error = "未能收集到会话连接数据"
                return result.dict()
                
            # 解析会话数据
            sessions = parse_sessions(sessions_data, vendor)
            
            if not sessions:
                result.status = "error"
                result.error = "未能解析到有效会话数据"
                return result.dict()
            
            # 过滤特定协议(如果指定)
            if include_protocols:
                sessions = [s for s in sessions if s["protocol"].upper() in [p.upper() for p in include_protocols]]
            
            # 分析会话数据
            analysis_result = analyze_sessions(sessions)
            
            # 设置返回结果
            result.status = "success"
            result.data = analysis_result
            
            # 生成总结信息
            summary_parts = []
            summary_parts.append(f"共发现 {analysis_result['total_sessions']} 个会话连接")
            summary_parts.append(f"活动会话: {analysis_result['active_sessions']} 个")
            summary_parts.append(f"空闲会话: {analysis_result['idle_sessions']} 个")
            
            protocol_summary = []
            for protocol, count in analysis_result['sessions_by_protocol'].items():
                if count > 0:
                    protocol_summary.append(f"{protocol}: {count}个")
            
            if protocol_summary:
                summary_parts.append("，".join(protocol_summary))
                
            if analysis_result['top_source_ips']:
                top_ip = analysis_result['top_source_ips'][0]
                summary_parts.append(f"最活跃IP: {top_ip['ip']}({top_ip['count']}个会话)")
                
            result.summary = "，".join(summary_parts)
            
    except Exception as e:
        result.status = "error"
        result.error = f"分析设备会话连接失败: {str(e)}"
        logger.error(f"分析设备会话连接失败: {str(e)}")
    
    return result.dict()

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

def collect_sessions(ssh, vendor: str) -> str:
    """根据设备类型收集会话数据"""
    # 收集命令集
    commands = []
    
    if vendor == "cisco":
        commands.extend([
            "show users", 
            "show ssh", 
            "show line"
        ])
    elif vendor == "juniper":
        commands.extend([
            "show system users", 
            "show system connections"
        ])
    elif vendor == "huawei":
        commands.extend([
            "display users", 
            "display ssh server session",
            "display telnet server status"
        ])
    elif vendor == "fortinet":
        commands.extend([
            "get system admin list", 
            "get system session-info"
        ])
    elif vendor == "zte":
        commands.extend([
            "show users",
            "show ssh session",
            "show telnet session"
        ])
    else:
        # 通用命令，尝试不同格式
        commands.extend([
            "show users",
            "display users", 
            "show ssh",
            "display ssh server session",
            "show system users",
            "get system admin list"
        ])
    
    # 执行命令并收集输出
    all_outputs = []
    for cmd in commands:
        try:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode('utf-8', errors='ignore')
            if output:
                all_outputs.append(output)
        except Exception as e:
            logger.warning(f"执行命令 '{cmd}' 失败: {str(e)}")
    
    return "\n".join(all_outputs)

def parse_sessions(data: str, vendor: str) -> List[DeviceSession]:
    """解析会话数据"""
    sessions = []
    
    if vendor == "cisco":
        sessions = parse_cisco_sessions(data)
    elif vendor == "juniper":
        sessions = parse_juniper_sessions(data)
    elif vendor == "huawei":
        sessions = parse_huawei_sessions(data)
    elif vendor == "fortinet":
        sessions = parse_fortinet_sessions(data)
    elif vendor == "zte":
        sessions = parse_zte_sessions(data)
    else:
        # 尝试所有解析器
        sessions = parse_generic_sessions(data)
    
    return sessions

def parse_cisco_sessions(data: str) -> List[DeviceSession]:
    """解析思科设备会话数据"""
    sessions = []
    
    # 解析"show users"输出
    # 示例: Line       User       Host(s)              Idle       Location
    #      *  2 vty 0     admin      192.168.1.100       00:01:23   
    users_pattern = r'[*\s]+(\d+\s+\w+\s+\d+)\s+(\w+)\s+(\S+)\s+(\S+)'
    users_matches = re.finditer(users_pattern, data)
    
    for match in users_matches:
        line = match.group(1).strip()
        user = match.group(2).strip()
        host = match.group(3).strip()
        idle = match.group(4).strip()
        
        # 提取IP和端口
        if ":" in host:
            ip, port = host.split(":")
        else:
            ip = host
            port = ""
            
        sessions.append({
            "session_id": line,
            "protocol": "SSH" if "vty" in line else "Console",
            "source_ip": ip,
            "source_port": port,
            "destination_ip": hostname,
            "destination_port": "22" if "vty" in line else "0",
            "username": user,
            "login_time": "",
            "idle_time": idle,
            "status": "active" if idle == "00:00:00" else "idle"
        })
    
    # 解析"show ssh"输出以获取更多信息
    # 示例: Connection Version Mode Encryption  State            Username
    #      1         2.0     IN   aes256-cbc   Session started  admin
    ssh_pattern = r'(\d+)\s+\d+\.\d+\s+\w+\s+\S+\s+(\S+\s+\S+)\s+(\S+)'
    ssh_matches = re.finditer(ssh_pattern, data)
    
    for match in ssh_matches:
        session_id = match.group(1).strip()
        state = match.group(2).strip()
        user = match.group(3).strip()
        
        # 尝试匹配已有会话并更新信息
        for s in sessions:
            if user == s["username"]:
                s["status"] = "active" if "started" in state.lower() else "idle"
                break
    
    return sessions

def parse_juniper_sessions(data: str) -> List[DeviceSession]:
    """解析Juniper设备会话数据"""
    sessions = []
    
    # 解析"show system users"输出
    # 示例: admin     p0       192.168.1.100    2d4h53m   -
    users_pattern = r'(\w+)\s+(\w+)\s+(\S+)\s+(\S+)'
    users_matches = re.finditer(users_pattern, data)
    
    for match in users_matches:
        user = match.group(1).strip()
        tty = match.group(2).strip()
        host = match.group(3).strip()
        idle = match.group(4).strip()
        
        protocol = "Console"
        if "p" in tty:
            protocol = "SSH"
        
        # 提取IP和端口
        if ":" in host:
            ip, port = host.split(":")
        else:
            ip = host
            port = ""
            
        sessions.append({
            "session_id": tty,
            "protocol": protocol,
            "source_ip": ip,
            "source_port": port,
            "destination_ip": "",
            "destination_port": "22" if protocol == "SSH" else "0",
            "username": user,
            "login_time": "",
            "idle_time": idle,
            "status": "active" if idle == "0" else "idle"
        })
    
    return sessions

def parse_huawei_sessions(data: str) -> List[DeviceSession]:
    """解析华为设备会话数据"""
    sessions = []
    
    # 解析"display users"输出
    # 示例: User-Intf    : VTY0
    #     User-Level   : 3
    #     User-Name    : admin
    #     IP-Address   : 192.168.1.100
    #     Idle-TimeOut : 10 minute(s)
    #     UserID       : 100
    #     Authentication-Mode : Password
    
    user_blocks = re.split(r'(?:User-Intf|Line)\s*:', data)[1:]
    
    for block in user_blocks:
        session = {
            "session_id": "",
            "protocol": "Unknown",
            "source_ip": "",
            "source_port": "",
            "destination_ip": "",
            "destination_port": "",
            "username": "",
            "login_time": "",
            "idle_time": "",
            "status": "unknown"
        }
        
        # 提取接口
        intf_match = re.search(r'^\s*(\S+)', block)
        if intf_match:
            session["session_id"] = intf_match.group(1).strip()
            if "VTY" in session["session_id"]:
                session["protocol"] = "SSH"
            elif "CON" in session["session_id"]:
                session["protocol"] = "Console"
        
        # 提取用户名
        user_match = re.search(r'User-Name\s*:\s*(\S+)', block)
        if user_match:
            session["username"] = user_match.group(1).strip()
        
        # 提取IP地址
        ip_match = re.search(r'IP-Address\s*:\s*(\S+)', block)
        if ip_match:
            session["source_ip"] = ip_match.group(1).strip()
        
        # 提取空闲时间
        idle_match = re.search(r'Idle-TimeOut\s*:\s*(\d+)', block)
        if idle_match:
            session["idle_time"] = idle_match.group(1).strip() + " min"
        
        # 尝试判断状态
        if session["idle_time"]:
            session["status"] = "idle" if int(session["idle_time"].split()[0]) > 0 else "active"
        
        sessions.append(session)
    
    return sessions

def parse_fortinet_sessions(data: str) -> List[DeviceSession]:
    """解析Fortinet设备会话数据"""
    sessions = []
    
    # 解析"get system admin list"输出，包含管理员会话信息
    admin_pattern = r'name\s*:\s*(\S+)[\s\S]*?ip\s*:\s*(\S+)'
    admin_matches = re.finditer(admin_pattern, data, re.MULTILINE)
    
    for match in admin_matches:
        user = match.group(1).strip()
        ip = match.group(2).strip()
        
        if ip and ip != "0.0.0.0":  # 忽略未登录的管理员
            sessions.append({
                "session_id": user + "-" + ip,
                "protocol": "HTTPS",  # 默认为Web界面
                "source_ip": ip,
                "source_port": "",
                "destination_ip": "",
                "destination_port": "443",
                "username": user,
                "login_time": "",
                "idle_time": "",
                "status": "active"
            })
    
    # 解析SSH会话（通常在get system session-info输出中）
    ssh_pattern = r'proto=(\d+)[\s\S]*?src=(\S+):(\d+)[\s\S]*?dst=(\S+):(\d+)'
    ssh_matches = re.finditer(ssh_pattern, data)
    
    for match in ssh_matches:
        proto = match.group(1).strip()
        src_ip = match.group(2).strip()
        src_port = match.group(3).strip()
        dst_ip = match.group(4).strip()
        dst_port = match.group(5).strip()
        
        # SSH协议号为22
        if proto == "22" or dst_port == "22":
            sessions.append({
                "session_id": f"ssh-{src_ip}-{src_port}",
                "protocol": "SSH",
                "source_ip": src_ip,
                "source_port": src_port,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "username": "",  # Fortinet不总是显示用户名
                "login_time": "",
                "idle_time": "",
                "status": "active"
            })
    
    return sessions

def parse_zte_sessions(data: str) -> List[DeviceSession]:
    """解析中兴设备会话数据"""
    sessions = []
    
    # 解析"show users"输出
    # 例如: 
    # Line     User      Host               Idle      Location
    # *0 con   admin     idle               00:00:00  
    #  1 vty 0 user1     192.168.1.100      00:05:23  
    users_pattern = r'[*\s]*(\d+\s+\S+\s+\d*)\s+(\S+)\s+(\S+)\s+(\S+)'
    users_matches = re.finditer(users_pattern, data)
    
    for match in users_matches:
        line = match.group(1).strip()
        username = match.group(2).strip()
        host = match.group(3).strip()
        idle = match.group(4).strip()
        
        protocol = "Console"
        if "vty" in line.lower():
            protocol = "SSH"
        elif "web" in line.lower():
            protocol = "HTTP"
            
        # 提取IP和端口
        source_ip = host
        source_port = ""
        if host != "idle" and ":" in host:
            source_ip, source_port = host.split(":")
            
        sessions.append({
            "session_id": line,
            "protocol": protocol,
            "source_ip": source_ip if source_ip != "idle" else "",
            "source_port": source_port,
            "destination_ip": "",
            "destination_port": "22" if protocol == "SSH" else "0",
            "username": username,
            "login_time": "",
            "idle_time": idle,
            "status": "active" if idle == "00:00:00" else "idle"
        })
    
    # 解析SSH会话详细信息
    ssh_pattern = r'Session\s+(\d+)[\s\S]*?Username\s*:\s*(\S+)[\s\S]*?Source\s+IP\s*:\s*(\S+)[\s\S]*?Login\s+time\s*:\s*([^\n]+)'
    ssh_matches = re.finditer(ssh_pattern, data)
    
    for match in ssh_matches:
        session_id = match.group(1).strip()
        username = match.group(2).strip()
        source_ip = match.group(3).strip()
        login_time = match.group(4).strip()
        
        # 查找并更新已存在的会话
        found = False
        for s in sessions:
            if s["username"] == username and (s["source_ip"] == source_ip or not s["source_ip"]):
                s["login_time"] = login_time
                found = True
                break
                
        # 如果没找到匹配的会话，添加新会话
        if not found:
            sessions.append({
                "session_id": f"ssh-{session_id}",
                "protocol": "SSH",
                "source_ip": source_ip,
                "source_port": "",
                "destination_ip": "",
                "destination_port": "22",
                "username": username,
                "login_time": login_time,
                "idle_time": "",
                "status": "active"
            })
    
    return sessions

def parse_generic_sessions(data: str) -> List[DeviceSession]:
    """通用会话解析方法，尝试提取会话信息"""
    sessions = []
    
    # 尝试匹配用户会话行
    user_patterns = [
        # 用户名 + 终端 + IP地址格式
        r'(\w+)\s+(\S+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?',
        # 终端 + 用户名 + IP地址格式
        r'(\S+)\s+(\w+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?',
        # SSH会话信息
        r'Session\s+(\d+).*?User(?:name)?\s*[:=]\s*(\S+).*?(?:Source|From)\s+(?:IP|Address)\s*[:=]\s*(\S+)',
        # 管理员会话信息
        r'admin\s+session.*?user\s*[:=]\s*(\S+).*?(?:ip|from)\s*[:=]\s*(\S+)',
    ]
    
    for pattern in user_patterns:
        matches = re.finditer(pattern, data, re.IGNORECASE | re.MULTILINE)
        
        for match in matches:
            # 根据匹配的模式确定字段
            if len(match.groups()) == 4:  # 第一或第二种模式
                if re.search(r'tty|con|vty', match.group(1), re.IGNORECASE):
                    # 第二种模式：终端 + 用户名 + IP地址
                    terminal = match.group(1)
                    username = match.group(2)
                    source_ip = match.group(3)
                    source_port = match.group(4) if match.group(4) else ""
                else:
                    # 第一种模式：用户名 + 终端 + IP地址
                    username = match.group(1)
                    terminal = match.group(2)
                    source_ip = match.group(3)
                    source_port = match.group(4) if match.group(4) else ""
                
                # 确定协议
                protocol = "Console"
                if re.search(r'vty|ssh', terminal, re.IGNORECASE):
                    protocol = "SSH"
                elif re.search(r'web|http', terminal, re.IGNORECASE):
                    protocol = "HTTP"
                
                # 创建会话记录
                sessions.append({
                    "session_id": terminal,
                    "protocol": protocol,
                    "source_ip": source_ip,
                    "source_port": source_port,
                    "destination_ip": "",
                    "destination_port": "22" if protocol == "SSH" else "23" if protocol == "Telnet" else "0",
                    "username": username,
                    "login_time": "",
                    "idle_time": "",
                    "status": "active"
                })
            elif len(match.groups()) == 3:  # 第三种模式
                session_id = match.group(1)
                username = match.group(2)
                source_ip = match.group(3)
                
                # 创建会话记录
                sessions.append({
                    "session_id": f"ssh-{session_id}",
                    "protocol": "SSH",
                    "source_ip": source_ip,
                    "source_port": "",
                    "destination_ip": "",
                    "destination_port": "22",
                    "username": username,
                    "login_time": "",
                    "idle_time": "",
                    "status": "active"
                })
            elif len(match.groups()) == 2:  # 第四种模式
                username = match.group(1)
                source_ip = match.group(2)
                
                # 创建会话记录
                sessions.append({
                    "session_id": f"{username}-{source_ip}",
                    "protocol": "HTTPS",
                    "source_ip": source_ip,
                    "source_port": "",
                    "destination_ip": "",
                    "destination_port": "443",
                    "username": username,
                    "login_time": "",
                    "idle_time": "",
                    "status": "active"
                })
    
    # 提取可能的空闲时间信息
    for s in sessions:
        idle_match = re.search(rf'{re.escape(s["username"])}.*?idle[\s:=]+(\S+)', data, re.IGNORECASE)
        if idle_match:
            s["idle_time"] = idle_match.group(1)
            
        login_match = re.search(rf'{re.escape(s["username"])}.*?login[\s:=]+(\S+\s+\S+)', data, re.IGNORECASE)
        if login_match:
            s["login_time"] = login_match.group(1)
        
        # 尝试根据空闲时间设置状态
        if s["idle_time"]:
            if s["idle_time"] == "0" or s["idle_time"] == "00:00:00":
                s["status"] = "active"
            else:
                s["status"] = "idle"
    
    return sessions

def analyze_sessions(sessions: List[DeviceSession]) -> DeviceSessionsResult:
    """分析会话数据"""
    result = {
        "total_sessions": len(sessions),
        "active_sessions": 0,
        "idle_sessions": 0,
        "sessions_by_protocol": {},
        "top_source_ips": [],
        "top_users": [],
        "recent_logins": [],
        "sessions": sessions
    }
    
    # 统计活动和空闲会话
    for session in sessions:
        if session["status"] == "active":
            result["active_sessions"] += 1
        else:
            result["idle_sessions"] += 1
            
        # 统计协议分布
        protocol = session["protocol"]
        if protocol not in result["sessions_by_protocol"]:
            result["sessions_by_protocol"][protocol] = 0
        result["sessions_by_protocol"][protocol] += 1
    
    # 统计源IP分布
    ip_count = {}
    for session in sessions:
        if session["source_ip"]:
            ip = session["source_ip"]
            if ip not in ip_count:
                ip_count[ip] = 0
            ip_count[ip] += 1
    
    # 排序源IP分布
    result["top_source_ips"] = [
        {"ip": ip, "count": count}
        for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True)
    ]
    
    # 统计用户分布
    user_count = {}
    for session in sessions:
        if session["username"]:
            user = session["username"]
            if user not in user_count:
                user_count[user] = 0
            user_count[user] += 1
    
    # 排序用户分布
    result["top_users"] = [
        {"username": user, "count": count}
        for user, count in sorted(user_count.items(), key=lambda x: x[1], reverse=True)
    ]
    
    # 尝试按登录时间排序会话
    sessions_with_time = []
    for session in sessions:
        if session["login_time"]:
            try:
                # 尝试多种格式解析时间
                formats = [
                    "%Y-%m-%d %H:%M:%S",
                    "%Y/%m/%d %H:%M:%S",
                    "%a %b %d %H:%M:%S %Y",
                    "%H:%M:%S %Y-%m-%d"
                ]
                
                login_time = None
                for fmt in formats:
                    try:
                        login_time = datetime.strptime(session["login_time"], fmt)
                        break
                    except ValueError:
                        continue
                
                if login_time:
                    sessions_with_time.append((login_time, session))
            except:
                # 忽略无法解析的时间
                pass
    
    # 排序并设置最近登录
    if sessions_with_time:
        sessions_with_time.sort(key=lambda x: x[0], reverse=True)
        result["recent_logins"] = [s[1] for s in sessions_with_time[:10]]
    
    return result 