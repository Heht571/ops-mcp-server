from typing import List, Dict, Any, Optional
import logging
import re
import ipaddress
from mcp.server.fastmcp import FastMCP
from network_tools.models.base_models import InspectionResult, SecurityPolicyRule, SecurityPolicyAnalysisResult
from network_tools.managers.ssh_manager import SSHManager
from network_tools.inspectors.network_inspector import NetworkInspector

# 配置日志
logger = logging.getLogger('network_tools.security_tools')

# 创建MCP实例
mcp = FastMCP(__name__)

@mcp.tool()
def analyze_security_policy(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    policy_type: str = "all",  # firewall, nat, pbr, all
    timeout: int = 60
) -> dict:
    """分析网络设备的安全策略配置，识别潜在风险和优化机会"""
    result = InspectionResult()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 检测设备类型和厂商
            vendor = detect_device_vendor(ssh)
            
            # 收集安全策略数据
            policy_data = collect_security_policy(ssh, vendor, policy_type)
            
            if not policy_data:
                result.status = "error"
                result.error = "未能收集到安全策略数据"
                return result.dict()
                
            # 解析安全策略数据
            policies = parse_security_policy(policy_data, vendor, policy_type)
            
            if not policies:
                result.status = "error"
                result.error = "未能解析到有效安全策略数据"
                return result.dict()
            
            # 分析安全策略
            analysis_result = analyze_policies(policies)
            
            # 设置返回结果
            result.status = "success"
            result.data = analysis_result
            
            # 生成总结信息
            summary_parts = []
            summary_parts.append(f"共分析 {analysis_result['total_rules']} 条安全策略规则")
            
            if analysis_result['rules_with_any_source'] > 0:
                ratio = analysis_result['rules_with_any_source'] / analysis_result['total_rules'] * 100
                summary_parts.append(f"源地址为Any的规则: {analysis_result['rules_with_any_source']}条({ratio:.1f}%)")
            
            if analysis_result['rules_with_any_destination'] > 0:
                ratio = analysis_result['rules_with_any_destination'] / analysis_result['total_rules'] * 100
                summary_parts.append(f"目标地址为Any的规则: {analysis_result['rules_with_any_destination']}条({ratio:.1f}%)")
            
            if analysis_result['rules_without_logging'] > 0:
                ratio = analysis_result['rules_without_logging'] / analysis_result['total_rules'] * 100
                summary_parts.append(f"未开启日志的规则: {analysis_result['rules_without_logging']}条({ratio:.1f}%)")
            
            if analysis_result['unused_rules'] > 0:
                ratio = analysis_result['unused_rules'] / analysis_result['total_rules'] * 100
                summary_parts.append(f"未使用的规则: {analysis_result['unused_rules']}条({ratio:.1f}%)")
            
            if analysis_result['shadowed_rules']:
                summary_parts.append(f"存在 {len(analysis_result['shadowed_rules'])} 条被遮蔽的规则")
            
            if analysis_result['policy_recommendations']:
                summary_parts.append(f"共有 {len(analysis_result['policy_recommendations'])} 条优化建议")
            
            result.summary = "，".join(summary_parts)
            
    except Exception as e:
        result.status = "error"
        result.error = f"分析安全策略失败: {str(e)}"
        logger.error(f"分析安全策略失败: {str(e)}")
    
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

def collect_security_policy(ssh, vendor: str, policy_type: str) -> str:
    """根据设备类型收集安全策略数据"""
    commands = []
    
    if vendor == "cisco":
        if policy_type in ["firewall", "all"]:
            commands.extend([
                "show access-lists", 
                "show ip access-lists",
                "show running-config | include access-list"
            ])
        if policy_type in ["nat", "all"]:
            commands.extend([
                "show ip nat translations",
                "show running-config | include nat"
            ])
            
    elif vendor == "juniper":
        if policy_type in ["firewall", "all"]:
            commands.extend([
                "show security policies detail",
                "show configuration security policies"
            ])
        if policy_type in ["nat", "all"]:
            commands.extend([
                "show security nat",
                "show configuration security nat"
            ])
            
    elif vendor == "huawei":
        if policy_type in ["firewall", "all"]:
            commands.extend([
                "display firewall-policy",
                "display firewall-policy rule all",
                "display current-configuration | include security-policy"
            ])
        if policy_type in ["nat", "all"]:
            commands.extend([
                "display nat all",
                "display current-configuration | include nat"
            ])
    
    elif vendor == "fortinet":
        if policy_type in ["firewall", "all"]:
            commands.extend([
                "show firewall policy",
                "diagnose firewall iprope show 100"
            ])
        if policy_type in ["nat", "all"]:
            commands.extend([
                "show firewall vip",
                "show firewall central-nat-table"
            ])
    
    elif vendor == "palo_alto":
        if policy_type in ["firewall", "all"]:
            commands.extend([
                "show running security-policy",
                "show security-policy-match"
            ])
        if policy_type in ["nat", "all"]:
            commands.extend([
                "show running nat",
                "show nat-policy-match"
            ])
    
    elif vendor == "zte":
        if policy_type in ["firewall", "all"]:
            commands.extend([
                "show access-lists",
                "show security policy",
                "show running-config | include policy"
            ])
        if policy_type in ["nat", "all"]:
            commands.extend([
                "show nat translations",
                "show running-config | include nat"
            ])
    
    else:
        # 通用命令，尝试不同的格式
        commands.extend([
            "show access-lists",
            "show security policy",
            "display firewall-policy",
            "show firewall policy",
            "show running-config | include access-list",
            "show nat translations",
            "display nat",
            "show firewall vip"
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

def parse_security_policy(data: str, vendor: str, policy_type: str) -> List[SecurityPolicyRule]:
    """解析安全策略数据"""
    policies = []
    
    # 根据厂商选择合适的解析方法
    if vendor == "cisco":
        if policy_type in ["firewall", "all"]:
            policies.extend(parse_cisco_acl(data))
    elif vendor == "juniper":
        if policy_type in ["firewall", "all"]:
            policies.extend(parse_juniper_policy(data))
    elif vendor == "huawei":
        if policy_type in ["firewall", "all"]:
            policies.extend(parse_huawei_policy(data))
    elif vendor == "fortinet":
        if policy_type in ["firewall", "all"]:
            policies.extend(parse_fortinet_policy(data))
    elif vendor == "palo_alto":
        if policy_type in ["firewall", "all"]:
            policies.extend(parse_paloalto_policy(data))
    elif vendor == "zte":
        if policy_type in ["firewall", "all"]:
            policies.extend(parse_zte_policy(data))
    else:
        # 尝试通用解析
        policies.extend(parse_generic_policy(data))
    
    return policies

def analyze_policies(policies: List[SecurityPolicyRule]) -> SecurityPolicyAnalysisResult:
    """分析安全策略，查找潜在问题和优化机会"""
    result = {
        "total_rules": len(policies),
        "enabled_rules": 0,
        "disabled_rules": 0,
        "rules_with_any_source": 0,
        "rules_with_any_destination": 0,
        "rules_with_any_service": 0,
        "rules_without_logging": 0,
        "unused_rules": 0,
        "top_hit_rules": [],
        "shadowed_rules": [],
        "policy_recommendations": [],
        "rules": policies
    }
    
    # 先统计基本指标
    for policy in policies:
        # 启用/禁用状态统计
        if policy.get("enabled", True):
            result["enabled_rules"] += 1
        else:
            result["disabled_rules"] += 1
        
        # 源地址为Any的规则统计
        if any("any" in src.lower() for src in policy.get("source", [])):
            result["rules_with_any_source"] += 1
        
        # 目标地址为Any的规则统计
        if any("any" in dst.lower() for dst in policy.get("destination", [])):
            result["rules_with_any_destination"] += 1
        
        # 服务为Any的规则统计
        if any("any" in svc.lower() for svc in policy.get("service", [])):
            result["rules_with_any_service"] += 1
        
        # 未开启日志的规则统计
        if not policy.get("logging", False):
            result["rules_without_logging"] += 1
        
        # 未使用的规则统计（依据hit_count）
        if policy.get("hit_count", 0) == 0:
            result["unused_rules"] += 1
    
    # 对规则按命中次数排序
    rules_with_hits = [p for p in policies if p.get("hit_count", 0) > 0]
    rules_with_hits.sort(key=lambda x: x.get("hit_count", 0), reverse=True)
    result["top_hit_rules"] = [
        {"rule_id": rule["rule_id"], "name": rule.get("name", ""), "hit_count": rule.get("hit_count", 0)}
        for rule in rules_with_hits[:10]  # 取前10条
    ]
    
    # 检测遮蔽规则
    shadowed_rules = find_shadowed_rules(policies)
    result["shadowed_rules"] = shadowed_rules
    
    # 生成优化建议
    result["policy_recommendations"] = generate_policy_recommendations(policies, result)
    
    return result

def parse_cisco_acl(data: str) -> List[SecurityPolicyRule]:
    """解析思科ACL策略"""
    policies = []
    
    # 解析标准ACL和扩展ACL
    # 先尝试提取ACL名称和条目
    acl_blocks = re.findall(r'((?:ip |)(access-list|access-group) \S+[\s\S]*?)(?=(?:ip |)access-list|access-group|\Z)', data)
    
    current_acl = ""
    for block in acl_blocks:
        acl_header = block[0].strip().split('\n')[0]
        
        # 提取ACL名称
        acl_match = re.search(r'(?:ip |)(access-list|access-group) (?:standard |extended |)(\S+)', acl_header)
        if acl_match:
            current_acl = acl_match.group(2)
            
        # 解析ACL条目
        lines = block[0].strip().split('\n')[1:]
        rule_id = 10
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('!'):
                continue
                
            # 提取permit/deny决策
            action_match = re.search(r'(permit|deny)', line)
            if not action_match:
                continue
                
            action = action_match.group(1)
            
            # 提取协议
            proto_match = re.search(r'(permit|deny)\s+(\w+)', line)
            protocol = proto_match.group(2) if proto_match else ""
            
            # 提取源和目标地址
            src_dst_match = re.search(r'(permit|deny)\s+\w+\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)', line)
            
            source = []
            destination = []
            service = []
            
            if src_dst_match:
                src = src_dst_match.group(2)
                src_mask = src_dst_match.group(3)
                dst = src_dst_match.group(4)
                dst_mask = src_dst_match.group(5)
                
                source = [f"{src} {src_mask}"]
                destination = [f"{dst} {dst_mask}"]
            else:
                # 简单格式
                simple_match = re.search(r'(permit|deny)\s+\w+\s+([^\s]+)\s+([^\s]+)', line)
                if simple_match:
                    src = simple_match.group(2)
                    dst = simple_match.group(3)
                    
                    source = [src]
                    destination = [dst]
            
            # 提取服务/端口
            service_match = re.search(r'eq\s+(\S+)', line)
            if service_match:
                service = [service_match.group(1)]
            elif "any" in line:
                service = ["any"]
            
            # 提取日志设置
            logging = "log" in line.lower()
            
            # 提取规则描述（如果有）
            description = ""
            remark_match = re.search(r'remark\s+(.*)', line)
            if remark_match:
                description = remark_match.group(1)
            
            # 创建策略条目
            policy = {
                "rule_id": str(rule_id),
                "name": f"ACL_{current_acl}_{rule_id}",
                "action": action,
                "source_zone": "",
                "destination_zone": "",
                "source": source,
                "destination": destination,
                "service": service,
                "application": [],
                "enabled": True,
                "logging": logging,
                "description": description,
                "hit_count": None,
                "last_hit": None
            }
            
            policies.append(policy)
            rule_id += 10
    
    # 如果没有找到ACL块，尝试匹配单独的ACL条目
    if not policies:
        acl_entries = re.finditer(r'(permit|deny)\s+(\w+)\s+([^\s]+)(?:\s+([^\s]+))?\s+([^\s]+)(?:\s+([^\s]+))?', data)
        
        rule_id = 10
        for entry in acl_entries:
            action = entry.group(1)
            protocol = entry.group(2)
            
            source = []
            destination = []
            
            if entry.group(4):  # 完整的源地址和掩码
                source = [f"{entry.group(3)} {entry.group(4)}"]
                if entry.group(6):  # 完整的目标地址和掩码
                    destination = [f"{entry.group(5)} {entry.group(6)}"]
                else:
                    destination = [entry.group(5)]
            else:  # 简单源地址
                source = [entry.group(3)]
                destination = [entry.group(5) if entry.group(5) else "any"]
            
            policy = {
                "rule_id": str(rule_id),
                "name": f"ACL_Entry_{rule_id}",
                "action": action,
                "source_zone": "",
                "destination_zone": "",
                "source": source,
                "destination": destination,
                "service": [protocol],
                "application": [],
                "enabled": True,
                "logging": "log" in entry.string.lower(),
                "description": "",
                "hit_count": None,
                "last_hit": None
            }
            
            policies.append(policy)
            rule_id += 10
    
    return policies

def parse_juniper_policy(data: str) -> List[SecurityPolicyRule]:
    """解析Juniper安全策略"""
    # 将在下一步实现
    return []

def parse_huawei_policy(data: str) -> List[SecurityPolicyRule]:
    """解析华为安全策略"""
    # 将在下一步实现
    return []

def parse_fortinet_policy(data: str) -> List[SecurityPolicyRule]:
    """解析飞塔安全策略"""
    # 将在下一步实现
    return []

def parse_paloalto_policy(data: str) -> List[SecurityPolicyRule]:
    """解析PaloAlto安全策略"""
    # 将在下一步实现
    return []

def parse_zte_policy(data: str) -> List[SecurityPolicyRule]:
    """解析中兴安全策略"""
    policies = []
    
    # 中兴设备的安全策略格式类似思科，但有一些特殊格式
    # 1. 解析ACL类似思科格式
    cisco_policies = parse_cisco_acl(data)
    if cisco_policies:
        policies.extend(cisco_policies)
    
    # 2. 尝试解析中兴特有的安全策略格式
    # 例如: policy-map xxx
    policy_blocks = re.findall(r'(policy-map\s+\S+[\s\S]*?)(?=policy-map|\Z)', data)
    
    for block in policy_blocks:
        # 提取策略名称
        policy_match = re.search(r'policy-map\s+(\S+)', block)
        if not policy_match:
            continue
            
        policy_name = policy_match.group(1)
        
        # 提取策略规则
        rule_matches = re.finditer(r'class\s+(\S+)[\s\S]*?(?=class|\Z)', block)
        
        rule_id = 10
        for rule_match in rule_matches:
            class_name = rule_match.group(1)
            rule_text = rule_match.group(0)
            
            # 提取动作
            action = "permit"  # 默认允许
            if "drop" in rule_text or "deny" in rule_text:
                action = "deny"
            
            # 提取源和目标
            source = ["any"]  # 默认任意
            destination = ["any"]  # 默认任意
            
            src_match = re.search(r'source\s+(\S+)', rule_text)
            if src_match:
                source = [src_match.group(1)]
                
            dst_match = re.search(r'destination\s+(\S+)', rule_text)
            if dst_match:
                destination = [dst_match.group(1)]
            
            # 提取服务
            service = ["any"]  # 默认任意
            svc_match = re.search(r'service\s+(\S+)', rule_text)
            if svc_match:
                service = [svc_match.group(1)]
            
            # 提取日志设置
            logging = "log" in rule_text.lower()
            
            # 创建策略条目
            policy = {
                "rule_id": str(rule_id),
                "name": f"{policy_name}_{class_name}",
                "action": action,
                "source_zone": "",
                "destination_zone": "",
                "source": source,
                "destination": destination,
                "service": service,
                "application": [],
                "enabled": True,
                "logging": logging,
                "description": f"ZTE policy: {policy_name}, class: {class_name}",
                "hit_count": None,
                "last_hit": None
            }
            
            policies.append(policy)
            rule_id += 10
    
    # 3. 尝试解析安全策略命令
    security_rules = re.finditer(r'security\s+policy\s+(\S+)[\s\S]*?(?=security\s+policy|\Z)', data)
    
    for rule_match in security_rules:
        policy_name = rule_match.group(1)
        rule_text = rule_match.group(0)
        
        # 提取源和目标区域
        src_zone = ""
        dst_zone = ""
        
        zone_match = re.search(r'from\s+(\S+)\s+to\s+(\S+)', rule_text)
        if zone_match:
            src_zone = zone_match.group(1)
            dst_zone = zone_match.group(2)
        
        # 提取源和目标地址
        source = ["any"]
        destination = ["any"]
        
        src_match = re.search(r'source-address\s+(\S+)', rule_text)
        if src_match:
            source = [src_match.group(1)]
            
        dst_match = re.search(r'destination-address\s+(\S+)', rule_text)
        if dst_match:
            destination = [dst_match.group(1)]
        
        # 提取动作
        action = "permit"
        action_match = re.search(r'action\s+(\S+)', rule_text)
        if action_match:
            action = action_match.group(1)
            if action in ["drop", "reject"]:
                action = "deny"
        
        # 提取服务
        service = ["any"]
        svc_match = re.search(r'service\s+(\S+)', rule_text)
        if svc_match:
            service = [svc_match.group(1)]
        
        # 提取日志设置
        logging = "log" in rule_text.lower() or "logging" in rule_text.lower()
        
        # 检查是否启用
        enabled = "disable" not in rule_text.lower()
        
        # 创建策略条目
        policy = {
            "rule_id": policy_name,
            "name": policy_name,
            "action": action,
            "source_zone": src_zone,
            "destination_zone": dst_zone,
            "source": source,
            "destination": destination,
            "service": service,
            "application": [],
            "enabled": enabled,
            "logging": logging,
            "description": f"ZTE security policy: {policy_name}",
            "hit_count": None,
            "last_hit": None
        }
        
        policies.append(policy)
    
    return policies

def parse_generic_policy(data: str) -> List[SecurityPolicyRule]:
    """通用策略解析方法，尝试识别和提取多种格式的安全策略"""
    policies = []
    
    # 1. 尝试解析ACL格式的策略（类似思科格式）
    cisco_policies = parse_cisco_acl(data)
    if cisco_policies:
        policies.extend(cisco_policies)
    
    # 2. 尝试解析通用策略格式
    # 匹配类似 "policy X from Y to Z source A destination B action C"的格式
    policy_matches = re.finditer(r'policy\s+(\S+)[\s\S]*?(?:from|source)[^\n]*?(?:to|destination)[^\n]*?(?:action|permit|deny|drop|reject)', data, re.IGNORECASE)
    
    for match in policy_matches:
        policy_name = match.group(1)
        policy_text = match.group(0)
        
        # 提取源和目标区域
        src_zone = ""
        dst_zone = ""
        zone_match = re.search(r'from\s+(\S+)\s+to\s+(\S+)', policy_text, re.IGNORECASE)
        if zone_match:
            src_zone = zone_match.group(1)
            dst_zone = zone_match.group(2)
        
        # 提取源和目标地址
        source = ["any"]
        destination = ["any"]
        
        src_match = re.search(r'source[:\s-]+(\S+)', policy_text, re.IGNORECASE)
        if src_match:
            source = [src_match.group(1)]
            
        dst_match = re.search(r'destination[:\s-]+(\S+)', policy_text, re.IGNORECASE)
        if dst_match:
            destination = [dst_match.group(1)]
        
        # 提取动作
        action = "permit"
        for action_keyword in ["permit", "deny", "drop", "reject"]:
            if action_keyword in policy_text.lower():
                action = "permit" if action_keyword == "permit" else "deny"
                break
                
        action_match = re.search(r'action[:\s-]+(\S+)', policy_text, re.IGNORECASE)
        if action_match:
            act = action_match.group(1).lower()
            if act in ["permit", "allow", "accept"]:
                action = "permit"
            elif act in ["deny", "drop", "reject", "block"]:
                action = "deny"
        
        # 提取服务/应用
        service = ["any"]
        service_match = re.search(r'service[:\s-]+(\S+)', policy_text, re.IGNORECASE)
        if service_match:
            service = [service_match.group(1)]
            
        application = []
        app_match = re.search(r'application[:\s-]+(\S+)', policy_text, re.IGNORECASE)
        if app_match:
            application = [app_match.group(1)]
        
        # 提取日志设置
        logging = "log" in policy_text.lower() or "logging" in policy_text.lower()
        
        # 提取启用状态
        enabled = "disable" not in policy_text.lower() and "inactive" not in policy_text.lower()
        
        # 提取命中次数
        hit_count = None
        hit_match = re.search(r'hit[s\s-]*(?:count)?[:\s-]+(\d+)', policy_text, re.IGNORECASE)
        if hit_match:
            try:
                hit_count = int(hit_match.group(1))
            except:
                pass
        
        # 创建策略条目
        policy = {
            "rule_id": policy_name,
            "name": policy_name,
            "action": action,
            "source_zone": src_zone,
            "destination_zone": dst_zone,
            "source": source,
            "destination": destination,
            "service": service,
            "application": application,
            "enabled": enabled,
            "logging": logging,
            "description": f"Generic policy: {policy_name}",
            "hit_count": hit_count,
            "last_hit": None
        }
        
        policies.append(policy)
    
    # 3. 尝试匹配单独的规则行
    if not policies:
        rule_patterns = [
            # 匹配 permit/deny IP source destination [port] 格式
            r'(permit|deny)\s+(\w+)\s+([^\s]+)\s+([^\s]+)(?:\s+(?:eq|gt|lt)\s+(\S+))?',
            # 匹配 action=permit src=X dst=Y 格式
            r'action=(\w+).*?src=([^\s,]+).*?dst=([^\s,]+)'
        ]
        
        rule_id = 10
        for pattern in rule_patterns:
            rule_matches = re.finditer(pattern, data, re.IGNORECASE)
            
            for match in rule_matches:
                if pattern.startswith('(permit|deny)'):
                    action = match.group(1)
                    protocol = match.group(2)
                    source = [match.group(3)]
                    destination = [match.group(4)]
                    service = [match.group(5)] if match.group(5) else [protocol]
                else:  # action=permit 格式
                    action = "permit" if match.group(1).lower() in ["permit", "allow", "accept"] else "deny"
                    source = [match.group(2)]
                    destination = [match.group(3)]
                    service = ["any"]
                
                policy = {
                    "rule_id": str(rule_id),
                    "name": f"Rule_{rule_id}",
                    "action": action,
                    "source_zone": "",
                    "destination_zone": "",
                    "source": source,
                    "destination": destination,
                    "service": service,
                    "application": [],
                    "enabled": True,
                    "logging": False,
                    "description": f"Generic rule: {rule_id}",
                    "hit_count": None,
                    "last_hit": None
                }
                
                policies.append(policy)
                rule_id += 10
    
    return policies

def find_shadowed_rules(policies: List[SecurityPolicyRule]) -> List[Dict[str, Any]]:
    """查找被其他规则遮蔽的可能规则"""
    shadowed_rules = []
    
    # 只检查启用的规则
    enabled_policies = [p for p in policies if p.get("enabled", True)]
    
    # 按规则ID排序，假设ID小的规则先匹配
    enabled_policies.sort(key=lambda x: x["rule_id"])
    
    for i, policy1 in enumerate(enabled_policies):
        for policy2 in enabled_policies[i+1:]:
            # 检查规则2是否可能被规则1遮蔽
            if potentially_shadowed(policy1, policy2):
                shadowed_rules.append({
                    "shadowed_rule": {
                        "rule_id": policy2["rule_id"],
                        "name": policy2.get("name", "")
                    },
                    "shadowing_rule": {
                        "rule_id": policy1["rule_id"],
                        "name": policy1.get("name", "")
                    },
                    "reason": generate_shadow_reason(policy1, policy2)
                })
    
    return shadowed_rules

def potentially_shadowed(policy1: SecurityPolicyRule, policy2: SecurityPolicyRule) -> bool:
    """检查policy2是否可能被policy1遮蔽"""
    # 如果动作不同，且policy1范围包含policy2，则可能存在遮蔽
    if policy1["action"] != policy2["action"]:
        # 检查zone是否匹配或包含
        if (not policy1["source_zone"] or not policy2["source_zone"] or 
            policy1["source_zone"] == policy2["source_zone"]):
            if (not policy1["destination_zone"] or not policy2["destination_zone"] or 
                policy1["destination_zone"] == policy2["destination_zone"]):
                
                # 检查source是否匹配或包含
                if contains_or_any(policy1["source"], policy2["source"]):
                    # 检查destination是否匹配或包含
                    if contains_or_any(policy1["destination"], policy2["destination"]):
                        # 检查service是否匹配或包含
                        if contains_or_any(policy1["service"], policy2["service"]):
                            return True
    
    # 如果动作相同，都是permit/deny，且有一个完全包含另一个但顺序不正确，可能是多余的
    if policy1["action"] == policy2["action"]:
        # 检查policy2是否完全包含在policy1中
        if (contains_all(policy1["source"], policy2["source"]) and
            contains_all(policy1["destination"], policy2["destination"]) and
            contains_all(policy1["service"], policy2["service"])):
            return True
    
    return False

def contains_or_any(list1: List[str], list2: List[str]) -> bool:
    """检查list1是否包含list2中的任何元素，或list1中是否有'any'"""
    if not list1 or not list2:
        return True
        
    if any(item.lower() == "any" for item in list1):
        return True
        
    for item1 in list1:
        for item2 in list2:
            if item1.lower() == item2.lower() or item2.lower() == "any":
                return True
                
    # 尝试检查IP网段包含关系
    try:
        for item1 in list1:
            if "any" in item1.lower():
                return True
                
            for item2 in list2:
                if "any" in item2.lower():
                    continue
                
                # 尝试解析IP地址/网段
                if "/" in item1 or "/" in item2:
                    net1 = ipaddress.ip_network(item1.split()[0].replace("host ", ""), strict=False)
                    net2 = ipaddress.ip_network(item2.split()[0].replace("host ", ""), strict=False)
                    
                    if net1.supernet_of(net2):
                        return True
    except:
        # 忽略IP解析错误
        pass
                
    return False

def contains_all(list1: List[str], list2: List[str]) -> bool:
    """检查list1是否完全包含list2中的所有元素"""
    if not list2:
        return True
        
    if any(item.lower() == "any" for item in list1):
        return True
        
    for item2 in list2:
        if item2.lower() == "any":
            return False  # list2有any但list1没有，则list1不完全包含list2
            
        found = False
        for item1 in list1:
            if item1.lower() == item2.lower():
                found = True
                break
                
        if not found:
            return False
                
    return True

def generate_shadow_reason(policy1: SecurityPolicyRule, policy2: SecurityPolicyRule) -> str:
    """生成规则遮蔽的原因说明"""
    if policy1["action"] != policy2["action"]:
        return f"规则 {policy1['rule_id']} 的动作为 {policy1['action']}，与规则 {policy2['rule_id']} 的动作 {policy2['action']} 不同，且前者匹配范围更广"
    else:
        return f"规则 {policy1['rule_id']} 与规则 {policy2['rule_id']} 动作相同，但前者匹配范围包含后者"

def generate_policy_recommendations(policies: List[SecurityPolicyRule], analysis: Dict) -> List[str]:
    """生成安全策略优化建议"""
    recommendations = []
    
    # 1. 建议删除或合并未使用的规则
    if analysis["unused_rules"] > 5:
        recommendations.append(f"发现 {analysis['unused_rules']} 条未被使用的规则，建议定期清理或合并这些规则以提高性能")
    
    # 2. 建议避免使用过于宽泛的规则
    if analysis["rules_with_any_source"] > analysis["total_rules"] * 0.3:
        recommendations.append(f"有 {analysis['rules_with_any_source']} 条规则使用了'Any'作为源地址，占比 {analysis['rules_with_any_source']/analysis['total_rules']*100:.1f}%，建议限制源地址范围以提高安全性")
    
    if analysis["rules_with_any_destination"] > analysis["total_rules"] * 0.3:
        recommendations.append(f"有 {analysis['rules_with_any_destination']} 条规则使用了'Any'作为目标地址，占比 {analysis['rules_with_any_destination']/analysis['total_rules']*100:.1f}%，建议限制目标地址范围以提高安全性")
    
    if analysis["rules_with_any_service"] > analysis["total_rules"] * 0.3:
        recommendations.append(f"有 {analysis['rules_with_any_service']} 条规则使用了'Any'作为服务，占比 {analysis['rules_with_any_service']/analysis['total_rules']*100:.1f}%，建议限制服务范围以提高安全性")
    
    # 3. 建议开启日志记录
    if analysis["rules_without_logging"] > analysis["total_rules"] * 0.5:
        recommendations.append(f"有 {analysis['rules_without_logging']} 条规则未开启日志，占比 {analysis['rules_without_logging']/analysis['total_rules']*100:.1f}%，建议对重要规则开启日志以便于审计和排障")
    
    # 4. 建议处理遮蔽规则
    if len(analysis["shadowed_rules"]) > 0:
        recommendations.append(f"发现 {len(analysis['shadowed_rules'])} 条可能被遮蔽的规则，建议检查这些规则的顺序和配置，避免策略失效")
    
    # 5. 建议关注热点规则性能
    if analysis["top_hit_rules"] and analysis["top_hit_rules"][0].get("hit_count", 0) > 10000:
        recommendations.append(f"规则 {analysis['top_hit_rules'][0]['rule_id']} 命中次数过高 ({analysis['top_hit_rules'][0]['hit_count']}次)，建议考虑优化该规则的匹配条件或调整策略顺序以提高性能")
    
    # 6. 建议定期优化策略
    recommendations.append("建议定期执行安全策略优化工作：合并相似规则、移除过期规则、优化规则顺序")
    
    # 7. 基于规则总数的建议
    if analysis["total_rules"] > 100:
        recommendations.append(f"安全策略规则数量较多 ({analysis['total_rules']} 条)，建议考虑使用策略组或对象组来简化管理")
    
    return recommendations 