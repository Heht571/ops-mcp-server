from typing import List
import logging
from mcp.server.fastmcp import FastMCP
from network_tools.models.base_models import InspectionResult
from network_tools.managers.ssh_manager import SSHManager
from network_tools.inspectors.network_inspector import NetworkInspector

# 配置日志
logger = logging.getLogger('network_tools.config_tools')

# 创建MCP实例
mcp = FastMCP(__name__)

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