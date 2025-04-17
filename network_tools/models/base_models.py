from __future__ import annotations
from typing import Optional, Literal, TypedDict, List, Dict, Any, Union
from pydantic import BaseModel, Field
from enum import Enum

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

class DevicePerformance(TypedDict):
    """设备性能数据结构"""
    cpu_usage: str  # CPU使用率
    memory_usage: str  # 内存使用率
    temperature: str  # 温度
    interface_traffic: List[Dict[str, str]]  # 接口流量信息
    buffer_usage: str  # 缓冲区使用率
    process_info: List[Dict[str, str]]  # 关键进程信息

class LogEntry(TypedDict):
    """日志条目数据结构"""
    timestamp: str
    log_level: str
    component: str
    message: str
    source_ip: Optional[str]
    username: Optional[str]
    event_type: str
    target: Optional[str]
    
class LogAnalysisResult(TypedDict):
    """日志分析结果数据结构"""
    log_count: int
    auth_success_count: int
    auth_failure_count: int
    config_change_count: int
    system_events_count: int
    error_events_count: int
    warning_events_count: int
    unusual_access_ips: List[Dict[str, str]]
    unusual_access_times: List[Dict[str, str]]
    top_users: List[Dict[str, Any]]
    time_distribution: Dict[str, int]
    recent_config_changes: List[Dict[str, str]]

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
    ZTE = "zte"  # 中兴
    UNKNOWN = "unknown"

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
    ANALYZE_DEVICE_LOGS = "analyze_device_logs"  # 新增设备日志分析工具
    CHECK_DEVICE_SESSIONS = "check_device_sessions"  # 新增设备会话连接信息工具
    ANALYZE_SECURITY_POLICY = "analyze_security_policy"  # 新增安全策略分析工具

# ======================
# 会话信息数据模型
# ======================
class DeviceSession(TypedDict):
    """设备会话连接信息"""
    session_id: str
    protocol: str  # SSH, Telnet, Console等
    source_ip: str
    source_port: str
    destination_ip: str
    destination_port: str
    username: str
    login_time: str
    idle_time: str
    status: str  # active, idle等

class DeviceSessionsResult(TypedDict):
    """设备会话连接分析结果"""
    total_sessions: int
    active_sessions: int
    idle_sessions: int
    sessions_by_protocol: Dict[str, int]
    top_source_ips: List[Dict[str, Any]]
    top_users: List[Dict[str, Any]]
    recent_logins: List[DeviceSession]
    sessions: List[DeviceSession]

# ======================
# 安全策略数据模型
# ======================
class SecurityPolicyRule(TypedDict):
    """安全策略规则"""
    rule_id: str
    name: str
    action: str  # allow, deny, reject等
    source_zone: str
    destination_zone: str
    source: List[str]
    destination: List[str]
    service: List[str]
    application: List[str]
    enabled: bool
    logging: bool
    description: str
    hit_count: Optional[int]
    last_hit: Optional[str]

class SecurityPolicyAnalysisResult(TypedDict):
    """安全策略分析结果"""
    total_rules: int
    enabled_rules: int
    disabled_rules: int
    rules_with_any_source: int
    rules_with_any_destination: int
    rules_with_any_service: int
    rules_without_logging: int
    unused_rules: int
    top_hit_rules: List[Dict[str, Any]]
    shadowed_rules: List[Dict[str, Any]]
    policy_recommendations: List[str]
    rules: List[SecurityPolicyRule] 