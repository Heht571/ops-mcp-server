"""数据模型定义"""

from typing import Optional, Literal, TypedDict, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field

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

class ContainerInfo(TypedDict):
    """容器信息数据结构"""
    container_id: str
    name: str
    image: str
    status: str
    created: str
    ports: str
    cpu_usage: Optional[float]
    memory_usage: Optional[float]

class ImageInfo(TypedDict):
    """镜像信息数据结构"""
    repository: str
    tag: str
    image_id: str
    created: str
    size: str

class VolumeInfo(TypedDict):
    """卷信息数据结构"""
    volume_name: str
    driver: str
    mountpoint: str

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
    # 新增容器相关工具
    DOCKER_CONTAINERS = "list_docker_containers"  # 列出Docker容器
    DOCKER_IMAGES = "list_docker_images"  # 列出Docker镜像
    DOCKER_VOLUMES = "list_docker_volumes"  # 列出Docker卷
    CONTAINER_LOGS = "get_container_logs"  # 获取容器日志
    CONTAINER_STATS = "monitor_container_stats"  # 监控容器状态
    DOCKER_HEALTHCHECK = "check_docker_health"  # 检查Docker服务健康状态
