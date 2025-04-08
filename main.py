from __future__ import annotations
from typing import Optional, Literal, TypedDict, List, Dict, Any, Union, Callable, cast
from enum import Enum
import re
import psutil
import paramiko
import functools
import logging
import platform
import socket
import datetime
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP
from io import StringIO

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('server_monitor')

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
    """Docker镜像信息数据结构"""
    image_id: str
    repository: str
    tag: str
    created: str
    size: str

class VolumeInfo(TypedDict):
    """Docker卷信息数据结构"""
    name: str
    mountpoint: str
    driver: str
    created: str
    size: Optional[str]

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

class ServerInspector:
    """服务器指标解析器"""

    # 缓存解析结果
    _parse_cache = {}

    @classmethod
    def _cached_parse(cls, parser_func: Callable, cache_key: str, raw_output: str, max_age: int = 60):
        """带缓存的解析函数"""
        current_time = datetime.datetime.now()

        # 检查缓存
        if cache_key in cls._parse_cache:
            cached_result, timestamp = cls._parse_cache[cache_key]
            # 检查缓存是否过期
            if (current_time - timestamp).total_seconds() < max_age:
                return cached_result

        # 执行解析
        result = parser_func(raw_output)

        # 更新缓存
        cls._parse_cache[cache_key] = (result, current_time)
        return result

    @classmethod
    def parse_cpu(cls, raw_output: str) -> CPUStats:
        """解析CPU使用率和负载"""
        def _parser(output):
            try:
                cpu_usage = re.search(r'(\d+\.\d+)%? id', output)
                load_avg = re.search(r'load average: ([\d\.]+), ([\d\.]+), ([\d\.]+)', output)
                return {
                    "usage": 100 - float(cpu_usage.group(1)) if cpu_usage else None,
                    "loadavg": ", ".join(load_avg.groups()) if load_avg else None
                }
            except Exception as e:
                logger.error(f"Error parsing CPU stats: {str(e)}")
                return {"usage": None, "loadavg": None}

        cache_key = f"cpu_{hash(raw_output)}"
        return cls._cached_parse(_parser, cache_key, raw_output)

    @classmethod
    def parse_memory(cls, raw_output: str) -> ServerMetric:
        """解析内存使用情况"""
        def _parser(output):
            try:
                mem_lines = [line.split() for line in output.split('\n') if line]
                if len(mem_lines) < 2 or len(mem_lines[1]) < 6:
                    logger.warning(f"Unexpected memory output format: {output}")
                    return ServerMetric(total=0, used=0, free=0, usage=0)

                total = int(mem_lines[1][1]) / 1024  # 转换为GB
                used = (int(mem_lines[1][2]) - int(mem_lines[1][5])) / 1024
                return ServerMetric(
                    total=round(total, 2),
                    used=round(used, 2),
                    free=round(total - used, 2),
                    usage=round(used / total * 100, 1) if total > 0 else 0
                )
            except Exception as e:
                logger.error(f"Error parsing memory stats: {str(e)}")
                return ServerMetric(total=0, used=0, free=0, usage=0)

        cache_key = f"memory_{hash(raw_output)}"
        return cls._cached_parse(_parser, cache_key, raw_output)

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

# 定义装饰器用于统一错误处理
def handle_exceptions(func):
    """装饰器：统一处理工具函数中的异常"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except paramiko.AuthenticationException as e:
            logger.error(f"SSH authentication failed in {func.__name__}: {str(e)}")
            return {"status": "error", "error": f"SSH认证失败: {str(e)}"}
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error in {func.__name__}: {str(e)}")
            return {"status": "error", "error": f"SSH连接错误: {str(e)}"}
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {str(e)}", exc_info=True)
            return {"status": "error", "error": f"执行失败: {str(e)}"}
    return wrapper

# ======================
# 工具函数
# ======================
@mcp.tool()
@handle_exceptions
def get_memory_info() -> dict:
    """获取本地服务器内存信息"""
    mem = psutil.virtual_memory()
    return {
        "status": "success",
        "total": mem.total,
        "used": mem.used,
        "free": mem.free,
        "usage": mem.percent,
        "available": mem.available,
        "cached": getattr(mem, 'cached', 0),
        "buffers": getattr(mem, 'buffers', 0)
    }

@mcp.tool()
@handle_exceptions
def remote_server_inspection(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    inspection_modules: list[str] = ["cpu", "memory", "disk"],
    timeout: int = 30,
    use_connection_cache: bool = True
) -> dict:
    """执行远程服务器巡检"""
    result = InspectionResult()
    logger
<<<<<<< HEAD
[已获取的main.py完整内容]
=======
from __future__ import annotations
from typing import Optional, Literal, TypedDict, List, Dict, Any, Union, Callable, cast
from enum import Enum
import re
import psutil
import paramiko
import functools
import logging
import platform
import socket
import datetime
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP
from io import StringIO

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('server_monitor')

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
    """Docker镜像信息数据结构"""
    image_id: str
    repository: str
    tag: str
    created: str
    size: str

class VolumeInfo(TypedDict):
    """Docker卷信息数据结构"""
    name: str
    mountpoint: str
    driver: str
    created: str
    size: Optional[str]

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

class ServerInspector:
    """服务器指标解析器"""

    # 缓存解析结果
    _parse_cache = {}

    @classmethod
    def _cached_parse(cls, parser_func: Callable, cache_key: str, raw_output: str, max_age: int = 60):
        """带缓存的解析函数"""
        current_time = datetime.datetime.now()

        # 检查缓存
        if cache_key in cls._parse_cache:
            cached_result, timestamp = cls._parse_cache[cache_key]
            # 检查缓存是否过期
            if (current_time - timestamp).total_seconds() < max_age:
                return cached_result

        # 执行解析
        result = parser_func(raw_output)

        # 更新缓存
        cls._parse_cache[cache_key] = (result, current_time)
        return result

    @classmethod
    def parse_cpu(cls, raw_output: str) -> CPUStats:
        """解析CPU使用率和负载"""
        def _parser(output):
            try:
                cpu_usage = re.search(r'(\d+\.\d+)%? id', output)
                load_avg = re.search(r'load average: ([\d\.]+), ([\d\.]+), ([\d\.]+)', output)
                return {
                    "usage": 100 - float(cpu_usage.group(1)) if cpu_usage else None,
                    "loadavg": ", ".join(load_avg.groups()) if load_avg else None
                }
            except Exception as e:
                logger.error(f"Error parsing CPU stats: {str(e)}")
                return {"usage": None, "loadavg": None}

        cache_key = f"cpu_{hash(raw_output)}"
        return cls._cached_parse(_parser, cache_key, raw_output)

    @classmethod
    def parse_memory(cls, raw_output: str) -> ServerMetric:
        """解析内存使用情况"""
        def _parser(output):
            try:
                mem_lines = [line.split() for line in output.split('\n') if line]
                if len(mem_lines) < 2 or len(mem_lines[1]) < 6:
                    logger.warning(f"Unexpected memory output format: {output}")
                    return ServerMetric(total=0, used=0, free=0, usage=0)

                total = int(mem_lines[1][1]) / 1024  # 转换为GB
                used = (int(mem_lines[1][2]) - int(mem_lines[1][5])) / 1024
                return ServerMetric(
                    total=round(total, 2),
                    used=round(used, 2),
                    free=round(total - used, 2),
                    usage=round(used / total * 100, 1) if total > 0 else 0
                )
            except Exception as e:
                logger.error(f"Error parsing memory stats: {str(e)}")
                return ServerMetric(total=0, used=0, free=0, usage=0)

        cache_key = f"memory_{hash(raw_output)}"
        return cls._cached_parse(_parser, cache_key, raw_output)

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

# 定义装饰器用于统一错误处理
def handle_exceptions(func):
    """装饰器：统一处理工具函数中的异常"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except paramiko.AuthenticationException as e:
            logger.error(f"SSH authentication failed in {func.__name__}: {str(e)}")
            return {"status": "error", "error": f"SSH认证失败: {str(e)}"}
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error in {func.__name__}: {str(e)}")
            return {"status": "error", "error": f"SSH连接错误: {str(e)}"}
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {str(e)}", exc_info=True)
            return {"status": "error", "error": f"执行失败: {str(e)}"}
    return wrapper

# ======================
# 工具函数
# ======================
@mcp.tool()
@handle_exceptions
def get_memory_info() -> dict:
    """获取本地服务器内存信息"""
    mem = psutil.virtual_memory()
    return {
        "status": "success",
        "total": mem.total,
        "used": mem.used,
        "free": mem.free,
        "usage": mem.percent,
        "available": mem.available,
        "cached": getattr(mem, 'cached', 0),
        "buffers": getattr(mem, 'buffers', 0)
    }

@mcp.tool()
@handle_exceptions
def remote_server_inspection(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    inspection_modules: list[str] = ["cpu", "memory", "disk"],
    timeout: int = 30,
    use_connection_cache: bool = True
) -> dict:
    """执行远程服务器巡检"""
    result = InspectionResult()
    logger.info(f"开始对 {hostname} 执行服务器巡检，模块: {inspection_modules}")

    # 定义命令映射，使用更高效的命令
    commands = {
        "cpu": "top -bn1 | grep 'Cpu(s)' && uptime",
        "memory": "free -m",
        "disk": "df -h",
        # 添加更多模块的命令
        "io": "iostat -x 1 2 | tail -n +4",
        "network": "netstat -i"
    }

    # 验证模块
    valid_modules = [m for m in inspection_modules if m in commands]
    if len(valid_modules) != len(inspection_modules):
        invalid_modules = set(inspection_modules) - set(valid_modules)
        logger.warning(f"忽略无效的巡检模块: {invalid_modules}")

    # 如果没有有效模块，提前返回
    if not valid_modules:
        result.status = "error"
        result.error = "没有有效的巡检模块"
        result.summary = "巡检失败：没有有效的巡检模块"
        return result.dict()

    # 使用优化的SSH连接管理器
    with SSHManager(hostname, username, password, port, timeout, use_cache=use_connection_cache) as ssh:
        # 并行执行所有命令
        module_results = {}
        for module in valid_modules:
            try:
                # 执行命令
                stdin, stdout, stderr = ssh.exec_command(commands[module], timeout=timeout)
                raw_output = stdout.read().decode().strip()
                error_output = stderr.read().decode().strip()

                if error_output:
                    logger.warning(f"模块 {module} 执行时有错误输出: {error_output}")

                result.raw_outputs[module] = raw_output

                # 解析结果
                if not raw_output:
                    logger.warning(f"模块 {module} 没有输出")
                    continue

                # 使用模式匹配解析不同模块的输出
                match module:
                    case "cpu":
                        result.data[module] = ServerInspector.parse_cpu(raw_output)
                    case "memory":
                        result.data[module] = ServerInspector.parse_memory(raw_output).dict()
                    case "disk":
                        result.data[module] = ServerInspector.parse_disk(raw_output)
                    case "io":
                        # 这里可以添加IO解析逻辑
                        pass
                    case "network":
                        # 这里可以添加网络解析逻辑
                        pass

                module_results[module] = "success"
            except Exception as e:
                logger.error(f"模块 {module} 执行失败: {str(e)}")
                module_results[module] = f"failed: {str(e)}"

        # 生成摘要
        success_modules = [m for m, status in module_results.items() if status == "success"]
        failed_modules = [m for m, status in module_results.items() if status != "success"]

        if failed_modules:
            if success_modules:
                result.summary = f"部分模块巡检成功 ({len(success_modules)}/{len(valid_modules)})"
            else:
                result.summary = "所有模块巡检失败"
        else:
            result.summary = "服务器巡检成功"

        result.status = "error" if not success_modules else "success"

    logger.info(f"完成对 {hostname} 的服务器巡检，状态: {result.status}")
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

def cleanup_resources():
    """清理资源"""
    SSHManager.clear_cache()
    network_tools.SSHManager.clear_cache()  # 同时清理网络工具的SSH连接缓存
    logger.info("Cleaned up all resources")

@mcp.tool()
def list_docker_containers(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    show_all: bool = False,  # 是否显示所有容器，包括已停止的
    timeout: int = 30
) -> dict:
    """列出Docker容器及其信息"""
    result = InspectionResult()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 检查Docker是否安装
            stdin, stdout, stderr = ssh.exec_command("command -v docker")
            if not stdout.read().strip():
                result.status = "error"
                result.error = "Docker未安装在目标服务器上"
                return result.dict()
            
            # 列出容器
            cmd = "docker ps --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.CreatedAt}}|{{.Ports}}'"
            if show_all:
                cmd += " -a"
                
            stdin, stdout, stderr = ssh.exec_command(cmd)
            container_output = stdout.read().decode('utf-8')
            
            # 获取容器资源使用情况
            stdin, stdout, stderr = ssh.exec_command("docker stats --no-stream --format '{{.ID}}|{{.CPUPerc}}|{{.MemPerc}}'")
            stats_output = stdout.read().decode('utf-8')
            
            # 处理结果
            containers = []
            stats_map = {}
            
            # 解析资源使用情况
            for line in stats_output.strip().split('\n'):
                if line:
                    parts = line.split('|')
                    if len(parts) >= 3:
                        container_id = parts[0]
                        cpu_perc = parts[1].replace('%', '') if parts[1] else "0"
                        mem_perc = parts[2].replace('%', '') if parts[2] else "0"
                        
                        try:
                            stats_map[container_id] = {
                                'cpu_usage': float(cpu_perc),
                                'memory_usage': float(mem_perc)
                            }
                        except ValueError:
                            stats_map[container_id] = {
                                'cpu_usage': 0.0,
                                'memory_usage': 0.0
                            }
            
            # 解析容器列表
            for line in container_output.strip().split('\n'):
                if line:
                    parts = line.split('|')
                    if len(parts) >= 6:
                        container_id = parts[0]
                        container_info = ContainerInfo(
                            container_id=container_id,
                            name=parts[1],
                            image=parts[2],
                            status=parts[3],
                            created=parts[4],
                            ports=parts[5],
                            cpu_usage=stats_map.get(container_id, {}).get('cpu_usage'),
                            memory_usage=stats_map.get(container_id, {}).get('memory_usage')
                        )
                        containers.append(container_info)
            
            # 设置结果
            result.status = "success"
            result.data = {"containers": containers}
            result.raw_outputs = {"container_list": container_output, "stats": stats_output}
            result.summary = f"发现 {len(containers)} 个容器"
            
    except Exception as e:
        result.status = "error"
        result.error = f"获取Docker容器信息失败: {str(e)}"
    
    return result.dict()

@mcp.tool()
def list_docker_images(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    timeout: int = 30
) -> dict:
    """列出Docker镜像"""
    result = InspectionResult()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 检查Docker是否安装
            stdin, stdout, stderr = ssh.exec_command("command -v docker")
            if not stdout.read().strip():
                result.status = "error"
                result.error = "Docker未安装在目标服务器上"
                return result.dict()
            
            # 列出镜像
            cmd = "docker images --format '{{.ID}}|{{.Repository}}|{{.Tag}}|{{.CreatedAt}}|{{.Size}}'"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            image_output = stdout.read().decode('utf-8')
            
            # 处理结果
            images = []
            
            # 解析镜像列表
            for line in image_output.strip().split('\n'):
                if line:
                    parts = line.split('|')
                    if len(parts) >= 5:
                        image_info = ImageInfo(
                            image_id=parts[0],
                            repository=parts[1],
                            tag=parts[2],
                            created=parts[3],
                            size=parts[4]
                        )
                        images.append(image_info)
            
            # 设置结果
            result.status = "success"
            result.data = {"images": images}
            result.raw_outputs = {"image_list": image_output}
            result.summary = f"发现 {len(images)} 个Docker镜像"
            
    except Exception as e:
        result.status = "error"
        result.error = f"获取Docker镜像信息失败: {str(e)}"
    
    return result.dict()

@mcp.tool()
def list_docker_volumes(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    timeout: int = 30
) -> dict:
    """列出Docker卷"""
    result = InspectionResult()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 检查Docker是否安装
            stdin, stdout, stderr = ssh.exec_command("command -v docker")
            if not stdout.read().strip():
                result.status = "error"
                result.error = "Docker未安装在目标服务器上"
                return result.dict()
            
            # 列出卷
            cmd = "docker volume ls --format '{{.Name}}|{{.Driver}}|{{.Mountpoint}}'"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            volume_output = stdout.read().decode('utf-8')
            
            # 处理结果
            volumes = []
            
            # 解析卷列表
            for line in volume_output.strip().split('\n'):
                if line:
                    parts = line.split('|')
                    if len(parts) >= 3:
                        # 尝试获取卷大小（非标准功能，可能需要自定义脚本）
                        size = None
                        try:
                            stdin, stdout, stderr = ssh.exec_command(f"sudo du -sh {parts[2]}")
                            size_output = stdout.read().decode('utf-8').strip()
                            if size_output:
                                size = size_output.split()[0]
                        except:
                            pass
                        
                        volume_info = VolumeInfo(
                            name=parts[0],
                            driver=parts[1],
                            mountpoint=parts[2],
                            created="N/A",  # Docker命令不直接提供创建时间
                            size=size
                        )
                        volumes.append(volume_info)
            
            # 获取更详细的卷信息(包括创建时间)
            for volume in volumes:
                try:
                    stdin, stdout, stderr = ssh.exec_command(f"docker volume inspect {volume['name']}")
                    inspect_output = stdout.read().decode('utf-8')
                    if "CreatedAt" in inspect_output:
                        import json
                        inspect_data = json.loads(inspect_output)
                        if inspect_data and len(inspect_data) > 0 and "CreatedAt" in inspect_data[0]:
                            volume["created"] = inspect_data[0]["CreatedAt"]
                except:
                    pass
            
            # 设置结果
            result.status = "success"
            result.data = {"volumes": volumes}
            result.raw_outputs = {"volume_list": volume_output}
            result.summary = f"发现 {len(volumes)} 个Docker卷"
            
    except Exception as e:
        result.status = "error"
        result.error = f"获取Docker卷信息失败: {str(e)}"
    
    return result.dict()

@mcp.tool()
def get_container_logs(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    container: str = "",  # 容器ID或名称
    tail: int = 100,  # 获取最后多少行日志
    since: str = "",  # 从什么时间开始的日志，例如 "2023-01-01T00:00:00"
    timeout: int = 30
) -> dict:
    """获取指定容器的日志"""
    result = InspectionResult()
    
    if not container:
        result.status = "error"
        result.error = "必须指定容器ID或名称"
        return result.dict()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 检查Docker是否安装
            stdin, stdout, stderr = ssh.exec_command("command -v docker")
            if not stdout.read().strip():
                result.status = "error"
                result.error = "Docker未安装在目标服务器上"
                return result.dict()
            
            # 构建命令
            cmd = f"docker logs --tail {tail}"
            if since:
                cmd += f" --since '{since}'"
            cmd += f" {container}"
            
            # 执行命令
            stdin, stdout, stderr = ssh.exec_command(cmd)
            log_output = stdout.read().decode('utf-8')
            error_output = stderr.read().decode('utf-8')
            
            if error_output:
                result.status = "error"
                result.error = f"获取容器日志失败: {error_output}"
                return result.dict()
            
            # 设置结果
            result.status = "success"
            result.data = {"logs": log_output.strip().split("\n")}
            result.raw_outputs = {"container_logs": log_output}
            
            log_lines = len(log_output.strip().split("\n")) if log_output.strip() else 0
            result.summary = f"获取到容器 {container} 的 {log_lines} 行日志"
            
    except Exception as e:
        result.status = "error"
        result.error = f"获取容器日志失败: {str(e)}"
    
    return result.dict()

@mcp.tool()
def monitor_container_stats(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    containers: list[str] = [],  # 容器ID或名称列表，空列表表示所有容器
    timeout: int = 30
) -> dict:
    """监控容器的资源使用情况"""
    result = InspectionResult()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 检查Docker是否安装
            stdin, stdout, stderr = ssh.exec_command("command -v docker")
            if not stdout.read().strip():
                result.status = "error"
                result.error = "Docker未安装在目标服务器上"
                return result.dict()
            
            # 构建命令
            container_list = " ".join(containers) if containers else ""
            cmd = f"docker stats --no-stream --format '{{{{.Name}}}}|{{{{.ID}}}}|{{{{.CPUPerc}}}}|{{{{.MemUsage}}}}|{{{{.MemPerc}}}}|{{{{.NetIO}}}}|{{{{.BlockIO}}}}|{{{{.PIDs}}}}' {container_list}"
            
            # 执行命令
            stdin, stdout, stderr = ssh.exec_command(cmd)
            stats_output = stdout.read().decode('utf-8')
            error_output = stderr.read().decode('utf-8')
            
            if error_output:
                result.status = "error"
                result.error = f"获取容器状态失败: {error_output}"
                return result.dict()
            
            # 处理结果
            container_stats = []
            for line in stats_output.strip().split('\n'):
                if line:
                    parts = line.split('|')
                    if len(parts) >= 8:
                        try:
                            cpu_perc = float(parts[2].replace('%', ''))
                        except:
                            cpu_perc = 0.0
                            
                        try:
                            mem_perc = float(parts[4].replace('%', ''))
                        except:
                            mem_perc = 0.0
                            
                        try:
                            pids = int(parts[7])
                        except:
                            pids = 0
                        
                        container_stat = {
                            "name": parts[0],
                            "id": parts[1],
                            "cpu_percent": cpu_perc,
                            "memory_usage": parts[3],
                            "memory_percent": mem_perc,
                            "network_io": parts[5],
                            "block_io": parts[6],
                            "pids": pids
                        }
                        container_stats.append(container_stat)
            
            # 设置结果
            result.status = "success"
            result.data = {"stats": container_stats}
            result.raw_outputs = {"container_stats": stats_output}
            result.summary = f"获取到 {len(container_stats)} 个容器的资源使用情况"
            
    except Exception as e:
        result.status = "error"
        result.error = f"监控容器状态失败: {str(e)}"
    
    return result.dict()

@mcp.tool()
def check_docker_health(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    timeout: int = 30
) -> dict:
    """检查Docker服务的健康状态和基本信息"""
    result = InspectionResult()
    
    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 检查Docker是否安装
            stdin, stdout, stderr = ssh.exec_command("command -v docker")
            if not stdout.read().strip():
                result.status = "error"
                result.error = "Docker未安装在目标服务器上"
                return result.dict()
            
            # 执行多个命令收集Docker信息
            cmds = {
                "version": "docker version --format '{{.Server.Version}}'",
                "info": "docker info --format '{{.ServerVersion}}|{{.ContainersRunning}}/{{.Containers}}|{{.Images}}|{{.Driver}}|{{.MemTotal}}'",
                "system_df": "docker system df",
                "service_status": "systemctl is-active docker",
                "docker_ps": "docker ps --quiet | wc -l"
            }
            
            outputs = {}
            for key, cmd in cmds.items():
                stdin, stdout, stderr = ssh.exec_command(cmd)
                outputs[key] = stdout.read().decode('utf-8').strip()
                error = stderr.read().decode('utf-8').strip()
                if error and not outputs[key]:
                    outputs[key] = f"Error: {error}"
            
            # 处理Docker信息输出
            docker_info = {}
            health_status = "healthy"
            
            # 处理版本信息
            docker_info["version"] = outputs["version"]
            
            # 处理基本信息
            if '|' in outputs["info"]:
                info_parts = outputs["info"].split('|')
                if len(info_parts) >= 5:
                    docker_info["server_version"] = info_parts[0]
                    container_parts = info_parts[1].split('/')
                    docker_info["running_containers"] = int(container_parts[0]) if container_parts[0].isdigit() else 0
                    docker_info["total_containers"] = int(container_parts[1]) if container_parts[1].isdigit() else 0
                    docker_info["images"] = int(info_parts[2]) if info_parts[2].isdigit() else 0
                    docker_info["storage_driver"] = info_parts[3]
                    docker_info["memory_total"] = info_parts[4]
            
            # 处理磁盘使用情况
            docker_info["disk_usage"] = outputs["system_df"]
            
            # 处理服务状态
            docker_info["service_active"] = outputs["service_status"] == "active"
            if not docker_info["service_active"]:
                health_status = "unhealthy"
            
            # 检查是否可以运行容器
            try:
                stdin, stdout, stderr = ssh.exec_command("docker run --rm hello-world")
                hello_output = stdout.read().decode('utf-8')
                if "Hello from Docker!" in hello_output:
                    docker_info["can_run_containers"] = True
                else:
                    docker_info["can_run_containers"] = False
                    health_status = "degraded"
            except Exception:
                docker_info["can_run_containers"] = False
                health_status = "degraded"
            
            # 设置结果
            result.status = "success"
            result.data = {
                "docker_info": docker_info,
                "health_status": health_status
            }
            result.raw_outputs = outputs
            
            if health_status == "healthy":
                result.summary = f"Docker服务健康状态良好，版本 {docker_info.get('version', 'unknown')}，{docker_info.get('running_containers', 0)} 个运行中的容器"
            elif health_status == "degraded":
                result.summary = f"Docker服务状态降级，可能存在功能限制"
            else:
                result.summary = f"Docker服务不健康，可能无法正常工作"
            
    except Exception as e:
        result.status = "error"
        result.error = f"检查Docker健康状态失败: {str(e)}"
    
    return result.dict()

if __name__ == "__main__":
    mcp.run(transport='stdio')



