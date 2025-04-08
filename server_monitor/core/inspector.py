"""服务器指标解析器模块"""

import re
import datetime
from typing import Callable, Tuple, Dict, List
import datetime
from server_monitor.config.logger import logger
from server_monitor.models.schemas import (
    ServerMetric, CPUStats, DiskInfo, LoginRecord, 
    NetworkInterface, ProcessInfo, ServiceStatus
)

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
    def parse_disk(raw_output: str) -> List[DiskInfo]:
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
    def parse_auth_log(raw_log: str) -> Tuple[Dict[str, int], List[LoginRecord]]:
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
    def parse_processes(raw_output: str) -> List[ProcessInfo]:
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
    def parse_services(raw_output: str) -> List[ServiceStatus]:
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
    def parse_network_interfaces(raw_output: str) -> List[NetworkInterface]:
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