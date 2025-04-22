"""服务器指标解析器模块"""

import re
import datetime
from typing import Callable, Tuple, Dict, List
import datetime
import logging

# 配置日志
logger = logging.getLogger('inspector')

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
    def parse_cpu(cls, raw_output: str) -> Dict:
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
    def parse_memory(cls, raw_output: str) -> Dict:
        """解析内存使用情况"""
        def _parser(output):
            try:
                mem_lines = [line.split() for line in output.split('\n') if line]
                if len(mem_lines) < 2 or len(mem_lines[1]) < 6:
                    logger.warning(f"Unexpected memory output format: {output}")
                    return {"total": 0, "used": 0, "free": 0, "usage": 0}

                total = int(mem_lines[1][1]) / 1024  # 转换为GB
                used = (int(mem_lines[1][2]) - int(mem_lines[1][5])) / 1024
                return {
                    "total": round(total, 2),
                    "used": round(used, 2),
                    "free": round(total - used, 2),
                    "usage": round(used / total * 100, 1) if total > 0 else 0
                }
            except Exception as e:
                logger.error(f"Error parsing memory stats: {str(e)}")
                return {"total": 0, "used": 0, "free": 0, "usage": 0}

        cache_key = f"memory_{hash(raw_output)}"
        return cls._cached_parse(_parser, cache_key, raw_output)

    @classmethod
    def parse_disk(cls, raw_output: str) -> List[Dict]:
        """解析磁盘使用情况"""
        def _parser(output):
            disks = []
            try:
                lines = output.strip().split('\n')
                for line in lines[1:]:  # 跳过标题行
                    parts = line.split()
                    if len(parts) >= 6:
                        # 提取使用率百分比
                        usage_str = parts[4]
                        usage = float(usage_str.rstrip('%')) if '%' in usage_str else 0

                        disks.append({
                            "mount_point": parts[5],
                            "total": parts[1],
                            "used": parts[2],
                            "usage": usage
                        })
                return disks
            except Exception as e:
                logger.error(f"Error parsing disk stats: {str(e)}")
                return []

        cache_key = f"disk_{hash(raw_output)}"
        return cls._cached_parse(_parser, cache_key, raw_output)

    @staticmethod
    def parse_auth_log(raw_log: str) -> Tuple[Dict[str, int], List[Dict]]:
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
    def parse_processes(raw_output: str) -> List[Dict]:
        """解析进程信息"""
        processes = []
        lines = raw_output.strip().split('\n')
        if len(lines) <= 1:
            return processes

        # 跳过标题行
        for line in lines[1:]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                try:
                    processes.append({
                        "pid": int(parts[1]),
                        "user": parts[0],
                        "cpu_percent": float(parts[2]),
                        "memory_percent": float(parts[3]),
                        "status": parts[7],
                        "created": parts[8] + " " + parts[9],
                        "name": parts[10]
                    })
                except (ValueError, IndexError) as e:
                    logger.warning(f"Error parsing process line: {line}, error: {str(e)}")
                    continue

        return processes

    @staticmethod
    def parse_services(raw_output: str) -> List[Dict]:
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
    def parse_network_interfaces(raw_output: str) -> List[Dict]:
        """解析网络接口信息"""
        interfaces = []
        current_interface = None
        ip_address = ""
        mac_address = ""

        for line in raw_output.split('\n'):
            # 新接口开始
            if line.strip() and not line.startswith(' '):
                # 保存上一个接口
                if current_interface:
                    interfaces.append({
                        "name": current_interface,
                        "ip_address": ip_address,
                        "mac_address": mac_address,
                        "status": "up" if "UP" in line else "down",
                        "rx_bytes": 0,
                        "tx_bytes": 0
                    })

                # 提取新接口名称
                interface_match = re.search(r'^[0-9]+: ([^:@]+)', line)
                if interface_match:
                    current_interface = interface_match.group(1)
                    ip_address = ""
                    mac_address = ""

            # 提取IP地址
            ip_match = re.search(r'inet ([\d\.]+)', line)
            if ip_match and not ip_address:
                ip_address = ip_match.group(1)

            # 提取MAC地址
            mac_match = re.search(r'link/ether ([0-9a-f:]+)', line)
            if mac_match:
                mac_address = mac_match.group(1)

        # 添加最后一个接口
        if current_interface:
            interfaces.append({
                "name": current_interface,
                "ip_address": ip_address,
                "mac_address": mac_address,
                "status": "up" if "UP" in line else "down",
                "rx_bytes": 0,
                "tx_bytes": 0
            })

        return interfaces

    @staticmethod
    def parse_docker_containers(raw_output: str) -> List[Dict]:
        """解析Docker容器列表"""
        containers = []
        lines = raw_output.strip().split('\n')

        # 跳过标题行
        for line in lines[1:]:
            parts = line.split(None, 6)
            if len(parts) >= 7:
                containers.append({
                    "container_id": parts[0],
                    "image": parts[1],
                    "name": parts[6],
                    "status": parts[4] + " " + parts[5],
                    "created": parts[3],
                    "ports": parts[2],
                    "cpu_usage": None,
                    "memory_usage": None
                })

        return containers

    @staticmethod
    def parse_docker_images(raw_output: str) -> List[Dict]:
        """解析Docker镜像列表"""
        images = []
        lines = raw_output.strip().split('\n')

        # 跳过标题行
        for line in lines[1:]:
            parts = line.split(None, 6)
            if len(parts) >= 7:
                images.append({
                    "repository": parts[0],
                    "tag": parts[1],
                    "image_id": parts[2],
                    "created": parts[3] + " " + parts[4],
                    "size": parts[6]
                })

        return images

    @staticmethod
    def parse_docker_volumes(raw_output: str) -> List[Dict]:
        """解析Docker卷列表"""
        volumes = []
        lines = raw_output.strip().split('\n')

        # 跳过标题行
        for line in lines[1:]:
            parts = line.split(None, 2)
            if len(parts) >= 3:
                volumes.append({
                    "volume_name": parts[1],
                    "driver": parts[0],
                    "mountpoint": parts[2]
                })

        return volumes
