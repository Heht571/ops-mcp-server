"""Docker相关工具函数"""

from models.schemas import InspectionResult
from core.ssh_manager import SSHManager
from core.inspector import ServerInspector
from utils.decorators import handle_exceptions
from config.logger import logger
import json

@handle_exceptions
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
            stdin, stdout, stderr = ssh.exec_command("command -v docker", timeout=timeout)
            if not stdout.read().strip():
                result.status = "error"
                result.error = "Docker未安装在目标服务器上"
                return result.dict()

            # 构建命令
            cmd = "docker ps"
            if show_all:
                cmd += " -a"

            # 执行命令
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
            container_output = stdout.read().decode('utf-8')
            error_output = stderr.read().decode('utf-8')

            if error_output:
                result.status = "error"
                result.error = f"获取容器列表失败: {error_output}"
                return result.dict()

            # 解析容器信息
            containers = ServerInspector.parse_docker_containers(container_output)

            # 设置结果
            result.status = "success"
            result.data = {"containers": containers}
            result.raw_outputs = {"container_list": container_output}

            container_count = len(containers)
            result.summary = f"找到 {container_count} 个{'所有' if show_all else '运行中的'}容器"

    except Exception as e:
        result.status = "error"
        result.error = f"获取容器列表失败: {str(e)}"

    return result.dict()

@handle_exceptions
def list_docker_images(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    timeout: int = 30
) -> dict:
    """列出Docker镜像及其信息"""
    result = InspectionResult()

    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 检查Docker是否安装
            stdin, stdout, stderr = ssh.exec_command("command -v docker", timeout=timeout)
            if not stdout.read().strip():
                result.status = "error"
                result.error = "Docker未安装在目标服务器上"
                return result.dict()

            # 执行命令
            stdin, stdout, stderr = ssh.exec_command("docker images", timeout=timeout)
            images_output = stdout.read().decode('utf-8')
            error_output = stderr.read().decode('utf-8')

            if error_output:
                result.status = "error"
                result.error = f"获取镜像列表失败: {error_output}"
                return result.dict()

            # 解析镜像信息
            images = ServerInspector.parse_docker_images(images_output)

            # 设置结果
            result.status = "success"
            result.data = {"images": images}
            result.raw_outputs = {"image_list": images_output}

            image_count = len(images)
            result.summary = f"找到 {image_count} 个Docker镜像"

    except Exception as e:
        result.status = "error"
        result.error = f"获取镜像列表失败: {str(e)}"

    return result.dict()

@handle_exceptions
def list_docker_volumes(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    timeout: int = 30
) -> dict:
    """列出Docker卷及其信息"""
    result = InspectionResult()

    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 检查Docker是否安装
            stdin, stdout, stderr = ssh.exec_command("command -v docker", timeout=timeout)
            if not stdout.read().strip():
                result.status = "error"
                result.error = "Docker未安装在目标服务器上"
                return result.dict()

            # 执行命令
            stdin, stdout, stderr = ssh.exec_command("docker volume ls", timeout=timeout)
            volumes_output = stdout.read().decode('utf-8')
            error_output = stderr.read().decode('utf-8')

            if error_output:
                result.status = "error"
                result.error = f"获取卷列表失败: {error_output}"
                return result.dict()

            # 解析卷信息
            volumes = ServerInspector.parse_docker_volumes(volumes_output)

            # 设置结果
            result.status = "success"
            result.data = {"volumes": volumes}
            result.raw_outputs = {"volume_list": volumes_output}

            volume_count = len(volumes)
            result.summary = f"找到 {volume_count} 个Docker卷"

    except Exception as e:
        result.status = "error"
        result.error = f"获取卷列表失败: {str(e)}"

    return result.dict()

@handle_exceptions
def get_container_logs(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    container: str = "",  # 容器ID或名称
    tail: int = 100,  # 获取最后多少行日志
    since: str = "",  # 从什么时间开始，如 "2021-01-01T00:00:00"
    timeout: int = 30
) -> dict:
    """获取Docker容器的日志"""
    result = InspectionResult()

    if not container:
        result.status = "error"
        result.error = "必须指定容器ID或名称"
        return result.dict()

    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 检查Docker是否安装
            stdin, stdout, stderr = ssh.exec_command("command -v docker", timeout=timeout)
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
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
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

@handle_exceptions
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
            stdin, stdout, stderr = ssh.exec_command("command -v docker", timeout=timeout)
            if not stdout.read().strip():
                result.status = "error"
                result.error = "Docker未安装在目标服务器上"
                return result.dict()

            # 构建命令
            container_list = " ".join(containers) if containers else ""
            cmd = f"docker stats --no-stream --format '{{{{.Name}}}}|{{{{.ID}}}}|{{{{.CPUPerc}}}}|{{{{.MemUsage}}}}|{{{{.MemPerc}}}}|{{{{.NetIO}}}}|{{{{.BlockIO}}}}|{{{{.PIDs}}}}' {container_list}"

            # 执行命令
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
            stats_output = stdout.read().decode('utf-8')
            error_output = stderr.read().decode('utf-8')

            if error_output:
                result.status = "error"
                result.error = f"获取容器状态失败: {error_output}"
                return result.dict()

            # 解析统计信息
            container_stats = []
            for line in stats_output.strip().split('\n'):
                if not line:
                    continue

                parts = line.split('|')
                if len(parts) >= 8:
                    container_stats.append({
                        "name": parts[0],
                        "id": parts[1],
                        "cpu_usage": parts[2],
                        "memory_usage": parts[3],
                        "memory_percent": parts[4],
                        "network_io": parts[5],
                        "block_io": parts[6],
                        "pids": parts[7]
                    })

            # 设置结果
            result.status = "success"
            result.data = {"container_stats": container_stats}
            result.raw_outputs = {"stats_output": stats_output}

            stats_count = len(container_stats)
            result.summary = f"获取到 {stats_count} 个容器的资源使用情况"

    except Exception as e:
        result.status = "error"
        result.error = f"获取容器状态失败: {str(e)}"

    return result.dict()

@handle_exceptions
def check_docker_health(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    timeout: int = 30
) -> dict:
    """检查Docker服务健康状态"""
    result = InspectionResult()

    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 检查Docker是否安装
            stdin, stdout, stderr = ssh.exec_command("command -v docker", timeout=timeout)
            if not stdout.read().strip():
                result.status = "error"
                result.error = "Docker未安装在目标服务器上"
                return result.dict()

            # 检查Docker服务状态
            stdin, stdout, stderr = ssh.exec_command("systemctl is-active docker", timeout=timeout)
            service_status = stdout.read().decode('utf-8').strip()

            # 获取Docker信息
            stdin, stdout, stderr = ssh.exec_command("docker info", timeout=timeout)
            info_output = stdout.read().decode('utf-8')
            error_output = stderr.read().decode('utf-8')

            # 解析Docker信息
            docker_info = {}
            for line in info_output.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    docker_info[key.strip()] = value.strip()

            # 检查Docker版本
            stdin, stdout, stderr = ssh.exec_command("docker version --format '{{.Server.Version}}'", timeout=timeout)
            version_output = stdout.read().decode('utf-8').strip()

            # 设置结果
            result.status = "success"
            result.data = {
                "service_status": service_status,
                "version": version_output,
                "info": docker_info
            }
            result.raw_outputs = {"docker_info": info_output}

            result.summary = f"Docker服务状态: {service_status}, 版本: {version_output}"

    except Exception as e:
        result.status = "error"
        result.error = f"检查Docker健康状态失败: {str(e)}"

    return result.dict()
