"""系统相关工具函数"""

import psutil
import re
from models.schemas import InspectionResult
from core.ssh_manager import SSHManager
from core.inspector import ServerInspector
from utils.decorators import handle_exceptions
from config.logger import logger

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

    try:
        with SSHManager(hostname, username, password, port, timeout, use_connection_cache) as ssh:
            # 执行每个模块的命令并解析结果
            for module in inspection_modules:
                if module in commands:
                    stdin, stdout, stderr = ssh.exec_command(commands[module], timeout=timeout)
                    output = stdout.read().decode().strip()
                    error = stderr.read().decode().strip()

                    if error:
                        logger.warning(f"执行 {module} 命令时出现警告: {error}")

                    # 存储原始输出
                    result.raw_outputs[module] = output

                    # 解析结果
                    if module == "cpu":
                        result.data[module] = ServerInspector.parse_cpu(output)
                    elif module == "memory":
                        result.data[module] = ServerInspector.parse_memory(output)
                    elif module == "disk":
                        result.data[module] = ServerInspector.parse_disk(output)
                    # 可以添加更多模块的解析逻辑
                else:
                    logger.warning(f"未知的巡检模块: {module}")

            # 设置状态和汇总信息
            result.status = "success"
            result.summary = f"完成对 {hostname} 的服务器巡检，检查了 {len(inspection_modules)} 个模块"

    except Exception as e:
        result.status = "error"
        result.error = str(e)
        logger.error(f"服务器巡检失败: {str(e)}")

    return result.dict()

@handle_exceptions
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
            return {"status": "success", "load_average": load_avg.group(1) if load_avg else "unknown"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

@handle_exceptions
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

@handle_exceptions
def check_service_status(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    service_names: list[str] = [],  # 为空则检查所有服务
    timeout: int = 30
) -> dict:
    """检查服务状态"""
    result = {"status": "unknown", "services": [], "error": ""}

    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 构建命令
            if service_names:
                # 检查指定服务
                services_str = " ".join(service_names)
                command = f"systemctl status {services_str}"
            else:
                # 列出所有服务
                command = "systemctl list-units --type=service --all"

            stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
            raw_output = stdout.read().decode().strip()

            # 解析服务状态
            result["services"] = ServerInspector.parse_services(raw_output)
            result["status"] = "success"

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result

@handle_exceptions
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

            result["os_info"] = os_info
            result["status"] = "success"

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result
