"""系统相关工具函数"""

import psutil
import re
from server_monitor.models.schemas import InspectionResult
from server_monitor.core.ssh_manager import SSHManager
from server_monitor.core.inspector import ServerInspector
from server_monitor.utils.decorators import handle_exceptions
from server_monitor.config.logger import logger

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