"""网络相关工具函数"""

from server_monitor.core.ssh_manager import SSHManager
from server_monitor.core.inspector import ServerInspector
from server_monitor.utils.decorators import handle_exceptions

@handle_exceptions
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

@handle_exceptions
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