"""安全相关工具函数"""

import re
from core.ssh_manager import SSHManager
from core.inspector import ServerInspector
from utils.decorators import handle_exceptions
from config.logger import logger

@handle_exceptions
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
            stdin, stdout, stderr = ssh.exec_command(f"ls {log_file}", timeout=timeout)
            if stderr.read().decode().strip():
                # 尝试其他常见的日志文件
                alternative_logs = ["/var/log/secure", "/var/log/audit/audit.log"]
                for alt_log in alternative_logs:
                    stdin, stdout, stderr = ssh.exec_command(f"ls {alt_log}", timeout=timeout)
                    if not stderr.read().decode().strip():
                        log_file = alt_log
                        break
                else:
                    result["status"] = "error"
                    result["error"] = f"找不到SSH日志文件: {log_file} 或其他常见日志文件"
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

@handle_exceptions
def check_firewall_config(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    timeout: int = 30
) -> dict:
    """检查防火墙配置"""
    result = {"status": "unknown", "firewall_info": {}, "error": ""}

    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 检查常见的防火墙服务
            firewall_services = ["ufw", "firewalld", "iptables"]
            firewall_info = {}

            for fw in firewall_services:
                if fw == "ufw":
                    stdin, stdout, stderr = ssh.exec_command("ufw status", timeout=timeout)
                    output = stdout.read().decode().strip()
                    if "Status: active" in output:
                        firewall_info["ufw"] = {
                            "active": True,
                            "rules": output.split('\n')[1:] if len(output.split('\n')) > 1 else []
                        }
                    else:
                        firewall_info["ufw"] = {"active": False}

                elif fw == "firewalld":
                    stdin, stdout, stderr = ssh.exec_command("firewall-cmd --state", timeout=timeout)
                    output = stdout.read().decode().strip()
                    if output == "running":
                        # 获取区域信息
                        stdin, stdout, stderr = ssh.exec_command("firewall-cmd --list-all", timeout=timeout)
                        zones_output = stdout.read().decode().strip()
                        firewall_info["firewalld"] = {
                            "active": True,
                            "config": zones_output
                        }
                    else:
                        firewall_info["firewalld"] = {"active": False}

                elif fw == "iptables":
                    stdin, stdout, stderr = ssh.exec_command("iptables -L", timeout=timeout)
                    output = stdout.read().decode().strip()
                    # 简单检查是否有规则
                    has_rules = len(output.split('\n')) > 6  # 基本的链定义通常有6行
                    firewall_info["iptables"] = {
                        "active": has_rules,
                        "rules": output.split('\n')
                    }

            result["firewall_info"] = firewall_info
            result["status"] = "success"

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result

@handle_exceptions
def security_vulnerability_scan(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    scan_type: str = "basic",  # basic, full
    timeout: int = 60
) -> dict:
    """执行安全漏洞扫描"""
    result = {"status": "unknown", "vulnerabilities": [], "summary": {}, "error": ""}

    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 检查是否安装了常见的安全扫描工具
            scan_tools = ["lynis", "rkhunter", "chkrootkit"]
            available_tools = []

            for tool in scan_tools:
                stdin, stdout, stderr = ssh.exec_command(f"command -v {tool}", timeout=timeout)
                if stdout.read().decode().strip():
                    available_tools.append(tool)

            if not available_tools:
                result["status"] = "error"
                result["error"] = "未找到可用的安全扫描工具，请安装 lynis, rkhunter 或 chkrootkit"
                return result

            vulnerabilities = []
            summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}

            # 使用可用的工具进行扫描
            for tool in available_tools:
                if tool == "lynis" and scan_type == "full":
                    stdin, stdout, stderr = ssh.exec_command("lynis audit system", timeout=timeout*2)
                    output = stdout.read().decode().strip()

                    # 解析Lynis输出
                    for line in output.split('\n'):
                        if "Warning:" in line:
                            severity = "medium"
                            if "Critical" in line:
                                severity = "critical"
                                summary["critical"] += 1
                            elif "High" in line:
                                severity = "high"
                                summary["high"] += 1
                            else:
                                summary["medium"] += 1

                            vulnerabilities.append({
                                "tool": "lynis",
                                "severity": severity,
                                "description": line.strip()
                            })

                elif tool == "rkhunter":
                    stdin, stdout, stderr = ssh.exec_command("rkhunter --check --skip-keypress", timeout=timeout*2)
                    output = stdout.read().decode().strip()

                    # 解析rkhunter输出
                    for line in output.split('\n'):
                        if "Warning:" in line or "[Warning]" in line:
                            summary["high"] += 1
                            vulnerabilities.append({
                                "tool": "rkhunter",
                                "severity": "high",
                                "description": line.strip()
                            })

                elif tool == "chkrootkit":
                    stdin, stdout, stderr = ssh.exec_command("chkrootkit", timeout=timeout*2)
                    output = stdout.read().decode().strip()

                    # 解析chkrootkit输出
                    for line in output.split('\n'):
                        if "INFECTED" in line:
                            summary["critical"] += 1
                            vulnerabilities.append({
                                "tool": "chkrootkit",
                                "severity": "critical",
                                "description": line.strip()
                            })

            # 如果没有专业工具，执行基本的安全检查
            if not vulnerabilities:
                # 检查SSH配置
                stdin, stdout, stderr = ssh.exec_command("grep PermitRootLogin /etc/ssh/sshd_config", timeout=timeout)
                output = stdout.read().decode().strip()
                if "yes" in output:
                    summary["high"] += 1
                    vulnerabilities.append({
                        "tool": "basic_check",
                        "severity": "high",
                        "description": "SSH允许root直接登录，存在安全风险"
                    })

                # 检查密码策略
                stdin, stdout, stderr = ssh.exec_command("grep PASS_MAX_DAYS /etc/login.defs", timeout=timeout)
                output = stdout.read().decode().strip()
                if output and int(output.split()[-1]) > 90:
                    summary["medium"] += 1
                    vulnerabilities.append({
                        "tool": "basic_check",
                        "severity": "medium",
                        "description": f"密码最长使用天数过长: {output.split()[-1]}天"
                    })

            result["vulnerabilities"] = vulnerabilities
            result["summary"] = summary
            result["status"] = "success"

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result

@handle_exceptions
def backup_critical_files(
    hostname: str,
    username: str,
    password: str = "",
    port: int = 22,
    backup_dir: str = "/tmp/backup",
    files_to_backup: list[str] = ["/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config"],
    timeout: int = 30
) -> dict:
    """备份关键系统文件"""
    result = {"status": "unknown", "backup_results": [], "error": ""}

    try:
        with SSHManager(hostname, username, password, port, timeout) as ssh:
            # 创建备份目录
            stdin, stdout, stderr = ssh.exec_command(f"mkdir -p {backup_dir}", timeout=timeout)
            error = stderr.read().decode().strip()
            if error:
                result["status"] = "error"
                result["error"] = f"创建备份目录失败: {error}"
                return result

            backup_results = []
            for file_path in files_to_backup:
                # 检查文件是否存在
                stdin, stdout, stderr = ssh.exec_command(f"ls {file_path}", timeout=timeout)
                error = stderr.read().decode().strip()
                if error:
                    backup_results.append({
                        "file": file_path,
                        "status": "error",
                        "message": f"文件不存在: {error}"
                    })
                    continue

                # 获取文件名
                file_name = file_path.split('/')[-1]
                backup_path = f"{backup_dir}/{file_name}.bak"

                # 备份文件
                stdin, stdout, stderr = ssh.exec_command(f"cp {file_path} {backup_path}", timeout=timeout)
                error = stderr.read().decode().strip()
                if error:
                    backup_results.append({
                        "file": file_path,
                        "status": "error",
                        "message": f"备份失败: {error}"
                    })
                else:
                    backup_results.append({
                        "file": file_path,
                        "status": "success",
                        "backup_path": backup_path
                    })

            result["backup_results"] = backup_results
            result["status"] = "success"

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result
