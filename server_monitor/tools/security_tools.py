"""安全相关工具函数"""

import re
from server_monitor.core.ssh_manager import SSHManager
from server_monitor.core.inspector import ServerInspector
from server_monitor.utils.decorators import handle_exceptions

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

@handle_exceptions
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

@handle_exceptions
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

@handle_exceptions
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