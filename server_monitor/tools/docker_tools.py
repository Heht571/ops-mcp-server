"""Docker相关工具函数"""

from server_monitor.models.schemas import InspectionResult, ContainerInfo, ImageInfo, VolumeInfo
from server_monitor.core.ssh_manager import SSHManager
from server_monitor.utils.decorators import handle_exceptions
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

@handle_exceptions
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

@handle_exceptions
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

@handle_exceptions
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

@handle_exceptions
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